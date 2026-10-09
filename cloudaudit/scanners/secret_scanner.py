"""
cloudaudit — Secret & Sensitive Data Scanner

Analyses text file content for:
  - Cloud provider credentials (AWS, GCP, Azure)
  - Auth tokens (JWT, OAuth, GitHub/GitLab)
  - Private keys and certificates
  - Database connection strings with credentials
  - Hardcoded passwords
  - PII indicators (emails, phone numbers)
  - Internal infrastructure hints
  - Terraform state secrets
  - CI/CD pipeline secrets

All matches are redacted before being stored in findings.
The full secret value is never logged or stored.
"""

from __future__ import annotations

import base64
import bisect
import json
import logging
import math
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from cloudaudit.core.exceptions import ConfigError
from cloudaudit.core.models import FileType, Finding, FindingCategory, Severity
from cloudaudit.intelligence.local_ai import looks_like_placeholder
from cloudaudit.utils.helpers import calculate_entropy, redact, secret_hash, truncate, url_filename

logger = logging.getLogger("cloudaudit.secret_scanner")


# ── Pattern definition ─────────────────────────────────────────────────────────

@dataclass
class Pattern:
    name:         str
    pattern:      str
    description:  str
    severity:     Severity
    category:     FindingCategory
    recommendation: str
    compliance:   List[str]        # Compliance framework references
    validation:   Optional[Callable[[str], bool]] = None
    context_required: Optional[List[str]] = None    # Keywords required near match
    # Structured values (IPs, config directives, URLs) are low-entropy by
    # nature — the entropy gate must not apply to them or they never fire.
    structured:   bool = False
    # Generic "looks like a secret" rules yield to any more specific rule
    # that already claimed the same text.
    generic:      bool = False
    base_confidence: Optional[float] = None         # Typed provider tokens: fixed high confidence


def _valid_aws_access(m: str) -> bool:
    return (
        m.startswith(("AKIA", "ASIA", "ABIA"))
        and len(m) in (20, 21)
        and "EXAMPLE" not in m          # AWS documentation keys (AKIAIOSFODNN7EXAMPLE)
        and len(set(m[4:])) > 4         # AKIAAAAAAAAAAAAAAAAA-style filler
    )


def _valid_password(m: str) -> bool:
    return len(m) >= 8 and not looks_like_placeholder(m)


def _not_placeholder(m: str) -> bool:
    return not looks_like_placeholder(m)


def _valid_luhn(m: str) -> bool:
    """Luhn checksum — rejects the ~90% of 13-16 digit numbers that are not card numbers."""
    digits = [int(c) for c in m if c.isdigit()]
    if len(digits) < 13 or len(set(digits)) < 3:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _valid_ipv4(m: str) -> bool:
    try:
        return all(0 <= int(o) <= 255 for o in m.split("."))
    except ValueError:
        return False


def _valid_jwt(m: str) -> bool:
    """A JWT's first segment must base64url-decode to a JSON object with alg/typ."""
    head = m.split(".", 1)[0]
    try:
        data = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
        return isinstance(data, dict) and ("alg" in data or "typ" in data)
    except Exception:
        return False


_NON_EMAIL_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "json", "html", "map", "ts", "md"}
_EXAMPLE_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "test.com", "domain.com",
                          "email.com", "yourdomain.com", "localhost.localdomain", "sentry.io")


def _valid_email(m: str) -> bool:
    local, _, domain = m.rpartition("@")
    domain = domain.lower()
    if domain.rsplit(".", 1)[-1] in _NON_EMAIL_TLDS:      # sprite@2x.png, pkg@1.0.js
        return False
    if domain in _EXAMPLE_EMAIL_DOMAINS or domain.endswith(".example"):
        return False
    return bool(local) and not local.isdigit()


def _valid_db_url(m: str) -> bool:
    cred = re.search(r"://[^:/\s]+:([^@\s]+)@", m)
    return bool(cred) and not looks_like_placeholder(cred.group(1))


_PATTERNS: List[Pattern] = [
    # ── AWS ───────────────────────────────────────────────────────────────────
    Pattern(
        name="AWS_ACCESS_KEY",
        pattern=r"\b((?:AKIA|ASIA|ABIA)[0-9A-Z]{16})\b",
        description="AWS Access Key ID",
        severity=Severity.CRITICAL,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Rotate the AWS key immediately. Audit CloudTrail for usage. Enable SCPs to block key creation in production.",
        compliance=["CIS 2.1", "NIST IA-5", "SOC2 CC6.7"],
        validation=_valid_aws_access,
    ),
    Pattern(
        name="AWS_SECRET_KEY",
        pattern=r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[=:\"']+\s*[\"']?([A-Za-z0-9/+]{40})[\"']?",
        description="AWS Secret Access Key",
        severity=Severity.CRITICAL,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Rotate the AWS secret key immediately. Restrict IAM permissions using least privilege.",
        compliance=["CIS 2.1", "NIST IA-5"],
    ),
    Pattern(
        name="AWS_SESSION_TOKEN",
        pattern=r"(?i)aws_session_token\s*[=:\"']+\s*[\"']?([A-Za-z0-9/+=]{100,})[\"']?",
        description="AWS Session Token (temporary credentials)",
        severity=Severity.HIGH,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Revoke the STS session and audit the role that issued it.",
        compliance=["NIST IA-5"],
    ),
    # ── GCP ───────────────────────────────────────────────────────────────────
    Pattern(
        name="GCP_API_KEY",
        pattern=r"\b(AIza[0-9A-Za-z\-_]{35})\b",
        description="Google Cloud API Key",
        severity=Severity.HIGH,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Restrict the API key to required APIs and IPs. Rotate if exposed.",
        compliance=["NIST IA-5", "SOC2 CC6.7"],
    ),
    Pattern(
        name="GCP_SERVICE_ACCOUNT_KEY",
        pattern=r'"type"\s*:\s*"service_account"',
        description="Google Cloud Service Account Key File",
        severity=Severity.CRITICAL,
        category=FindingCategory.CREDENTIAL_FILE,
        recommendation="Revoke the service account key in IAM. Audit all API calls made with it.",
        compliance=["CIS", "NIST IA-5"],
    ),
    Pattern(
        name="GCP_OAUTH_TOKEN",
        pattern=r"\b(ya29\.[0-9A-Za-z\-_]{80,})\b",
        description="Google OAuth 2.0 Access Token",
        severity=Severity.HIGH,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Revoke the OAuth token in Google Cloud Console.",
        compliance=["NIST IA-5"],
    ),
    # ── Azure ─────────────────────────────────────────────────────────────────
    Pattern(
        name="AZURE_STORAGE_KEY",
        pattern=r"(?i)AccountKey=([A-Za-z0-9+/=]{88,})",
        description="Azure Storage Account Key",
        severity=Severity.CRITICAL,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Rotate the storage account access key immediately via Azure Portal.",
        compliance=["CIS", "NIST IA-5", "SOC2 CC6.7"],
    ),
    Pattern(
        name="AZURE_SAS_TOKEN",
        pattern=r"(?i)(?:sig=)([A-Za-z0-9%+/=]{40,})",
        description="Azure SAS (Shared Access Signature) Token",
        severity=Severity.HIGH,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Revoke the SAS token and generate a new one with minimum required permissions and expiry.",
        compliance=["NIST IA-5"],
        # A bare ``sig=`` query parameter is not a SAS token — require the
        # other SAS fields (version / expiry / permissions) nearby.
        context_required=["sv=", "se=", "sp="],
    ),
    # ── Private Keys ──────────────────────────────────────────────────────────
    Pattern(
        name="PRIVATE_KEY",
        pattern=r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
        description="Private Key Material",
        severity=Severity.CRITICAL,
        category=FindingCategory.CREDENTIAL_FILE,
        recommendation="Revoke and regenerate the key pair immediately. Never store private keys in cloud storage.",
        compliance=["CIS", "NIST IA-5", "SOC2 CC6.1"],
        structured=True,
        base_confidence=0.97,
    ),
    # ── Auth Tokens ───────────────────────────────────────────────────────────
    Pattern(
        name="JWT_TOKEN",
        pattern=r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b",
        description="JSON Web Token (JWT)",
        severity=Severity.MEDIUM,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Invalidate the JWT, rotate the signing secret, and enforce token expiry.",
        compliance=["NIST IA-5"],
        validation=_valid_jwt,
    ),
    # ── Source Control ────────────────────────────────────────────────────────
    Pattern(
        name="GITHUB_PAT",
        pattern=r"\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b",
        description="GitHub Personal Access Token",
        severity=Severity.CRITICAL,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Revoke the token on GitHub. Audit all API calls it made.",
        compliance=["NIST IA-5", "SOC2 CC6.7"],
    ),
    Pattern(
        name="GITLAB_TOKEN",
        pattern=r"\b(glpat-[A-Za-z0-9\-_]{20})\b",
        description="GitLab Personal Access Token",
        severity=Severity.CRITICAL,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Revoke the token in GitLab User Settings > Access Tokens.",
        compliance=["NIST IA-5"],
    ),
    # ── Databases ─────────────────────────────────────────────────────────────
    Pattern(
        name="DATABASE_URL",
        pattern=r"(?i)(?:mongodb|mysql|mariadb|postgres|postgresql|redis|rediss|mssql|sqlserver|oracle|amqp|amqps|clickhouse|cockroachdb)(?:\+[a-z0-9]+)?://[^:/\s]+:[^@\s]+@[^\s'\"<>{}\[\]]+",
        description="Database Connection String with Credentials",
        severity=Severity.CRITICAL,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Rotate database credentials immediately. Restrict DB access to application subnet only.",
        compliance=["CIS", "NIST IA-5", "SOC2 CC6.1"],
        validation=_valid_db_url,
        structured=True,
        base_confidence=0.9,
    ),
    # ── Generic Secrets ───────────────────────────────────────────────────────
    Pattern(
        name="GENERIC_API_KEY",
        pattern=r"(?i)(?:api[_-]?key|apikey|api[_-]?token)\s*[=:\"']+\s*[\"']?([A-Za-z0-9\-_]{20,})[\"']?",
        description="Generic API Key or Token",
        severity=Severity.MEDIUM,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Rotate the API key and restrict its permissions. Use environment variables for storage.",
        compliance=["NIST IA-5"],
        validation=_not_placeholder,
        generic=True,
    ),
    Pattern(
        name="HARDCODED_PASSWORD",
        pattern=r"(?i)(?:password|passwd|pwd)\s*[=:\"']+\s*[\"']([^\"'\s]{6,})[\"']",
        description="Hardcoded Password",
        severity=Severity.HIGH,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Remove hardcoded credentials. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault).",
        compliance=["CIS 2.1", "NIST IA-5", "SOC2 CC6.1"],
        validation=_valid_password,
        generic=True,
    ),
    # ── Environment Files ─────────────────────────────────────────────────────
    Pattern(
        name="ENV_VARIABLE_SECRET",
        pattern=r"(?m)^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]{1,60}(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|CREDENTIALS?)[ \t]*=[ \t]*[\"']?([^\s\"'#]{8,})[\"']?[ \t]*(?:#.*)?$",
        description="Secret in Environment Variable Assignment",
        severity=Severity.HIGH,
        category=FindingCategory.CREDENTIAL_FILE,
        recommendation="Remove .env files from cloud storage. Use IAM roles or a secrets manager.",
        compliance=["NIST IA-5", "SOC2 CC6.7"],
        validation=_valid_password,
        generic=True,
    ),
    # ── Infrastructure ────────────────────────────────────────────────────────
    Pattern(
        name="INTERNAL_IP",
        pattern=r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        description="Internal / RFC-1918 IP Address",
        severity=Severity.LOW,
        category=FindingCategory.INFRASTRUCTURE_INF,
        recommendation="Review whether internal network topology should be exposed in these files.",
        compliance=["NIST SC-7"],
        validation=_valid_ipv4,
        structured=True,
        base_confidence=0.7,
    ),
    Pattern(
        name="SSH_CONFIG",
        pattern=r"(?im)^[ \t]*(IdentityFile[ \t]+\S+|StrictHostKeyChecking[ \t]+no\b|ProxyCommand[ \t]+\S.*)",
        description="SSH Configuration with Potentially Sensitive Details",
        severity=Severity.MEDIUM,
        category=FindingCategory.INFRASTRUCTURE_INF,
        recommendation="Avoid storing SSH configuration files in cloud storage. Use bastion hosts with ephemeral keys.",
        compliance=["NIST IA-5"],
        structured=True,
        base_confidence=0.75,
    ),
    # ── PII ───────────────────────────────────────────────────────────────────
    Pattern(
        name="EMAIL_ADDRESS",
        pattern=r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
        description="Email Address (potential PII)",
        severity=Severity.LOW,
        category=FindingCategory.PII_EXPOSURE,
        recommendation="Review whether email addresses in this file constitute PII and apply appropriate data governance.",
        compliance=["SOC2 CC6.7"],
        validation=_valid_email,
        generic=True,
        base_confidence=0.7,
    ),
    Pattern(
        name="CREDIT_CARD",
        pattern=r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        description="Potential Credit Card Number",
        severity=Severity.CRITICAL,
        category=FindingCategory.PII_EXPOSURE,
        recommendation="Immediately assess scope of PCI-DSS impact. Notify compliance team.",
        compliance=["SOC2 CC6.7", "PCI-DSS Req 3.4"],
        validation=_valid_luhn,
        structured=True,
        base_confidence=0.8,
    ),
]


# ── Provider-specific token formats (v1.3.0) ──────────────────────────────────
# Each entry: (name, regex, description, severity, revoke-hint, context keywords)
# These are strongly-typed formats (fixed prefix + fixed alphabet/length), so
# they carry a high fixed confidence instead of the entropy-derived estimate.

_B = r"(?<![A-Za-z0-9_\-])"      # left boundary for tokens that may contain - or _
_E = r"(?![A-Za-z0-9_\-])"       # right boundary

_TYPED_TOKENS: List[Tuple[str, str, str, Severity, str, Optional[List[str]]]] = [
    ("SLACK_TOKEN", _B + r"(xox[abeposr]-(?:[0-9A-Za-z]+-)+[0-9A-Za-z]{6,})" + _E,
     "Slack API Token", Severity.HIGH, "Revoke the token at api.slack.com/apps and review the workspace audit log.", None),
    ("SLACK_WEBHOOK", r"(https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,})",
     "Slack Incoming Webhook URL", Severity.MEDIUM, "Regenerate the webhook URL in the Slack app configuration.", None),
    ("DISCORD_WEBHOOK", r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,22}/[A-Za-z0-9_\-]{40,})",
     "Discord Webhook URL", Severity.MEDIUM, "Delete and recreate the webhook in the Discord channel settings.", None),
    ("STRIPE_SECRET_KEY", _B + r"((?:sk|rk)_live_[0-9A-Za-z]{20,})" + _E,
     "Stripe Live Secret Key", Severity.CRITICAL, "Roll the key in the Stripe dashboard and review recent API requests and payouts.", None),
    ("TWILIO_API_KEY", r"\b(SK[0-9a-f]{32})\b",
     "Twilio API Key", Severity.HIGH, "Delete the API key in the Twilio console and issue a new one.", ["twilio"]),
    ("SENDGRID_API_KEY", _B + r"(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})" + _E,
     "SendGrid API Key", Severity.HIGH, "Delete the key in SendGrid and check for unauthorised sends.", None),
    ("OPENAI_API_KEY", _B + r"(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})" + _E,
     "OpenAI API Key", Severity.HIGH, "Revoke the key at platform.openai.com/api-keys and review usage.", None),
    ("ANTHROPIC_API_KEY", _B + r"(sk-ant-[A-Za-z0-9_\-]{40,})" + _E,
     "Anthropic API Key", Severity.HIGH, "Revoke the key in the Anthropic Console and review usage.", None),
    ("NPM_ACCESS_TOKEN", r"\b(npm_[A-Za-z0-9]{36})\b",
     "npm Access Token", Severity.HIGH, "Revoke the token with `npm token revoke` and audit recent package publishes.", None),
    ("PYPI_UPLOAD_TOKEN", _B + r"(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})" + _E,
     "PyPI Upload Token", Severity.HIGH, "Delete the token in PyPI account settings and audit recent releases.", None),
    ("DIGITALOCEAN_TOKEN", r"\b(do[opr]_v1_[a-f0-9]{64})\b",
     "DigitalOcean Access Token", Severity.CRITICAL, "Revoke the token in the DigitalOcean API settings.", None),
    ("HUGGINGFACE_TOKEN", r"\b(hf_[A-Za-z0-9]{34,})\b",
     "Hugging Face Access Token", Severity.HIGH, "Invalidate the token in Hugging Face settings.", None),
    ("TELEGRAM_BOT_TOKEN", r"\b(\d{8,10}:AA[A-Za-z0-9_\-]{33})" + _E,
     "Telegram Bot Token", Severity.HIGH, "Revoke the token via @BotFather (/revoke).", None),
    ("SHOPIFY_ACCESS_TOKEN", r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b",
     "Shopify Access Token", Severity.HIGH, "Rotate the app credentials in the Shopify admin.", None),
    ("GOOGLE_OAUTH_CLIENT_SECRET", _B + r"(GOCSPX-[A-Za-z0-9_\-]{28})" + _E,
     "Google OAuth Client Secret", Severity.HIGH, "Reset the client secret in Google Cloud Console > Credentials.", None),
    ("AZURE_AD_CLIENT_SECRET", _B + r"([A-Za-z0-9_~.]{3}8Q~[A-Za-z0-9_~.\-]{31,34})" + _E,
     "Microsoft Entra ID (Azure AD) Client Secret", Severity.HIGH, "Delete the client secret on the app registration and issue a new one.", None),
    ("DATABRICKS_TOKEN", r"\b(dapi[a-f0-9]{32}(?:-\d)?)\b",
     "Databricks Personal Access Token", Severity.HIGH, "Revoke the token in Databricks user settings.", None),
    ("VAULT_TOKEN", _B + r"(hvs\.[A-Za-z0-9_\-]{24,})" + _E,
     "HashiCorp Vault Token", Severity.CRITICAL, "Revoke the token (`vault token revoke`) and review the Vault audit device.", None),
    ("TERRAFORM_CLOUD_TOKEN", r"\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,})" + _E,
     "Terraform Cloud / Enterprise API Token", Severity.HIGH, "Revoke the token in Terraform Cloud user/team settings.", None),
    ("DOCKERHUB_TOKEN", _B + r"(dckr_pat_[A-Za-z0-9_\-]{27})" + _E,
     "Docker Hub Personal Access Token", Severity.HIGH, "Delete the access token in Docker Hub security settings.", None),
    ("GRAFANA_TOKEN", _B + r"(gl(?:sa|c)_[A-Za-z0-9_]{32,})" + _E,
     "Grafana Service Account / Cloud Token", Severity.HIGH, "Delete the token in Grafana administration.", None),
    ("NEWRELIC_API_KEY", r"\b(NRAK-[A-Z0-9]{27})\b",
     "New Relic User API Key", Severity.HIGH, "Delete the key in New Relic API keys settings.", None),
    ("MAILGUN_API_KEY", r"\b(key-[0-9a-f]{32})\b",
     "Mailgun API Key", Severity.HIGH, "Rotate the key in the Mailgun dashboard.", ["mailgun"]),
    ("SQUARE_ACCESS_TOKEN", _B + r"(sq0(?:atp|csp)-[A-Za-z0-9_\-]{22,43})" + _E,
     "Square Access Token / Application Secret", Severity.HIGH, "Revoke the token in the Square developer dashboard.", None),
    ("POSTMAN_API_KEY", r"\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b",
     "Postman API Key", Severity.HIGH, "Regenerate the key in Postman account settings.", None),
    ("LINEAR_API_KEY", r"\b(lin_api_[A-Za-z0-9]{40})\b",
     "Linear API Key", Severity.MEDIUM, "Revoke the key in Linear API settings.", None),
    ("AGE_SECRET_KEY", r"\b(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})\b",
     "age Encryption Secret Key", Severity.CRITICAL, "Generate a new age identity and re-encrypt everything encrypted to the old recipient.", None),
    ("GITLAB_RUNNER_TOKEN", _B + r"(gl(?:rt|dt|ft)-[A-Za-z0-9_\-]{20,})" + _E,
     "GitLab Runner / Deploy / Feed Token", Severity.HIGH, "Reset the token in the GitLab project or group settings.", None),
]

for _name, _rx, _desc, _sev, _hint, _ctx in _TYPED_TOKENS:
    _PATTERNS.append(Pattern(
        name=_name,
        pattern=_rx,
        description=_desc,
        severity=_sev,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation=_hint,
        compliance=["NIST IA-5", "SOC2 CC6.7"],
        validation=_not_placeholder,
        context_required=_ctx,
        structured=True,
        base_confidence=0.82 if _ctx else 0.93,
    ))

_PATTERNS += [
    Pattern(
        name="BASIC_AUTH_URL",
        pattern=r"\b(?:https?|ftp|sftp|ssh|git|smtps?|ldaps?)://[^/\s:@'\"<>]{1,64}:([^/\s:@'\"<>]{3,128})@[\w.\-]+",
        description="URL with Embedded Username and Password",
        severity=Severity.HIGH,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Rotate the embedded credential and switch to a credential helper or token-based authentication.",
        compliance=["NIST IA-5", "SOC2 CC6.7"],
        validation=_not_placeholder,
        structured=True,
        base_confidence=0.8,
    ),
    Pattern(
        name="CONNECTION_STRING_PASSWORD",
        pattern=r"(?i)(?:Server|Data Source|Host|Addr)\s*=[^;\n]{1,120};[^\n]{0,240}?(?:Password|Pwd)\s*=\s*([^;\"'\s]{4,})",
        description="Database Connection String with Embedded Password",
        severity=Severity.CRITICAL,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Rotate the database password and move the connection string to a secrets manager / managed identity.",
        compliance=["CIS", "NIST IA-5", "SOC2 CC6.1"],
        validation=_not_placeholder,
        structured=True,
        base_confidence=0.85,
    ),
    Pattern(
        name="US_SSN",
        pattern=r"\b((?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4})\b",
        description="Potential US Social Security Number",
        severity=Severity.HIGH,
        category=FindingCategory.PII_EXPOSURE,
        recommendation="Remove the file from public storage and assess breach-notification obligations.",
        compliance=["SOC2 CC6.7", "NIST SC-28"],
        context_required=["ssn", "social security", "social_security", "taxpayer", "tax id", "tax_id"],
        structured=True,
        base_confidence=0.8,
    ),
]

# Fixed-format provider credentials defined above get the same fixed, high
# confidence as the v1.3.0 typed tokens (the entropy estimate under-rated them).
_TYPED_CONFIDENCE = {
    "AWS_ACCESS_KEY": 0.92, "AWS_SECRET_KEY": 0.92, "AWS_SESSION_TOKEN": 0.90,
    "GCP_API_KEY": 0.88, "GCP_SERVICE_ACCOUNT_KEY": 0.95, "GCP_OAUTH_TOKEN": 0.90,
    "AZURE_STORAGE_KEY": 0.93, "GITHUB_PAT": 0.95, "GITLAB_TOKEN": 0.93,
}
for _p in _PATTERNS:
    if _p.name in _TYPED_CONFIDENCE:
        _p.base_confidence = _TYPED_CONFIDENCE[_p.name]
    # Documentation values (…EXAMPLEKEY, xxxxxxxx) must not fire any credential rule.
    if _p.name in ("AWS_SECRET_KEY", "AWS_SESSION_TOKEN", "GCP_API_KEY", "GCP_OAUTH_TOKEN",
                   "AZURE_STORAGE_KEY", "GITHUB_PAT", "GITLAB_TOKEN") and _p.validation is None:
        _p.validation = _not_placeholder

_PATTERNS += [
    Pattern(
        name="AUTHORIZATION_HEADER",
        pattern=r"(?i)\bAuthorization[\"']?\s*[:=]\s*[\"']?(?:Bearer|Token|Basic|ApiKey)\s+([A-Za-z0-9_\-.~+/=]{16,})",
        description="Hardcoded Authorization Header Credential",
        severity=Severity.HIGH,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Revoke the token and inject the Authorization header from a secret at runtime.",
        compliance=["NIST IA-5", "SOC2 CC6.7"],
        validation=_not_placeholder,
        generic=True,
    ),
    Pattern(
        name="URL_QUERY_SECRET",
        pattern=r"(?i)[?&](?:access_token|auth_token|api_key|apikey|token|key|secret|client_secret|password|passwd|signature)=([A-Za-z0-9_\-.~%+/]{16,})",
        description="Secret Passed in a URL Query Parameter",
        severity=Severity.MEDIUM,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Rotate the value and send it in a header instead — URLs are logged by proxies, servers and browsers.",
        compliance=["NIST IA-5", "SOC2 CC6.7"],
        validation=_not_placeholder,
        generic=True,
    ),
]

# Specific rules run first so that generic rules can yield to them.
_PATTERNS.sort(key=lambda p: p.generic)


_SEVERITY_MAP = {s.value.lower(): s for s in Severity}
_CATEGORY_MAP = {c.value.lower(): c for c in FindingCategory}


def load_custom_patterns(path: str) -> List[Pattern]:
    """
    Load user-supplied secret patterns from a YAML file (--custom-patterns).

    Expected shape:

        patterns:
          - name: INTERNAL_SERVICE_TOKEN
            regex: "internal_tok_[a-zA-Z0-9]{32}"
            severity: high                # critical|high|medium|low|informational
            description: "Internal service token"
            category: secret exposure     # optional, defaults to Secret Exposure
            compliance: ["NIST IA-5"]      # optional
            recommendation: "Rotate the token."   # optional
    """
    try:
        import yaml
    except ImportError as exc:
        raise ConfigError("pyyaml is required to load --custom-patterns files.") from exc

    from pathlib import Path
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"Custom patterns file not found: {path}")

    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise ConfigError(f"Failed to parse custom patterns file {path}: {exc}") from exc

    raw_patterns = data.get("patterns", data if isinstance(data, list) else [])
    patterns: List[Pattern] = []

    for item in raw_patterns:
        name  = item.get("name")
        regex = item.get("regex") or item.get("pattern")
        if not name or not regex:
            logger.warning("Skipping custom pattern with missing name/regex: %s", item)
            continue
        try:
            re.compile(regex)
        except re.error as exc:
            logger.warning("Skipping custom pattern %r — invalid regex: %s", name, exc)
            continue

        severity = _SEVERITY_MAP.get(str(item.get("severity", "medium")).lower(), Severity.MEDIUM)
        category = _CATEGORY_MAP.get(
            str(item.get("category", "secret exposure")).lower(), FindingCategory.SECRET_EXPOSURE
        )

        patterns.append(Pattern(
            name=str(name),
            pattern=regex,
            description=item.get("description", f"Custom pattern: {name}"),
            severity=severity,
            category=category,
            recommendation=item.get("recommendation", "Review and remediate this custom-pattern finding."),
            compliance=list(item.get("compliance", [])),
        ))

    logger.info("Loaded %d custom secret pattern(s) from %s", len(patterns), path)
    return patterns


class SecretScanner:
    """
    Scan text content for secrets, credentials, and sensitive data.

    Findings include redacted matches only — the actual secret value
    is never stored in the Finding object.
    """

    def __init__(self, min_entropy: float = 3.5, custom_patterns: Optional[List[Pattern]] = None) -> None:
        self._min_entropy = min_entropy
        all_patterns = sorted(list(_PATTERNS) + list(custom_patterns or []), key=lambda p: p.generic)
        self._compiled = [
            (p, re.compile(p.pattern, re.MULTILINE))
            for p in all_patterns
        ]

    # Hard cap on findings a single rule may raise in one file — bulk data is
    # summarised by the aggregation pass, not listed row by row.
    MAX_PER_RULE_PER_FILE = 1000

    def scan(self, content: str, file_url: str, file_type: FileType) -> List[Finding]:
        findings: List[Finding] = []
        file_name = url_filename(file_url)

        # Line index: O(log n) line lookups instead of re-counting newlines
        # from the start of the file for every match.
        line_starts = [0]
        for nl in re.finditer(r"\n", content):
            line_starts.append(nl.end())

        def line_of(pos: int) -> int:
            return bisect.bisect_right(line_starts, pos)

        by_value: Dict[Tuple[str, str], Finding] = {}          # (rule, value hash) → finding
        claimed:  Dict[int, List[Tuple[int, int]]] = {}        # line → spans already reported
        per_rule: Dict[str, int] = {}

        for pattern, regex in self._compiled:
            for m in regex.finditer(content):
                # Prefer group(1) if capturing group exists, else full match
                group = 1 if regex.groups and m.group(1) else 0
                matched = m.group(group)
                if not matched:
                    continue

                # Apply custom validator if defined
                if pattern.validation and not pattern.validation(matched):
                    continue

                # Context keyword requirement
                if pattern.context_required:
                    window = content[max(0, m.start()-150): m.end()+150].lower()
                    if not any(k in window for k in pattern.context_required):
                        continue

                # Entropy gate: very low-entropy strings are likely false positives.
                # This only makes sense for *random-looking secret* patterns — structured
                # values (PII, IPs, config directives) are naturally low-entropy and must
                # not be gated here, otherwise those rules never fire.
                ent = calculate_entropy(matched)
                effective_severity = pattern.severity
                # Shannon entropy cannot exceed log2(length): a random 24-character
                # key tops out near 4.5, so a fixed 4.5 threshold silently dropped
                # most real 20-32 character keys. The floor now scales with length.
                floor = min(self._min_entropy, 0.85 * math.log2(max(len(matched), 2)))
                if (
                    ent < floor
                    and pattern.severity in (Severity.MEDIUM, Severity.LOW)
                    and pattern.category != FindingCategory.PII_EXPOSURE
                    and not pattern.structured
                ):
                    continue   # skip — likely a placeholder or example
                if ent > 5.2 and effective_severity == Severity.MEDIUM and not pattern.structured:
                    effective_severity = Severity.HIGH   # high-entropy medium → escalate

                # The same value seen again in this file is one finding, counted.
                value_hash = secret_hash(matched)
                key = (pattern.name, value_hash)
                if key in by_value:
                    by_value[key].occurrences += 1
                    continue

                # A generic rule yields when a more specific rule already
                # reported overlapping text (e.g. AWS_SECRET_KEY vs ENV_VARIABLE_SECRET).
                start, stop = m.span(group)
                line = line_of(start)
                spans = claimed.setdefault(line, [])
                if pattern.generic and any(start < e and s < stop for s, e in spans):
                    continue
                spans.append((start, stop))

                per_rule[pattern.name] = per_rule.get(pattern.name, 0) + 1
                if per_rule[pattern.name] > self.MAX_PER_RULE_PER_FILE:
                    continue

                finding = Finding(
                    file_url=file_url,
                    file_name=file_name,
                    file_type=file_type,
                    category=pattern.category,
                    rule_name=pattern.name,
                    description=pattern.description,
                    severity=effective_severity,
                    match=redact(matched),
                    context=self._sanitise_context(self._context_snippet(content, line_starts, line)),
                    line_number=line,
                    recommendation=pattern.recommendation,
                    compliance_refs=list(pattern.compliance),
                    confidence=self._confidence(matched, ent, pattern),
                    scanner="SecretScanner",
                    value_hash=value_hash,
                )
                by_value[key] = finding
                findings.append(finding)

        for f in findings:
            if f.occurrences > 1:
                f.description += f" (x{f.occurrences} in this file)"
        return findings

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _context_snippet(content: str, line_starts: List[int], line: int, radius: int = 3) -> str:
        """Lines [line-radius, line+radius] (1-indexed ``line``), sliced by offset."""
        lo = max(0, line - 1 - radius)
        hi = min(len(line_starts), line + radius)
        start = line_starts[lo]
        stop = line_starts[hi] if hi < len(line_starts) else len(content)
        return content[start:stop].rstrip("\n")[:4000]

    @staticmethod
    def _sanitise_context(snippet: str) -> str:
        """
        Light sanitisation of context lines — remove obvious secret values
        while preserving line structure so analysts can understand the finding.
        """
        # Redact anything that looks like a long base64 / hex / token value.
        # 24+ (was 40+): most provider tokens are 24-40 characters and were
        # previously written to the report context in full.
        sanitised = re.sub(
            r"([A-Za-z0-9+/=_\-]{24,})",
            lambda m: redact(m.group(1)),
            snippet,
        )
        # Redact the value side of secret-looking assignments and URL passwords.
        sanitised = re.sub(
            r"(?i)((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|private[_-]?key|credential)\w*[\"']?\s*[=:]\s*[\"']?)([^\s\"',;]{4,})",
            lambda m: m.group(1) + redact(m.group(2), keep_chars=3),
            sanitised,
        )
        sanitised = re.sub(r"(://[^/\s:@]{1,64}:)([^@\s]{3,})(@)", lambda m: m.group(1) + "***" + m.group(3), sanitised)
        return sanitised[:800]  # cap context length

    @staticmethod
    def _confidence(matched: str, entropy: float, pattern: Pattern) -> float:
        if pattern.base_confidence is not None:
            return pattern.base_confidence
        conf = 0.4
        if len(matched) > 20:
            conf += 0.15
        if entropy > 4.0:
            conf += 0.20
        if entropy > 5.0:
            conf += 0.15
        if pattern.validation:
            conf += 0.10   # validated patterns are more reliable
        return min(conf, 0.95)  # a regex match is never certainty
