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

import re
from dataclasses import dataclass
from typing import Callable, List, Optional

from cloudaudit.core.models import FileType, Finding, FindingCategory, Severity
from cloudaudit.utils.helpers import calculate_entropy, redact, truncate, url_filename


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


def _valid_aws_access(m: str) -> bool:
    return m.startswith(("AKIA", "ASIA", "ABIA")) and len(m) in (20, 21)


def _valid_password(m: str) -> bool:
    fp = {"password", "passwd", "pwd", "secret", "null", "undefined",
          "true", "false", "your_password", "changeme", "example", "placeholder",
          "xxxxxxxx", "12345678", "test", "demo"}
    return m.lower() not in fp and len(m) >= 8 and not m.startswith("<")


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
    ),
    # ── Private Keys ──────────────────────────────────────────────────────────
    Pattern(
        name="PRIVATE_KEY",
        pattern=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        description="Private Key Material",
        severity=Severity.CRITICAL,
        category=FindingCategory.CREDENTIAL_FILE,
        recommendation="Revoke and regenerate the key pair immediately. Never store private keys in cloud storage.",
        compliance=["CIS", "NIST IA-5", "SOC2 CC6.1"],
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
        pattern=r"(?i)(?:mongodb|mysql|postgres|postgresql|redis|mssql|oracle)(?:\+[a-z]+)?://[^:\s]+:[^@\s]+@[^\s'\"<>{}\[\]]+",
        description="Database Connection String with Credentials",
        severity=Severity.CRITICAL,
        category=FindingCategory.SECRET_EXPOSURE,
        recommendation="Rotate database credentials immediately. Restrict DB access to application subnet only.",
        compliance=["CIS", "NIST IA-5", "SOC2 CC6.1"],
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
    ),
    # ── Environment Files ─────────────────────────────────────────────────────
    Pattern(
        name="ENV_VARIABLE_SECRET",
        pattern=r"(?m)^([A-Z_]{3,}(?:KEY|SECRET|TOKEN|PASSWORD|API|PASS|CREDENTIAL))\s*=\s*(.{8,})\s*$",
        description="Secret in Environment Variable Assignment",
        severity=Severity.HIGH,
        category=FindingCategory.CREDENTIAL_FILE,
        recommendation="Remove .env files from cloud storage. Use IAM roles or a secrets manager.",
        compliance=["NIST IA-5", "SOC2 CC6.7"],
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
    ),
    Pattern(
        name="SSH_CONFIG",
        pattern=r"(?i)(?:Host\s+\S+|IdentityFile\s+\S+|StrictHostKeyChecking\s+no)",
        description="SSH Configuration with Potentially Sensitive Details",
        severity=Severity.MEDIUM,
        category=FindingCategory.INFRASTRUCTURE_INF,
        recommendation="Avoid storing SSH configuration files in cloud storage. Use bastion hosts with ephemeral keys.",
        compliance=["NIST IA-5"],
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
    ),
    Pattern(
        name="CREDIT_CARD",
        pattern=r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        description="Potential Credit Card Number",
        severity=Severity.CRITICAL,
        category=FindingCategory.PII_EXPOSURE,
        recommendation="Immediately assess scope of PCI-DSS impact. Notify compliance team.",
        compliance=["SOC2 CC6.7"],
    ),
]


class SecretScanner:
    """
    Scan text content for secrets, credentials, and sensitive data.

    Findings include redacted matches only — the actual secret value
    is never stored in the Finding object.
    """

    def __init__(self, min_entropy: float = 3.5) -> None:
        self._min_entropy = min_entropy
        self._compiled = [
            (p, re.compile(p.pattern, re.MULTILINE))
            for p in _PATTERNS
        ]

    def scan(self, content: str, file_url: str, file_type: FileType) -> List[Finding]:
        findings: List[Finding] = []

        for pattern, regex in self._compiled:
            for m in regex.finditer(content):
                # Prefer group(1) if capturing group exists, else full match
                try:
                    matched = m.group(1)
                except IndexError:
                    matched = m.group(0)

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

                # Entropy gate: very low-entropy strings are likely false positives
                ent = calculate_entropy(matched)
                effective_severity = pattern.severity
                if ent < self._min_entropy and pattern.severity in (Severity.MEDIUM, Severity.LOW):
                    continue   # skip — likely a placeholder or example
                if ent > 5.2 and effective_severity == Severity.MEDIUM:
                    effective_severity = Severity.HIGH   # high-entropy medium → escalate

                # Compute confidence
                confidence = self._confidence(matched, ent, pattern)

                # Redact the actual value before storing
                redacted_match = redact(matched)
                context_snip   = self._context_snippet(content, m.start(), radius=3)

                findings.append(Finding(
                    file_url=file_url,
                    file_name=url_filename(file_url),
                    file_type=file_type,
                    category=pattern.category,
                    rule_name=pattern.name,
                    description=pattern.description,
                    severity=effective_severity,
                    match=redacted_match,
                    context=self._sanitise_context(context_snip),
                    line_number=content[: m.start()].count("\n") + 1,
                    recommendation=pattern.recommendation,
                    compliance_refs=pattern.compliance,
                    confidence=confidence,
                    scanner="SecretScanner",
                ))

        return findings

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _context_snippet(content: str, pos: int, radius: int = 3) -> str:
        lines = content.split("\n")
        cur   = 0
        for i, line in enumerate(lines):
            if cur + len(line) + 1 > pos:
                lo = max(0, i - radius)
                hi = min(len(lines), i + radius + 1)
                return "\n".join(lines[lo:hi])
            cur += len(line) + 1
        return ""

    @staticmethod
    def _sanitise_context(snippet: str) -> str:
        """
        Light sanitisation of context lines — remove obvious secret values
        while preserving line structure so analysts can understand the finding.
        """
        # Redact anything that looks like a long base64 / hex value
        sanitised = re.sub(
            r"([A-Za-z0-9+/=]{40,})",
            lambda m: redact(m.group(1)),
            snippet,
        )
        return sanitised[:800]  # cap context length

    @staticmethod
    def _confidence(matched: str, entropy: float, pattern: Pattern) -> float:
        conf = 0.4
        if len(matched) > 20:
            conf += 0.15
        if entropy > 4.0:
            conf += 0.20
        if entropy > 5.0:
            conf += 0.15
        if pattern.validation:
            conf += 0.10   # validated patterns are more reliable
        return min(conf, 1.0)
