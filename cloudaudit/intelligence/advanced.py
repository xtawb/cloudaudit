"""
cloudaudit.intelligence.advanced — Advanced Detection Algorithms

Implements:
  1. High-entropy string detection with statistical analysis
  2. Duplicate secret detection (same secret in multiple files)
  3. Secret reuse detection (same credential pattern, different values)
  4. Exposure surface mapping (which files expose what)
  5. Cloud misconfiguration pattern analysis
  6. Fingerprinting of known secret formats
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from cloudaudit.core.models import FileType, Finding, FindingCategory, Severity
from cloudaudit.utils.helpers import calculate_entropy, redact, url_filename


# ── High-entropy string hunter ─────────────────────────────────────────────────

@dataclass
class EntropyHit:
    value:      str         # Redacted
    entropy:    float
    line_number:int
    context:    str         # Surrounding line(s), sanitised


class EntropyHunter:
    """
    Scans for high-entropy strings that may be secrets not caught by regex patterns.
    Uses sliding-window analysis and character set profiling to reduce false positives.
    """

    # Minimum length to consider — short strings have high entropy naturally
    MIN_LEN = 16
    MAX_LEN = 512

    # Known false-positive patterns (hashes, UUIDs, etc. that aren't secrets)
    FP_PATTERNS = [
        re.compile(r"^[a-f0-9]{32}$"),          # MD5 hash
        re.compile(r"^[a-f0-9]{40}$"),          # SHA1 hash
        re.compile(r"^[a-f0-9]{64}$"),          # SHA256 hash
        re.compile(r"^[0-9a-f-]{36}$"),         # UUID
        re.compile(r"^\d+$"),                    # Pure numeric
        re.compile(r"^[A-Z_]+$"),               # ALL_CAPS constants
        re.compile(r"^\d{4}-\d{2}-\d{2}"),     # Date
        re.compile(r"^https?://"),              # URLs
    ]

    # Token separators
    _SPLIT_RE = re.compile(r'[\s=:"\',;<>()\[\]{}]+')

    def scan(self, content: str, threshold: float = 4.5) -> List[EntropyHit]:
        hits: List[EntropyHit] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            tokens = self._SPLIT_RE.split(line)
            for token in tokens:
                token = token.strip()
                if not (self.MIN_LEN <= len(token) <= self.MAX_LEN):
                    continue
                if self._is_false_positive(token):
                    continue

                ent = calculate_entropy(token)
                if ent >= threshold:
                    # Additional validation: require mixed character classes
                    if self._has_mixed_chars(token):
                        ctx = lines[max(0, line_num-2):line_num+1]
                        hits.append(EntropyHit(
                            value=redact(token),
                            entropy=round(ent, 3),
                            line_number=line_num,
                            context="\n".join(ctx)[:200],
                        ))

        return hits

    def _is_false_positive(self, token: str) -> bool:
        for pat in self.FP_PATTERNS:
            if pat.match(token):
                return True
        # Skip very repetitive strings (aaaaaaa...)
        unique_ratio = len(set(token)) / len(token)
        if unique_ratio < 0.3:
            return True
        return False

    @staticmethod
    def _has_mixed_chars(token: str) -> bool:
        """Has at least 2 of: upper, lower, digit, special."""
        has = [
            any(c.isupper() for c in token),
            any(c.islower() for c in token),
            any(c.isdigit() for c in token),
            any(not c.isalnum() for c in token),
        ]
        return sum(has) >= 2


# ── Duplicate and reuse detection ──────────────────────────────────────────────

class SecretDeduplicator:
    """
    Tracks seen secret hashes to detect:
      1. Exact duplicates (same value in multiple files)
      2. Credential reuse by rule (same API_KEY pattern appearing in many files)
    """

    def __init__(self) -> None:
        # hash -> list of (file_url, rule_name)
        self._seen_hashes: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        # rule_name -> set of file_urls
        self._rule_files: Dict[str, Set[str]] = defaultdict(set)

    def register(self, finding: Finding) -> None:
        # Use a hash of the match so we never store the actual value
        h = hashlib.sha256(finding.match.encode()).hexdigest()[:16]
        self._seen_hashes[h].append((finding.file_url, finding.rule_name))
        self._rule_files[finding.rule_name].add(finding.file_url)

    def get_duplicate_findings(self) -> List[Finding]:
        """Return synthetic findings for secrets that appear in multiple files."""
        duplicates: List[Finding] = []
        for h, occurrences in self._seen_hashes.items():
            if len(occurrences) < 2:
                continue
            files = list({url for url, _ in occurrences})
            rule  = occurrences[0][1]
            duplicates.append(Finding(
                file_url=occurrences[0][0],
                file_name="[Multiple Files]",
                file_type=FileType.OTHER,
                category=FindingCategory.SECRET_EXPOSURE,
                rule_name=f"DUPLICATE_SECRET:{rule}",
                description=(
                    f"The same secret value ({rule}) was found in {len(files)} different files: "
                    + ", ".join(url_filename(f) for f in files[:5])
                    + ("..." if len(files) > 5 else "")
                ),
                severity=Severity.CRITICAL,
                match=f"[redacted — duplicated across {len(files)} files]",
                recommendation=(
                    "A secret appearing in multiple files indicates credential sharing or copy-paste "
                    "deployment practices. Each service should have a unique, scoped credential. "
                    "Rotate all affected credentials immediately."
                ),
                compliance_refs=["NIST IA-5", "SOC2 CC6.7"],
                confidence=0.99,
                scanner="SecretDeduplicator",
            ))
        return duplicates

    def get_reuse_findings(self, min_files: int = 3) -> List[Finding]:
        """Return findings for rules that appear across many files (credential reuse pattern)."""
        reuse: List[Finding] = []
        for rule, files in self._rule_files.items():
            if len(files) < min_files:
                continue
            reuse.append(Finding(
                file_url=next(iter(files)),
                file_name="[Multiple Files]",
                file_type=FileType.OTHER,
                category=FindingCategory.SECRET_EXPOSURE,
                rule_name=f"CREDENTIAL_REUSE:{rule}",
                description=(
                    f"Credential type '{rule}' detected across {len(files)} files, "
                    "suggesting widespread credential sharing or insecure deployment patterns."
                ),
                severity=Severity.HIGH,
                match=f"[{len(files)} files affected]",
                recommendation=(
                    "Implement per-service, scoped credentials. Use IAM roles instead of "
                    "hardcoded keys. Rotate all affected credentials."
                ),
                compliance_refs=["NIST IA-5", "CIS 2.1"],
                confidence=0.85,
                scanner="SecretDeduplicator",
            ))
        return reuse


# ── Exposure surface mapper ────────────────────────────────────────────────────

@dataclass
class ExposureSurface:
    """Summarises what categories of data are exposed across the entire container."""
    credential_types:   List[str] = field(default_factory=list)
    pii_categories:     List[str] = field(default_factory=list)
    infra_details:      List[str] = field(default_factory=list)
    compliance_gaps:    List[str] = field(default_factory=list)
    highest_severity:   Optional[Severity] = None
    total_exposure_score: float = 0.0

    def summary(self) -> str:
        parts = []
        if self.credential_types:
            parts.append(f"Credentials: {', '.join(self.credential_types[:5])}")
        if self.pii_categories:
            parts.append(f"PII: {', '.join(self.pii_categories)}")
        if self.infra_details:
            parts.append(f"Infrastructure: {', '.join(self.infra_details[:3])}")
        return " | ".join(parts) if parts else "No significant exposure surface"


class ExposureMapper:
    """Maps findings to an exposure surface summary."""

    _CREDENTIAL_RULES = {
        "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SESSION_TOKEN",
        "GCP_API_KEY", "GCP_SERVICE_ACCOUNT_KEY", "GCP_OAUTH_TOKEN",
        "AZURE_STORAGE_KEY", "AZURE_SAS_TOKEN",
        "GITHUB_PAT", "GITLAB_TOKEN",
        "DATABASE_URL", "GENERIC_API_KEY", "HARDCODED_PASSWORD",
        "PRIVATE_KEY", "JWT_TOKEN",
    }
    _PII_RULES = {"EMAIL_ADDRESS", "CREDIT_CARD"}
    _INFRA_RULES = {"INTERNAL_IP", "SSH_CONFIG"}

    def map(self, findings: List[Finding]) -> ExposureSurface:
        surface = ExposureSurface()
        seen_creds: Set[str] = set()
        seen_pii:   Set[str] = set()
        seen_infra: Set[str] = set()
        max_sev_val = -1

        for f in findings:
            base_rule = f.rule_name.split(":")[-1]  # strip DUPLICATE: prefix

            if base_rule in self._CREDENTIAL_RULES:
                label = f.description.split("(")[0].strip()
                seen_creds.add(label)
            if base_rule in self._PII_RULES:
                seen_pii.add(f.description)
            if base_rule in self._INFRA_RULES:
                seen_infra.add(f.description)

            if f.severity.int_value > max_sev_val:
                max_sev_val = f.severity.int_value
                surface.highest_severity = f.severity

            # Compliance gaps
            for ref in f.compliance_refs:
                framework = ref.split(" ")[0]
                if framework not in surface.compliance_gaps:
                    surface.compliance_gaps.append(framework)

        surface.credential_types = sorted(seen_creds)
        surface.pii_categories   = sorted(seen_pii)
        surface.infra_details    = sorted(seen_infra)

        # Simple exposure score
        surface.total_exposure_score = (
            len(seen_creds) * 2.0
            + len(seen_pii) * 1.5
            + len(seen_infra) * 0.5
        )

        return surface


# ── Cloud misconfiguration patterns ───────────────────────────────────────────

@dataclass
class MisconfigFinding:
    name:           str
    description:    str
    severity:       Severity
    recommendation: str
    compliance_refs: List[str]


class MisconfigAnalyzer:
    """
    Analyses container-level and file-level misconfigurations.
    Works on metadata, not file content.
    """

    def analyse_bucket_exposure(
        self, is_public: bool, container_type: str, notes: List[str]
    ) -> List[MisconfigFinding]:
        findings: List[MisconfigFinding] = []

        if is_public:
            findings.append(MisconfigFinding(
                name="PUBLIC_BUCKET_ACCESS",
                description=(
                    f"The {container_type} container is publicly accessible without authentication. "
                    "Any file listed can be downloaded by an unauthenticated user on the internet."
                ),
                severity=Severity.CRITICAL,
                recommendation=(
                    "Enable Block Public Access (S3) / set container to Private (Azure) / "
                    "enable Uniform Bucket-Level Access (GCS). "
                    "Review bucket policy and ACLs. Remove any public ACL grants."
                ),
                compliance_refs=["CIS 2.1", "NIST SC-7", "SOC2 CC6.1", "PCI-DSS Req 1.3"],
            ))

        return findings

    def analyse_file_inventory(
        self, file_keys: List[str]
    ) -> List[MisconfigFinding]:
        """Detect sensitive files that should never be in cloud storage."""
        findings: List[MisconfigFinding] = []
        sensitive_patterns = [
            (r"\.env$",           "Environment variable file",      Severity.CRITICAL),
            (r"id_rsa$",          "RSA private key",                Severity.CRITICAL),
            (r"\.pem$",           "PEM certificate/key",            Severity.CRITICAL),
            (r"\.p12$|\.pfx$",    "PKCS12 certificate bundle",      Severity.CRITICAL),
            (r"credentials$",     "Credentials file",               Severity.CRITICAL),
            (r"\.htpasswd$",      "Apache password file",           Severity.HIGH),
            (r"wp-config\.php",   "WordPress configuration",        Severity.HIGH),
            (r"database\.yml",    "Database configuration",         Severity.HIGH),
            (r"settings\.py$",    "Django settings file",           Severity.HIGH),
            (r"\.npmrc$",         "NPM configuration (may have token)", Severity.MEDIUM),
            (r"\.netrc$",         "Netrc credentials file",         Severity.CRITICAL),
            (r"terraform\.tfstate","Terraform state (may contain secrets)", Severity.HIGH),
        ]

        matched_patterns: Set[str] = set()
        for key in file_keys:
            key_lower = key.lower()
            for pattern, label, severity in sensitive_patterns:
                if re.search(pattern, key_lower) and pattern not in matched_patterns:
                    matched_patterns.add(pattern)
                    findings.append(MisconfigFinding(
                        name=f"SENSITIVE_FILE_EXPOSED:{pattern.strip(r'^$')}",
                        description=f"{label} ({key}) is publicly accessible in cloud storage.",
                        severity=severity,
                        recommendation=(
                            f"Remove {key} from cloud storage immediately. "
                            "If credentials were stored here, rotate them. "
                            "Add this path to .gitignore and cloud storage lifecycle rules."
                        ),
                        compliance_refs=["NIST IA-5", "CIS 2.1.5", "SOC2 CC6.7"],
                    ))

        return findings
