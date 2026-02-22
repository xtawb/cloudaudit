"""cloudaudit — Core Data Models"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Enumerations ───────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL      = "Critical"
    HIGH          = "High"
    MEDIUM        = "Medium"
    LOW           = "Low"
    INFORMATIONAL = "Informational"

    @property
    def int_value(self) -> int:
        return {
            Severity.INFORMATIONAL: 0,
            Severity.LOW:           1,
            Severity.MEDIUM:        2,
            Severity.HIGH:          3,
            Severity.CRITICAL:      4,
        }[self]

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.int_value < other.int_value


class ContainerType(str, Enum):
    AWS_S3         = "AWS S3"
    GCS            = "Google Cloud Storage"
    AZURE_BLOB     = "Azure Blob Storage"
    CLOUDFRONT     = "CloudFront (CDN)"
    OPEN_DIRECTORY = "Open Directory Listing"
    GENERIC        = "Generic Web File Listing"
    UNKNOWN        = "Unknown"


class FileType(str, Enum):
    JAVASCRIPT  = "JavaScript"
    TYPESCRIPT  = "TypeScript"
    JSON        = "JSON"
    CONFIG      = "Configuration"
    ENVIRONMENT = "Environment"
    SHELL       = "Shell Script"
    PYTHON      = "Python"
    RUBY        = "Ruby"
    PHP         = "PHP"
    TERRAFORM   = "Terraform"
    SQL         = "SQL / Database Dump"
    CERTIFICATE = "Certificate / Key"
    ARCHIVE     = "Archive"
    IMAGE       = "Image"
    DOCUMENT    = "Document"
    BINARY      = "Binary"
    OTHER       = "Other"


class FindingCategory(str, Enum):
    SECRET_EXPOSURE    = "Secret Exposure"
    PUBLIC_ACCESS      = "Public Access Misconfiguration"
    METADATA_LEAKAGE   = "Metadata / EXIF Leakage"
    INFRASTRUCTURE_INF = "Infrastructure Information"
    CREDENTIAL_FILE    = "Credential File Exposed"
    PII_EXPOSURE       = "PII / Personal Data"
    ARCHIVE_CONTENT    = "Sensitive Archive Content"
    COMPLIANCE         = "Compliance Gap"


# ── Container metadata ─────────────────────────────────────────────────────────

@dataclass
class ContainerInfo:
    """Metadata about the detected cloud storage container."""
    raw_url:        str
    container_type: ContainerType = ContainerType.UNKNOWN
    container_name: str = ""
    region:         str = ""
    is_public:      bool = True       # We detected a listing — so yes
    supports_put:   Optional[bool] = None
    supports_delete:Optional[bool] = None
    server_header:  str = ""
    extra_headers:  Dict[str, str] = field(default_factory=dict)
    notes:          List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_url":        self.raw_url,
            "container_type": self.container_type.value,
            "container_name": self.container_name,
            "region":         self.region,
            "is_public":      self.is_public,
            "server_header":  self.server_header,
            "notes":          self.notes,
        }


# ── Findings ───────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single security or compliance finding."""
    file_url:        str
    file_name:       str
    file_type:       FileType
    category:        FindingCategory
    rule_name:       str
    description:     str
    severity:        Severity
    match:           str                    # Redacted/truncated match
    context:         str = ""              # Surrounding lines (redacted)
    line_number:     Optional[int] = None
    recommendation:  str = ""
    compliance_refs: List[str] = field(default_factory=list)
    confidence:      float = 0.0
    scanner:         str = "SecretScanner"
    from_archive:    bool = False          # Was this found inside an extracted archive?
    archive_path:    str = ""             # Path within archive

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_url":        self.file_url,
            "file_name":       self.file_name,
            "file_type":       self.file_type.value,
            "category":        self.category.value,
            "rule_name":       self.rule_name,
            "description":     self.description,
            "severity":        self.severity.value,
            "match":           self.match,
            "context":         self.context,
            "line_number":     self.line_number,
            "recommendation":  self.recommendation,
            "compliance_refs": self.compliance_refs,
            "confidence":      round(self.confidence, 3),
            "scanner":         self.scanner,
            "from_archive":    self.from_archive,
            "archive_path":    self.archive_path,
        }


@dataclass
class ExposedFile:
    """Metadata about a discovered file (before content analysis)."""
    url:         str
    key:         str          # S3/GCS/Azure object key or relative path
    size_bytes:  int = 0
    last_modified: str = ""
    file_type:   FileType = FileType.OTHER
    etag:        str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url":          self.url,
            "key":          self.key,
            "size_bytes":   self.size_bytes,
            "last_modified":self.last_modified,
            "file_type":    self.file_type.value,
        }


# ── Scan statistics ────────────────────────────────────────────────────────────

@dataclass
class ScanStats:
    """Aggregated results from a full audit scan."""
    container_info:    Optional[ContainerInfo] = None
    total_files:       int = 0
    scanned_files:     int = 0
    skipped_files:     int = 0
    archive_files:     int = 0       # Archives downloaded and extracted
    findings:          List[Finding] = field(default_factory=list)
    errors:            List[str] = field(default_factory=list)
    ai_summary:        str = ""      # Executive summary from AI provider
    risk_score:        float = 0.0   # 0–10 computed risk score
    start_time:        float = field(default_factory=time.time)
    exposed_files:     List[ExposedFile] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        elapsed = round(time.time() - self.start_time, 2)
        return {
            "container":     self.container_info.to_dict() if self.container_info else {},
            "total_files":   self.total_files,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "archive_files": self.archive_files,
            "findings":      [f.to_dict() for f in self.findings],
            "errors":        self.errors,
            "ai_summary":    self.ai_summary,
            "risk_score":    self.risk_score,
            "elapsed_sec":   elapsed,
        }
