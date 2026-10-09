"""cloudaudit — Custom Exception Hierarchy"""


class AuditError(Exception):
    """Base exception for all cloudaudit errors."""


class ConfigError(AuditError):
    """Invalid or missing configuration."""


class OwnershipError(AuditError):
    """Raised when ownership confirmation is missing or rejected."""


class ValidationError(AuditError):
    """Input validation failure."""


class DiscoveryError(AuditError):
    """File/directory discovery failure."""


class AnalysisError(AuditError):
    """Content analysis failure."""


class ProviderError(AuditError):
    """AI provider communication error."""


class ProviderAuthError(ProviderError):
    """Missing or invalid AI provider API key."""


class ProviderQuotaError(ProviderError):
    """The API key is valid but the account has no remaining quota / credit."""


class ArchiveError(AuditError):
    """Archive extraction failure."""


class ReportError(AuditError):
    """Report generation/rendering failure (e.g. missing optional PDF dependency)."""
