"""cloudaudit — Framework Constants"""

__version__     = "1.0.0"
__tool_name__   = "CloudAudit"
__author__      = "xtawb"
__author_url__  = "https://linktr.ee/xtawb"
__github_repo__ = "https://github.com/xtawb/cloudaudit"
__github_api__  = "https://api.github.com/repos/xtawb/cloudaudit/releases/latest"
__description__ = "Next-Generation AI-Powered Cloud Security Auditing Framework"
__tagline__     = "Powered by xtawb | Defensive. Intelligent. Enterprise-Grade."

DEFAULT_MAX_CONCURRENT   = 8
DEFAULT_TIMEOUT          = 30.0
DEFAULT_MAX_FILE_SIZE    = 20 * 1024 * 1024
DEFAULT_MAX_DEPTH        = 15
DEFAULT_RATE_LIMIT_DELAY = 0.15
DEFAULT_MAX_RETRIES      = 3
DEFAULT_RETRY_DELAY      = 1.5
DEFAULT_MIN_ENTROPY      = 4.5

MAX_ARCHIVE_EXTRACT_SIZE  = 500 * 1024 * 1024
MAX_ARCHIVE_FILE_COUNT    = 10_000
MAX_ARCHIVE_NESTING_DEPTH = 3
ARCHIVE_WORKSPACE         = "./cloudaudit_workspace"

ARCHIVE_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".bz2", ".xz",
    ".tar.gz", ".tar.bz2", ".tar.xz",
    ".7z", ".rar", ".jar", ".war", ".ear", ".whl",
}

SKIP_DOWNLOAD_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".svg",
    ".mp4", ".mp3", ".avi", ".mov", ".wav", ".flac", ".ogg",
    ".ttf", ".woff", ".woff2", ".eot",
    ".exe", ".dll", ".so", ".dylib", ".iso", ".img",
}

AWS_S3_NAMESPACES = {
    "http://s3.amazonaws.com/doc/2006-03-01/",
    "https://s3.amazonaws.com/doc/2006-03-01/",
}
AWS_S3_HEADERS = {"x-amz-request-id", "x-amz-id-2", "x-amz-bucket-region"}
GCS_HEADERS    = {"x-guploader-uploadid", "x-goog-stored-content-length"}
AZURE_HEADERS  = {"x-ms-request-id", "x-ms-version"}

PROVIDER_ENV_KEYS = {
    "gemini":   "GEMINI_API_KEY",
    "openai":   "OPENAI_API_KEY",
    "claude":   "ANTHROPIC_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "ollama":   "",
}

PROVIDER_MODEL_FALLBACKS = {
    "gemini": [
        "gemini-1.5-flash",
        "gemini-1.5-pro",
        "gemini-1.0-pro",
        "gemini-pro",
    ],
    "openai": [
        "gpt-4o-mini",
        "gpt-4o",
        "gpt-4-turbo",
        "gpt-3.5-turbo",
    ],
    "claude": [
        "claude-3-haiku-20240307",
        "claude-3-sonnet-20240229",
        "claude-3-opus-20240229",
    ],
    "deepseek": [
        "deepseek-chat",
        "deepseek-coder",
    ],
}

COMPLIANCE_FRAMEWORKS = {
    "CIS": {
        "public_access":   "CIS 2.1 — Ensure S3 bucket is not publicly accessible",
        "encryption":      "CIS 2.2 — Ensure server-side encryption is enabled",
        "versioning":      "CIS 2.3 — Ensure versioning is enabled",
        "logging":         "CIS 2.4 — Ensure access logging is enabled",
        "secret_exposure": "CIS 2.1.5 — Sensitive data must not be publicly exposed",
    },
    "NIST": {
        "public_access":   "NIST 800-53 SC-7 — Boundary Protection",
        "secret_exposure": "NIST 800-53 IA-5 — Authenticator Management",
        "logging":         "NIST 800-53 AU-12 — Audit Record Generation",
        "encryption":      "NIST 800-53 SC-28 — Protection of Information at Rest",
    },
    "SOC2": {
        "public_access":   "SOC2 CC6.1 — Logical and Physical Access Controls",
        "secret_exposure": "SOC2 CC6.7 — Transmission of Confidential Information",
        "logging":         "SOC2 CC7.2 — System Monitoring",
    },
    "ISO27001": {
        "public_access":   "ISO27001 A.13.1 — Network Security Management",
        "secret_exposure": "ISO27001 A.9.2 — User Access Management",
        "logging":         "ISO27001 A.12.4 — Logging and Monitoring",
    },
    "PCI-DSS": {
        "secret_exposure": "PCI-DSS Req 6.3.1 — Sensitive data must be protected",
        "public_access":   "PCI-DSS Req 1.3 — Prohibit direct public access",
        "logging":         "PCI-DSS Req 10 — Track and monitor all access",
    },
}

ENTROPY_THRESHOLDS = {
    "LOW":      3.0,
    "MEDIUM":   4.0,
    "HIGH":     4.5,
    "CRITICAL": 5.0,
}

CONFIG_DIR       = "~/.cloudaudit"
CONFIG_FILE      = "~/.cloudaudit/config.enc"
CONFIG_SALT_FILE = "~/.cloudaudit/.salt"
