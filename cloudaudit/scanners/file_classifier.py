"""cloudaudit — File Type Classifier"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from cloudaudit.core.models import FileType


_EXT_MAP: dict[str, FileType] = {
    # JavaScript / TypeScript
    ".js":   FileType.JAVASCRIPT,
    ".mjs":  FileType.JAVASCRIPT,
    ".cjs":  FileType.JAVASCRIPT,
    ".ts":   FileType.TYPESCRIPT,
    # JSON
    ".json": FileType.JSON,
    ".jsonc":FileType.JSON,
    # Config
    ".yaml": FileType.CONFIG,
    ".yml":  FileType.CONFIG,
    ".toml": FileType.CONFIG,
    ".ini":  FileType.CONFIG,
    ".conf": FileType.CONFIG,
    ".cfg":  FileType.CONFIG,
    ".config": FileType.CONFIG,
    ".xml":  FileType.CONFIG,
    ".tf":   FileType.TERRAFORM,
    ".tfvars": FileType.TERRAFORM,
    # Environment
    ".env":  FileType.ENVIRONMENT,
    ".properties": FileType.ENVIRONMENT,
    # Shell
    ".sh":   FileType.SHELL,
    ".bash": FileType.SHELL,
    ".zsh":  FileType.SHELL,
    ".ps1":  FileType.SHELL,
    # Python
    ".py":   FileType.PYTHON,
    # Ruby
    ".rb":   FileType.RUBY,
    # PHP
    ".php":  FileType.PHP,
    # SQL
    ".sql":  FileType.SQL,
    ".dump": FileType.SQL,
    # Certificates / Keys
    ".pem":  FileType.CERTIFICATE,
    ".key":  FileType.CERTIFICATE,
    ".crt":  FileType.CERTIFICATE,
    ".cer":  FileType.CERTIFICATE,
    ".p12":  FileType.CERTIFICATE,
    ".pfx":  FileType.CERTIFICATE,
    # Archives
    ".zip":  FileType.ARCHIVE,
    ".tar":  FileType.ARCHIVE,
    ".gz":   FileType.ARCHIVE,
    ".bz2":  FileType.ARCHIVE,
    ".xz":   FileType.ARCHIVE,
    ".7z":   FileType.ARCHIVE,
    ".rar":  FileType.ARCHIVE,
    ".jar":  FileType.ARCHIVE,
    ".war":  FileType.ARCHIVE,
    ".ear":  FileType.ARCHIVE,
    # Images
    ".jpg":  FileType.IMAGE,
    ".jpeg": FileType.IMAGE,
    ".png":  FileType.IMAGE,
    ".gif":  FileType.IMAGE,
    ".tiff": FileType.IMAGE,
    # Documents
    ".pdf":  FileType.DOCUMENT,
    ".doc":  FileType.DOCUMENT,
    ".docx": FileType.DOCUMENT,
    ".xls":  FileType.DOCUMENT,
    ".xlsx": FileType.DOCUMENT,
    # Binary
    ".exe":  FileType.BINARY,
    ".dll":  FileType.BINARY,
    ".so":   FileType.BINARY,
    ".dylib":FileType.BINARY,
}

_SPECIAL_NAMES: dict[str, FileType] = {
    ".env":        FileType.ENVIRONMENT,
    "dockerfile":  FileType.CONFIG,
    ".htpasswd":   FileType.CONFIG,
    ".htaccess":   FileType.CONFIG,
    ".npmrc":      FileType.ENVIRONMENT,
    ".pypirc":     FileType.ENVIRONMENT,
    ".netrc":      FileType.ENVIRONMENT,
    "id_rsa":      FileType.CERTIFICATE,
    "id_ed25519":  FileType.CERTIFICATE,
    "authorized_keys": FileType.CERTIFICATE,
}


class FileClassifier:

    @classmethod
    def classify(cls, url_or_path: str) -> FileType:
        path = Path(urlparse(url_or_path).path)
        name = path.name.lower()
        ext  = path.suffix.lower()

        # Check special names first
        if name in _SPECIAL_NAMES:
            return _SPECIAL_NAMES[name]

        # Then extension map
        return _EXT_MAP.get(ext, FileType.OTHER)

    @classmethod
    def is_text_analysable(cls, ft: FileType) -> bool:
        return ft in {
            FileType.JAVASCRIPT,
            FileType.TYPESCRIPT,
            FileType.JSON,
            FileType.CONFIG,
            FileType.ENVIRONMENT,
            FileType.SHELL,
            FileType.PYTHON,
            FileType.RUBY,
            FileType.PHP,
            FileType.SQL,
            FileType.TERRAFORM,
            FileType.CERTIFICATE,
            FileType.OTHER,
        }

    @classmethod
    def is_archive(cls, ft: FileType) -> bool:
        return ft == FileType.ARCHIVE

    @classmethod
    def is_image(cls, ft: FileType) -> bool:
        return ft == FileType.IMAGE
