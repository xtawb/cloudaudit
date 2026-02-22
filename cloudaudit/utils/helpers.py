"""cloudaudit — Utility Helpers"""

from __future__ import annotations

import math
import time
from pathlib import Path
from urllib.parse import urlparse


def calculate_entropy(data: str) -> float:
    """Shannon entropy of a string. Higher == more random == more likely a real secret."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def url_filename(url: str) -> str:
    return Path(urlparse(url).path).name or url


def url_extension(url: str) -> str:
    return Path(urlparse(url).path).suffix.lower()


def truncate(value: str, max_len: int = 80) -> str:
    """Truncate string with ellipsis — used to avoid logging full secrets."""
    if len(value) <= max_len:
        return value
    keep = max_len // 2
    return value[:keep] + " … " + value[-keep:]


def redact(value: str, keep_chars: int = 6) -> str:
    """Partially redact a sensitive value for display in reports."""
    if len(value) <= keep_chars:
        return "***"
    return value[:keep_chars] + "***"


def elapsed(start: float) -> float:
    return round(time.time() - start, 2)


def human_size(n_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n_bytes < 1024:
            return f"{n_bytes:.1f} {unit}"
        n_bytes //= 1024
    return f"{n_bytes:.1f} TB"


def safe_filename(name: str) -> str:
    """Sanitise a string for use as a filesystem filename."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
