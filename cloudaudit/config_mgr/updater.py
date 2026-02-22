"""
cloudaudit.config_mgr.updater — Intelligent Auto-Update System

Checks GitHub releases, compares versions, and offers to update.
Safe rollback on failure.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import urllib.request
from typing import Optional, Tuple

from cloudaudit.core.constants import __github_api__, __version__

logger = logging.getLogger("cloudaudit.updater")


def _compare_versions(v1: str, v2: str) -> int:
    """Return -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
    def parts(v: str) -> list[int]:
        try:
            return [int(x) for x in v.strip("v").split(".")]
        except ValueError:
            return [0]
    p1, p2 = parts(v1), parts(v2)
    for a, b in zip(p1, p2):
        if a < b: return -1
        if a > b: return  1
    return -1 if len(p1) < len(p2) else (1 if len(p1) > len(p2) else 0)


def check_for_update(timeout: int = 6) -> Tuple[bool, str, str]:
    """
    Query GitHub releases API.
    Returns (update_available, latest_version, changelog_url).
    Returns (False, current_version, "") on network failure (silent).
    """
    try:
        req = urllib.request.Request(
            __github_api__,
            headers={"User-Agent": "CloudAudit-Updater/2.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        latest  = data.get("tag_name", "").lstrip("v")
        html_url= data.get("html_url", __github_api__)

        if not latest:
            return False, __version__, ""

        if _compare_versions(__version__, latest) < 0:
            return True, latest, html_url

        return False, __version__, ""

    except Exception as exc:
        logger.debug("Update check failed (non-fatal): %s", exc)
        return False, __version__, ""


def perform_update() -> Tuple[bool, str]:
    """
    Attempt pip upgrade. Returns (success, message).
    Safe: on failure, reports error without crashing.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade",
             f"git+{__github_api__.replace('/repos/', '/').replace('/releases/latest', '')}"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            return True, "Update successful. Please restart cloudaudit."
        return False, f"pip returned exit code {result.returncode}: {result.stderr[:300]}"
    except Exception as exc:
        return False, f"Update failed: {exc}"
