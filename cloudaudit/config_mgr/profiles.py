"""
cloudaudit.config_mgr.profiles — Named CLI Flag Profiles

Lets a user save the CLI flags for a common scan (concurrency, extensions,
format, AI provider, etc.) as a reusable named profile at
``~/.cloudaudit/profiles/<name>.yml``, then reload it with ``--profile NAME``
on a future invocation.

Design:
  * Profiles are plain YAML — human-editable, diffable, safe to check in
    (minus secrets, which are deliberately never written to a profile).
  * ``cloudaudit config --save-profile NAME`` persists the *other* CLI flags
    given on that same command line (any top-level scan flag provided before
    the ``config`` subcommand token is merged into the same argparse
    Namespace, so this "just works": e.g.
    ``cloudaudit --extract-archives --threads 20 --format sarif config --save-profile ci``).
  * ``--profile NAME`` loads the profile; any flag explicitly supplied on
    that invocation's command line still takes precedence over the profile's
    stored value (see ``cli.main.apply_profile``).
  * API keys and one-shot per-run inputs (target URL, ownership flags,
    subcommand-only args) are never persisted to a profile file.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List

from cloudaudit.core.constants import PROFILES_DIR
from cloudaudit.core.exceptions import ConfigError

logger = logging.getLogger("cloudaudit.profiles")

# Flags that must never be written to a profile file, either because they are
# secrets, or because they are meaningless outside a single invocation.
EXCLUDED_KEYS = {
    "subcommand", "api_key", "set_api", "list_providers", "remove_api",
    "save_profile", "profile", "old_report", "new_report", "limit",
    "url", "targets_file", "scan_docker_image", "confirm_ownership",
    "org_name", "output", "resume", "checkpoint",
}


def profiles_dir() -> Path:
    p = Path(os.path.expanduser(PROFILES_DIR))
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    return p


def profile_path(name: str) -> Path:
    safe = "".join(c if (c.isalnum() or c in "-_") else "_" for c in name.strip())
    if not safe:
        raise ConfigError("Profile name must contain at least one alphanumeric character.")
    return profiles_dir() / f"{safe}.yml"


def save_profile(name: str, values: Dict[str, Any]) -> Path:
    """Persist ``values`` (a CLI args namespace as a dict) as a named profile."""
    try:
        import yaml
    except ImportError as exc:
        raise ConfigError("pyyaml is required to save/load profiles.") from exc

    clean: Dict[str, Any] = {}
    for key, value in values.items():
        if key in EXCLUDED_KEYS:
            continue
        if value is None or value is False:
            continue
        if isinstance(value, (set, frozenset)):
            value = sorted(value)
        clean[key] = value

    path = profile_path(name)
    path.write_text(yaml.safe_dump(clean, sort_keys=True, default_flow_style=False), encoding="utf-8")
    logger.info("Saved profile %r to %s (%d flag(s))", name, path, len(clean))
    return path


def load_profile(name: str) -> Dict[str, Any]:
    """Load a previously saved profile. Raises ConfigError if it doesn't exist."""
    try:
        import yaml
    except ImportError as exc:
        raise ConfigError("pyyaml is required to save/load profiles.") from exc

    path = profile_path(name)
    if not path.exists():
        raise ConfigError(
            f"Profile {name!r} not found at {path}. "
            f"List saved profiles at {profiles_dir()}."
        )
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise ConfigError(f"Failed to parse profile {name!r}: {exc}") from exc
    return data if isinstance(data, dict) else {}


def list_profiles() -> List[str]:
    return sorted(p.stem for p in profiles_dir().glob("*.yml"))
