"""
cloudaudit.intelligence.baseline — Baseline / Allowlist Suppression

Loads a JSON or YAML file listing finding fingerprints that have been
reviewed and accepted as known/acceptable risk, and filters them out of
a scan's findings so recurring audits only surface *new* issues.

Fingerprint format: sha256(rule_name + "|" + file_url + "|" + file_name)[:16]
(see cloudaudit.utils.helpers.finding_fingerprint).

Baseline file formats supported:

    # JSON
    {"suppressed": ["<fingerprint>", ...]}
    # or simply a JSON list: ["<fingerprint>", ...]

    # YAML
    suppressed:
      - <fingerprint>   # AWS_ACCESS_KEY on s3://bucket/legacy/config.env
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Set

from cloudaudit.core.exceptions import ConfigError
from cloudaudit.core.models import Finding
from cloudaudit.utils.helpers import finding_fingerprint

logger = logging.getLogger("cloudaudit.baseline")


def load_baseline(path: str) -> Set[str]:
    """Load a set of accepted-risk fingerprints from a JSON or YAML file."""
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"Baseline file not found: {path}")

    text = p.read_text(encoding="utf-8")
    data = None

    if p.suffix.lower() in (".yml", ".yaml"):
        try:
            import yaml
            data = yaml.safe_load(text)
        except ImportError as exc:
            raise ConfigError("pyyaml is required to load YAML baseline files.") from exc
        except Exception as exc:
            raise ConfigError(f"Failed to parse YAML baseline file {path}: {exc}") from exc
    else:
        try:
            data = json.loads(text)
        except Exception as exc:
            # Fall back to YAML parsing — it's a JSON superset for simple structures
            try:
                import yaml
                data = yaml.safe_load(text)
            except Exception:
                raise ConfigError(f"Failed to parse baseline file {path}: {exc}") from exc

    if isinstance(data, dict):
        items = data.get("suppressed", data.get("fingerprints", []))
    elif isinstance(data, list):
        items = data
    else:
        items = []

    fingerprints = {str(x).strip() for x in items if str(x).strip()}
    logger.info("Loaded %d baseline fingerprint(s) from %s", len(fingerprints), path)
    return fingerprints


def apply_baseline(findings: List[Finding], baseline: Set[str]) -> tuple[List[Finding], int]:
    """
    Split findings into (kept, suppressed_count) based on the baseline fingerprint set.
    """
    if not baseline:
        return findings, 0

    kept: List[Finding] = []
    suppressed = 0
    for f in findings:
        fp = finding_fingerprint(f.rule_name, f.file_url, f.file_name)
        if fp in baseline:
            suppressed += 1
        else:
            kept.append(f)
    return kept, suppressed
