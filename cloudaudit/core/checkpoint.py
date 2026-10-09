"""
cloudaudit.core.checkpoint — Crawl/Analysis Resume Support

Periodically persists crawl + analysis progress to a JSON checkpoint file so a
long-running audit can be resumed with `--resume checkpoint.json` after being
interrupted (Ctrl+C, network blip, etc.) instead of restarting the whole crawl.

The checkpoint stores only metadata already destined for the report (exposed
file inventory, which URLs have been analysed, and findings already produced
via Finding.to_dict() — which are already redacted). Nothing sensitive that
isn't already in the eventual report is written to disk.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from cloudaudit.core.exceptions import ConfigError
from cloudaudit.core.models import ContainerInfo, ContainerType, ExposedFile, FileType, Finding

logger = logging.getLogger("cloudaudit.checkpoint")

_CHECKPOINT_VERSION = 1


def save_checkpoint(
    path: str,
    *,
    url: str,
    container: Optional[ContainerInfo],
    exposed_files: List[ExposedFile],
    analysed_urls: List[str],
    findings: List[Finding],
    crawl_complete: bool,
) -> None:
    data: Dict[str, Any] = {
        "checkpoint_version": _CHECKPOINT_VERSION,
        "url": url,
        "crawl_complete": crawl_complete,
        "container": container.to_dict() if container else None,
        "container_type_raw": container.container_type.value if container else None,
        "exposed_files": [ef.to_dict() | {"etag": ef.etag} for ef in exposed_files],
        "analysed_urls": analysed_urls,
        "findings": [f.to_dict() for f in findings],
    }
    try:
        tmp = Path(path).with_suffix(Path(path).suffix + ".tmp")
        tmp.write_text(json.dumps(data, default=str), encoding="utf-8")
        tmp.replace(path)
        logger.debug(
            "Checkpoint saved: %s (%d files, %d analysed, %d findings)",
            path, len(exposed_files), len(analysed_urls), len(findings),
        )
    except Exception as exc:
        logger.warning("Failed to write checkpoint %s: %s", path, exc)


def load_checkpoint(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"Checkpoint file not found: {path}")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ConfigError(f"Failed to parse checkpoint file {path}: {exc}") from exc

    container = None
    cdict = raw.get("container")
    if cdict:
        try:
            ctype = ContainerType(raw.get("container_type_raw") or cdict.get("container_type"))
        except ValueError:
            ctype = ContainerType.UNKNOWN
        container = ContainerInfo(
            raw_url=cdict.get("raw_url", raw.get("url", "")),
            container_type=ctype,
            container_name=cdict.get("container_name", ""),
            region=cdict.get("region", ""),
            is_public=cdict.get("is_public", True),
            server_header=cdict.get("server_header", ""),
            notes=cdict.get("notes", []),
        )

    exposed_files = []
    for efd in raw.get("exposed_files", []):
        try:
            ft = FileType(efd.get("file_type", "Other"))
        except ValueError:
            ft = FileType.OTHER
        exposed_files.append(ExposedFile(
            url=efd.get("url", ""),
            key=efd.get("key", ""),
            size_bytes=efd.get("size_bytes", 0),
            last_modified=efd.get("last_modified", ""),
            file_type=ft,
            etag=efd.get("etag", ""),
        ))

    findings = []
    for fd in raw.get("findings", []):
        try:
            findings.append(_finding_from_dict(fd))
        except Exception as exc:
            logger.debug("Skipping unparsable checkpoint finding: %s", exc)

    return {
        "url": raw.get("url", ""),
        "container": container,
        "exposed_files": exposed_files,
        "analysed_urls": set(raw.get("analysed_urls", [])),
        "findings": findings,
        "crawl_complete": bool(raw.get("crawl_complete", False)),
    }


def _finding_from_dict(fd: Dict[str, Any]) -> Finding:
    from cloudaudit.core.models import FindingCategory, Severity
    return Finding(
        file_url=fd.get("file_url", ""),
        file_name=fd.get("file_name", ""),
        file_type=FileType(fd.get("file_type", "Other")),
        category=FindingCategory(fd.get("category")),
        rule_name=fd.get("rule_name", ""),
        description=fd.get("description", ""),
        severity=Severity(fd.get("severity", "Informational")),
        match=fd.get("match", ""),
        context=fd.get("context", ""),
        line_number=fd.get("line_number"),
        recommendation=fd.get("recommendation", ""),
        compliance_refs=fd.get("compliance_refs", []),
        confidence=fd.get("confidence", 0.0),
        scanner=fd.get("scanner", "SecretScanner"),
        from_archive=fd.get("from_archive", False),
        archive_path=fd.get("archive_path", ""),
        occurrences=fd.get("occurrences", 1),
    )
