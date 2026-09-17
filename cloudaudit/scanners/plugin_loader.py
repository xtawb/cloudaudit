"""
cloudaudit.scanners.plugin_loader — Third-Party Scanner Plugin System

Third-party packages can contribute additional content scanners to
CloudAudit's Phase 4 concurrent content analysis without modifying this
codebase, by registering a Python packaging entry point in the
``cloudaudit.scanners`` group.

Plugin interface
-----------------

An entry point must resolve to either a class (instantiated with no
arguments) or a ready-made object exposing a single method:

    def scan(self, file_content: str, file_meta: dict) -> list[Finding]:
        ...

``file_meta`` is a plain dict with at least the keys:

    - ``url``       (str)       — the file's source URL
    - ``file_name`` (str)       — the basename of the file
    - ``file_type`` (FileType)  — the classified file type

Example ``pyproject.toml`` for a plugin package::

    [project.entry-points."cloudaudit.scanners"]
    my_plugin = "my_package.scanner:MySecretScanner"

Safety
------

Plugins run read-only, in-process, against content CloudAudit has already
downloaded — they receive no network access of their own and cannot alter
the audit's read-only HTTP behaviour. A plugin that raises, returns garbage,
or fails to import is logged and skipped; it can never abort a scan.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from cloudaudit.core.constants import SCANNER_PLUGIN_ENTRY_POINT_GROUP
from cloudaudit.core.models import Finding

logger = logging.getLogger("cloudaudit.plugin_loader")


def discover_plugins() -> List[Any]:
    """
    Discover and instantiate all third-party scanner plugins registered
    under the ``cloudaudit.scanners`` entry point group.

    Never raises — discovery failures are logged and result in an empty list.
    """
    plugins: List[Any] = []
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover — py<3.8, unsupported anyway
        return plugins

    try:
        eps = entry_points()
        if hasattr(eps, "select"):  # Python 3.10+
            group = eps.select(group=SCANNER_PLUGIN_ENTRY_POINT_GROUP)
        else:  # pragma: no cover — Python 3.9 and earlier
            group = eps.get(SCANNER_PLUGIN_ENTRY_POINT_GROUP, [])
    except Exception as exc:
        logger.debug("Scanner plugin discovery failed: %s", exc)
        return plugins

    for ep in group:
        try:
            loaded = ep.load()
            plugin = loaded() if isinstance(loaded, type) else loaded
            if not hasattr(plugin, "scan") or not callable(getattr(plugin, "scan")):
                logger.warning("Scanner plugin %r does not implement scan() — skipping.", ep.name)
                continue
            plugins.append(plugin)
            logger.info("Loaded third-party scanner plugin: %s", ep.name)
        except Exception as exc:
            logger.warning("Failed to load scanner plugin %r: %s", ep.name, exc)

    return plugins


def run_plugins(plugins: List[Any], content: str, file_meta: Dict[str, Any]) -> List[Finding]:
    """
    Run every discovered plugin against one file's content.

    Never raises — a misbehaving plugin's contribution for this file is
    simply dropped, and the scan continues normally.
    """
    findings: List[Finding] = []
    for plugin in plugins:
        try:
            result = plugin.scan(content, file_meta)
        except Exception as exc:
            logger.warning("Scanner plugin %r raised during scan(): %s", type(plugin).__name__, exc)
            continue
        if not result:
            continue
        for f in result:
            if isinstance(f, Finding):
                findings.append(f)
            else:
                logger.warning(
                    "Scanner plugin %r returned a non-Finding object — ignoring.", type(plugin).__name__
                )
    return findings
