"""
cloudaudit.config_mgr.history — Local Scan History

Records a one-row summary of every scan to a local SQLite database at
~/.cloudaudit/history.db, so users can track posture over time with
`cloudaudit history [--limit N]` without needing any external service.

No finding content (secrets, redacted matches, etc.) is stored — only
aggregate counts and metadata.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from cloudaudit.core.constants import HISTORY_DB_FILE
from cloudaudit.core.models import ScanStats, Severity

logger = logging.getLogger("cloudaudit.history")


def get_history_db_path() -> Path:
    return Path(os.path.expanduser(HISTORY_DB_FILE))


@dataclass
class ScanHistoryEntry:
    id:          int
    timestamp:   str
    target:      str
    org:         str
    risk_score:  float
    total_files: int
    total_findings: int
    critical:    int
    high:        int
    medium:      int
    low:         int
    informational: int
    suppressed:  int


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT    NOT NULL,
    target         TEXT    NOT NULL,
    org            TEXT    NOT NULL,
    risk_score     REAL    NOT NULL,
    total_files    INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    critical       INTEGER NOT NULL DEFAULT 0,
    high           INTEGER NOT NULL DEFAULT 0,
    medium         INTEGER NOT NULL DEFAULT 0,
    low            INTEGER NOT NULL DEFAULT 0,
    informational  INTEGER NOT NULL DEFAULT 0,
    suppressed     INTEGER NOT NULL DEFAULT 0
);
"""


class HistoryStore:
    """Thin wrapper around a local SQLite scan-history database."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._path = Path(db_path) if db_path else get_history_db_path()

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._path))
        conn.execute(_SCHEMA)
        return conn

    def record(self, stats: ScanStats, target: str, org: str) -> bool:
        """Persist a one-row summary of a completed scan. Never raises."""
        try:
            sev_counts = {s.value: 0 for s in Severity}
            for f in stats.findings:
                sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

            # Note: sqlite3.Connection's context manager only commits/rolls back
            # the transaction — it does NOT close the connection. Close it
            # explicitly, otherwise every record()/list_recent() call leaks a
            # connection handle (and can leave the DB file locked on Windows).
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        "INSERT INTO scans "
                        "(timestamp, target, org, risk_score, total_files, total_findings, "
                        " critical, high, medium, low, informational, suppressed) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            target, org, float(stats.risk_score), stats.total_files,
                            len(stats.findings),
                            sev_counts.get("Critical", 0),
                            sev_counts.get("High", 0),
                            sev_counts.get("Medium", 0),
                            sev_counts.get("Low", 0),
                            sev_counts.get("Informational", 0),
                            stats.suppressed_count,
                        ),
                    )
            finally:
                conn.close()
            return True
        except Exception as exc:
            logger.warning("Failed to record scan history: %s", exc)
            return False

    def list_recent(self, limit: int = 20) -> List[ScanHistoryEntry]:
        try:
            conn = self._connect()
            try:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
            finally:
                conn.close()
            return [
                ScanHistoryEntry(
                    id=r["id"], timestamp=r["timestamp"], target=r["target"], org=r["org"],
                    risk_score=r["risk_score"], total_files=r["total_files"],
                    total_findings=r["total_findings"], critical=r["critical"],
                    high=r["high"], medium=r["medium"], low=r["low"],
                    informational=r["informational"], suppressed=r["suppressed"],
                )
                for r in rows
            ]
        except Exception as exc:
            logger.warning("Failed to read scan history: %s", exc)
            return []
