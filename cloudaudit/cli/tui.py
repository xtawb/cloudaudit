"""
cloudaudit.cli.tui — Live Terminal Dashboard (--tui)

An optional ``rich.live.Live``-based real-time dashboard shown while
``AuditEngine.run()`` is executing, as an alternative to the default
phase-based terminal output. It renders:

  * The current audit phase
  * Files discovered / scanned so far
  * A running findings-by-severity count
  * Elapsed time

The dashboard is fed by ``AuditEngine``'s optional ``on_progress`` callback
(see ``core/engine.py``), which is called at coarse-grained milestones
(container detected, crawl complete, each file analysed, risk scored) — it
is not a per-network-request tracer, so it stays cheap and never adds
observable timing side effects to the read-only scan itself.

Falls back cleanly (raises nothing, just runs in "unavailable" mode) if:
  * ``rich`` is not installed, or
  * stdout is not a real terminal (e.g. piped to a file, non-interactive CI)

In unavailable mode, callers should keep using the classic ``PhaseDisplay``
output instead — see ``cli/main.py``'s ``_run_one_target``.
"""

from __future__ import annotations

import sys
import time
from typing import Any, Dict, Optional


class TuiDashboard:
    """Context manager wrapping a rich.live.Live dashboard for one scan run."""

    def __init__(self, quiet: bool = False, verbose: bool = False) -> None:
        self._quiet   = quiet
        self._verbose = verbose
        self._start   = time.monotonic()
        self._phase   = "Starting"
        self._total_files   = 0
        self._scanned_files = 0
        self._findings: Dict[str, int] = {
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0,
        }
        self._risk_score: Optional[float] = None
        self._container = ""

        self._live = None
        self.available = False

        if quiet or not sys.stdout.isatty():
            return

        try:
            from rich.live import Live
            from rich.table import Table
            from rich.panel import Panel
            self._Live, self._Table, self._Panel = Live, Table, Panel
            self.available = True
        except ImportError:
            self.available = False

    # ── Context manager ────────────────────────────────────────────────────────

    def __enter__(self) -> "TuiDashboard":
        if self.available:
            try:
                self._live = self._Live(self._render(), refresh_per_second=6, transient=False)
                self._live.__enter__()
            except Exception:
                # Terminal doesn't actually support Live rendering — degrade silently.
                self.available = False
                self._live = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if self._live is not None:
            try:
                self._live.__exit__(exc_type, exc_val, exc_tb)
            except Exception:
                pass
        return False

    # ── Progress callback (passed as AuditEngine(on_progress=...)) ────────────

    def update(self, info: Dict[str, Any]) -> None:
        phase = info.get("phase")
        if phase:
            self._phase = phase
        if "container" in info:
            self._container = str(info["container"])
        if "total_files" in info:
            self._total_files = int(info["total_files"])
        if "scanned_files" in info:
            self._scanned_files = int(info["scanned_files"])
        if "risk_score" in info:
            self._risk_score = float(info["risk_score"])
        if "severity_counts" in info and isinstance(info["severity_counts"], dict):
            self._findings.update(info["severity_counts"])

        if self.available and self._live is not None:
            try:
                self._live.update(self._render())
            except Exception:
                pass

    # ── Rendering ──────────────────────────────────────────────────────────────

    def _render(self):
        elapsed = time.monotonic() - self._start
        table = self._Table(show_header=False, expand=True, box=None, padding=(0, 1))
        table.add_column("k", style="bold cyan", ratio=1)
        table.add_column("v", ratio=2)

        table.add_row("Phase", self._phase)
        if self._container:
            table.add_row("Container", self._container)
        table.add_row("Files discovered", str(self._total_files))
        table.add_row("Files scanned", str(self._scanned_files))
        table.add_row("Elapsed", f"{elapsed:.1f}s")

        sev_colors = {
            "Critical": "bright_red", "High": "orange3",
            "Medium": "yellow", "Low": "green", "Informational": "blue",
        }
        for sev, color in sev_colors.items():
            n = self._findings.get(sev, 0)
            table.add_row(f"  {sev}", f"[{color}]{n}[/{color}]" if n else "0")

        if self._risk_score is not None:
            risk_color = "bright_red" if self._risk_score >= 7 else "yellow" if self._risk_score >= 4 else "green"
            table.add_row("Risk score", f"[{risk_color}]{self._risk_score:.1f} / 10[/{risk_color}]")

        return self._Panel(table, title="CloudAudit — Live Scan Dashboard", border_style="cyan")
