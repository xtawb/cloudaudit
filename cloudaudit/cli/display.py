"""
cloudaudit.cli.display — Professional Real-Time CLI Display

Structured phase-based progress output with clean ANSI formatting.
No emojis. Cybersecurity-grade visual style.
"""

from __future__ import annotations

import sys
import time
from contextlib import contextmanager
from typing import Optional


# ── ANSI Codes ─────────────────────────────────────────────────────────────────

class _C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    UNDER   = "\033[4m"

    # Colours
    WHITE   = "\033[97m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    GREY    = "\033[90m"

    # Severity
    CRITICAL = "\033[38;5;196m"
    HIGH     = "\033[38;5;202m"
    MEDIUM   = "\033[38;5;226m"
    LOW      = "\033[38;5;82m"
    INFO_C   = "\033[38;5;39m"

C = _C()


# ── ASCII Banner ───────────────────────────────────────────────────────────────

_BANNER_ART = r'''
                                                                                              
              ,,                           ,,                                ,,    ,,         
  .g8"""bgd `7MM                         `7MM        db                    `7MM    db   mm    
.dP'     `M   MM                           MM       ;MM:                     MM         MM    
dM'       `   MM  ,pW"Wq.`7MM  `7MM   ,M""bMM      ,V^MM.  `7MM  `7MM   ,M""bMM  `7MM mmMMmm  
MM            MM 6W'   `Wb MM    MM ,AP    MM     ,M  `MM    MM    MM ,AP    MM    MM   MM    
MM.           MM 8M     M8 MM    MM 8MI    MM     AbmmmqMA   MM    MM 8MI    MM    MM   MM    
`Mb.     ,'   MM YA.   ,A9 MM    MM `Mb    MM    A'     VML  MM    MM `Mb    MM    MM   MM    
  `"bmmmd'  .JMML.`Ybmd9'  `Mbod"YML.`Wbmd"MML..AMA.   .AMMA.`Mbod"YML.`Wbmd"MML..JMML. `Mbmo 
                                                                                              
'''                                                                                                                                                                                                                                                                             
BANNER = (
    f"{C.CYAN}{C.BOLD}\n"
    f"{_BANNER_ART}"
    f"{C.RESET}{C.GREY}\n"
    f"  Next-Generation AI-Powered Cloud Security Auditing Framework\n"
    f"  Powered by xtawb  |  https://linktr.ee/xtawb\n"
    f"{C.RESET}"
)

OWNERSHIP_NOTICE = f"""{C.YELLOW}{C.BOLD}
  +------------------------------------------------------------------+
  |                    OWNERSHIP DECLARATION                         |
  +------------------------------------------------------------------+
  |  This tool audits cloud storage assets that you own.             |
  |  By providing --confirm-ownership you declare that:              |
  |    [1] You are authorised to audit the target resource           |
  |    [2] The target belongs to your organisation                   |
  |    [3] You comply with all applicable laws and policies          |
  +------------------------------------------------------------------+
{C.RESET}"""


# ── Phase status indicators ────────────────────────────────────────────────────

_PHASES = {
    "init":        "Initializing scan engine",
    "ownership":   "Validating ownership declaration",
    "update":      "Checking for updates",
    "detect":      "Detecting container type and provider",
    "crawl":       "Discovering file inventory",
    "analyse":     "Analysing file contents",
    "entropy":     "Running entropy analysis",
    "archives":    "Extracting and scanning archives",
    "ai_file":     "Performing AI semantic file review",
    "ai_summary":  "Generating AI executive summary",
    "compliance":  "Generating compliance mapping",
    "scoring":     "Computing risk score",
    "reports":     "Writing reports",
    "done":        "Audit complete",
}


class PhaseDisplay:
    """Structured phase output with timing."""

    def __init__(self, quiet: bool = False, verbose: bool = False) -> None:
        self._quiet   = quiet
        self._verbose = verbose
        self._phase_times: dict[str, float] = {}
        self._current_phase: Optional[str] = None
        self._phase_start: float = 0.0

    def phase(self, phase_key: str, extra: str = "") -> None:
        if self._quiet:
            return
        label = _PHASES.get(phase_key, phase_key)
        extra_str = f"  {C.GREY}{extra}{C.RESET}" if extra else ""
        print(f"\n{C.CYAN}  [{C.WHITE}{C.BOLD}{label}{C.RESET}{C.CYAN}]{C.RESET}{extra_str}")
        self._current_phase = phase_key
        self._phase_start   = time.monotonic()
        sys.stdout.flush()

    def step(self, message: str, indent: int = 4) -> None:
        if self._quiet:
            return
        pad = " " * indent
        print(f"{pad}{C.GREY}>{C.RESET} {message}")
        sys.stdout.flush()

    def status(self, label: str, value: str, ok: bool = True, indent: int = 4) -> None:
        if self._quiet:
            return
        pad   = " " * indent
        color = C.GREEN if ok else C.YELLOW
        print(f"{pad}{color}{label:<20}{C.RESET}  {value}")
        sys.stdout.flush()

    def warning(self, message: str, indent: int = 4) -> None:
        if self._quiet:
            return
        pad = " " * indent
        print(f"{pad}{C.YELLOW}[!]{C.RESET} {message}")
        sys.stdout.flush()

    def error(self, message: str, indent: int = 4) -> None:
        pad = " " * indent
        print(f"{pad}{C.RED}[ERROR]{C.RESET} {message}", file=sys.stderr)
        sys.stdout.flush()

    def finding(self, severity: str, rule: str, filename: str) -> None:
        if self._quiet:
            return
        colors = {
            "Critical":      C.CRITICAL,
            "High":          C.HIGH,
            "Medium":        C.MEDIUM,
            "Low":           C.LOW,
            "Informational": C.INFO_C,
        }
        color = colors.get(severity, C.GREY)
        print(f"    {color}[{severity.upper():<13}]{C.RESET} {rule}  {C.GREY}{filename}{C.RESET}")
        sys.stdout.flush()

    def phase_done(self, extra: str = "") -> None:
        if self._quiet or not self._current_phase:
            return
        elapsed = time.monotonic() - self._phase_start
        extra_str = f" — {extra}" if extra else ""
        print(f"    {C.GREEN}Done{C.RESET} {C.GREY}({elapsed:.1f}s{extra_str}){C.RESET}")
        sys.stdout.flush()

    def separator(self, char: str = "-", width: int = 66) -> None:
        if not self._quiet:
            print(f"  {C.GREY}{char * width}{C.RESET}")

    def section_header(self, title: str) -> None:
        if self._quiet:
            return
        width = 66
        pad   = (width - len(title) - 2) // 2
        print(f"\n  {C.CYAN}{C.BOLD}{'=' * width}{C.RESET}")
        print(f"  {C.CYAN}{C.BOLD}{' ' * pad}  {title}  {' ' * pad}{C.RESET}")
        print(f"  {C.CYAN}{C.BOLD}{'=' * width}{C.RESET}")

    def kv(self, key: str, value: str, color=None, indent: int = 4) -> None:
        if self._quiet:
            return
        col = color or C.WHITE
        print(f"  {' ' * (indent - 2)}{C.GREY}{key:<22}{C.RESET}{col}{value}{C.RESET}")


def print_banner(quiet: bool) -> None:
    if not quiet:
        print(BANNER)


def print_ownership_notice(quiet: bool) -> None:
    if not quiet:
        print(OWNERSHIP_NOTICE)


def print_container_info(display: PhaseDisplay, stats) -> None:
    c = stats.container_info
    if not c:
        return
    display.section_header("CONTAINER DETECTED")
    display.kv("Type",       c.container_type.value,  C.CYAN + C.BOLD)
    display.kv("Name",       c.container_name or "N/A", C.WHITE + C.BOLD)
    display.kv("Region",     c.region or "N/A")
    display.kv("Public",     "YES" if c.is_public else "No",
               C.RED if c.is_public else C.GREEN)
    display.kv("Server",     c.server_header or "N/A")
    for note in c.notes:
        display.warning(note)


def print_audit_summary(display: PhaseDisplay, stats) -> None:
    display.section_header("AUDIT SUMMARY")

    import time as _time
    elapsed = round(_time.time() - stats.start_time, 1)

    sev_counts: dict[str, int] = {}
    for f in stats.findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

    display.kv("Files Discovered",   str(stats.total_files))
    display.kv("Files Scanned",      str(stats.scanned_files))
    display.kv("Files Skipped",      str(stats.skipped_files))
    display.kv("Archives Extracted", str(stats.archive_files))
    display.kv("Scan Duration",      f"{elapsed}s")
    display.kv("Errors",             str(len(stats.errors)),
               C.YELLOW if stats.errors else C.GREEN)

    risk_color = (C.RED if stats.risk_score >= 7 else
                  C.YELLOW if stats.risk_score >= 4 else C.GREEN)
    display.kv("Risk Score",         f"{stats.risk_score:.1f} / 10",  risk_color + C.BOLD)

    print()
    for sev_name, color in [
        ("Critical",      C.CRITICAL),
        ("High",          C.HIGH),
        ("Medium",        C.MEDIUM),
        ("Low",           C.LOW),
        ("Informational", C.INFO_C),
    ]:
        n = sev_counts.get(sev_name, 0)
        print(f"    {color}{sev_name:<16}{C.RESET}  {n}")


def print_findings_detail(display: PhaseDisplay, stats) -> None:
    if not stats.findings:
        print(f"\n    {C.GREEN}No findings above the minimum severity threshold.{C.RESET}\n")
        return

    display.section_header("FINDINGS")

    for f in stats.findings:
        colors = {
            "Critical": C.CRITICAL, "High": C.HIGH,
            "Medium": C.MEDIUM, "Low": C.LOW, "Informational": C.INFO_C,
        }
        color    = colors.get(f.severity.value, C.GREY)
        arch_tag = "  [ARCHIVE]" if f.from_archive else ""
        det_type = getattr(f, 'scanner', '')
        ai_tag   = "  [AI]" if "AI:" in det_type else ""

        print(f"\n  {color}[{f.severity.value.upper():<13}]{C.RESET} "
              f"{C.BOLD}{f.rule_name}{C.RESET}{arch_tag}{C.YELLOW}{ai_tag}{C.RESET}")
        print(f"    File          : {f.file_name}")
        print(f"    Description   : {f.description}")
        print(f"    Category      : {f.category.value}")
        print(f"    Confidence    : {f.confidence:.0%}  |  Line: {f.line_number or 'N/A'}")
        print(f"    Compliance    : {', '.join(f.compliance_refs) or 'N/A'}")
        print(f"    Recommendation: {f.recommendation[:110]}...")
        if f.from_archive:
            print(f"    Archive Path  : {f.archive_path}")
