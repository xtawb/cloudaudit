"""
cloudaudit — CLI Entry Point v2.0

Full-featured CLI with:
  - Structured phase display
  - Interactive AI provider setup with live key validation
  - Auto-update check
  - Subcommand: cloudaudit config --set-api / --list-providers / --remove-api
  - Professional ANSI output, no emojis
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import argparse

from cloudaudit.core.config import AuditConfig
from cloudaudit.core.constants import (
    DEFAULT_BATCH_CONCURRENCY, DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE,
    DEFAULT_RATE_LIMIT_DELAY, DEFAULT_TIMEOUT, DEFAULT_MIN_SCAN_INTERVAL,
    __tool_name__, __version__, __author__, __author_url__,
)
from cloudaudit.core.engine import AuditEngine
from cloudaudit.core.exceptions import AuditError, OwnershipError, ProviderAuthError
from cloudaudit.core.logger import configure_logging
from cloudaudit.core.models import ScanStats, Severity
from cloudaudit.utils.helpers import finding_dict_fingerprint, safe_filename
from cloudaudit.cli.display import (
    PhaseDisplay, print_banner, print_ownership_notice,
    print_container_info, print_audit_summary, print_findings_detail, C,
)

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# ── Argument parser ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloudaudit",
        description=f"{__tool_name__} — Next-Generation AI-Powered Cloud Security Auditing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  cloudaudit -u https://mybucket.s3.amazonaws.com/ \\
             --confirm-ownership --org-name "Acme Corp" -o report

  cloudaudit -u https://mybucket.s3.amazonaws.com/ \\
             --confirm-ownership --org-name "Acme Corp" \\
             --extract-archives --deep-metadata \\
             --provider gemini --api-key AIza... \\
             -o report --format all

  cloudaudit config --list-providers
  cloudaudit config --set-api gemini
  cloudaudit config --remove-api gemini

Powered by {__author__} | {__author_url__}
        """,
    )

    sub = p.add_subparsers(dest="subcommand")

    # ── config subcommand ────────────────────────────────────────────────────
    cfg = sub.add_parser("config", help="Manage API keys and configuration")
    cfg.add_argument("--set-api",        metavar="PROVIDER", help="Set API key for a provider")
    cfg.add_argument("--list-providers", action="store_true", help="List all supported AI providers")
    cfg.add_argument("--remove-api",     metavar="PROVIDER", help="Remove stored API key for a provider")
    cfg.add_argument("--save-profile",   metavar="NAME",
                      help="Save the scan flags given on this command line as a reusable "
                           "profile at ~/.cloudaudit/profiles/<name>.yml (API keys are never saved)")
    cfg.add_argument("--list-profiles",  action="store_true", help="List saved profile names")

    # ── diff subcommand ──────────────────────────────────────────────────────
    diff_p = sub.add_parser("diff", help="Compare two JSON audit reports (new/resolved/unchanged findings)")
    diff_p.add_argument("old_report", help="Path to the earlier report (cloudaudit JSON output)")
    diff_p.add_argument("new_report", help="Path to the later report (cloudaudit JSON output)")

    # ── history subcommand ───────────────────────────────────────────────────
    hist_p = sub.add_parser("history", help="List locally recorded past scans (~/.cloudaudit/history.db)")
    hist_p.add_argument("--limit", type=int, default=20, help="Maximum number of scans to show (default: 20)")

    # ── init-ci subcommand ───────────────────────────────────────────────────
    ci_p = sub.add_parser("init-ci", help="Write a ready-to-use GitHub Actions workflow for CloudAudit + SARIF upload")
    ci_p.add_argument("--output", metavar="PATH", default=".github/workflows/cloudaudit.yml",
                       help="Workflow file to write, relative to the current directory "
                            "(default: .github/workflows/cloudaudit.yml)")
    ci_p.add_argument("--schedule", metavar="CRON", default="0 6 * * 1",
                       help="Cron schedule for the periodic scan (default: weekly, Monday 06:00 UTC)")
    ci_p.add_argument("--force", action="store_true", help="Overwrite the workflow file if it already exists")

    # ── selftest subcommand ──────────────────────────────────────────────────
    sub.add_parser(
        "selftest",
        help="Run the secret scanner and redaction pipeline against known-bad synthetic "
             "samples and report PASS/FAIL per check",
    )

    # ── scan arguments ────────────────────────────────────────────────────────
    p.add_argument("-u", "--url", help="Target cloud storage URL")
    p.add_argument("--targets-file", metavar="FILE",
                   help="Batch-scan multiple targets, one URL per line (comments with # supported)")
    p.add_argument("--batch-concurrency", type=int, default=DEFAULT_BATCH_CONCURRENCY,
                   help=f"Number of targets to scan concurrently with --targets-file (default: {DEFAULT_BATCH_CONCURRENCY})")
    p.add_argument("--scan-docker-image", metavar="IMAGE_REF",
                   help="Read-only scan of a container image's layers for secrets, "
                        "e.g. registry.example.com/team/app:1.2.3 (no -u required)")

    p.add_argument("--confirm-ownership", action="store_true",
                   help="Declare that you own and are authorised to audit this resource (required)")
    p.add_argument("--org-name", metavar="ORG",
                   help="Organisation name for the audit report (required)")

    p.add_argument("--max-depth",  type=int, default=DEFAULT_MAX_DEPTH,
                   help=f"Maximum crawl recursion depth (default: {DEFAULT_MAX_DEPTH})")
    p.add_argument("--max-size",   type=int, default=DEFAULT_MAX_FILE_SIZE,
                   help=f"Max file download size in bytes (default: 20 MB)")
    p.add_argument("--extensions", help="Comma-separated extension allow-list (default: all sensitive types)")
    p.add_argument("--ignore-paths", help="Comma-separated path fragments to exclude")

    p.add_argument("--extract-archives", action="store_true",
                   help="Download and scan archives (zip, tar, gz, jar, war...)")
    p.add_argument("--deep-metadata", action="store_true",
                   help="Extract EXIF / binary metadata from images")

    p.add_argument("--baseline", metavar="FILE",
                   help="JSON/YAML file of previously-accepted finding fingerprints to suppress")
    p.add_argument("--custom-patterns", metavar="FILE",
                   help="YAML file of additional secret regex patterns to merge into the scanner")
    p.add_argument("--checkpoint", metavar="FILE",
                   help="Periodically save crawl/analysis progress to this file")
    p.add_argument("--resume", metavar="FILE",
                   help="Resume a previously interrupted crawl from a --checkpoint file")
    p.add_argument("--dry-run", action="store_true",
                   help="Enumerate discovered files (size/type) without downloading or analysing content")
    p.add_argument("--aws-acl-check", action="store_true",
                   help="Enrich AWS S3 findings with real ACL/policy detail via boto3 (optional dependency, "
                        "requires AWS credentials in the environment)")
    p.add_argument("--webhook-url", metavar="URL",
                   help="POST a redacted scan summary (Slack/Discord-compatible JSON) to this webhook when the scan finishes")
    p.add_argument("--fail-on-severity", choices=["low", "medium", "high", "critical"],
                   help="Exit non-zero if any finding at or above this severity is present (for CI/CD gating)")
    p.add_argument("--no-history", action="store_true",
                   help="Don't record this scan in the local history database")
    p.add_argument("--interval", metavar="SECONDS", type=float,
                   help="Continuous/drift-detection mode: re-run this exact scan every SECONDS "
                        "until interrupted (Ctrl+C). Each run is logged to scan history like a normal scan.")
    p.add_argument("--tui", action="store_true",
                   help="Show a live rich.live-based terminal dashboard during the scan instead of "
                        "the default phase-by-phase output (falls back automatically if unsupported)")
    p.add_argument("--profile", metavar="NAME",
                   help="Load a saved profile from ~/.cloudaudit/profiles/<name>.yml — "
                        "explicit CLI flags on this invocation override the profile's values")
    p.add_argument("--webhook-format", choices=["auto", "slack", "generic"], default="auto",
                   help="Payload format for --webhook-url (default: auto-detect Slack via hooks.slack.com)")
    p.add_argument("--slack-summary", action="store_true",
                   help="Shortcut for --webhook-format slack — force a Slack Block Kit executive "
                        "summary payload for --webhook-url")

    p.add_argument("--provider", choices=["gemini","openai","claude","deepseek","ollama","custom"],
                   help="AI provider for semantic analysis and executive summary")
    p.add_argument("--api-key",       help="API key for the selected AI provider")
    p.add_argument("--provider-url",  help="Base URL for custom OpenAI-compatible endpoints")
    p.add_argument("--ollama-url",    default="http://localhost:11434",
                   help="Ollama server URL (default: http://localhost:11434)")
    p.add_argument("--ollama-model",  default="llama3", help="Ollama model name (default: llama3)")

    p.add_argument("-t","--threads","--concurrency", dest="threads", type=int, default=DEFAULT_MAX_CONCURRENT,
                   help=f"Concurrent HTTP requests, applied to both the crawl and analysis phases "
                        f"(default: {DEFAULT_MAX_CONCURRENT})")
    p.add_argument("--timeout",       type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--rate-limit",    type=float, default=DEFAULT_RATE_LIMIT_DELAY,
                   help=f"Delay in seconds applied per request per connection — combined with "
                        f"--concurrency this bounds effective requests/sec (default: {DEFAULT_RATE_LIMIT_DELAY})")

    p.add_argument("-o","--output",   help="Output base path (extensions added automatically)")
    p.add_argument("--format", choices=["json","html","markdown","sarif","csv","pdf","all"], default="all",
                   help="Report format (default: all — note: 'pdf' is never included in 'all' "
                        "since it requires the optional xhtml2pdf dependency; request it explicitly)")
    p.add_argument("--min-severity",
                   choices=["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"],
                   default="LOW")

    p.add_argument("--no-update", action="store_true", help="Skip update check")
    p.add_argument("-v","--verbose",  action="store_true")
    p.add_argument("-d","--debug",    action="store_true")
    p.add_argument("--silent",        action="store_true", help="No terminal output (implies -q)")
    p.add_argument("-q","--quiet",    action="store_true")
    p.add_argument(
    "--version",
    action="version",
    version=f"{__tool_name__} v{__version__}",
    help="Show tool version and exit"
)
    return p


# ── Config subcommand ──────────────────────────────────────────────────────────

def handle_config(args, display: PhaseDisplay) -> int:
    from cloudaudit.config_mgr.key_manager import (
        SecureKeyStore, PROVIDER_INFO, validate_key_format, validate_key_live,
        get_troubleshoot_guide,
    )
    store = SecureKeyStore()

    if args.list_providers:
        display.section_header("SUPPORTED AI PROVIDERS")
        for name, info in PROVIDER_INFO.items():
            configured = "CONFIGURED" if store.get(name) else ""
            print(f"  {C.CYAN}{name:<12}{C.RESET}  {info['label']:<25}  "
                  f"{C.GREY}{info['get_key']}{C.RESET}  "
                  f"{C.GREEN}{configured}{C.RESET}")
        print()
        return 0

    if args.set_api:
        provider = args.set_api.lower()
        info     = PROVIDER_INFO.get(provider)
        if not info:
            display.error(f"Unknown provider: {provider}")
            return 1

        print(f"\n  Setting API key for {C.BOLD}{info['label']}{C.RESET}")
        print(f"  Get your key at: {C.CYAN}{info['get_key']}{C.RESET}")
        if info.get("hint"):
            print(f"  {C.GREY}{info['hint']}{C.RESET}")

        if provider == "ollama":
            display.step("Ollama does not require an API key.")
            return 0

        import getpass
        api_key = getpass.getpass("  Enter API key: ")
        if not api_key.strip():
            display.warning("No key entered. Aborting.")
            return 1

        display.step("Validating key format...")
        fmt_ok, fmt_hint = validate_key_format(provider, api_key)
        if not fmt_ok:
            display.warning(f"Format mismatch: {fmt_hint}")
            cont = input("  Continue anyway? (y/N): ").strip().lower()
            if cont != "y":
                return 1

        display.step("Validating key against API (live check)...")
        live_ok, live_err = validate_key_live(provider, api_key)
        if live_ok:
            print(f"  {C.GREEN}Key is valid.{C.RESET}")
        else:
            print(f"  {C.YELLOW}Key validation failed: {live_err}{C.RESET}")
            print(f"\n  Troubleshooting for {info['label']}:")
            for tip in get_troubleshoot_guide(provider):
                print(f"    - {tip}")
            cont = input("\n  Store anyway? (y/N): ").strip().lower()
            if cont != "y":
                return 1

        if store.save(provider, api_key):
            print(f"  {C.GREEN}Key stored securely at ~/.cloudaudit/config.enc{C.RESET}")
            return 0
        else:
            display.error("Failed to store key. Check ~/.cloudaudit/ permissions.")
            return 1

    if args.remove_api:
        provider = args.remove_api.lower()
        if store.remove(provider):
            print(f"  {C.GREEN}Removed API key for {provider}.{C.RESET}")
        else:
            print(f"  {C.YELLOW}No key found for {provider}.{C.RESET}")
        return 0

    if getattr(args, "save_profile", None):
        from cloudaudit.config_mgr.profiles import save_profile
        try:
            path = save_profile(args.save_profile, vars(args))
        except Exception as exc:
            display.error(f"Failed to save profile: {exc}")
            return 1
        print(f"  {C.GREEN}Profile '{args.save_profile}' saved to {path}{C.RESET}")
        print(f"  {C.GREY}Load it on a future scan with --profile {args.save_profile}{C.RESET}")
        return 0

    if getattr(args, "list_profiles", False):
        from cloudaudit.config_mgr.profiles import list_profiles, profiles_dir
        names = list_profiles()
        if not names:
            print(f"  No saved profiles in {profiles_dir()}")
        else:
            display.section_header("SAVED PROFILES")
            for name in names:
                print(f"  {C.CYAN}{name}{C.RESET}")
        return 0

    print("  Use --list-providers, --set-api <provider>, --remove-api <provider>, "
          "--save-profile <name>, or --list-profiles")
    return 0


# ── Named config profiles (--profile) ───────────────────────────────────────────

def apply_profile(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """
    Merge a saved profile's values into ``args`` for every destination the
    user did NOT explicitly override on this command line.

    Detection heuristic: a flag counts as "explicitly given" if its parsed
    value differs from the parser's registered default for that action. This
    is a pragmatic approximation (a user who explicitly passes a value that
    happens to equal the default will have it silently overridden by the
    profile) documented as a known trade-off in the docs.
    """
    profile_name = getattr(args, "profile", None)
    if not profile_name:
        return
    from cloudaudit.config_mgr.profiles import load_profile
    from cloudaudit.core.exceptions import ConfigError
    try:
        profile = load_profile(profile_name)
    except ConfigError as exc:
        print(f"{C.RED}  [ERROR]{C.RESET} {exc}", file=sys.stderr)
        raise SystemExit(1)

    defaults_by_dest = {a.dest: a.default for a in parser._actions}
    for dest, value in profile.items():
        if dest not in defaults_by_dest:
            continue  # stale/unknown key from an older profile — ignore
        if getattr(args, dest, None) == defaults_by_dest[dest]:
            setattr(args, dest, value)


# ── init-ci subcommand ───────────────────────────────────────────────────────

_CI_WORKFLOW_TEMPLATE = """name: CloudAudit Security Scan

# Auto-generated by `cloudaudit init-ci`. Customise as needed.
# Requires two repository secrets:
#   CLOUDAUDIT_TARGET_URL — the cloud storage URL you own and are authorised to audit
#   CLOUDAUDIT_ORG_NAME   — your organisation name for the report

on:
  workflow_dispatch: {{}}
  schedule:
    - cron: "{schedule}"

permissions:
  contents: read
  security-events: write   # required to upload SARIF results

jobs:
  cloudaudit:
    runs-on: ubuntu-latest
    steps:
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install CloudAudit
        run: pip install cloudaudit

      - name: Run CloudAudit (read-only, SARIF output)
        env:
          CLOUDAUDIT_TARGET_URL: ${{{{ secrets.CLOUDAUDIT_TARGET_URL }}}}
          CLOUDAUDIT_ORG_NAME: ${{{{ secrets.CLOUDAUDIT_ORG_NAME }}}}
        run: |
          cloudaudit -u "$CLOUDAUDIT_TARGET_URL" \\
                     --confirm-ownership \\
                     --org-name "$CLOUDAUDIT_ORG_NAME" \\
                     --format sarif \\
                     --no-update \\
                     --quiet \\
                     -o cloudaudit-report
        continue-on-error: true   # let the SARIF upload step surface findings instead of a bare failure

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: cloudaudit-report.sarif
"""


def handle_init_ci(args, display: PhaseDisplay) -> int:
    output_path = Path(args.output)
    if output_path.exists() and not getattr(args, "force", False):
        display.error(f"{output_path} already exists. Use --force to overwrite.")
        return 1
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        content = _CI_WORKFLOW_TEMPLATE.format(schedule=args.schedule)
        output_path.write_text(content, encoding="utf-8")
    except Exception as exc:
        display.error(f"Failed to write workflow file: {exc}")
        return 1

    display.section_header("CI WORKFLOW SCAFFOLD WRITTEN")
    display.kv("File", str(output_path))
    print(f"\n  {C.GREY}Next steps:{C.RESET}")
    print(f"    1. Add repository secrets: CLOUDAUDIT_TARGET_URL, CLOUDAUDIT_ORG_NAME")
    print(f"    2. Commit {output_path} and push")
    print(f"    3. Findings will appear under the repository's Security > Code scanning tab\n")
    return 0


# ── selftest subcommand ──────────────────────────────────────────────────────

def handle_selftest(args, display: PhaseDisplay) -> int:
    """
    Defensive sanity check: run the secret scanner against a small built-in
    set of known-bad *synthetic* (non-functional) samples and assert both
    that detection fires and that the stored match is redacted, never raw.
    Intended to be run after installing/upgrading CloudAudit.
    """
    from cloudaudit.scanners.secret_scanner import SecretScanner
    from cloudaudit.core.models import FileType

    scanner = SecretScanner(min_entropy=3.0)

    # All values below are synthetic / obviously fake — they are not valid
    # credentials for any real service and exist only to exercise the
    # detection + redaction pipeline.
    cases = [
        ("AWS Access Key",     "aws_access_key_id = AKIAABCDEFGHIJKLMNOP", "AWS_ACCESS_KEY"),
        ("GitHub PAT",         "token = ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "GITHUB_PAT"),
        ("Private Key Block",  "-----BEGIN RSA PRIVATE KEY-----\nMIIFAKE1234567890NOTREALKEYDATA\n-----END RSA PRIVATE KEY-----", "PRIVATE_KEY"),
        ("Hardcoded Password", 'password = "N0tARealPassword!23"', "HARDCODED_PASSWORD"),
        ("Database URL",       "postgres://admin:S3cretFakePW9@db.internal.example:5432/prod", "DATABASE_URL"),
    ]

    display.section_header("CLOUDAUDIT SELF-TEST")
    print(f"  {C.GREY}Running detection + redaction checks against built-in synthetic samples...{C.RESET}\n")

    all_ok = True
    for label, sample, expected_rule in cases:
        try:
            findings = scanner.scan(sample, "selftest://synthetic-sample", FileType.OTHER)
        except Exception as exc:
            print(f"  [{C.RED}FAIL{C.RESET}] {label:<22} scanner raised: {exc}")
            all_ok = False
            continue

        matches = [f for f in findings if f.rule_name == expected_rule]
        detected = bool(matches)
        # Redaction check: the stored match must never equal or contain the
        # full raw sample value — redact() always yields "<=6 chars>***" or "***".
        redacted_ok = all(m.match.endswith("***") and sample not in m.match for m in matches) if matches else False

        ok = detected and redacted_ok
        all_ok = all_ok and ok
        status = f"{C.GREEN}PASS{C.RESET}" if ok else f"{C.RED}FAIL{C.RESET}"
        print(
            f"  [{status}] {label:<22} "
            f"detection={'yes' if detected else 'no ':<3}  redaction={'yes' if redacted_ok else 'no ':<3}"
        )

    print()
    if all_ok:
        print(f"  {C.GREEN}All self-tests passed — detection and redaction are functioning correctly.{C.RESET}\n")
    else:
        print(f"  {C.RED}One or more self-tests FAILED. Do not rely on this installation until this is resolved.{C.RESET}\n")
    return 0 if all_ok else 1


# ── Update check ───────────────────────────────────────────────────────────────

def run_update_check(display: PhaseDisplay, skip: bool = False) -> None:
    if skip:
        return
    from cloudaudit.config_mgr.updater import check_for_update, perform_update
    display.phase("update")
    available, latest, url = check_for_update(timeout=5)
    if available:
        display.warning(f"Update available: v{__version__} -> v{latest}  ({url})")
        if sys.stdin.isatty():
            choice = input("  Update now? [Y/n]: ").strip().lower()
            if choice in ("", "y"):
                display.step("Updating...")
                ok, msg = perform_update()
                if ok:
                    display.status("Update", "successful — please restart cloudaudit", ok=True)
                    sys.exit(0)
                else:
                    display.warning(f"Update failed: {msg}")
    else:
        display.step(f"Version {__version__} is current.")
    display.phase_done()


# ── Interactive AI setup ───────────────────────────────────────────────────────

def interactive_ai_setup(display: PhaseDisplay) -> tuple[Optional[str], Optional[str]]:
    from cloudaudit.config_mgr.key_manager import (
        SecureKeyStore, PROVIDER_INFO, validate_key_format, validate_key_live, get_troubleshoot_guide
    )

    print(f"\n  {C.CYAN}{C.BOLD}AI-Powered Analysis{C.RESET}")
    print("  CloudAudit can use AI for semantic file analysis and executive summary generation.")
    print("  Without AI, the built-in heuristic engine is used instead.\n")

    enable = input("  Enable AI analysis? (y/N): ").strip().lower()
    if enable != "y":
        return None, None

    store = SecureKeyStore()

    print("\n  Available AI Providers:")
    providers = list(PROVIDER_INFO.items())
    for i, (name, info) in enumerate(providers, 1):
        stored = " [key stored]" if store.get(name) else ""
        print(f"    {i}) {info['label']:<25} {C.GREY}{info['get_key']}{C.RESET}{C.GREEN}{stored}{C.RESET}")

    try:
        choice = int(input("\n  Select provider [1-5]: ").strip())
        if not 1 <= choice <= len(providers):
            raise ValueError
        provider_name, info = providers[choice - 1]
    except (ValueError, IndexError):
        display.warning("Invalid selection. Using heuristic analysis.")
        return None, None

    if provider_name == "ollama":
        return "ollama", None

    # Check stored key
    stored_key = store.get(provider_name)
    if stored_key:
        print(f"  {C.GREEN}Using stored key for {info['label']}.{C.RESET}")
        return provider_name, stored_key

    print(f"\n  Get your {info['label']} key at: {C.CYAN}{info['get_key']}{C.RESET}")
    if info.get("hint"):
        print(f"  {C.GREY}{info['hint']}{C.RESET}")

    import getpass
    api_key = getpass.getpass("  Enter API key (or press Enter to skip): ")
    if not api_key.strip():
        return None, None

    # Live validation
    print("  Validating key...")
    live_ok, live_err = validate_key_live(provider_name, api_key)
    if live_ok:
        print(f"  {C.GREEN}Key validated successfully.{C.RESET}")
    else:
        print(f"  {C.YELLOW}Validation returned: {live_err}{C.RESET}")
        for tip in get_troubleshoot_guide(provider_name):
            print(f"    - {tip}")
        cont = input("  Use anyway? (y/N): ").strip().lower()
        if cont != "y":
            return None, None

    save = input("  Save key securely for future sessions? (y/N): ").strip().lower()
    if save == "y":
        if store.save(provider_name, api_key):
            print(f"  {C.GREEN}Key stored at ~/.cloudaudit/config.enc{C.RESET}")

    return provider_name, api_key


# ── Diff subcommand ──────────────────────────────────────────────────────────

def handle_diff(args, display: PhaseDisplay) -> int:
    try:
        old_data = json.loads(Path(args.old_report).read_text(encoding="utf-8"))
        new_data = json.loads(Path(args.new_report).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"{C.RED}[ERROR]{C.RESET} Failed to read report(s): {exc}", file=sys.stderr)
        return 1

    old_findings = (old_data.get("scan") or old_data).get("findings", [])
    new_findings = (new_data.get("scan") or new_data).get("findings", [])

    old_map = {finding_dict_fingerprint(f): f for f in old_findings}
    new_map = {finding_dict_fingerprint(f): f for f in new_findings}

    new_fps       = set(new_map) - set(old_map)
    resolved_fps  = set(old_map) - set(new_map)
    unchanged_fps = set(old_map) & set(new_map)

    def _rank(fp: str, mapping: dict) -> int:
        return _SEVERITY_RANK.get(str(mapping[fp].get("severity", "")).lower(), 0)

    def _line(fp: str, mapping: dict) -> str:
        f = mapping[fp]
        loc = f.get("file_name") or f.get("file_url") or "?"
        return f"    [{f.get('severity', '?'):<13}] {f.get('rule_name', '?'):<28} {loc}"

    print(f"\n  {C.BOLD}CloudAudit Diff{C.RESET}")
    print(f"  Old report: {args.old_report}")
    print(f"  New report: {args.new_report}")

    print(f"\n  {C.RED}{C.BOLD}NEW ({len(new_fps)}){C.RESET}")
    for fp in sorted(new_fps, key=lambda x: -_rank(x, new_map)):
        print(_line(fp, new_map))

    print(f"\n  {C.GREEN}{C.BOLD}RESOLVED ({len(resolved_fps)}){C.RESET}")
    for fp in sorted(resolved_fps, key=lambda x: -_rank(x, old_map)):
        print(_line(fp, old_map))

    print(f"\n  {C.GREY}{C.BOLD}UNCHANGED ({len(unchanged_fps)}){C.RESET}")
    for fp in sorted(unchanged_fps, key=lambda x: -_rank(x, new_map)):
        print(_line(fp, new_map))
    print()

    return 2 if new_fps else 0


# ── History subcommand ───────────────────────────────────────────────────────

def handle_history(args, display: PhaseDisplay) -> int:
    from cloudaudit.config_mgr.history import HistoryStore

    entries = HistoryStore().list_recent(limit=getattr(args, "limit", 20))
    if not entries:
        print("  No scan history recorded yet. Run a scan first (recorded unless --no-history is set).")
        return 0

    display.section_header("SCAN HISTORY")
    print(f"  {'ID':<5}{'Timestamp':<22}{'Risk':<7}{'Total':<7}{'Crit':<6}{'High':<6}{'Target'}")
    print("  " + "-" * 90)
    for e in entries:
        target_disp = e.target if len(e.target) <= 60 else e.target[:57] + "..."
        print(f"  {e.id:<5}{e.timestamp:<22}{e.risk_score:<7.1f}{e.total_findings:<7}"
              f"{e.critical:<6}{e.high:<6}{target_disp}")
    print()
    return 0


# ── Docker image layer scan ───────────────────────────────────────────────────

async def _run_docker_scan(args) -> ScanStats:
    from cloudaudit.core.models import ContainerInfo, ContainerType
    from cloudaudit.intelligence.risk_scorer import RiskScorer
    from cloudaudit.scanners.docker_registry import scan_docker_image
    from cloudaudit.utils.http_client import HTTPClient

    config = AuditConfig(
        url=f"docker://{args.scan_docker_image}",
        ownership_confirmed=True,
        owner_org=args.org_name or "",
        timeout=args.timeout,
        max_concurrent=args.threads,
        rate_limit_delay=args.rate_limit,
    )
    stats = ScanStats()
    async with HTTPClient(config) as http:
        findings, summary = await scan_docker_image(http, args.scan_docker_image)

    notes = []
    if summary.manifest_digest:
        notes.append(f"Manifest digest: {summary.manifest_digest}")
    if summary.layers_skipped:
        notes.append(f"{summary.layers_skipped} layer(s) skipped (unsupported type or oversized)")

    stats.container_info = ContainerInfo(
        raw_url=f"docker://{args.scan_docker_image}",
        container_type=ContainerType.DOCKER_REGISTRY,
        container_name=summary.repository,
        region=summary.registry,
        is_public=True,
        notes=notes,
    )
    stats.findings = findings
    stats.findings.sort(key=lambda f: -f.severity.int_value)
    stats.total_files = summary.files_scanned
    stats.scanned_files = summary.files_scanned
    stats.archive_files = summary.layers_scanned
    stats.errors = summary.errors
    stats.risk_score = RiskScorer().compute(stats.findings, stats.container_info)
    return stats


# ── Shared scan config / post-scan helpers ────────────────────────────────────

def _build_audit_config(args, url, provider, api_key, output_base, quiet, verbose, debug) -> AuditConfig:
    ignore_paths: set = set()
    if getattr(args, "ignore_paths", None):
        ignore_paths = {p.strip() for p in args.ignore_paths.split(",") if p.strip()}

    extensions: set = set()
    if getattr(args, "extensions", None):
        extensions = {e.strip().lstrip(".").lower() for e in args.extensions.split(",") if e.strip()}

    config = AuditConfig(
        url=url,
        ownership_confirmed=args.confirm_ownership,
        owner_org=args.org_name,
        max_concurrent=args.threads,
        timeout=args.timeout,
        rate_limit_delay=args.rate_limit,
        max_file_size=args.max_size,
        max_depth=args.max_depth,
        extensions=extensions,
        ignore_paths=ignore_paths,
        extract_archives=args.extract_archives,
        deep_metadata=args.deep_metadata,
        provider=provider,
        api_key=api_key,
        ollama_url=args.ollama_url,
        ollama_model=args.ollama_model,
        output_base=output_base,
        output_format=args.format,
        min_severity=args.min_severity,
        verbose=verbose,
        debug=debug,
        quiet=quiet,
        baseline_path=getattr(args, "baseline", None),
        custom_patterns_path=getattr(args, "custom_patterns", None),
        checkpoint_path=getattr(args, "checkpoint", None),
        resume_path=getattr(args, "resume", None),
        dry_run=getattr(args, "dry_run", False),
        aws_acl_check=getattr(args, "aws_acl_check", False),
        webhook_url=getattr(args, "webhook_url", None),
        fail_on_severity=getattr(args, "fail_on_severity", None),
    )
    if getattr(args, "provider_url", None):
        config.__dict__["provider_url"] = args.provider_url
    return config


def _severity_exit_code(stats: ScanStats, fail_on_severity: Optional[str]) -> int:
    """2 if the CI exit-gating condition is met, else 0."""
    if fail_on_severity:
        threshold = _SEVERITY_RANK.get(fail_on_severity.lower(), 3)
        return 2 if any(f.severity.int_value >= threshold for f in stats.findings) else 0
    # Default (unchanged from earlier versions): non-zero on High/Critical findings
    return 2 if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in stats.findings) else 0


def _post_scan_actions(args, stats: ScanStats, target: str) -> None:
    """History recording + webhook notification. Never allowed to fail the scan."""
    if not getattr(args, "no_history", False):
        try:
            from cloudaudit.config_mgr.history import HistoryStore
            HistoryStore().record(stats, target=target, org=args.org_name or "")
        except Exception as exc:
            logging.getLogger("cloudaudit.cli").debug("History recording failed: %s", exc)

    if getattr(args, "webhook_url", None):
        try:
            from cloudaudit.utils.webhook import send_webhook
            webhook_fmt = "slack" if getattr(args, "slack_summary", False) else getattr(args, "webhook_format", None)
            ok, msg = send_webhook(
                args.webhook_url, stats, target=target, org=args.org_name or "", fmt=webhook_fmt
            )
            if not ok:
                logging.getLogger("cloudaudit.cli").warning("Webhook delivery failed: %s", msg)
        except Exception as exc:
            logging.getLogger("cloudaudit.cli").warning("Webhook delivery failed: %s", exc)


async def _run_one_target(
    args, display: PhaseDisplay, config: AuditConfig, url: str, quiet: bool
) -> tuple[int, Optional[ScanStats]]:
    """Run the full audit engine against one target and write its reports."""
    try:
        dashboard = None
        on_progress = None
        if getattr(args, "tui", False) and not quiet:
            from cloudaudit.cli.tui import TuiDashboard
            dashboard = TuiDashboard(quiet=quiet, verbose=getattr(args, "verbose", False))
            on_progress = dashboard.update

        engine = AuditEngine(config, display=display, on_progress=on_progress)
        display.phase("detect", url)
        if dashboard is not None:
            with dashboard:
                stats = await engine.run()
        else:
            stats = await engine.run()

        if not quiet:
            print_container_info(display, stats)
            print_audit_summary(display, stats)
            print_findings_detail(display, stats)

        display.phase("reports")
        written = engine.write_reports()
        display.phase_done()
        if written and not quiet:
            display.section_header("REPORTS WRITTEN")
            for p in written:
                display.kv(p.suffix.lstrip(".").upper(), str(p))

        if getattr(args, "verbose", False) and stats.ai_summary:
            display.section_header("AI EXECUTIVE SUMMARY")
            print()
            for line in stats.ai_summary.split("\n"):
                print(f"  {line}")

        _post_scan_actions(args, stats, target=url)
        return _severity_exit_code(stats, getattr(args, "fail_on_severity", None)), stats

    except OwnershipError as exc:
        display.error(f"Ownership error: {exc}")
        return 1, None
    except AuditError as exc:
        display.error(f"Audit error: {exc}")
        return 1, None
    except Exception as exc:
        display.error(f"Fatal: {exc}")
        if getattr(args, "debug", False):
            import traceback; traceback.print_exc()
        return 1, None


async def _run_batch(args, display: PhaseDisplay, provider, api_key, quiet: bool, verbose: bool, debug: bool) -> int:
    targets_path = Path(args.targets_file)
    if not targets_path.exists():
        display.error(f"Targets file not found: {args.targets_file}")
        return 1

    targets = [
        line.strip() for line in targets_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not targets:
        display.error(f"No targets found in {args.targets_file}")
        return 1

    display.section_header(f"BATCH SCAN — {len(targets)} TARGET(S)")

    sem = asyncio.Semaphore(max(1, getattr(args, "batch_concurrency", DEFAULT_BATCH_CONCURRENCY)))
    results: list[tuple[str, int, Optional[ScanStats]]] = []

    async def _one(target: str) -> None:
        async with sem:
            output_base = f"{args.output}_{safe_filename(target)}" if args.output else None
            config = _build_audit_config(args, target, provider, api_key, output_base, quiet, verbose, debug)
            if not quiet:
                display.step(f"Scanning: {target}")
            code, stats = await _run_one_target(args, display, config, target, quiet)
            results.append((target, code, stats))

    await asyncio.gather(*(_one(t) for t in targets))

    if args.output:
        summary = {
            "meta": {"tool": __tool_name__, "version": __version__, "targets": len(targets)},
            "results": [
                {
                    "target": t,
                    "risk_score": s.risk_score if s else None,
                    "total_findings": len(s.findings) if s else None,
                    "exit_code": code,
                }
                for t, code, s in results
            ],
        }
        Path(f"{args.output}_batch_summary.json").write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
        if not quiet:
            display.kv("BATCH SUMMARY", f"{args.output}_batch_summary.json")

    return 2 if any(code == 2 for _, code, _ in results) else (1 if any(code == 1 for _, code, _ in results) else 0)


# ── Continuous / interval scan mode (--interval SECONDS) ───────────────────────

def _run_interval(
    args, display: PhaseDisplay, provider, api_key, quiet: bool, verbose: bool, debug: bool
) -> int:
    """
    Drift-detection mode: re-run the exact same scan on a fixed timer until
    interrupted (Ctrl+C). Each run is a normal, independent scan — it writes
    its own reports (a per-run suffix is appended to -o so runs don't
    overwrite each other) and is recorded to scan history like any other
    scan, so `cloudaudit history` / `cloudaudit diff` naturally show drift
    across runs of the same target over time.
    """
    url = args.url
    interval = args.interval
    if interval < DEFAULT_MIN_SCAN_INTERVAL:
        display.warning(
            f"--interval {interval:g}s is below the minimum of {DEFAULT_MIN_SCAN_INTERVAL:g}s "
            f"— using {DEFAULT_MIN_SCAN_INTERVAL:g}s instead."
        )
        interval = DEFAULT_MIN_SCAN_INTERVAL

    base_output = getattr(args, "output", None)
    run_number  = 0
    last_code   = 0

    try:
        while True:
            run_number += 1
            if not quiet:
                display.section_header(f"CONTINUOUS SCAN — RUN #{run_number}")
            run_output = f"{base_output}_run{run_number}" if base_output else None
            try:
                run_config = _build_audit_config(args, url, provider, api_key, run_output, quiet, verbose, debug)
            except Exception as exc:
                display.error(f"Configuration error: {exc}")
                return 1

            last_code, _ = asyncio.run(_run_one_target(args, display, run_config, url, quiet))

            if not quiet:
                print(f"  {C.GREY}Next run in {interval:g}s — press Ctrl+C to stop.{C.RESET}\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}  Continuous scan stopped after {run_number} run(s).{C.RESET}")
        return last_code


# ── Main ───────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    parser = build_parser()
    args   = parser.parse_args(argv)

    quiet   = getattr(args, "silent", False) or getattr(args, "quiet", False)
    verbose = getattr(args, "verbose", False)
    debug   = getattr(args, "debug", False)

    configure_logging(verbose=verbose, debug=debug)
    display = PhaseDisplay(quiet=quiet, verbose=verbose)

    # ── Config subcommand ────────────────────────────────────────────────────
    if args.subcommand == "config":
        return handle_config(args, display)

    # ── Diff subcommand ──────────────────────────────────────────────────────
    if args.subcommand == "diff":
        return handle_diff(args, display)

    # ── History subcommand ───────────────────────────────────────────────────
    if args.subcommand == "history":
        return handle_history(args, display)

    # ── init-ci subcommand ───────────────────────────────────────────────────
    if args.subcommand == "init-ci":
        return handle_init_ci(args, display)

    # ── selftest subcommand ──────────────────────────────────────────────────
    if args.subcommand == "selftest":
        return handle_selftest(args, display)

    # ── Named profile (--profile NAME) — merges into args before scan setup ──
    try:
        apply_profile(parser, args)
    except SystemExit as exc:
        return exc.code or 1

    # ── Scan mode (single target, batch, or docker image) ───────────────────
    print_banner(quiet)

    if not args.url and not getattr(args, "targets_file", None) and not getattr(args, "scan_docker_image", None):
        parser.print_help()
        return 1

    if getattr(args, "interval", None) and (not args.url or getattr(args, "targets_file", None) or getattr(args, "scan_docker_image", None)):
        print(f"{C.RED}  [ERROR]{C.RESET} --interval is only supported for single-target scans (-u URL).", file=sys.stderr)
        return 1

    if not getattr(args, "confirm_ownership", False):
        print_ownership_notice(quiet)
        print(f"{C.RED}  [ERROR]{C.RESET} --confirm-ownership is required.", file=sys.stderr)
        return 1

    if not getattr(args, "org_name", ""):
        print(f"{C.RED}  [ERROR]{C.RESET} --org-name is required.", file=sys.stderr)
        return 1

    display.phase("init")

    # Check for stored keys first
    from cloudaudit.config_mgr.key_manager import SecureKeyStore
    store = SecureKeyStore()

    provider = getattr(args, "provider", None)
    api_key  = getattr(args, "api_key", None)

    # Load from secure store if not on CLI
    if provider and not api_key:
        api_key = store.get(provider)
        if api_key:
            display.step(f"Using stored key for {provider}")

    # Interactive AI setup if no provider given and we're in a terminal.
    # stdin can report isatty()==True yet still not be a real interactive
    # session (e.g. some CI runners, redirected-but-tty-like environments) —
    # fall back to heuristic analysis instead of crashing with an EOFError.
    if not provider and not quiet and sys.stdin.isatty():
        try:
            provider, api_key = interactive_ai_setup(display)
        except EOFError:
            display.warning("No interactive input available — using heuristic analysis.")
            provider, api_key = None, None

    display.phase_done()

    # Update check
    run_update_check(display, skip=getattr(args, "no_update", False))

    # Ownership confirmation
    display.phase("ownership")
    print_ownership_notice(quiet)
    display.status("Organisation", args.org_name)
    display.status("Target URL",   args.url or args.targets_file or args.scan_docker_image)
    display.phase_done("confirmed")

    # Graceful interrupt
    def _shutdown(sig, frame):
        print(f"\n{C.YELLOW}  Interrupted.{C.RESET}")
        sys.exit(130)
    signal.signal(signal.SIGINT, _shutdown)

    # ── Docker image layer scan ───────────────────────────────────────────────
    if getattr(args, "scan_docker_image", None):
        try:
            display.phase("detect", args.scan_docker_image)
            stats = asyncio.run(_run_docker_scan(args))
            display.phase_done()

            if not quiet:
                print_container_info(display, stats)
                print_audit_summary(display, stats)
                print_findings_detail(display, stats)

            if getattr(args, "output", None):
                display.phase("reports")
                from cloudaudit.reports.generator import ReportGenerator
                written = ReportGenerator.write_all(stats, args.output, args.format, org=args.org_name)
                display.phase_done()
                if written and not quiet:
                    display.section_header("REPORTS WRITTEN")
                    for p in written:
                        display.kv(p.suffix.lstrip(".").upper(), str(p))

            _post_scan_actions(args, stats, target=args.scan_docker_image)

            if not quiet:
                print(f"\n  {C.GREY}Powered by {__author__} | {__author_url__}{C.RESET}\n")
            return _severity_exit_code(stats, getattr(args, "fail_on_severity", None))
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}  Interrupted{C.RESET}")
            return 130
        except Exception as exc:
            display.error(f"Fatal: {exc}")
            if debug:
                import traceback; traceback.print_exc()
            return 1

    # ── Batch mode (--targets-file) ──────────────────────────────────────────
    if getattr(args, "targets_file", None):
        try:
            code = asyncio.run(_run_batch(args, display, provider, api_key, quiet, verbose, debug))
            if not quiet:
                print(f"\n  {C.GREY}Powered by {__author__} | {__author_url__}{C.RESET}\n")
            return code
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}  Interrupted{C.RESET}")
            return 130

    # ── Continuous scan mode (--interval SECONDS) ─────────────────────────────
    if getattr(args, "interval", None):
        code = _run_interval(args, display, provider, api_key, quiet, verbose, debug)
        if not quiet:
            print(f"\n  {C.GREY}Powered by {__author__} | {__author_url__}{C.RESET}\n")
        return code

    # ── Single-target scan ────────────────────────────────────────────────────
    try:
        config = _build_audit_config(
            args, args.url, provider, api_key, getattr(args, "output", None), quiet, verbose, debug
        )
    except Exception as exc:
        display.error(f"Configuration error: {exc}")
        return 1

    try:
        code, stats = asyncio.run(_run_one_target(args, display, config, args.url, quiet))
        if not quiet:
            print(f"\n  {C.GREY}Powered by {__author__} | {__author_url__}{C.RESET}\n")
        return code
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}  Interrupted{C.RESET}")
        return 130


if __name__ == "__main__":
    sys.exit(main())
