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
import signal
import sys
from pathlib import Path
from typing import Optional

import argparse

from cloudaudit.core.config import AuditConfig
from cloudaudit.core.constants import (
    DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_SIZE,
    DEFAULT_RATE_LIMIT_DELAY, DEFAULT_TIMEOUT,
    __tool_name__, __version__, __author__, __author_url__,
)
from cloudaudit.core.engine import AuditEngine
from cloudaudit.core.exceptions import AuditError, OwnershipError, ProviderAuthError
from cloudaudit.core.logger import configure_logging
from cloudaudit.core.models import Severity
from cloudaudit.cli.display import (
    PhaseDisplay, print_banner, print_ownership_notice,
    print_container_info, print_audit_summary, print_findings_detail, C,
)


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

    # ── scan arguments ────────────────────────────────────────────────────────
    p.add_argument("-u", "--url", help="Target cloud storage URL")

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

    p.add_argument("--provider", choices=["gemini","openai","claude","deepseek","ollama","custom"],
                   help="AI provider for semantic analysis and executive summary")
    p.add_argument("--api-key",       help="API key for the selected AI provider")
    p.add_argument("--provider-url",  help="Base URL for custom OpenAI-compatible endpoints")
    p.add_argument("--ollama-url",    default="http://localhost:11434",
                   help="Ollama server URL (default: http://localhost:11434)")
    p.add_argument("--ollama-model",  default="llama3", help="Ollama model name (default: llama3)")

    p.add_argument("-t","--threads",  type=int, default=DEFAULT_MAX_CONCURRENT,
                   help=f"Concurrent HTTP requests (default: {DEFAULT_MAX_CONCURRENT})")
    p.add_argument("--timeout",       type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--rate-limit",    type=float, default=DEFAULT_RATE_LIMIT_DELAY)

    p.add_argument("-o","--output",   help="Output base path (extensions added automatically)")
    p.add_argument("--format", choices=["json","html","markdown","all"], default="all",
                   help="Report format (default: all)")
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

    print("  Use --list-providers, --set-api <provider>, or --remove-api <provider>")
    return 0


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


# ── Main ───────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    parser = build_parser()
    args   = parser.parse_args(argv)

    quiet   = args.silent or getattr(args, "quiet", False)
    verbose = getattr(args, "verbose", False)
    debug   = getattr(args, "debug", False)

    configure_logging(verbose=verbose, debug=debug)
    display = PhaseDisplay(quiet=quiet, verbose=verbose)

    # ── Config subcommand ────────────────────────────────────────────────────
    if args.subcommand == "config":
        return handle_config(args, display)

    # ── Scan mode ────────────────────────────────────────────────────────────
    print_banner(quiet)

    if not args.url:
        parser.print_help()
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

    # Interactive AI setup if no provider given and we're in a terminal
    if not provider and not quiet and sys.stdin.isatty():
        provider, api_key = interactive_ai_setup(display)

    display.phase_done()

    # Update check
    run_update_check(display, skip=getattr(args, "no_update", False))

    # Ownership confirmation
    display.phase("ownership")
    print_ownership_notice(quiet)
    display.status("Organisation", args.org_name)
    display.status("Target URL",   args.url)
    display.phase_done("confirmed")

    # Build config
    try:
        ignore_paths: set = set()
        if getattr(args, "ignore_paths", None):
            ignore_paths = {p.strip() for p in args.ignore_paths.split(",") if p.strip()}

        extensions: set = set()
        if getattr(args, "extensions", None):
            extensions = {e.strip().lstrip(".").lower() for e in args.extensions.split(",") if e.strip()}

        config = AuditConfig(
            url=args.url,
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
            output_base=getattr(args, "output", None),
            output_format=args.format,
            min_severity=args.min_severity,
            verbose=verbose,
            debug=debug,
            quiet=quiet,
        )
        # Store provider_url for custom endpoints
        if getattr(args, "provider_url", None):
            config.__dict__["provider_url"] = args.provider_url

    except Exception as exc:
        display.error(f"Configuration error: {exc}")
        return 1

    # Graceful interrupt
    def _shutdown(sig, frame):
        print(f"\n{C.YELLOW}  Interrupted.{C.RESET}")
        sys.exit(130)
    signal.signal(signal.SIGINT, _shutdown)

    # Run audit
    try:
        engine = AuditEngine(config, display=display)

        display.phase("detect", args.url)
        # Phases are logged internally — engine calls display internally via logger

        stats = asyncio.run(engine.run())

        print_container_info(display, stats)
        print_audit_summary(display, stats)
        print_findings_detail(display, stats)

        # Write reports
        display.phase("reports")
        written = engine.write_reports()
        display.phase_done()
        if written and not quiet:
            display.section_header("REPORTS WRITTEN")
            for p in written:
                display.kv(p.suffix.lstrip(".").upper(), str(p))

        # AI summary to terminal
        if verbose and stats.ai_summary:
            display.section_header("AI EXECUTIVE SUMMARY")
            print()
            for line in stats.ai_summary.split("\n"):
                print(f"  {line}")

        has_high = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in stats.findings
        )

        if not quiet:
            print(f"\n  {C.GREY}Powered by {__author__} | {__author_url__}{C.RESET}\n")

        return 2 if has_high else 0

    except OwnershipError as exc:
        display.error(f"Ownership error: {exc}")
        return 1
    except AuditError as exc:
        display.error(f"Audit error: {exc}")
        return 1
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}  Interrupted{C.RESET}")
        return 130
    except Exception as exc:
        display.error(f"Fatal: {exc}")
        if debug:
            import traceback; traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
