"""cloudaudit — Runtime Configuration"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Set

from cloudaudit.core.constants import (
    DEFAULT_MAX_CONCURRENT,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_RETRIES,
    DEFAULT_MIN_ENTROPY,
    DEFAULT_RATE_LIMIT_DELAY,
    DEFAULT_RETRY_DELAY,
    DEFAULT_TIMEOUT,
    PROVIDER_ENV_KEYS,
    ARCHIVE_WORKSPACE,
)
from cloudaudit.core.exceptions import ConfigError


@dataclass
class AuditConfig:
    """
    Complete runtime configuration for an audit run.

    All write/delete probing is permanently disabled at the architecture level.
    This config supports only read-only GET/HEAD/OPTIONS inspection.
    """

    # ── Target ────────────────────────────────────────────────────────────────
    url: str = ""

    # ── Ownership declaration ─────────────────────────────────────────────────
    # The CLI requires explicit confirmation before scanning.
    # This flag must be True for the engine to start.
    ownership_confirmed: bool = False
    owner_org: str = ""         # Organisation name for the audit report

    # ── Performance ────────────────────────────────────────────────────────────
    max_concurrent:    int   = DEFAULT_MAX_CONCURRENT
    timeout:           float = DEFAULT_TIMEOUT
    max_retries:       int   = DEFAULT_MAX_RETRIES
    retry_delay:       float = DEFAULT_RETRY_DELAY
    rate_limit_delay:  float = DEFAULT_RATE_LIMIT_DELAY

    # ── Scope limits ───────────────────────────────────────────────────────────
    max_file_size:  int = DEFAULT_MAX_FILE_SIZE
    max_depth:      int = DEFAULT_MAX_DEPTH
    min_entropy:    float = DEFAULT_MIN_ENTROPY

    # ── File filtering ─────────────────────────────────────────────────────────
    extensions:        Set[str] = field(default_factory=set)  # empty = all sensible defaults
    ignore_extensions: Set[str] = field(default_factory=set)
    ignore_paths:      Set[str] = field(default_factory=lambda: {
        "__MACOSX", ".git", ".svn", ".DS_Store", "node_modules",
        "bower_components", "vendor",
    })

    # ── Feature flags ──────────────────────────────────────────────────────────
    extract_archives: bool = False     # Download and inspect archives
    deep_metadata:    bool = False     # EXIF / binary metadata extraction
    auto_detect:      bool = True      # Auto-detect container type from response

    # ── Output ─────────────────────────────────────────────────────────────────
    output_base:   Optional[str] = None
    output_format: str = "all"         # "json" | "html" | "markdown" | "all"
    min_severity:  str = "LOW"

    # ── Verbosity ─────────────────────────────────────────────────────────────
    verbose: bool = False
    debug:   bool = False
    quiet:   bool = False

    # ── AI provider ───────────────────────────────────────────────────────────
    provider:    Optional[str] = None
    api_key:     Optional[str] = None     # NEVER logged
    ollama_url:  str = "http://localhost:11434"
    ollama_model: str = "llama3"
    provider_url: Optional[str] = None    # --provider-url (OpenAI-compatible endpoints)
    ai_model:     Optional[str] = None    # --model (override automatic model selection)

    # ── Workspace ─────────────────────────────────────────────────────────────
    workspace: str = ARCHIVE_WORKSPACE

    # ── v1.1.0 feature flags ──────────────────────────────────────────────────
    baseline_path:        Optional[str] = None   # --baseline FILE (accepted-risk suppression)
    custom_patterns_path: Optional[str] = None   # --custom-patterns FILE
    checkpoint_path:      Optional[str] = None   # --checkpoint FILE (periodic progress save)
    resume_path:          Optional[str] = None   # --resume FILE (continue an interrupted crawl)
    dry_run:              bool = False           # --dry-run (enumerate only, no content analysis)
    aws_acl_check:        bool = False           # --aws-acl-check (boto3 ACL/policy enrichment)
    webhook_url:          Optional[str] = None   # --webhook-url URL
    fail_on_severity:     Optional[str] = None   # --fail-on-severity {low,medium,high,critical}
    record_history:       bool = True            # scan history is recorded unless disabled

    def validate(self) -> None:
        if not self.url:
            raise ConfigError("Target URL is required.")
        if not self.url.startswith(("http://", "https://")):
            raise ConfigError(f"URL must start with http:// or https://: {self.url!r}")
        if not self.ownership_confirmed:
            raise ConfigError(
                "Ownership must be confirmed before scanning. "
                "Use --confirm-ownership and --org-name."
            )
        if not self.owner_org:
            raise ConfigError("--org-name is required to label the audit report.")
        if self.max_concurrent < 1 or self.max_concurrent > 100:
            raise ConfigError("max_concurrent must be between 1 and 100.")
        if self.timeout <= 0:
            raise ConfigError("timeout must be positive.")

    def resolve_api_key(self) -> Optional[str]:
        """
        Resolve AI provider API key from:
          1. Explicit --api-key flag (self.api_key)
          2. Environment variable  (e.g. GEMINI_API_KEY, plus known alternates)
          3. .cloudaudit.env file in the current directory
          4. The encrypted key store (cloudaudit config --set-api)
        The value is normalised (whitespace/quotes/"Bearer " stripped) and never logged.
        """
        from cloudaudit.config_mgr.key_manager import resolve_api_key
        key, _source = resolve_api_key(self.provider, self.api_key)
        return key
