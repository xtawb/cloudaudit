# Changelog

All notable changes to CloudAudit are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.3.0] — 2026-10-09

The "works without an API key" release: a new offline Local Intelligence
Engine, a rebuilt AI provider layer, and a round of detection-accuracy fixes.

### Added

* **Local Intelligence Engine** (`intelligence/local_ai.py`) — runs offline on
  every scan, no API key required:
  * statistical **token classifier** (charset-normalised entropy, English
    bigram language model, character-class transitions, benign-format
    recognition) used to tell secrets from hashes, UUIDs, identifiers and paths;
  * **semantic key/value analysis** across env / YAML / JSON / INI / XML / code
    that understands key names (`dbPassword` vs `password_min_length`) and
    ignores placeholders, `${VAR}` references and prose;
  * **config auditor** with 27 IaC / container / server / database
    misconfiguration rules;
  * **JWT inspection** (expired / still valid / non-expiring / unsigned);
  * **confidence calibration** by path context, **noise aggregation**, and a
    **correlation engine** that reports compound exposures;
  * **file risk ranking** (`scan.file_risk`) and a data-driven **executive
    summary** with key risk drivers, a phased remediation plan and compliance
    impact.
* **31 new credential formats** — Slack, Stripe, SendGrid, Twilio, OpenAI,
  Anthropic, npm, PyPI, DigitalOcean, Hugging Face, Telegram, Shopify, Google
  OAuth, Entra ID, Databricks, Vault, Terraform Cloud, Docker Hub, Grafana,
  New Relic, Mailgun, Square, Postman, Linear, age, GitLab runner tokens,
  URL-embedded credentials, connection-string passwords, US SSNs (51 rules, up
  from 20).
* **19 new sensitive-file inventory rules** — SSH keys, key stores, Git
  metadata, kubeconfig, Docker config, database dumps, shell history,
  `.tfvars`, secrets files, backups, network captures and more.
* `cloudaudit config --test-api PROVIDER` — tests the key a scan would use and
  distinguishes *valid*, *no quota*, *rejected* and *could not verify*.
* `--model NAME` to override automatic model selection; `--no-ai` to force the
  offline engine; `--provider anthropic` alias; the provider is auto-detected
  from `--api-key` when `--provider` is omitted.
* Report fields `scan.ai_engine`, `scan.ai_status`, `scan.file_risk`, and
  per-finding `occurrences`.
* A unit-test suite (`python -m unittest discover -s tests -t .`), and
  `cloudaudit selftest` now also exercises the offline engine.

### Fixed — API keys

* Modern key formats were rejected by the format check (`sk-proj-…` OpenAI
  keys contain `-`/`_`; Gemini `AQ.` keys). The check is now advisory.
* Pasted keys are normalised — whitespace, newlines, quotes, zero-width
  characters, `Bearer ` and `NAME=value` wrappers were stored verbatim and
  later rejected by the provider.
* Saving a key when the encrypted store could not be decrypted silently wiped
  every other provider's key. The unreadable store is now kept aside, and
  writes are atomic.
* `validate_key_live` reported every failure as "invalid", including network
  errors and exhausted quota, and returned no reason for OpenAI/Claude.
* Key lookup was inconsistent between the CLI and the engine; there is now one
  resolver (flag → env var → alternates → `.cloudaudit.env` → key store).
  `.cloudaudit.env` matching with an empty variable name is fixed.
* `--api-key` without `--provider` was silently ignored in non-interactive
  runs; `--provider custom` without `--provider-url` produced an "unknown
  provider" error; the interactive menu was hardcoded to `[1-5]`.
* API keys could appear in logged provider errors (Gemini puts the key in the
  request URL). Error text is now scrubbed.

### Fixed — AI

* **An invalid key aborted the summary** — auth errors were re-raised through
  the provider chain, leaving `[Summary generation failed]` in the report and
  repeating the failed request for every analysed file. A circuit breaker now
  disables the provider once and the local engine takes over.
* **Truncated audit JSON** — scan data was cut at 12,000 characters before
  being parsed, producing invalid JSON for any non-trivial scan; the fallback
  summary then reported "Unknown" and 0 findings. Remote providers now receive
  a compact, always-valid digest; the local engine reads the full data.
* **Gemini** — model selection could pick TTS / image / preview models or a
  `pro` model with zero free-tier quota, with no fallback; quota errors were
  reported as an invalid key; `response.text` could raise on blocked or empty
  candidates; thinking models returned empty text at the default token limit.
* **OpenAI** — newer models reject `max_tokens`; the request now adapts
  between `max_tokens` and `max_completion_tokens`. Custom endpoints were sent
  `gpt-4o-mini` regardless of what they serve.
* **Claude** — the fallback list contained only retired model IDs, and the
  reply was read from `content[0]` even when that block was not text.
* **Ollama** — a missing model failed every request; an installed model is now
  used instead.
* AI replies wrapped in markdown fences or prose are parsed correctly; AI
  findings are de-duplicated against deterministic findings, categorised, and
  have any echoed token-shaped text redacted.
* No retry or back-off existed for rate limits or transient errors.
* The duplicate legacy implementation in `providers/ai_provider.py` (stale
  model names, no error handling) is replaced by a shim over the maintained one.

### Fixed — Detection

* **False CRITICAL "duplicate secret" findings** — duplicates were detected by
  hashing the redacted match (first six characters), so every pair of JWTs or
  `AKIA…` keys was "the same secret". A salted hash of the raw value is used.
* `INTERNAL_IP` and `SSH_CONFIG` never fired under the default entropy
  threshold; `SSH_CONFIG` matched the word "host" in any text.
* `ENV_VARIABLE_SECRET` captured the variable name instead of the value.
* Placeholders (`changeme`, `your_api_key_here`, `${VAR}`, AWS documentation
  keys) were reported as secrets.
* `CREDIT_CARD` matched any 16-digit number (now Luhn-validated);
  `AZURE_SAS_TOKEN` matched any `sig=` parameter; `EMAIL_ADDRESS` matched
  `icon@2x.png`.
* Every occurrence of a value was a separate finding, and several rules
  reported the same text; emails and IP addresses were counted as "credential
  reuse".
* Lockfiles and minified bundles produced one entropy finding per line.
* Context snippets could contain complete tokens shorter than 40 characters.
* Line-number lookup re-scanned the file for every match (quadratic on large
  files).

### Changed

* Risk score v3: confidence-weighted, diminishing returns per rule, explicit
  floors for confident credentials and compound exposures.
* Docker image scans now get the same calibration, aggregation, correlation
  and executive summary as storage scans.
* `pyproject.toml`: AI SDKs are extras only (`gemini`, `openai`, `deepseek`,
  `claude`, `all`) — malformed `extra ==` markers removed from core dependencies.

---

## [1.2.0] — 2026

### Added

* **PDF report export** — `--format pdf` renders the existing HTML report to
  PDF via the optional `xhtml2pdf` dependency (`pip install cloudaudit[pdf]`),
  failing with a clear install hint rather than silently producing nothing
  if the dependency is missing.
* **Continuous / interval scan mode** — `--interval SECONDS` re-runs the same
  scan on a timer until interrupted (Ctrl+C), logging each run to local scan
  history for drift detection.
* **Structured Terraform state scanning** — `intelligence/terraform_scanner.py`
  parses `.tfstate` files as JSON (not just regex) and flags sensitive
  attribute names under `resources[].instances[].attributes`, tagging each
  finding with the Terraform resource address.
* **CI workflow scaffold generator** — `cloudaudit init-ci` writes a
  ready-to-use GitHub Actions workflow that runs CloudAudit with
  `--format sarif` and uploads results via `github/codeql-action/upload-sarif`.
* **Named config profiles** — `cloudaudit config --save-profile NAME` saves
  the current scan flags to `~/.cloudaudit/profiles/<name>.yml`;
  `--profile NAME` loads one, with explicit CLI flags always taking
  precedence. API keys, target URL, output path, and ownership flags are
  never persisted to a profile.
* **Scanner plugin system** — `scanners/plugin_loader.py` discovers
  third-party scanners registered via the `cloudaudit.scanners` Python
  entry-point group and runs them alongside the built-in scanners during
  Phase 4 content analysis.
* **Live terminal dashboard** — `--tui` shows a real-time `rich.live`
  dashboard (files crawled, findings by severity, current phase) as an
  alternative to the phase-based terminal output.
* **Self-test command** — `cloudaudit selftest` runs the secret scanner and
  redaction pipeline against built-in synthetic known-bad samples and prints
  PASS/FAIL per check, so you can sanity-check detection after installing
  or upgrading.
* **Slack-formatted executive summary** — `--slack-summary` (or
  `--webhook-format slack`, or auto-detection of `hooks.slack.com` in
  `--webhook-url`) posts a Slack Block Kit–formatted summary in addition to
  the existing generic webhook JSON payload.
* **Exposure trend delta** — when local scan history has a previous scan of
  the same target, the executive summary (AI or heuristic) now reports the
  change since that scan (new/resolved findings, risk score delta).

### Fixed

* **ReadTheDocs site was mostly empty** — the live site
  (https://cloudaudit.readthedocs.io) is built with MkDocs
  (`.readthedocs.yaml` uses the `mkdocs:` builder), but nine of the twelve
  pages MkDocs actually serves (`installation.md`, `configuration.md`,
  `architecture.md`, `ai-engine.md`, `detection-algorithms.md`,
  `risk-engine.md`, `reporting.md`, `update-system.md`, `contributing.md`)
  were near-empty placeholders pointing at a parallel set of `.rst`
  (Sphinx) files that were never built. All nine pages now carry real,
  current content; the unused `docs/*.rst` files and `docs/conf.py` have
  been removed to eliminate the dead duplicate documentation system. Added
  a new `docs/cli-reference.md` page and a `docs/changelog.md` page (linked
  from a new "Releases" nav section alongside the GitHub Releases page).
* **Inconsistent license badges** — README showed both a "Proprietary" and
  an "MIT" badge; standardised on MIT, matching the repository's `LICENSE`
  file.

---

## [1.1.0] — 2026

### Added

* **SARIF 2.1.0 output** — `--format sarif` produces a valid SARIF log
  (rules, results, partial fingerprints) for ingestion by GitHub Advanced
  Security code scanning or any other SARIF consumer.
* **CSV export** — `--format csv` writes a flat findings table.
* **Baseline / allowlist suppression** — `--baseline FILE` (JSON or YAML) of
  previously-accepted finding fingerprints; matching findings are suppressed
  and counted separately as "previously accepted risk" (`suppressed_count`).
* **Diff mode** — new `cloudaudit diff <old_report.json> <new_report.json>`
  subcommand prints new / resolved / unchanged findings between two JSON
  reports (exits non-zero if new findings appeared, for CI use).
* **Local scan history** — every scan is recorded to a SQLite database at
  `~/.cloudaudit/history.db` (timestamp, target, risk score, finding counts).
  New `cloudaudit history [--limit N]` subcommand lists past scans.
  Opt out per-scan with `--no-history`.
* **Multi-target batch scanning** — `--targets-file urls.txt` scans multiple
  targets (bounded by `--batch-concurrency`, default sequential), writing a
  separate report set per target plus a combined `<output>_batch_summary.json`.
* **Configurable concurrency** — `--concurrency` (alias for `--threads`) now
  also bounds the crawler's recursive HTML directory listing phase, which
  previously issued unbounded concurrent requests regardless of this setting.
  `--rate-limit` continues to control the per-request delay used for throttling.
* **Resume/checkpoint support** — `--checkpoint FILE` periodically persists
  crawl/analysis progress; `--resume FILE` continues an interrupted scan
  instead of restarting the crawl from scratch.
* **Custom secret pattern plugins** — `--custom-patterns FILE` merges
  user-supplied YAML regex patterns (name, regex, severity, description,
  compliance tags) into the secret scanner's pattern set.
* **GitLab / Bitbucket generic package registry detection** — the container
  detector now recognises GitLab generic package registry URLs (enumerated
  read-only via the GitLab packages JSON API) and Bitbucket repository
  Downloads sections as additional container types.
* **Docker image layer scanning** — `--scan-docker-image <registry>/<image>:<tag>`
  performs a read-only pull of the image manifest and layers via the Docker
  Registry HTTP API v2 (GET only), extracts layer contents with the existing
  archive-extraction safeguards, and runs the secret scanner over them.
* **AWS bucket ACL/policy inspection** — `--aws-acl-check` (optional `boto3`
  dependency) enriches AWS S3 findings with real `get_bucket_acl` /
  `get_bucket_policy` / `get_bucket_policy_status` detail when AWS credentials
  are available; skips gracefully otherwise.
* **Webhook notifications** — `--webhook-url URL` posts a redacted, Slack/Discord-
  compatible JSON scan summary (target, risk score, severity counts, top
  findings) at the end of a scan. Never sends raw secret values.
* **Dry-run mode** — `--dry-run` enumerates discovered files (size, type)
  without downloading or analysing their content.
* **CI exit-code gating** — `--fail-on-severity {low,medium,high,critical}`
  makes the process exit non-zero if any finding at or above that severity
  is present.

### Fixed

* Heuristic AI executive summary always reported "Unknown"/zero findings
  because it read scan data from a `"scan"` wrapper key that
  `ScanStats.to_dict()` never produces — the summary is now populated correctly.
* `cloudaudit config --set-api gemini` always reported the key as valid: the
  live-validation path treated Gemini's structured `{"valid": ..., "error": ...}`
  result as a boolean instead of unpacking it.
* Fixed a resource leak: HTTP responses were never released back to the
  connection pool when the crawler or analyser short-circuited on a non-200
  status or an oversized `Content-Length` — under a large crawl this could
  exhaust the connection pool.
* Replaced deprecated `asyncio.get_event_loop()` calls in the engine with
  `asyncio.get_running_loop()`.
* The `EMAIL_ADDRESS` (and other PII) secret patterns were silently and
  permanently suppressed by the entropy gate under the default
  `--min-entropy`, because structured PII is naturally low-entropy; the gate
  now only applies to non-PII secret patterns.
* The recursive HTML directory crawler ignored `--threads`/`--concurrency`
  entirely, issuing unbounded concurrent requests for every discovered
  subdirectory; it is now bounded by a semaphore sized from that setting.
* Fixed a truncation-ellipsis bug in the terminal findings detail view that
  appended `...` to every recommendation even when it wasn't truncated.
* Fixed a real resource/file-lock leak in the new local scan-history store:
  `sqlite3.Connection`'s context manager only manages the transaction, not
  the connection — connections are now explicitly closed.
* Interactive AI provider setup could crash the whole process with an
  uncaught `EOFError` when stdin reported `isatty()==True` but had no real
  input available; it now falls back to heuristic analysis.

---

## [1.0.2] — 2026

### Changed

* **AI Provider Architecture — Stability & Hardening**

  * Refactored base provider interface to enforce stricter contract compliance.
  * Unified structured response format across all AI providers.
  * Standardized exception hierarchy for provider-level errors.
  * Improved fallback resolution order (Primary → Secondary → Heuristic).

* **GeminiProvider — Production Stability Enhancements**

  * Added capability filtering to select text-generation models only.
  * Implemented smart model ranking based on context window and token limits.
  * Added internal retry mechanism for transient API failures.
  * Improved structured configuration handling for temperature and token limits.
  * Explicit separation between authentication, quota, and model errors.

* **Executive Summary Engine**

  * Integrated summary generation directly into the scan result pipeline.
  * Added deterministic fallback summary if AI provider fails.
  * Added validation guard to prevent empty or malformed prompt submission.
  * Prevented provider failures from interrupting the audit orchestrator.

* **Auto-Update System**

  * Improved semantic version parsing and comparison logic.
  * Hardened GitHub API response validation.
  * Prevented crash on malformed or incomplete release metadata.

* **CLI Improvements**

  * Enhanced structured phase rendering output.
  * Improved async cancellation handling (safe SIGINT/SIGTERM exit).
  * Cleaner ANSI formatting for small terminal environments.

* **Secret Scanner Engine**

  * Calibrated entropy threshold to reduce false positives.
  * Improved normalization before entropy scoring.
  * Reduced benign high-entropy string misclassification.

* **Logging & Error Handling**

  * Improved structured logging across AI and scanning layers.
  * Removed silent exception swallowing in async tasks.
  * Added explicit timeout safeguards for AI provider calls.

### Fixed

* Fixed residual Gemini 404 edge cases caused by API version mismatches.
* Fixed executive summary failure when model list returned empty.
* Fixed AI provider crash propagating to the audit orchestrator.
* Fixed malformed AI config causing token overflow edge case.
* Fixed auto-update crash when GitHub API schema changed.
* Fixed CLI freeze when provider timeout exceeded event loop threshold.
* Fixed rare async race condition in phase aggregation.

---

## [1.0.1] — 2025

### Changed

* **AI Integration — GeminiProvider complete rewrite**

  * Replaced deprecated `google.generativeai` package with the official modern
    `google.genai` SDK (`from google import genai`).
  * Dynamic model discovery via `client.models.list()` — no model names are
    ever hardcoded. The provider automatically selects the most capable
    non-deprecated text-generation model available for the supplied API key.
  * `complete()` rewritten to use `client.models.generate_content()` with
    structured `GenerateContentConfig` for temperature and token control.
  * `validate_key()` now returns a structured `dict` with `valid`, `model`,
    and `error` keys instead of a bare `bool`.
  * `generate_executive_summary()` uses the dynamically selected model —
    eliminates all 404 "model not found" errors.
  * Auth and permission errors are surfaced as `ProviderAuthError` immediately
    rather than being silently swallowed.
  * Comprehensive docstrings added throughout.

* **Documentation infrastructure**

  * Added `.readthedocs.yaml` (ReadTheDocs v2 build config).
  * Added `mkdocs.yml` (Material theme, navigation, API reference).
  * Added `docs/conf.py` (Sphinx config, version pulled dynamically).
  * Added `docs/requirements.txt` with pinned documentation dependencies.

* **Versioning** — bumped to `v1.0.1` across:

  * `cloudaudit/__init__.py`
  * `cloudaudit/core/constants.py`
  * `pyproject.toml`
  * Report footer
  * README badges

* **README** — enhanced badges, added detailed Technical Architecture section.

### Fixed

* Executive summary no longer triggers 404 errors (dynamic model selection).
* AI layer no longer crashes the framework on model errors (graceful fallback).
* `pyproject.toml` optional dependency updated from `google-generativeai` to
  `google-genai`.

---

## [1.0.0] — Initial Release

* 11-phase async audit orchestrator (AWS S3, GCS, Azure Blob, Open Directory).
* Deterministic secret scanning (20+ patterns, Shannon entropy gate).
* AI semantic analysis layer (Gemini, OpenAI, Claude, DeepSeek, Ollama).
* Heuristic fallback provider (always available, zero external calls).
* JSON + HTML + Markdown report generation.
* Encrypted API key storage (Fernet AES-128-CBC + PBKDF2-SHA256).
* Composite risk scoring v2 (weighted severity × category multipliers).
* CIS / NIST / SOC2 / ISO27001 / PCI-DSS compliance mapping.
* Auto-update system via GitHub releases API.
