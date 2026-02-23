# Changelog

All notable changes to CloudAudit are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
