# Architecture

CloudAudit is built around a modular, phase-based async architecture. Each
phase is independently testable and replaceable, and third parties can
extend the content-analysis phase with their own scanner plugins without
modifying this codebase.

## Module Structure

```text
cloudaudit/
├── cli/            User interface layer (argparse, phase display, --tui dashboard)
├── core/           Config, models, engine, exceptions, checkpoint
├── ai/             AI provider abstraction + semantic analysis
├── config_mgr/     Key management, auto-update, named profiles, scan history
├── intelligence/   Advanced detection algorithms (entropy, dedup, risk, Terraform state)
├── reports/        Multi-format output generation (JSON/HTML/Markdown/SARIF/CSV/PDF)
├── scanners/       Cloud-specific crawlers, content scanners, plugin loader
└── utils/          Shared utilities (HTTP client, entropy, redaction, webhooks)
```

## The Engine Pipeline

`AuditEngine` (in `core/engine.py`) orchestrates the audit via Python's
`asyncio` event loop. File analysis runs concurrently, bounded by a
configurable semaphore (`--threads`/`--concurrency`).

**Phase 0 — Ownership Gate**

`AuditConfig.validate()` runs before any network activity and raises
`ConfigError`/`OwnershipError` if `ownership_confirmed` is `False` or
`owner_org` is empty. This is enforced at the model level and cannot be
bypassed through the public API.

**Phase 1 — Container Detection**

`ContainerDetector` inspects HTTP response headers, XML namespace
declarations, hostname patterns, and body fingerprints to classify the
container as `AWS_S3`, `GCS`, `AZURE_BLOB`, `CLOUDFRONT`, `OPEN_DIRECTORY`,
`GITLAB_PACKAGE_REGISTRY`, `BITBUCKET_DOWNLOADS`, or `GENERIC`.

**Phase 2 — Recursive File Crawl**

`FileCrawler` paginates through the full file listing:

- **S3 / GCS** — `ListBucketResult` XML, `IsTruncated` + `ContinuationToken` pagination
- **Azure Blob** — `EnumerationResults` XML, `NextMarker` pagination
- **GitLab generic package registry** — JSON API enumeration of packages/files
- **Bitbucket Downloads / HTML** — recursive `<a href>` link following

**Phase 3 — Misconfiguration Analysis**

`MisconfigAnalyzer` inspects container-level metadata and the file inventory
(before any content is downloaded) for public-access configuration and
known-sensitive filenames (`.env`, `id_rsa`, `.pem`, `*.tfstate`, etc.).

**Phase 4 — Concurrent Content Analysis**

A bounded pool of `asyncio` tasks (default: 8 concurrent) runs, per file:

1. Deterministic secret scanning (`SecretScanner`) — 20+ regex patterns with entropy gates
2. **Dedicated Terraform state scanning** (`TerraformStateScanner`) — for `*.tfstate`/`*.tfstate.backup`
   files, walks the actual `resources[].instances[].attributes` JSON structure
   (rather than relying on regex alone) and flags sensitive attribute *names*
   regardless of the value's entropy, tagging the resource address as context
3. **Third-party scanner plugins** (`scanners/plugin_loader.py`) — any
   package registering the `cloudaudit.scanners` entry point group is
   discovered at engine start-up and run alongside the built-in scanners
4. High-entropy string detection (`EntropyHunter`)
5. AI semantic analysis (`AIFileAnalyzer`) — invoked selectively for high-value files
6. EXIF metadata extraction (`ImageMetaAnalyser`) — for images when `--deep-metadata` is set

**Phase 5 — Archive Extraction**

When `--extract-archives` is set, `ArchiveExtractor` downloads archives and
extracts members with zip-slip protection, a decompression-bomb size limit,
and a 10,000-member cap.

**Phase 6 — Image EXIF Analysis** (integrated into Phase 4)

**Phase 7 — Duplicate & Reuse Detection**

`SecretDeduplicator` correlates findings across files: exact duplicates via
SHA-256 hashes of redacted values, and credential reuse when the same rule
fires across 3+ distinct files.

**Phase 8 — Misconfiguration Aggregation**

**Phase 9 — Risk Scoring v2**

See [Risk Engine](risk-engine.md) for the full scoring formula.

**Phase 10 — Exposure Trend Computation**

The engine looks up the most recent locally-recorded scan of the same target
in `~/.cloudaudit/history.db` (see [Update System](update-system.md) is
unrelated — history lives in `config_mgr/history.py`) and, if found, records
a short trend delta (new/resolved findings per severity since that scan) on
`ScanStats.trend_summary`. This is surfaced in the executive summary and, if
`--webhook-url`/`--slack-summary` is used, in the Slack notification.

**Phase 11 — AI Executive Summary**

`ProviderChain` calls the configured AI provider with a JSON summary of
findings (all secrets already redacted, trend data included). Falls back
automatically to `HeuristicProvider` on any failure. See [AI Engine](ai-engine.md).

**Phase 12 — Report Output**

`ReportGenerator` produces JSON, HTML, Markdown, SARIF, CSV, and/or PDF from
`ScanStats`. See [Reporting](reporting.md).

## Live Progress & the `--tui` Dashboard

`AuditEngine` accepts an optional `on_progress` callback, invoked at
coarse-grained milestones (container detected, crawl complete, each file
analysed, risk scored). `cli/tui.py`'s `TuiDashboard` wraps this in a
`rich.live.Live` panel as an alternative to the default phase-based terminal
output when `--tui` is passed, falling back cleanly to the classic output
if `rich` is unavailable or stdout isn't a real terminal.

## Data Flow

```text
HTTP Response
     |
     v
ContainerInfo (container type, name, region, is_public)
     |
     v
List[ExposedFile] (url, key, size, file_type)
     |
     v
List[Finding] (redacted match, severity, compliance_refs, recommendation)
     |
     +-- SecretDeduplicator (cross-file correlation)
     +-- TerraformStateScanner (structural .tfstate walk)
     +-- Third-party scanner plugins
     |
     v
ScanStats (all findings, risk_score, trend_summary, ai_summary, container_info)
     |
     v
ReportGenerator (JSON / HTML / Markdown / SARIF / CSV / PDF)
     |
     v
HistoryStore (~/.cloudaudit/history.db)  +  optional webhook (generic or Slack Block Kit)
```

## Read-Only Enforcement

`HTTPClient` intentionally does not implement `put()`, `delete()`, or
`patch()`. The only exposed methods are:

- `get(url)` — download text content
- `head(url)` — retrieve headers only
- `options(url)` — retrieve allowed methods
- `download_bytes(url, max_size)` — binary download with a size cap

There is no code path anywhere in the codebase that performs a write
operation against a scanned remote target. The single intentional outbound
POST in the whole tool is the optional `--webhook-url` notification, which
only ever talks to the URL the user explicitly supplied — never to a
scanned target.

## Scanner Plugin Interface

Third-party packages can extend Phase 4 without touching this codebase, by
registering an entry point in the `cloudaudit.scanners` group:

```toml
# a plugin package's pyproject.toml
[project.entry-points."cloudaudit.scanners"]
my_plugin = "my_package.scanner:MySecretScanner"
```

```python
# my_package/scanner.py
class MySecretScanner:
    def scan(self, file_content: str, file_meta: dict) -> list[Finding]:
        ...  # return a list of cloudaudit.core.models.Finding
```

Plugin discovery and execution are wrapped so a broken or misbehaving plugin
can never abort a scan — see `scanners/plugin_loader.py`.
