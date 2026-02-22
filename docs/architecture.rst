Architecture
============

CloudAudit is built around a modular, phase-based async architecture. Each phase is
independently testable and replaceable, enabling enterprise customisation.

Module Structure
----------------

.. code-block:: text

   cloudaudit/
   ├── cli/            User interface layer
   ├── core/           Config, models, engine, exceptions
   ├── ai/             AI provider abstraction + semantic analysis
   ├── config_mgr/     Key management and auto-update
   ├── intelligence/   Advanced detection algorithms
   ├── reports/        Multi-format output generation
   ├── scanners/       Cloud-specific crawlers + content scanners
   └── utils/          Shared utilities (HTTP, entropy, helpers)

The 11-Phase Engine
-------------------

The ``AuditEngine`` class in ``core/engine.py`` orchestrates 11 sequential phases via
Python's ``asyncio`` event loop. File analysis phases run concurrently, bounded by a
configurable semaphore.

**Phase 0 — Ownership Gate**

``AuditConfig.validate()`` is called before any network activity. It raises
``OwnershipError`` if ``ownership_confirmed`` is ``False`` or ``owner_org`` is empty.
This is enforced at the model level and cannot be bypassed via the public API.

**Phase 1 — Container Detection**

The ``ContainerDetector`` inspects HTTP response headers, XML namespace declarations,
hostname patterns, and body fingerprints to classify the container as one of:
``S3``, ``GCS``, ``AZURE_BLOB``, ``CLOUDFRONT``, or ``OPEN_DIRECTORY``.

**Phase 2 — Recursive File Crawl**

The ``FileCrawler`` paginates through the full file listing:

* **S3 / GCS**: Parses ``ListBucketResult`` XML, handles ``IsTruncated`` with ``ContinuationToken``
* **Azure Blob**: Parses ``EnumerationResults`` XML, handles ``NextMarker``
* **HTML**: Recursively follows ``<a href>`` links in directory listing pages

**Phase 3 — Misconfiguration Analysis**

The ``MisconfigAnalyzer`` inspects container-level metadata and the file inventory for:

* Public access configured on bucket/container
* Presence of known-sensitive filenames (``.env``, ``id_rsa``, ``.pem``, ``*.tfstate``, etc.)

Findings are emitted with full compliance references before any file content is downloaded.

**Phase 4 — Concurrent Content Analysis**

Launched as a bounded pool of ``asyncio`` tasks (default: 8 concurrent):

* Deterministic secret scanning (``SecretScanner``) — 20+ regex patterns with entropy gates
* High-entropy string detection (``EntropyHunter``) — entropy-based token analysis
* AI semantic analysis (``AIFileAnalyzer``) — invoked selectively for high-value files
* EXIF metadata extraction (``ImageMetaAnalyser``) — for image files when ``--deep-metadata``

**Phase 5 — Archive Extraction**

When ``--extract-archives`` is set, the ``ArchiveExtractor`` downloads archives and
extracts members. Protections:

* Zip-slip: ``_sanitise_path()`` rejects absolute paths and ``..`` components
* Decompression bomb: 500 MB total extraction limit, 50 MB per-member limit
* File count: maximum 10,000 members per archive

**Phase 6 — Image EXIF Analysis** (integrated into Phase 4)

**Phase 7 — Duplicate & Reuse Detection**

The ``SecretDeduplicator`` performs post-analysis correlation:

* **Exact duplicates**: SHA-256 hashes of redacted match values detect identical secrets across files
* **Credential reuse**: Identifies credential types appearing across 3+ files

**Phase 8 — Misconfiguration Aggregation**

**Phase 9 — Risk Scoring v2**

See :doc:`risk-engine` for full scoring formula.

**Phase 10 — AI Executive Summary**

The ``ProviderChain`` calls the configured AI provider with a JSON summary of findings
(all secrets already redacted). Falls back automatically to ``HeuristicProvider`` on
any failure.

**Phase 11 — Report Output**

``ReportGenerator`` produces JSON, HTML, and/or Markdown from ``ScanStats``.

Data Flow
---------

.. code-block:: text

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
        |
        v
   ScanStats (all findings, risk_score, ai_summary, container_info)
        |
        v
   ReportGenerator (JSON / HTML / Markdown)

Read-Only Enforcement
---------------------

The ``HTTPClient`` class intentionally does not implement ``put()``, ``delete()``, or
``patch()`` methods. The only exposed methods are:

* ``get(url)`` — Download text content
* ``head(url)`` — Retrieve headers only
* ``options(url)`` — Retrieve allowed methods
* ``download_bytes(url, max_size)`` — Binary download with size cap

There is no code path in the entire codebase that performs write operations against
remote storage.
