Detection Algorithms
====================

CloudAudit combines three complementary detection layers. Each finding is clearly
labelled with its detection method so analysts can apply appropriate confidence levels.

Detection Types
---------------

.. list-table::
   :header-rows: 1
   :widths: 25 40 35

   * - Type Label
     - Description
     - Confidence Range
   * - ``DETERMINISTIC``
     - Regex pattern + entropy gate
     - 0.70 – 0.99
   * - ``AI_HEURISTIC``
     - AI semantic analysis
     - 0.40 – 0.95 (penalised 10%)
   * - ``EntropyHunter``
     - High-entropy string detection
     - 0.55
   * - ``SecretDeduplicator``
     - Cross-file duplicate/reuse
     - 0.85 – 0.99
   * - ``MisconfigAnalyzer``
     - Metadata-level misconfigurations
     - 0.99

Layer 1: Deterministic Secret Scanning
---------------------------------------

Source: ``scanners/secret_scanner.py``

Each pattern consists of:

* **Regex**: A compiled pattern matching the credential format
* **Entropy gate**: Minimum Shannon entropy threshold (rejects low-entropy placeholders like ``EXAMPLE_KEY``)
* **Validator**: Optional function for provider-specific validation (e.g. AWS key prefix check ``AKIA/ASIA/ABIA``)
* **Context requirement**: Optional keywords that must appear near the match
* **Compliance refs**: Applicable control framework references

Complete Rule Set
~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 15 15 40

   * - Rule
     - Severity
     - Entropy Min
     - Notes
   * - ``AWS_ACCESS_KEY``
     - Critical
     - 3.5
     - Must start with AKIA/ASIA/ABIA. Validates 20-char format.
   * - ``AWS_SECRET_KEY``
     - Critical
     - 4.5
     - 40-char base64. Requires ``aws_secret`` keyword context.
   * - ``AWS_SESSION_TOKEN``
     - High
     - 4.0
     - Temporary STS tokens. High entropy, 100+ chars.
   * - ``GCP_API_KEY``
     - High
     - 3.5
     - Starts with ``AIza``.
   * - ``GCP_SERVICE_ACCOUNT_KEY``
     - Critical
     - 4.5
     - JSON object with ``private_key`` field detected.
   * - ``GCP_OAUTH_TOKEN``
     - High
     - 4.0
     - Starts with ``ya29.``.
   * - ``AZURE_STORAGE_KEY``
     - Critical
     - 4.5
     - Base64 storage account key, ``AccountKey=`` context.
   * - ``AZURE_SAS_TOKEN``
     - High
     - 3.5
     - URL-encoded SAS token with ``sig=`` parameter.
   * - ``PRIVATE_KEY``
     - Critical
     - 5.0
     - PEM header: ``-----BEGIN * PRIVATE KEY-----``
   * - ``JWT_TOKEN``
     - Medium
     - 4.0
     - Three base64url segments separated by dots.
   * - ``GITHUB_PAT``
     - Critical
     - 4.5
     - Starts with ``ghp_`` or ``github_pat_``.
   * - ``GITLAB_TOKEN``
     - Critical
     - 4.5
     - Starts with ``glpat-``.
   * - ``DATABASE_URL``
     - Critical
     - 3.0
     - ``postgresql://``, ``mysql://``, ``mongodb://`` with embedded credentials.
   * - ``HARDCODED_PASSWORD``
     - High
     - 3.5
     - ``password=``, ``passwd=``, ``pwd=`` with non-placeholder value.
   * - ``ENV_VARIABLE_SECRET``
     - High
     - 4.0
     - ``SECRET_KEY=``, ``API_SECRET=`` in .env syntax.
   * - ``GENERIC_API_KEY``
     - Medium
     - 4.5
     - ``api_key=``, ``apikey=`` with high-entropy value.
   * - ``INTERNAL_IP``
     - Low
     - N/A
     - RFC 1918 addresses (10.x, 172.16-31.x, 192.168.x).
   * - ``SSH_CONFIG``
     - Medium
     - N/A
     - ``Host`` / ``IdentityFile`` in SSH config format.
   * - ``EMAIL_ADDRESS``
     - Low
     - N/A
     - RFC 5322 email pattern.
   * - ``CREDIT_CARD``
     - Critical
     - N/A
     - Luhn-validated 13-19 digit card numbers.

Entropy Escalation
~~~~~~~~~~~~~~~~~~

Secrets whose matched value has Shannon entropy significantly above the pattern minimum
are automatically escalated. A ``GENERIC_API_KEY`` match at entropy 5.8 is upgraded
from Medium to High.

Layer 2: High-Entropy String Detection
---------------------------------------

Source: ``intelligence/advanced.py`` — ``EntropyHunter``

Detects secrets that do not match any known format by identifying statistically anomalous
string tokens.

Algorithm:

1. Tokenise each line on whitespace and delimiters (``=``, ``:``, ``"``, ``'``, ``,``, ``;``)
2. Filter tokens shorter than 16 chars or longer than 512 chars
3. Apply false-positive filter (reject MD5/SHA1/SHA256 hashes, UUIDs, pure numeric, dates, URLs)
4. Compute Shannon entropy: ``H = -sum(p * log2(p) for each unique char)``
5. Accept tokens with H >= threshold (default 4.5) AND mixed character classes (>= 2 of: upper, lower, digit, special)

Results are created as ``HIGH_ENTROPY_STRING`` findings at Low severity with confidence 0.55.
They serve as a safety net for credential formats not yet in the deterministic ruleset.

Layer 3: AI Semantic Analysis
------------------------------

Source: ``ai/analyzer.py`` — ``AIFileAnalyzer``

AI analysis is invoked selectively to control API cost and latency. A file is analysed by
AI only if it meets one or more conditions:

* File type is ``ENVIRONMENT`` or ``CERTIFICATE``
* Filename matches high-value patterns: ``.env``, ``config.*``, ``credentials*``, ``secret*``,
  ``docker*``, ``kubernetes*``, ``terraform*``, ``.sql``, ``settings.py``, ``application.yml``,
  ``.aws/``, ``.ssh/``
* Deterministic scanner produced at least one finding in this file

Content Sanitisation Before AI Transmission
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Base64 strings >= 40 chars are redacted
   sanitised = re.sub(r"\b([A-Za-z0-9+/]{40,}={0,2})\b",
                      lambda m: redact(m.group(1), keep_chars=8), content)

   # PEM blocks are replaced entirely
   sanitised = re.sub(r"(-----BEGIN[^-]+-----)[^-]+(-----END[^-]+-----)",
                      r"\1 [REDACTED] \2", sanitised, flags=re.DOTALL)

The AI receives at most 5,000 characters of sanitised content and is prompted to return
structured JSON findings. The prompt explicitly forbids exploitation guidance.

AI Finding Confidence Penalty
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All AI findings receive a 10% confidence penalty versus deterministic findings:

.. code-block:: python

   confidence = min(ai_reported_confidence * 0.90, 0.95)

Layer 4: Duplicate & Reuse Detection
--------------------------------------

Source: ``intelligence/advanced.py`` — ``SecretDeduplicator``

After the main analysis phase, findings are correlated across files:

**Duplicate Detection**: The SHA-256 hash of each redacted match is computed and tracked.
If the same hash appears in 2+ files, a ``DUPLICATE_SECRET`` Critical finding is generated.
The raw value is never stored — only its hash.

**Credential Reuse**: If the same rule name (e.g. ``AWS_ACCESS_KEY``) appears across 3 or more
distinct files, a ``CREDENTIAL_REUSE`` High finding is generated, indicating insecure
credential sharing practices.

Layer 5: Misconfiguration Analysis
------------------------------------

Source: ``intelligence/advanced.py`` — ``MisconfigAnalyzer``

Operates on container metadata and the file inventory (not file content):

**Bucket-level**: Detects public access configuration. A public bucket generates a
``PUBLIC_BUCKET_ACCESS`` Critical finding mapped to CIS 2.1, NIST SC-7, SOC2 CC6.1, PCI-DSS Req 1.3.

**File inventory**: Scans the complete list of filenames for known-sensitive patterns:
``.env``, ``id_rsa``, ``.pem``, ``.p12``, ``credentials``, ``.htpasswd``, ``wp-config.php``,
``database.yml``, ``settings.py``, ``.npmrc``, ``.netrc``, ``terraform.tfstate``.
Each generates a ``SENSITIVE_FILE_EXPOSED`` finding.
