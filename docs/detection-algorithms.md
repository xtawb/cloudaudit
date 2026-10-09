# Detection Algorithms

CloudAudit combines multiple complementary detection layers. Each finding is
clearly labelled with its detection method so analysts can apply appropriate
confidence levels.

## Detection Types

| Type Label | Description | Confidence Range |
|---|---|---|
| `DETERMINISTIC` | Regex pattern + entropy gate | 0.70 – 0.99 |
| `AI_HEURISTIC` | AI semantic analysis | 0.40 – 0.95 (penalised 10%) |
| `EntropyHunter` | High-entropy string detection | 0.55 |
| `SecretDeduplicator` | Cross-file duplicate/reuse | 0.85 – 0.99 |
| `MisconfigAnalyzer` | Metadata-level misconfigurations | 0.99 |
| `TerraformStateScanner` | Structured `.tfstate` attribute inspection | 0.90 |

## Layer 1: Deterministic Secret Scanning

Source: `scanners/secret_scanner.py`

Each pattern consists of:

- **Regex** — a compiled pattern matching the credential format
- **Entropy gate** — minimum Shannon entropy threshold (rejects low-entropy
  placeholders like `EXAMPLE_KEY`); PII patterns such as `EMAIL_ADDRESS` are
  exempt from the entropy gate since structured PII is naturally low-entropy
- **Validator** — optional function for provider-specific validation (e.g.
  AWS key prefix check `AKIA`/`ASIA`/`ABIA`)
- **Context requirement** — optional keywords that must appear near the match
- **Compliance refs** — applicable control framework references

### Complete Rule Set

| Rule | Severity | Entropy Min | Notes |
|---|---|---|---|
| `AWS_ACCESS_KEY` | Critical | 3.5 | Must start with AKIA/ASIA/ABIA. Validates 20-char format. |
| `AWS_SECRET_KEY` | Critical | 4.5 | 40-char base64. Requires `aws_secret` keyword context. |
| `AWS_SESSION_TOKEN` | High | 4.0 | Temporary STS tokens. High entropy, 100+ chars. |
| `GCP_API_KEY` | High | 3.5 | Starts with `AIza`. |
| `GCP_SERVICE_ACCOUNT_KEY` | Critical | 4.5 | JSON object with `private_key` field detected. |
| `GCP_OAUTH_TOKEN` | High | 4.0 | Starts with `ya29.`. |
| `AZURE_STORAGE_KEY` | Critical | 4.5 | Base64 storage account key, `AccountKey=` context. |
| `AZURE_SAS_TOKEN` | High | 3.5 | URL-encoded SAS token with `sig=` parameter. |
| `PRIVATE_KEY` | Critical | 5.0 | PEM header: `-----BEGIN * PRIVATE KEY-----` |
| `JWT_TOKEN` | Medium | 4.0 | Three base64url segments separated by dots. |
| `GITHUB_PAT` | Critical | 4.5 | Starts with `ghp_` or `github_pat_`. |
| `GITLAB_TOKEN` | Critical | 4.5 | Starts with `glpat-`. |
| `DATABASE_URL` | Critical | 3.0 | `postgresql://`, `mysql://`, `mongodb://` with embedded credentials. |
| `HARDCODED_PASSWORD` | High | 3.5 | `password=`, `passwd=`, `pwd=` with non-placeholder value. |
| `ENV_VARIABLE_SECRET` | High | 4.0 | `SECRET_KEY=`, `API_SECRET=` in `.env` syntax. |
| `GENERIC_API_KEY` | Medium | 4.5 | `api_key=`, `apikey=` with high-entropy value. |
| `INTERNAL_IP` | Low | N/A | RFC 1918 addresses (10.x, 172.16-31.x, 192.168.x). |
| `SSH_CONFIG` | Medium | N/A | `Host` / `IdentityFile` in SSH config format. |
| `EMAIL_ADDRESS` | Low | N/A (exempt from entropy gate) | RFC 5322 email pattern. |
| `CREDIT_CARD` | Critical | N/A | Luhn-validated 13-19 digit card numbers. |

You can extend this rule set without modifying source by supplying
`--custom-patterns patterns.yml` — see [Configuration](configuration.md).

### Entropy Escalation

Secrets whose matched value has Shannon entropy significantly above the
pattern minimum are automatically escalated. A `GENERIC_API_KEY` match at
entropy 5.8 is upgraded from Medium to High.

## Layer 2: High-Entropy String Detection

Source: `intelligence/advanced.py` — `EntropyHunter`

Detects secrets that do not match any known format by identifying
statistically anomalous string tokens.

Algorithm:

1. Tokenise each line on whitespace and delimiters (`=`, `:`, `"`, `'`, `,`, `;`)
2. Filter tokens shorter than 16 chars or longer than 512 chars
3. Apply a false-positive filter (reject MD5/SHA1/SHA256 hashes, UUIDs, pure
   numeric, dates, URLs)
4. Compute Shannon entropy: `H = -sum(p * log2(p) for each unique char)`
5. Accept tokens with `H >= threshold` (default 4.5, configurable with
   `--min-entropy`) **and** mixed character classes (at least 2 of: upper,
   lower, digit, special)

Results are created as `HIGH_ENTROPY_STRING` findings at Low severity with
confidence 0.55. They serve as a safety net for credential formats not yet in
the deterministic ruleset.

## Layer 3: AI Semantic Analysis

Source: `ai/analyzer.py` — `AIFileAnalyzer`

AI analysis is invoked selectively to control API cost and latency. A file is
analysed by AI only if it meets one or more conditions:

- File type is `ENVIRONMENT` or `CERTIFICATE`
- Filename matches high-value patterns: `.env`, `config.*`, `credentials*`,
  `secret*`, `docker*`, `kubernetes*`, `terraform*`, `.sql`, `settings.py`,
  `application.yml`, `.aws/`, `.ssh/`
- The deterministic scanner produced at least one finding in this file

### Content Sanitisation Before AI Transmission

```python
# Base64 strings >= 40 chars are redacted
sanitised = re.sub(r"\b([A-Za-z0-9+/]{40,}={0,2})\b",
                    lambda m: redact(m.group(1), keep_chars=8), content)

# PEM blocks are replaced entirely
sanitised = re.sub(r"(-----BEGIN[^-]+-----)[^-]+(-----END[^-]+-----)",
                    r"\1 [REDACTED] \2", sanitised, flags=re.DOTALL)
```

The AI receives at most 5,000 characters of sanitised content and is prompted
to return structured JSON findings. The prompt explicitly forbids
exploitation guidance.

### AI Finding Confidence Penalty

All AI findings receive a 10% confidence penalty versus deterministic
findings:

```python
confidence = min(ai_reported_confidence * 0.90, 0.95)
```

## Layer 4: Duplicate & Reuse Detection

Source: `intelligence/advanced.py` — `SecretDeduplicator`

After the main analysis phase, findings are correlated across files:

- **Duplicate detection** — the SHA-256 hash of each redacted match is
  computed and tracked. If the same hash appears in 2+ files, a
  `DUPLICATE_SECRET` Critical finding is generated. The raw value is never
  stored — only its hash.
- **Credential reuse** — if the same rule name (e.g. `AWS_ACCESS_KEY`)
  appears across 3 or more distinct files, a `CREDENTIAL_REUSE` High finding
  is generated, indicating insecure credential-sharing practices.

## Layer 5: Misconfiguration Analysis

Source: `intelligence/advanced.py` — `MisconfigAnalyzer`

Operates on container metadata and the file inventory (not file content):

- **Bucket-level** — detects public access configuration. A public bucket
  generates a `PUBLIC_BUCKET_ACCESS` Critical finding mapped to CIS 2.1,
  NIST SC-7, SOC2 CC6.1, PCI-DSS Req 1.3.
- **File inventory** — scans the complete list of filenames for
  known-sensitive patterns: `.env`, `id_rsa`, `.pem`, `.p12`, `credentials`,
  `.htpasswd`, `wp-config.php`, `database.yml`, `settings.py`, `.npmrc`,
  `.netrc`, `terraform.tfstate`. Each generates a `SENSITIVE_FILE_EXPOSED`
  finding.

## Layer 6: Structured Terraform State Scanning

Source: `intelligence/terraform_scanner.py`

Whenever a `terraform.tfstate` (or any `*.tfstate`) file is discovered, it is
parsed as structured JSON rather than only regex-scanned:

- Walks `resources[].instances[].attributes` for every resource in state
- Flags attribute names matching sensitive keywords (`password`, `secret`,
  `key`, `token`, `connection_string`, `private_key`, etc.)
- Each finding carries the Terraform resource address (e.g.
  `aws_db_instance.main`) as context, in addition to the file location

This catches secrets stored as structured Terraform output values that a
plain-text regex pass could miss or under-report.

## Extensibility: Scanner Plugins

Source: `scanners/plugin_loader.py`

Third-party scanners can be registered via a Python package entry point in
the `cloudaudit.scanners` group. Each plugin implements:

```python
def scan(file_content: bytes, file_meta: dict) -> list[Finding]:
    ...
```

Discovered plugins run alongside the built-in scanners during Phase 4
(Concurrent Content Analysis) and their findings flow through the same
`AdvancedIntelligence` aggregation, risk scoring, and reporting pipeline.

## v1.3.0 Detection Changes

### New credential formats

Slack tokens and webhooks, Discord webhooks, Stripe live keys, Twilio,
SendGrid, OpenAI, Anthropic, npm, PyPI, DigitalOcean, Hugging Face, Telegram
bot tokens, Shopify, Google OAuth client secrets, Microsoft Entra ID client
secrets, Databricks, HashiCorp Vault, Terraform Cloud, Docker Hub, Grafana,
New Relic, Mailgun, Square, Postman, Linear, `age` secret keys, GitLab
runner/deploy tokens, URLs with embedded credentials, ADO.NET-style connection
strings, and US Social Security numbers (context-gated). Fixed-format tokens
carry a fixed high confidence rather than an entropy estimate.

### Accuracy fixes

- **Placeholders are not secrets** — `changeme`, `your_api_key_here`,
  `${VAR}`, `<password>`, `xxxxxxxx`, AWS documentation keys
  (`AKIA…EXAMPLE`) and similar never produce a finding.
- **Structured rules fire again** — `INTERNAL_IP` and `SSH_CONFIG` were
  silently disabled by the entropy gate under the default threshold.
- **`SSH_CONFIG`** no longer matches the word "host" in prose.
- **`ENV_VARIABLE_SECRET`** now reports the *value* (it captured the variable
  name).
- **`CREDIT_CARD`** requires a valid Luhn checksum; **`JWT_TOKEN`** requires a
  decodable JOSE header; **`AZURE_SAS_TOKEN`** requires SAS fields nearby;
  **`EMAIL_ADDRESS`** ignores `image@2x.png` and example domains.
- **One finding per value per file** — repeats are counted
  (`occurrences`), and a generic rule yields when a specific rule already
  matched the same text.
- **Context snippets** redact token-shaped strings of 24+ characters (was
  40+), assignment values, and URL passwords.

### Duplicate / reuse detection

Duplicates are detected by a salted hash of the **raw** value held only in
memory. Previously the *redacted* match (first six characters) was hashed, so
any two secrets sharing a prefix — every JWT, every `AKIA…` key — were reported
as a CRITICAL duplicate. Emails, IP addresses and entropy hits no longer count
as "credentials" for duplicate or reuse findings, and a value repeated inside
a single file is not cross-file duplication.

### Entropy analysis

High-entropy candidates are passed through the local token classifier (see
[AI Engine](ai-engine.md#local-intelligence-engine-offline)) and are skipped
entirely in lockfiles, minified bundles, source maps and vendored trees.

