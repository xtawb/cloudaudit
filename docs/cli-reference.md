# CLI Reference

## Required Flags

| Flag | Description |
|---|---|
| `-u`, `--url URL` | Target cloud storage URL |
| `--confirm-ownership` | Declare authorisation to audit this resource |
| `--org-name ORG` | Organisation name for the report |

`-u`/`--confirm-ownership`/`--org-name` are not required when using
`--targets-file` (batch mode, one URL per line) or `--scan-docker-image`
(no target URL at all) — see below.

## Scan Control

| Flag | Default | Description |
|---|---|---|
| `--max-depth N` | 15 | Maximum recursive crawl depth |
| `--max-size BYTES` | 20971520 | Maximum per-file download size |
| `--extensions LIST` | (all text types) | Comma-separated extension allowlist |
| `--ignore-paths LIST` | | Path fragments to skip |
| `--min-severity` | `LOW` | Minimum finding severity to include in output |
| `--extract-archives` | off | Extract and scan archives (zip-slip and bomb protected) |
| `--deep-metadata` | off | Extract EXIF from images |
| `-t`, `--threads`, `--concurrency N` | 8 | Concurrent HTTP requests — bounds both the crawl and analysis phases |
| `--rate-limit SECONDS` | 0.15 | Delay per request per connection |
| `--dry-run` | off | Enumerate discovered files (size/type) without downloading or analysing content |
| `--interval SECONDS` | | Repeat the scan on a timer until interrupted (Ctrl+C) — drift detection |

## Data & Detection

| Flag | Description |
|---|---|
| `--baseline FILE` | JSON/YAML file of accepted-risk finding fingerprints to suppress |
| `--custom-patterns FILE` | YAML file of additional secret regex patterns to merge into the scanner |
| `--checkpoint FILE` | Periodically save crawl/analysis progress to this file |
| `--resume FILE` | Resume a previously interrupted scan from a `--checkpoint` file |
| `--aws-acl-check` | Enrich AWS S3 findings with real ACL/policy detail via `boto3` (optional) |

## Batch & Alternate Targets

| Flag | Default | Description |
|---|---|---|
| `--targets-file FILE` | | Batch-scan multiple targets, one URL per line |
| `--batch-concurrency N` | 1 | Targets scanned concurrently with `--targets-file` |
| `--scan-docker-image REF` | | Read-only scan of a container image's layers for secrets |

## AI Provider

| Flag | Default | Description |
|---|---|---|
| `--provider NAME` | | `gemini`, `openai`, `claude` (`anthropic`), `deepseek`, `ollama`, `custom`. Optional — the offline Local Intelligence Engine runs without it |
| `--api-key KEY` | | API key for the selected provider. If `--provider` is omitted, the provider is detected from the key's prefix |
| `--model NAME` | auto | Override automatic AI model selection |
| `--no-ai` | off | Never contact an AI provider — offline engine only |
| `--provider-url URL` | | Base URL for custom OpenAI-compatible endpoints |
| `--ollama-url URL` | `http://localhost:11434` | Ollama server |
| `--ollama-model MODEL` | `llama3` | Ollama model name |

## Notifications

| Flag | Default | Description |
|---|---|---|
| `--webhook-url URL` | | POST a redacted scan summary to a Slack/Discord-compatible webhook |
| `--webhook-format {auto,slack,generic}` | `auto` | Force the payload format (auto-detects `hooks.slack.com`) |
| `--slack-summary` | off | Post a richly formatted Slack Block Kit executive summary |

## CI/CD & Automation

| Flag | Description |
|---|---|
| `--fail-on-severity {low,medium,high,critical}` | Exit non-zero if any finding at/above this severity is present |
| `--no-history` | Don't record this scan in `~/.cloudaudit/history.db` |
| `--profile NAME` | Load a named config profile; explicit flags override it |
| `--tui` | Live `rich`-based terminal dashboard instead of phase-based output |

## Output

| Flag | Default | Description |
|---|---|---|
| `-o`, `--output BASE` | | Output base filename |
| `--format FORMAT` | `all` | `json` / `html` / `markdown` / `sarif` / `csv` / `pdf` / `all` (`pdf` requires `cloudaudit[pdf]`) |
| `-v`, `--verbose` | off | Verbose output including AI summary |
| `-d`, `--debug` | off | Full debug with stack traces |
| `--silent` | off | No terminal output (implies `-q`) |
| `-q`, `--quiet` | off | Suppress most terminal output |
| `--no-update` | off | Skip the GitHub release update check |

## Subcommands

| Subcommand | Description |
|---|---|
| `cloudaudit config --set-api / --list-providers / --remove-api PROVIDER` | Manage encrypted AI provider API keys |
| `cloudaudit config --test-api PROVIDER [--model NAME] [--provider-url URL]` | Test the key a scan would use and report *valid* / *no quota* / *rejected* / *could not verify* |
| `cloudaudit config --save-profile NAME` | Save the flags given on this command line as a named profile |
| `cloudaudit config --list-profiles` | List saved profile names |
| `cloudaudit diff <old_report.json> <new_report.json>` | Print new / resolved / unchanged findings between two JSON reports |
| `cloudaudit history [--limit N]` | List locally recorded past scans from `~/.cloudaudit/history.db` |
| `cloudaudit init-ci` | Write a GitHub Actions workflow that runs CloudAudit + uploads SARIF |
| `cloudaudit selftest` | Run detection/redaction self-checks against synthetic samples |

### `cloudaudit init-ci`

Scaffolds a ready-to-use GitHub Actions workflow in the current project
(not this repository) that runs CloudAudit with `--format sarif` and
uploads the results via `github/codeql-action/upload-sarif`.

| Flag | Default | Description |
|---|---|---|
| `--output PATH` | `.github/workflows/cloudaudit.yml` | Where to write the workflow file |
| `--schedule CRON` | `0 6 * * 1` | Cron schedule for the workflow trigger |
| `--force` | off | Overwrite the workflow file if it already exists |

See [Configuration](configuration.md) for the file formats used by
`--custom-patterns`, `--baseline`, and profiles, and
[Reporting](reporting.md) for details on each output format.

## Added in v1.4.0

### Scan flags

| Flag | Default | Description |
|------|---------|-------------|
| `--aws-inventory` | off | Owner mode for S3. Lists the bucket with **your** AWS credentials (boto3: `get_bucket_location`, `list_objects_v2` — read-only), probes each object with an unauthenticated `HEAD`, and analyses only the objects that are anonymously readable. Target: `-u s3://bucket[/prefix]` or the bucket URL. Requires `pip install cloudaudit[aws]` |
| `--aws-inventory-max N` | `5000` | Maximum objects listed per run |
| `--no-documents` | off | Do not download and analyse PDF / Office documents |

```bash
# Find publicly readable objects in a bucket whose listing is NOT public
AWS_PROFILE=audit cloudaudit -u s3://acme-assets --aws-inventory \
    --confirm-ownership --org-name "Acme" -o report
```

### `cloudaudit benchmark`

Scores the detection pipeline on the built-in labelled synthetic corpus,
offline, and prints precision / recall / F1 for the pattern rules alone and
for the full pipeline.

| Flag | Description |
|------|-------------|
| `--json` | Machine-readable output |
| `--min-precision X` | Exit `1` if full-pipeline precision is below `X` (0–1) |
| `--min-recall Y` | Exit `1` if full-pipeline recall is below `Y` (0–1) |
| `--seed N` | Regenerate the corpus values with a different seed |

```bash
cloudaudit benchmark --min-precision 0.97 --min-recall 0.95   # CI gate
```
