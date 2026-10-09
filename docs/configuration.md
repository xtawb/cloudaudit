# Configuration

## API Key Management

CloudAudit provides a dedicated `config` subcommand for managing AI provider
API keys securely.

Store a key (interactive, validates before saving):

```bash
cloudaudit config --set-api gemini
cloudaudit config --set-api openai
cloudaudit config --set-api claude
cloudaudit config --set-api deepseek
```

List all configured providers:

```bash
cloudaudit config --list-providers
```

Remove a stored key:

```bash
cloudaudit config --remove-api openai
```

### Storage Security

Keys are stored at `~/.cloudaudit/config.enc` using Fernet symmetric encryption:

- **Algorithm:** AES-128-CBC + HMAC-SHA256 (Fernet)
- **Key derivation:** PBKDF2-SHA256 (100,000 iterations, random 32-byte salt)
- **Salt location:** `~/.cloudaudit/.salt` (mode 600)
- **Config location:** `~/.cloudaudit/config.enc` (mode 600)
- Keys are **never logged** to any output stream.

### Live Validation

When a key is entered via `config --set-api`, CloudAudit validates it with a
minimal live API call (e.g. listing available models) before saving. If
validation fails, provider-specific troubleshooting steps are displayed.

## Environment Variables

Instead of the key manager, you can set environment variables:

| Provider | Variable |
|---|---|
| Google Gemini | `GEMINI_API_KEY` |
| OpenAI | `OPENAI_API_KEY` |
| Anthropic Claude | `ANTHROPIC_API_KEY` |
| DeepSeek | `DEEPSEEK_API_KEY` |

Or create a `.cloudaudit.env` file in your working directory:

```bash
GEMINI_API_KEY=AIzaSy...
OPENAI_API_KEY=sk-...
```

### Key Resolution Order

`AuditConfig.resolve_api_key()` (backed by
`config_mgr.key_manager.resolve_api_key`) resolves the API key in this order:

1. `--api-key` CLI flag
2. The provider-specific environment variable (e.g. `GEMINI_API_KEY`), then
   known alternates (`GOOGLE_API_KEY` for Gemini, `CLAUDE_API_KEY` for Claude)
3. A `.cloudaudit.env` file in the working directory
4. The encrypted key store (`cloudaudit config --set-api`)

Whatever the source, the value is **normalised** before use: surrounding
whitespace and quotes, zero-width characters, a leading `Bearer `, and a
pasted `NAME=value` / `export NAME=value` wrapper are removed. The CLI prints
which source the key came from (never the key itself).

If no key is found for the selected provider, the scan does **not** fail: it
continues with the offline Local Intelligence Engine and says so.

### Testing a key

```bash
cloudaudit config --test-api gemini
```

reports one of four outcomes, which need different actions:

| Outcome | Meaning | Action |
|---------|---------|--------|
| **valid** | The provider accepted the key | none |
| **no quota** | The key is genuine, the account has no credit / quota | add billing or wait; scans use the offline engine meanwhile |
| **rejected** | The provider refused the key | re-create the key; check it belongs to the provider you selected |
| **could not verify** | The check could not run (offline, rate limited, SDK missing) | not evidence of a bad key — retry later |

### Provider / key mix-ups

The provider is inferred from the key prefix when `--provider` is omitted
(`AIza…`/`AQ.…` → Gemini, `sk-ant-…` → Claude, `sk-proj-…` → OpenAI), and a
key that clearly belongs to a different provider than the one selected is
flagged before any request is made.

## Named Profiles (`--profile`)

Repeated scans of the same environment often use the same flags — profiles
let you save them once and reuse them by name.

Save the flags given on a command line as a profile (any top-level scan flag
placed before the `config` subcommand token is merged into the same profile):

```bash
cloudaudit --extract-archives --threads 20 --format sarif \
           config --save-profile ci
```

List saved profiles:

```bash
cloudaudit config --list-profiles
```

Load a profile on a future scan — explicit flags on that invocation always
override the profile's stored value:

```bash
cloudaudit -u https://mybucket.s3.amazonaws.com/ \
           --confirm-ownership --org-name "Acme Corp" \
           --profile ci
```

Profiles are stored as plain YAML at `~/.cloudaudit/profiles/<name>.yml` and
are safe to inspect or edit by hand. **API keys, the target URL, output path,
and ownership flags are never written to a profile** — these are always
supplied per-invocation for safety and clarity.

## Custom Secret Patterns

`--custom-patterns FILE` merges additional regex rules into the secret
scanner without touching source code. Format (YAML):

```yaml
patterns:
  - name: INTERNAL_SERVICE_TOKEN
    regex: "internal_tok_[a-zA-Z0-9]{32}"
    severity: high                # critical|high|medium|low|informational
    description: "Internal service-to-service auth token"
    compliance_refs: ["SOC2 CC6.7"]
```

Invalid entries (missing `name`/`regex`, or an unparseable regex) are
skipped individually with a warning rather than aborting the whole load.

```bash
cloudaudit -u https://mybucket.s3.amazonaws.com/ \
           --confirm-ownership --org-name "Acme Corp" \
           --custom-patterns patterns.yml
```

## Baseline / Allowlist Suppression

`--baseline FILE` suppresses findings that have already been triaged and
accepted as risk, so recurring audits only surface *new* issues. Findings
are matched by a fingerprint (`sha256(rule_name + file_url + file_name)`,
truncated) — never by raw content, so nothing sensitive needs to be stored
in the baseline file itself.

```json
{"suppressed": ["a1b2c3d4e5f6a7b8"]}
```

or as YAML:

```yaml
suppressed:
  - a1b2c3d4e5f6a7b8   # AWS_ACCESS_KEY on s3://bucket/legacy/config.env
```

Suppressed findings are excluded from the report body but still counted in
`ScanStats.suppressed_count`, so nothing silently disappears from the audit
trail.

## Checkpoint & Resume

`--checkpoint FILE` periodically persists crawl/analysis progress to disk.
If a scan is interrupted (Ctrl+C, network blip, process kill), continue it
with `--resume FILE` instead of restarting the crawl from scratch:

```bash
cloudaudit -u https://mybucket.s3.amazonaws.com/ \
           --confirm-ownership --org-name "Acme Corp" \
           --checkpoint audit.checkpoint.json
# ... interrupted ...
cloudaudit -u https://mybucket.s3.amazonaws.com/ \
           --confirm-ownership --org-name "Acme Corp" \
           --resume audit.checkpoint.json
```

## Webhook Notifications

`--webhook-url URL` posts an already-redacted JSON summary (target, risk
score, severity counts, and the top few findings by severity — never raw
secret values) to a webhook at the end of a scan. This is the one place in
CloudAudit that makes an outbound POST; it only ever talks to the URL you
explicitly provide, never to the audit target.

The payload includes both a Slack-style `text` field and a Discord-style
`content` field, so a plain webhook works against either platform without
extra configuration. For a richer, Slack Block Kit–formatted summary
instead of the plain payload, add `--slack-summary` (or
`--webhook-format slack`) — this is auto-detected whenever the URL contains
`hooks.slack.com`:

```bash
cloudaudit -u https://mybucket.s3.amazonaws.com/ \
           --confirm-ownership --org-name "Acme Corp" \
           --webhook-url https://hooks.slack.com/services/... \
           --slack-summary
```

## AWS ACL/Policy Enrichment

`--aws-acl-check` (requires `pip install cloudaudit[aws]`) enriches AWS S3
findings with real bucket ACL and policy detail using read-only `boto3`
calls (`get_bucket_acl`, `get_bucket_policy`, `get_bucket_policy_status`),
using whatever AWS credentials are already present in your environment
(e.g. `~/.aws/credentials`, environment variables, or an instance role). If
`boto3` isn't installed or no credentials are available, this enrichment is
skipped gracefully and the scan continues with pattern-based findings only.

## Docker Image Layer Scanning

`--scan-docker-image <registry>/<image>:<tag>` performs a read-only pull of
an image's manifest and layers from a container registry's v2 HTTP API and
runs the same secret scanner over the extracted layer contents — no `-u`
target URL is required for this mode:

```bash
cloudaudit --scan-docker-image registry.example.com/team/app:1.2.3 \
           --confirm-ownership --org-name "Acme Corp" \
           -o reports/image_audit
```

## Performance Tuning

| Flag | Default | Description |
|---|---|---|
| `-t`, `--threads`, `--concurrency` | 8 | Concurrent HTTP request workers (bounds both crawl and analysis phases) |
| `--timeout` | 30.0 | Per-request timeout in seconds |
| `--rate-limit` | 0.15 | Delay in seconds per request per connection |
| `--max-size` | 20971520 | Maximum per-file download size in bytes (20 MB) |
| `--max-depth` | 15 | Maximum recursive crawl depth |
| `--batch-concurrency` | 1 | Targets scanned concurrently with `--targets-file` |

## Scan Scope Control

```bash
# Only scan specific file extensions
cloudaudit -u https://... --confirm-ownership --org-name "Acme Corp" \
           --extensions env,json,yml,py,sql,tfstate

# Skip certain path prefixes
cloudaudit -u https://... --confirm-ownership --org-name "Acme Corp" \
           --ignore-paths logs,tmp,cache

# Only report findings at HIGH severity and above
cloudaudit -u https://... --confirm-ownership --org-name "Acme Corp" \
           --min-severity HIGH
```

See the [CLI Reference](cli-reference.md) for the complete, categorised flag
table.
