# AI Engine

!!! note "No API key required"
    Since v1.3.0 every function on this page has an **offline implementation**
    — the [Local Intelligence Engine](#local-intelligence-engine-offline) —
    that runs on every scan. An external AI provider is an optional second
    opinion, never a dependency.

CloudAudit integrates AI across three distinct functions:

1. **Semantic file analysis** — understanding file intent, not just pattern
   matching
2. **Anomaly scoring** — entropy and pattern correlation to rate file risk
3. **Executive summary** — a human-readable, CISO-level summary of the full
   audit, including exposure trend versus the previous scan

## AI Safety Principles

All AI integration in CloudAudit is governed by strict safety rules:

- **No raw secrets transmitted** — content is sanitised before sending
  (base64 truncation, PEM replacement)
- **No exploitation guidance** — all AI prompts explicitly forbid attack
  path generation or weaponisation advice
- **Defensive framing only** — prompts are written from the perspective of
  a defensive security auditor
- **Heuristic fallback** — the `HeuristicProvider` always runs if no AI
  provider is configured, and as the final link in the provider chain if a
  configured provider fails — no API required, and it never crashes

## Provider Abstraction Layer

Source: `ai/providers.py`

All providers implement the `AIProvider` abstract base class with four
methods:

```python
class AIProvider(ABC):
    def complete(self, prompt: str, max_tokens: int) -> AIResponse: ...
    def generate_executive_summary(self, audit_json: str) -> AIResponse: ...
    def analyse_file_content(self, filename, filetype, content) -> AIResponse: ...
    def score_anomaly(self, filename, entropy_strings, patterns) -> AIResponse: ...
```

All responses are normalised to
`AIResponse(text, provider, model, latency_ms, tokens_used)`.

## Provider Chain

The `ProviderChain` class wraps one primary provider and always appends
`HeuristicProvider` as the final fallback:

```text
[Configured Provider]  →  fails?  →  [HeuristicProvider]  →  always succeeds
```

### Error handling

Every provider error is classified by `classify_error()` from its HTTP status
and message, and handled according to its kind:

| Kind | Examples | Handling |
|------|----------|----------|
| `auth` / `permission` | 401, "API key not valid", API not enabled, unsupported region | provider disabled for the run, one clear warning, local engine continues |
| `quota` | 402, `insufficient_quota`, "credit balance is too low" | provider disabled for the run (the key is valid — the account is empty) |
| `rate_limit` | 429, `RESOURCE_EXHAUSTED` | retry with back-off (honours `Retry-After`), then try the next model |
| `model` | 404, model not found / retired | try the next candidate model; the first model that works is remembered |
| `param` | `max_tokens` vs `max_completion_tokens` | request shape is adapted and retried |
| `context` | prompt too long | prompt is shortened and retried |
| `transient` | 5xx, timeouts | retry with back-off |
| `unreachable` | DNS / connection refused | provider disabled for the run |

A **circuit breaker** disables the remote provider after an unrecoverable
error, or after three consecutive failed requests, so a bad key costs one
request rather than one per scanned file. Nothing in the chain raises: the
worst case is always a locally generated result, and the reason is recorded
in the report (`scan.ai_status`) and shown in the audit summary.

Provider error text is scrubbed of anything key-shaped (`?key=…` query
parameters, bearer tokens, `AIza…` / `sk-…` values) before it is logged or
displayed.

## Supported Providers

### Google Gemini

- **Dynamic model discovery** — calls `client.models.list()`, ranks the
  results (stable before preview, newer generation first, `flash` before
  `pro` because free-tier keys commonly have zero `pro` quota) and tries them
  in order; non-text models (TTS, image, embedding, live audio) are excluded
- **Thinking-model aware** — an empty reply that hit the output-token limit
  is retried once with a larger budget
- **Requirement** — `pip install cloudaudit[gemini]`

### OpenAI

- **Models** — tried in order: `gpt-4.1-mini`, `gpt-4o-mini`, `gpt-5-mini`,
  `gpt-4o` (override with `--model`)
- **Dialect adaptation** — switches between `max_completion_tokens` and
  `max_tokens` automatically when the endpoint rejects one of them
- **Requirement** — `pip install openai`

### DeepSeek

- Uses the OpenAI-compatible API endpoint at `https://api.deepseek.com`
- Same `openai` Python package, different base URL
- **Models** — `deepseek-chat`, `deepseek-reasoner`

### Anthropic Claude

- **Models** — tried in order: `claude-haiku-5-5`, `claude-sonnet-5-5`, `claude-haiku-4-5`,
  `claude-sonnet-4-5` (override with `--model`)
- **Requirement** — `pip install anthropic`

### Ollama (Local)

- Calls `http://localhost:11434/api/generate` (configurable URL)
- No API key required
- Reads `/api/tags` to confirm the server is running and to see which models
  are installed; if the requested model is missing, an installed one is used
  (with a warning) instead of failing
- Supports any locally installed model (`ollama pull llama3`)

### Custom OpenAI-Compatible

- Specify `--provider custom --provider-url https://your-endpoint/v1`
- Works with self-hosted vLLM, LM Studio, Jan, and any OpenAI-compatible API
- The model is taken from `--model`, or discovered from the endpoint's
  `/models` listing when omitted

### Local Intelligence Engine (Built-in)

- No API required, no network, always available — see the next section
- Reported as `heuristic/local-intelligence-v2` in `scan.ai_engine`

## Local Intelligence Engine (offline)

Source: `intelligence/local_ai.py`

Runs on **every** scan, with or without an AI provider.

| Stage | What it does |
|-------|--------------|
| **Token classifier** | Scores any opaque string 0–1 for "is this a real secret": charset-normalised entropy, an English-bigram language model (identifiers vs. random text), character-class transition rate, and known benign shapes (UUIDs, digests, paths, versions, SRI hashes, dotted names). Used to filter entropy hits and to score assignments |
| **Semantic assignments** | Extracts `key = value` pairs from env / YAML / JSON / INI / XML / code and reasons about the **key name** (`dbPassword`, `client-secret` are secret-bearing; `token_url`, `password_min_length`, `public_key`, `secret_name` are not) and the **value** (placeholders, `${VAR}` references and prose are ignored). Finds secrets no regex rule knows about |
| **Config auditor** | 27 misconfiguration rules for Terraform/CloudFormation, Kubernetes/Docker, web servers, databases and app config: open ingress, wildcard IAM, public ACLs, disabled TLS verification / encryption / auth / MFA / logging, privileged containers, weak crypto, exposed password hashes, default credentials, database dumps |
| **JWT inspection** | Decodes the header and claims (the token is never verified or used) to mark tokens as expired, still valid, non-expiring, or unsigned |
| **Calibration** | Lowers confidence and severity for generic findings in test / example / documentation paths |
| **Aggregation** | Collapses bulk values (hundreds of emails or internal IPs in one file) into one finding, and escalates bulk personal data |
| **Correlation** | Emits compound-exposure findings — a complete AWS key pair in one file, a private key with host details, data-store credentials with internal addressing, a multi-credential secrets file, systemic secret sprawl, personal data alongside working credentials |
| **Executive summary** | Risk posture, key risk drivers, exposure breakdown, highest-risk files, a phased remediation plan built only from the finding types actually present, and compliance impact by framework |

What is sent to a remote provider is a compact, always-valid JSON digest
(`build_ai_digest`) — counts, highest-risk files and the top findings by
severity — with no `match` or `context` values.

## Semantic File Analysis

Source: `ai/analyzer.py` — `AIFileAnalyzer`

The AI receives a structured prompt for file analysis:

```text
You are a cloud security analyst reviewing a file found in a publicly exposed
cloud storage container.

File: {filename}
File Type: {filetype}
Content (truncated, secrets partially redacted):
{content}

Identify any of the following:
1. Credentials, API keys, tokens, or secrets
2. Internal infrastructure details
3. PII or sensitive personal data patterns
4. Security misconfigurations
5. Hardcoded environment-specific values
6. Compliance violations

For each finding, output JSON:
{"findings": [{"type": "...", "description": "...", "severity": "critical|high|medium|low",
               "line_hint": "...", "confidence": 0.0-1.0, "recommendation": "..."}]}

Output ONLY valid JSON. No markdown fences.
```

The response is parsed and each item becomes an `AIFinding` (labelled `[AI]`
in reports).

## Anomaly Scoring

Source: `ai/analyzer.py` — `AnomalyScorer`

For files where the heuristic anomaly score exceeds 3.0, the AI is asked to
score the anomaly and provide a 2-sentence explanation:

```text
{"score": 0-10, "explanation": "..."}
```

The final score blends heuristic (60%) and AI (40%) contributions.

The heuristic anomaly score is computed from:

- High-entropy string density ratio (lines with entropy ≥ threshold / total
  lines)
- Existing finding severity amplification (Critical: +1.5 per finding,
  High: +0.8)
- Sensitive keyword density (`password`, `secret`, `token`, `key`, etc.)
- File size relative to extension (small `.env` files score higher)

## Executive Summary

The AI is asked to produce a 4-6 paragraph executive summary:

1. Overall risk posture and exposure severity
2. Most critical finding categories and their business impact
3. Top 3 remediation priorities with estimated effort
4. Compliance framework gaps
5. Strategic recommendations
6. Exposure trend versus the previous scan of the same target, when
   [local history](update-system.md#local-scan-history) has one

The prompt explicitly states: *"Do NOT suggest exploitation steps or attack
paths."*

The summary is included in all report formats and printed to the terminal
with `-v`/`--verbose`. Pass `--slack-summary` (or a `--webhook-url` pointing
at `hooks.slack.com`) to also post a Slack Block Kit–formatted version of
this summary — see [Configuration](configuration.md#webhook-notifications).
