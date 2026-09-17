# AI Engine

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

Auth errors (HTTP 401, invalid key) are re-raised immediately rather than
falling back — they require user action and should not be silently
swallowed.

## Supported Providers

### Google Gemini

- **Dynamic model discovery** — calls `client.models.list()` to find
  compatible text models before generation, so there are no hardcoded model
  names and no 404s when Google renames or deprecates a model
- **Requirement** — `pip install cloudaudit[gemini]`

### OpenAI

- **Models** — `gpt-4o-mini`, `gpt-3.5-turbo` (automatic fallback)
- **Auth detection** — 401 responses raise `ProviderAuthError` immediately
  (no retry)
- **Requirement** — `pip install openai`

### DeepSeek

- Uses the OpenAI-compatible API endpoint at `https://api.deepseek.com/v1`
- Same `openai` Python package, different base URL
- **Models** — `deepseek-chat`, `deepseek-coder`

### Anthropic Claude

- **Models** — `claude-3-5-haiku-latest`, `claude-3-haiku-20240307`
- **Requirement** — `pip install anthropic`

### Ollama (Local)

- Calls `http://localhost:11434/api/generate` (configurable URL)
- No API key required
- `validate_key()` pings `/api/tags` to confirm the server is running
- Supports any locally installed model (`ollama pull llama3`)

### Custom OpenAI-Compatible

- Specify `--provider custom --provider-url https://your-endpoint/v1`
- Works with self-hosted vLLM, LM Studio, Jan, and any OpenAI-compatible API

### Heuristic (Built-in)

- No API required, zero latency, always available
- Generates structured summaries directly from finding data using
  deterministic logic — reads the actual scan statistics dict rather than an
  incorrect nested key, so it never falls back to showing "Unknown"
- Produces the same executive summary structure as AI providers, including
  the exposure trend delta, for a consistent report format regardless of
  which provider ran

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
