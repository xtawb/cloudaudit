"""
cloudaudit.ai.providers — Unified AI Abstraction Layer

Supports:
  - Google Gemini (dynamic model discovery, ranked, with per-model fallback)
  - OpenAI
  - Anthropic Claude
  - DeepSeek AI (OpenAI-compatible endpoint)
  - Any OpenAI-compatible endpoint (--provider custom --provider-url ...)
  - Ollama (local, no key required)
  - Built-in Local Intelligence Engine (always available, no external calls)

Design principles:
  - All providers normalise responses to AIResponse
  - Every provider error is *classified* (auth / quota / rate limit / model /
    parameter / context length / transient / unreachable) and handled
    accordingly: retry with back-off, switch model, adapt the request, or stop
  - A circuit breaker disables a failing remote provider for the rest of the
    run, so a bad key costs one failed request — not one per scanned file
  - The local engine is always the final link: an audit never loses its
    analysis or its executive summary because of an AI provider problem
  - API keys are never logged, and are scrubbed from provider error text
  - AI receives only redacted finding summaries
  - AI does NOT generate exploitation guidance
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from cloudaudit.core.exceptions import ProviderAuthError, ProviderError, ProviderQuotaError
from cloudaudit.core.constants import PROVIDER_MODEL_FALLBACKS, __version__

logger = logging.getLogger("cloudaudit.ai")

REQUEST_TIMEOUT_S   = 60.0
MAX_RETRIES         = 2          # per model, for rate-limit / transient errors
MAX_MODEL_ATTEMPTS  = 4          # distinct models tried per request
MAX_BACKOFF_S       = 20.0
MAX_OUTPUT_TOKENS   = 8192


# ── Normalised response type ───────────────────────────────────────────────────

@dataclass
class AIResponse:
    text:     str
    provider: str
    model:    str
    latency_ms: int = 0
    tokens_used: int = 0
    truncated: bool = False      # stopped because the output-token budget ran out

    @property
    def ok(self) -> bool:
        return bool(self.text and self.text.strip())


# ── Error classification ───────────────────────────────────────────────────────

AUTH, PERMISSION, QUOTA, RATE_LIMIT, MODEL, PARAM, CONTEXT, TRANSIENT, UNREACHABLE, UNKNOWN = (
    "auth", "permission", "quota", "rate_limit", "model", "param", "context",
    "transient", "unreachable", "unknown",
)

_SECRET_SCRUB_RES = (
    re.compile(r"(?i)([?&](?:key|api_key|apikey|access_token|token)=)[^&\s'\"]+"),
    re.compile(r"(?i)((?:bearer|x-api-key|api-key|authorization)[\"']?\s*[:=]\s*[\"']?(?:bearer\s+)?)[A-Za-z0-9._\-]{8,}"),
    re.compile(r"\b(AIza)[0-9A-Za-z_\-]{10,}"),
    re.compile(r"\b(AQ\.)[0-9A-Za-z_\-]{10,}"),
    re.compile(r"(?<![A-Za-z0-9])(sk-(?:ant-|proj-|svcacct-|admin-)?)[A-Za-z0-9_\-]{8,}"),
)


def scrub_secrets(text: str) -> str:
    """Remove anything key-shaped from provider error text before it is logged or shown."""
    out = str(text)
    for rx in _SECRET_SCRUB_RES:
        out = rx.sub(lambda m: m.group(1) + "***", out)
    return out


@dataclass
class ErrorInfo:
    kind:        str
    status:      Optional[int]
    message:     str                 # full (scrubbed) text — used for classification / debug logs
    retry_after: Optional[float] = None
    summary:     str = ""            # short human-readable form — used in anything shown to the user

    def __post_init__(self) -> None:
        if not self.summary:
            self.summary = self.message[:200]


def _http_status(exc: BaseException) -> Optional[int]:
    for attr in ("status_code", "code", "http_status", "status"):
        val = getattr(exc, attr, None)
        if isinstance(val, int) and not isinstance(val, bool) and 100 <= val <= 599:
            return val
    resp = getattr(exc, "response", None)
    val = getattr(resp, "status_code", None)
    return val if isinstance(val, int) and 100 <= val <= 599 else None


def _retry_after(exc: BaseException, text: str) -> Optional[float]:
    headers = getattr(getattr(exc, "response", None), "headers", None) or getattr(exc, "headers", None)
    try:
        if headers is not None:
            val = headers.get("retry-after") or headers.get("Retry-After")
            if val:
                return float(val)
    except Exception:
        pass
    m = re.search(r"retry(?:\s+in|Delay['\"]?\s*[:=]\s*['\"]?)\s*([\d.]+)\s*s", text, re.IGNORECASE)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def classify_error(exc: BaseException) -> ErrorInfo:
    """
    Map any SDK / HTTP exception onto one actionable category.

    Works from the HTTP status when the exception carries one and from the
    message otherwise, so it behaves the same for the google-genai, openai and
    anthropic SDKs, raw urllib errors, and OpenAI-compatible gateways.
    """
    status = _http_status(exc)
    raw = f"{type(exc).__name__}: {exc}"
    extra = getattr(exc, "status", None)
    if isinstance(extra, str):
        raw += f" [{extra}]"
    msg = scrub_secrets(raw)
    low = msg.lower()
    retry = _retry_after(exc, low)

    def has(*needles: str) -> bool:
        return any(n in low for n in needles)

    if has("insufficient_quota", "credit balance is too low", "insufficient balance", "billing_not_active",
           "billing hard limit", "payment required", "exceeded your monthly", "out of credits") or status == 402:
        kind = QUOTA
    elif status == 401 or has("api key not valid", "api_key_invalid", "invalid api key", "invalid_api_key",
                              "incorrect api key", "invalid x-api-key", "authentication_error",
                              "unauthenticated", "invalid authentication", "api key expired",
                              "key has been revoked", "no api key", "missing api key", "authenticationerror",
                              "invalid bearer", "api key was reported as leaked"):
        kind = AUTH
    elif status == 429 or has("rate limit", "rate_limit", "resource_exhausted", "too many requests",
                              "exceeded your current quota", "quota exceeded", "overloaded_error"):
        kind = RATE_LIMIT
    elif has("context length", "context_length", "maximum context", "too many tokens", "prompt is too long",
             "request too large", "string too long", "exceeds the maximum", "input token") or status == 413:
        kind = CONTEXT
    elif status == 404 or has("model_not_found", "model not found", "does not exist", "is not found for api version",
                              "not supported for generatecontent", "unknown model", "decommissioned",
                              "no such model", "is not a valid model", "pull the model", "invalid model"):
        kind = MODEL
    elif status == 403 or has("permission_denied", "permission denied", "forbidden", "not allowed",
                              "has not been used in project", "is disabled", "location is not supported",
                              "country, region, or territory not supported"):
        kind = PERMISSION
    elif status in (400, 422) and has("max_tokens", "max_completion_tokens", "temperature", "unsupported parameter",
                                      "unsupported value", "unrecognized request argument", "unknown parameter",
                                      "extra inputs are not permitted", "system"):
        kind = PARAM
    elif has("connection refused", "connecterror", "name or service not known", "getaddrinfo",
             "nodename nor servname", "name resolution", "no route to host", "network is unreachable",
             "winerror 10061", "winerror 11001", "failed to establish", "apiconnectionerror", "urlopen error"):
        kind = UNREACHABLE
    elif (status is not None and (status >= 500 or status in (408, 409, 425))) or has(
            "timeout", "timed out", "temporarily", "overloaded", "unavailable", "reset by peer",
            "connection aborted", "remote end closed", "internal server error", "bad gateway", "deadline"):
        kind = TRANSIENT
    else:
        kind = UNKNOWN
    # Providers wrap the useful sentence in a JSON/dict dump — pull it out.
    inner = re.search(r"""['"]message['"]\s*:\s*(['"])(.{5,240}?)\1\s*[,}]""", msg)
    text = inner.group(2) if inner else re.sub(r"^\w+(?:\.\w+)*:\s*", "", msg)[:200]
    summary = (f"HTTP {status} — " if status else "") + text.strip()
    return ErrorInfo(kind, status, msg[:400], retry, summary)


# ── JSON extraction ────────────────────────────────────────────────────────────

def extract_json(text: str) -> Optional[Any]:
    """
    Pull the first JSON object out of a model reply.

    Models routinely wrap JSON in markdown fences or add a sentence before or
    after it; a bare ``json.loads`` then throws away an otherwise valid answer.
    """
    if not text:
        return None
    t = text.strip()
    try:
        return json.loads(t)
    except Exception:
        pass
    fenced = re.search(r"```(?:json|JSON)?\s*(.*?)```", t, re.DOTALL)
    if fenced:
        try:
            return json.loads(fenced.group(1).strip())
        except Exception:
            t = fenced.group(1)
    start = t.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(t)):
            c = t[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(t[start:i + 1])
                    except Exception:
                        break
        start = t.find("{", start + 1)
    return None


# ── AI task prompts ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are an enterprise cloud security auditor. You write only defensive analysis and "
    "remediation guidance. You never provide exploitation steps or attack paths."
)

PROMPT_EXECUTIVE_SUMMARY = """You are a cloud security auditor writing an executive summary for an internal security report.

Audit digest (JSON, findings are redacted — no raw credentials included). "top_findings" is sorted by
severity; "findings_omitted" counts findings left out of this digest for brevity — the *_counts fields
cover every finding:
{audit_json}

Write a professional executive summary (4-6 paragraphs) covering:
1. Overall risk posture and exposure severity
2. Most critical finding categories and their business impact
3. Top 3 remediation priorities with estimated effort
4. Compliance framework gaps identified (CIS/NIST/SOC2/ISO27001/PCI-DSS)
5. Strategic recommendations for security posture improvement
6. If a "trend_summary" field is present in the audit data, briefly note the
   exposure trend versus the previous scan of this target (new vs. resolved findings)

Rules:
- Do NOT suggest exploitation steps or attack paths
- Focus entirely on defensive remediation
- Be precise and actionable; use only facts present in the digest
- Write for a CISO/CTO audience
"""

PROMPT_FILE_ANALYSIS = """You are a cloud security analyst reviewing a file found in a publicly exposed cloud storage container.

File: {filename}
File Type: {filetype}
Already detected by deterministic scanners (do NOT repeat these): {known}
Content (truncated, secrets partially redacted):
{content}

Identify any of the following that the scanners missed:
1. Credentials, API keys, tokens, or secrets (even partially visible)
2. Internal infrastructure details (IPs, hostnames, service names)
3. PII or sensitive personal data patterns
4. Security misconfigurations
5. Hardcoded environment-specific values
6. Compliance violations

For each finding, output JSON:
{{"findings": [{{"type": "...", "description": "...", "severity": "critical|high|medium|low", "line_hint": "...", "confidence": 0.0-1.0, "recommendation": "..."}}]}}

If nothing new is found output {{"findings": []}}.
Output ONLY valid JSON. No markdown fences.
"""

PROMPT_ANOMALY_SCORE = """You are analyzing a file for anomalous security patterns.

Filename: {filename}
High-entropy strings found: {entropy_strings}
Pattern matches: {patterns}

Rate the anomaly risk on a scale of 0-10 and explain in 2 sentences.
Output JSON: {{"score": 0-10, "explanation": "..."}}
Output ONLY valid JSON.
"""


# ── Abstract base ──────────────────────────────────────────────────────────────

class AIProvider(ABC):
    """
    Base class. Subclasses implement ``_call`` (one request to one model) and
    ``_candidate_models``; retry, back-off, model fallback and error mapping
    live here so every provider behaves the same way.
    """

    is_local: bool = False

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    # ── To be provided by subclasses ───────────────────────────────────────────

    def _call(self, model: str, prompt: str, max_tokens: int) -> AIResponse:  # pragma: no cover - abstract-ish
        raise NotImplementedError

    def _candidate_models(self) -> List[str]:  # pragma: no cover - abstract-ish
        return []

    def _adapt_to_param_error(self, info: ErrorInfo) -> bool:
        """Change request shape after a 400 about a parameter. True if a retry is worthwhile."""
        return False

    def _auth_help(self) -> str:
        return "Check the key or run: cloudaudit config --set-api " + self.name

    # ── Shared machinery ───────────────────────────────────────────────────────

    _good_model: Optional[str] = None
    _sleep = staticmethod(time.sleep)

    def _model_order(self) -> List[str]:
        models = list(dict.fromkeys(m for m in self._candidate_models() if m))
        if self._good_model and self._good_model in models:
            models.remove(self._good_model)
            models.insert(0, self._good_model)
        return models

    def complete(self, prompt: str, max_tokens: int = 1500) -> AIResponse:
        """Send prompt, return normalised AIResponse. Raises ProviderError on failure."""
        models = self._model_order()
        if not models:
            raise ProviderError(f"{self.name}: no usable model found. Pass one explicitly with --model.")

        last: Optional[ErrorInfo] = None
        for model in models[:MAX_MODEL_ATTEMPTS]:
            tokens = max_tokens
            adapted = shrunk = False
            attempt = 0
            while attempt <= MAX_RETRIES:
                try:
                    resp = self._call(model, prompt, tokens)
                except Exception as exc:
                    info = classify_error(exc)
                    last = info
                    logger.debug("%s model=%s attempt=%d failed [%s]: %s",
                                 self.name, model, attempt, info.kind, info.message)
                    if info.kind == AUTH:
                        raise ProviderAuthError(
                            f"{self.name} rejected the API key ({info.summary}). {self._auth_help()}"
                        ) from None
                    if info.kind == PERMISSION:
                        raise ProviderAuthError(
                            f"{self.name} refused the request — the key lacks permission, the API is not enabled, "
                            f"or the region is unsupported ({info.summary})."
                        ) from None
                    if info.kind == QUOTA:
                        raise ProviderQuotaError(
                            f"{self.name} account has no remaining quota / credit ({info.summary})."
                        ) from None
                    if info.kind == UNREACHABLE:
                        raise ProviderError(f"{self.name} is unreachable ({info.summary}).") from None
                    if info.kind == PARAM and not adapted and self._adapt_to_param_error(info):
                        adapted = True
                        continue
                    if info.kind == CONTEXT and not shrunk:
                        shrunk = True
                        prompt = prompt[: max(2000, len(prompt) // 2)]
                        continue
                    if info.kind in (RATE_LIMIT, TRANSIENT) and attempt < MAX_RETRIES:
                        delay = info.retry_after if info.retry_after is not None else 1.5 * (2 ** attempt)
                        self._sleep(min(max(delay, 0.5), MAX_BACKOFF_S))
                        attempt += 1
                        continue
                    break  # model-specific or exhausted → next model
                else:
                    if resp.ok and not (resp.truncated and len(resp.text) < 40):
                        self._good_model = model
                        return resp
                    # Empty / cut-off answer: "thinking" models spend the output
                    # budget on reasoning tokens. Retry once with more room.
                    if resp.truncated and tokens < MAX_OUTPUT_TOKENS and attempt < MAX_RETRIES:
                        tokens = min(tokens * 4, MAX_OUTPUT_TOKENS)
                        attempt += 1
                        continue
                    last = ErrorInfo("empty", None, f"model {model} returned an empty response")
                    break

        detail = f"[{last.kind}] {last.summary}" if last else "no response"
        raise ProviderError(f"All {self.name} models failed. Last: {detail}")

    def check_key(self) -> Dict[str, Any]:
        """
        Cheap credential check. Returns
        ``{"status": "valid"|"invalid"|"quota"|"unverified", "model": str|None, "error": str}``.
        ``unverified`` means the check itself could not run (network, rate limit) —
        it says nothing about the key.
        """
        try:
            self._probe()
            return {"status": "valid", "model": self._good_model or (self._model_order() or [None])[0], "error": ""}
        except Exception as exc:
            info = classify_error(exc)
            # Our own ProviderErrors already carry a readable sentence; raw SDK
            # errors are reduced to their one useful line.
            error = scrub_secrets(str(exc))[:300] if isinstance(exc, ProviderError) else info.summary
            if isinstance(exc, ProviderAuthError) or info.kind in (AUTH, PERMISSION):
                return {"status": "invalid", "model": None, "error": error}
            if isinstance(exc, ProviderQuotaError) or info.kind == QUOTA:
                return {"status": "quota", "model": None, "error": error}
            return {"status": "unverified", "model": None, "error": error, "kind": info.kind}

    def _probe(self) -> None:
        """Default probe: the cheapest possible real request."""
        self.complete("Reply with the single word: ok", max_tokens=16)

    # ── Tasks ─────────────────────────────────────────────────────────────────

    def generate_executive_summary(self, audit_json: str) -> AIResponse:
        prompt = PROMPT_EXECUTIVE_SUMMARY.format(audit_json=compact_audit_json(audit_json))
        return self.complete(prompt, max_tokens=2000)

    def analyse_file_content(self, filename: str, filetype: str, content: str, known: str = "") -> AIResponse:
        prompt = PROMPT_FILE_ANALYSIS.format(
            filename=filename,
            filetype=filetype,
            known=known or "none",
            content=content[:4000],
        )
        return self.complete(prompt, max_tokens=1200)

    def score_anomaly(self, filename: str, entropy_strings: list, patterns: list) -> AIResponse:
        prompt = PROMPT_ANOMALY_SCORE.format(
            filename=filename,
            entropy_strings=str(entropy_strings[:10]),
            patterns=str(patterns[:20]),
        )
        return self.complete(prompt, max_tokens=400)


def compact_audit_json(audit_json: str, max_chars: int = 9000) -> str:
    """Always-valid, size-bounded digest of the audit for a remote model."""
    try:
        data = json.loads(audit_json)
        if not isinstance(data, dict):
            raise ValueError("not an object")
    except Exception:
        return audit_json[:max_chars]
    from cloudaudit.intelligence.local_ai import build_ai_digest
    return build_ai_digest(data, max_chars=max_chars)


# ── Gemini ─────────────────────────────────────────────────────────────────────

# Model families that list ``generateContent`` but are not general text models.
_GEMINI_SKIP = (
    "embedding", "aqa", "vision", "tts", "audio", "image", "imagen", "veo", "live", "learnlm",
    "gemma", "robotics", "computer-use", "native", "dialog", "nano", "banana", "lyria", "search",
    "legacy", "deprecated",
)


def rank_gemini_models(names: Sequence[str]) -> List[str]:
    """
    Order Gemini model names best-first for this workload.

    Stable releases beat previews; newer generations beat older ones; within
    a generation ``flash`` is preferred over ``pro`` (fast, inexpensive and —
    crucially — available on free-tier keys, where ``pro`` models commonly
    have a zero request quota) and ``flash-lite`` is the last resort.
    """
    ranked = []
    for raw in names:
        name = (raw or "").removeprefix("models/")
        low = name.lower()
        if not low.startswith("gemini") or any(s in low for s in _GEMINI_SKIP):
            continue
        m = re.search(r"gemini-(\d+(?:\.\d+)?)", low)
        version = float(m.group(1)) if m else (50.0 if low.endswith("-latest") else 0.0)
        tier = 1 if "lite" in low else 3 if "flash" in low else 2 if "pro" in low else 0
        stable = 0 if any(t in low for t in ("exp", "preview")) else 1
        pinned = 0 if re.search(r"-\d{3,}$|-\d{2}-\d{2}$", low) else 1     # prefer the rolling alias
        ranked.append(((stable, version, tier, pinned), name))
    ranked.sort(key=lambda x: x[0], reverse=True)
    return list(dict.fromkeys(n for _, n in ranked))


class GeminiProvider(AIProvider):
    """
    Google Gemini provider using the modern ``google.genai`` SDK
    (never the deprecated ``google.generativeai`` package).

    Models are discovered with ``client.models.list()``, ranked with
    :func:`rank_gemini_models`, and tried in order — so a renamed, retired or
    zero-quota model costs one failed request instead of the whole AI phase.
    If discovery itself fails for a non-credential reason, a static fallback
    list is used.
    """

    name = "gemini"

    def __init__(self, api_key: str, model: Optional[str] = None) -> None:
        try:
            from google import genai  # type: ignore[import]
        except ImportError as exc:
            raise ProviderError(
                "google-genai package is not installed. Run: pip install google-genai"
            ) from exc
        self._client = genai.Client(api_key=api_key)
        self._override = model
        self._models: Optional[List[str]] = None

    def _auth_help(self) -> str:
        return ("Create or check the key at https://aistudio.google.com/app/apikey "
                "or run: cloudaudit config --set-api gemini")

    def _discover(self) -> List[str]:
        """List + rank models. Raises the SDK error unchanged so callers can classify it."""
        usable: List[str] = []
        for model in self._client.models.list():
            raw_name: str = getattr(model, "name", "") or ""
            methods = getattr(model, "supported_actions", None) \
                or getattr(model, "supported_generation_methods", None) or []
            if methods and "generateContent" not in methods:
                continue
            usable.append(raw_name)
        ranked = rank_gemini_models(usable)
        logger.debug("Gemini candidate models (ranked): %s", ranked[:8])
        return ranked

    def _candidate_models(self) -> List[str]:
        if self._override:
            return [self._override]
        if self._models is None:
            try:
                self._models = self._discover()
            except Exception as exc:
                info = classify_error(exc)
                if info.kind in (AUTH, PERMISSION):
                    raise ProviderAuthError(
                        f"Gemini rejected the API key ({info.summary}). {self._auth_help()}"
                    ) from None
                logger.debug("Gemini model discovery failed (%s) — using static fallback list", info.message)
                self._models = []
            if not self._models:
                self._models = list(PROVIDER_MODEL_FALLBACKS["gemini"])
            else:
                logger.info("Gemini model selected: %s (from %d candidates)", self._models[0], len(self._models))
        return self._models

    def _probe(self) -> None:
        # models.list() authenticates the key without spending any quota.
        models = self._discover()
        if models:
            self._models = models

    def _call(self, model: str, prompt: str, max_tokens: int) -> AIResponse:
        from google.genai import types as genai_types  # type: ignore[import]

        config = genai_types.GenerateContentConfig(
            max_output_tokens=max_tokens,
            temperature=0.2,
            system_instruction=SYSTEM_PROMPT,
        )
        t0 = time.monotonic()
        response = self._client.models.generate_content(model=model, contents=prompt, config=config)
        latency = int((time.monotonic() - t0) * 1000)

        # ``response.text`` raises when the candidate has no text part
        # (safety block, MAX_TOKENS during thinking) — never let that escape.
        text = ""
        try:
            text = response.text or ""
        except Exception:
            text = ""
        finish = ""
        for candidate in getattr(response, "candidates", None) or []:
            finish = finish or str(getattr(candidate, "finish_reason", "") or "")
            if not text:
                content = getattr(candidate, "content", None)
                for part in getattr(content, "parts", None) or []:
                    if not getattr(part, "thought", False):
                        text += getattr(part, "text", "") or ""
        usage = getattr(response, "usage_metadata", None)
        tokens = int(getattr(usage, "total_token_count", 0) or 0)
        logger.info("Gemini response: model=%s latency=%dms chars=%d", model, latency, len(text))
        return AIResponse(text=text, provider="gemini", model=model, latency_ms=latency,
                          tokens_used=tokens, truncated="MAX_TOKENS" in finish.upper())

    # Backwards-compatible structured validator (pre-1.3 callers).
    def validate_key(self) -> dict:
        res = self.check_key()
        return {
            "valid": res["status"] in ("valid", "quota"),
            "model": res["model"],
            "error": res["error"] or None,
        }


# ── OpenAI (also used for DeepSeek and custom endpoints) ──────────────────────

class OpenAICompatibleProvider(AIProvider):
    """
    Handles OpenAI, DeepSeek, and any OpenAI-compatible endpoint.

    Adapts automatically to the two incompatible request dialects in the wild:
    newer OpenAI models require ``max_completion_tokens`` and reject
    ``max_tokens``; most compatible gateways only know ``max_tokens``.
    """

    _BASE_URLS = {"deepseek": "https://api.deepseek.com"}

    def __init__(
        self,
        api_key: str,
        provider_name: str = "openai",
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        try:
            from openai import OpenAI
        except ImportError:
            raise ProviderError("openai package not installed. Run: pip install openai")
        url = base_url or self._BASE_URLS.get(provider_name)
        kwargs: dict = {"api_key": api_key, "timeout": REQUEST_TIMEOUT_S, "max_retries": 0}
        if url:
            kwargs["base_url"] = url
        self._client        = OpenAI(**kwargs)
        self._provider_name = provider_name
        self._override      = model
        self._discovered: Optional[List[str]] = None
        self._token_param   = "max_completion_tokens" if provider_name == "openai" else "max_tokens"
        self._use_system    = True

    @property
    def name(self) -> str:
        return self._provider_name

    def _auth_help(self) -> str:
        return f"Check the key or run: cloudaudit config --set-api {self._provider_name}"

    def _candidate_models(self) -> List[str]:
        if self._override:
            return [self._override]
        static = PROVIDER_MODEL_FALLBACKS.get(self._provider_name)
        if static:
            return list(static)
        # Custom endpoint with no --model: ask the endpoint what it serves.
        if self._discovered is None:
            try:
                ids = [getattr(m, "id", "") for m in self._client.models.list()]
            except Exception as exc:
                info = classify_error(exc)
                if info.kind in (AUTH, PERMISSION):
                    raise ProviderAuthError(
                        f"{self.name} rejected the API key ({info.summary}). {self._auth_help()}"
                    ) from None
                logger.debug("Model discovery failed for %s: %s", self.name, info.message)
                ids = []
            skip = ("embed", "whisper", "tts", "dall", "image", "moderation", "rerank", "audio", "realtime")
            self._discovered = [i for i in ids if i and not any(s in i.lower() for s in skip)]
        return self._discovered

    def _adapt_to_param_error(self, info: ErrorInfo) -> bool:
        low = info.message.lower()
        if "max_completion_tokens" in low or "max_tokens" in low:
            self._token_param = "max_tokens" if self._token_param == "max_completion_tokens" else "max_completion_tokens"
            return True
        if "system" in low and self._use_system:
            self._use_system = False
            return True
        return False

    def _probe(self) -> None:
        # Listing models authenticates without spending tokens. Some gateways
        # do not implement it — fall back to a one-token completion.
        try:
            next(iter(self._client.models.list()), None)
        except Exception as exc:
            info = classify_error(exc)
            if info.kind in (AUTH, PERMISSION, QUOTA, UNREACHABLE):
                raise
            super()._probe()

    def _call(self, model: str, prompt: str, max_tokens: int) -> AIResponse:
        if self._use_system:
            messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]
        else:
            messages = [{"role": "user", "content": SYSTEM_PROMPT + "\n\n" + prompt}]
        t0 = time.monotonic()
        resp = self._client.chat.completions.create(
            model=model, messages=messages, **{self._token_param: max_tokens},
        )
        latency = int((time.monotonic() - t0) * 1000)
        choice = resp.choices[0] if getattr(resp, "choices", None) else None
        text = (getattr(getattr(choice, "message", None), "content", None) or "") if choice else ""
        finish = str(getattr(choice, "finish_reason", "") or "") if choice else ""
        tokens = int(getattr(getattr(resp, "usage", None), "total_tokens", 0) or 0)
        logger.info("%s response: model=%s latency=%dms tokens=%d", self._provider_name, model, latency, tokens)
        return AIResponse(text=text, provider=self._provider_name, model=model, latency_ms=latency,
                          tokens_used=tokens, truncated=finish == "length")

    def validate_key(self) -> bool:
        return self.check_key()["status"] in ("valid", "quota")


# ── Claude ─────────────────────────────────────────────────────────────────────

class ClaudeProvider(AIProvider):

    name = "claude"

    def __init__(self, api_key: str, model: Optional[str] = None) -> None:
        try:
            import anthropic
        except ImportError:
            raise ProviderError("anthropic package not installed. Run: pip install anthropic")
        self._client   = anthropic.Anthropic(api_key=api_key, timeout=REQUEST_TIMEOUT_S, max_retries=0)
        self._override = model

    def _auth_help(self) -> str:
        return ("Check the key at https://console.anthropic.com/settings/keys "
                "or run: cloudaudit config --set-api claude")

    def _candidate_models(self) -> List[str]:
        return [self._override] if self._override else list(PROVIDER_MODEL_FALLBACKS["claude"])

    def _probe(self) -> None:
        try:
            next(iter(self._client.models.list(limit=1)), None)
        except TypeError:
            next(iter(self._client.models.list()), None)

    def _call(self, model: str, prompt: str, max_tokens: int) -> AIResponse:
        t0 = time.monotonic()
        msg = self._client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        latency = int((time.monotonic() - t0) * 1000)
        # The first block is not guaranteed to be text (thinking / tool blocks).
        text = "".join(
            getattr(b, "text", "") or "" for b in (msg.content or []) if getattr(b, "type", "text") == "text"
        )
        usage = getattr(msg, "usage", None)
        tokens = int(getattr(usage, "input_tokens", 0) or 0) + int(getattr(usage, "output_tokens", 0) or 0)
        return AIResponse(text=text, provider="claude", model=model, latency_ms=latency,
                          tokens_used=tokens, truncated=getattr(msg, "stop_reason", "") == "max_tokens")

    def validate_key(self) -> bool:
        return self.check_key()["status"] in ("valid", "quota")


# ── Ollama ─────────────────────────────────────────────────────────────────────

class OllamaProvider(AIProvider):

    name = "ollama"

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3") -> None:
        self._base_url = (base_url or "http://localhost:11434").rstrip("/")
        self._model    = model
        self._installed: Optional[List[str]] = None

    def _auth_help(self) -> str:
        return "Ollama needs no key — check that `ollama serve` is running."

    def _installed_models(self) -> List[str]:
        import urllib.request
        with urllib.request.urlopen(f"{self._base_url}/api/tags", timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return [m.get("name", "") for m in data.get("models", []) if m.get("name")]

    def _candidate_models(self) -> List[str]:
        if self._installed is None:
            self._installed = self._installed_models()      # raises → classified as unreachable
        if not self._installed:
            raise ProviderError(
                f"Ollama at {self._base_url} has no models installed. Run: ollama pull {self._model}"
            )
        wanted = self._model
        exact = [m for m in self._installed if m == wanted or m == f"{wanted}:latest" or m.split(":")[0] == wanted]
        if exact:
            return exact + [m for m in self._installed if m not in exact]
        logger.warning("Ollama model %r is not installed — using %r instead (ollama pull %s to install it)",
                       wanted, self._installed[0], wanted)
        return list(self._installed)

    def complete(self, prompt: str, max_tokens: int = 1500) -> AIResponse:
        try:
            return super().complete(prompt, max_tokens)
        except ProviderError:
            raise
        except Exception as exc:
            info = classify_error(exc)
            kind = "is unreachable" if info.kind == UNREACHABLE else "error"
            raise ProviderError(f"Ollama {kind} ({self._base_url}): {info.summary}") from None

    def _probe(self) -> None:
        self._installed = self._installed_models()

    def _call(self, model: str, prompt: str, max_tokens: int) -> AIResponse:
        import urllib.request
        payload = json.dumps({
            "model":   model,
            "system":  SYSTEM_PROMPT,
            "prompt":  prompt,
            "stream":  False,
            "options": {"num_predict": max_tokens, "temperature": 0.2},
        }).encode("utf-8")
        t0 = time.monotonic()
        req = urllib.request.Request(
            f"{self._base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=180) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        latency = int((time.monotonic() - t0) * 1000)
        return AIResponse(
            text=result.get("response", "") or "",
            provider="ollama",
            model=model,
            latency_ms=latency,
            tokens_used=int(result.get("eval_count", 0) or 0) + int(result.get("prompt_eval_count", 0) or 0),
            truncated=result.get("done_reason") == "length",
        )

    def validate_key(self) -> bool:
        return self.check_key()["status"] == "valid"


# ── Local Intelligence Engine (no external calls) ──────────────────────────────

class HeuristicProvider(AIProvider):
    """
    The built-in offline engine. Always available, no API key, no network.

    Since v1.3.0 this is a real analysis engine (see
    ``cloudaudit.intelligence.local_ai``) rather than a fixed template: it
    produces a data-driven executive summary, semantic file findings and an
    anomaly score. Used when no AI provider is configured, and as the
    guaranteed final link whenever a configured provider fails.
    """

    name = "heuristic"
    is_local = True
    MODEL = "local-intelligence-v2"

    def complete(self, prompt: str, max_tokens: int = 1500) -> AIResponse:
        # Free-form prompts cannot be answered offline; the task methods below can.
        return AIResponse(text="", provider="heuristic", model=self.MODEL)

    def check_key(self) -> Dict[str, Any]:
        return {"status": "valid", "model": self.MODEL, "error": ""}

    def generate_executive_summary(self, audit_json: str) -> AIResponse:
        from cloudaudit.intelligence.local_ai import generate_summary
        try:
            data = json.loads(audit_json)
            if not isinstance(data, dict):
                data = {}
        except Exception:
            data = {}
        return AIResponse(text=generate_summary(data, version=__version__), provider="heuristic", model=self.MODEL)

    def analyse_file_content(self, filename: str, filetype: str, content: str, known: str = "") -> AIResponse:
        from cloudaudit.intelligence.local_ai import analyse_content_as_json
        return AIResponse(text=analyse_content_as_json(filename, filetype, content),
                          provider="heuristic", model=self.MODEL)

    def score_anomaly(self, filename: str, entropy_strings: list, patterns: list) -> AIResponse:
        score = min(10.0, 1.2 * len(entropy_strings) + 0.9 * len(patterns))
        return AIResponse(
            text=json.dumps({"score": round(score, 1),
                             "explanation": f"{len(entropy_strings)} high-entropy strings and "
                                            f"{len(patterns)} rule matches."}),
            provider="heuristic", model=self.MODEL,
        )


LocalIntelligenceProvider = HeuristicProvider


# ── Provider chain (automatic fallback + circuit breaker) ─────────────────────

class ProviderChain:
    """
    ``[configured provider] → [local intelligence engine]``.

    The remote provider is skipped for the rest of the run as soon as it is
    known to be unusable (rejected key, exhausted quota, unreachable) or after
    ``FAILURE_THRESHOLD`` consecutive failures. No method on this class raises:
    the worst case is always a locally generated answer.
    """

    FAILURE_THRESHOLD = 3

    def __init__(self, primary: Optional[AIProvider] = None) -> None:
        self._remote: Optional[AIProvider] = primary if (primary and not primary.is_local) else None
        self._local = HeuristicProvider()
        self._lock = threading.Lock()
        self._failures = 0
        self._disabled_reason = ""
        self._hard_disabled = False       # rejected key / no quota / unreachable: retrying is pointless
        self._calls = 0
        self._last_model = ""

    # ── State ─────────────────────────────────────────────────────────────────

    @property
    def remote_name(self) -> str:
        return self._remote.name if self._remote else ""

    @property
    def has_remote(self) -> bool:
        """True while a remote provider is configured and has not been disabled."""
        return self._remote is not None and not self._disabled_reason

    @property
    def status(self) -> str:
        """One-line, human-readable description of what the AI layer did."""
        if self._remote is None:
            return "Local intelligence engine (no AI provider configured)"
        if self._disabled_reason:
            return f"{self._remote.name} disabled — {self._disabled_reason}. Local intelligence engine used instead"
        model = f"/{self._last_model}" if self._last_model else ""
        return f"{self._remote.name}{model} active ({self._calls} request(s))"

    def _disable(self, reason: str, hard: bool = True) -> None:
        with self._lock:
            if self._disabled_reason:
                return
            self._disabled_reason = scrub_secrets(reason)[:300]
            self._hard_disabled = hard
        logger.warning("AI provider %s disabled for this run: %s — continuing with the local intelligence engine.",
                       self.remote_name, self._disabled_reason)

    def preflight(self) -> Dict[str, Any]:
        """Verify the remote provider once, before any file is analysed."""
        if self._remote is None:
            return {"status": "valid", "model": HeuristicProvider.MODEL, "error": ""}
        try:
            res = self._remote.check_key()
        except Exception as exc:  # check_key should not raise; belt and braces
            res = {"status": "unverified", "model": None, "error": scrub_secrets(str(exc))[:300]}
        if res["status"] == "invalid":
            self._disable(f"API key rejected: {res['error']}")
        elif res["status"] == "quota":
            self._disable(f"no remaining quota: {res['error']}")
        elif res["status"] == "unverified" and (
                res.get("kind") == UNREACHABLE or classify_error(Exception(res["error"])).kind == UNREACHABLE):
            self._disable(f"provider unreachable: {res['error']}")
        elif res.get("model"):
            self._last_model = res["model"]
        return res

    # ── Tasks ─────────────────────────────────────────────────────────────────

    def generate_executive_summary(self, audit_json: str) -> AIResponse:
        # The summary is the single most valuable request of a run, and it comes
        # last. If the breaker tripped on transient failures (rate limiting
        # during per-file analysis), it still gets one attempt.
        resp = self._try_remote("generate_executive_summary", audit_json, force=not self._hard_disabled)
        # A two-line reply is not an executive summary — prefer the local one.
        if resp is not None and len(resp.text.strip()) >= 200:
            return resp
        return self._local.generate_executive_summary(audit_json)

    def analyse_file_content(self, filename: str, filetype: str, content: str, known: str = "") -> AIResponse:
        resp = self._try_remote("analyse_file_content", filename, filetype, content, known)
        if resp is not None:
            return resp
        return AIResponse(text="", provider="heuristic", model=HeuristicProvider.MODEL)

    def score_anomaly(self, filename: str, entropy_strings: list, patterns: list) -> AIResponse:
        resp = self._try_remote("score_anomaly", filename, entropy_strings, patterns)
        return resp if resp is not None else self._local.score_anomaly(filename, entropy_strings, patterns)

    def _try_remote(self, method: str, *args, force: bool = False) -> Optional[AIResponse]:
        if self._remote is None or (self._disabled_reason and not force):
            return None
        assert self._remote is not None
        try:
            result: AIResponse = getattr(self._remote, method)(*args)
        except ProviderAuthError as exc:
            self._disable(str(exc))
            return None
        except ProviderQuotaError as exc:
            self._disable(str(exc))
            return None
        except Exception as exc:
            msg = scrub_secrets(str(exc))
            if "unreachable" in msg.lower() or classify_error(exc).kind == UNREACHABLE:
                self._disable(msg)
                return None
            with self._lock:
                self._failures += 1
                failures = self._failures
            logger.warning("AI provider %s failed (%s): %s", self.remote_name, method, msg[:200])
            if failures >= self.FAILURE_THRESHOLD:
                self._disable(f"{failures} consecutive failures, last: {msg[:160]}", hard=False)
            return None
        with self._lock:
            self._calls += 1
            if result.ok:
                self._failures = 0
                self._last_model = result.model
                if force and not self._hard_disabled:
                    self._disabled_reason = ""      # provider recovered
        return result if result.ok else None


# ── Factory ────────────────────────────────────────────────────────────────────

PROVIDER_ALIASES = {
    "anthropic": "claude", "google": "gemini", "googleai": "gemini", "gpt": "openai",
    "chatgpt": "openai", "local": "ollama", "openai-compatible": "custom", "compatible": "custom",
}


def canonical_provider(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    n = name.strip().lower()
    return PROVIDER_ALIASES.get(n, n)


def build_provider_chain(
    provider_name: Optional[str],
    api_key: Optional[str],
    base_url: Optional[str] = None,
    ollama_url: str = "http://localhost:11434",
    ollama_model: str = "llama3",
    model: Optional[str] = None,
) -> ProviderChain:
    """
    Build the provider chain. Raises ``ProviderAuthError`` for a missing key and
    ``ProviderError`` for an unknown provider / missing SDK — the caller decides
    whether that is fatal (CLI) or falls back to the local engine (engine).
    """
    name = canonical_provider(provider_name)
    if not name or name in ("heuristic", "none", "off"):
        return ProviderChain()  # local engine only

    if name == "ollama":
        return ProviderChain(OllamaProvider(ollama_url, model or ollama_model))

    if name not in ("gemini", "openai", "deepseek", "custom", "claude"):
        raise ProviderError(
            f"Unknown provider: {provider_name!r}. "
            "Valid options: gemini, openai, claude, deepseek, ollama, custom"
        )
    if name == "custom" and not base_url:
        raise ProviderError("--provider custom requires --provider-url (the OpenAI-compatible base URL).")
    if not api_key:
        from cloudaudit.core.constants import PROVIDER_ENV_KEYS
        env = PROVIDER_ENV_KEYS.get(name, "")
        raise ProviderAuthError(
            f"No API key found for {name}. Pass --api-key, set {env or 'the provider API key variable'}, "
            f"or run: cloudaudit config --set-api {name}"
        )

    if name == "gemini":
        return ProviderChain(GeminiProvider(api_key, model))
    if name == "claude":
        return ProviderChain(ClaudeProvider(api_key, model))
    return ProviderChain(OpenAICompatibleProvider(api_key, name, base_url, model))
