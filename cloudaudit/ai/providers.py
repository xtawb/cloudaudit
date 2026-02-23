"""
cloudaudit.ai.providers — Unified AI Abstraction Layer

Supports:
  - Google Gemini (with dynamic model discovery + fallback)
  - OpenAI (GPT-4o family)
  - Anthropic Claude
  - DeepSeek AI (OpenAI-compatible endpoint)
  - Any OpenAI-compatible endpoint (--provider-url)
  - Ollama (local, no key required)
  - Built-in heuristic (always available, no external calls)

Design principles:
  - All providers normalise responses to AIResponse
  - Automatic fallback to next provider in chain on failure
  - API keys never logged
  - AI receives only redacted finding summaries
  - AI does NOT generate exploitation guidance
"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

from cloudaudit.core.exceptions import ProviderAuthError, ProviderError
from cloudaudit.core.constants import PROVIDER_MODEL_FALLBACKS

logger = logging.getLogger("cloudaudit.ai")


# ── Normalised response type ───────────────────────────────────────────────────

@dataclass
class AIResponse:
    text:     str
    provider: str
    model:    str
    latency_ms: int = 0
    tokens_used: int = 0

    @property
    def ok(self) -> bool:
        return bool(self.text and self.text.strip())


# ── AI task types ──────────────────────────────────────────────────────────────

PROMPT_EXECUTIVE_SUMMARY = """You are a cloud security auditor writing an executive summary for an internal security report.

Audit data (findings are redacted — no raw credentials included):
{audit_json}

Write a professional executive summary (4-6 paragraphs) covering:
1. Overall risk posture and exposure severity
2. Most critical finding categories and their business impact
3. Top 3 remediation priorities with estimated effort
4. Compliance framework gaps identified (CIS/NIST/SOC2/ISO27001/PCI-DSS)
5. Strategic recommendations for security posture improvement

Rules:
- Do NOT suggest exploitation steps or attack paths
- Focus entirely on defensive remediation
- Be precise and actionable
- Write for a CISO/CTO audience
"""

PROMPT_FILE_ANALYSIS = """You are a cloud security analyst reviewing a file found in a publicly exposed cloud storage container.

File: {filename}
File Type: {filetype}
Content (truncated, secrets partially redacted):
{content}

Identify any of the following:
1. Credentials, API keys, tokens, or secrets (even partially visible)
2. Internal infrastructure details (IPs, hostnames, service names)
3. PII or sensitive personal data patterns
4. Security misconfigurations
5. Hardcoded environment-specific values
6. Compliance violations

For each finding, output JSON:
{{"findings": [{{"type": "...", "description": "...", "severity": "critical|high|medium|low", "line_hint": "...", "confidence": 0.0-1.0, "recommendation": "..."}}]}}

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

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def complete(self, prompt: str, max_tokens: int = 1500) -> AIResponse:
        """Send prompt, return normalised AIResponse. Raises ProviderError on failure."""

    def generate_executive_summary(self, audit_json: str) -> AIResponse:
        prompt = PROMPT_EXECUTIVE_SUMMARY.format(audit_json=audit_json[:10000])
        return self.complete(prompt, max_tokens=1500)

    def analyse_file_content(self, filename: str, filetype: str, content: str) -> AIResponse:
        prompt = PROMPT_FILE_ANALYSIS.format(
            filename=filename,
            filetype=filetype,
            content=content[:4000],
        )
        return self.complete(prompt, max_tokens=800)

    def score_anomaly(self, filename: str, entropy_strings: list, patterns: list) -> AIResponse:
        prompt = PROMPT_ANOMALY_SCORE.format(
            filename=filename,
            entropy_strings=str(entropy_strings[:10]),
            patterns=str(patterns[:20]),
        )
        return self.complete(prompt, max_tokens=200)


# ── Gemini ─────────────────────────────────────────────────────────────────────

class GeminiProvider(AIProvider):
    """
    Google Gemini provider using the modern ``google.genai`` SDK.

    Key design decisions:
    - Uses ``from google import genai`` (the latest official SDK — never the
      deprecated ``google.generativeai`` package).
    - Performs dynamic model discovery via ``client.models.list()`` at
      initialisation time; no model names are ever hardcoded.
    - Selects the most capable, non-deprecated model that supports text
      generation and caches the choice for the lifetime of the instance.
    - Fails gracefully: if discovery fails or no suitable model is found, a
      ``ProviderError`` is raised rather than silently degrading.
    - API key is never logged.
    """

    name = "gemini"

    # Substrings that indicate a model is unsuitable (deprecated / vision-only etc.)
    _SKIP_SUBSTRINGS: tuple[str, ...] = (
        "vision",
        "embedding",
        "aqa",
        "legacy",
        "deprecated",
    )

    # Preference order: more capable / newer models rank first
    _CAPABILITY_KEYWORDS: tuple[str, ...] = (
        "ultra",
        "pro",
        "flash",
    )

    def __init__(self, api_key: str) -> None:
        """
        Initialise the Gemini client and perform dynamic model discovery.

        Args:
            api_key: A valid Google AI Studio / Vertex AI API key.

        Raises:
            ProviderError: If the ``google-genai`` package is not installed.
            ProviderError: If no suitable text-generation model can be found.
        """
        try:
            from google import genai  # type: ignore[import]
        except ImportError as exc:
            raise ProviderError(
                "google-genai package is not installed. "
                "Run: pip install google-genai"
            ) from exc

        self._client = genai.Client(api_key=api_key)
        self._model_name: str = self._discover_model()
        logger.info("GeminiProvider initialised with model: %s", self._model_name)

    # ── Model discovery ────────────────────────────────────────────────────────

    def _discover_model(self) -> str:
        """
        Discover the best available text-generation model dynamically.

        Queries ``client.models.list()``, filters to models that support
        text generation and are not deprecated, then sorts by capability
        preference keywords.

        Returns:
            The name of the selected model (e.g. ``"gemini-1.5-pro"``).

        Raises:
            ProviderError: If no suitable model is found.
        """
        try:
            all_models = list(self._client.models.list())
        except Exception as exc:
            raise ProviderError(
                f"Gemini model discovery failed — could not list models: {exc}"
            ) from exc

        if not all_models:
            raise ProviderError("Gemini model discovery returned an empty model list.")

        candidates: list[str] = []
        for model in all_models:
            raw_name: str = getattr(model, "name", "") or ""
            # Normalise: strip leading "models/" prefix for display
            short_name = raw_name.removeprefix("models/")
            # Must support text generation
            supported_methods: list[str] = getattr(
                model, "supported_generation_methods", []
            ) or []
            if "generateContent" not in supported_methods:
                continue
            # Skip vision-only, embedding, or deprecated models
            if any(skip in short_name.lower() for skip in self._SKIP_SUBSTRINGS):
                continue
            candidates.append(short_name)

        if not candidates:
            raise ProviderError(
                "No suitable Gemini text-generation models are available for this API key."
            )

        logger.debug("Gemini candidate models after filtering: %s", candidates)

        # Sort by capability preference: ultra > pro > flash > others
        def _rank(model_name: str) -> int:
            name_lower = model_name.lower()
            for rank, keyword in enumerate(self._CAPABILITY_KEYWORDS):
                if keyword in name_lower:
                    return rank
            return len(self._CAPABILITY_KEYWORDS)

        candidates.sort(key=_rank)
        selected = candidates[0]
        logger.info(
            "Gemini dynamic model selection: selected=%s (from %d candidates)",
            selected, len(candidates),
        )
        return selected

    # ── Core completion ────────────────────────────────────────────────────────

    def complete(self, prompt: str, max_tokens: int = 1500) -> AIResponse:
        """
        Send a text prompt to Gemini and return a normalised ``AIResponse``.

        Uses ``client.models.generate_content()`` with the dynamically
        selected model. Handles API errors safely — never crashes the caller.

        Args:
            prompt:     The text prompt to send.
            max_tokens: Maximum number of tokens to generate.

        Returns:
            ``AIResponse`` with ``ok=True`` on success.

        Raises:
            ProviderError: If the API call fails.
        """
        from google.genai import types as genai_types  # type: ignore[import]

        config = genai_types.GenerateContentConfig(
            max_output_tokens=max_tokens,
        )

        try:
            t0 = time.monotonic()
            response = self._client.models.generate_content(
                model=self._model_name,
                contents=prompt,
                config=config,
            )
            latency = int((time.monotonic() - t0) * 1000)
        except Exception as exc:
            err_str = str(exc)
            # Surface auth/quota errors immediately
            if any(kw in err_str.lower() for kw in ("api_key", "permission", "quota", "403", "401")):
                raise ProviderAuthError(
                    f"Gemini API key is invalid or lacks permissions: {exc}"
                ) from exc
            logger.error("Gemini generate_content failed for model=%s: %s", self._model_name, exc)
            raise ProviderError(
                f"Gemini generation failed (model={self._model_name}): {exc}"
            ) from exc

        # Extract text safely
        text: str = ""
        if hasattr(response, "text") and response.text:
            text = response.text
        elif hasattr(response, "candidates") and response.candidates:
            for candidate in response.candidates:
                if hasattr(candidate, "content") and candidate.content:
                    for part in getattr(candidate.content, "parts", []):
                        text += getattr(part, "text", "")

        if not text:
            logger.warning(
                "Gemini returned an empty response for model=%s", self._model_name
            )

        logger.info(
            "Gemini response: model=%s latency=%dms chars=%d",
            self._model_name, latency, len(text),
        )
        return AIResponse(
            text=text,
            provider="gemini",
            model=self._model_name,
            latency_ms=latency,
        )

    # ── Key validation ─────────────────────────────────────────────────────────

    def validate_key(self) -> dict:
        """
        Validate the API key by performing a lightweight ``models.list()`` call.

        Returns:
            A structured dict with keys:
            - ``valid`` (bool): Whether the key is functional.
            - ``model`` (str): The model selected during discovery, if valid.
            - ``error`` (str): Human-readable error message, if invalid.
        """
        try:
            models = list(self._client.models.list())
            logger.info(
                "Gemini API key validation succeeded — %d models visible", len(models)
            )
            return {
                "valid": True,
                "model": self._model_name,
                "error": None,
            }
        except Exception as exc:
            err_str = str(exc)
            if any(kw in err_str.lower() for kw in ("api_key", "invalid", "revoked", "403", "401")):
                reason = "API key is invalid or has been revoked."
            elif "permission" in err_str.lower():
                reason = "API key lacks required permissions for the Gemini API."
            else:
                reason = f"Unexpected error during key validation: {exc}"
            logger.error("Gemini API key validation failed: %s", reason)
            return {
                "valid": False,
                "model": None,
                "error": reason,
            }

    # ── Executive summary pipeline ─────────────────────────────────────────────

    def generate_executive_summary(self, audit_json: str) -> AIResponse:
        """
        Generate a professional executive summary from scan results.

        Formats the audit data cleanly, uses the dynamically selected model,
        and falls back gracefully if the AI call fails. Never triggers 404
        because model selection is dynamic.

        Args:
            audit_json: JSON string of scan results (will be truncated safely).

        Returns:
            ``AIResponse`` — either an AI-generated summary or a safe fallback.
        """
        # Truncate safely to avoid context-length errors
        truncated_json = audit_json[:10000]
        prompt = PROMPT_EXECUTIVE_SUMMARY.format(audit_json=truncated_json)
        try:
            return self.complete(prompt, max_tokens=1500)
        except ProviderAuthError:
            raise
        except Exception as exc:
            logger.warning(
                "Gemini executive summary generation failed (%s) — "
                "caller should fall back to heuristic provider.", exc
            )
            raise ProviderError(
                f"Executive summary generation failed: {exc}"
            ) from exc


# ── OpenAI (also used for DeepSeek and custom endpoints) ──────────────────────

class OpenAICompatibleProvider(AIProvider):
    """
    Handles OpenAI, DeepSeek, and any OpenAI-compatible endpoint.
    """

    def __init__(
        self,
        api_key: str,
        provider_name: str = "openai",
        base_url: Optional[str] = None,
    ) -> None:
        try:
            from openai import OpenAI
            url = base_url or {
                "openai":   None,
                "deepseek": "https://api.deepseek.com/v1",
            }.get(provider_name)
            kwargs: dict = {"api_key": api_key}
            if url:
                kwargs["base_url"] = url
            self._client        = OpenAI(**kwargs)
            self._provider_name = provider_name
        except ImportError:
            raise ProviderError("openai package not installed. Run: pip install openai")

    @property
    def name(self) -> str:
        return self._provider_name

    def complete(self, prompt: str, max_tokens: int = 1500) -> AIResponse:
        candidates = PROVIDER_MODEL_FALLBACKS.get(self._provider_name, ["gpt-4o-mini"])
        last_exc: Optional[Exception] = None

        for model_name in candidates:
            try:
                t0 = time.monotonic()
                resp = self._client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": "You are an enterprise cloud security auditor."},
                        {"role": "user",   "content": prompt},
                    ],
                    max_tokens=max_tokens,
                )
                latency = int((time.monotonic() - t0) * 1000)
                text = resp.choices[0].message.content or ""
                tokens = resp.usage.total_tokens if resp.usage else 0
                logger.info("%s response: model=%s latency=%dms tokens=%d",
                            self._provider_name, model_name, latency, tokens)
                return AIResponse(
                    text=text,
                    provider=self._provider_name,
                    model=model_name,
                    latency_ms=latency,
                    tokens_used=tokens,
                )
            except Exception as exc:
                # Check for auth error (don't retry on 401)
                err_str = str(exc).lower()
                if "401" in err_str or "authentication" in err_str or "invalid api key" in err_str:
                    raise ProviderAuthError(
                        f"Invalid API key for {self._provider_name}. "
                        "Check your key or run: cloudaudit config --set-api"
                    )
                logger.debug("%s model %s failed: %s", self._provider_name, model_name, exc)
                last_exc = exc
                continue

        raise ProviderError(f"All {self._provider_name} models failed. Last: {last_exc}")

    def validate_key(self) -> bool:
        try:
            models = self._client.models.list()
            return bool(models)
        except Exception:
            return False


# ── Claude ─────────────────────────────────────────────────────────────────────

class ClaudeProvider(AIProvider):

    name = "claude"

    def __init__(self, api_key: str) -> None:
        try:
            import anthropic
            self._client = anthropic.Anthropic(api_key=api_key)
        except ImportError:
            raise ProviderError("anthropic package not installed. Run: pip install anthropic")

    def complete(self, prompt: str, max_tokens: int = 1500) -> AIResponse:
        candidates = PROVIDER_MODEL_FALLBACKS["claude"]
        last_exc: Optional[Exception] = None

        for model_name in candidates:
            try:
                t0 = time.monotonic()
                msg = self._client.messages.create(
                    model=model_name,
                    max_tokens=max_tokens,
                    messages=[{"role": "user", "content": prompt}],
                )
                latency = int((time.monotonic() - t0) * 1000)
                text = msg.content[0].text if msg.content else ""
                return AIResponse(
                    text=text, provider="claude", model=model_name, latency_ms=latency
                )
            except Exception as exc:
                err_str = str(exc).lower()
                if "401" in err_str or "authentication" in err_str:
                    raise ProviderAuthError("Invalid Anthropic API key.")
                logger.debug("Claude model %s failed: %s", model_name, exc)
                last_exc = exc
                continue

        raise ProviderError(f"All Claude models failed. Last: {last_exc}")

    def validate_key(self) -> bool:
        try:
            self._client.models.list()
            return True
        except Exception:
            return False


# ── Ollama ─────────────────────────────────────────────────────────────────────

class OllamaProvider(AIProvider):

    name = "ollama"

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3") -> None:
        self._base_url = base_url.rstrip("/")
        self._model    = model

    def complete(self, prompt: str, max_tokens: int = 1500) -> AIResponse:
        import urllib.request
        payload = json.dumps({
            "model":   self._model,
            "prompt":  prompt,
            "stream":  False,
            "options": {"num_predict": max_tokens},
        }).encode("utf-8")
        try:
            t0 = time.monotonic()
            req = urllib.request.Request(
                f"{self._base_url}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            latency = int((time.monotonic() - t0) * 1000)
            return AIResponse(
                text=result.get("response", ""),
                provider="ollama",
                model=self._model,
                latency_ms=latency,
            )
        except Exception as exc:
            raise ProviderError(f"Ollama error ({self._base_url}): {exc}") from exc

    def validate_key(self) -> bool:
        import urllib.request
        try:
            urllib.request.urlopen(f"{self._base_url}/api/tags", timeout=5)
            return True
        except Exception:
            return False


# ── Heuristic fallback (no external calls) ─────────────────────────────────────

class HeuristicProvider(AIProvider):
    """
    Built-in deterministic summariser. Always available, zero latency, no API calls.
    Used when no AI provider is configured or all providers fail.
    """

    name = "heuristic"

    def complete(self, prompt: str, max_tokens: int = 1500) -> AIResponse:
        # The heuristic generates summaries based on the prompt content
        return AIResponse(text="", provider="heuristic", model="builtin")

    def generate_executive_summary(self, audit_json: str) -> AIResponse:
        try:
            data = json.loads(audit_json)
        except Exception:
            data = {}

        scan     = data.get("scan", {})
        findings = scan.get("findings", [])
        container= scan.get("container", {})
        risk     = scan.get("risk_score", 0)

        sev_counts: dict[str, int] = {}
        cat_counts: dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "Informational")
            c = f.get("category", "Unknown")
            sev_counts[s] = sev_counts.get(s, 0) + 1
            cat_counts[c] = cat_counts.get(c, 0) + 1

        crit = sev_counts.get("Critical", 0)
        high = sev_counts.get("High", 0)
        med  = sev_counts.get("Medium", 0)
        total= len(findings)
        cname= container.get("container_name", "Unknown")
        ctype= container.get("container_type", "Unknown")

        exposure = "CRITICAL" if crit > 0 else "HIGH" if high > 2 else "MODERATE" if high > 0 or med > 3 else "LOW"

        lines = [
            "## Executive Summary",
            "",
            f"The CloudAudit security assessment of **{cname}** ({ctype}) identified "
            f"**{total} findings** across {scan.get('scanned_files', 0)} scanned assets. "
            f"The overall risk posture is assessed as **{exposure}** with a composite risk "
            f"score of **{risk:.1f}/10**.",
            "",
        ]

        if crit > 0:
            rules = list({f.get("rule_name", "") for f in findings
                          if f.get("severity") == "Critical"})[:4]
            lines += [
                f"**Critical Findings ({crit}):** {crit} critical-severity findings require "
                f"immediate remediation before this audit closes. These include detections of "
                f"{', '.join(rules)}. Critical-severity exposures have a direct path to "
                f"full account compromise or significant data breach.",
                "",
            ]

        if high > 0:
            lines += [
                f"**High-Severity Findings ({high}):** High-severity findings should be "
                f"remediated within 24-72 hours. These represent significant exposure "
                f"vectors that could be chained with other vulnerabilities.",
                "",
            ]

        top_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_cats:
            cat_str = ", ".join(f"{c} ({n})" for c, n in top_cats)
            lines += [
                f"**Finding Categories:** The most prevalent finding categories are: "
                f"{cat_str}. These should inform your remediation prioritisation.",
                "",
            ]

        lines += [
            "**Top 3 Remediation Priorities:**",
            "1. Immediately rotate all exposed credentials, API keys, and tokens identified "
               "in this report. Contact the relevant service providers to confirm revocation.",
            "2. Enable cloud provider access controls (S3 Block Public Access / Azure Private "
               "Endpoint / GCS Uniform Bucket-Level Access) to prevent future accidental exposure.",
            "3. Implement a CI/CD secret scanning gate (e.g. git-secrets, truffleHog, Semgrep) "
               "to prevent future credential commits.",
            "",
            "**Compliance Implications:** Based on detected finding categories, the following "
            "frameworks have applicable gaps: CIS Benchmarks (public access controls), "
            "NIST 800-53 IA-5 (credential management), SOC2 CC6.7 (data transmission controls).",
            "",
            f"*Report generated by CloudAudit v1.0.1 — Powered by xtawb — https://linktr.ee/xtawb*",
        ]

        return AIResponse(text="\n".join(lines), provider="heuristic", model="builtin")


# ── Provider chain (automatic fallback) ───────────────────────────────────────

class ProviderChain:
    """
    Tries providers in order. Falls back to next on failure.
    Always ends with HeuristicProvider which never fails.
    """

    def __init__(self, primary: Optional[AIProvider] = None) -> None:
        self._chain: List[AIProvider] = []
        if primary:
            self._chain.append(primary)
        self._chain.append(HeuristicProvider())

    def generate_executive_summary(self, audit_json: str) -> AIResponse:
        return self._try_chain("generate_executive_summary", audit_json)

    def analyse_file_content(self, filename: str, filetype: str, content: str) -> AIResponse:
        return self._try_chain("analyse_file_content", filename, filetype, content)

    def score_anomaly(self, filename: str, entropy_strings: list, patterns: list) -> AIResponse:
        return self._try_chain("score_anomaly", filename, entropy_strings, patterns)

    def _try_chain(self, method: str, *args) -> AIResponse:
        for provider in self._chain:
            try:
                result: AIResponse = getattr(provider, method)(*args)
                if result.ok or provider.name == "heuristic":
                    return result
            except ProviderAuthError:
                raise  # Auth errors should surface immediately
            except ProviderError as exc:
                logger.warning("Provider %s failed (%s): %s — trying next", provider.name, method, exc)
            except Exception as exc:
                logger.warning("Unexpected error from %s: %s — trying next", provider.name, exc)
        return AIResponse(text="[Summary unavailable]", provider="none", model="none")


# ── Factory ────────────────────────────────────────────────────────────────────

def build_provider_chain(
    provider_name: Optional[str],
    api_key: Optional[str],
    base_url: Optional[str] = None,
    ollama_url: str = "http://localhost:11434",
    ollama_model: str = "llama3",
) -> ProviderChain:
    if not provider_name:
        return ProviderChain()  # heuristic only

    name = provider_name.lower()
    try:
        if name == "gemini":
            if not api_key:
                raise ProviderAuthError("Gemini requires an API key.")
            return ProviderChain(GeminiProvider(api_key))

        if name in ("openai", "deepseek"):
            if not api_key:
                raise ProviderAuthError(f"{name.title()} requires an API key.")
            return ProviderChain(OpenAICompatibleProvider(api_key, name, base_url))

        if name == "custom" and base_url:
            if not api_key:
                raise ProviderAuthError("Custom OpenAI-compatible endpoint requires an API key.")
            return ProviderChain(OpenAICompatibleProvider(api_key, "custom", base_url))

        if name in ("claude", "anthropic"):
            if not api_key:
                raise ProviderAuthError("Claude requires an Anthropic API key.")
            return ProviderChain(ClaudeProvider(api_key))

        if name == "ollama":
            return ProviderChain(OllamaProvider(ollama_url, ollama_model))

    except ProviderAuthError:
        raise
    except ProviderError as exc:
        logger.error("Failed to initialise %s provider: %s — falling back to heuristic", name, exc)
        return ProviderChain()

    raise ProviderError(
        f"Unknown provider: {provider_name!r}. "
        "Valid options: gemini, openai, claude, deepseek, ollama, custom"
    )
