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
    Google Gemini with dynamic model discovery.
    Tries each model in PROVIDER_MODEL_FALLBACKS['gemini'] until one succeeds.
    """

    name = "gemini"

    def __init__(self, api_key: str) -> None:
        try:
            import google.generativeai as genai
            self._genai   = genai
            self._api_key = api_key
            genai.configure(api_key=api_key)
            self._model_name = self._discover_model()
        except ImportError:
            raise ProviderError(
                "google-generativeai not installed. Run: pip install google-generativeai"
            )

    def _discover_model(self) -> str:
        """Try to list available models; fall back to hardcoded list."""
        candidates = list(PROVIDER_MODEL_FALLBACKS["gemini"])
        try:
            available = [m.name for m in self._genai.list_models()
                         if "generateContent" in (m.supported_generation_methods or [])]
            if available:
                logger.debug("Gemini available models: %s", available[:5])
                # Prefer candidates that are actually available
                for c in candidates:
                    full = f"models/{c}" if not c.startswith("models/") else c
                    if full in available or c in available:
                        logger.info("Gemini selected model: %s", c)
                        return c
        except Exception as exc:
            logger.debug("Gemini model discovery failed: %s — using fallback list", exc)

        # Return first candidate blindly; complete() will try each
        return candidates[0]

    def complete(self, prompt: str, max_tokens: int = 1500) -> AIResponse:
        candidates = PROVIDER_MODEL_FALLBACKS["gemini"]
        last_exc: Optional[Exception] = None

        for model_name in candidates:
            try:
                t0 = time.monotonic()
                model = self._genai.GenerativeModel(model_name)
                result = model.generate_content(
                    prompt,
                    generation_config={"max_output_tokens": max_tokens},
                )
                latency = int((time.monotonic() - t0) * 1000)
                text = result.text if hasattr(result, "text") else str(result)
                logger.info("Gemini response: model=%s latency=%dms", model_name, latency)
                return AIResponse(
                    text=text, provider="gemini", model=model_name, latency_ms=latency
                )
            except Exception as exc:
                logger.debug("Gemini model %s failed: %s", model_name, exc)
                last_exc = exc
                continue

        raise ProviderError(f"All Gemini models failed. Last error: {last_exc}")

    def validate_key(self) -> bool:
        """Attempt a minimal API call to confirm the key is valid."""
        try:
            list(self._genai.list_models())
            return True
        except Exception:
            return False


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
            f"*Report generated by CloudAudit v2.0.0 — Powered by xtawb — https://linktr.ee/xtawb*",
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
