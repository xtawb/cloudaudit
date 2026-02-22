"""
cloudaudit — AI Provider Integration

Supports:
  - Google Gemini
  - OpenAI (GPT-4 family)
  - Anthropic Claude
  - Ollama (local, no key required)

AI is used strictly for:
  1. Summarising findings for executive reports
  2. Classifying severity of ambiguous findings
  3. Generating remediation guidance

AI does NOT:
  - Generate exploitation steps or attack playbooks
  - Receive raw secret values (only redacted finding summaries)
  - Store data externally beyond the API request/response
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from typing import List, Optional

from cloudaudit.core.exceptions import ProviderAuthError, ProviderError
from cloudaudit.core.models import Finding, ScanStats

logger = logging.getLogger("cloudaudit.provider")

# ── Prompt templates ───────────────────────────────────────────────────────────

_SUMMARY_PROMPT = """You are a cloud security auditor producing an executive summary.

The following is a structured audit result for a cloud storage container.
Write a concise, professional executive summary (3–5 paragraphs) covering:
1. Overall exposure level and risk posture
2. Most critical findings and their business impact
3. Top 3 remediation priorities
4. Compliance implications (CIS/NIST/SOC2)

Do NOT generate exploitation steps or attack paths.
Focus entirely on defensive remediation guidance.

Audit data:
{audit_json}
"""


# ── Abstract base ──────────────────────────────────────────────────────────────

class AIProvider(ABC):
    """Base class for all AI providers."""

    @abstractmethod
    def generate_summary(self, stats: ScanStats) -> str:
        """Generate an executive summary from scan statistics."""

    def _build_audit_json(self, stats: ScanStats) -> str:
        """Build a redacted JSON summary suitable for sending to an AI provider."""
        data = {
            "container": stats.container_info.to_dict() if stats.container_info else {},
            "files_scanned": stats.scanned_files,
            "total_files":   stats.total_files,
            "risk_score":    stats.risk_score,
            "findings_summary": self._findings_summary(stats.findings),
        }
        # Findings are already redacted in the model — safe to serialise
        return json.dumps(data, indent=2, default=str)[:12000]  # cap token usage

    @staticmethod
    def _findings_summary(findings: List[Finding]) -> list:
        # Send only metadata — matches are already redacted strings
        return [
            {
                "rule":       f.rule_name,
                "severity":   f.severity.value,
                "category":   f.category.value,
                "file":       f.file_name,
                "description": f.description,
            }
            for f in findings
        ]


# ── Gemini ─────────────────────────────────────────────────────────────────────

class GeminiProvider(AIProvider):

    def __init__(self, api_key: str, model: str = "gemini-1.5-flash") -> None:
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self._model = genai.GenerativeModel(model)
        except ImportError:
            raise ProviderError(
                "google-generativeai package not installed. "
                "Run: pip install google-generativeai"
            )

    def generate_summary(self, stats: ScanStats) -> str:
        prompt = _SUMMARY_PROMPT.format(audit_json=self._build_audit_json(stats))
        try:
            response = self._model.generate_content(prompt)
            return response.text
        except Exception as exc:
            raise ProviderError(f"Gemini API error: {exc}") from exc


# ── OpenAI ─────────────────────────────────────────────────────────────────────

class OpenAIProvider(AIProvider):

    def __init__(self, api_key: str, model: str = "gpt-4o-mini") -> None:
        try:
            from openai import OpenAI
            self._client = OpenAI(api_key=api_key)
            self._model  = model
        except ImportError:
            raise ProviderError(
                "openai package not installed. Run: pip install openai"
            )

    def generate_summary(self, stats: ScanStats) -> str:
        prompt = _SUMMARY_PROMPT.format(audit_json=self._build_audit_json(stats))
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": "You are an enterprise cloud security auditor."},
                    {"role": "user",   "content": prompt},
                ],
                max_tokens=1024,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            raise ProviderError(f"OpenAI API error: {exc}") from exc


# ── Anthropic Claude ───────────────────────────────────────────────────────────

class ClaudeProvider(AIProvider):

    def __init__(self, api_key: str, model: str = "claude-3-haiku-20240307") -> None:
        try:
            import anthropic
            self._client = anthropic.Anthropic(api_key=api_key)
            self._model  = model
        except ImportError:
            raise ProviderError(
                "anthropic package not installed. Run: pip install anthropic"
            )

    def generate_summary(self, stats: ScanStats) -> str:
        prompt = _SUMMARY_PROMPT.format(audit_json=self._build_audit_json(stats))
        try:
            message = self._client.messages.create(
                model=self._model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text
        except Exception as exc:
            raise ProviderError(f"Claude API error: {exc}") from exc


# ── Ollama (local) ─────────────────────────────────────────────────────────────

class OllamaProvider(AIProvider):

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3") -> None:
        self._base_url = base_url.rstrip("/")
        self._model    = model

    def generate_summary(self, stats: ScanStats) -> str:
        import urllib.request
        prompt = _SUMMARY_PROMPT.format(audit_json=self._build_audit_json(stats))
        payload = json.dumps({
            "model":  self._model,
            "prompt": prompt,
            "stream": False,
        }).encode("utf-8")
        try:
            req = urllib.request.Request(
                f"{self._base_url}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result.get("response", "")
        except Exception as exc:
            raise ProviderError(f"Ollama API error: {exc}") from exc


# ── Heuristic fallback ─────────────────────────────────────────────────────────

class HeuristicProvider(AIProvider):
    """
    Built-in heuristic summariser used when no AI provider is configured.
    Produces a deterministic, rule-based executive summary.
    """

    def generate_summary(self, stats: ScanStats) -> str:
        from cloudaudit.core.models import Severity

        critical = sum(1 for f in stats.findings if f.severity == Severity.CRITICAL)
        high     = sum(1 for f in stats.findings if f.severity == Severity.HIGH)
        medium   = sum(1 for f in stats.findings if f.severity == Severity.MEDIUM)
        low      = sum(1 for f in stats.findings if f.severity == Severity.LOW)
        total    = len(stats.findings)
        container = stats.container_info

        exposure = "critical" if critical > 0 else "high" if high > 0 else "moderate" if medium > 0 else "low"

        lines = [
            f"## Executive Summary",
            f"",
            f"The cloud storage audit of **{container.container_name or container.raw_url}** "
            f"({container.container_type.value}) identified **{total} findings** "
            f"across {stats.scanned_files} scanned files. "
            f"The overall risk posture is assessed as **{exposure.upper()}**.",
            f"",
        ]

        if critical > 0:
            rules = [f.rule_name for f in stats.findings if f.severity == Severity.CRITICAL]
            lines += [
                f"**{critical} Critical Finding(s)** require immediate attention. "
                f"These include: {', '.join(sorted(set(rules)))}. "
                f"Exposed credentials or private keys can lead to full account compromise.",
                "",
            ]

        if high > 0:
            lines += [
                f"**{high} High-Severity Finding(s)** were identified that should be "
                f"remediated within 24–48 hours to prevent data exposure.",
                "",
            ]

        if medium + low > 0:
            lines += [
                f"An additional {medium} medium and {low} low-severity findings were recorded, "
                f"including infrastructure metadata exposure and PII indicators.",
                "",
            ]

        lines += [
            "**Top Remediation Priorities:**",
            "1. Rotate any exposed credentials or API keys immediately.",
            "2. Enable S3 Block Public Access / equivalent and enforce bucket policies.",
            "3. Remove sensitive files (.env, config, keys) from cloud storage.",
            "4. Implement automated secret scanning in your CI/CD pipeline.",
            "",
            f"**Risk Score:** {stats.risk_score:.1f}/10",
        ]

        return "\n".join(lines)


# ── Factory ────────────────────────────────────────────────────────────────────

def build_provider(
    provider_name: Optional[str],
    api_key: Optional[str],
    ollama_url: str = "http://localhost:11434",
    ollama_model: str = "llama3",
) -> AIProvider:
    """Instantiate the appropriate AIProvider."""
    if not provider_name:
        return HeuristicProvider()

    name = provider_name.lower()

    if name == "gemini":
        if not api_key:
            raise ProviderAuthError(
                "Gemini requires an API key. Set GEMINI_API_KEY or use --api-key.\n"
                "Get one at: https://aistudio.google.com/app/apikey"
            )
        return GeminiProvider(api_key)

    if name == "openai":
        if not api_key:
            raise ProviderAuthError(
                "OpenAI requires an API key. Set OPENAI_API_KEY or use --api-key.\n"
                "Get one at: https://platform.openai.com/api-keys"
            )
        return OpenAIProvider(api_key)

    if name in ("claude", "anthropic"):
        if not api_key:
            raise ProviderAuthError(
                "Claude requires an Anthropic API key. Set ANTHROPIC_API_KEY or use --api-key.\n"
                "Get one at: https://console.anthropic.com/settings/keys"
            )
        return ClaudeProvider(api_key)

    if name == "ollama":
        return OllamaProvider(base_url=ollama_url, model=ollama_model)

    raise ProviderError(f"Unknown AI provider: {provider_name!r}. Choose from: gemini, openai, claude, ollama")
