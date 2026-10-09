"""
cloudaudit.providers.ai_provider — legacy import path (compatibility shim)

Before v1.3.0 this module carried a second, independent copy of every AI
provider. The copies drifted apart — this one still hardcoded retired model
names and had none of the error handling in ``cloudaudit.ai.providers`` — so
the duplicate implementations were removed. The public names are kept and now
delegate to the single maintained implementation.
"""

from __future__ import annotations

import json
from typing import Optional

from cloudaudit.ai.providers import (  # noqa: F401  (re-exported)
    AIProvider as _ChainProvider,
    ClaudeProvider,
    GeminiProvider,
    HeuristicProvider as _LocalProvider,
    OllamaProvider,
    OpenAICompatibleProvider as OpenAIProvider,
    ProviderChain,
    build_provider_chain,
)
from cloudaudit.core.models import ScanStats


class AIProvider:
    """Legacy interface: ``generate_summary(stats) -> str``."""

    def __init__(self, chain: Optional[ProviderChain] = None) -> None:
        self._chain = chain or ProviderChain()

    def generate_summary(self, stats: ScanStats) -> str:
        return self._chain.generate_executive_summary(json.dumps(stats.to_dict(), default=str)).text


class HeuristicProvider(AIProvider):
    """Offline summariser (the local intelligence engine)."""

    def __init__(self) -> None:
        super().__init__(ProviderChain())


def build_provider(
    provider_name: Optional[str],
    api_key: Optional[str],
    ollama_url: str = "http://localhost:11434",
    ollama_model: str = "llama3",
) -> AIProvider:
    """Instantiate a summary provider. Falls back to the local engine on any provider failure."""
    if not provider_name:
        return HeuristicProvider()
    return AIProvider(build_provider_chain(provider_name, api_key, None, ollama_url, ollama_model))
