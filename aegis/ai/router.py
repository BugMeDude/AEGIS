"""Multi-model AI router — selects provider based on task and availability."""

from __future__ import annotations

from ..config import AIProviderConfig
from .providers import BaseProvider, OllamaProvider, OpenAIProvider, AnthropicProvider
from .providers.base import ProviderResponse

_TASK_WEIGHTS = {
    "plan": "balanced",
    "nlp": "fast",
    "security": "deep",
    "insight": "deep",
    "payload": "creative",
    "strategy": "deep",
    "analysis": "balanced",
    "quick": "fast",
}


class ModelRouter:
    """Routes AI tasks to the optimal available provider.

    Order of preference:
      1. Task-specific model if configured
      2. Primary configured provider
      3. Fallback to next available provider
      4. Return None (caller uses heuristic)
    """

    def __init__(self, cfg: AIProviderConfig) -> None:
        self.cfg = cfg
        self._providers: dict[str, BaseProvider] = {}
        self._init_providers()

    def _init_providers(self) -> None:
        ollama = OllamaProvider(self.cfg.ollama)
        self._providers["ollama"] = ollama

        openai = OpenAIProvider(self.cfg.openai)
        self._providers["openai"] = openai

        anthropic = AnthropicProvider(self.cfg.anthropic)
        self._providers["anthropic"] = anthropic

    def _check_all(self) -> None:
        for p in self._providers.values():
            if p._available is None:
                p.check_health()

    def available_providers(self) -> list[str]:
        self._check_all()
        return [name for name, p in self._providers.items() if p.available]

    def best_provider(self, task: str = "balanced") -> BaseProvider | None:
        self._check_all()
        primary = self.cfg.primary

        if primary in self._providers and self._providers[primary].available:
            return self._providers[primary]

        for name, provider in self._providers.items():
            if provider.available:
                return provider

        return None

    def chat(self, system: str, user: str, task: str = "balanced", **kwargs) -> ProviderResponse:
        provider = self.best_provider(task)
        if provider is None:
            return ProviderResponse(success=False, error="No AI provider available")
        return provider.chat(system, user, **kwargs)

    def chat_json(self, system: str, user: str, task: str = "balanced", **kwargs):
        provider = self.best_provider(task)
        if provider is None:
            return None
        return provider.chat_json(system, user, **kwargs)

    def get_provider(self, name: str) -> BaseProvider | None:
        return self._providers.get(name)
