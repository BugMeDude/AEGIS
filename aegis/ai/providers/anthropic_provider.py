"""Anthropic Claude provider."""

from __future__ import annotations

from ...config import AnthropicConfig
from .base import BaseProvider, ProviderResponse


class AnthropicProvider(BaseProvider):
    """Anthropic Claude provider. Requires anthropic>=0.30."""

    def __init__(self, cfg: AnthropicConfig) -> None:
        super().__init__("anthropic")
        self.cfg = cfg
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        if not self.cfg.api_key:
            return None
        try:
            from anthropic import Anthropic
            self._client = Anthropic(api_key=self.cfg.api_key)
            return self._client
        except Exception:
            return None

    def check_health(self) -> bool:
        if not self.cfg.enabled or not self.cfg.api_key:
            self._available = False
            return False
        client = self._get_client()
        if client is None:
            self._available = False
            return False
        try:
            client.ping()
            self._available = True
            return True
        except Exception:
            self._available = False
            return False

    def chat(self, system: str, user: str, **kwargs) -> ProviderResponse:
        resp = ProviderResponse(provider=self.name)
        if not self.cfg.enabled:
            resp.error = "Anthropic disabled by configuration"
            return resp
        if not self.cfg.api_key:
            resp.error = "No Anthropic API key configured"
            return resp
        client = self._get_client()
        if client is None:
            resp.error = "Failed to initialize Anthropic client"
            return resp

        if self._available is None:
            self.check_health()

        try:
            result = client.messages.create(
                model=kwargs.get("model", self.cfg.model),
                system=system,
                messages=[{"role": "user", "content": user}],
                max_tokens=4096,
                temperature=kwargs.get("temperature", self.cfg.temperature),
            )
            resp.content = result.content[0].text if result.content else ""
            resp.model = result.model
            resp.success = True
            resp.raw = result
            if hasattr(result, "usage"):
                resp.usage = {
                    "input_tokens": result.usage.input_tokens or 0,
                    "output_tokens": result.usage.output_tokens or 0,
                }
            self._available = True
        except Exception as exc:
            resp.error = f"{type(exc).__name__}: {exc}"
        return resp
