"""Ollama provider — resilient HTTP client for local Ollama daemon."""

from __future__ import annotations

import httpx

from ...config import OllamaConfig
from .base import BaseProvider, ProviderResponse


class OllamaProvider(BaseProvider):
    """Ollama provider. Fails soft: returns success=False on error."""

    def __init__(self, cfg: OllamaConfig) -> None:
        super().__init__("ollama")
        self.cfg = cfg
        self._active_model = cfg.model

    def check_health(self) -> bool:
        if not self.cfg.enabled:
            self._available = False
            return False
        try:
            r = httpx.get(f"{self.cfg.host}/api/tags", timeout=5.0)
            r.raise_for_status()
            models = [m["name"] for m in r.json().get("models", [])]
            chosen = self.cfg.model
            if chosen not in models:
                if self.cfg.fallback_model in models:
                    chosen = self.cfg.fallback_model
                elif models:
                    chosen = models[0]
            self._active_model = chosen
            self._available = True
            return True
        except Exception:
            self._available = False
            return False

    @property
    def active_model(self) -> str:
        return self._active_model

    def chat(self, system: str, user: str, **kwargs) -> ProviderResponse:
        resp = ProviderResponse(provider="ollama")
        if not self.cfg.enabled:
            resp.error = "AI disabled by configuration"
            return resp
        if self._available is None:
            self.check_health()
        if not self._available:
            resp.error = "Ollama daemon unavailable"
            return resp

        payload = {
            "model": self._active_model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "options": {"temperature": kwargs.get("temperature", self.cfg.temperature)},
        }
        if kwargs.get("json_mode", True):
            payload["format"] = "json"

        try:
            r = httpx.post(
                f"{self.cfg.host}/api/chat",
                json=payload,
                timeout=kwargs.get("timeout", self.cfg.timeout_seconds),
            )
            r.raise_for_status()
            data = r.json()
            resp.content = (data.get("message", {}).get("content", "") or "")
            resp.model = self._active_model
            resp.success = True
            resp.raw = data
        except Exception as exc:
            self._available = False
            resp.error = f"{type(exc).__name__}: {exc}"
        return resp
