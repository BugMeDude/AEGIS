"""OpenAI provider — connects to OpenAI API or compatible endpoints."""

from __future__ import annotations

from ...config import OpenAIConfig
from .base import BaseProvider, ProviderResponse


class OpenAIProvider(BaseProvider):
    """OpenAI API provider. Requires openai>=1.0."""

    def __init__(self, cfg: OpenAIConfig) -> None:
        super().__init__("openai")
        self.cfg = cfg
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        if not self.cfg.api_key:
            return None
        try:
            from openai import OpenAI
            kwargs = {"api_key": self.cfg.api_key, "timeout": self.cfg.timeout_seconds}
            if self.cfg.org_id:
                kwargs["organization"] = self.cfg.org_id
            self._client = OpenAI(**kwargs)
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
            client.models.list()
            self._available = True
            return True
        except Exception:
            self._available = False
            return False

    def chat(self, system: str, user: str, **kwargs) -> ProviderResponse:
        resp = ProviderResponse(provider="openai")
        if not self.cfg.enabled:
            resp.error = "OpenAI disabled by configuration"
            return resp
        if not self.cfg.api_key:
            resp.error = "No OpenAI API key configured"
            return resp
        client = self._get_client()
        if client is None:
            resp.error = "Failed to initialize OpenAI client"
            return resp

        if self._available is None:
            self.check_health()

        try:
            result = client.chat.completions.create(
                model=kwargs.get("model", self.cfg.model),
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=kwargs.get("temperature", self.cfg.temperature),
                response_format={"type": "json_object"} if kwargs.get("json_mode", True) else None,
            )
            choice = result.choices[0]
            resp.content = choice.message.content or ""
            resp.model = result.model
            resp.success = True
            resp.raw = result
            if result.usage:
                resp.usage = {
                    "prompt_tokens": result.usage.prompt_tokens or 0,
                    "completion_tokens": result.usage.completion_tokens or 0,
                    "total_tokens": result.usage.total_tokens or 0,
                }
            self._available = True
        except Exception as exc:
            resp.error = f"{type(exc).__name__}: {exc}"
        return resp
