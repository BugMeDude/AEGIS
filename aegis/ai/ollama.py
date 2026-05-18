"""A small, resilient Ollama chat client.

Targets the local Ollama daemon (default ``gemma4:31b-cloud``). It is built to
fail *soft*: every public method returns ``None`` instead of raising when the
daemon is unreachable, so the AIBrain can transparently fall back to its
deterministic engine. JSON answers are extracted even when the model wraps
them in Markdown code fences (gemma does this).
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from ..config import OllamaConfig

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)
_OBJ_RE = re.compile(r"(\{.*\}|\[.*\])", re.DOTALL)


class OllamaClient:
    def __init__(self, cfg: OllamaConfig) -> None:
        self.cfg = cfg
        self._available: bool | None = None
        self._active_model = cfg.model

    # ------------------------------------------------------------------ #
    def health(self) -> dict[str, Any]:
        """Probe the daemon and return a structured status dict."""
        if not self.cfg.enabled:
            return {"ok": False, "reason": "AI disabled by configuration",
                    "model": self.cfg.model}
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
            return {"ok": True, "host": self.cfg.host, "model": chosen,
                    "available_models": models}
        except Exception as exc:
            self._available = False
            return {"ok": False, "reason": f"{type(exc).__name__}: {exc}",
                    "host": self.cfg.host, "model": self.cfg.model}

    @property
    def available(self) -> bool:
        if self._available is None:
            self.health()
        return bool(self._available)

    @property
    def active_model(self) -> str:
        return self._active_model

    # ------------------------------------------------------------------ #
    def chat(self, system: str, user: str, *, json_mode: bool = False) -> str | None:
        """Single-turn chat. Returns raw assistant text, or ``None`` on failure."""
        if not self.cfg.enabled:
            return None
        if self._available is None:
            self.health()
        if not self._available:
            return None
        payload: dict[str, Any] = {
            "model": self._active_model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "options": {"temperature": self.cfg.temperature},
        }
        if json_mode:
            payload["format"] = "json"
        try:
            r = httpx.post(
                f"{self.cfg.host}/api/chat",
                json=payload,
                timeout=self.cfg.timeout_seconds,
            )
            r.raise_for_status()
            return r.json().get("message", {}).get("content", "") or None
        except Exception:
            self._available = False
            return None

    def chat_json(self, system: str, user: str) -> Any | None:
        """Chat and robustly coerce the answer into a Python object."""
        raw = self.chat(system, user, json_mode=True)
        if raw is None:
            return None
        return self._extract_json(raw)

    @staticmethod
    def _extract_json(text: str) -> Any | None:
        text = text.strip()
        for candidate in (text, *_FENCE_RE.findall(text)):
            candidate = candidate.strip()
            try:
                return json.loads(candidate)
            except Exception:
                m = _OBJ_RE.search(candidate)
                if m:
                    try:
                        return json.loads(m.group(1))
                    except Exception:
                        continue
        return None
