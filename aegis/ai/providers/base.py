"""Abstract base class for all AI model providers."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProviderResponse:
    """Normalized response from any AI provider."""
    content: str = ""
    json_data: Any = None
    model: str = ""
    provider: str = ""
    success: bool = False
    error: str = ""
    raw: Any = None
    usage: dict[str, int] = field(default_factory=dict)


_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
_OBJ_RE = re.compile(r"(\{.*\}|\[.*\])", re.DOTALL)


class BaseProvider:
    """Abstract AI provider. Subclasses implement chat() and chat_json()."""

    def __init__(self, name: str = "base"):
        self.name = name
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        return bool(self._available)

    def check_health(self) -> bool:
        """Override to probe provider availability. Returns True if reachable."""
        raise NotImplementedError

    def chat(self, system: str, user: str, **kwargs) -> ProviderResponse:
        """Single-turn chat. Returns ProviderResponse."""
        raise NotImplementedError

    def chat_json(self, system: str, user: str, **kwargs) -> Any | None:
        """Chat and coerce to JSON. Returns parsed object or None."""
        resp = self.chat(system, user, **kwargs)
        if resp.success and resp.content:
            parsed = self._extract_json(resp.content)
            resp.json_data = parsed
            return parsed
        return None

    @staticmethod
    def _extract_json(text: str) -> Any | None:
        """Extract JSON from text, handling code fences and prose wrapping."""
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
