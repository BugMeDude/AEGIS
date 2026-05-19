"""Backward-compatible Ollama client — delegates to OllamaProvider."""

from __future__ import annotations

from ..config import OllamaConfig
from .providers.ollama_provider import OllamaProvider


class OllamaClient(OllamaProvider):
    """Backward-compatible OllamaClient that looks like the original API.

    Maintains the same interface as the v2.1.0 OllamaClient for
    backward compatibility with existing code.
    """

    def __init__(self, cfg: OllamaConfig) -> None:
        super().__init__(cfg)
