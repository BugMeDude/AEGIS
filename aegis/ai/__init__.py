"""AEGIS AI layer: Ollama-backed reasoning with deterministic fallback."""

from .brain import AIBrain
from .ollama import OllamaClient

__all__ = ["AIBrain", "OllamaClient"]
