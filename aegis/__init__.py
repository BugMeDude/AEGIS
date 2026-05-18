"""AEGIS - Autonomous API Stress & Security Intelligence Platform.

A complete, AI-driven rebuild of the original "Ethical Hacker API Tester".

AEGIS provides:
  * An async, percentile-accurate API load / stress engine.
  * Real LLM reasoning via Ollama (default model: ``gemma4:31b-cloud``) with a
    deterministic heuristic fallback so every feature works even offline.
  * A unified CLI and a modern GUI.
  * Autopilot: a fully automated plan -> stress -> analyse -> report loop.
  * Built-in responsible-use safety controls (authorization gate + caps).

Public package surface is intentionally small; import submodules directly.
"""

from __future__ import annotations

__app_name__ = "AEGIS"
__tagline__ = "Autonomous API Stress & Security Intelligence Platform"
__version__ = "2.1.0"
__author__ = "BugMeDude"

# Single source of truth for the education/research caption. Surfaced in the
# CLI banner, the GUI header, every generated report and the docs.
EDU_NOTICE = (
    "FOR EDUCATION & SECURITY RESEARCH ONLY. AEGIS is a dual-use "
    "offensive + defensive API testing platform built for students, "
    "researchers and authorised penetration testers to learn how API "
    "load, resilience and injection-class vulnerabilities work — and how "
    "to defend against them. Use it ONLY on systems you own or are "
    "explicitly authorised to test. Unauthorised use is illegal and is "
    "solely the user's responsibility."
)

EDU_CAPTION = (
    "🎓 Educational & Research Edition — Offensive + Defensive · "
    "Authorised testing only"
)

__all__ = [
    "__app_name__", "__tagline__", "__version__", "__author__",
    "EDU_NOTICE", "EDU_CAPTION",
]
