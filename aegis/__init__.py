"""AEGIS v3 - Autonomous API Attack, Stress & Security Intelligence Platform.

v3 is a red-team / adversary-simulation enhancement of the original platform:
  * Multi-provider AI (Ollama, OpenAI, Anthropic) with agentic attack planning
  * AI-driven payload generation and WAF-aware mutation engine
  * 15+ vulnerability class scanners (SQLi, XSS, SSRF, XXE, deserialization, etc.)
  * Multi-stage attack chain execution (sqli_to_auth, ssrf_to_cloud, etc.)
  * Full reconnaissance: tech fingerprinting, endpoint discovery, schema extraction
  * Interactive REPL console campaign management
  * MITRE ATT&CK mapping and Navigator layer generation
  * Proxy chain, TLS fingerprint randomization, and Tor integration
  * Progressive authorization tiers (education → research → expert)

Public package surface is intentionally small; import submodules directly.
"""

from __future__ import annotations

__app_name__ = "AEGIS"
__tagline__ = "Autonomous API Attack, Stress & Security Intelligence Platform"
__version__ = "3.0.0"
__author__ = "BugMeDude"

EDU_NOTICE = (
    "FOR EDUCATION & SECURITY RESEARCH ONLY. AEGIS v3 is an adversarial "
    "API security testing platform built for students, researchers and "
    "authorised penetration testers. It provides dual-use offensive + defensive "
    "capabilities including autonomous attack planning, AI-generated payloads, "
    "and advanced evasion techniques. Use it ONLY on systems you own or are "
    "explicitly authorised to test. Unauthorised use is illegal and is solely "
    "the user's responsibility."
)

EDU_CAPTION = (
    "🎓 Educational & Research Edition v3 — Red Team · Offensive + Defensive · "
    "Authorised testing only"
)

__all__ = [
    "__app_name__", "__tagline__", "__version__", "__author__",
    "EDU_NOTICE", "EDU_CAPTION",
]
