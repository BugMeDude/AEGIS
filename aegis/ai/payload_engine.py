"""AI-driven payload generation and mutation engine.

Instead of static payload lists, this engine uses AI to:
1. Generate context-aware payloads based on observed technology
2. Mutate payloads when WAF blocks them (encoding, splitting, obfuscation)
3. Generate progressively complex payload chains for multi-stage attacks
4. Optimize payloads for specific vulnerability classes and contexts
"""

from __future__ import annotations

import json
from typing import Any

from ..models import Severity
from .router import ModelRouter
from . import prompts


class PayloadEngine:
    """AI-driven payload generation, mutation, and optimization."""

    def __init__(self, router: ModelRouter) -> None:
        self.router = router

    def generate_payloads(
        self,
        vuln_class: str,
        context: dict[str, Any] | None = None,
        count: int = 5,
        evasion_level: int = 0,
    ) -> list[dict]:
        """Generate AI-crafted payloads for a given vulnerability class.

        Args:
            vuln_class: Type of vulnerability (sqli, xss, ssti, cmdi, etc.)
            context: Observed context (WAF type, parameter type, content-type, etc.)
            count: Number of payloads to generate
            evasion_level: 0=basic, 1=encoded, 2=obfuscated, 3=polymorphic

        Returns:
            List of dicts with 'payload', 'description', 'expected_indicator' keys
        """
        context_str = json.dumps(context or {})
        system = prompts.PAYLOAD_SYSTEM
        user = prompts.PAYLOAD_USER.format(
            vuln_class=vuln_class,
            context=context_str,
            count=count,
            evasion_level=evasion_level,
        )

        data = self.router.chat_json(system, user, task="payload")
        if isinstance(data, dict) and data.get("payloads"):
            return data["payloads"]
        return []

    def mutate_payload(
        self,
        payload: str,
        vuln_class: str,
        waf_signature: str = "",
        technique: str = "encoding",
    ) -> str | None:
        """Mutate a payload to bypass WAF/filter detection.

        Techniques: encoding, case_permutation, comment_injection,
                    unicode_normalization, parameter_pollution,
                    chunked_encoding, whitespace_variation
        """
        system = prompts.MUTATION_SYSTEM
        user = prompts.MUTATION_USER.format(
            payload=payload,
            vuln_class=vuln_class,
            waf_signature=waf_signature or "generic",
            technique=technique,
        )

        data = self.router.chat_json(system, user, task="payload")
        if isinstance(data, dict) and data.get("mutated"):
            return data["mutated"]
        return None

    def generate_chain(
        self,
        entry_points: list[dict],
        goal: str = "data_exfiltration",
    ) -> list[dict] | None:
        """Generate a multi-step attack chain combining multiple vuln classes.

        Example: SQLi → extract hash → crack → authenticate → pivot
        """
        system = prompts.CHAIN_SYSTEM
        user = prompts.CHAIN_USER.format(
            entry_points=json.dumps(entry_points[:5]),
            goal=goal,
        )

        data = self.router.chat_json(system, user, task="payload")
        if isinstance(data, dict) and data.get("chain"):
            return data["chain"]
        return None

    def analyze_response(
        self,
        payload: str,
        response_status: int,
        response_body: str,
        response_headers: dict,
        vuln_class: str,
    ) -> dict | None:
        """AI analyzes whether a payload successfully triggered a vulnerability."""
        system = prompts.RESPONSE_ANALYSIS_SYSTEM
        user = prompts.RESPONSE_ANALYSIS_USER.format(
            payload=payload,
            vuln_class=vuln_class,
            status=response_status,
            body=response_body[:3000],
            headers=json.dumps(dict(response_headers))[:1500],
        )

        data = self.router.chat_json(system, user, task="analysis")
        if isinstance(data, dict):
            return data
        return None
