"""Agentic Attack Strategist — autonomous multi-phase attack planner.

The AI acts as an autonomous red-team operator:
  1. Analyzes target from recon data
  2. Develops attack plan (recon → fingerprint → enumerate → exploit → pivot)
  3. Executes steps in order, adapting based on responses
  4. Maintains state machine for decision making
  5. Generates full report with MITRE ATT&CK mapping
"""

from __future__ import annotations

import json
import time
from typing import Any

from ..config import AIProviderConfig, SafetyPolicy
from ..models import (
    AttackBudget, AuthLevel, AuthProfile, Campaign, CampaignPhase,
    ProxyConfig, RequestSpec, TLSFingerprint, TestPlan,
    VulnerabilityV3, Severity, now_iso,
)
from .knowledge import KnowledgeBase
from .router import ModelRouter
from . import prompts


def _coerce_auth_level(value: str | AuthLevel) -> AuthLevel:
    """Map a string to AuthLevel, defaulting to EDUCATION on anything bad."""
    if isinstance(value, AuthLevel):
        return value
    try:
        return AuthLevel(str(value).lower())
    except ValueError:
        return AuthLevel.EDUCATION


class AttackStrategist:
    """Autonomous attack strategist using agentic AI planning."""

    def __init__(self, cfg: AIProviderConfig) -> None:
        self.router = ModelRouter(cfg)
        self.cfg = cfg
        # RAG: retrieve relevant technique notes to ground the planner.
        self.knowledge = KnowledgeBase()

    def plan_campaign(
        self,
        target: str,
        goal: str = "",
        auth: AuthProfile | None = None,
        proxy: ProxyConfig | None = None,
        tls: TLSFingerprint | None = None,
        budget: AttackBudget | None = None,
        auth_level: str = "education",
    ) -> Campaign:
        """Design a complete attack campaign from high-level goal."""
        campaign = Campaign(
            id=f"camp-{int(time.time())}",
            name=f"Campaign against {target}",
            target=target,
            goal=goal or "Comprehensive security assessment",
            auth=auth or AuthProfile(),
            budget=budget or AttackBudget(),
            proxy=proxy or ProxyConfig(),
            tls=tls or TLSFingerprint(),
            started_at=now_iso(),
            auth_level=_coerce_auth_level(auth_level),
        )

        if not self.cfg.agentic_enabled:
            campaign.phase = CampaignPhase.RECON
            return campaign

        # RAG grounding: pull relevant technique notes for the goal/target.
        hits = self.knowledge.search(f"{goal} {target}", n_results=5)
        kb_context = "\n".join(f"- {h['text']}" for h in hits)

        system = prompts.STRATEGIST_SYSTEM
        user = prompts.STRATEGY_USER.format(
            target=target,
            goal=goal or "security assessment",
            auth_level=auth_level,
            budget=json.dumps(budget.to_dict() if budget else {}),
        )
        if kb_context:
            user += ("\n\nRelevant techniques from the knowledge base "
                     "(use only those in scope for the auth level):\n"
                     + kb_context)

        data = self.router.chat_json(system, user, task="strategy")
        if isinstance(data, dict):
            campaign.name = data.get("campaign_name", campaign.name)
            phase_str = data.get("initial_phase", "recon")
            try:
                campaign.phase = CampaignPhase(phase_str)
            except ValueError:
                campaign.phase = CampaignPhase.RECON

        return campaign

    def next_phase(
        self,
        campaign: Campaign,
        recon_results: dict | None = None,
        scan_results: list[VulnerabilityV3] | None = None,
    ) -> CampaignPhase:
        """AI decides the next phase based on current state and results."""
        if not self.cfg.agentic_enabled:
            phases = list(CampaignPhase)
            idx = phases.index(campaign.phase)
            if idx < len(phases) - 1:
                return phases[idx + 1]
            return CampaignPhase.COMPLETE

        current = campaign.phase.value
        findings_summary = []
        if scan_results:
            for v in scan_results[:5]:
                findings_summary.append(f"{v.type} ({v.severity.value})")

        system = "You are AEGIS-Strategist. Decide the next attack phase based on results."
        user = (
            f"Current phase: {current}\n"
            f"Target: {campaign.target}\n"
            f"Goal: {campaign.goal}\n"
            f"Findings so far: {', '.join(findings_summary) or 'none'}\n"
            f"Auth level: {campaign.auth_level.value}\n\n"
            "Return JSON: {\"next_phase\": \"recon|fingerprint|enumerate|exploit|escalate|pivot|exfil|report|complete\", \"rationale\": \"<reason>\"}"
        )

        data = self.router.chat_json(system, user, task="strategy")
        if isinstance(data, dict) and data.get("next_phase"):
            try:
                return CampaignPhase(data["next_phase"])
            except ValueError:
                pass
        return CampaignPhase.COMPLETE

    def select_attack_vector(
        self,
        target: str,
        tech_stack: dict[str, str] | None = None,
        phase: CampaignPhase = CampaignPhase.EXPLOIT,
    ) -> list[dict]:
        """AI selects the best attack vectors based on target technology."""
        tech_info = ""
        if tech_stack:
            tech_info = "\n".join(f"  {k}: {v}" for k, v in tech_stack.items())

        system = prompts.ATTACK_VECTOR_SYSTEM
        user = prompts.ATTACK_VECTOR_USER.format(
            target=target,
            phase=phase.value,
            tech_stack=tech_info or "unknown",
        )

        data = self.router.chat_json(system, user, task="strategy")
        if isinstance(data, dict) and data.get("vectors"):
            return data["vectors"]
        return []
