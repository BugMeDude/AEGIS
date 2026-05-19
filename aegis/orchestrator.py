"""The orchestration pipeline v3 — shared by CLI, GUI, REPL, and autopilot.

v3 enhancements:
  - Multi-provider AI (Ollama, OpenAI, Anthropic)
  - Agentic attack planning (AttackStrategist)
  - AI-driven payload generation (PayloadEngine)
  - Campaign state management
  - Reconnaissance integration (fingerprinting, discovery, schema)
  - Attack chain execution
  - MITRE ATT&CK mapping
  - Enhanced reporting narrative
"""

from __future__ import annotations

import json
from typing import Callable
from urllib.parse import urlparse

from .ai import AIBrain, AttackStrategist, PayloadEngine
from .config import AegisConfig
from .engine import run_engine
from .models import (
    Campaign, CampaignPhase, RequestSpec, RunReport, RunReportV3,
    TestPlan, VulnerabilityV3, Severity, now_iso,
)
from .offense.offense import OffensiveScanner, active_scan_v3
from .parsers import parse_any
from .recon import Fingerprinter, DiscoveryEngine, SchemaExtractor
from .reporting.attack_mapper import ATTACKMapper
from .reporting.narrative import NarrativeGenerator
from .safety import enforce


class Orchestrator:
    """Enhanced v3 orchestrator with full red-team capabilities."""

    def __init__(self, config: AegisConfig | None = None) -> None:
        self.config = config or AegisConfig.load()
        self.brain = AIBrain(ai_cfg=self.config.ai)
        self.strategist = self.brain.strategist
        self.payload_engine = self.brain.payload_engine
        self.recon_fp = Fingerprinter()
        self.recon_disc = DiscoveryEngine()
        self.recon_schema = SchemaExtractor()
        self.narrative = NarrativeGenerator(self.config.ai)
        self._current_campaign: Campaign | None = None

    # ================================================================== #
    # CAMPAIGN MANAGEMENT
    # ================================================================== #
    @property
    def current_campaign(self) -> Campaign | None:
        return self._current_campaign

    def start_campaign(
        self,
        target: str,
        goal: str = "",
        auth_level: str = "",
    ) -> Campaign:
        """Start a new autonomous attack campaign."""
        campaign = self.strategist.plan_campaign(
            target=target,
            goal=goal,
            auth_level=auth_level or self.config.safety.auth_level,
        )
        self._current_campaign = campaign
        return campaign

    # ================================================================== #
    # RECONNAISSANCE
    # ================================================================== #
    async def run_recon(self, target: str) -> dict:
        """Run full reconnaissance against a target.

        Returns combined results from fingerprinting, endpoint discovery,
        schema extraction, and parameter fuzzing.
        """
        import httpx

        result = {
            "fingerprint": {},
            "endpoints": [],
            "schema": None,
            "params": [],
        }

        # Fingerprint
        try:
            r = httpx.get(target, timeout=10.0, verify=False)
            result["fingerprint"] = self.recon_fp.fingerprint(
                r.status_code, dict(r.headers), r.text
            )
        except Exception as e:
            result["fingerprint"] = {"error": str(e)}

        # Discover endpoints
        try:
            import asyncio
            result["endpoints"] = await self.recon_disc.discover_endpoints(target)
        except Exception:
            pass

        # Schema
        try:
            import asyncio
            schema = None
            oa = await self.recon_schema.extract_from_openapi(target)
            if oa:
                schema = {"type": "openapi", "endpoints": len(self.recon_schema.endpoints)}
            else:
                gql = await self.recon_schema.extract_from_graphql(target)
                if gql:
                    schema = {"type": "graphql"}
            result["schema"] = schema
        except Exception:
            pass

        # Params
        try:
            import asyncio
            result["params"] = await self.recon_disc.discover_params(target)
        except Exception:
            pass

        return result

    # ================================================================== #
    # PARSING
    # ================================================================== #
    def parse(
        self,
        raw: str,
        *,
        input_type: str = "auto",
        base_url: str = "",
        token: str = "",
        variables: dict[str, str] | None = None,
    ) -> list[RequestSpec]:
        return parse_any(
            raw, input_type=input_type, base_url=base_url,
            token=token, variables=variables or {},
        )

    # ================================================================== #
    # CORE RUN PIPELINE
    # ================================================================== #
    def run(
        self,
        specs: list[RequestSpec],
        *,
        plan: TestPlan | None = None,
        goal: str = "",
        ai_plan: bool = False,
        offensive: bool = False,
        enable_ai_payloads: bool = False,
        enable_chains: bool = False,
        chain_names: list[str] | None = None,
        campaign: Campaign | None = None,
        on_event: Callable[[str, dict], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> RunReport:
        """Execute the full pipeline with v3 enhancements.

        Args:
            specs: Parsed request specifications
            plan: Test plan (or None for AI plan)
            goal: Testing goal
            ai_plan: Use AI to design the plan
            offensive: Enable active vulnerability scanning
            enable_ai_payloads: Use AI-generated payloads in scanning
            enable_chains: Execute attack chains
            chain_names: Specific attack chains to run
            campaign: Current campaign context
            on_event: Progress callback
            should_stop: Stop signal callback

        Returns:
            Populated RunReport
        """
        emit = on_event or (lambda _e, _d: None)

        # ── Phase: Planning ──
        if plan is None:
            if ai_plan:
                emit("phase", {"name": "planning"})
                plan = self.brain.plan(specs, goal, self.config.safety)
            else:
                plan = TestPlan(timeout_seconds=self.config.default_timeout,
                                source="user")

        emit("plan", {"plan": plan.to_dict()})

        # ── Safety gate ──
        notes = enforce(specs, plan, self.config.safety)
        if notes:
            emit("safety", {"notes": notes})

        report = RunReport(started_at=now_iso(), plan=plan)
        report.targets = sorted({urlparse(s.url).netloc for s in specs if s.url})

        # ── Phase: Load / Stress ──
        emit("phase", {"name": "stress"})
        metrics, stopped, wall = run_engine(
            specs, plan,
            on_progress=lambda s: emit("progress", s),
            should_stop=should_stop,
        )

        report.endpoints = metrics.finalize()
        report.total_attempts = metrics.total
        report.total_successes = metrics.successes
        report.total_failures = metrics.failures
        report.wall_seconds = wall
        report.throughput_rps = metrics.total / wall if wall > 0 else 0.0
        report.stopped_early = stopped
        report.finished_at = now_iso()

        # ── Phase: Passive Security Analysis ──
        emit("phase", {"name": "security"})
        report.vulnerabilities = self.brain.analyze_security(report.endpoints)

        # ── Phase: Active Offensive Scan ──
        if offensive:
            emit("phase", {"name": "offensive-scan"})
            try:
                import asyncio
                vulns_v3 = asyncio.run(active_scan_v3(
                    specs,
                    timeout=plan.timeout_seconds,
                    enable_ai=enable_ai_payloads,
                    ai_payload_engine=self.payload_engine if enable_ai_payloads else None,
                    on_event=emit,
                ))
                report.vulnerabilities = self.brain._dedupe(
                    report.vulnerabilities + [
                        Vulnerability(type=v.type, description=v.description,
                                      severity=v.severity, endpoint=v.endpoint,
                                      remediation=v.remediation, evidence=v.evidence,
                                      source=v.source)
                        for v in vulns_v3
                    ]
                )
            except Exception as exc:
                emit("safety", {"notes": [f"active scan skipped: {exc}"]})

        # ── Phase: Attack Chains ──
        if enable_chains and chain_names:
            emit("phase", {"name": "attack-chains"})
            from .offense.chains import AttackChain
            for chain_name in chain_names:
                try:
                    chain = AttackChain.by_name(chain_name)
                    import asyncio
                    chain_result = asyncio.run(chain.execute(specs[0]))
                    if chain_result.findings:
                        report.vulnerabilities.extend([
                            Vulnerability(type=f.type, description=f.description,
                                          severity=f.severity, endpoint=f.endpoint,
                                          remediation=f.remediation, evidence=f.evidence,
                                          source=f"chain:{chain_name}")
                            for f in chain_result.findings
                        ])
                        emit("safety", {"notes": [f"Chain {chain_name}: "
                                                   f"{len(chain_result.findings)} findings"]})
                except Exception as exc:
                    emit("safety", {"notes": [f"chain {chain_name} failed: {exc}"]})

        # ── Phase: AI Insight ──
        emit("phase", {"name": "insight"})
        report.insight = self.brain.build_insight(report)

        emit("done", {"report": report.to_dict()})
        return report

    # ================================================================== #
    # AUTOPILOT v2
    # ================================================================== #
    def autopilot(
        self,
        raw: str,
        *,
        input_type: str = "auto",
        goal: str = "",
        base_url: str = "",
        token: str = "",
        variables: dict[str, str] | None = None,
        offensive: bool = False,
        enable_ai_payloads: bool = False,
        on_event: Callable[[str, dict], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> RunReport:
        """Fully automated: parse input, AI designs the plan, then run."""
        specs = self.parse(
            raw, input_type=input_type, base_url=base_url,
            token=token, variables=variables or {},
        )
        if not specs:
            raise ValueError("Autopilot could not extract any request from input.")
        return self.run(
            specs, goal=goal, ai_plan=True, offensive=offensive,
            enable_ai_payloads=enable_ai_payloads,
            on_event=on_event, should_stop=should_stop,
        )

    # ================================================================== #
    # NLP
    # ================================================================== #
    def from_nlp(
        self,
        query: str,
        *,
        on_event: Callable[[str, dict], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> RunReport:
        """Natural-language entry point: 'stress https://x for 30s, 50 concurrent'."""
        spec, plan = self.brain.nlp(query)
        if spec is None:
            raise ValueError("Could not derive a target URL from the request.")
        plan.timeout_seconds = self.config.default_timeout
        return self.run([spec], plan=plan, on_event=on_event,
                        should_stop=should_stop)
