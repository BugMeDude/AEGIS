"""The orchestration pipeline shared by the CLI, the GUI and autopilot.

    parse -> (AI plan | user plan) -> safety gate -> stress engine ->
    security analysis -> AI insight -> RunReport

This is the single source of truth for "what AEGIS does"; both front-ends are
thin shells over :class:`Orchestrator`.
"""

from __future__ import annotations

from typing import Callable
from urllib.parse import urlparse

from .ai import AIBrain
from .config import AegisConfig
from .engine import run_engine
from .models import RequestSpec, RunReport, TestPlan, now_iso
from .offense import active_scan
from .parsers import parse_any
from .safety import enforce


class Orchestrator:
    def __init__(self, config: AegisConfig | None = None) -> None:
        self.config = config or AegisConfig.load()
        self.brain = AIBrain(self.config.ollama)

    # ------------------------------------------------------------------ #
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

    # ------------------------------------------------------------------ #
    def run(
        self,
        specs: list[RequestSpec],
        *,
        plan: TestPlan | None = None,
        goal: str = "",
        ai_plan: bool = False,
        offensive: bool = False,
        on_event: Callable[[str, dict], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> RunReport:
        """Execute the full pipeline and return a populated :class:`RunReport`.

        ``offensive=True`` adds an active (offensive) DAST scan phase after the
        passive analysis — for education / authorised research only.
        """
        emit = on_event or (lambda _e, _d: None)

        if plan is None:
            if ai_plan:
                emit("phase", {"name": "planning"})
                plan = self.brain.plan(specs, goal, self.config.safety)
            else:
                plan = TestPlan(timeout_seconds=self.config.default_timeout,
                                source="user")

        emit("plan", {"plan": plan.to_dict()})

        # Responsible-use gate (raises SafetyError on refusal).
        notes = enforce(specs, plan, self.config.safety)
        if notes:
            emit("safety", {"notes": notes})

        report = RunReport(started_at=now_iso(), plan=plan)
        report.targets = sorted({urlparse(s.url).netloc for s in specs if s.url})

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

        emit("phase", {"name": "security"})
        report.vulnerabilities = self.brain.analyze_security(report.endpoints)

        if offensive:
            emit("phase", {"name": "offensive-scan"})
            try:
                active = active_scan(specs, timeout=plan.timeout_seconds)
            except Exception as exc:  # never let a probe failure abort the run
                emit("safety", {"notes": [f"active scan skipped: {exc}"]})
                active = []
            report.vulnerabilities = self.brain._dedupe(
                report.vulnerabilities + active
            )

        emit("phase", {"name": "insight"})
        report.insight = self.brain.build_insight(report)

        emit("done", {"report": report.to_dict()})
        return report

    # ------------------------------------------------------------------ #
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
        on_event: Callable[[str, dict], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> RunReport:
        """Fully automated: parse input, let the AI design the plan, then run."""
        specs = self.parse(
            raw, input_type=input_type, base_url=base_url,
            token=token, variables=variables or {},
        )
        if not specs:
            raise ValueError("Autopilot could not extract any request from input.")
        return self.run(
            specs, goal=goal, ai_plan=True, offensive=offensive,
            on_event=on_event, should_stop=should_stop,
        )

    # ------------------------------------------------------------------ #
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
