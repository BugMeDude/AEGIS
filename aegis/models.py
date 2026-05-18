"""Core domain models for AEGIS.

Everything that flows between the parsers, the engine, the AI brain and the
reporters is one of these dataclasses. They are deliberately plain and
JSON-serialisable via :func:`to_dict` so reports and the AI layer share one
shape.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Ordered vulnerability severity. ``rank`` enables sorting/threshold logic."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def rank(self) -> int:
        return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}[self.value]


@dataclass(slots=True)
class RequestSpec:
    """A single HTTP request to be exercised by the engine."""

    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    name: str = ""

    def normalised(self) -> "RequestSpec":
        self.method = (self.method or "GET").upper()
        if not self.name:
            self.name = f"{self.method} {self.url}"
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TestPlan:
    """Execution parameters. May be authored by a human or proposed by the AI."""

    concurrency: int = 10
    duration_seconds: int = 0          # >0 => time-bounded (open) model
    total_requests: int = 100          # used when duration_seconds == 0
    target_rps: float = 0.0            # 0 => unthrottled
    ramp_up_seconds: int = 0
    timeout_seconds: float = 15.0
    rationale: str = "Default plan."
    source: str = "default"            # default | user | ai | nlp

    def mode(self) -> str:
        return "duration" if self.duration_seconds > 0 else "count"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["mode"] = self.mode()
        return d


@dataclass(slots=True)
class AttemptResult:
    """The outcome of one executed request."""

    url: str
    method: str
    status_code: int
    latency_ms: float
    ok: bool
    error: str | None = None
    response_size: int = 0
    started_at: float = 0.0
    # Captured only for the first attempt per endpoint (sampling) to bound memory.
    sample_body: str | None = None
    sample_headers: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("sample_body", None)
        d.pop("sample_headers", None)
        return d


@dataclass(slots=True)
class EndpointStats:
    """Aggregated metrics for one (method, url) pair."""

    url: str
    method: str
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    latencies: list[float] = field(default_factory=list)
    status_codes: dict[int, int] = field(default_factory=dict)
    errors: dict[str, int] = field(default_factory=dict)
    sample_status: int = 0
    sample_body: str = ""
    sample_headers: dict[str, str] = field(default_factory=dict)
    sample_request_body: str | None = None

    def _pct(self, p: float) -> float:
        if not self.latencies:
            return 0.0
        data = sorted(self.latencies)
        if len(data) == 1:
            return data[0]
        k = (len(data) - 1) * (p / 100.0)
        f, c = int(k), min(int(k) + 1, len(data) - 1)
        return data[f] + (data[c] - data[f]) * (k - f)

    @property
    def avg_ms(self) -> float:
        return statistics.fmean(self.latencies) if self.latencies else 0.0

    @property
    def min_ms(self) -> float:
        return min(self.latencies) if self.latencies else 0.0

    @property
    def max_ms(self) -> float:
        return max(self.latencies) if self.latencies else 0.0

    @property
    def stdev_ms(self) -> float:
        return statistics.pstdev(self.latencies) if len(self.latencies) > 1 else 0.0

    @property
    def p50(self) -> float:
        return self._pct(50)

    @property
    def p90(self) -> float:
        return self._pct(90)

    @property
    def p95(self) -> float:
        return self._pct(95)

    @property
    def p99(self) -> float:
        return self._pct(99)

    @property
    def success_rate(self) -> float:
        return (self.successes / self.attempts * 100.0) if self.attempts else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "attempts": self.attempts,
            "successes": self.successes,
            "failures": self.failures,
            "success_rate": round(self.success_rate, 2),
            "avg_ms": round(self.avg_ms, 2),
            "min_ms": round(self.min_ms, 2),
            "max_ms": round(self.max_ms, 2),
            "stdev_ms": round(self.stdev_ms, 2),
            "p50_ms": round(self.p50, 2),
            "p90_ms": round(self.p90, 2),
            "p95_ms": round(self.p95, 2),
            "p99_ms": round(self.p99, 2),
            "status_codes": dict(sorted(self.status_codes.items())),
            "errors": self.errors,
            "sample_status": self.sample_status,
        }


@dataclass(slots=True)
class Vulnerability:
    type: str
    description: str
    severity: Severity
    endpoint: str = ""
    remediation: str = ""
    evidence: str = ""
    source: str = "heuristic"  # heuristic | ai

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass(slots=True)
class AIInsight:
    """A bundle of LLM (or fallback) reasoning attached to a run."""

    summary: str = ""
    benchmark: str = ""
    optimization: str = ""
    prediction: str = ""
    assertions: list[str] = field(default_factory=list)
    grade: str = ""
    engine: str = "heuristic"  # heuristic | ollama:<model>

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RunReport:
    """The single artefact produced by a complete AEGIS run."""

    started_at: str
    finished_at: str = ""
    wall_seconds: float = 0.0
    plan: TestPlan = field(default_factory=TestPlan)
    total_attempts: int = 0
    total_successes: int = 0
    total_failures: int = 0
    throughput_rps: float = 0.0
    endpoints: list[EndpointStats] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    insight: AIInsight = field(default_factory=AIInsight)
    stopped_early: bool = False
    targets: list[str] = field(default_factory=list)

    @property
    def overall_avg_ms(self) -> float:
        lat: list[float] = []
        for e in self.endpoints:
            lat.extend(e.latencies)
        return statistics.fmean(lat) if lat else 0.0

    @property
    def success_rate(self) -> float:
        return (self.total_successes / self.total_attempts * 100.0) if self.total_attempts else 0.0

    @property
    def highest_severity(self) -> Severity:
        if not self.vulnerabilities:
            return Severity.INFO
        return max((v.severity for v in self.vulnerabilities), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, Any]:
        return {
            "app": "AEGIS",
            "version": "2.0.0",
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "wall_seconds": round(self.wall_seconds, 3),
            "targets": self.targets,
            "plan": self.plan.to_dict(),
            "summary": {
                "total_attempts": self.total_attempts,
                "total_successes": self.total_successes,
                "total_failures": self.total_failures,
                "success_rate": round(self.success_rate, 2),
                "overall_avg_ms": round(self.overall_avg_ms, 2),
                "throughput_rps": round(self.throughput_rps, 2),
                "stopped_early": self.stopped_early,
                "highest_severity": self.highest_severity.value,
            },
            "endpoints": [e.to_dict() for e in self.endpoints],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "insight": self.insight.to_dict(),
        }


def now_iso() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")
