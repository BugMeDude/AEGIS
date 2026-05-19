"""Core domain models for AEGIS v3.

Everything that flows between the parsers, the engine, the AI brain and the
reporters is one of these dataclasses. They are deliberately plain and
JSON-serialisable via :func:`to_dict` so reports and the AI layer share one
shape. v3 adds red-team / adversary-simulation models: attack chains, MITRE
ATT&CK mapping, session state, pivot targets, and budget controls.
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
    http2: bool = False                # negotiate HTTP/2 (ALPN h2) if offered
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
            "version": "2.1.0",
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


# ====================================================================
# v3 Enhanced Models — Red Team / Advanced Adversary
# ====================================================================

class AuthLevel(str, Enum):
    """Progressive authorization tiers for the safety gate."""
    EDUCATION = "education"
    RESEARCH = "research"
    EXPERT = "expert"

    @property
    def rank(self) -> int:
        return {"education": 0, "research": 1, "expert": 2}[self.value]


MITRE_ATTACK_MAP: dict[str, str] = {
    "SQL Injection (error-based)": "T1190",
    "SQL Injection (time-based blind)": "T1190",
    "Reflected XSS": "T1059.007",
    "Path Traversal / LFI": "T1005",
    "OS Command Injection": "T1059.003",
    "Server-Side Template Injection": "T1059.007",
    "Open Redirect": "T1204.001",
    "Access-Control Bypass via Headers": "T1190",
    "SSRF": "T1190",
    "XXE": "T1059.007",
    "Insecure Deserialization": "T1059.007",
    "HTTP Request Smuggling": "T1190",
    "Race Condition": "T1498",
    "GraphQL Injection": "T1190",
    "NoSQL Injection": "T1190",
    "JWT Attack": "T1528",
    "WebSocket Hijacking": "T1190",
    "Mass Assignment": "T1190",
    "Missing HSTS": "T1071.001",
    "Missing Content-Security-Policy": "T1071.001",
    "Stack Trace Disclosure": "T1040",
    "SQL Error Leakage": "T1040",
    "Potential Sensitive Data Exposure": "T1040",
    "No Rate-Limiting Signalled": "T1498",
    "Permissive CORS": "T1071.001",
    "Server Version Disclosure": "T1040",
    "Technology Disclosure": "T1040",
    "Cleartext Transport": "T1040",
    "Missing X-Content-Type-Options": "T1071.001",
    "Missing X-Frame-Options": "T1071.001",
}


@dataclass(slots=True)
class VulnerabilityV3:
    """Enhanced vulnerability with MITRE ATT&CK mapping."""
    type: str
    description: str
    severity: Severity
    endpoint: str = ""
    remediation: str = ""
    evidence: str = ""
    source: str = "heuristic"
    mitre_id: str = ""
    cve: str = ""
    cwe: int = 0
    confidence: float = 1.0
    chain_step: int = 0
    tags: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.mitre_id:
            self.mitre_id = MITRE_ATTACK_MAP.get(self.type, "")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass(slots=True)
class AttackBudget:
    """Budget controls for a campaign — limits what the AI can do."""
    max_injection_points: int = 50
    max_data_extracted_kb: int = 100
    max_concurrent_targets: int = 5
    max_attack_seconds: int = 3600
    max_chains: int = 3
    allow_exfiltration: bool = False
    allow_pivot: bool = False
    allow_persistence: bool = False
    usage: dict[str, int] = field(default_factory=lambda: {
        "injection_points": 0, "data_kb": 0, "chains": 0, "targets": 0
    })

    def remaining(self, key: str) -> int:
        limits = {
            "injection_points": self.max_injection_points,
            "data_kb": self.max_data_extracted_kb,
            "chains": self.max_chains,
            "targets": self.max_concurrent_targets,
        }
        used = self.usage.get(key, 0)
        return max(0, limits.get(key, 0) - used)

    def consume(self, key: str, amount: int = 1) -> bool:
        if self.remaining(key) >= amount:
            self.usage[key] = self.usage.get(key, 0) + amount
            return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ProxyConfig:
    """Proxy chain configuration for layered anonymity."""
    http: str = ""
    https: str = ""
    socks5: str = ""
    socks5h: str = ""
    tor: bool = False
    chain: list[str] = field(default_factory=list)
    rotate_per_request: bool = False

    def effective_proxy(self) -> str | None:
        if self.tor:
            return "socks5h://127.0.0.1:9050"
        if self.socks5h:
            return f"socks5h://{self.socks5h}"
        if self.socks5:
            return f"socks5://{self.socks5}"
        if self.https:
            return self.https
        if self.http:
            return self.http
        if self.chain:
            return self.chain[0]
        return None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TLSFingerprint:
    """Controls for TLS stack fingerprint randomization."""
    ja3: str = ""
    ja3s: str = ""
    randomize: bool = False
    impersonate: str = ""  # "chrome", "firefox", "safari", "ios", "android"


@dataclass(slots=True)
class AuthProfile:
    """Persistent authentication profile for a campaign."""
    type: str = "bearer"  # bearer | basic | digest | oauth2 | ntlm | apikey | custom
    token: str = ""
    username: str = ""
    password: str = ""
    client_id: str = ""
    client_secret: str = ""
    token_url: str = ""
    scope: str = ""
    refresh_token: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    auto_refresh: bool = False

    @property
    def is_configured(self) -> bool:
        return bool(self.token or self.username or self.client_id)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if d["token"]:
            d["token"] = d["token"][:8] + "..." if len(d["token"]) > 11 else d["token"]
        if d["password"]:
            d["password"] = "***"
        if d["client_secret"]:
            d["client_secret"] = "***"
        return d


@dataclass(slots=True)
class PivotTarget:
    """A lateral-movement target discovered during a campaign."""
    host: str
    port: int = 0
    service: str = ""  # http | ssh | rdp | mysql | etc.
    via_host: str = ""
    via_port: int = 0
    via_method: str = "ssh"  # ssh | socks | http_proxy
    credentials: str = ""
    discovered_by: str = ""
    accessible: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CampaignPhase(str, Enum):
    """Phases of an autonomous attack campaign."""
    INIT = "init"
    RECON = "recon"
    FINGERPRINT = "fingerprint"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    ESCALATE = "escalate"
    PIVOT = "pivot"
    EXFIL = "exfil"
    REPORT = "report"
    COMPLETE = "complete"
    FAILED = "failed"
    ABORTED = "aborted"


@dataclass(slots=True)
class Campaign:
    """A full autonomous attack campaign with state tracking."""
    id: str
    name: str = ""
    target: str = ""
    goal: str = ""
    phase: CampaignPhase = CampaignPhase.INIT
    auth: AuthProfile = field(default_factory=AuthProfile)
    budget: AttackBudget = field(default_factory=AttackBudget)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    tls: TLSFingerprint = field(default_factory=TLSFingerprint)
    pivot_targets: list[PivotTarget] = field(default_factory=list)
    findings: list[VulnerabilityV3] = field(default_factory=list)
    sessions: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    operator: str = ""
    auth_level: AuthLevel = AuthLevel.EDUCATION
    tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "target": self.target,
            "goal": self.goal,
            "phase": self.phase.value,
            "auth_level": self.auth_level.value,
            "pivot_targets": [p.to_dict() for p in self.pivot_targets],
            "findings": [f.to_dict() for f in self.findings],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "operator": self.operator,
        }


@dataclass(slots=True)
class SessionState:
    """Serializable session state for save/restore."""
    campaign: Campaign | None = None
    cookies: dict[str, dict[str, str]] = field(default_factory=dict)
    headers: dict[str, dict[str, str]] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)
    discovered_endpoints: list[str] = field(default_factory=list)
    discovered_params: list[str] = field(default_factory=list)
    active_connections: int = 0
    total_requests: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Update RunReport to include v3 fields
# We add optional v3 fields via a wrapper
@dataclass(slots=True)
class RunReportV3:
    """Extended v3 run report with campaign data."""
    report: RunReport = field(default_factory=lambda: RunReport(started_at=now_iso()))
    campaign: Campaign | None = None
    attack_chain: list[dict] = field(default_factory=list)
    mitre_mapping: dict[str, list[VulnerabilityV3]] = field(default_factory=dict)
    executive_narrative: str = ""
    session_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        base = self.report.to_dict()
        base["version"] = "3.0.0"
        if self.campaign:
            base["campaign"] = self.campaign.to_dict()
        if self.attack_chain:
            base["attack_chain"] = self.attack_chain
        if self.mitre_mapping:
            base["mitre_mapping"] = {
                k: [v.to_dict() for v in vs]
                for k, vs in self.mitre_mapping.items()
            }
        if self.executive_narrative:
            base["executive_narrative"] = self.executive_narrative
        return base
