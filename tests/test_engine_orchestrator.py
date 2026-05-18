"""Live engine + orchestrator tests against a real local HTTP server.

These deliberately use no mocks for the transport: they exercise asyncio +
httpx end to end. AI runs in heuristic mode (Ollama disabled) so the suite is
deterministic and offline-safe.
"""

from aegis.config import AegisConfig
from aegis.engine import run_engine
from aegis.models import RequestSpec, TestPlan
from aegis.orchestrator import Orchestrator


def _cfg() -> AegisConfig:
    c = AegisConfig()
    c.ollama.enabled = False          # force heuristic engine -> deterministic
    c.safety.authorized = True        # localhost anyway, but explicit
    return c


def test_engine_count_mode(http_server):
    spec = RequestSpec(url=f"{http_server}/ping").normalised()
    plan = TestPlan(concurrency=8, total_requests=40, timeout_seconds=10)
    metrics, stopped, wall = run_engine([spec], plan)
    assert metrics.total == 40
    assert metrics.successes == 40 and metrics.failures == 0
    assert not stopped and wall > 0
    ep = metrics.finalize()[0]
    assert ep.success_rate == 100.0 and ep.avg_ms > 0


def test_engine_duration_mode(http_server):
    spec = RequestSpec(url=f"{http_server}/d").normalised()
    plan = TestPlan(concurrency=5, duration_seconds=1, timeout_seconds=5)
    metrics, stopped, wall = run_engine([spec], plan)
    assert metrics.total > 0
    assert 0.8 <= wall <= 4.0


def test_engine_cooperative_stop(http_server):
    spec = RequestSpec(url=f"{http_server}/s").normalised()
    plan = TestPlan(concurrency=4, total_requests=100000, timeout_seconds=5)
    state = {"n": 0}

    def stop():
        state["n"] += 1
        return state["n"] > 5

    metrics, stopped, _ = run_engine([spec], plan, should_stop=stop)
    assert stopped and metrics.total < 100000


def test_engine_handles_connection_error():
    spec = RequestSpec(url="http://127.0.0.1:1/none").normalised()
    plan = TestPlan(concurrency=2, total_requests=4, timeout_seconds=2)
    metrics, _, _ = run_engine([spec], plan)
    assert metrics.failures == 4 and metrics.successes == 0
    ep = metrics.finalize()[0]
    assert ep.errors  # an error class was recorded


def test_orchestrator_full_pipeline(http_server):
    orch = Orchestrator(_cfg())
    specs = orch.parse(f"curl {http_server}/api")
    plan = TestPlan(concurrency=6, total_requests=24, source="user")
    rep = orch.run(specs, plan=plan)
    assert rep.total_attempts == 24
    assert rep.success_rate == 100.0
    assert rep.insight.grade in {"A", "B", "C", "D", "F"}
    assert rep.insight.engine == "heuristic"
    # Local server omits security headers -> heuristic findings expected.
    assert any(v.type for v in rep.vulnerabilities)
    d = rep.to_dict()
    assert d["summary"]["total_attempts"] == 24


def test_orchestrator_autopilot(http_server):
    orch = Orchestrator(_cfg())
    rep = orch.autopilot(f"{http_server}/auto", goal="baseline")
    assert rep.total_attempts > 0
    assert rep.plan.source in {"ai", "default"}


def test_orchestrator_nlp_heuristic(http_server):
    orch = Orchestrator(_cfg())
    rep = orch.from_nlp(
        f"send 12 requests to {http_server}/nlp with 4 concurrent")
    assert rep.total_attempts == 12
    assert rep.plan.concurrency == 4
