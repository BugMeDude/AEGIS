"""Tests for Phase 4.2 (protocols) and Phase 6 (bounded validation/scope).

Deterministic & offline: a local HTTP server + an unbound port. No live
internet, no real exploitation (the validator is gated off here).
"""

from __future__ import annotations

import asyncio

from aegis.config import AegisConfig
from aegis.engine import run_engine
from aegis.models import RequestSpec, TestPlan
from aegis.orchestrator import Orchestrator
from aegis.pivot import ImpactValidator, ScopedAssessment
from aegis.transport.protocols import (probe_grpc, http2_report,
                                       websocket_report)


# ---- Phase 4.2: protocols ------------------------------------------------- #
def test_http2_probe_local(http_server):
    r = http2_report(f"{http_server}/x", timeout=5.0)
    # python http.server is HTTP/1.1 -> probe must say so, no crash.
    assert r["status"] == 200
    assert r["negotiated"].startswith("HTTP/1")   # 1.0/1.1, not HTTP/2
    assert r["http2_supported"] is False
    assert r["error"] is None


def test_http2_probe_dead_host_softfails():
    r = http2_report("http://127.0.0.1:1/none", timeout=2.0)
    assert r["error"] and r["http2_supported"] is False


def test_websocket_softfail_on_non_ws(http_server):
    ws = websocket_report(http_server.replace("http://", "ws://"), timeout=4.0)
    # Connecting WS to a plain HTTP server fails gracefully (no exception).
    assert ws["available"] is True
    assert ws["connected"] is False and ws["error"]
    # Friendly, no raw traceback-style class dump.
    assert "Traceback" not in ws["error"]


def test_websocket_friendly_messages():
    from aegis.transport.protocols.websocket import _diagnose, _friendly
    redir = type("InvalidURI", (Exception,), {})(
        "https://www.example.com/ isn't a valid URI: scheme isn't ws or wss")
    assert _friendly(redir) == "no WebSocket endpoint here (server HTTP-redirected)"
    assert "https://www.example.com/" in _diagnose(redir)
    dns = type("gaierror", (Exception,), {})("[Errno -2] Name or service not known")
    assert _friendly(dns) == "host did not resolve (DNS)"
    ref = type("ConnectionRefusedError", (Exception,), {})("Connect call failed")
    assert _friendly(ref) == "connection refused (no listener)"


def test_grpc_probe_softfails(http_server):
    g = probe_grpc(http_server, timeout=4.0)
    assert "grpcio" in g and g["method"] in ("reflection", "http2-probe")
    # Plain JSON server is not gRPC.
    assert g.get("looks_like_grpc") in (False, None)


def test_engine_http2_flag_plumbs(http_server):
    spec = RequestSpec(url=f"{http_server}/h2").normalised()
    plan = TestPlan(concurrency=2, total_requests=4, timeout_seconds=5,
                    http2=True)
    metrics, stopped, _ = run_engine([spec], plan)
    # http.server downgrades to HTTP/1.1; requests still succeed.
    assert metrics.total == 4 and metrics.successes == 4


def test_orchestrator_test_protocols(http_server):
    orch = Orchestrator(_cfg())
    r = orch.test_protocols(http_server, timeout=4.0)
    assert set(r) == {"target", "http2", "websocket", "grpc"}
    assert r["http2"]["status"] == 200


# ---- Phase 6.1: bounded validation (gated) -------------------------------- #
def _cfg() -> AegisConfig:
    c = AegisConfig()
    c.ollama.enabled = False
    c.safety.lab_mode = True
    return c


def test_validator_refuses_below_expert():
    iv = ImpactValidator(auth_level="research", allow_exfil=True)
    r = iv.validate_sync("SQL Injection", "http://127.0.0.1:9/x?id=1")
    assert r.confirmed is False and "EXPERT" in r.notes


def test_validator_refuses_without_budget():
    iv = ImpactValidator(auth_level="expert", allow_exfil=False)
    r = iv.validate_sync("SQL Injection", "http://127.0.0.1:9/x?id=1")
    assert r.confirmed is False and "budget" in r.notes


def test_validator_bounded_probe_cap(http_server):
    # Clean server -> no differential -> not confirmed; probes stay bounded.
    iv = ImpactValidator(auth_level="expert", allow_exfil=True, timeout=4.0)
    r = iv.validate_sync("SQL Injection", f"{http_server}/q?id=1")
    assert r.probes_used <= 4
    assert r.confirmed is False  # local JSON server is not injectable


def test_orchestrator_validate_findings_gating():
    from aegis.models import RunReport, Severity, Vulnerability
    rep = RunReport(started_at="t")
    rep.vulnerabilities = [Vulnerability("SQL Injection", "d",
                                         Severity.CRITICAL,
                                         "http://127.0.0.1:9/x?id=1",
                                         "fix", "", "active-scan")]
    c = AegisConfig()
    c.safety.auth_level = "education"          # below expert -> skipped
    rows = Orchestrator(c).validate_findings(rep)
    assert rows and rows[0]["confirmed"] is False
    assert "EXPERT" in rows[0]["notes"]


# ---- Phase 6.2: scoped assessment (explicit + re-authorised) -------------- #
def test_scoped_assessment_reauthorises_each(http_server):
    c = AegisConfig()
    c.safety.authorized = False
    c.safety.lab_mode = False                 # force the gate to bite
    sa = ScopedAssessment(c)
    res = sa.assess([http_server, "https://example.com"])
    by = {r["target"].rstrip("/"): r for r in res}
    # localhost authorised; external refused by the per-target gate.
    loc = next(v for k, v in by.items() if "127.0.0.1" in k)
    assert loc["authorised"] is True
    ext = next(v for k, v in by.items() if "example.com" in k)
    assert ext["authorised"] is False and "safety gate" in ext["error"]
