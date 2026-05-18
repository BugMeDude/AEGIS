"""AI heuristic-fallback and reporting tests (offline, deterministic)."""

import json
from pathlib import Path

from aegis.ai.brain import AIBrain
from aegis.ai.ollama import OllamaClient
from aegis.config import OllamaConfig, SafetyPolicy
from aegis.models import EndpointStats, RequestSpec, RunReport, Severity, TestPlan
from aegis.reporting import render_html, render_markdown, write_reports


def _brain() -> AIBrain:
    return AIBrain(OllamaConfig(enabled=False))  # force heuristic


def test_json_fence_extraction():
    raw = 'noise\n```json\n{"ok": true, "n": 3}\n```\ntrailing'
    assert OllamaClient._extract_json(raw) == {"ok": True, "n": 3}
    assert OllamaClient._extract_json('{"a":1}') == {"a": 1}
    assert OllamaClient._extract_json("not json") is None


def test_heuristic_plan_variants():
    b = _brain()
    specs = [RequestSpec(url="https://x.com").normalised()]
    assert b.plan(specs, "run a soak test", SafetyPolicy()).duration_seconds > 0
    assert b.plan(specs, "heavy stress test", SafetyPolicy()).concurrency >= 50
    assert b.plan(specs, "", SafetyPolicy()).mode() == "count"


def test_heuristic_nlp():
    b = _brain()
    spec, plan = b.nlp("hit https://api.x.com/v1 for 30 seconds 20 concurrent")
    assert spec.url == "https://api.x.com/v1"
    assert plan.duration_seconds == 30 and plan.concurrency == 20


def test_heuristic_security_findings():
    b = _brain()
    ep = EndpointStats(url="http://x.com/a", method="GET")
    ep.sample_status = 200
    ep.sample_headers = {"Server": "nginx/1.18.0"}
    ep.sample_body = "Warning: mysql_fetch_array() error; password=hunter2"
    vulns = b.analyze_security([ep])
    types = {v.type for v in vulns}
    assert "SQL Error Leakage" in types
    assert "Cleartext Transport" in types
    assert any(v.severity == Severity.CRITICAL for v in vulns)


def test_clean_endpoint_minimal_findings():
    b = _brain()
    ep = EndpointStats(url="https://x.com/a", method="GET")
    ep.sample_headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "RateLimit-Limit": "100",
    }
    ep.sample_body = '{"ok": true}'
    vulns = b.analyze_security([ep])
    assert all(v.severity.rank <= Severity.MEDIUM.rank for v in vulns)


def _sample_report() -> RunReport:
    r = RunReport(started_at="2026-05-18 10:00:00", plan=TestPlan())
    e = EndpointStats(url="https://x.com/a", method="GET")
    e.attempts, e.successes = 100, 99
    e.failures = 1
    e.latencies = [120.0] * 100
    e.status_codes = {200: 99, 500: 1}
    r.endpoints = [e]
    r.total_attempts, r.total_successes, r.total_failures = 100, 99, 1
    r.throughput_rps = 50.0
    r.targets = ["x.com"]
    return r


def test_insight_grade_and_serialisation():
    b = _brain()
    rep = _sample_report()
    rep.insight = b.build_insight(rep)
    assert rep.insight.grade in set("ABCDF")
    assert rep.insight.engine == "heuristic"
    assert rep.insight.summary
    json.dumps(rep.to_dict())  # must be serialisable


def test_report_rendering_and_write(tmp_path: Path):
    rep = _sample_report()
    rep.insight = _brain().build_insight(rep)
    assert "AEGIS" in render_html(rep)
    assert "# AEGIS Report" in render_markdown(rep)
    written = write_reports(rep, str(tmp_path), ["json", "csv", "md", "html"])
    assert set(written) == {"json", "csv", "md", "html"}
    for p in written.values():
        assert Path(p).stat().st_size > 0
    loaded = json.loads(Path(written["json"]).read_text())
    assert loaded["summary"]["total_attempts"] == 100
