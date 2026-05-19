"""Regression tests for the v3 audit fixes.

Covers: config single-source-of-truth (offline determinism), RAG offline
keyword fallback, the strategist relative-import crash, and SARIF export.
"""

from __future__ import annotations

import json

from aegis.config import AegisConfig, AIProviderConfig
from aegis.ai.knowledge import KnowledgeBase
from aegis.ai.strategist import AttackStrategist, _coerce_auth_level
from aegis.models import (AuthLevel, EndpointStats, RunReport, Severity,
                          TestPlan, Vulnerability)
from aegis.reporting.exporters import to_sarif, write_sarif


def test_config_ollama_alias_disables_router():
    # Legacy cfg.ollama and cfg.ai.ollama must be the SAME object so that
    # cfg.ollama.enabled=False (tests/--no-ai) truly disables the router.
    c = AegisConfig()
    assert c.ollama is c.ai.ollama
    c.ollama.enabled = False
    assert c.ai.ollama.enabled is False


def test_rag_offline_keyword_fallback():
    kb = KnowledgeBase()                 # chromadb absent in CI
    assert kb.available and not kb.vector_backed
    hits = kb.search("mysql sqli time based bypass", n_results=3)
    assert hits and any("SQLi" in h["text"] for h in hits)
    assert kb.retrieve("graphql introspection")          # alias works
    assert kb.search("zzzznomatchzzzz") == []


def test_strategist_plan_campaign_no_crash():
    s = AttackStrategist(AIProviderConfig())             # agentic disabled
    camp = s.plan_campaign("http://127.0.0.1:9/x", "sqli + xss assessment")
    assert camp.target.endswith("/x")
    assert camp.auth_level == AuthLevel.EDUCATION


def test_coerce_auth_level():
    assert _coerce_auth_level("research") == AuthLevel.RESEARCH
    assert _coerce_auth_level("bogus") == AuthLevel.EDUCATION
    assert _coerce_auth_level(AuthLevel.EXPERT) == AuthLevel.EXPERT


def _report() -> RunReport:
    r = RunReport(started_at="2026-05-19 10:00:00")
    r.finished_at = "2026-05-19 10:01:00"
    r.targets = ["app.lab.local"]
    e = EndpointStats(url="https://app.lab.local/x", method="GET")
    e.attempts = e.successes = 5
    e.latencies = [10.0] * 5
    r.endpoints = [e]
    r.vulnerabilities = [
        Vulnerability("SQL Injection", "param injectable", Severity.CRITICAL,
                      "https://app.lab.local/x?id=1", "Parameterise queries",
                      "id=1' -> SQL error", "active-scan"),
        Vulnerability("Missing HSTS", "no HSTS header", Severity.MEDIUM,
                      "https://app.lab.local/x", "Add HSTS", "", "heuristic"),
    ]
    return r


def test_sarif_export(tmp_path):
    doc = to_sarif(_report())
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "AEGIS"
    assert len(run["results"]) == 2
    assert {r["level"] for r in run["results"]} == {"error", "warning"}
    p = write_sarif(_report(), str(tmp_path / "out.sarif"))
    loaded = json.loads(open(p).read())
    assert loaded["runs"][0]["results"][0]["ruleId"] == "sql-injection"


def test_write_reports_supports_sarif(tmp_path):
    from aegis.reporting import write_reports
    out = write_reports(_report(), str(tmp_path), ["json", "sarif"])
    assert "sarif" in out and out["sarif"].endswith(".sarif")
    json.loads(open(out["sarif"]).read())   # valid JSON
