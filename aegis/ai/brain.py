"""AIBrain v3 — the enhanced reasoning core.

Every capability has three implementations:
  1. LLM path (multi-provider via ModelRouter)
  2. Deterministic heuristic path (always available)
  3. Agentic path (AI strategist + payload engine)

The heuristic path is *always* run; the LLM path *augments* it when a
provider is reachable. The agentic path is opt-in (agentic_enabled).

v3 adds: multi-provider support, RAG knowledge base integration,
         AI-driven payload generation, autonomous campaign planning.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlparse

from ..config import AIProviderConfig, OllamaConfig, SafetyPolicy
from ..models import (
    AIInsight,
    EndpointStats,
    RequestSpec,
    RunReport,
    Severity,
    TestPlan,
    Vulnerability,
    VulnerabilityV3,
    MITRE_ATTACK_MAP,
)
from . import prompts
from .payload_engine import PayloadEngine
from .router import ModelRouter
from .strategist import AttackStrategist

SENSITIVE = ("password", "passwd", "secret", "api_key", "apikey", "private_key",
             "access_token", "client_secret", "aws_secret", "ssn", "credit_card")
SQL_ERRORS = (r"sql syntax", r"mysql_fetch", r"pg_query", r"unclosed quotation",
              r"syntax error.*near", r"ora-\d{5}", r"sqlite3\.")
STACK_TRACES = (r"traceback \(most recent call last\)", r"at [\w.]+\(.*\.java:\d+\)",
                r"\bexception in thread\b", r"stack trace:")


class AIBrain:
    """Enhanced AI reasoning core with multi-provider and agentic support."""

    def __init__(self, ollama_cfg: OllamaConfig | None = None,
                 ai_cfg: AIProviderConfig | None = None) -> None:
        if ai_cfg is not None:
            self.ai_cfg = ai_cfg
        elif ollama_cfg is not None:
            from ..config import AIProviderConfig, OllamaConfig
            self.ai_cfg = AIProviderConfig(ollama=ollama_cfg)
        else:
            from ..config import AIProviderConfig
            self.ai_cfg = AIProviderConfig()

        self.router = ModelRouter(self.ai_cfg)
        self.strategist = AttackStrategist(self.ai_cfg)
        self.payload_engine = PayloadEngine(self.router)

        # Backward compat: expose OllamaClient-like interface
        self.client = _LegacyClientWrapper(self.router)

    @property
    def engine_tag(self) -> str:
        best = self.router.best_provider()
        if best:
            return f"{best.name}:{best.active_model if hasattr(best, 'active_model') else 'active'}"
        return "heuristic"

    # ================================================================== #
    # 1. PLANNING
    # ================================================================== #
    def plan(self, specs: list[RequestSpec], goal: str, policy: SafetyPolicy) -> TestPlan:
        targets = "\n".join(f"- {s.method} {s.url}" for s in specs[:25])
        data = self.router.chat_json(
            prompts.PLANNER_SYSTEM,
            prompts.PLANNER_USER.format(
                targets=targets, goal=goal or "general performance & reliability check",
                authorized=policy.authorized,
                max_c=policy.max_concurrency, max_d=policy.max_duration_seconds,
            ),
            task="plan",
        )
        if isinstance(data, dict) and ("concurrency" in data or "duration_seconds" in data):
            try:
                return TestPlan(
                    concurrency=int(data.get("concurrency", 10) or 10),
                    duration_seconds=int(data.get("duration_seconds", 0) or 0),
                    total_requests=int(data.get("total_requests", 200) or 200),
                    target_rps=float(data.get("target_rps", 0) or 0),
                    ramp_up_seconds=int(data.get("ramp_up_seconds", 0) or 0),
                    rationale=str(data.get("rationale", "AI-designed plan."))[:300],
                    source="ai",
                )
            except (TypeError, ValueError):
                pass
        return self._heuristic_plan(specs, goal)

    @staticmethod
    def _heuristic_plan(specs: list[RequestSpec], goal: str) -> TestPlan:
        g = (goal or "").lower()
        if any(w in g for w in ("soak", "endurance", "duration", "sustained")):
            return TestPlan(concurrency=20, duration_seconds=60, ramp_up_seconds=5,
                            rationale="Heuristic soak: 20 conn for 60s with ramp-up.",
                            source="default")
        if any(w in g for w in ("spike", "stress", "peak", "heavy")):
            return TestPlan(concurrency=80, total_requests=4000, ramp_up_seconds=3,
                            rationale="Heuristic stress: ramped burst to 80 conn.",
                            source="default")
        n = max(200, 50 * len(specs))
        return TestPlan(concurrency=15, total_requests=min(n, 2000),
                        rationale="Heuristic baseline: 15 conn, bounded request count.",
                        source="default")

    # ================================================================== #
    # 2. NATURAL LANGUAGE -> REQUEST + PLAN
    # ================================================================== #
    def nlp(self, query: str) -> tuple[RequestSpec | None, TestPlan]:
        data = self.router.chat_json(
            prompts.NLP_SYSTEM, prompts.NLP_USER.format(query=query), task="nlp"
        )
        if isinstance(data, dict) and data.get("url"):
            spec = RequestSpec(
                url=str(data["url"]),
                method=str(data.get("method", "GET")),
                headers=dict(data.get("headers") or {}),
                body=(data.get("body") or None),
            ).normalised()
            plan = TestPlan(
                concurrency=int(data.get("concurrency", 10) or 10),
                duration_seconds=int(data.get("duration_seconds", 0) or 0),
                total_requests=int(data.get("total_requests", 100) or 100),
                rationale=str(data.get("rationale", "From natural language."))[:300],
                source="nlp",
            )
            return spec, plan
        return self._heuristic_nlp(query)

    @staticmethod
    def _heuristic_nlp(query: str) -> tuple[RequestSpec | None, TestPlan]:
        q = query.strip()
        url_m = re.search(r"https?://[^\s'\"]+", q)
        spec = None
        if url_m:
            method_m = re.search(r"\b(GET|POST|PUT|DELETE|PATCH)\b", q, re.I)
            token_m = re.search(r"token\s+([A-Za-z0-9._\-]+)", q, re.I)
            spec = RequestSpec(
                url=url_m.group(0),
                method=(method_m.group(1).upper() if method_m else "GET"),
            )
            if token_m:
                spec.headers["Authorization"] = f"Bearer {token_m.group(1)}"
            spec = spec.normalised()
        dur_m = re.search(r"(\d+)\s*(?:s|sec|second)", q, re.I)
        cnt_m = re.search(r"(\d+)\s*requests?", q, re.I)
        con_m = re.search(r"(\d+)\s*(?:concurren|parallel|thread|worker)", q, re.I)
        plan = TestPlan(
            concurrency=int(con_m.group(1)) if con_m else 10,
            duration_seconds=int(dur_m.group(1)) if dur_m else 0,
            total_requests=int(cnt_m.group(1)) if cnt_m else 100,
            rationale="Parsed from natural language (heuristic).",
            source="nlp",
        )
        return spec, plan

    # ================================================================== #
    # 3. SECURITY ANALYSIS  (heuristic always + AI augmentation)
    # ================================================================== #
    def analyze_security(self, endpoints: list[EndpointStats]) -> list[Vulnerability]:
        findings: list[Vulnerability] = []
        for ep in endpoints:
            findings.extend(self._heuristic_security(ep))
            findings.extend(self._ai_security(ep))
        return self._dedupe(findings)

    def _heuristic_security(self, ep: EndpointStats) -> list[Vulnerability]:
        out: list[Vulnerability] = []
        h = {k.lower(): v for k, v in (ep.sample_headers or {}).items()}
        body = ep.sample_body or ""
        low = body.lower()

        def add(t, d, sev, rem, ev=""):
            out.append(Vulnerability(t, d, sev, ep.url, rem, ev, "heuristic"))

        if "strict-transport-security" not in h and ep.url.startswith("https"):
            add("Missing HSTS", "No Strict-Transport-Security header; allows TLS "
                "stripping / downgrade.", Severity.MEDIUM,
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.")
        if "content-security-policy" not in h:
            add("Missing Content-Security-Policy", "No CSP increases XSS and data "
                "injection blast radius.", Severity.HIGH,
                "Define a restrictive CSP appropriate to the API surface.")
        if "x-content-type-options" not in h:
            add("Missing X-Content-Type-Options", "MIME sniffing possible.",
                Severity.LOW, "Add 'X-Content-Type-Options: nosniff'.")
        if "x-frame-options" not in h and "content-security-policy" not in h:
            add("Missing X-Frame-Options", "Clickjacking exposure.", Severity.MEDIUM,
                "Add 'X-Frame-Options: DENY' or a CSP frame-ancestors directive.")
        srv = h.get("server", "")
        if srv and re.search(r"\d", srv):
            add("Server Version Disclosure", f"Server header reveals '{srv}'.",
                Severity.LOW, "Suppress or genericise the Server header.", srv)
        if "x-powered-by" in h:
            add("Technology Disclosure", f"X-Powered-By exposes "
                f"'{h['x-powered-by']}'.", Severity.LOW,
                "Remove the X-Powered-By header.", h["x-powered-by"])
        if any(re.search(p, low) for p in SQL_ERRORS):
            add("SQL Error Leakage", "Response leaks database error text — "
                "indicative of injection exposure.", Severity.CRITICAL,
                "Use parameterised queries; return generic error messages.")
        if any(re.search(p, low) for p in STACK_TRACES):
            add("Stack Trace Disclosure", "Unhandled exception / stack trace in "
                "response body.", Severity.HIGH,
                "Return sanitised errors; log details server-side only.")
        for s in SENSITIVE:
            if re.search(rf"\b{s}\b", low):
                add("Potential Sensitive Data Exposure",
                    f"Response body references '{s}'.", Severity.HIGH,
                    "Verify no credentials/PII are returned to clients.", s)
                break
        if not any(k in h for k in
                   ("x-ratelimit-limit", "ratelimit-limit", "retry-after")):
            add("No Rate-Limiting Signalled", "No rate-limit headers; endpoint may "
                "be brute-forceable / abusable.", Severity.MEDIUM,
                "Enforce and advertise rate limits (RateLimit-* headers).")
        if urlparse(ep.url).scheme == "http":
            add("Cleartext Transport", "Endpoint served over plain HTTP.",
                Severity.HIGH, "Enforce HTTPS and redirect HTTP.")
        ct = h.get("content-type", "")
        if "access-control-allow-origin" in h and h["access-control-allow-origin"] == "*":
            add("Permissive CORS", "Access-Control-Allow-Origin: * exposes the "
                "API to any origin.", Severity.MEDIUM,
                "Restrict CORS to trusted origins.", "ACAO: *")
        return out

    def _ai_security(self, ep: EndpointStats) -> list[Vulnerability]:
        provider = self.router.best_provider("security")
        if provider is None or not (ep.sample_body or ep.sample_headers):
            return []
        data = provider.chat_json(
            prompts.SECURITY_SYSTEM,
            prompts.SECURITY_USER.format(
                method=ep.method, url=ep.url, status=ep.sample_status,
                headers=json.dumps(ep.sample_headers or {})[:1500],
                body=(ep.sample_body or "")[:3000],
            ),
        )
        out: list[Vulnerability] = []
        items = data.get("findings", []) if isinstance(data, dict) else (
            data if isinstance(data, list) else [])
        for f in items or []:
            if not isinstance(f, dict) or not f.get("type"):
                continue
            try:
                sev = Severity(str(f.get("severity", "Info")).title())
            except ValueError:
                sev = Severity.INFO
            out.append(Vulnerability(
                type=str(f["type"])[:120],
                description=str(f.get("description", ""))[:600],
                severity=sev, endpoint=ep.url,
                remediation=str(f.get("remediation", ""))[:400],
                evidence=str(f.get("evidence", ""))[:300], source="ai",
            ))
        return out

    @staticmethod
    def _dedupe(items: list[Vulnerability]) -> list[Vulnerability]:
        seen: dict[tuple[str, str], Vulnerability] = {}
        for v in items:
            key = (v.type.lower().strip(), v.endpoint)
            cur = seen.get(key)
            if cur is None or (v.severity.rank > cur.severity.rank):
                seen[key] = v
        return sorted(seen.values(),
                      key=lambda x: (-x.severity.rank, x.endpoint, x.type))

    # ================================================================== #
    # 4. INSIGHT (summary / benchmark / optimization / prediction / grade)
    # ================================================================== #
    def build_insight(self, report: RunReport) -> AIInsight:
        compact = {
            "summary": report.to_dict()["summary"],
            "plan": report.plan.to_dict(),
            "endpoints": [e.to_dict() for e in report.endpoints][:10],
            "top_vulns": [v.to_dict() for v in report.vulnerabilities[:5]],
        }
        data = self.router.chat_json(
            prompts.SUMMARY_SYSTEM,
            prompts.SUMMARY_USER.format(report=json.dumps(compact)[:6000]),
            task="insight",
        )
        if isinstance(data, dict) and data.get("summary"):
            ins = AIInsight(
                summary=str(data.get("summary", ""))[:1500],
                benchmark=str(data.get("benchmark", ""))[:300],
                optimization=str(data.get("optimization", ""))[:400],
                prediction=str(data.get("prediction", ""))[:300],
                assertions=[str(a)[:160] for a in (data.get("assertions") or [])][:5],
                grade=str(data.get("grade", ""))[:2].strip().upper(),
                engine=self.engine_tag,
            )
            if not ins.grade:
                ins.grade = self._grade(report)
            return ins
        return self._heuristic_insight(report)

    def _heuristic_insight(self, report: RunReport) -> AIInsight:
        sr = report.success_rate
        avg = report.overall_avg_ms
        p95s = [e.p95 for e in report.endpoints if e.latencies]
        p95 = max(p95s) if p95s else 0.0
        rps = report.throughput_rps
        verdict = ("excellent" if avg < 200 and sr > 99 else
                   "acceptable" if avg < 500 and sr > 95 else "poor")
        summary = (
            f"Executed {report.total_attempts} requests across "
            f"{len(report.endpoints)} endpoint(s) at {rps:.1f} req/s. "
            f"Success rate {sr:.1f}%, mean latency {avg:.0f} ms, "
            f"worst p95 {p95:.0f} ms. Overall performance is {verdict}. "
            f"{len(report.vulnerabilities)} security finding(s); highest "
            f"severity {report.highest_severity.value}."
        )
        return AIInsight(
            summary=summary,
            benchmark=f"{'PASS' if avg < 200 and sr > 99 else 'REVIEW'} vs "
                      f"<200ms / >99% bar (avg {avg:.0f}ms, {sr:.1f}%).",
            optimization=("Reduce concurrency or add caching; tail latency "
                          "dominates." if p95 > 2 * avg and avg
                          else "Tune connection pooling and server worker count."),
            prediction=("Likely degradation and elevated error rate under 2-3x "
                        "load." if sr < 99 or avg > 400
                        else "Headroom appears adequate for moderate load growth."),
            assertions=self._heuristic_assertions(report),
            grade=self._grade(report),
            engine="heuristic",
        )

    @staticmethod
    def _heuristic_assertions(report: RunReport) -> list[str]:
        out = ["status:2xx", "response_time_ms:p95:<500"]
        for e in report.endpoints[:3]:
            ct = (e.sample_headers or {}).get("Content-Type", "")
            if ct:
                out.append(f"header:Content-Type:{ct.split(';')[0]}")
            if e.sample_body.strip().startswith("{"):
                out.append(f"body[{e.url}]:json:valid")
        return out[:5]

    @staticmethod
    def _grade(report: RunReport) -> str:
        sr, avg = report.success_rate, report.overall_avg_ms
        sev = report.highest_severity.rank
        score = 100.0
        score -= (100 - sr) * 1.5
        score -= max(0, avg - 200) / 10.0
        score -= sev * 8
        if score >= 90:
            return "A"
        if score >= 78:
            return "B"
        if score >= 62:
            return "C"
        if score >= 45:
            return "D"
        return "F"


class _LegacyClientWrapper:
    """Wraps ModelRouter to provide backward-compatible OllamaClient-like interface."""

    def __init__(self, router: ModelRouter) -> None:
        self.router = router

    @property
    def available(self) -> bool:
        return len(self.router.available_providers()) > 0

    @property
    def active_model(self) -> str:
        best = self.router.best_provider()
        if best and hasattr(best, 'active_model'):
            return best.active_model
        return "heuristic"

    def health(self) -> dict:
        providers = self.router.available_providers()
        best = self.router.best_provider()
        return {
            "ok": len(providers) > 0,
            "providers": providers,
            "model": self.active_model,
            "reason": "" if providers else "No AI provider available",
        }
