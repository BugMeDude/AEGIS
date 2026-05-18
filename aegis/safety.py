"""The authorization gate.

This is what keeps AEGIS a professional appsec / load-testing tool rather than
an abuse vector. Every run passes through :func:`enforce` before a single
packet is sent.
"""

from __future__ import annotations

from urllib.parse import urlparse

from .config import SafetyPolicy
from .models import RequestSpec, TestPlan


class SafetyError(RuntimeError):
    """Raised when a run violates the responsible-use policy."""


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def is_local(host: str, policy: SafetyPolicy) -> bool:
    return host in policy.local_allow or host.endswith(".local")


def classify_targets(requests: list[RequestSpec], policy: SafetyPolicy) -> dict:
    """Return {hosts, all_local, blocked, off_allowlist} for the request set."""
    hosts = sorted({_host(r.url) for r in requests if _host(r.url)})
    blocked = [h for h in hosts if h in policy.blocklist]
    off_allow = []
    if policy.allowlist:
        off_allow = [
            h for h in hosts
            if h not in policy.allowlist and not is_local(h, policy)
        ]
    return {
        "hosts": hosts,
        "all_local": all(is_local(h, policy) for h in hosts) if hosts else True,
        "blocked": blocked,
        "off_allowlist": off_allow,
    }


def clamp_plan(plan: TestPlan, policy: SafetyPolicy) -> list[str]:
    """Clamp a plan to policy caps in place. Returns human-readable notes."""
    notes: list[str] = []
    if plan.concurrency > policy.max_concurrency:
        notes.append(
            f"concurrency {plan.concurrency} -> {policy.max_concurrency} (cap)"
        )
        plan.concurrency = policy.max_concurrency
    if plan.concurrency < 1:
        plan.concurrency = 1
    if plan.duration_seconds > policy.max_duration_seconds:
        notes.append(
            f"duration {plan.duration_seconds}s -> {policy.max_duration_seconds}s (cap)"
        )
        plan.duration_seconds = policy.max_duration_seconds
    if plan.duration_seconds == 0 and plan.total_requests > policy.max_total_requests:
        notes.append(
            f"total_requests {plan.total_requests} -> "
            f"{policy.max_total_requests} (cap)"
        )
        plan.total_requests = policy.max_total_requests
    if plan.total_requests < 1 and plan.duration_seconds == 0:
        plan.total_requests = 1
    return notes


def enforce(
    requests: list[RequestSpec],
    plan: TestPlan,
    policy: SafetyPolicy,
) -> list[str]:
    """Authorize (or refuse) a run. Returns advisory notes; raises on refusal."""
    if not requests:
        raise SafetyError("No valid requests to execute.")

    info = classify_targets(requests, policy)

    if info["blocked"]:
        raise SafetyError(
            f"Target host(s) on blocklist: {', '.join(info['blocked'])}"
        )
    if info["off_allowlist"]:
        raise SafetyError(
            "Target host(s) not on the configured allowlist: "
            f"{', '.join(info['off_allowlist'])}. Add them to safety.allowlist "
            "to proceed."
        )
    if not info["all_local"] and not policy.authorized:
        raise SafetyError(
            "Refusing to generate load against a non-local target without "
            "authorization.\n"
            f"  Targets: {', '.join(h for h in info['hosts'] if h)}\n"
            "  You must be explicitly authorised to test these systems.\n"
            "  Re-run with --authorized (or set safety.authorized: true / "
            "AEGIS_AUTHORIZED=1) to affirm authorisation."
        )

    return clamp_plan(plan, policy)
