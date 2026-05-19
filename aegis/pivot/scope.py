"""Scoped adjacent-target assessment.

The *safe* interpretation of "pivot": assess additional targets the operator
has **explicitly listed and is authorised for**. Each target is independently
re-passed through the standard safety gate. There is deliberately:

  * NO auto-discovery of neighbours from a "compromised" host
  * NO SSH tunnelling / port-forwarding / lateral movement
  * NO persistence or implant

It is "also assess these other authorised hosts", nothing more.
"""

from __future__ import annotations

import httpx

from ..config import AegisConfig
from ..models import RequestSpec, TestPlan
from ..recon import Fingerprinter
from ..safety import SafetyError, enforce


class ScopedAssessment:
    def __init__(self, config: AegisConfig) -> None:
        self.config = config
        self.fp = Fingerprinter()

    def assess(self, targets: list[str]) -> list[dict]:
        """Light assessment of each explicitly-supplied authorised target."""
        results: list[dict] = []
        for raw in targets:
            url = raw if "://" in raw else f"http://{raw}"
            entry: dict = {"target": url, "authorised": False,
                           "fingerprint": {}, "error": None}
            spec = RequestSpec(url=url).normalised()
            try:
                # Re-authorise EVERY target independently. No implicit scope.
                enforce([spec], TestPlan(total_requests=1),
                        self.config.safety)
                entry["authorised"] = True
            except SafetyError as e:
                entry["error"] = f"refused by safety gate: {e}"
                results.append(entry)
                continue
            try:
                r = httpx.get(url, timeout=10.0, verify=False,
                              follow_redirects=True)
                entry["status"] = r.status_code
                entry["fingerprint"] = self.fp.fingerprint(
                    r.status_code, dict(r.headers), r.text)
            except Exception as exc:  # noqa: BLE001
                entry["error"] = f"{type(exc).__name__}: {exc}"
            results.append(entry)
        return results
