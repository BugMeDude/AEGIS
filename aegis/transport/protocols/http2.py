"""HTTP/2 capability tester.

Detects whether a target negotiates HTTP/2 (ALPN ``h2``) and measures basic
round-trip timing on both protocols. Pure observation — no payloads, no
attack. Used by ``aegis protocols`` and to inform the load engine.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx


async def probe_http2(url: str, *, timeout: float = 10.0,
                      verify: bool = False) -> dict[str, Any]:
    """Return {http2_supported, negotiated, status, ms, error}."""
    out: dict[str, Any] = {"url": url, "http2_supported": False,
                           "negotiated": "", "status": 0, "ms": 0.0,
                           "error": None}
    try:
        t0 = time.perf_counter()
        async with httpx.AsyncClient(http2=True, timeout=timeout,
                                     verify=verify,
                                     follow_redirects=True) as c:
            r = await c.get(url)
            out["ms"] = round((time.perf_counter() - t0) * 1000, 2)
            out["status"] = r.status_code
            ver = r.http_version  # "HTTP/2" or "HTTP/1.1"
            out["negotiated"] = ver
            out["http2_supported"] = ver == "HTTP/2"
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def http2_report(url: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Sync wrapper."""
    return asyncio.run(probe_http2(url, timeout=timeout))
