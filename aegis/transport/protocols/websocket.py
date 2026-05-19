"""WebSocket connectivity & robustness tester (bounded).

Authorised-research probe in the same spirit as the bounded DAST scanner:
connect, do an echo round-trip, then send a *small fixed* set of edge-case
frames (oversized text, malformed JSON, a binary blob) and record how the
server reacts. It is NOT an unbounded fuzzer — at most a handful of frames.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

try:
    import websockets
    _HAS_WS = True
except Exception:  # pragma: no cover
    _HAS_WS = False

# Bounded, fixed probe set (teaching/robustness, not a fuzzer).
_EDGE_FRAMES = [
    ("echo", "aegis-ws-probe"),
    ("large_text", "A" * 8192),
    ("malformed_json", '{"a": '),
    ("binary", b"\x00\x01\x02\xff" * 16),
]


async def probe_websocket(url: str, *, timeout: float = 8.0,
                          headers: dict[str, str] | None = None
                          ) -> dict[str, Any]:
    """Connect and run the bounded probe set. Returns observations."""
    out: dict[str, Any] = {"url": url, "available": _HAS_WS,
                           "connected": False, "observations": [],
                           "error": None}
    if not _HAS_WS:
        out["error"] = "websockets library not installed"
        return out
    try:
        async with websockets.connect(
            url, open_timeout=timeout, close_timeout=timeout,
            additional_headers=list((headers or {}).items()) or None,
        ) as ws:
            out["connected"] = True
            for name, frame in _EDGE_FRAMES:
                t0 = time.perf_counter()
                rec = {"probe": name, "ms": 0.0, "reply": None,
                       "closed": False}
                try:
                    await ws.send(frame)
                    reply = await asyncio.wait_for(ws.recv(), timeout=3.0)
                    rec["reply"] = (reply[:200] if isinstance(reply, str)
                                    else f"<{len(reply)} bytes>")
                except asyncio.TimeoutError:
                    rec["reply"] = "<no reply / timeout>"
                except Exception as exc:  # noqa: BLE001
                    rec["closed"] = True
                    rec["reply"] = f"{type(exc).__name__}"
                rec["ms"] = round((time.perf_counter() - t0) * 1000, 2)
                out["observations"].append(rec)
                if rec["closed"]:
                    break
    except Exception as exc:  # noqa: BLE001
        out["error"] = _friendly(exc)
        out["note"] = _diagnose(exc)
    return out


def _friendly(exc: Exception) -> str:
    name = type(exc).__name__
    msg = str(exc)
    if name == "InvalidURI" and ("http://" in msg or "https://" in msg):
        return "no WebSocket endpoint here (server HTTP-redirected)"
    if name in ("gaierror",) or "Name or service not known" in msg:
        return "host did not resolve (DNS)"
    if name in ("ConnectionRefusedError",) or "Connect call failed" in msg:
        return "connection refused (no listener)"
    if name in ("InvalidStatus", "InvalidStatusCode", "InvalidHandshake",
                "InvalidMessage"):
        return f"not a WebSocket endpoint ({name})"
    if name in ("TimeoutError",):
        return "WebSocket handshake timed out"
    return f"{name}: {msg[:120]}"


def _diagnose(exc: Exception) -> str:
    msg = str(exc)
    if "http://" in msg or "https://" in msg:
        # Surface the redirect target so the operator can re-target it.
        import re
        m = re.search(r"https?://[^\s']+", msg)
        if m:
            return f"redirected to {m.group(0)} — try that URL or its ws(s):// form"
    return ""


def websocket_report(url: str, *, timeout: float = 8.0) -> dict[str, Any]:
    return asyncio.run(probe_websocket(url, timeout=timeout))
