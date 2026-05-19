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
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def websocket_report(url: str, *, timeout: float = 8.0) -> dict[str, Any]:
    return asyncio.run(probe_websocket(url, timeout=timeout))
