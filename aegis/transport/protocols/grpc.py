"""gRPC detection & (optional) reflection enumeration.

If ``grpcio`` + reflection are installed, lists exposed services via the
standard Server Reflection API (the same thing ``grpcurl`` does). Otherwise
degrades to an HTTP/2 content-type probe that detects a gRPC endpoint
(``application/grpc``). Detection / enumeration only — no message fuzzing.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

try:  # optional
    import grpc  # type: ignore
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc  # type: ignore
    _HAS_GRPC = True
except Exception:  # pragma: no cover
    _HAS_GRPC = False


async def _http2_grpc_hint(url: str, timeout: float) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(http2=True, timeout=timeout,
                                     verify=False) as c:
            r = await c.post(url, headers={"content-type": "application/grpc"},
                              content=b"\x00\x00\x00\x00\x00")
            ct = r.headers.get("content-type", "")
            return {
                "method": "http2-probe",
                "looks_like_grpc": ct.startswith("application/grpc"),
                "http_version": r.http_version,
                "status": r.status_code,
                "grpc_status": r.headers.get("grpc-status"),
            }
    except Exception as exc:  # noqa: BLE001
        return {"method": "http2-probe", "error": f"{type(exc).__name__}: {exc}"}


def _reflect(host: str, timeout: float) -> dict[str, Any]:
    try:
        chan = grpc.insecure_channel(host)
        stub = reflection_pb2_grpc.ServerReflectionStub(chan)
        req = reflection_pb2.ServerReflectionRequest(list_services="")
        services: list[str] = []
        for resp in stub.ServerReflectionInfo(iter([req]), timeout=timeout):
            for s in resp.list_services_response.service:
                services.append(s.name)
        chan.close()
        return {"method": "reflection", "services": services}
    except Exception as exc:  # noqa: BLE001
        return {"method": "reflection", "error": f"{type(exc).__name__}: {exc}"}


def probe_grpc(target: str, *, timeout: float = 8.0) -> dict[str, Any]:
    """Detect/enumerate a gRPC endpoint. ``target`` is a URL or host:port."""
    out: dict[str, Any] = {"target": target, "grpcio": _HAS_GRPC}
    if _HAS_GRPC and "://" not in target:
        out.update(_reflect(target, timeout))
        if not out.get("error"):
            return out
    url = target if "://" in target else f"http://{target}"
    out.update(asyncio.run(_http2_grpc_hint(url, timeout)))
    return out
