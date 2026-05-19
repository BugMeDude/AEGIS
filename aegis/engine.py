"""The async load / stress engine.

A full rewrite of the original thread-pool ``ApiTester``. Built on
``asyncio`` + ``httpx`` so a single process can drive hundreds of concurrent
connections with accurate latency percentiles, two load models, optional RPS
pacing and ramp-up, live progress, and cooperative cancellation.
"""

from __future__ import annotations

import asyncio
import time
from typing import Callable

import httpx

from .metrics import MetricsCollector
from .models import AttemptResult, RequestSpec, TestPlan

ProgressCB = Callable[[dict], None]
StopCB = Callable[[], bool]


class LoadEngine:
    def __init__(
        self,
        specs: list[RequestSpec],
        plan: TestPlan,
        *,
        on_progress: ProgressCB | None = None,
        should_stop: StopCB | None = None,
    ) -> None:
        if not specs:
            raise ValueError("LoadEngine requires at least one RequestSpec.")
        self.specs = [s.normalised() for s in specs]
        self.plan = plan
        self.on_progress = on_progress or (lambda _s: None)
        self.should_stop = should_stop or (lambda: False)
        self.metrics = MetricsCollector()
        self._sampled: set[tuple[str, str]] = set()
        self._stopped_early = False
        self._dispatched = 0
        self._t0 = 0.0

    # ------------------------------------------------------------------ #
    async def _one(self, client: httpx.AsyncClient, spec: RequestSpec) -> None:
        start = time.perf_counter()
        key = (spec.method, spec.url)
        want_sample = key not in self._sampled
        try:
            resp = await client.request(
                spec.method,
                spec.url,
                headers=spec.headers or None,
                content=spec.body.encode() if spec.body else None,
            )
            latency = (time.perf_counter() - start) * 1000.0
            ok = 200 <= resp.status_code < 400
            res = AttemptResult(
                url=spec.url,
                method=spec.method,
                status_code=resp.status_code,
                latency_ms=latency,
                ok=ok,
                response_size=len(resp.content),
                started_at=start,
            )
            if want_sample:
                res.sample_body = resp.text[:20000]
                res.sample_headers = dict(resp.headers)
                self._sampled.add(key)
        except Exception as exc:  # network / timeout / TLS
            latency = (time.perf_counter() - start) * 1000.0
            res = AttemptResult(
                url=spec.url,
                method=spec.method,
                status_code=0,
                latency_ms=latency,
                ok=False,
                error=type(exc).__name__ + (f": {exc}" if str(exc) else ""),
                started_at=start,
            )
            if want_sample:
                res.sample_body = ""
                res.sample_headers = {}
                self._sampled.add(key)
        self.metrics.add(res)

    # ------------------------------------------------------------------ #
    def _emit(self, force: bool = False) -> None:
        snap = self.metrics.snapshot()
        elapsed = time.perf_counter() - self._t0
        if self.plan.mode() == "duration" and self.plan.duration_seconds:
            pct = min(100.0, elapsed / self.plan.duration_seconds * 100.0)
        else:
            total = max(1, self.plan.total_requests)
            pct = min(100.0, snap["total"] / total * 100.0)
        snap.update(
            percent=pct,
            elapsed=elapsed,
            rps=(snap["total"] / elapsed) if elapsed > 0 else 0.0,
        )
        self.on_progress(snap)

    # ------------------------------------------------------------------ #
    async def _worker(
        self, wid: int, client: httpx.AsyncClient, deadline: float | None,
        counter: list[int], target_total: int, gap: float,
    ) -> None:
        n = len(self.specs)
        while True:
            if self.should_stop():
                self._stopped_early = True
                return
            if deadline is not None:
                if time.perf_counter() >= deadline:
                    return
            else:
                idx = counter[0]
                if idx >= target_total:
                    return
                counter[0] += 1
            spec = self.specs[(self._dispatched) % n]
            self._dispatched += 1
            await self._one(client, spec)
            if gap > 0:
                await asyncio.sleep(gap)

    async def _ramp(self, concurrency: int) -> list[float]:
        """Return per-worker start delays implementing linear ramp-up."""
        if self.plan.ramp_up_seconds <= 0 or concurrency <= 1:
            return [0.0] * concurrency
        step = self.plan.ramp_up_seconds / concurrency
        return [i * step for i in range(concurrency)]

    # ------------------------------------------------------------------ #
    async def run(self) -> MetricsCollector:
        plan = self.plan
        concurrency = max(1, plan.concurrency)
        limits = httpx.Limits(
            max_connections=concurrency + 10,
            max_keepalive_connections=concurrency,
        )
        timeout = httpx.Timeout(plan.timeout_seconds)
        self._t0 = time.perf_counter()

        deadline = (
            self._t0 + plan.duration_seconds if plan.mode() == "duration" else None
        )
        target_total = plan.total_requests if plan.mode() == "count" else 1 << 60
        counter = [0]
        # RPS pacing: distribute the inter-request gap across workers.
        gap = (concurrency / plan.target_rps) if plan.target_rps > 0 else 0.0

        async with httpx.AsyncClient(
            limits=limits, timeout=timeout, follow_redirects=True,
            verify=False, http2=getattr(plan, "http2", False),
        ) as client:
            delays = await self._ramp(concurrency)

            async def staged(wid: int) -> None:
                if delays[wid]:
                    await asyncio.sleep(delays[wid])
                await self._worker(
                    wid, client, deadline, counter, target_total, gap
                )

            workers = [asyncio.create_task(staged(i)) for i in range(concurrency)]

            async def reporter() -> None:
                while not all(w.done() for w in workers):
                    self._emit()
                    await asyncio.sleep(0.4)

            rep = asyncio.create_task(reporter())
            await asyncio.gather(*workers, return_exceptions=True)
            rep.cancel()
            self._emit(force=True)

        return self.metrics

    @property
    def stopped_early(self) -> bool:
        return self._stopped_early


def run_engine(
    specs: list[RequestSpec],
    plan: TestPlan,
    *,
    on_progress: ProgressCB | None = None,
    should_stop: StopCB | None = None,
) -> tuple[MetricsCollector, bool, float]:
    """Synchronous wrapper. Returns (metrics, stopped_early, wall_seconds)."""
    eng = LoadEngine(specs, plan, on_progress=on_progress, should_stop=should_stop)
    t0 = time.perf_counter()
    asyncio.run(eng.run())
    return eng.metrics, eng.stopped_early, time.perf_counter() - t0
