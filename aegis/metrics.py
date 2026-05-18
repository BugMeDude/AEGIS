"""Aggregation helpers: turn a stream of AttemptResult into EndpointStats."""

from __future__ import annotations

from collections import defaultdict

from .models import AttemptResult, EndpointStats


class MetricsCollector:
    """Thread/async-safe-by-convention accumulator.

    The engine appends every :class:`AttemptResult` here from a single
    asyncio task context, so no locking is required.
    """

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], EndpointStats] = {}
        self._order: list[tuple[str, str]] = []
        self.total = 0
        self.successes = 0
        self.failures = 0
        self._live_latencies: list[float] = []

    def add(self, r: AttemptResult) -> None:
        key = (r.method, r.url)
        stats = self._by_key.get(key)
        if stats is None:
            stats = EndpointStats(url=r.url, method=r.method)
            self._by_key[key] = stats
            self._order.append(key)

        stats.attempts += 1
        self.total += 1
        if r.ok:
            stats.successes += 1
            self.successes += 1
        else:
            stats.failures += 1
            self.failures += 1

        stats.latencies.append(r.latency_ms)
        self._live_latencies.append(r.latency_ms)
        stats.status_codes[r.status_code] = stats.status_codes.get(r.status_code, 0) + 1
        if r.error:
            stats.errors[r.error] = stats.errors.get(r.error, 0) + 1

        # Capture one representative exchange per endpoint for AI/security review.
        if r.sample_body is not None and not stats.sample_body:
            stats.sample_status = r.status_code
            stats.sample_body = r.sample_body[:20000]
            stats.sample_headers = r.sample_headers or {}

    def snapshot(self) -> dict:
        """Lightweight live view for progress UIs."""
        lat = self._live_latencies
        avg = sum(lat) / len(lat) if lat else 0.0
        return {
            "total": self.total,
            "successes": self.successes,
            "failures": self.failures,
            "avg_ms": avg,
        }

    def finalize(self) -> list[EndpointStats]:
        return [self._by_key[k] for k in self._order]
