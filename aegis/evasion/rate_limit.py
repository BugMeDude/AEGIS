"""Rate-limit detection and evasion strategies."""

from __future__ import annotations

import random
import time
from typing import Any


class RateLimitEvader:
    """Detect and evade API rate limits with adaptive backoff."""

    def __init__(self, base_delay: float = 0.5, max_delay: float = 30.0) -> None:
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.current_delay = base_delay
        self.consecutive_blocks = 0
        self.total_blocks = 0
        self.jitter_factor = 0.3

    def detect_rate_limit(self, status_code: int, headers: dict[str, str],
                          body: str) -> bool:
        """Check if a response indicates rate limiting."""
        h = {k.lower(): v for k, v in headers.items()}
        if status_code == 429:
            self.consecutive_blocks += 1
            self.total_blocks += 1
            if "retry-after" in h:
                try:
                    self.current_delay = float(h["retry-after"])
                except ValueError:
                    pass
            return True
        if status_code == 503 and "retry-after" in h:
            self.consecutive_blocks += 1
            self.total_blocks += 1
            return True
        if "x-ratelimit-remaining" in h:
            remaining = int(h.get("x-ratelimit-remaining", "0"))
            if remaining == 0:
                self.consecutive_blocks += 1
                self.total_blocks += 1
                return True
        low = body.lower()
        if any(s in low for s in ("rate limit", "too many requests",
                                  "slow down", "try again later")):
            self.consecutive_blocks += 1
            self.total_blocks += 1
            return True
        self.consecutive_blocks = 0
        return False

    def wait_time(self) -> float:
        """Calculate adaptive wait time based on block history."""
        if self.consecutive_blocks == 0:
            delay = self.base_delay
        else:
            delay = min(
                self.base_delay * (2 ** self.consecutive_blocks),
                self.max_delay
            )
        jitter = delay * self.jitter_factor * (random.random() * 2 - 1)
        return max(0.1, delay + jitter)

    def wait(self) -> None:
        """Wait for the calculated delay period."""
        delay = self.wait_time()
        time.sleep(delay)
        self.current_delay = delay

    def reset(self) -> None:
        """Reset rate-limit state."""
        self.current_delay = self.base_delay
        self.consecutive_blocks = 0

    def distribute_requests(self, count: int, time_window: float) -> list[float]:
        """Distribute N requests across a time window with jitter.

        Returns a list of delays (in seconds) to wait before each request.
        """
        if count <= 1:
            return [0.0]
        base_interval = time_window / count
        delays = []
        for _ in range(count):
            jitter = base_interval * self.jitter_factor * (random.random() * 2 - 1)
            delays.append(max(0.05, base_interval + jitter))
        return delays
