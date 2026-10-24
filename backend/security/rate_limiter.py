"""Rate Limiting Abstraction for Volcano AI Firewall.
Provides an extensible rate limiter interface with an in-memory implementation
that can later be backed by Redis or an external distributed cache.
"""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from typing import Dict, Tuple


class BaseRateLimiter(ABC):
    """Abstract rate limiter interface."""

    @abstractmethod
    def is_rate_limited(self, key: str, max_attempts: int, window_seconds: float) -> Tuple[bool, float]:
        """Check if key has exceeded max_attempts within window_seconds.

        Returns (is_limited, retry_after_seconds).
        """
        pass

    @abstractmethod
    def record_failure(self, key: str) -> None:
        """Record a failed attempt for the given key."""
        pass

    @abstractmethod
    def reset(self, key: str) -> None:
        """Reset attempts counter for the given key."""
        pass


class InMemoryRateLimiter(BaseRateLimiter):
    """Thread-safe in-memory sliding window rate limiter."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._failures: Dict[str, deque[float]] = defaultdict(deque)

    def is_rate_limited(self, key: str, max_attempts: int, window_seconds: float) -> Tuple[bool, float]:
        with self._lock:
            now = time.monotonic()
            q = self._failures[key]
            cutoff = now - window_seconds
            while q and q[0] < cutoff:
                q.popleft()

            if len(q) >= max_attempts:
                oldest = q[0]
                retry_after = max(1.0, (oldest + window_seconds) - now)
                return True, retry_after
            return False, 0.0

    def record_failure(self, key: str) -> None:
        with self._lock:
            self._failures[key].append(time.monotonic())

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._failures.clear()
