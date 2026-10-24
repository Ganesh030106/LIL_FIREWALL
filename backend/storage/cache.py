from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass


@dataclass(slots=True)
class RateLimitBucket:
    tokens: float
    last_refill: float
    capacity: float
    refill_rate: float


class RateLimiter:
    def __init__(self, capacity: float = 100.0, refill_rate: float = 10.0) -> None:
        self.capacity = capacity
        self.refill_rate = refill_rate
        self._buckets: dict[str, RateLimitBucket] = {}
        self._lock = threading.RLock()

    def is_allowed(self, identifier: str, tokens_required: float = 1.0) -> bool:
        with self._lock:
            now = time.time()

            if identifier not in self._buckets:
                self._buckets[identifier] = RateLimitBucket(
                    tokens=self.capacity,
                    last_refill=now,
                    capacity=self.capacity,
                    refill_rate=self.refill_rate,
                )

            bucket = self._buckets[identifier]
            time_passed = now - bucket.last_refill
            bucket.tokens = min(bucket.capacity, bucket.tokens + time_passed * bucket.refill_rate)
            bucket.last_refill = now

            if bucket.tokens >= tokens_required:
                bucket.tokens -= tokens_required
                return True
            return False


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, timeout_seconds: int = 60) -> None:
        self.failure_threshold = failure_threshold
        self.timeout_seconds = timeout_seconds
        self._failures: dict[str, deque] = {}
        self._state: dict[str, str] = {}
        self._lock = threading.RLock()

    def record_success(self, identifier: str) -> None:
        with self._lock:
            if identifier in self._failures:
                self._failures[identifier].clear()
            self._state[identifier] = "closed"

    def record_failure(self, identifier: str) -> None:
        with self._lock:
            now = time.time()
            if identifier not in self._failures:
                self._failures[identifier] = deque()

            self._failures[identifier].append(now)
            while self._failures[identifier] and now - self._failures[identifier][0] > self.timeout_seconds:
                self._failures[identifier].popleft()

            if len(self._failures[identifier]) >= self.failure_threshold:
                self._state[identifier] = "open"
            else:
                self._state[identifier] = "closed"

    def is_available(self, identifier: str) -> bool:
        with self._lock:
            return self._state.get(identifier, "closed") == "closed"
