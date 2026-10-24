"""Thread-Safe Bounded Event Buffer for Volcano Sensors."""

from __future__ import annotations

import threading
from collections import deque
from typing import List

from sensor.schema import SensorEvent


class BoundedEventBuffer:
    """
    Bounded queue that buffers sensor events.
    Under heavy load / network bursts, drops the oldest events to ensure
    packet capture threads are never blocked, and increments a dropped_events counter.
    """

    def __init__(self, max_size: int = 5000) -> None:
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        self.max_size = max_size
        self._queue: deque[SensorEvent] = deque()
        self._lock = threading.Lock()
        self._dropped_events: int = 0

    def push(self, event: SensorEvent) -> bool:
        """
        Push an event into the buffer.
        If the buffer is full, drop the oldest event and increment dropped_events.
        Always returns True to signify non-blocking ingestion.
        """
        with self._lock:
            if len(self._queue) >= self.max_size:
                self._queue.popleft()
                self._dropped_events += 1
            self._queue.append(event)
            return True

    def pop_batch(self, max_batch_size: int = 100) -> List[SensorEvent]:
        """Pop up to max_batch_size events from the head of the buffer."""
        batch: List[SensorEvent] = []
        with self._lock:
            for _ in range(min(max_batch_size, len(self._queue))):
                batch.append(self._queue.popleft())
        return batch

    @property
    def dropped_events(self) -> int:
        """Total count of dropped events due to buffer overflow."""
        with self._lock:
            return self._dropped_events

    @property
    def size(self) -> int:
        """Current number of events waiting in the buffer."""
        with self._lock:
            return len(self._queue)

    def clear(self) -> None:
        with self._lock:
            self._queue.clear()
