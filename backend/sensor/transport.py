"""Event Transports for Volcano Sensor Telemetry."""

from __future__ import annotations

import abc
import logging
import threading
import time
from typing import Callable, List, Optional

import requests

from sensor.schema import SensorEvent, SensorEventBatch

logger = logging.getLogger("volcano.sensor.transport")


class EventTransport(abc.ABC):
    """Abstract base transport interface for dispatching sensor events to Volcano core."""

    @abc.abstractmethod
    def emit(self, event: SensorEvent) -> None:
        """Emit a single sensor event."""
        raise NotImplementedError

    @abc.abstractmethod
    def emit_batch(self, events: List[SensorEvent]) -> None:
        """Emit a batch of sensor events."""
        raise NotImplementedError

    @abc.abstractmethod
    def close(self) -> None:
        """Flush buffers and clean up transport resources."""
        raise NotImplementedError


class InProcessTransport(EventTransport):
    """
    Default in-process event transport.
    Dispatches sensor events directly into the in-memory handler / core engine callback.
    """

    def __init__(self, handler: Callable[[SensorEvent], None]) -> None:
        self.handler = handler

    def emit(self, event: SensorEvent) -> None:
        try:
            self.handler(event)
        except Exception as exc:
            logger.error("InProcessTransport handler failed: %s", exc)

    def emit_batch(self, events: List[SensorEvent]) -> None:
        for ev in events:
            self.emit(ev)

    def close(self) -> None:
        pass


class HttpBatchTransport(EventTransport):
    """
    HTTP batch transport that emits SensorEvent batches to POST /api/ingest/events.
    Authenticated via per-sensor secret bearer token.
    """

    def __init__(
        self,
        endpoint_url: str,
        sensor_token: str,
        sensor_id: str = "sensor-edge-01",
        batch_size: int = 50,
        flush_interval_seconds: float = 1.0,
        timeout_seconds: float = 5.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.endpoint_url = endpoint_url
        self.sensor_token = sensor_token
        self.sensor_id = sensor_id
        self.batch_size = batch_size
        self.flush_interval_seconds = flush_interval_seconds
        self.timeout_seconds = timeout_seconds
        self.session = session or requests.Session()

        self._buffer: List[SensorEvent] = []
        self._lock = threading.Lock()
        self._running = True
        self._last_flush = time.monotonic()
        self._worker_thread = threading.Thread(target=self._flush_worker, daemon=True)
        self._worker_thread.start()

    def emit(self, event: SensorEvent) -> None:
        batch_to_send: Optional[List[SensorEvent]] = None
        with self._lock:
            self._buffer.append(event)
            if len(self._buffer) >= self.batch_size:
                batch_to_send = list(self._buffer)
                self._buffer.clear()
                self._last_flush = time.monotonic()

        if batch_to_send:
            self._send_batch(batch_to_send)

    def emit_batch(self, events: List[SensorEvent]) -> None:
        if not events:
            return
        self._send_batch(events)

    def _flush_worker(self) -> None:
        while self._running:
            time.sleep(0.2)
            now = time.monotonic()
            batch_to_send: Optional[List[SensorEvent]] = None
            with self._lock:
                if self._buffer and (now - self._last_flush >= self.flush_interval_seconds):
                    batch_to_send = list(self._buffer)
                    self._buffer.clear()
                    self._last_flush = now

            if batch_to_send:
                self._send_batch(batch_to_send)

    def _send_batch(self, events: List[SensorEvent]) -> bool:
        payload = SensorEventBatch(
            sensor_id=self.sensor_id,
            events=events,
        ).model_dump()

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.sensor_token}",
            "X-Sensor-Token": self.sensor_token,
        }

        try:
            resp = self.session.post(
                self.endpoint_url,
                json=payload,
                headers=headers,
                timeout=self.timeout_seconds,
            )
            if resp.status_code >= 400:
                logger.error(
                    "HttpBatchTransport error response from %s: %s %s",
                    self.endpoint_url,
                    resp.status_code,
                    resp.text,
                )
                return False
            return True
        except Exception as exc:
            logger.error("HttpBatchTransport failed to post batch to %s: %s", self.endpoint_url, exc)
            return False

    def close(self) -> None:
        self._running = False
        remaining: List[SensorEvent] = []
        with self._lock:
            remaining = list(self._buffer)
            self._buffer.clear()
        if remaining:
            self._send_batch(remaining)
