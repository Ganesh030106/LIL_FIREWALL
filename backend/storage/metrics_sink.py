"""Time-Series Metrics Sinks for Volcano AI Firewall."""

from __future__ import annotations

import abc
import os
import threading
from collections import defaultdict
from typing import Any, Dict, Optional

try:
    from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest
    PROMETHEUS_AVAILABLE = True
except ImportError:
    CollectorRegistry = None  # type: ignore[misc,assignment]
    Counter = None  # type: ignore[misc,assignment]
    Gauge = None  # type: ignore[misc,assignment]
    generate_latest = None  # type: ignore[misc,assignment]
    PROMETHEUS_AVAILABLE = False


class MetricsSink(abc.ABC):
    """Abstract interface for metrics export and time-series telemetry."""

    @abc.abstractmethod
    def record_packet(self, count: int = 1) -> None:
        """Increment observed packet counts."""
        raise NotImplementedError

    @abc.abstractmethod
    def set_packet_rate(self, rate: float) -> None:
        """Update current packet velocity / rate."""
        raise NotImplementedError

    @abc.abstractmethod
    def record_alert(self, severity: str, category: str = "") -> None:
        """Increment alert counts by severity."""
        raise NotImplementedError

    @abc.abstractmethod
    def record_dropped_events(self, count: int = 1) -> None:
        """Increment dropped telemetry events count."""
        raise NotImplementedError

    @abc.abstractmethod
    def record_rate_limit_rejection(self, endpoint: str = "login") -> None:
        """Increment rate limit rejection count."""
        raise NotImplementedError

    @abc.abstractmethod
    def record_containment_action(self, action_type: str) -> None:
        """Increment containment action count."""
        raise NotImplementedError

    @abc.abstractmethod
    def set_enforcement_mode(self, mode: str) -> None:
        """Set current firewall enforcement mode ('active', 'dry_run', 'disabled')."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_metrics_text(self) -> str:
        """Generate exposition format text (e.g., Prometheus text format)."""
        raise NotImplementedError

    @abc.abstractmethod
    def snapshot(self) -> Dict[str, Any]:
        """Return in-memory snapshot of metrics."""
        raise NotImplementedError


class InMemorySink(MetricsSink):
    """
    Default in-process metrics sink.
    Stores counters and gauges in memory with zero external dependencies.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._packet_count: int = 0
        self._packet_rate: float = 0.0
        self._alerts_by_severity: Dict[str, int] = defaultdict(int)
        self._dropped_events: int = 0
        self._rate_limit_rejections: Dict[str, int] = defaultdict(int)
        self._containment_actions: Dict[str, int] = defaultdict(int)
        self._enforcement_mode: str = "active"

    def record_packet(self, count: int = 1) -> None:
        with self._lock:
            self._packet_count += count

    def set_packet_rate(self, rate: float) -> None:
        with self._lock:
            self._packet_rate = float(rate)

    def record_alert(self, severity: str, category: str = "") -> None:
        with self._lock:
            self._alerts_by_severity[severity.lower().strip()] += 1

    def record_dropped_events(self, count: int = 1) -> None:
        with self._lock:
            self._dropped_events += count

    def record_rate_limit_rejection(self, endpoint: str = "login") -> None:
        with self._lock:
            self._rate_limit_rejections[endpoint.lower().strip()] += 1

    def record_containment_action(self, action_type: str) -> None:
        with self._lock:
            self._containment_actions[action_type.lower().strip()] += 1

    def set_enforcement_mode(self, mode: str) -> None:
        with self._lock:
            self._enforcement_mode = mode.lower().strip()

    def get_metrics_text(self) -> str:
        with self._lock:
            lines = [
                "# HELP volcano_packet_rate Current packet rate in packets/second",
                "# TYPE volcano_packet_rate gauge",
                f"volcano_packet_rate {self._packet_rate}",
                "# HELP volcano_dropped_events_total Total dropped sensor events",
                "# TYPE volcano_dropped_events_total counter",
                f"volcano_dropped_events_total {self._dropped_events}",
            ]
            for sev, count in self._alerts_by_severity.items():
                lines.append(f'volcano_alerts_total{{severity="{sev}"}} {count}')
            for ep, count in self._rate_limit_rejections.items():
                lines.append(f'volcano_rate_limit_rejections_total{{endpoint="{ep}"}} {count}')
            for act, count in self._containment_actions.items():
                lines.append(f'volcano_containment_actions_total{{action_type="{act}"}} {count}')
            lines.append(f'volcano_enforcement_mode{{mode="{self._enforcement_mode}"}} 1')
            return "\n".join(lines) + "\n"

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "packet_rate": self._packet_rate,
                "packet_count": self._packet_count,
                "alerts_by_severity": dict(self._alerts_by_severity),
                "dropped_events": self._dropped_events,
                "rate_limit_rejections": dict(self._rate_limit_rejections),
                "containment_actions": dict(self._containment_actions),
                "enforcement_mode": self._enforcement_mode,
            }


class PrometheusSink(MetricsSink):
    """
    Prometheus metrics sink exporting standard text format using prometheus_client.
    """

    def __init__(self, registry: Optional[Any] = None) -> None:
        if not PROMETHEUS_AVAILABLE:
            raise RuntimeError("prometheus_client is not installed; install requirements-extras.txt")

        self.registry = registry or CollectorRegistry(auto_describe=True)

        self._gauge_packet_rate = Gauge(
            "volcano_packet_rate",
            "Current packet processing rate (packets/second)",
            registry=self.registry,
        )
        self._counter_alerts = Counter(
            "volcano_alerts_total",
            "Total alerts detected by severity",
            ["severity"],
            registry=self.registry,
        )
        self._counter_dropped_events = Counter(
            "volcano_dropped_events_total",
            "Total dropped telemetry events due to queue/buffer overflow",
            registry=self.registry,
        )
        self._counter_rate_limit_rejections = Counter(
            "volcano_rate_limit_rejections_total",
            "Total requests rejected by rate limiters",
            ["endpoint"],
            registry=self.registry,
        )
        self._counter_containment_actions = Counter(
            "volcano_containment_actions_total",
            "Total autonomous and manual containment actions applied",
            ["action_type"],
            registry=self.registry,
        )
        self._gauge_enforcement_mode = Gauge(
            "volcano_enforcement_mode",
            "Active firewall enforcement mode",
            ["mode"],
            registry=self.registry,
        )

        self._in_memory_mirror = InMemorySink()
        # Initialize default enforcement mode
        self.set_enforcement_mode("active")

    def record_packet(self, count: int = 1) -> None:
        self._in_memory_mirror.record_packet(count)

    def set_packet_rate(self, rate: float) -> None:
        self._gauge_packet_rate.set(rate)
        self._in_memory_mirror.set_packet_rate(rate)

    def record_alert(self, severity: str, category: str = "") -> None:
        clean_sev = severity.lower().strip() or "low"
        self._counter_alerts.labels(severity=clean_sev).inc()
        self._in_memory_mirror.record_alert(clean_sev, category)

    def record_dropped_events(self, count: int = 1) -> None:
        if count > 0:
            self._counter_dropped_events.inc(count)
            self._in_memory_mirror.record_dropped_events(count)

    def record_rate_limit_rejection(self, endpoint: str = "login") -> None:
        clean_ep = endpoint.lower().strip()
        self._counter_rate_limit_rejections.labels(endpoint=clean_ep).inc()
        self._in_memory_mirror.record_rate_limit_rejection(clean_ep)

    def record_containment_action(self, action_type: str) -> None:
        clean_act = action_type.lower().strip()
        self._counter_containment_actions.labels(action_type=clean_act).inc()
        self._in_memory_mirror.record_containment_action(clean_act)

    def set_enforcement_mode(self, mode: str) -> None:
        clean_mode = mode.lower().strip()
        for m in ["active", "dry_run", "disabled"]:
            self._gauge_enforcement_mode.labels(mode=m).set(1.0 if m == clean_mode else 0.0)
        self._in_memory_mirror.set_enforcement_mode(clean_mode)

    def get_metrics_text(self) -> str:
        raw_bytes = generate_latest(self.registry)
        return raw_bytes.decode("utf-8")

    def snapshot(self) -> Dict[str, Any]:
        return self._in_memory_mirror.snapshot()


def get_metrics_sink(
    backend: Optional[str] = None,
    registry: Optional[Any] = None,
) -> MetricsSink:
    """Factory creating the appropriate MetricsSink."""
    chosen_backend = (backend or os.getenv("VOLCANO_METRICS_SINK", "memory")).lower().strip()
    if chosen_backend == "prometheus" and PROMETHEUS_AVAILABLE:
        return PrometheusSink(registry=registry)
    return InMemorySink()
