"""Beaconing Detection Module for Volcano AI Firewall.
Monitors periodic outbound and lateral network connections to detect Command & Control
(C2) beaconing patterns by analyzing inter-arrival time variance and coefficient of variation.
"""

from __future__ import annotations

import statistics
import threading
import time
from collections import defaultdict, deque
from typing import Any, Dict, Optional, Tuple

from config import get_settings


class BeaconDetector:
    """Detects regular, periodic beaconing traffic patterns indicative of C2 callbacks."""

    def __init__(self, max_history_per_flow: int = 100, cooldown: Optional[float] = None) -> None:
        self._lock = threading.RLock()
        self._max_history = max_history_per_flow
        self._custom_cooldown = cooldown
        # Key: (src_ip, dst_ip, dst_port) -> deque of timestamp floats
        self._flows: Dict[Tuple[str, str, int], deque[float]] = defaultdict(
            lambda: deque(maxlen=self._max_history)
        )
        # Key: (src_ip, dst_ip, dst_port) -> timestamp of last emitted alert
        self._alert_cooldowns: Dict[Tuple[str, str, int], float] = {}

    def record_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """Record a connection event and evaluate for periodic beaconing patterns.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            dst_port: Destination port number.
            timestamp: Event timestamp in seconds. Defaults to time.time().

        Returns:
            Alert dictionary if beaconing threshold and jitter conditions are met, else None.
        """
        if not src_ip or not dst_ip or not dst_port:
            return None

        cfg = get_settings()
        min_events = getattr(cfg, "beacon_min_events", 10)
        max_jitter = getattr(cfg, "beacon_max_jitter", 0.15)
        cooldown_sec = self._custom_cooldown if self._custom_cooldown is not None else getattr(cfg, "beacon_cooldown", 60.0)

        now = timestamp if timestamp is not None else time.time()
        flow_key = (src_ip.strip(), dst_ip.strip(), dst_port)

        with self._lock:
            q = self._flows[flow_key]
            q.append(now)

            # Need at least min_events
            if len(q) < min_events:
                return None

            # Calculate inter-arrival times
            # Sort slice in case timestamps arrived slightly out-of-order
            sorted_times = sorted(q)
            intervals = [
                sorted_times[i] - sorted_times[i - 1]
                for i in range(1, len(sorted_times))
            ]

            if not intervals:
                return None

            mean_interval = statistics.mean(intervals)

            # Ordinary chatty traffic (bursty connections < 1.0s) must not match
            if mean_interval <= 1.0:
                return None

            # Compute standard deviation and coefficient of variation (jitter)
            stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
            jitter = stdev_interval / mean_interval

            # Check if variation is below maximum allowed jitter
            if jitter <= max_jitter:
                last_alert = self._alert_cooldowns.get(flow_key, 0.0)
                if now - last_alert >= cooldown_sec:
                    self._alert_cooldowns[flow_key] = now
                    return {
                        "source": "beacon_detector",
                        "severity": "high",
                        "category": "Possible C2 Beaconing",
                        "message": (
                            f"Possible C2 beaconing detected from {flow_key[0]} to "
                            f"{flow_key[1]}:{flow_key[2]} (interval ~{mean_interval:.1f}s, jitter: {jitter:.3f})"
                        ),
                        "meta": {
                            "source_ip": flow_key[0],
                            "destination_ip": flow_key[1],
                            "destination_port": flow_key[2],
                            "observed_interval": round(mean_interval, 2),
                            "observed_jitter": round(jitter, 4),
                            "event_count": len(q),
                            "min_events": min_events,
                            "max_jitter": max_jitter,
                        },
                    }

            return None
