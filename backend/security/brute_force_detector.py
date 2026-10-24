"""Brute-Force Attack Detection Module for Volcano AI Firewall.
Monitors high-risk authentication and remote access ports (SSH, RDP, FTP, SMB)
and triggers alerts when rapid repeated connection attempts exceed configured thresholds.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any, Dict, Optional, Tuple

from config import get_settings


PORT_SERVICE_MAP: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    27017: "MongoDB",
}


class BruteForceDetector:
    """Detects rapid repeated connection attempts to sensitive authentication ports."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Key: (src_ip, dst_port) -> deque of timestamps
        self._attempts: Dict[Tuple[str, int], deque[float]] = defaultdict(deque)
        # Key: (src_ip, dst_port) -> last_alert_time
        self._alert_cooldowns: Dict[Tuple[str, int], float] = {}

    def get_service_name(self, port: int) -> str:
        return PORT_SERVICE_MAP.get(port, f"Port-{port}")

    def is_monitored_port(self, port: int) -> bool:
        cfg = get_settings()
        return port in cfg.brute_force_ports

    def record_attempt(
        self,
        src_ip: str,
        dst_ip: Optional[str],
        dst_port: int,
        protocol: str = "TCP",
    ) -> Optional[Dict[str, Any]]:
        """Record a connection attempt. Returns alert dict if brute-force threshold is breached."""
        if not src_ip or not dst_port:
            return None

        cfg = get_settings()
        if dst_port not in cfg.brute_force_ports:
            return None

        now = time.monotonic()
        key = (src_ip, dst_port)
        service = self.get_service_name(dst_port)

        with self._lock:
            q = self._attempts[key]
            q.append(now)

            # Evict timestamps outside the window
            cutoff = now - cfg.brute_force_window
            while q and q[0] < cutoff:
                q.popleft()

            attempt_count = len(q)

            # Check threshold
            if attempt_count >= cfg.brute_force_threshold:
                last_alert = self._alert_cooldowns.get(key, 0.0)
                # 30-second cooldown per (src_ip, dst_port) to avoid flooding
                if now - last_alert >= 30.0:
                    self._alert_cooldowns[key] = now
                    return {
                        "source": "network",
                        "severity": "high",
                        "category": "Brute Force Attack",
                        "rule_name": f"Brute Force Attempt: {service}",
                        "message": (
                            f"Detected brute-force attack from {src_ip} targeting {service} "
                            f"(port {dst_port}) with {attempt_count} attempts in {cfg.brute_force_window:.1f}s."
                        ),
                        "meta": {
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "port": dst_port,
                            "service": service,
                            "attempt_count": attempt_count,
                            "window_seconds": cfg.brute_force_window,
                            "protocol": protocol,
                        },
                    }
    def record_login_failure(self, username: str, src_ip: str) -> Optional[Dict[str, Any]]:
        """Record an application-level failed login attempt. Returns alert if threshold breached."""
        if not src_ip:
            src_ip = "127.0.0.1"
        now = time.monotonic()
        key = (f"web_login:{src_ip}", 443)
        cfg = get_settings()

        with self._lock:
            q = self._attempts[key]
            q.append(now)
            cutoff = now - cfg.brute_force_window
            while q and q[0] < cutoff:
                q.popleft()

            attempt_count = len(q)
            if attempt_count >= cfg.brute_force_threshold:
                last_alert = self._alert_cooldowns.get(key, 0.0)
                if now - last_alert >= 30.0:
                    self._alert_cooldowns[key] = now
                    return {
                        "source": "auth",
                        "severity": "high",
                        "category": "Brute Force Attack",
                        "rule_name": "Web Console Brute Force",
                        "message": (
                            f"Detected credential brute-force attack from {src_ip} "
                            f"(targeting username: {username}) with {attempt_count} attempts in {cfg.brute_force_window:.1f}s."
                        ),
                        "meta": {
                            "source_ip": src_ip,
                            "destination_ip": "127.0.0.1",
                            "port": 443,
                            "service": "WebAuth",
                            "username": username,
                            "attempt_count": attempt_count,
                            "window_seconds": cfg.brute_force_window,
                            "protocol": "HTTPS",
                        },
                    }
        return None

    def get_stats(self) -> Dict[str, Any]:
        """Return operational stats for active tracking."""
        with self._lock:
            now = time.monotonic()
            cfg = get_settings()
            active_suspects = []
            for (ip, port), q in list(self._attempts.items()):
                # Clean old
                cutoff = now - cfg.brute_force_window
                while q and q[0] < cutoff:
                    q.popleft()
                if q:
                    active_suspects.append({
                        "source_ip": ip,
                        "port": port,
                        "service": self.get_service_name(port),
                        "attempts_in_window": len(q),
                    })
            return {
                "active_tracking_targets": len(self._attempts),
                "monitored_ports": cfg.brute_force_ports,
                "threshold": cfg.brute_force_threshold,
                "window": cfg.brute_force_window,
                "active_suspects": active_suspects[:20],
            }

    def clear(self) -> None:
        with self._lock:
            self._attempts.clear()
            self._alert_cooldowns.clear()
