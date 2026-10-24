"""Lateral Movement Detection Module for Volcano AI Firewall.
Monitors internal-to-internal network traffic on administrative protocols (SMB, WinRM, RDP, SSH)
and detects rapid fan-out across multiple endpoints indicative of lateral traversal or worm propagation.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections import defaultdict
from typing import Any, Dict, Optional, Tuple

from config import get_settings

ADMIN_PROTOCOLS: Dict[int, str] = {
    22: "SSH",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
}


def is_internal_rfc1918(ip_str: str) -> bool:
    """Validate that an IP is a valid RFC 1918 internal address, strictly excluding loopback and multicast."""
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(str(ip_str).strip())
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
            return False

        if addr.version == 4:
            return (
                addr in ipaddress.ip_network("10.0.0.0/8")
                or addr in ipaddress.ip_network("172.16.0.0/12")
                or addr in ipaddress.ip_network("192.168.0.0/16")
            )
        # IPv6 Unique Local Address (ULA)
        return addr.is_private and not addr.is_loopback
    except (ValueError, TypeError):
        return False


class LateralMovementDetector:
    """Tracks fan-out of administrative protocol connections across internal endpoints."""

    def __init__(self, cooldown: Optional[float] = None) -> None:
        self._lock = threading.RLock()
        self._custom_cooldown = cooldown
        # Key: src_ip -> dict of {dst_ip: (last_timestamp, port)}
        self._contacts: Dict[str, Dict[str, Tuple[float, int]]] = defaultdict(dict)
        # Key: src_ip -> timestamp of last alert
        self._alert_cooldowns: Dict[str, float] = {}

    def is_admin_port(self, port: int) -> bool:
        return port in ADMIN_PROTOCOLS

    def record_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """Inspect a connection for lateral movement fan-out.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            dst_port: Destination port.
            timestamp: Event timestamp in epoch seconds (defaults to time.time()).

        Returns:
            Alert dictionary if threshold is met, else None.
        """
        if not src_ip or not dst_ip or not dst_port:
            return None

        # Protocol check: Must be an administrative port (SMB 445, WinRM 5985/5986, RDP 3389, SSH 22)
        if dst_port not in ADMIN_PROTOCOLS:
            return None

        # Network boundary check: Both source and destination MUST be RFC 1918 internal addresses
        if not is_internal_rfc1918(src_ip) or not is_internal_rfc1918(dst_ip):
            return None

        cfg = get_settings()
        min_hosts = getattr(cfg, "lateral_min_hosts", 5)
        window = getattr(cfg, "lateral_window", 300.0)
        cooldown_sec = self._custom_cooldown if self._custom_cooldown is not None else getattr(cfg, "lateral_cooldown", 300.0)

        now = timestamp if timestamp is not None else time.time()
        src_key = str(src_ip).strip()
        dst_key = str(dst_ip).strip()

        with self._lock:
            host_records = self._contacts[src_key]
            # Record or update destination contact timestamp and port
            host_records[dst_key] = (now, dst_port)

            # Evict destinations contacted outside the sliding window
            cutoff = now - window
            expired_dsts = [d for d, (ts, _) in host_records.items() if ts < cutoff]
            for d in expired_dsts:
                del host_records[d]

            active_destinations = set(host_records.keys())
            if len(active_destinations) >= min_hosts:
                last_alert = self._alert_cooldowns.get(src_key, 0.0)
                if now - last_alert >= cooldown_sec:
                    self._alert_cooldowns[src_key] = now
                    protocols_used = sorted(list({ADMIN_PROTOCOLS.get(p, f"Port-{p}") for _, p in host_records.values()}))
                    return {
                        "source": "lateral_movement_detector",
                        "severity": "high",
                        "category": "Possible Lateral Movement",
                        "message": (
                            f"Possible lateral movement detected: Internal host {src_key} reached "
                            f"{len(active_destinations)} distinct endpoints on admin protocols ({', '.join(protocols_used)})"
                        ),
                        "meta": {
                            "source_ip": src_key,
                            "destination_count": len(active_destinations),
                            "destinations": sorted(list(active_destinations)),
                            "protocols": protocols_used,
                            "window_seconds": window,
                            "threshold": min_hosts,
                        },
                    }

            return None
