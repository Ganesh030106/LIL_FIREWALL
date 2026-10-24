"""PCAP Ring Buffer Module for Volcano AI Firewall.
Maintains a 1,000-packet rolling in-memory buffer of captured network traffic
and provides PCAP binary export for Wireshark forensics and incident investigation.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from scapy.utils import wrpcap
except Exception:
    wrpcap = None


class PCAPRingBuffer:
    """Thread-safe circular ring buffer for recent network packets."""

    def __init__(self, maxlen: int = 1000) -> None:
        self.maxlen = maxlen
        self._buffer: deque[Any] = deque(maxlen=maxlen)
        self._timestamps: deque[float] = deque(maxlen=maxlen)
        self._lock = threading.RLock()

    def add_packet(self, packet: Any) -> None:
        """Add a captured packet to the rolling buffer."""
        if packet is None:
            return
        with self._lock:
            self._buffer.append(packet)
            self._timestamps.append(time.time())

    def get_packet_count(self) -> int:
        with self._lock:
            return len(self._buffer)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            count = len(self._buffer)
            oldest = self._timestamps[0] if self._timestamps else None
            newest = self._timestamps[-1] if self._timestamps else None
            return {
                "packet_count": count,
                "capacity": self.maxlen,
                "oldest_timestamp": oldest,
                "newest_timestamp": newest,
                "pcap_export_supported": wrpcap is not None,
            }

    def export_pcap_file(self, output_path: str | Path, count: Optional[int] = None) -> Path:
        """Write recent packets to a .pcap file on disk."""
        if wrpcap is None:
            raise RuntimeError("Scapy wrpcap is not available in the current environment.")

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        with self._lock:
            packets_to_write = list(self._buffer)
            if count and count > 0:
                packets_to_write = packets_to_write[-count:]

        wrpcap(str(out), packets_to_write)
        return out

    def export_pcap_bytes(self, count: Optional[int] = None) -> bytes:
        """Export recent packets directly as PCAP binary bytes."""
        if wrpcap is None:
            raise RuntimeError("Scapy wrpcap is not available in the current environment.")

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            self.export_pcap_file(tmp_path, count=count)
            return tmp_path.read_bytes()
        finally:
            if tmp_path.exists():
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()
            self._timestamps.clear()
