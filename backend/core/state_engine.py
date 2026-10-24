from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Set


class TCPState(str, Enum):
    CLOSED = "closed"
    LISTEN = "listen"
    SYN_SENT = "syn_sent"
    SYN_RECEIVED = "syn_received"
    ESTABLISHED = "established"
    FIN_WAIT_1 = "fin_wait_1"
    FIN_WAIT_2 = "fin_wait_2"
    CLOSE_WAIT = "close_wait"
    CLOSING = "closing"
    TIME_WAIT = "time_wait"


@dataclass(slots=True)
class TCPSession:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    state: TCPState = TCPState.CLOSED
    created_at: float = 0.0
    last_seen: float = 0.0
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    flags_seen: Set[str] = field(default_factory=set)

    def __post_init__(self):
        if self.flags_seen is None:
            self.flags_seen = set()
        if self.created_at == 0.0:
            self.created_at = time.time()
        if self.last_seen == 0.0:
            self.last_seen = self.created_at

    @property
    def session_key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port)

    def update(self, flags: str, packet_size: int, direction: str) -> None:
        self.last_seen = time.time()
        self.flags_seen.update(flags)

        if direction == "outbound":
            self.packets_sent += 1
            self.bytes_sent += packet_size
        else:
            self.packets_received += 1
            self.bytes_received += packet_size

    def is_expired(self, timeout: float) -> bool:
        return time.time() - self.last_seen > timeout


@dataclass(slots=True)
class UDPFlow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    created_at: float = 0.0
    last_seen: float = 0.0
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    bidirectional: bool = False

    def __post_init__(self):
        if self.created_at == 0.0:
            self.created_at = time.time()
        if self.last_seen == 0.0:
            self.last_seen = self.created_at

    @property
    def flow_key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port)

    def update(self, packet_size: int, direction: str) -> None:
        self.last_seen = time.time()
        if direction == "outbound":
            self.packets_sent += 1
            self.bytes_sent += packet_size
        else:
            self.packets_received += 1
            self.bytes_received += packet_size
            if self.packets_sent > 0:
                self.bidirectional = True

    def is_expired(self, timeout: float) -> bool:
        return time.time() - self.last_seen > timeout


class StateEngine:
    def __init__(self, tcp_timeout: float = 300.0, udp_timeout: float = 60.0) -> None:
        self._tcp_sessions: Dict[tuple, TCPSession] = {}
        self._udp_flows: Dict[tuple, UDPFlow] = {}
        self._lock = threading.RLock()
        self._tcp_timeout = tcp_timeout
        self._udp_timeout = udp_timeout

    def track_tcp(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: str, packet_size: int, direction: str) -> TCPSession:
        key = (src_ip, dst_ip, src_port, dst_port)
        with self._lock:
            if key not in self._tcp_sessions:
                self._tcp_sessions[key] = TCPSession(src_ip, dst_ip, src_port, dst_port)
            session = self._tcp_sessions[key]
            session.update(flags, packet_size, direction)
            self._update_tcp_state(session, flags)
            return session

    def track_udp(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, packet_size: int, direction: str) -> UDPFlow:
        key = (src_ip, dst_ip, src_port, dst_port)
        with self._lock:
            if key not in self._udp_flows:
                self._udp_flows[key] = UDPFlow(src_ip, dst_ip, src_port, dst_port)
            flow = self._udp_flows[key]
            flow.update(packet_size, direction)
            return flow

    def _update_tcp_state(self, session: TCPSession, flags: str) -> None:
        flags_set = set(flags)

        if session.state == TCPState.CLOSED:
            if "S" in flags_set:
                session.state = TCPState.SYN_SENT
        elif session.state == TCPState.SYN_SENT:
            if "SA" in flags_set:
                session.state = TCPState.ESTABLISHED
        elif session.state == TCPState.ESTABLISHED:
            if "F" in flags_set:
                session.state = TCPState.FIN_WAIT_1
        elif session.state == TCPState.FIN_WAIT_1:
            if "FA" in flags_set or "A" in flags_set:
                session.state = TCPState.FIN_WAIT_2
        elif session.state == TCPState.FIN_WAIT_2:
            if "F" in flags_set:
                session.state = TCPState.TIME_WAIT

        if "R" in flags_set:
            session.state = TCPState.CLOSED

    def get_tcp_session(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Optional[TCPSession]:
        key = (src_ip, dst_ip, src_port, dst_port)
        with self._lock:
            return self._tcp_sessions.get(key)

    def get_udp_flow(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Optional[UDPFlow]:
        key = (src_ip, dst_ip, src_port, dst_port)
        with self._lock:
            return self._udp_flows.get(key)

    def list_tcp_sessions(self) -> list[TCPSession]:
        with self._lock:
            return list(self._tcp_sessions.values())

    def list_udp_flows(self) -> list[UDPFlow]:
        with self._lock:
            return list(self._udp_flows.values())

    def cleanup_expired(self) -> tuple[int, int]:
        with self._lock:
            expired_tcp = [k for k, v in self._tcp_sessions.items() if v.is_expired(self._tcp_timeout)]
            expired_udp = [k for k, v in self._udp_flows.items() if v.is_expired(self._udp_timeout)]

            for key in expired_tcp:
                del self._tcp_sessions[key]
            for key in expired_udp:
                del self._udp_flows[key]

            return len(expired_tcp), len(expired_udp)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "tcp_sessions": len(self._tcp_sessions),
                "udp_flows": len(self._udp_flows),
                "tcp_established": sum(1 for s in self._tcp_sessions.values() if s.state == TCPState.ESTABLISHED),
            }
