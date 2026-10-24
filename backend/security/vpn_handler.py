from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional


class VPNStatus(str, Enum):
    CONNECTED = "connected"
    CONNECTING = "connecting"
    DISCONNECTED = "disconnected"
    ERROR = "error"


@dataclass(slots=True)
class VPNSession:
    id: int
    client_ip: str
    tunnel_ip: str
    gateway: str
    protocol: str
    status: VPNStatus = VPNStatus.CONNECTING
    created_at: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    authenticated: bool = False


class VPNHandler:
    def __init__(self) -> None:
        self._sessions: Dict[int, VPNSession] = {}
        self._next_id = 1
        self._lock = threading.RLock()

    def create_session(self, client_ip: str, tunnel_ip: str, gateway: str, protocol: str) -> VPNSession:
        with self._lock:
            session = VPNSession(
                id=self._next_id,
                client_ip=client_ip,
                tunnel_ip=tunnel_ip,
                gateway=gateway,
                protocol=protocol,
            )
            self._sessions[self._next_id] = session
            self._next_id += 1
            return session

    def update_session_status(self, session_id: int, status: VPNStatus, authenticated: bool = False) -> Optional[VPNSession]:
        with self._lock:
            if session_id in self._sessions:
                session = self._sessions[session_id]
                session.status = status
                session.authenticated = authenticated
                return session
            return None

    def terminate_session(self, session_id: int) -> bool:
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    def get_session(self, session_id: int) -> Optional[VPNSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def list_sessions(self) -> list[VPNSession]:
        with self._lock:
            return list(self._sessions.values())

    def get_active_sessions(self) -> list[VPNSession]:
        with self._lock:
            return [s for s in self._sessions.values() if s.status == VPNStatus.CONNECTED]
