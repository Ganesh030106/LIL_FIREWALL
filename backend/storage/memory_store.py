from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import asdict
from typing import Any, Deque, Dict, List, Optional

from api.schemas import AlertRecord, now_utc


class AlertStore:
    def __init__(self, max_items: int = 500, on_alert: Any = None) -> None:
        self._items: Deque[AlertRecord] = deque(maxlen=max_items)
        self._lock = threading.RLock()
        self._counter = 0
        self._on_alert = on_alert

    def set_on_alert(self, callback: Any) -> None:
        self._on_alert = callback

    def add(
        self,
        source: str,
        severity: str,
        category: str,
        message: str,
        meta: Dict[str, Any],
        status: str = "new",
        assignee: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> AlertRecord:
        with self._lock:
            self._counter += 1
            record = AlertRecord(
                id=self._counter,
                timestamp=now_utc(),
                source=source,
                severity=severity,
                category=category,
                message=message,
                meta=meta,
                status=status or "new",
                assignee=assignee,
                notes=notes,
            )
            self._items.append(record)
            if self._on_alert:
                try:
                    self._on_alert(record)
                except Exception:
                    pass
            return record

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [asdict(item) for item in list(self._items)]

    def update_triage(
        self,
        alert_id: int,
        status: Optional[str] = None,
        assignee: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> bool:
        with self._lock:
            for item in self._items:
                if item.id == alert_id:
                    if status is not None:
                        item.status = status
                    if assignee is not None:
                        item.assignee = assignee
                    if notes is not None:
                        item.notes = notes
                    return True
        return False

    def bulk_update(self, alert_ids: List[int], action: str, status_value: Optional[str] = None) -> int:
        with self._lock:
            count = 0
            id_set = set(alert_ids)
            if action == "delete":
                new_items = deque([item for item in self._items if item.id not in id_set], maxlen=self._items.maxlen)
                count = len(self._items) - len(new_items)
                self._items = new_items
            elif action == "status" and status_value:
                for item in self._items:
                    if item.id in id_set:
                        item.status = status_value
                        count += 1
            return count


class MetricsStore:
    def __init__(self, watch_directory: str = ".") -> None:
        self._lock = threading.RLock()
        self.packet_timestamps: Deque[float] = deque()
        self.port_windows: Dict[str, Deque[tuple[float, int]]] = defaultdict(deque)
        self.fs_events: Deque[float] = deque()
        self.protocol_breakdown: Dict[str, int] = defaultdict(int)
        self.port_activity: Dict[int, Dict[str, Any]] = {}
        self.source_ip_activity: Dict[str, Dict[str, Any]] = {}
        self.packet_velocity = 0.0
        self.port_scan_active = False
        self.ransomware_rate = 0.0
        self.last_packet_seen = 0.0
        self.watch_directory = watch_directory
        # Historical telemetry
        self.web_searches: Deque[Dict[str, Any]] = deque(maxlen=2000)
        self.file_shares: Deque[Dict[str, Any]] = deque(maxlen=2000)
        self.port_history: Deque[Dict[str, Any]] = deque(maxlen=5000)
        self.ip_history: Dict[str, Deque[Dict[str, Any]]] = defaultdict(lambda: deque(maxlen=2000))
        # Active connections: key -> {src,dst,protocol,port,last_seen}
        self.current_connections: Dict[str, Dict[str, Any]] = {}

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "current_packet_velocity": round(self.packet_velocity, 2),
                "port_monitoring_active": bool(self.port_scan_active),
                "file_change_rate": round(self.ransomware_rate, 2),
                "watch_directory": str(self.watch_directory),
                "protocol_breakdown": dict(self.protocol_breakdown),
            }

    # Historical APIs
    def add_search(self, who: str, query: str, url: str | None = None, meta: Dict[str, Any] | None = None) -> None:
        with self._lock:
            entry = {"timestamp": now_utc(), "who": who, "query": query, "url": url, "meta": meta or {}}
            self.web_searches.appendleft(entry)

    def list_searches(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.web_searches)[:limit]

    def add_file_share(self, who: str, filename: str, dest_ip: str | None = None, meta: Dict[str, Any] | None = None) -> None:
        with self._lock:
            entry = {"timestamp": now_utc(), "who": who, "filename": filename, "dest_ip": dest_ip, "meta": meta or {}}
            self.file_shares.appendleft(entry)

    def list_file_shares(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.file_shares)[:limit]

    def add_port_activity(self, src_ip: str, dst_ip: str | None, port: int, protocol: str, direction: str) -> None:
        with self._lock:
            entry = {"timestamp": now_utc(), "src": src_ip, "dst": dst_ip, "port": port, "protocol": protocol, "direction": direction}
            self.port_history.appendleft(entry)
            key = f"{src_ip}:{port}->{dst_ip}"
            self.current_connections[key] = {"src": src_ip, "dst": dst_ip, "port": port, "protocol": protocol, "last_seen": now_utc(), "direction": direction}

    def list_port_history(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.port_history)[:limit]

    def add_ip_access(self, ip: str, who: str | None = None, meta: Dict[str, Any] | None = None) -> None:
        with self._lock:
            entry = {"timestamp": now_utc(), "ip": ip, "who": who, "meta": meta or {}}
            self.ip_history[ip].appendleft(entry)

    def list_ip_history(self, ip: str | None = None, limit: int = 200) -> Dict[str, Any] | List[Dict[str, Any]]:
        with self._lock:
            if ip:
                return list(self.ip_history.get(ip, []))[:limit]
            # return aggregated keys
            return {k: list(v)[:limit] for k, v in self.ip_history.items()}

    def list_current_connections(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.current_connections.values())
