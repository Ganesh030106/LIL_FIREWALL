from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(slots=True)
class Signature:
    id: int
    name: str
    pattern: str
    severity: str
    category: str
    description: str = ""


@dataclass(slots=True)
class IDSAlert:
    signature_id: int
    signature_name: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    payload_snippet: str
    severity: str
    timestamp: float = 0.0


class IDSEngine:
    def __init__(self) -> None:
        self._signatures: Dict[int, Signature] = {}
        self._compiled_patterns: Dict[int, re.Pattern] = {}
        self._next_id = 1
        self._lock = threading.RLock()

    def add_signature(self, name: str, pattern: str, severity: str, category: str, description: str = "") -> Signature:
        with self._lock:
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")

            signature = Signature(
                id=self._next_id,
                name=name,
                pattern=pattern,
                severity=severity,
                category=category,
                description=description,
            )
            self._signatures[self._next_id] = signature
            try:
                self._compiled_patterns[self._next_id] = re.compile(pattern, re.IGNORECASE | re.DOTALL)
            except re.error:
                pass
            self._next_id += 1
            return signature

    def delete_signature(self, sig_id: int) -> bool:
        with self._lock:
            if sig_id in self._signatures:
                del self._signatures[sig_id]
                if sig_id in self._compiled_patterns:
                    del self._compiled_patterns[sig_id]
                return True
            return False

    def detect(self, src_ip: str, dst_ip: str, src_port: Optional[int], dst_port: Optional[int], protocol: str, payload: str) -> List[IDSAlert]:
        alerts = []
        with self._lock:
            for sig_id, compiled_pattern in self._compiled_patterns.items():
                if compiled_pattern.search(payload):
                    sig = self._signatures[sig_id]
                    alert = IDSAlert(
                        signature_id=sig_id,
                        signature_name=sig.name,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        payload_snippet=payload[:100],
                        severity=sig.severity,
                    )
                    alerts.append(alert)
        return alerts

    def list_signatures(self) -> List[Signature]:
        with self._lock:
            return list(self._signatures.values())

    def get_signature(self, sig_id: int) -> Optional[Signature]:
        with self._lock:
            return self._signatures.get(sig_id)
