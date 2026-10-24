from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(slots=True)
class NATMapping:
    id: int
    internal_ip: str
    external_ip: str
    protocol: str
    enabled: bool = True
    description: str = ""


@dataclass(slots=True)
class NATTranslation:
    internal_ip: str
    internal_port: int
    external_ip: str
    external_port: int
    protocol: str


class NATEngine:
    def __init__(self) -> None:
        self._mappings: Dict[int, NATMapping] = {}
        self._translations: Dict[Tuple[str, int, str], NATTranslation] = {}
        self._next_id = 1
        self._lock = threading.RLock()
        self._external_port_counter = 10000

    def add_mapping(self, internal_ip: str, external_ip: str, protocol: str, description: str = "") -> NATMapping:
        with self._lock:
            mapping = NATMapping(
                id=self._next_id,
                internal_ip=internal_ip,
                external_ip=external_ip,
                protocol=protocol,
                description=description,
            )
            self._mappings[self._next_id] = mapping
            self._next_id += 1
            return mapping

    def delete_mapping(self, mapping_id: int) -> bool:
        with self._lock:
            if mapping_id in self._mappings:
                del self._mappings[mapping_id]
                return True
            return False

    def translate_outbound(
        self, internal_ip: str, internal_port: int, external_ip: str, protocol: str
    ) -> NATTranslation:
        key = (internal_ip, internal_port, protocol)
        with self._lock:
            if key in self._translations:
                return self._translations[key]

            external_port = self._external_port_counter
            self._external_port_counter += 1
            if self._external_port_counter > 65535:
                self._external_port_counter = 10000

            translation = NATTranslation(
                internal_ip=internal_ip,
                internal_port=internal_port,
                external_ip=external_ip,
                external_port=external_port,
                protocol=protocol,
            )
            self._translations[key] = translation
            return translation

    def translate_inbound(self, external_ip: str, external_port: int, protocol: str) -> Optional[NATTranslation]:
        with self._lock:
            for translation in self._translations.values():
                if translation.external_ip == external_ip and translation.external_port == external_port and translation.protocol == protocol:
                    return translation
            return None

    def list_mappings(self) -> list[NATMapping]:
        with self._lock:
            return list(self._mappings.values())

    def list_translations(self) -> list[NATTranslation]:
        with self._lock:
            return list(self._translations.values())
