from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List


class ACLAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(slots=True)
class ACLEntry:
    id: int
    name: str
    subject_type: str
    subject_value: str
    resource: str
    action: ACLAction
    description: str = ""


class ACLEngine:
    def __init__(self) -> None:
        self._entries: Dict[int, ACLEntry] = {}
        self._next_id = 1
        self._lock = threading.RLock()

    def add_entry(
        self, name: str, subject_type: str, subject_value: str, resource: str, action: ACLAction, description: str = ""
    ) -> ACLEntry:
        with self._lock:
            entry = ACLEntry(
                id=self._next_id,
                name=name,
                subject_type=subject_type,
                subject_value=subject_value,
                resource=resource,
                action=action,
                description=description,
            )
            self._entries[self._next_id] = entry
            self._next_id += 1
            return entry

    def delete_entry(self, entry_id: int) -> bool:
        with self._lock:
            if entry_id in self._entries:
                del self._entries[entry_id]
                return True
            return False

    def can_access(self, subject_type: str, subject_value: str, resource: str) -> bool:
        with self._lock:
            for entry in self._entries.values():
                if entry.subject_type == subject_type and entry.subject_value == subject_value and entry.resource == resource:
                    return entry.action == ACLAction.ALLOW
            return False

    def list_entries(self) -> List[ACLEntry]:
        with self._lock:
            return list(self._entries.values())

    def get_entries_for_subject(self, subject_type: str, subject_value: str) -> List[ACLEntry]:
        with self._lock:
            return [e for e in self._entries.values() if e.subject_type == subject_type and e.subject_value == subject_value]

    def get_entries_for_resource(self, resource: str) -> List[ACLEntry]:
        with self._lock:
            return [e for e in self._entries.values() if e.resource == resource]
