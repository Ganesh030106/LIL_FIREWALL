from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

import ipaddress


class RuleAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    REJECT = "reject"


class RulePriority(int, Enum):
    CRITICAL = 1
    HIGH = 5
    NORMAL = 10
    LOW = 20


@dataclass(slots=True)
class FirewallRule:
    id: int
    name: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    action: RuleAction = RuleAction.ALLOW
    priority: RulePriority = RulePriority.NORMAL
    enabled: bool = True
    description: str = ""
    app_name: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    meta: Dict[str, Any] = field(default_factory=dict)

    def matches(self, src_ip: str, dst_ip: str, src_port: Optional[int], dst_port: Optional[int], protocol: str, app_name: Optional[str] = None) -> bool:
        if not self.enabled:
            return False

        if self.app_name:
            if not app_name or (self.app_name.lower() not in app_name.lower()):
                return False

        if self.src_ip and not self._match_ip(src_ip, self.src_ip):
            return False
        if self.dst_ip and not self._match_ip(dst_ip, self.dst_ip):
            return False
        if self.src_port is not None and src_port != self.src_port:
            return False
        if self.dst_port is not None and dst_port != self.dst_port:
            return False
        if self.protocol and self.protocol.upper() != protocol.upper():
            return False

        return True

    @staticmethod
    def _match_ip(ip: str, pattern: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if "/" in pattern:
                return ip_obj in ipaddress.ip_network(pattern, strict=False)
            return str(ip_obj) == pattern
        except ValueError:
            return False


class RuleEngine:
    def __init__(self) -> None:
        self._rules: Dict[int, FirewallRule] = {}
        self._next_id = 1
        self._lock = threading.RLock()
        self._cache_enabled = True
        self._cache: Dict[Tuple[str, str, Optional[int], Optional[int], str], Tuple[RuleAction, Optional[FirewallRule]]] = {}

    def add_rule(
        self,
        name: str,
        action: RuleAction,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        priority: RulePriority = RulePriority.NORMAL,
        description: str = "",
        app_name: Optional[str] = None,
    ) -> FirewallRule:
        with self._lock:
            rule = FirewallRule(
                id=self._next_id,
                name=name,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                action=action,
                priority=priority,
                description=description,
                app_name=app_name,
            )
            self._rules[self._next_id] = rule
            self._next_id += 1
            self._invalidate_cache()
            return rule

    def delete_rule(self, rule_id: int) -> bool:
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                self._invalidate_cache()
                return True
            return False

    def update_rule(self, rule_id: int, **kwargs) -> Optional[FirewallRule]:
        with self._lock:
            if rule_id not in self._rules:
                return None
            rule = self._rules[rule_id]
            for key, value in kwargs.items():
                if hasattr(rule, key) and key != "id":
                    setattr(rule, key, value)
            self._invalidate_cache()
            return rule

    def get_rule(self, rule_id: int) -> Optional[FirewallRule]:
        with self._lock:
            return self._rules.get(rule_id)

    def list_rules(self) -> List[FirewallRule]:
        with self._lock:
            return sorted(self._rules.values(), key=lambda r: (r.priority, r.id))

    def evaluate(self, src_ip: str, dst_ip: str, src_port: Optional[int], dst_port: Optional[int], protocol: str, app_name: Optional[str] = None) -> tuple[RuleAction, Optional[FirewallRule]]:
        cache_key = (src_ip, dst_ip, src_port, dst_port, protocol, app_name)
        if self._cache_enabled and cache_key in self._cache:
            return self._cache[cache_key]

        result: Tuple[RuleAction, Optional[FirewallRule]]
        with self._lock:
            sorted_rules = sorted(self._rules.values(), key=lambda r: r.priority)
            for rule in sorted_rules:
                if rule.matches(src_ip, dst_ip, src_port, dst_port, protocol, app_name):
                    result = (rule.action, rule)
                    if self._cache_enabled:
                        self._cache[cache_key] = result
                    return result

        default_action = RuleAction.ALLOW
        result = (default_action, None)
        if self._cache_enabled:
            self._cache[cache_key] = result
        return result

    def _invalidate_cache(self) -> None:
        self._cache.clear()

    def disable_cache(self) -> None:
        self._cache_enabled = False
        self._cache.clear()

    def enable_cache(self) -> None:
        self._cache_enabled = True
