"""Autonomous Response Engine for Volcano AI Firewall.
Provides automated threat containment (blocking, quarantine, rate limiting)
with strict allowlist protection, rule engine integration, and auto-expiring unblocks.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional

from config import get_settings

logger = logging.getLogger("volcano.response_engine")


class ResponseAction(str, Enum):
    BLOCK = "block"
    QUARANTINE = "quarantine"
    RATE_LIMIT = "rate_limit"
    ISOLATE = "isolate"
    ALERT = "alert"


@dataclass(slots=True)
class AutonomousResponse:
    id: int
    action: ResponseAction
    target_ip: str
    target_port: Optional[int]
    duration: float
    reason: str
    created_at: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.created_at == 0.0:
            self.created_at = time.time()
        if self.metadata is None:
            self.metadata = {}

    def is_expired(self) -> bool:
        if self.duration <= 0:
            return False  # Permanent until manually lifted
        return time.time() - self.created_at > self.duration


class ResponseEngine:
    """Manages active containment actions and lifecycle with safe allowlist protections."""

    def __init__(
        self,
        rule_engine: Optional[Any] = None,
        alerts: Optional[Any] = None,
        db: Optional[Any] = None,
        ws_manager: Optional[Any] = None,
        settings: Optional[Any] = None,
        enforcement_backend: Optional[Any] = None,
        dry_run: Optional[bool] = None,
    ) -> None:
        self.rule_engine = rule_engine
        self.alerts = alerts
        self.db = db
        self.ws_manager = ws_manager
        self.settings = settings
        self.enforcement_backend = enforcement_backend
        self.dry_run = dry_run
        self._responses: Dict[int, AutonomousResponse] = {}
        self._next_id = 1
        self._lock = threading.RLock()
        self._snapshots: Deque[Dict[str, Any]] = deque(maxlen=10)
        self._callbacks: Dict[ResponseAction, List[Callable]] = {action: [] for action in ResponseAction}
        self._running = True
        self._cleaner_thread = threading.Thread(target=self._auto_unblock_loop, daemon=True)
        self._cleaner_thread.start()

    def set_dependencies(
        self,
        rule_engine: Optional[Any] = None,
        alerts: Optional[Any] = None,
        db: Optional[Any] = None,
        ws_manager: Optional[Any] = None,
        settings: Optional[Any] = None,
        enforcement_backend: Optional[Any] = None,
        dry_run: Optional[bool] = None,
    ) -> None:
        """Inject or update runtime dependencies."""
        if rule_engine:
            self.rule_engine = rule_engine
        if alerts:
            self.alerts = alerts
        if db:
            self.db = db
        if ws_manager:
            self.ws_manager = ws_manager
        if settings:
            self.settings = settings
        if enforcement_backend:
            self.enforcement_backend = enforcement_backend
        if dry_run is not None:
            self.dry_run = dry_run

    def is_dry_run(self) -> bool:
        """Check if containment actions should be simulated (dry_run mode)."""
        if self.dry_run is not None:
            return bool(self.dry_run)
        cfg = self.settings or get_settings()
        if getattr(cfg, "containment_dry_run", False):
            return True
        c_mode = getattr(cfg, "containment_mode", "live")
        return c_mode.lower().strip() == "dry_run"

    def take_snapshot(self) -> Dict[str, Any]:
        """Capture point-in-time snapshot of active firewall containment state."""
        with self._lock:
            rule_list: List[Dict[str, Any]] = []
            if self.rule_engine:
                for r in self.rule_engine.list_rules():
                    rule_list.append({
                        "id": r.id,
                        "name": r.name,
                        "src_ip": r.src_ip,
                        "dst_ip": r.dst_ip,
                        "src_port": r.src_port,
                        "dst_port": r.dst_port,
                        "protocol": r.protocol,
                        "action": r.action.value if hasattr(r.action, "value") else str(r.action),
                        "priority": r.priority.value if hasattr(r.priority, "value") else int(r.priority),
                        "enabled": r.enabled,
                        "description": r.description,
                    })

            responses_state: Dict[int, Dict[str, Any]] = {}
            for rid, resp in self._responses.items():
                responses_state[rid] = {
                    "action": resp.action.value,
                    "target_ip": resp.target_ip,
                    "target_port": resp.target_port,
                    "duration": resp.duration,
                    "reason": resp.reason,
                    "created_at": resp.created_at,
                    "metadata": dict(resp.metadata),
                }

            enforcement_snap = None
            if self.enforcement_backend and hasattr(self.enforcement_backend, "snapshot"):
                try:
                    enforcement_snap = self.enforcement_backend.snapshot()
                except Exception as exc:
                    logger.warning("Could not snapshot enforcement backend: %s", exc)

            snapshot_data = {
                "timestamp": time.time(),
                "rules": rule_list,
                "responses": responses_state,
                "enforcement_snapshot": enforcement_snap,
            }
            self._snapshots.append(snapshot_data)
            return snapshot_data

    def rollback(self, dry_run: bool = False, username: str = "admin") -> Dict[str, Any]:
        """Restore most recent snapshot. If dry_run=True, returns diff without applying."""
        with self._lock:
            if not self._snapshots:
                return {
                    "success": False,
                    "message": "No snapshots available for rollback",
                    "diff": {},
                    "dry_run": dry_run,
                }

            # Target snapshot is the most recent
            target_snap = self._snapshots[-1]

            # Compute diff between current state and target snapshot
            current_rule_ids = set()
            current_rules_map = {}
            if self.rule_engine:
                for r in self.rule_engine.list_rules():
                    current_rule_ids.add(r.id)
                    current_rules_map[r.id] = r.name

            target_rules = target_snap.get("rules", [])
            target_rule_ids = {r["id"] for r in target_rules}

            rules_to_remove = [current_rules_map[rid] for rid in (current_rule_ids - target_rule_ids)]
            rules_to_restore = [r["name"] for r in target_rules if r["id"] not in current_rule_ids]

            diff = {
                "snapshot_timestamp": target_snap["timestamp"],
                "rules_to_restore_count": len(rules_to_restore),
                "rules_to_restore": rules_to_restore,
                "rules_to_remove_count": len(rules_to_remove),
                "rules_to_remove": rules_to_remove,
            }

            if dry_run:
                return {
                    "success": True,
                    "dry_run": True,
                    "message": "Rollback simulated. State left untouched.",
                    "diff": diff,
                }

            # Pop the target snapshot for live restoration
            snap = self._snapshots.pop()

            # 1. Restore RuleEngine rules
            if self.rule_engine:
                from core.rule_engine import FirewallRule, RuleAction, RulePriority
                self.rule_engine._rules.clear()
                self.rule_engine._cache.clear()
                for rdata in snap.get("rules", []):
                    rule_obj = FirewallRule(
                        id=rdata["id"],
                        name=rdata["name"],
                        src_ip=rdata["src_ip"],
                        dst_ip=rdata["dst_ip"],
                        src_port=rdata["src_port"],
                        dst_port=rdata["dst_port"],
                        protocol=rdata["protocol"],
                        action=RuleAction(rdata["action"]),
                        priority=RulePriority(rdata["priority"]),
                        enabled=rdata["enabled"],
                        description=rdata["description"],
                    )
                    self.rule_engine._rules.append(rule_obj)

            # 2. Restore active responses
            self._responses.clear()
            for rid_val, rdict in snap.get("responses", {}).items():
                rid = int(rid_val)
                self._responses[rid] = AutonomousResponse(
                    id=rid,
                    action=ResponseAction(rdict["action"]),
                    target_ip=rdict["target_ip"],
                    target_port=rdict["target_port"],
                    duration=rdict["duration"],
                    reason=rdict["reason"],
                    created_at=rdict["created_at"],
                    metadata=dict(rdict["metadata"]),
                )

            # 3. Restore enforcement backend if present
            if self.enforcement_backend and snap.get("enforcement_snapshot"):
                try:
                    self.enforcement_backend.restore(snap["enforcement_snapshot"])
                except Exception as exc:
                    logger.warning("Error restoring enforcement backend: %s", exc)

            # 4. Audit rollback
            if self.db:
                try:
                    self.db.log_audit(
                        username,
                        "containment_rollback",
                        "containment",
                        {"diff": diff, "dry_run": False},
                        status="success",
                    )
                except Exception:
                    pass

            return {
                "success": True,
                "dry_run": False,
                "message": "Containment successfully rolled back to prior snapshot.",
                "diff": diff,
                "restored_rules_count": len(snap.get("rules", [])),
            }

    def register_callback(self, action: ResponseAction, callback: Callable) -> None:
        with self._lock:
            if action in self._callbacks:
                self._callbacks[action].append(callback)

    def is_allowlisted(self, ip: str) -> bool:
        """Check if an IP address is protected by the allowlist."""
        if not ip:
            return True
        cfg = self.settings or get_settings()

        # Check exact string match
        if ip in cfg.allowlist_ips:
            return True

        # Check IP network/range
        try:
            target_addr = ipaddress.ip_address(ip)
            if target_addr.is_loopback or target_addr.is_unspecified:
                return True
            for allowed in cfg.allowlist_ips:
                try:
                    if "/" in allowed:
                        if target_addr in ipaddress.ip_network(allowed, strict=False):
                            return True
                    else:
                        if target_addr == ipaddress.ip_address(allowed):
                            return True
                except ValueError:
                    pass
        except ValueError:
            pass

        return False

    def trigger_response(
        self,
        action: ResponseAction,
        target_ip: str,
        target_port: Optional[int] = None,
        duration: float = 300.0,
        reason: str = "",
    ) -> AutonomousResponse:
        """Execute containment action while enforcing allowlist protections."""
        clean_ip = target_ip.strip()

        # Enforce allowlist protection
        if action in (ResponseAction.BLOCK, ResponseAction.QUARANTINE, ResponseAction.ISOLATE):
            if self.is_allowlisted(clean_ip):
                logger.warning("Attempted containment on allowlisted IP %s rejected.", clean_ip)
                return AutonomousResponse(
                    id=0,
                    action=action,
                    target_ip=clean_ip,
                    target_port=target_port,
                    duration=duration,
                    reason=f"Rejected: IP {clean_ip} is protected by system allowlist.",
                    metadata={"allowlisted": True, "blocked": False},
                )

        # Capture snapshot before any state modification
        self.take_snapshot()

        with self._lock:
            is_dry = self.is_dry_run()
            meta: Dict[str, Any] = {"blocked": not is_dry, "dry_run": is_dry}
            if is_dry:
                meta["simulated"] = True

            # If not dry run, apply live firewall and enforcement rules
            if not is_dry:
                if self.rule_engine and action == ResponseAction.BLOCK:
                    try:
                        from core.rule_engine import RuleAction, RulePriority
                        rule = self.rule_engine.add_rule(
                            name=f"Auto Block: {clean_ip}",
                            action=RuleAction.DENY,
                            src_ip=clean_ip,
                            dst_port=target_port,
                            priority=RulePriority.HIGH,
                            description=f"Autonomous response: {reason} (expires in {int(duration)}s)",
                        )
                        meta["rule_id"] = rule.id
                    except Exception as exc:
                        logger.warning("Failed to inject rule into rule_engine: %s", exc)

                if self.enforcement_backend and action == ResponseAction.BLOCK:
                    try:
                        self.enforcement_backend.apply_block(clean_ip, ttl=duration)
                    except Exception as exc:
                        logger.warning("Failed to apply block on enforcement backend: %s", exc)

            response = AutonomousResponse(
                id=self._next_id,
                action=action,
                target_ip=clean_ip,
                target_port=target_port,
                duration=duration,
                reason=reason,
                metadata=meta,
            )
            self._responses[self._next_id] = response
            self._next_id += 1

            # Dispatch callbacks
            if action in self._callbacks:
                for callback in self._callbacks[action]:
                    try:
                        callback(response)
                    except Exception as exc:
                        logger.error("Callback error in ResponseEngine: %s", exc)

            return response

    def unblock_ip(self, ip: str) -> bool:
        """Lift all active blocks on a specific IP immediately."""
        clean_ip = ip.strip()
        unblocked_any = False
        with self._lock:
            for response in self._responses.values():
                if response.target_ip == clean_ip and not response.metadata.get("unblocked", False):
                    self._lift_containment(response)
                    unblocked_any = True
        return unblocked_any

    def _lift_containment(self, response: AutonomousResponse) -> None:
        """Remove firewall rule and emit unblock event."""
        # Capture snapshot before removal
        self.take_snapshot()

        response.metadata["unblocked"] = True
        rule_id = response.metadata.get("rule_id")

        if rule_id and self.rule_engine:
            try:
                self.rule_engine.delete_rule(rule_id)
                logger.info("Removed auto-block firewall rule #%d for %s", rule_id, response.target_ip)
            except Exception as exc:
                logger.warning("Error deleting rule #%d: %s", rule_id, exc)

        if self.enforcement_backend and hasattr(self.enforcement_backend, "remove_block"):
            try:
                self.enforcement_backend.remove_block(response.target_ip)
            except Exception as exc:
                logger.warning("Error removing block on enforcement backend: %s", exc)

        if self.alerts:
            self.alerts.add(
                source="response_engine",
                severity="info",
                category="Auto Unblock",
                message=f"Autonomous block for IP {response.target_ip} has expired and was lifted.",
                meta={"target_ip": response.target_ip, "duration": response.duration},
            )

        if self.db:
            try:
                self.db.log_audit("system", "auto_unblock", f"ip:{response.target_ip}", {"response_id": response.id})
            except Exception:
                pass

    def _auto_unblock_loop(self) -> None:
        """Background daemon periodically checking and reverting expired blocks."""
        while self._running:
            time.sleep(2.0)
            try:
                with self._lock:
                    for response in list(self._responses.values()):
                        if response.is_expired() and not response.metadata.get("unblocked", False):
                            self._lift_containment(response)
            except Exception as exc:
                logger.debug("Error in auto unblock loop: %s", exc)

    def list_active_responses(self) -> List[AutonomousResponse]:
        with self._lock:
            return [r for r in self._responses.values() if not r.is_expired() and not r.metadata.get("unblocked")]

    def is_ip_blocked(self, ip: str) -> bool:
        with self._lock:
            for response in self._responses.values():
                if (
                    response.target_ip == ip
                    and response.action == ResponseAction.BLOCK
                    and not response.is_expired()
                    and not response.metadata.get("unblocked")
                ):
                    return True
            return False

    def get_response_stats(self) -> Dict[str, Any]:
        with self._lock:
            active = [r for r in self._responses.values() if not r.is_expired() and not r.metadata.get("unblocked")]
            action_counts = {}
            for action in ResponseAction:
                action_counts[action.value] = sum(1 for r in active if r.action == action)

            return {
                "total_active": len(active),
                "by_action": action_counts,
                "total_triggered": len(self._responses),
            }

    def stop(self) -> None:
        self._running = False
