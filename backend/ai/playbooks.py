"""Playbooks Module for Volcano AI Firewall (Phase 2).
Provides schema validation, directory loading, and deterministic sequential execution
for autonomous response workflows with safe allowlist protections and full step auditing.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from ai.response_engine import ResponseAction, ResponseEngine

logger = logging.getLogger("volcano.playbooks")

SUPPORTED_ACTIONS: Set[str] = {
    "block_ip",
    "notify",
    "attach_pcap",
    "create_alert_note",
}

FORBIDDEN_ACTIONS: Set[str] = {
    "killswitch",
    "isolate",
    "isolate_host",
    "disable_interface",
    "network_disconnect",
}

VALID_CHANNELS: Set[str] = {"slack", "discord", "telegram", "email", "smtp"}
VALID_SEVERITIES: Set[str] = {"low", "medium", "high", "critical"}


class PlaybookValidationError(Exception):
    """Raised when a playbook YAML file fails structural or semantic validation."""
    pass


def validate_playbook_schema(data: Any, source_name: str = "playbook") -> Dict[str, Any]:
    """Validate a parsed playbook against the Volcano specification.

    Raises PlaybookValidationError with detailed explanation on failure.
    """
    if not isinstance(data, dict):
        raise PlaybookValidationError(f"[{source_name}] Root of playbook must be a mapping/dictionary.")

    # 1. Name validation
    name = data.get("name")
    if not name or not isinstance(name, str) or not name.strip():
        raise PlaybookValidationError(f"[{source_name}] Missing or empty required field: 'name'.")

    # 2. Match criteria validation
    match_section = data.get("match")
    if match_section is not None:
        if not isinstance(match_section, dict):
            raise PlaybookValidationError(f"[{source_name}] Field 'match' must be a dictionary.")
        min_sev = match_section.get("min_severity")
        if min_sev and min_sev.lower() not in VALID_SEVERITIES:
            raise PlaybookValidationError(
                f"[{source_name}] Invalid min_severity '{min_sev}'. Must be one of: {sorted(list(VALID_SEVERITIES))}"
            )

    # 3. Actions list validation
    actions = data.get("actions")
    if not actions or not isinstance(actions, list):
        raise PlaybookValidationError(f"[{source_name}] 'actions' must be a non-empty list of action definitions.")

    for idx, act in enumerate(actions, start=1):
        if not isinstance(act, dict):
            raise PlaybookValidationError(f"[{source_name}] Action #{idx} must be a dictionary.")

        act_type = act.get("type")
        if not act_type or not isinstance(act_type, str):
            raise PlaybookValidationError(f"[{source_name}] Action #{idx} missing required field 'type'.")

        act_type_clean = act_type.strip().lower()

        # Reject prohibited killswitch actions
        if act_type_clean in FORBIDDEN_ACTIONS:
            raise PlaybookValidationError(
                f"[{source_name}] Action #{idx} '{act_type}' is forbidden. "
                "Playbooks must not be able to run killswitch actions."
            )

        # Reject unknown action types
        if act_type_clean not in SUPPORTED_ACTIONS:
            raise PlaybookValidationError(
                f"[{source_name}] Unknown action type '{act_type}' in action #{idx}. "
                f"Supported actions are: {sorted(list(SUPPORTED_ACTIONS))}"
            )

        # Validate action-specific parameters
        if act_type_clean == "block_ip":
            dur = act.get("duration_seconds")
            if dur is None:
                raise PlaybookValidationError(
                    f"[{source_name}] Action #{idx} (block_ip) missing required field 'duration_seconds'."
                )
            try:
                dur_val = float(dur)
            except (ValueError, TypeError):
                raise PlaybookValidationError(
                    f"[{source_name}] Action #{idx} (block_ip) duration_seconds must be a valid number."
                )
            if dur_val < 1.0 or dur_val > 2592000.0:
                raise PlaybookValidationError(
                    f"[{source_name}] Action #{idx} (block_ip) duration_seconds {dur_val} out of range. "
                    "Must be between 1 and 2,592,000 seconds (30 days)."
                )

        elif act_type_clean == "notify":
            channels = act.get("channels")
            if not channels or not isinstance(channels, list):
                raise PlaybookValidationError(
                    f"[{source_name}] Action #{idx} (notify) missing or invalid required field 'channels' (must be a list)."
                )
            for ch in channels:
                if not isinstance(ch, str) or ch.strip().lower() not in VALID_CHANNELS:
                    raise PlaybookValidationError(
                        f"[{source_name}] Action #{idx} (notify) invalid channel '{ch}'. "
                        f"Supported channels: {sorted(list(VALID_CHANNELS))}"
                    )

        elif act_type_clean == "attach_pcap":
            packets = act.get("packets", 100)
            try:
                pkt_val = int(packets)
            except (ValueError, TypeError):
                raise PlaybookValidationError(
                    f"[{source_name}] Action #{idx} (attach_pcap) 'packets' must be an integer."
                )
            if pkt_val < 1 or pkt_val > 1000:
                raise PlaybookValidationError(
                    f"[{source_name}] Action #{idx} (attach_pcap) 'packets' {pkt_val} out of range. Must be 1 to 1000."
                )

        elif act_type_clean == "create_alert_note":
            note = act.get("note")
            if not note or not isinstance(note, str) or not note.strip():
                raise PlaybookValidationError(
                    f"[{source_name}] Action #{idx} (create_alert_note) missing or empty required field 'note'."
                )

    return data


class PlaybookLoader:
    """Discovers, validates, and loads playbook YAML configurations from the playbooks directory."""

    def __init__(self, directory: Optional[Path | str] = None) -> None:
        self.directory = Path(directory) if directory else (Path(__file__).resolve().parent.parent / "playbooks")
        self.playbooks: Dict[str, Dict[str, Any]] = {}
        self.errors: Dict[str, str] = {}
        self.load()

    def load(self) -> Tuple[int, int]:
        """Load and validate all playbooks in the directory and subdirectories."""
        self.playbooks.clear()
        self.errors.clear()

        if not self.directory.exists():
            try:
                self.directory.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            return 0, 0

        # Scan for yaml and yml files
        yaml_files = sorted(list(self.directory.glob("**/*.yaml")) + list(self.directory.glob("**/*.yml")))

        for path in yaml_files:
            file_key = str(path.relative_to(self.directory))
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw_data = yaml.safe_load(f)

                if not raw_data:
                    self.errors[file_key] = "File is empty or contains no YAML mapping."
                    continue

                validated = validate_playbook_schema(raw_data, source_name=file_key)
                name = validated["name"]
                self.playbooks[name] = validated
                logger.info("Loaded playbook '%s' from %s", name, file_key)
            except yaml.YAMLError as y_err:
                self.errors[file_key] = f"YAML syntax error: {y_err}"
            except PlaybookValidationError as v_err:
                self.errors[file_key] = str(v_err)
            except Exception as exc:
                self.errors[file_key] = f"Unexpected load error: {exc}"

        return len(self.playbooks), len(self.errors)

    def reload(self) -> Tuple[int, int]:
        return self.load()

    def list_playbooks(self) -> List[Dict[str, Any]]:
        """Return status for API listing."""
        results = []
        for name, pb in self.playbooks.items():
            results.append({
                "name": name,
                "status": "valid",
                "description": pb.get("description", ""),
                "match": pb.get("match", {}),
                "actions_count": len(pb.get("actions", [])),
                "actions": [a.get("type") for a in pb.get("actions", [])],
                "error": None,
            })
        for file_key, err in self.errors.items():
            results.append({
                "name": file_key,
                "status": "invalid",
                "description": "",
                "match": {},
                "actions_count": 0,
                "actions": [],
                "error": err,
            })
        return sorted(results, key=lambda x: x["name"])


class PlaybookExecutor:
    """Executes validated playbook action chains in strict order with safe allowlist protections and auditing."""

    def __init__(
        self,
        response_engine: Optional[ResponseEngine] = None,
        notifier: Optional[Any] = None,
        pcap_buffer: Optional[Any] = None,
        alerts: Optional[Any] = None,
        db: Optional[Any] = None,
        dry_run: bool = False,
    ) -> None:
        self.response_engine = response_engine
        self.notifier = notifier
        self.pcap_buffer = pcap_buffer
        self.alerts = alerts
        self.db = db
        self.dry_run = dry_run

    def _record_audit(
        self,
        playbook_name: str,
        action: str,
        resource: str,
        changes: Dict[str, Any],
        status: str,
    ) -> None:
        if self.db and hasattr(self.db, "log_audit"):
            try:
                self.db.log_audit(
                    user_id=f"playbook:{playbook_name}",
                    action=action,
                    resource=resource,
                    changes=changes,
                    status=status,
                )
            except Exception as exc:
                logger.warning("Failed to record audit log for playbook step: %s", exc)

    def execute_playbook(
        self,
        playbook: Dict[str, Any],
        alert: Dict[str, Any],
        dry_run: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Execute all playbook actions in sequence.

        Stops on the first failure. Audits each step.
        """
        pb_name = playbook.get("name", "unknown")
        actions = playbook.get("actions", [])
        is_dry_run = self.dry_run if dry_run is None else dry_run

        executed_steps: List[Dict[str, Any]] = []
        overall_success = True
        halted_reason: Optional[str] = None

        logger.info("Executing playbook '%s' (dry_run=%s)", pb_name, is_dry_run)

        # Extract target IP from alert if available
        meta = alert.get("meta", {})
        target_ip = meta.get("source_ip") or alert.get("source_ip") or alert.get("src_ip") or alert.get("ip")

        for idx, act in enumerate(actions, start=1):
            act_type = act.get("type", "").strip().lower()
            step_record: Dict[str, Any] = {
                "step": idx,
                "type": act_type,
                "dry_run": is_dry_run,
                "status": "pending",
            }

            try:
                if act_type == "block_ip":
                    duration = float(act.get("duration_seconds", 3600))
                    if not target_ip:
                        raise ValueError("No source IP found in alert to block.")

                    # Enforce allowlist invariant
                    if self.response_engine and self.response_engine.is_allowlisted(target_ip):
                        step_record.update({
                            "status": "skipped",
                            "reason": f"IP {target_ip} is protected by system allowlist.",
                            "target_ip": target_ip,
                            "allowlisted": True,
                        })
                        self._record_audit(
                            pb_name,
                            action="block_ip",
                            resource=target_ip,
                            changes={"duration": duration, "allowlisted": True, "dry_run": is_dry_run},
                            status="skipped",
                        )
                        executed_steps.append(step_record)
                        continue

                    step_record["target_ip"] = target_ip
                    step_record["duration"] = duration

                    if is_dry_run:
                        step_record["status"] = "simulated"
                        self._record_audit(
                            pb_name,
                            action="block_ip",
                            resource=target_ip,
                            changes={"duration": duration, "dry_run": True},
                            status="success",
                        )
                    else:
                        if self.response_engine:
                            resp = self.response_engine.trigger_response(
                                action=ResponseAction.BLOCK,
                                target_ip=target_ip,
                                duration=duration,
                                reason=f"Playbook: {pb_name}",
                            )
                            step_record["response_id"] = resp.id
                            step_record["status"] = "success"
                        else:
                            step_record["status"] = "success"
                        self._record_audit(
                            pb_name,
                            action="block_ip",
                            resource=target_ip,
                            changes={"duration": duration, "dry_run": False},
                            status="success",
                        )

                elif act_type == "notify":
                    channels = act.get("channels", ["slack"])
                    msg = act.get("message") or f"Playbook alert: {alert.get('category')} - {alert.get('message')}"
                    step_record["channels"] = channels

                    if is_dry_run:
                        step_record["status"] = "simulated"
                        self._record_audit(
                            pb_name,
                            action="notify",
                            resource=",".join(channels),
                            changes={"message": msg, "dry_run": True},
                            status="success",
                        )
                    else:
                        if self.notifier and hasattr(self.notifier, "dispatch_sync"):
                            self.notifier.dispatch_sync(
                                severity=alert.get("severity", "high"),
                                category=alert.get("category", "Playbook Notification"),
                                message=msg,
                                meta={"playbook": pb_name, "channels": channels},
                            )
                        step_record["status"] = "success"
                        self._record_audit(
                            pb_name,
                            action="notify",
                            resource=",".join(channels),
                            changes={"message": msg, "dry_run": False},
                            status="success",
                        )

                elif act_type == "attach_pcap":
                    packets = int(act.get("packets", 100))
                    step_record["packets"] = packets
                    pcap_len = 0
                    if self.pcap_buffer and hasattr(self.pcap_buffer, "size"):
                        pcap_len = self.pcap_buffer.size()
                    step_record["available_packets"] = pcap_len

                    step_record["status"] = "simulated" if is_dry_run else "success"
                    self._record_audit(
                        pb_name,
                        action="attach_pcap",
                        resource=f"packets:{packets}",
                        changes={"packets_requested": packets, "dry_run": is_dry_run},
                        status="success",
                    )

                elif act_type == "create_alert_note":
                    note = act.get("note", "")
                    alert_id = alert.get("id")
                    step_record["note"] = note
                    step_record["alert_id"] = alert_id

                    if not is_dry_run and self.alerts and alert_id:
                        if hasattr(self.alerts, "update_triage"):
                            self.alerts.update_triage(int(alert_id), notes=note)

                    step_record["status"] = "simulated" if is_dry_run else "success"
                    self._record_audit(
                        pb_name,
                        action="create_alert_note",
                        resource=f"alert:{alert_id}",
                        changes={"note": note, "dry_run": is_dry_run},
                        status="success",
                    )

                executed_steps.append(step_record)

            except Exception as exc:
                step_record["status"] = "failed"
                step_record["error"] = str(exc)
                executed_steps.append(step_record)
                self._record_audit(
                    pb_name,
                    action=act_type,
                    resource=target_ip or "system",
                    changes={"error": str(exc), "step": idx},
                    status="failed",
                )
                overall_success = False
                halted_reason = f"Step #{idx} ({act_type}) failed: {exc}"
                logger.error("Playbook '%s' halted on step #%d: %s", pb_name, idx, exc)
                break  # Stop on the first failure

        return {
            "playbook": pb_name,
            "success": overall_success,
            "dry_run": is_dry_run,
            "steps_count": len(executed_steps),
            "steps": executed_steps,
            "halted_reason": halted_reason,
        }
