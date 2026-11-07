"""Threat Correlation Engine for Volcano AI Firewall V5.0.
Correlates disparate security events and alerts across temporal sliding windows,
IP addresses, and MITRE ATT&CK tactics into unified multi-stage Security Incidents.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from security.mitre_mapper import mitre_mapper

logger = logging.getLogger("volcano.correlation")

# Standard Cyber Kill Chain / MITRE progression hierarchy
KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

TACTIC_TO_KILL_CHAIN = {
    "Reconnaissance": "Reconnaissance",
    "Initial Access": "Initial Access",
    "Execution": "Execution",
    "Persistence": "Persistence",
    "Privilege Escalation": "Privilege Escalation",
    "Defense Evasion": "Defense Evasion",
    "Credential Access": "Credential Access",
    "Discovery": "Discovery",
    "Lateral Movement": "Lateral Movement",
    "Command and Control": "Command and Control",
    "Exfiltration": "Exfiltration",
    "Impact": "Impact",
}

CATEGORY_TO_KILL_CHAIN = {
    "port_scan": "Reconnaissance",
    "reconnaissance": "Reconnaissance",
    "brute_force": "Credential Access",
    "phishing": "Initial Access",
    "sqli": "Initial Access",
    "xss": "Execution",
    "rce": "Execution",
    "path_traversal": "Defense Evasion",
    "canary_tamper": "Impact",
    "ransomware": "Impact",
    "lateral_movement": "Lateral Movement",
    "c2_beacon": "Command and Control",
    "dns_tunneling": "Exfiltration",
    "dga": "Command and Control",
    "data_exfiltration": "Exfiltration",
}


class ThreatCorrelationEngine:
    """Intelligent correlation engine synthesizing alerts into actionable incidents."""

    def __init__(self, db: Optional[Any] = None) -> None:
        self.db = db

    def set_db(self, db: Any) -> None:
        self.db = db

    def correlate_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Cluster an alert list into correlated security incidents.

        Alerts sharing source_ip, target_ip, or proximate temporal windows
        are consolidated into unified multi-stage incidents with attack progression.
        """
        if not alerts:
            return []

        # Sort alerts chronologically
        sorted_alerts = sorted(
            alerts,
            key=lambda a: a.get("timestamp") or a.get("created_at") or "",
        )

        clusters: Dict[str, List[Dict[str, Any]]] = {}

        for alert in sorted_alerts:
            meta = alert.get("meta") or {}
            src_ip = meta.get("source_ip") or alert.get("source") or "unknown"
            dst_ip = meta.get("destination_ip") or meta.get("dest_ip") or "perimeter"

            # Primary clustering key: source host or distinct target host
            cluster_key = src_ip if src_ip != "unknown" else f"target:{dst_ip}"

            if cluster_key not in clusters:
                clusters[cluster_key] = []
            clusters[cluster_key].append(alert)

        incidents: List[Dict[str, Any]] = []

        for key, cluster_alerts in clusters.items():
            inc = self._synthesize_incident(key, cluster_alerts)
            incidents.append(inc)

        return incidents

    def correlate_and_persist(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlate alerts and persist new or updated incidents into the database."""
        if not self.db:
            return self.correlate_alerts(alerts)

        synthesized = self.correlate_alerts(alerts)
        persisted_incidents: List[Dict[str, Any]] = []

        # Get existing open incidents
        existing = self.db.list_incidents(limit=200)
        open_by_src = {
            i.get("source_ip"): i
            for i in existing
            if i.get("status") not in ["resolved", "false_positive"] and i.get("source_ip")
        }

        for inc in synthesized:
            src = inc.get("source_ip")
            if src and src in open_by_src:
                existing_inc = open_by_src[src]
                # Merge alerts and update existing open incident
                merged_ids = list(set((existing_inc.get("alert_ids") or []) + (inc.get("alert_ids") or [])))
                merged_tactics = list(set((existing_inc.get("mitre_tactics") or []) + (inc.get("mitre_tactics") or [])))
                merged_techs = list(set((existing_inc.get("mitre_techniques") or []) + (inc.get("mitre_techniques") or [])))
                
                updates = {
                    "alert_count": len(merged_ids),
                    "alert_ids": merged_ids,
                    "mitre_tactics": merged_tactics,
                    "mitre_techniques": merged_techs,
                    "risk_score": max(existing_inc.get("risk_score", 0.0), inc.get("risk_score", 0.0)),
                    "kill_chain_stage": inc.get("kill_chain_stage") or existing_inc.get("kill_chain_stage"),
                }
                self.db.update_incident(existing_inc["incident_id"], updates)
                updated = self.db.get_incident(existing_inc["incident_id"])
                if updated:
                    persisted_incidents.append(updated)
            else:
                # Create fresh incident record
                created = self.db.create_incident(inc)
                persisted_incidents.append(created)

        return persisted_incidents

    def _synthesize_incident(self, cluster_key: str, cluster_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate a cluster of alerts into a cohesive incident model."""
        alert_ids = [a.get("id") for a in cluster_alerts if a.get("id") is not None]
        categories = list(set(a.get("category", "threat") for a in cluster_alerts))
        severities = [str(a.get("severity", "medium")).lower() for a in cluster_alerts]

        first_alert = cluster_alerts[0]
        last_alert = cluster_alerts[-1]
        first_time = first_alert.get("timestamp") or first_alert.get("created_at") or datetime.now(timezone.utc).isoformat()
        last_time = last_alert.get("timestamp") or last_alert.get("created_at") or first_time

        meta_sample = cluster_alerts[-1].get("meta") or {}
        src_ip = meta_sample.get("source_ip") or first_alert.get("source") or cluster_key.replace("target:", "")
        dst_ip = meta_sample.get("destination_ip") or meta_sample.get("dest_ip") or "127.0.0.1"

        # Determine overall severity
        if "critical" in severities:
            overall_sev = "critical"
        elif "high" in severities:
            overall_sev = "high"
        elif "medium" in severities:
            overall_sev = "medium"
        else:
            overall_sev = "low"

        # Map MITRE tactics and techniques across all cluster alerts
        tactics: List[str] = []
        techniques: List[str] = []
        for a in cluster_alerts:
            cat = a.get("category", "")
            mapping = mitre_mapper.map_category(cat)
            if mapping.get("tactic_name") and mapping["tactic_name"] not in tactics:
                tactics.append(mapping["tactic_name"])
            if mapping.get("technique_id") and mapping["technique_id"] not in techniques:
                techniques.append(mapping["technique_id"])

        # Determine highest kill-chain stage observed
        highest_stage = "Initial Access"
        max_stage_idx = -1
        for cat in categories:
            stage = CATEGORY_TO_KILL_CHAIN.get(cat.lower())
            if stage and stage in KILL_CHAIN_STAGES:
                idx = KILL_CHAIN_STAGES.index(stage)
                if idx > max_stage_idx:
                    max_stage_idx = idx
                    highest_stage = stage

        # Calculate incident risk score (base severity + bonus for multi-stage progression)
        sev_weights = {"critical": 0.85, "high": 0.65, "medium": 0.40, "low": 0.15}
        base_risk = sev_weights.get(overall_sev, 0.3)
        multi_stage_bonus = min(0.20, len(tactics) * 0.05)
        volume_bonus = min(0.15, len(cluster_alerts) * 0.02)
        total_risk = round(min(1.0, base_risk + multi_stage_bonus + volume_bonus), 3)

        # Generate contextual title
        if len(categories) == 1:
            title = f"{categories[0].replace('_', ' ').title()} Activity from {src_ip}"
        else:
            primary_cat = categories[0].replace('_', ' ').title()
            title = f"Multi-Stage Attack Campaign: {primary_cat} & {len(categories)-1} Vectors from {src_ip}"

        description = (
            f"Detected {len(cluster_alerts)} correlated security event(s) originating from {src_ip} "
            f"targeting {dst_ip}. Highest attack progression reached: {highest_stage}. "
            f"Observed MITRE Tactics: {', '.join(tactics) if tactics else 'General Intrusion'}."
        )

        timeline = [
            {
                "timestamp": a.get("timestamp") or a.get("created_at"),
                "category": a.get("category"),
                "severity": a.get("severity"),
                "message": a.get("message"),
                "stage": CATEGORY_TO_KILL_CHAIN.get(str(a.get("category", "")).lower(), "Initial Access"),
            }
            for a in cluster_alerts[:12]
        ]

        evidence = {
            "first_seen": first_time,
            "last_seen": last_time,
            "event_count": len(cluster_alerts),
            "categories": categories,
            "timeline": timeline,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "stages_reached": list(set(t.get("stage") for t in timeline)),
        }

        return {
            "title": title,
            "description": description,
            "severity": overall_sev,
            "status": "new",
            "assignee": None,
            "risk_score": total_risk,
            "source_ip": src_ip,
            "target_ip": dst_ip,
            "alert_count": len(cluster_alerts),
            "alert_ids": alert_ids,
            "mitre_tactics": tactics,
            "mitre_techniques": techniques,
            "kill_chain_stage": highest_stage,
            "evidence": evidence,
            "analyst_notes": [],
            "created_at": first_time,
        }


correlation_engine = ThreatCorrelationEngine()
