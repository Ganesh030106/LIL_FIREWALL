"""MITRE ATT&CK Threat Mapping Engine for Volcano AI Firewall.
Correlates security alerts and detection signatures to the MITRE ATT&CK Enterprise Matrix.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


MITRE_TACTICS = {
    "TA0001": {"id": "TA0001", "name": "Initial Access", "icon": "🚪"},
    "TA0002": {"id": "TA0002", "name": "Execution", "icon": "⚡"},
    "TA0006": {"id": "TA0006", "name": "Credential Access", "icon": "🔑"},
    "TA0007": {"id": "TA0007", "name": "Discovery", "icon": "🔍"},
    "TA0008": {"id": "TA0008", "name": "Lateral Movement", "icon": "↔️"},
    "TA0011": {"id": "TA0011", "name": "Command and Control", "icon": "📡"},
    "TA0010": {"id": "TA0010", "name": "Exfiltration", "icon": "📤"},
    "TA0040": {"id": "TA0040", "name": "Impact", "icon": "💥"},
}

MITRE_TECHNIQUES = {
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "TA0001",
        "description": "Adversary exploiting software vulnerabilities like SQL Injection, XSS, or path traversal.",
    },
    "T1566": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "TA0001",
        "description": "Adversary sending spearphishing links or deploying deceptive malicious domains.",
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "TA0002",
        "description": "Execution of commands via bash, cmd.exe, or PowerShell commands.",
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "TA0006",
        "description": "Systematic credential guessing across SSH, RDP, or administrative web consoles.",
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "TA0007",
        "description": "Adversary enumerating open ports, listening services, and operating system banners.",
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "TA0008",
        "description": "Adversary pivoting through internal SMB (445), RDP (3389), or WinRM (5985).",
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol (C2)",
        "tactic": "TA0011",
        "description": "Periodic communication with remote command-and-control servers using standard protocols.",
    },
    "T1071.004": {
        "id": "T1071.004",
        "name": "DNS C2 & Tunneling",
        "tactic": "TA0011",
        "description": "Adversary utilizing high-entropy DNS queries or DGA domains for covert communication.",
    },
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "TA0010",
        "description": "Stealthy exfiltration of data through unexpected network channels or burst traffic.",
    },
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "TA0040",
        "description": "Adversary encrypting filesystem files or tampering with decoy canary honeytokens.",
    },
}


class MitreMapper:
    """Engine mapping detection alerts to the MITRE ATT&CK framework."""

    def map_alert(self, category: str, message: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Correlate alert parameters to standard MITRE technique."""
        cat_lower = (category or "").lower()
        msg_lower = (message or "").lower()

        technique_id = "T1190"  # default application exploit

        if "ransomware" in cat_lower or "canary" in msg_lower or "honeytoken" in msg_lower or "encrypted" in msg_lower:
            technique_id = "T1486"
        elif "brute" in cat_lower or "login" in cat_lower or "lockout" in msg_lower:
            technique_id = "T1110"
        elif "port" in cat_lower or "scan" in cat_lower or "recon" in msg_lower:
            technique_id = "T1046"
        elif "phishing" in cat_lower or "suspicious url" in msg_lower:
            technique_id = "T1566"
        elif "dns" in cat_lower or "entropy" in msg_lower or "dga" in msg_lower:
            technique_id = "T1071.004"
        elif "beacon" in cat_lower or "c2" in cat_lower:
            technique_id = "T1071"
        elif "lateral" in cat_lower or "pivot" in msg_lower:
            technique_id = "T1021"
        elif "command" in msg_lower or "rce" in msg_lower or "powershell" in msg_lower:
            technique_id = "T1059"
        elif "exfiltration" in cat_lower or "anomaly" in cat_lower:
            technique_id = "T1048"

        tech = MITRE_TECHNIQUES.get(technique_id, MITRE_TECHNIQUES["T1190"])
        tactic = MITRE_TACTICS.get(tech["tactic"], {"name": "Initial Access", "icon": "🚪"})

        return {
            "technique_id": tech["id"],
            "technique_name": tech["name"],
            "tactic_id": tech["tactic"],
            "tactic_name": tactic["name"],
            "tactic_icon": tactic.get("icon", "🛡️"),
            "description": tech["description"],
        }

    def map_category(self, category: str) -> Dict[str, Any]:
        """Convenience method to map a category name directly to MITRE."""
        return self.map_alert(category=category, message="", meta=None)

    def summarize_matrix(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate full MITRE ATT&CK enterprise coverage summary from active alerts."""
        technique_counts: Dict[str, int] = {}
        tactic_counts: Dict[str, int] = {}
        last_observed: Dict[str, str] = {}

        for a in alerts:
            mapped = self.map_alert(
                category=a.get("category", ""),
                message=a.get("message", ""),
                meta=a.get("meta") or {},
            )
            tid = mapped["technique_id"]
            tac_id = mapped["tactic_id"]

            technique_counts[tid] = technique_counts.get(tid, 0) + 1
            tactic_counts[tac_id] = tactic_counts.get(tac_id, 0) + 1
            if "timestamp" in a:
                last_observed[tid] = a["timestamp"]

        techniques_list = []
        for tid, tech in MITRE_TECHNIQUES.items():
            count = technique_counts.get(tid, 0)
            tactic = MITRE_TACTICS.get(tech["tactic"], {})
            techniques_list.append({
                "id": tid,
                "name": tech["name"],
                "tactic_id": tech["tactic"],
                "tactic_name": tactic.get("name", "Unknown"),
                "tactic_icon": tactic.get("icon", "🛡️"),
                "count": count,
                "active": count > 0,
                "last_seen": last_observed.get(tid, "None"),
            })

        active_techniques = sum(1 for t in techniques_list if t["active"])
        total_techniques = len(MITRE_TECHNIQUES)
        coverage_pct = round((active_techniques / total_techniques) * 100, 1)

        return {
            "total_techniques": total_techniques,
            "active_techniques": active_techniques,
            "coverage_percentage": coverage_pct,
            "techniques": sorted(techniques_list, key=lambda x: (-x["count"], x["id"])),
            "tactics": [
                {
                    "id": tac_id,
                    "name": tac["name"],
                    "icon": tac["icon"],
                    "threat_count": tactic_counts.get(tac_id, 0),
                    "active": tactic_counts.get(tac_id, 0) > 0,
                }
                for tac_id, tac in MITRE_TACTICS.items()
            ],
        }


# Singleton instance
mitre_mapper = MitreMapper()

