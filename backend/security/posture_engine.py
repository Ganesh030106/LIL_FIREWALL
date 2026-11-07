"""Security Posture Scoring & Benchmark Engine for Volcano AI Firewall.
Computes a dynamic 0-100 enterprise cybersecurity posture index and hardening recommendations.
"""

from __future__ import annotations

from typing import Any, Dict


class PostureEngine:
    """Calculates multidimensional enterprise security posture from live firewall telemetry."""

    def __init__(self, rule_engine=None, alerts=None, vuln_db=None, response_engine=None) -> None:
        self.rule_engine = rule_engine
        self.alerts = alerts
        self.vuln_db = vuln_db
        self.response_engine = response_engine

    def calculate_posture(
        self,
        rules_count: int = 0,
        unhandled_critical_alerts: int = 0,
        open_cves: int = 0,
        models_loaded: bool = True,
        canary_armed: bool = True,
        allowlist_count: int = 1,
    ) -> Dict[str, Any]:
        """Compute 0-100 score and categorical pillar ratings."""
        # 1. Perimeter Hardening (Max 25 pts)
        rule_pts = min(15, rules_count * 3) if rules_count > 0 else 5
        allow_pts = min(10, allowlist_count * 2) if allowlist_count > 0 else 4
        perimeter_score = rule_pts + allow_pts

        # 2. Threat Detection Readiness (Max 25 pts)
        model_pts = 15 if models_loaded else 5
        canary_pts = 10 if canary_armed else 3
        detection_score = model_pts + canary_pts

        # 3. Vulnerability Surface (Max 25 pts, minus CVE penalties)
        cve_penalty = min(20, open_cves * 5)
        vuln_score = max(5, 25 - cve_penalty)

        # 4. Incident Response & Containment (Max 25 pts, minus unhandled alerts)
        alert_penalty = min(20, unhandled_critical_alerts * 6)
        response_score = max(5, 25 - alert_penalty)

        total_score = min(100, max(10, perimeter_score + detection_score + vuln_score + response_score))

        if total_score >= 90:
            grade = "A+"
            grade_label = "Optimal Defense"
            grade_color = "var(--safe)"
        elif total_score >= 80:
            grade = "A"
            grade_label = "Hardened"
            grade_color = "var(--safe)"
        elif total_score >= 70:
            grade = "B"
            grade_label = "Adequate"
            grade_color = "var(--warning)"
        elif total_score >= 60:
            grade = "C"
            grade_label = "Elevated Exposure"
            grade_color = "var(--warning)"
        else:
            grade = "D"
            grade_label = "At-Risk"
            grade_color = "var(--danger)"

        recommendations = []
        if unhandled_critical_alerts > 0:
            recommendations.append(f"Triage and contain {unhandled_critical_alerts} unacknowledged critical alert(s).")
        if open_cves > 0:
            recommendations.append(f"Deploy 1-click DROP firewall rules for {open_cves} open CVE vulnerability port(s).")
        if rules_count < 3:
            recommendations.append("Define ingress firewall ACL policies for sensitive ports (22, 3389, 445).")
        if not canary_armed:
            recommendations.append("Re-arm the filesystem canary tripwire to detect ransomware early.")
        if not recommendations:
            recommendations.append("System security posture is optimal. Maintain periodic threat intelligence feed updates.")

        return {
            "score": total_score,
            "grade": grade,
            "grade_label": grade_label,
            "grade_color": grade_color,
            "pillars": {
                "perimeter_hardening": {"score": perimeter_score, "max": 25, "percentage": round((perimeter_score / 25) * 100)},
                "threat_detection": {"score": detection_score, "max": 25, "percentage": round((detection_score / 25) * 100)},
                "vulnerability_surface": {"score": vuln_score, "max": 25, "percentage": round((vuln_score / 25) * 100)},
                "incident_response": {"score": response_score, "max": 25, "percentage": round((response_score / 25) * 100)},
            },
            "recommendations": recommendations,
            "telemetry": {
                "rules_active": rules_count,
                "unhandled_critical_alerts": unhandled_critical_alerts,
                "open_cves_detected": open_cves,
                "ai_models_loaded": models_loaded,
                "canary_tripwire_armed": canary_armed,
            },
        }


# Global singleton
posture_engine = PostureEngine()

