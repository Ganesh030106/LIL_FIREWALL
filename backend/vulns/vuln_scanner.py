"""Vulnerability Assessment and Audit Scanner.

Correlates discovered open ports and service banners with known CVEs, CVSS ratings,
and security best practices to generate comprehensive vulnerability audit reports.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from scanner.port_scanner import PortScanner, get_port_scanner
from .vuln_database import VulnerabilityDatabase, get_vuln_database


class VulnerabilityScanner:
    """Performs defensive vulnerability scanning and risk assessment."""

    def __init__(
        self,
        port_scanner: Optional[PortScanner] = None,
        vuln_db: Optional[VulnerabilityDatabase] = None,
    ) -> None:
        self.port_scanner = port_scanner or get_port_scanner()
        self.vuln_db = vuln_db or get_vuln_database()

    def evaluate_open_ports(self, open_ports: List[Dict[str, Any]], target: str = "Unknown") -> Dict[str, Any]:
        """Audits a list of open port dicts and identifies matching vulnerabilities."""
        findings: List[Dict[str, Any]] = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        max_cvss = 0.0
        compliance_set = set()
        recommended_rules: List[Dict[str, Any]] = []

        for port_info in open_ports:
            port = port_info.get("port")
            service = port_info.get("service", "")
            banner = port_info.get("banner", "")

            if port is None:
                continue

            matches = self.vuln_db.match_port_and_banner(port=port, service=service, banner=banner)

            for sig in matches:
                severity = sig.severity.lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                if sig.cvss_score > max_cvss:
                    max_cvss = sig.cvss_score

                for tag in sig.compliance_tags:
                    compliance_set.add(tag)

                finding_entry = {
                    "vulnerability_id": sig.id,
                    "title": sig.title,
                    "severity": sig.severity,
                    "cvss_score": sig.cvss_score,
                    "cve_id": sig.cve_id,
                    "cwe_id": sig.cwe_id,
                    "port": port,
                    "service": service,
                    "banner_captured": banner or "None",
                    "description": sig.description,
                    "remediation": sig.remediation,
                    "compliance_tags": sig.compliance_tags,
                }
                findings.append(finding_entry)

                # Generate recommended firewall rule for high/critical findings
                if sig.severity in ("critical", "high"):
                    recommended_rules.append({
                        "name": f"AutoBlock {sig.id} Port {port}",
                        "action": "drop",
                        "dst_port": port,
                        "protocol": "TCP",
                        "priority": 10 if sig.severity == "critical" else 20,
                        "description": f"Automated remediation for {sig.title} ({sig.cve_id or sig.cwe_id})",
                    })

        # Calculate Composite Risk Score (0.0 to 10.0)
        # Formula: max_cvss adjusted for density of critical/high issues
        risk_modifier = (severity_counts["critical"] * 0.8) + (severity_counts["high"] * 0.4) + (severity_counts["medium"] * 0.1)
        composite_score = min(10.0, round(max_cvss + min(1.5, risk_modifier), 1)) if findings else 0.0

        if severity_counts["critical"] > 0:
            overall_risk = "CRITICAL"
        elif severity_counts["high"] > 0:
            overall_risk = "HIGH"
        elif severity_counts["medium"] > 0:
            overall_risk = "MEDIUM"
        elif severity_counts["low"] > 0:
            overall_risk = "LOW"
        else:
            overall_risk = "CLEAN / SAFE"

        return {
            "target": target,
            "overall_risk": overall_risk,
            "composite_risk_score": composite_score,
            "total_vulnerabilities": len(findings),
            "severity_breakdown": severity_counts,
            "vulnerabilities": findings,
            "recommended_firewall_rules": recommended_rules,
            "compliance_frameworks_impacted": sorted(list(compliance_set)),
            "timestamp": time.time(),
        }

    def scan_target(
        self,
        target: str,
        profile: str = "top20",
        custom_ports: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Runs an end-to-end port scan and vulnerability audit against a target."""
        # 1. Execute port scan
        port_scan_results = self.port_scanner.scan(
            target=target,
            profile=profile,
            custom_ports=custom_ports,
            timeout=timeout,
            grab_banner=True,
        )

        # 2. Audit discovered open ports
        vuln_report = self.evaluate_open_ports(
            open_ports=port_scan_results.get("open_ports", []),
            target=port_scan_results.get("resolved_ip", target),
        )

        # 3. Combine into unified report
        return {
            "target": target,
            "resolved_ip": port_scan_results.get("resolved_ip", target),
            "profile": profile,
            "ports_scanned_count": port_scan_results.get("ports_scanned_count", 0),
            "open_ports_count": port_scan_results.get("open_ports_count", 0),
            "scan_duration_seconds": port_scan_results.get("scan_duration_seconds", 0.0),
            "open_ports": port_scan_results.get("open_ports", []),
            "vulnerability_assessment": vuln_report,
            "timestamp": time.time(),
        }


# Singleton instance
_vuln_scanner_instance: Optional[VulnerabilityScanner] = None

def get_vuln_scanner() -> VulnerabilityScanner:
    """Returns singleton VulnerabilityScanner instance."""
    global _vuln_scanner_instance
    if _vuln_scanner_instance is None:
        _vuln_scanner_instance = VulnerabilityScanner()
    return _vuln_scanner_instance
