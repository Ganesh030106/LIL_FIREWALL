"""Vulnerability Signature Database and Evaluation Rules.

Provides curated security rules, CVE mappings, and CVSS severity scoring
for open ports, service banners, and protocol exposures.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class VulnerabilitySignature:
    id: str
    title: str
    severity: str  # "critical", "high", "medium", "low", "info"
    cvss_score: float
    cve_id: Optional[str]
    cwe_id: Optional[str]
    port: Optional[int]
    service_pattern: Optional[str]
    banner_regex: Optional[str]
    description: str
    remediation: str
    compliance_tags: List[str] = field(default_factory=list)


# Comprehensive Vulnerability Signatures Catalogue
VULNERABILITY_CATALOGUE: List[VulnerabilitySignature] = [
    VulnerabilitySignature(
        id="VULN-SMB-EXPOSED",
        title="Exposed SMB Service (Ransomware & Lateral Movement Risk)",
        severity="critical",
        cvss_score=9.8,
        cve_id="CVE-2017-0144",
        cwe_id="CWE-284",
        port=445,
        service_pattern="SMB",
        banner_regex=None,
        description="Port 445 (Server Message Block) is open and accessible. Exposed SMB is the primary vector for ransomware propagation (e.g. WannaCry, NotPetya) and internal lateral movement.",
        remediation="Block inbound port 445 at the firewall perimeter. Restrict SMB access exclusively to trusted management subnets via VPN.",
        compliance_tags=["NIST CSF PR.AC-5", "CIS Control 4.4", "ISO 27001 A.8.20"],
    ),
    VulnerabilitySignature(
        id="VULN-REDIS-UNAUTH",
        title="Exposed Redis In-Memory Store (Remote Code Execution Risk)",
        severity="critical",
        cvss_score=9.8,
        cve_id="CVE-2022-0543",
        cwe_id="CWE-306",
        port=6379,
        service_pattern="Redis",
        banner_regex=None,
        description="Redis data store is directly exposed on port 6379. Misconfigured or unauthenticated Redis instances permit unauthenticated attackers to dump databases or execute remote arbitrary commands.",
        remediation="Bind Redis to localhost (127.0.0.1) in redis.conf, enforce strong authentication (requirepass), and block port 6379 on external interfaces.",
        compliance_tags=["NIST CSF PR.AC-3", "CIS Control 3.3", "ISO 27001 A.8.24"],
    ),
    VulnerabilitySignature(
        id="VULN-TELNET-CLEAR",
        title="Cleartext Telnet Service Active",
        severity="high",
        cvss_score=7.5,
        cve_id=None,
        cwe_id="CWE-319",
        port=23,
        service_pattern="Telnet",
        banner_regex=None,
        description="Port 23 is open running Telnet. Telnet transmits all credentials, commands, and administrative sessions in plaintext without encryption.",
        remediation="Disable the Telnet daemon immediately and migrate all remote administration to SSH (Port 22) with public key authentication.",
        compliance_tags=["NIST CSF PR.DS-2", "PCI DSS 2.2.3", "ISO 27001 A.8.24"],
    ),
    VulnerabilitySignature(
        id="VULN-FTP-CLEAR",
        title="Cleartext FTP Service Active",
        severity="medium",
        cvss_score=6.5,
        cve_id=None,
        cwe_id="CWE-319",
        port=21,
        service_pattern="FTP",
        banner_regex=None,
        description="Port 21 is open running standard FTP. Standard FTP transmits authentication credentials and transferred files in unencrypted cleartext.",
        remediation="Enforce FTPS (FTP over TLS) or migrate to SFTP (SSH File Transfer Protocol). Ensure anonymous login is disabled.",
        compliance_tags=["NIST CSF PR.DS-2", "PCI DSS 4.1", "ISO 27001 A.8.24"],
    ),
    VulnerabilitySignature(
        id="VULN-RDP-EXPOSED",
        title="Exposed Remote Desktop Protocol (RDP)",
        severity="high",
        cvss_score=8.5,
        cve_id="CVE-2019-0708",
        cwe_id="CWE-306",
        port=3389,
        service_pattern="RDP",
        banner_regex=None,
        description="Port 3389 (Microsoft RDP) is publicly accessible. Exposed RDP endpoints are heavily targeted by automated brute-force attacks and BlueKeep exploitation.",
        remediation="Do not expose port 3389 directly to the Internet. Enforce Multi-Factor Authentication (MFA), Network Level Authentication (NLA), or require an encrypted VPN tunnel.",
        compliance_tags=["NIST CSF PR.AC-7", "CIS Control 4.1", "ISO 27001 A.8.20"],
    ),
    VulnerabilitySignature(
        id="VULN-VNC-EXPOSED",
        title="Exposed VNC Remote Desktop",
        severity="high",
        cvss_score=8.0,
        cve_id=None,
        cwe_id="CWE-287",
        port=5900,
        service_pattern="VNC",
        banner_regex=None,
        description="Virtual Network Computing (VNC) is running on port 5900. VNC frequently uses weak DES password encryption and lacks session protection.",
        remediation="Tunnel VNC traffic through SSH or an encrypted WireGuard/OpenVPN tunnel. Never expose port 5900 directly to public networks.",
        compliance_tags=["NIST CSF PR.AC-7", "ISO 27001 A.8.20"],
    ),
    VulnerabilitySignature(
        id="VULN-MONGODB-EXPOSED",
        title="Exposed MongoDB Database Server",
        severity="high",
        cvss_score=8.5,
        cve_id=None,
        cwe_id="CWE-284",
        port=27017,
        service_pattern="MongoDB",
        banner_regex=None,
        description="Port 27017 (MongoDB) is open. Databases exposed directly to external networks risk ransom attacks where databases are wiped and held for ransom.",
        remediation="Bind MongoDB to 127.0.0.1 or internal VPC subnets. Enforce auth (security.authorization: enabled) and TLS encryption.",
        compliance_tags=["NIST CSF PR.AC-3", "CIS Benchmark MongoDB 2.1", "ISO 27001 A.8.24"],
    ),
    VulnerabilitySignature(
        id="VULN-MYSQL-EXPOSED",
        title="Exposed MySQL Database Port",
        severity="high",
        cvss_score=7.5,
        cve_id=None,
        cwe_id="CWE-284",
        port=3306,
        service_pattern="MySQL",
        banner_regex=None,
        description="Port 3306 (MySQL) is exposed. Databases should reside in private subnets behind application tiers.",
        remediation="Configure bind-address = 127.0.0.1 in my.cnf and add firewall DROP rules for external connections to port 3306.",
        compliance_tags=["NIST CSF PR.AC-3", "CIS Benchmark MySQL 1.1", "ISO 27001 A.8.20"],
    ),
    VulnerabilitySignature(
        id="VULN-POSTGRES-EXPOSED",
        title="Exposed PostgreSQL Database Port",
        severity="high",
        cvss_score=7.5,
        cve_id=None,
        cwe_id="CWE-284",
        port=5432,
        service_pattern="PostgreSQL",
        banner_regex=None,
        description="Port 5432 (PostgreSQL) is exposed. Direct exposure leaves database authentication open to brute force and denial of service.",
        remediation="Configure listen_addresses in postgresql.conf and enforce hostssl rules in pg_hba.conf. Block port 5432 at the firewall.",
        compliance_tags=["NIST CSF PR.AC-3", "CIS Benchmark PostgreSQL 1.2", "ISO 27001 A.8.20"],
    ),
    VulnerabilitySignature(
        id="VULN-MSSQL-EXPOSED",
        title="Exposed Microsoft SQL Server",
        severity="high",
        cvss_score=7.5,
        cve_id=None,
        cwe_id="CWE-284",
        port=1433,
        service_pattern="MSSQL",
        banner_regex=None,
        description="Port 1433 (MSSQL) is open and accessible from external networks. Highly vulnerable to brute force and SQL injection pivots.",
        remediation="Disable external listening on port 1433 and route all connections through application servers or VPNs.",
        compliance_tags=["NIST CSF PR.AC-3", "ISO 27001 A.8.20"],
    ),
    VulnerabilitySignature(
        id="VULN-ELASTIC-EXPOSED",
        title="Exposed Elasticsearch Cluster REST API",
        severity="high",
        cvss_score=8.2,
        cve_id=None,
        cwe_id="CWE-306",
        port=9200,
        service_pattern="Elasticsearch",
        banner_regex=None,
        description="Port 9200 (Elasticsearch) is exposed. Unauthenticated or exposed clusters frequently lead to massive corporate data leaks and index ransom deletion.",
        remediation="Enable Elastic Security (xpack.security.enabled: true), configure HTTPS, and restrict port 9200 to internal cluster nodes.",
        compliance_tags=["NIST CSF PR.AC-3", "ISO 27001 A.8.24"],
    ),
    VulnerabilitySignature(
        id="VULN-MEMCACHED-EXPOSED",
        title="Exposed Memcached Server (DDoS Reflection Vector)",
        severity="high",
        cvss_score=7.5,
        cve_id="CVE-2018-1000115",
        cwe_id="CWE-400",
        port=11211,
        service_pattern="Memcached",
        banner_regex=None,
        description="Memcached is open on port 11211. Exposed Memcached servers are actively weaponized as massive UDP amplification reflectors for DDoS attacks.",
        remediation="Bind Memcached to 127.0.0.1 (-l 127.0.0.1) and disable UDP support (-U 0).",
        compliance_tags=["NIST CSF PR.PT-4", "ISO 27001 A.8.20"],
    ),
    VulnerabilitySignature(
        id="VULN-HTTP-UNENCRYPTED",
        title="Unencrypted HTTP Service (Missing Mandatory TLS)",
        severity="medium",
        cvss_score=5.3,
        cve_id=None,
        cwe_id="CWE-319",
        port=80,
        service_pattern="HTTP",
        banner_regex=None,
        description="Port 80 is serving HTTP traffic without enforced HTTPS encryption. Allows eavesdropping, man-in-the-middle manipulation, and session hijacking.",
        remediation="Deploy a valid TLS/SSL certificate (e.g. Let's Encrypt) on port 443 and configure an automatic HTTP 301 redirect from port 80 to HTTPS.",
        compliance_tags=["NIST CSF PR.DS-2", "PCI DSS 4.1", "ISO 27001 A.8.24"],
    ),
    VulnerabilitySignature(
        id="VULN-SSH-REGRESSHION",
        title="OpenSSH regreSSHion Signal Vulnerability",
        severity="high",
        cvss_score=8.1,
        cve_id="CVE-2024-6387",
        cwe_id="CWE-362",
        port=22,
        service_pattern="SSH",
        banner_regex=r"OpenSSH[_-](?:8\.[5-9]|9\.[0-7])",
        description="The captured SSH banner indicates an OpenSSH version between 8.5p1 and 9.7p1, which is vulnerable to a race condition in sshd resulting in potential unauthenticated remote code execution as root on glibc-based systems.",
        remediation="Update OpenSSH to version 9.8p1 or newer immediately. Alternatively, set LoginGraceTime 0 in sshd_config as a mitigation.",
        compliance_tags=["NIST CSF PR.IP-12", "CIS Control 7.1", "ISO 27001 A.8.19"],
    ),
    VulnerabilitySignature(
        id="VULN-APACHE-PATH-TRAVERSAL",
        title="Vulnerable Apache HTTP Server Banner (Path Traversal / RCE)",
        severity="critical",
        cvss_score=9.8,
        cve_id="CVE-2021-41773",
        cwe_id="CWE-22",
        port=None,
        service_pattern="HTTP",
        banner_regex=r"Apache/2\.4\.(?:49|50)",
        description="The web server banner matches Apache 2.4.49 or 2.4.50. These versions contain an actively exploited path traversal and remote code execution flaw.",
        remediation="Upgrade Apache HTTP Server to version 2.4.51 or later. Ensure ServerTokens is set to Prod to minimize information disclosure.",
        compliance_tags=["NIST CSF PR.IP-12", "CIS Control 7.1", "ISO 27001 A.8.19"],
    ),
    VulnerabilitySignature(
        id="VULN-WINRM-EXPOSED",
        title="Exposed Windows Remote Management (WinRM)",
        severity="medium",
        cvss_score=6.5,
        cve_id=None,
        cwe_id="CWE-284",
        port=5985,
        service_pattern="WinRM",
        banner_regex=None,
        description="WinRM HTTP (port 5985) is exposed. Attackers can attempt password spraying or relay attacks against Windows authentication endpoints.",
        remediation="Disable WinRM HTTP listening or restrict access to dedicated administrative jump-boxes. Prefer HTTPS WinRM (port 5986) with certificate authentication.",
        compliance_tags=["NIST CSF PR.AC-3", "CIS Control 4.1", "ISO 27001 A.8.20"],
    ),
]


class VulnerabilityDatabase:
    """Provides querying and signature evaluation over the vulnerability catalogue."""

    def __init__(self, signatures: Optional[List[VulnerabilitySignature]] = None) -> None:
        self.signatures = signatures or list(VULNERABILITY_CATALOGUE)

    def get_all_signatures(self) -> List[Dict[str, Any]]:
        """Returns all signatures formatted for API responses."""
        return [
            {
                "id": s.id,
                "title": s.title,
                "severity": s.severity,
                "cvss_score": s.cvss_score,
                "cve_id": s.cve_id,
                "cwe_id": s.cwe_id,
                "port": s.port,
                "service_pattern": s.service_pattern,
                "description": s.description,
                "remediation": s.remediation,
                "compliance_tags": s.compliance_tags,
            }
            for s in self.signatures
        ]

    def match_port_and_banner(self, port: int, service: str, banner: str) -> List[VulnerabilitySignature]:
        """Matches a single open port, service name, and banner against signature database."""
        matches: List[VulnerabilitySignature] = []
        for sig in self.signatures:
            # 1. Check Port Match
            if sig.port is not None and sig.port == port:
                # If banner regex is also specified, verify regex matches banner
                if sig.banner_regex:
                    if banner and re.search(sig.banner_regex, banner, re.IGNORECASE):
                        matches.append(sig)
                else:
                    matches.append(sig)
                continue

            # 2. Check Banner Regex Match regardless of port (e.g. Apache banner on port 8080 or custom port)
            if sig.port is None and sig.banner_regex and banner:
                if re.search(sig.banner_regex, banner, re.IGNORECASE):
                    matches.append(sig)

        return matches


# Singleton instance
_vuln_db_instance: Optional[VulnerabilityDatabase] = None

def get_vuln_database() -> VulnerabilityDatabase:
    """Returns the singleton VulnerabilityDatabase instance."""
    global _vuln_db_instance
    if _vuln_db_instance is None:
        _vuln_db_instance = VulnerabilityDatabase()
    return _vuln_db_instance
