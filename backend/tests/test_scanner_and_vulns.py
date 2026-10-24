"""Unit and integration tests for Port Scanning & Vulnerability Detection Suite."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import app
from scanner.port_scanner import PortScanner, TOP_20_PORTS, TOP_100_PORTS
from vulns.vuln_database import VulnerabilityDatabase, get_vuln_database
from vulns.vuln_scanner import VulnerabilityScanner, get_vuln_scanner


@pytest.fixture
def client():
    return TestClient(app)


# ── 1. PortScanner Unit Tests ──

def test_port_scanner_target_resolution():
    # Valid localhost
    ip = PortScanner.resolve_target("127.0.0.1")
    assert ip == "127.0.0.1"

    # URL stripping
    ip2 = PortScanner.resolve_target("http://127.0.0.1:8000/api/health")
    assert ip2 == "127.0.0.1"

    # Invalid empty target
    with pytest.raises(ValueError):
        PortScanner.resolve_target("")


def test_port_scanner_port_range_parsing():
    ports = PortScanner.parse_port_range("80, 443, 8000-8003")
    assert ports == [80, 443, 8000, 8001, 8002, 8003]

    # Deduplication and sorting
    ports_dup = PortScanner.parse_port_range("80, 80, 22, 21")
    assert ports_dup == [21, 22, 80]

    # Limit check (> 1000 ports)
    with pytest.raises(ValueError, match="exceeds maximum allowable"):
        PortScanner.parse_port_range("1-2000")


def test_port_scanner_loopback_scan():
    scanner = PortScanner(default_timeout=0.1)
    # Scan small custom ports on loopback
    res = scanner.scan(target="127.0.0.1", profile="custom", custom_ports="54321, 54322", timeout=0.05)
    assert res["target"] == "127.0.0.1"
    assert res["resolved_ip"] == "127.0.0.1"
    assert res["profile"] == "custom"
    assert res["ports_scanned_count"] == 2
    assert isinstance(res["open_ports"], list)


# ── 2. Vulnerability Database Unit Tests ──

def test_vuln_db_signatures():
    db = get_vuln_database()
    sigs = db.get_all_signatures()
    assert len(sigs) >= 15
    # Verify critical SMB and Redis signatures exist
    smb_sig = next((s for s in sigs if s["id"] == "VULN-SMB-EXPOSED"), None)
    assert smb_sig is not None
    assert smb_sig["severity"] == "critical"
    assert smb_sig["cvss_score"] >= 9.0
    assert "CVE-2017-0144" in smb_sig["cve_id"]

    redis_sig = next((s for s in sigs if s["id"] == "VULN-REDIS-UNAUTH"), None)
    assert redis_sig is not None
    assert redis_sig["port"] == 6379


def test_vuln_db_matching_rules():
    db = get_vuln_database()

    # Match port 445 (SMB)
    matches_smb = db.match_port_and_banner(port=445, service="SMB", banner="")
    assert any(m.id == "VULN-SMB-EXPOSED" for m in matches_smb)

    # Match Telnet port 23
    matches_telnet = db.match_port_and_banner(port=23, service="Telnet", banner="")
    assert any(m.id == "VULN-TELNET-CLEAR" for m in matches_telnet)

    # Match OpenSSH regreSSHion banner
    matches_ssh = db.match_port_and_banner(port=22, service="SSH", banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
    assert any(m.id == "VULN-SSH-REGRESSHION" for m in matches_ssh)

    # Match Apache Path Traversal banner on arbitrary port
    matches_apache = db.match_port_and_banner(port=8080, service="HTTP", banner="Server: Apache/2.4.49 (Unix)")
    assert any(m.id == "VULN-APACHE-PATH-TRAVERSAL" for m in matches_apache)


# ── 3. VulnerabilityScanner Evaluation Tests ──

def test_vuln_scanner_evaluation():
    scanner = get_vuln_scanner()
    mock_open_ports = [
        {"port": 445, "service": "SMB", "banner": "Windows Server SMB"},
        {"port": 6379, "service": "Redis", "banner": "+PONG"},
        {"port": 80, "service": "HTTP", "banner": "Server: nginx"},
    ]

    report = scanner.evaluate_open_ports(open_ports=mock_open_ports, target="192.168.1.100")
    assert report["overall_risk"] == "CRITICAL"
    assert report["composite_risk_score"] >= 9.0
    assert report["total_vulnerabilities"] >= 3
    assert report["severity_breakdown"]["critical"] >= 2
    assert len(report["recommended_firewall_rules"]) >= 2
    assert any("445" in r["name"] for r in report["recommended_firewall_rules"])
    assert len(report["compliance_frameworks_impacted"]) > 0


def test_vuln_scanner_clean_host():
    scanner = get_vuln_scanner()
    # High unmapped random ports
    mock_clean = [
        {"port": 49152, "service": "Custom Internal Service", "banner": "OK"},
    ]
    report = scanner.evaluate_open_ports(open_ports=mock_clean, target="10.0.0.5")
    assert report["overall_risk"] == "CLEAN / SAFE"
    assert report["composite_risk_score"] == 0.0
    assert report["total_vulnerabilities"] == 0


# ── 4. API Endpoints Integration Tests ──

def test_api_scanner_signatures(client):
    response = client.get("/api/scanner/signatures")
    assert response.status_code == 200
    data = response.json()
    assert "signatures" in data
    assert data["total_signatures"] >= 15


def test_api_scanner_vuln_audit(client):
    payload = {
        "target": "10.10.10.25",
        "open_ports": [
            {"port": 23, "service": "Telnet", "banner": "Welcome to Router Telnet"},
            {"port": 3389, "service": "RDP", "banner": ""},
        ],
    }
    response = client.post("/api/scanner/vuln-audit", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["overall_risk"] in ("HIGH", "CRITICAL")
    assert data["total_vulnerabilities"] >= 2
    assert len(data["recommended_firewall_rules"]) >= 1


def test_api_scanner_port_scan_custom(client):
    payload = {
        "target": "127.0.0.1",
        "profile": "custom",
        "custom_ports": "59998, 59999",
        "timeout": 0.05,
        "grab_banner": False,
    }
    response = client.post("/api/scanner/port-scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "127.0.0.1"
    assert data["ports_scanned_count"] == 2
    assert "scan_duration_seconds" in data


def test_api_scanner_history(client):
    response = client.get("/api/scanner/history")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    # The previous test should have inserted an entry
    assert len(data) >= 1
    assert data[0]["target"] == "127.0.0.1"


# ── 5. Layer-7 Application-Level DPI & Canary Tripwire Tests ──

def test_l7_application_inspector_sqli():
    from security.l7_inspector import get_l7_inspector
    inspector = get_l7_inspector()
    raw_payload = b"GET /products?id=1%20UNION%20SELECT%20username,%20password%20FROM%20users HTTP/1.1\r\nHost: target\r\n\r\n"
    res = inspector.inspect_payload(raw_payload, "192.168.1.5", "10.0.0.1", 80)
    assert res is not None
    assert "SQL Injection" in res["category"]
    assert res["severity"] == "high"


def test_l7_application_inspector_xss():
    from security.l7_inspector import get_l7_inspector
    inspector = get_l7_inspector()
    raw_payload = b"POST /comment HTTP/1.1\r\nHost: target\r\n\r\n<script>alert(document.cookie)</script>"
    res = inspector.inspect_payload(raw_payload, "192.168.1.5", "10.0.0.1", 8080)
    assert res is not None
    assert "XSS" in res["category"]


def test_l7_application_inspector_path_traversal():
    from security.l7_inspector import get_l7_inspector
    inspector = get_l7_inspector()
    raw_payload = b"GET /download?file=../../../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n"
    res = inspector.inspect_payload(raw_payload, "192.168.1.5", "10.0.0.1", 80)
    assert res is not None
    assert "Directory Path Traversal" in res["category"]


def test_ransomware_canary_tripwire():
    from app import RansomwareEventHandler, alerts, metrics
    from watchdog.events import FileModifiedEvent

    handler = RansomwareEventHandler(alerts, metrics)
    event = FileModifiedEvent(".canary_system_vault.docx")
    handler.on_any_event(event)

    recent_alerts = alerts.list()
    canary_alert = next(
        (a for a in recent_alerts if "Canary Triggered" in (a.get("category") if isinstance(a, dict) else getattr(a, "category", ""))),
        None,
    )
    assert canary_alert is not None
    sev = canary_alert.get("severity") if isinstance(canary_alert, dict) else getattr(canary_alert, "severity", "")
    assert sev == "critical"

