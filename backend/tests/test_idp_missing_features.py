"""Integration and unit tests for the features added from the IDP project report:
1. Isolation Forest traffic anomaly detector
2. File download & ransomware payload inspector
3. Application/process-aware firewall rules
4. API endpoints (/api/check-file, /api/anomaly-score, and /api/rules app_name)
"""

from __future__ import annotations

import base64
import pytest
from fastapi.testclient import TestClient

from app import app
from ai_engine.isolation_forest_detector import IsolationForestAnomalyDetector, get_traffic_anomaly_detector
from security.file_inspector import FileInspector, get_file_inspector
from core.rule_engine import RuleEngine, RuleAction, RulePriority


@pytest.fixture
def client():
    return TestClient(app)


# ── 1. Isolation Forest Tests ──

def test_isolation_forest_detector_baseline_and_predict():
    detector = get_traffic_anomaly_detector()
    assert detector is not None

    # Normal enterprise traffic flow: 1420B, dst 80, TCP, moderate flow rate
    normal_flow = {
        "packet_size": 1420,
        "src_port": 50123,
        "dst_port": 80,
        "protocol": "TCP",
        "flow_rate": 10.0,
    }
    normal_res = detector.predict(normal_flow)
    assert "anomaly_score" in normal_res
    assert "raw_decision_score" in normal_res
    assert "signals" in normal_res
    assert normal_res["anomaly_score"] <= 0.65  # Normal flow shouldn't be flagged

    # Anomalous traffic flow: massive oversized packet, hacker port 31337, huge burst rate
    malicious_flow = {
        "packet_size": 95000,
        "src_port": 1337,
        "dst_port": 31337,
        "protocol": "TCP",
        "flow_rate": 850.0,
    }
    malicious_res = detector.predict(malicious_flow)
    assert malicious_res["is_anomaly"] is True
    assert malicious_res["anomaly_score"] >= 0.65
    assert len(malicious_res["signals"]) > 0


# ── 2. File Download & Ransomware Payload Inspector Tests ──

def test_file_inspector_benign_file():
    inspector = get_file_inspector()
    benign_text = b"Hello, this is a normal text file with regular English sentences and low entropy."
    res = inspector.inspect_bytes(benign_text, filename="notes.txt")

    assert res["is_malicious"] is False
    assert res["risk_score"] < 0.50
    assert res["entropy"] < 6.0
    assert res["recommendation"] == "ALLOW / SAFE"


def test_file_inspector_double_extension():
    inspector = get_file_inspector()
    dummy_exe = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 200
    res = inspector.inspect_bytes(dummy_exe, filename="invoice.pdf.exe")

    assert res["is_malicious"] is True
    assert "double extension" in str(res["signals"]).lower()
    assert res["is_pe"] is True
    assert res["recommendation"] == "QUARANTINE / BLOCK EXECUTION"


def test_file_inspector_ransomware_heuristics():
    inspector = get_file_inspector()
    # Payload with ransomware command string
    ransom_payload = b"MZ\x90\x00 cmd.exe /c vssadmin delete shadows /all /quiet && bcdedit /set {default} recoveryenabled no"
    res = inspector.inspect_bytes(ransom_payload, filename="payload.bin")

    assert res["is_malicious"] is True
    assert any("Ransomware indicators" in sig for sig in res["signals"])


# ── 3. Application / Process Control in Rule Engine Tests ──

def test_rule_engine_app_name_filtering():
    engine = RuleEngine()
    engine.add_rule(
        name="Block Curl",
        action=RuleAction.DROP,
        app_name="curl.exe",
        dst_port=80,
    )

    # Packet with curl.exe should be blocked
    curl_packet = {
        "src_ip": "192.168.1.50",
        "dst_ip": "93.184.216.34",
        "src_port": 49152,
        "dst_port": 80,
        "protocol": "TCP",
        "app_name": "curl.exe",
    }
    action, rule_matched = engine.evaluate(**curl_packet)
    assert action == RuleAction.DROP
    assert rule_matched is not None
    assert rule_matched.name == "Block Curl"

    # Packet from chrome.exe to port 80 should not match the curl rule
    chrome_packet = {
        "src_ip": "192.168.1.50",
        "dst_ip": "93.184.216.34",
        "src_port": 49152,
        "dst_port": 80,
        "protocol": "TCP",
        "app_name": "chrome.exe",
    }
    action_chrome, rule_chrome = engine.evaluate(**chrome_packet)
    assert rule_chrome is None or rule_chrome.name != "Block Curl"


# ── 4. API Endpoints Tests ──

def test_api_anomaly_score_endpoint(client):
    payload = {
        "packet_size": 1420,
        "src_port": 52000,
        "dst_port": 443,
        "protocol": "TCP",
        "flow_rate": 12.0,
    }
    response = client.post("/api/anomaly-score", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "anomaly_score" in data
    assert "classification" in data
    assert "features_evaluated" in data


def test_api_check_file_multipart_upload(client):
    file_bytes = b"MZ\x90\x00\x03\x00" + b"\x55" * 100
    files = {"file": ("malicious.exe", file_bytes, "application/octet-stream")}
    response = client.post("/api/check-file", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "malicious.exe"
    assert "entropy" in data
    assert data["is_pe"] is True


def test_api_check_file_base64_json(client):
    raw = b"Sample text file content for checking."
    b64 = base64.b64encode(raw).decode("ascii")
    response = client.post("/api/check-file", json={"file_base64": b64, "filename": "sample.txt"})
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "sample.txt"
    assert data["is_malicious"] is False


def test_api_rules_app_name_support(client):
    rule_data = {
        "name": "Block SSH client",
        "action": "drop",
        "dst_port": 22,
        "protocol": "TCP",
        "app_name": "ssh.exe",
        "priority": 5,
        "description": "Block outbound ssh executable",
    }
    response = client.post("/api/rules", json=rule_data)
    assert response.status_code == 200
    data = response.json()
    assert data["app_name"] == "ssh.exe"
    rule_id = data["id"]

    # Verify rule is in list
    list_res = client.get("/api/rules")
    assert list_res.status_code == 200
    rules = list_res.json()
    target = next((r for r in rules if r["id"] == rule_id), None)
    assert target is not None
    assert target["app_name"] == "ssh.exe"


# ── 5. PyTorch LSTM Flow Sequence Detector Tests ──

def test_pytorch_lstm_flow_sequence_detector():
    from ai_engine.lstm_detector import get_lstm_traffic_detector
    detector = get_lstm_traffic_detector()
    assert detector is not None

    # Normal sequence: 8 packets, typical inter-arrival 0.05s, 1420 bytes
    normal_seq = [{"delta_time": 0.05, "packet_size": 1420, "direction": 1, "protocol": "TCP"} for _ in range(8)]
    normal_res = detector.predict_sequence(normal_seq)
    assert "anomaly_probability" in normal_res
    assert normal_res["is_anomaly"] is False
    assert normal_res["anomaly_probability"] < 0.50

    # Flood / SYN burst attack: 8 packets, microsecond delta time (0.0001s), tiny packets (40B)
    attack_seq = [{"delta_time": 0.0001, "packet_size": 40, "direction": 0, "protocol": "TCP"} for _ in range(8)]
    attack_res = detector.predict_sequence(attack_seq)
    assert attack_res["is_anomaly"] is True
    assert attack_res["anomaly_probability"] >= 0.50
    assert any("burst" in s.lower() or "recurrent" in s.lower() for s in attack_res["signals"])


def test_api_lstm_flow_score_endpoint(client):
    payload = {
        "delta_time": 0.05,
        "packet_size": 1420,
        "direction": 1,
        "protocol": "TCP",
    }
    response = client.post("/api/lstm-flow-score", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "anomaly_probability" in data
    assert "classification" in data
    assert "metrics" in data


# ── 6. Live SSL Validator & Domain Age Tests ──

def test_ssl_validator_and_domain_age():
    from security.ssl_validator import inspect_url_ssl
    # Test plaintext HTTP on suspicious TLD
    res = inspect_url_ssl("http://login-verify-account.xyz")
    assert res["has_ssl"] is False
    assert res["is_valid"] is False
    assert "Plaintext" in str(res["signals"]) or "No TLS" in str(res["signals"])
    assert "High Risk" in res["domain_age_heuristic"]


# ── 7. Automated Quarantine Hook on Ransomware Payload ──

def test_automated_quarantine_hook_on_ransomware(client):
    # Payload with high-entropy ransomware command string
    ransom_payload = (
        b"MZ\x90\x00"
        + b"\x90" * 50
        + b"cmd.exe /c vssadmin delete shadows /all /quiet && bcdedit /set {default} recoveryenabled no"
        + b"\xff\xfe\xfd\xfc\xfb\xfa\x01\x02\x03\x04" * 40
    )
    files = {"file": ("ransom_locker.pdf.exe", ransom_payload, "application/octet-stream")}
    response = client.post("/api/check-file", files=files)
    assert response.status_code == 200
    data = response.json()

    assert data["is_malicious"] is True
    assert data["quarantine_enforced"] is True
    assert "QUARANTINE_AUTO_" in data["quarantine_rule_name"]

    # Verify drop rule exists in active firewall rules
    rules_res = client.get("/api/rules")
    rules = rules_res.json()
    quarantine_rule = next((r for r in rules if r["name"] == data["quarantine_rule_name"]), None)
    assert quarantine_rule is not None
    assert quarantine_rule["action"] == "drop"


# ── 8. Compliance & SDG-9 Audit in Incident Report Tests ──

def test_compliance_and_sdg9_audit_report(client):
    req_body = {
        "incident_type": "ransomware_attack",
        "severity": "high",
        "days": 2,
    }
    response = client.post("/api/reports/incident", json=req_body)
    assert response.status_code == 200
    report = response.json()

    assert "compliance_audit" in report
    audit = report["compliance_audit"]
    assert "iso_27001_mapping" in audit
    assert "A.8.20 Network Security" in audit["iso_27001_mapping"]
    assert "A.8.7 Protection Against Malware" in audit["iso_27001_mapping"]
    assert "nist_csf_v2" in audit
    assert "sdg_9_alignment" in audit
    assert audit["sdg_9_alignment"]["goal"] == "SDG 9: Industry, Innovation, and Infrastructure"
    assert "infrastructure_resilience_rating" in audit["sdg_9_alignment"]

