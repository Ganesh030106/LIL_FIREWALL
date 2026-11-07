"""Tests for Volcano AI Firewall V5.0 Autonomous SOC Platform additions:
- Multi-Stage Incident Storage & Lifecycle
- Threat Correlation Engine
- Predictive Early-Warning Signals
- Playbook Execution API (Dry-Run & Approval)
- Forensic PCAP Export with SHA-256 Evidence Integrity Hash
- Upgraded XAI Dual-Contribution Breakdown
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import app
from storage.auth import create_access_token
from security.correlation_engine import correlation_engine
from security.predictive_engine import predictive_engine


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_headers():
    token = create_access_token(user_id="1", username="admin", role="admin")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers():
    token = create_access_token(user_id="2", username="analyst", role="analyst")
    return {"Authorization": f"Bearer {token}"}


def test_incident_lifecycle(client: TestClient, admin_headers: dict):
    # 1. Create a security incident
    payload = {
        "title": "Suspected Lateral Movement Campaign",
        "description": "Multi-host SMB and RDP handshake anomalies observed.",
        "severity": "high",
        "status": "new",
        "risk_score": 0.78,
        "source_ip": "192.168.1.188",
        "target_ip": "10.0.0.15",
        "alert_count": 3,
        "alert_ids": [101, 102, 103],
        "mitre_tactics": ["Lateral Movement", "Defense Evasion"],
        "mitre_techniques": ["T1021", "T1071"],
        "kill_chain_stage": "Lateral Movement",
        "evidence": {"ports": [445, 3389], "protocol": "TCP"},
    }
    res = client.post("/api/incidents", json=payload, headers=admin_headers)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "created"
    inc = data["incident"]
    inc_id = inc["incident_id"]
    assert inc["severity"] == "high"
    assert inc["source_ip"] == "192.168.1.188"

    # 2. Retrieve incident
    get_res = client.get(f"/api/incidents/{inc_id}")
    assert get_res.status_code == 200
    assert get_res.json()["incident"]["incident_id"] == inc_id

    # 3. Add analyst note
    note_res = client.post(
        f"/api/incidents/{inc_id}/notes",
        json={"note": "Isolated host 192.168.1.188 from SMB broadcast segment."},
        headers=admin_headers,
    )
    assert note_res.status_code == 200
    assert note_res.json()["status"] == "note_added"

    # 4. Update incident status
    patch_res = client.patch(
        f"/api/incidents/{inc_id}",
        json={"status": "investigating", "assignee": "analyst_sarah"},
        headers=admin_headers,
    )
    assert patch_res.status_code == 200
    updated_inc = patch_res.json()["incident"]
    assert updated_inc["status"] == "investigating"
    assert updated_inc["assignee"] == "analyst_sarah"

    # 5. List incidents
    list_res = client.get("/api/incidents?status=investigating")
    assert list_res.status_code == 200
    incidents = list_res.json()["incidents"]
    assert any(i["incident_id"] == inc_id for i in incidents)


def test_threat_correlation_engine():
    synthetic_alerts = [
        {
            "id": 1,
            "category": "port_scan",
            "severity": "medium",
            "message": "TCP port sweep detected",
            "meta": {"source_ip": "198.51.100.77", "destination_ip": "10.0.0.1"},
            "timestamp": "2026-11-07T10:00:00Z",
        },
        {
            "id": 2,
            "category": "brute_force",
            "severity": "high",
            "message": "SSH repeated failure burst",
            "meta": {"source_ip": "198.51.100.77", "destination_ip": "10.0.0.1"},
            "timestamp": "2026-11-07T10:05:00Z",
        },
        {
            "id": 3,
            "category": "c2_beacon",
            "severity": "critical",
            "message": "Periodic beacon rhythm confirmed",
            "meta": {"source_ip": "198.51.100.77", "destination_ip": "10.0.0.1"},
            "timestamp": "2026-11-07T10:12:00Z",
        },
    ]

    correlated = correlation_engine.correlate_alerts(synthetic_alerts)
    assert len(correlated) == 1
    inc = correlated[0]
    assert inc["severity"] == "critical"
    assert inc["source_ip"] == "198.51.100.77"
    assert inc["alert_count"] == 3
    assert inc["kill_chain_stage"] in ["Command and Control", "Credential Access"]
    assert len(inc["mitre_tactics"]) >= 2


def test_predictive_signals_endpoint(client: TestClient):
    res = client.get("/api/predictive/signals")
    assert res.status_code == 200
    data = res.json()
    assert "predictions" in data
    assert "telemetry_derivatives" in data
    assert isinstance(data["predictions"], list)


def test_playbook_execution_dry_run(client: TestClient, admin_headers: dict):
    # Execute the built-in ssh-brute-force-response playbook in dry-run mode
    payload = {
        "target_ip": "203.0.113.99",
        "alert_id": 42,
        "dry_run": True,
    }
    res = client.post("/api/playbooks/ssh-brute-force-response/execute", json=payload, headers=admin_headers)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "completed"
    assert data["playbook"] == "ssh-brute-force-response"
    assert data["dry_run"] is True
    assert data["result"]["overall_success"] is True


def test_incident_pcap_with_sha256_hash(client: TestClient, admin_headers: dict):
    # 1. Create temporary incident
    payload = {
        "title": "Forensic PCAP Test Incident",
        "severity": "medium",
        "status": "new",
        "source_ip": "10.0.0.50",
    }
    res = client.post("/api/incidents", json=payload, headers=admin_headers)
    assert res.status_code == 200
    inc_id = res.json()["incident"]["incident_id"]

    # 2. Request incident PCAP
    pcap_res = client.get(f"/api/incidents/{inc_id}/pcap")
    assert pcap_res.status_code == 200
    assert pcap_res.headers["content-type"] == "application/vnd.tcpdump.pcap"
    # Verify SHA-256 evidence integrity header is present
    assert "x-evidence-hash-sha256" in pcap_res.headers
    assert len(pcap_res.headers["x-evidence-hash-sha256"]) == 64


def test_upgraded_xai_explain_dual_contributions(client: TestClient):
    payload = {
        "type": "url",
        "url": "http://192.168.1.1/secure-update-login.xyz",
        "probability": 0.89,
    }
    res = client.post("/api/ai/explain", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "feature_contributions" in data
    assert "positive_contributions" in data
    assert "negative_contributions" in data
    assert "suggested_investigation_steps" in data
    assert data["decision"] == "Malicious"
