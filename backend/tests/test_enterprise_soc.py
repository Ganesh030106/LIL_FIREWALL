"""Unit tests for Enterprise SOC capabilities: MITRE ATT&CK, Security Posture, and Explainable AI (XAI)."""

from __future__ import annotations

import pytest
from security.mitre_mapper import mitre_mapper, MITRE_TECHNIQUES, MITRE_TACTICS
from security.posture_engine import posture_engine
from ai_engine.xai_explainer import xai_explainer


def test_mitre_mapping_known_categories():
    # 1. Ransomware canary tripwire
    m1 = mitre_mapper.map_alert("ransomware", "Canary honeytoken modified", {})
    assert m1["technique_id"] == "T1486"
    assert m1["tactic_id"] == "TA0040"

    # 2. Brute-force credential stuffing
    m2 = mitre_mapper.map_alert("brute_force", "Excessive SSH login failures", {})
    assert m2["technique_id"] == "T1110"
    assert m2["tactic_name"] == "Credential Access"

    # 3. Port scan discovery
    m3 = mitre_mapper.map_alert("port_scan", "Scanning multiple ports on target", {})
    assert m3["technique_id"] == "T1046"

    # 4. Phishing domain
    m4 = mitre_mapper.map_alert("phishing", "Suspicious URL detected", {})
    assert m4["technique_id"] == "T1566"

    # 5. DNS exfiltration
    m5 = mitre_mapper.map_alert("dns_threat", "High entropy DNS subdomain", {})
    assert m5["technique_id"] == "T1071.004"


def test_mitre_summary_matrix():
    fake_alerts = [
        {"category": "ransomware", "message": "Canary trap tripped", "timestamp": "2026-11-07T10:00:00Z"},
        {"category": "brute_force", "message": "SSH lockout", "timestamp": "2026-11-07T10:05:00Z"},
        {"category": "port_scan", "message": "TCP sweep", "timestamp": "2026-11-07T10:10:00Z"},
    ]
    summary = mitre_mapper.summarize_matrix(fake_alerts)
    assert summary["total_techniques"] == len(MITRE_TECHNIQUES)
    assert summary["active_techniques"] == 3
    assert summary["coverage_percentage"] > 0
    assert len(summary["tactics"]) == len(MITRE_TACTICS)


def test_posture_engine_scoring():
    # Test optimal posture
    p_opt = posture_engine.calculate_posture(
        rules_count=5,
        unhandled_critical_alerts=0,
        open_cves=0,
        models_loaded=True,
        canary_armed=True,
        allowlist_count=3,
    )
    assert p_opt["score"] >= 85
    assert p_opt["grade"] in ["A", "A+"]
    assert "optimal" in p_opt["recommendations"][0].lower()

    # Test degraded posture with critical alerts and open CVEs
    p_deg = posture_engine.calculate_posture(
        rules_count=0,
        unhandled_critical_alerts=4,
        open_cves=3,
        models_loaded=False,
        canary_armed=False,
        allowlist_count=0,
    )
    assert p_deg["score"] < 60
    assert p_deg["grade"] in ["C", "D"]
    assert any("critical alert" in r for r in p_deg["recommendations"])
    assert any("cve" in r.lower() for r in p_deg["recommendations"])


def test_xai_explainer_url_phishing():
    # Suspicious domain with high entropy and raw IP
    res = xai_explainer.explain_url_prediction(
        url="http://192.168.1.100/login-account-verify.xyz?q=a8f9b7c2d1e4",
        phishing_probability=0.92,
    )
    assert res["decision"] == "Malicious"
    assert res["confidence"] > 80
    assert len(res["feature_contributions"]) >= 2
    # Verify percentage sum is ~100
    total_pct = sum(c["percentage"] for c in res["feature_contributions"])
    assert 99.0 <= total_pct <= 101.0


def test_xai_explainer_flow_anomaly():
    res = xai_explainer.explain_flow_anomaly(
        pps=120.0,
        byte_size=1500,
        protocol="TCP",
        anomaly_score=0.88,
        inter_arrival_ms=1.2,
    )
    assert res["classification"] == "Anomaly"
    assert res["anomaly_score"] == 0.88
    assert len(res["factors"]) >= 2
    total_pct = sum(f["percentage"] for f in res["factors"])
    assert 99.0 <= total_pct <= 101.0

