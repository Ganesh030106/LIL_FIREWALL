"""Unit tests for Detection Engines: Brute-Force, DNS Threats, and Phishing ML."""

from __future__ import annotations

from security.brute_force_detector import BruteForceDetector
from security.dns_threat_detector import DNSThreatDetector, calculate_entropy
from ai_engine.threat_services import PhishingDetector
from model_generator import extract_features


def test_brute_force_detector_triggers() -> None:
    detector = BruteForceDetector()
    attacker_ip = "198.51.100.55"

    alert = None
    # Default threshold is 5 attempts
    for _ in range(5):
        alert = detector.record_attempt(attacker_ip, dst_ip="10.0.0.1", dst_port=22)

    assert alert is not None
    assert alert["category"] == "Brute Force Attack"
    assert alert["severity"] in ("high", "critical")
    assert alert["meta"]["service"] == "SSH"
    assert alert["meta"]["port"] == 22
    assert alert["meta"]["attempt_count"] >= 5

    # Cooldown prevents immediate re-alerting
    duplicate_alert = detector.record_attempt(attacker_ip, dst_ip="10.0.0.1", dst_port=22)
    assert duplicate_alert is None


def test_brute_force_ignores_unmonitored_ports() -> None:
    detector = BruteForceDetector()
    for _ in range(10):
        alert = detector.record_attempt("198.51.100.60", dst_ip="10.0.0.1", dst_port=80)
        assert alert is None


def test_dns_threat_entropy_calculation() -> None:
    low_ent = calculate_entropy("aaaaaaa")
    assert low_ent == 0.0

    norm_ent = calculate_entropy("google")
    assert 1.5 < norm_ent < 3.0

    high_ent = calculate_entropy("c2VjcmV0ZGF0YXRvYmVleGZpbHRyYXRlZDFmMjM0")
    assert high_ent > 3.8


def test_dns_threat_tunneling_detection() -> None:
    detector = DNSThreatDetector()
    src_ip = "10.0.0.99"

    # Encoded exfiltration payload query (length > 45, entropy > 3.8)
    tunnel_domain = "a8f7c9e1b2d3f4a5b6c7d8e9f0123456789abcdef0123456789abcdef.exfil.attacker.net"
    alert = detector.inspect_query(src_ip, tunnel_domain)

    assert alert is not None
    assert alert["category"] == "DNS Threat"
    assert alert["severity"] in ("high", "critical")
    assert alert["meta"]["threat_type"] == "DNS_TUNNELING"
    assert alert["meta"]["entropy"] > 3.8
    assert alert["meta"]["subdomain_length"] >= 45


def test_dns_threat_dga_detection() -> None:
    detector = DNSThreatDetector()
    src_ip = "10.0.0.101"

    # DGA-generated algorithmic domain
    dga_domain = "xqzpthbkfwrlnmzvd.ru"
    alert = detector.inspect_query(src_ip, dga_domain)

    assert alert is not None
    assert alert["category"] == "DNS Threat"
    assert alert["severity"] in ("high", "critical")
    assert alert["meta"]["threat_type"] == "DGA"
    assert alert["meta"]["entropy"] > 3.5


def test_dns_threat_normal_traffic_safe() -> None:
    detector = DNSThreatDetector()
    safe_domains = [
        "www.google.com",
        "api.github.com",
        "update.microsoft.com",
        "cdn.cloudflare.net",
    ]
    for d in safe_domains:
        assert detector.inspect_query("10.0.0.5", d) is None


def test_phishing_feature_extraction_shape() -> None:
    features = extract_features("https://secure-login.bank-update.com/verify?account=123")
    assert isinstance(features, list)
    assert len(features) == 10  # Upgraded 10-feature vector
    assert all(isinstance(v, (int, float)) for v in features)


def test_phishing_detector_classification() -> None:
    detector = PhishingDetector()
    if detector.model is None:
        return

    # Check benign domain
    benign_result = detector.predict("https://www.google.com")
    assert benign_result["is_safe"] is True
    assert benign_result["classification"] == "Safe"
    assert benign_result["final_risk_score"] < 0.5

    # Check suspicious phishing URL
    malicious_url = "http://192.168.1.1/paypal.com/security/login-verification-update.php?token=xyz"
    phish_result = detector.predict(malicious_url)
    assert phish_result["final_risk_score"] > 0.4
