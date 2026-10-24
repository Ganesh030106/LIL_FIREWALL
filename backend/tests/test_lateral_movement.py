"""Unit tests for Lateral Movement Detection (Task 4)."""

from __future__ import annotations

from security.lateral_movement_detector import (
    LateralMovementDetector,
    is_internal_rfc1918,
)


def test_is_internal_rfc1918() -> None:
    # RFC 1918 private IPv4
    assert is_internal_rfc1918("10.0.0.1") is True
    assert is_internal_rfc1918("10.255.255.255") is True
    assert is_internal_rfc1918("172.16.5.10") is True
    assert is_internal_rfc1918("172.31.255.254") is True
    assert is_internal_rfc1918("192.168.1.1") is True
    assert is_internal_rfc1918("192.168.100.50") is True

    # Loopback, unspecified, and multicast must be strictly excluded
    assert is_internal_rfc1918("127.0.0.1") is False
    assert is_internal_rfc1918("::1") is False
    assert is_internal_rfc1918("0.0.0.0") is False
    assert is_internal_rfc1918("224.0.0.1") is False

    # External public IPs
    assert is_internal_rfc1918("8.8.8.8") is False
    assert is_internal_rfc1918("1.1.1.1") is False
    assert is_internal_rfc1918("198.51.100.22") is False
    assert is_internal_rfc1918("203.0.113.5") is False
    assert is_internal_rfc1918("invalid-ip") is False


def test_internal_fanout_alerts() -> None:
    detector = LateralMovementDetector()
    src_ip = "10.0.1.50"
    base_time = 10000.0

    # Fan out to 6 distinct internal RFC 1918 hosts on admin ports within window
    internal_hosts = [
        ("10.0.1.1", 445),   # SMB
        ("10.0.1.2", 22),    # SSH
        ("10.0.1.3", 3389),  # RDP
        ("10.0.1.4", 5985),  # WinRM
        ("10.0.1.5", 445),   # SMB (5th host reaches threshold)
        ("10.0.1.6", 22),    # SSH (6th host)
    ]

    last_alert = None
    for i, (dst, port) in enumerate(internal_hosts):
        alert = detector.record_connection(src_ip, dst, port, timestamp=base_time + (i * 10.0))
        if alert:
            last_alert = alert

    assert last_alert is not None
    assert last_alert["category"] == "Possible Lateral Movement"
    assert last_alert["severity"] == "high"
    assert last_alert["meta"]["source_ip"] == src_ip
    assert last_alert["meta"]["destination_count"] >= 5
    assert "10.0.1.5" in last_alert["meta"]["destinations"]


def test_external_fanout_does_not_alert() -> None:
    detector = LateralMovementDetector()
    src_ip = "10.0.1.50"
    base_time = 20000.0

    # Fan out to 6 external destinations (should never trigger lateral movement alert)
    external_hosts = [
        "8.8.8.8",
        "1.1.1.1",
        "9.9.9.9",
        "208.67.222.222",
        "142.250.190.46",
        "151.101.1.69",
    ]

    for i, dst in enumerate(external_hosts):
        alert = detector.record_connection(src_ip, dst, 445, timestamp=base_time + (i * 5.0))
        assert alert is None


def test_below_threshold_does_not_alert() -> None:
    detector = LateralMovementDetector()
    src_ip = "192.168.1.20"
    base_time = 30000.0

    # Contacts only 3 internal endpoints (threshold is 5)
    for i in range(3):
        dst = f"192.168.1.{100 + i}"
        alert = detector.record_connection(src_ip, dst, 3389, timestamp=base_time + (i * 10.0))
        assert alert is None


def test_hosts_outside_window_expire() -> None:
    detector = LateralMovementDetector()
    src_ip = "172.16.0.10"
    start_time = 40000.0

    # Contact 4 hosts at start_time
    for i in range(4):
        dst = f"172.16.0.{50 + i}"
        alert = detector.record_connection(src_ip, dst, 445, timestamp=start_time)
        assert alert is None

    # Advance time by 350 seconds (exceeds VOLCANO_LATERAL_WINDOW = 300s)
    future_time = start_time + 350.0

    # Contact a 5th host at future_time
    alert = detector.record_connection(src_ip, "172.16.0.99", 445, timestamp=future_time)
    # The previous 4 hosts expired, so active destination count is only 1
    assert alert is None


def test_non_admin_ports_ignored() -> None:
    detector = LateralMovementDetector()
    src_ip = "10.0.2.15"
    base_time = 50000.0

    # Contact 10 internal hosts on non-admin web/dns ports (80, 443, 53)
    for i in range(10):
        dst = f"10.0.2.{100 + i}"
        alert = detector.record_connection(src_ip, dst, 80, timestamp=base_time + i)
        assert alert is None
        alert2 = detector.record_connection(src_ip, dst, 443, timestamp=base_time + i)
        assert alert2 is None


def test_lateral_movement_pipeline_integration() -> None:
    from app import packet_engine, alerts

    alerts._items.clear()
    src = "10.10.10.5"
    base_time = 60000.0

    # Simulate 5 internal admin contacts
    for i in range(5):
        dst = f"10.10.10.{20 + i}"
        alert = packet_engine.lateral_detector.record_connection(src, dst, 445, timestamp=base_time + i)
        if alert:
            alerts.add(
                source=alert["source"],
                severity=alert["severity"],
                category=alert["category"],
                message=alert["message"],
                meta=alert["meta"],
            )

    matching_alerts = [a for a in alerts.list() if a.get("category") == "Possible Lateral Movement"]
    assert len(matching_alerts) >= 1
    assert matching_alerts[0]["severity"] == "high"
    assert matching_alerts[0]["meta"]["source_ip"] == src
    assert matching_alerts[0]["meta"]["destination_count"] >= 5
