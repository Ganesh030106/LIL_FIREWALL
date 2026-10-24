"""Unit tests for BeaconDetector (Task 3: C2 Beaconing Detection)."""

from __future__ import annotations

import random
from security.beacon_detector import BeaconDetector


def test_periodic_synthetic_stream_alerts() -> None:
    detector = BeaconDetector()
    src_ip = "192.168.1.100"
    dst_ip = "203.0.113.50"
    dst_port = 4444

    # Generate 10 events spaced ~60 seconds apart with tiny jitter (±0.5 sec)
    base_time = 1000000.0
    current_time = base_time
    alert = None

    for i in range(10):
        jitter_offset = (random.random() - 0.5) * 1.0  # [-0.5, 0.5]
        event_time = current_time + jitter_offset
        res = detector.record_connection(src_ip, dst_ip, dst_port, timestamp=event_time)
        if res:
            alert = res
        current_time += 60.0

    assert alert is not None
    assert alert["category"] == "Possible C2 Beaconing"
    assert alert["severity"] == "high"
    assert alert["meta"]["source_ip"] == src_ip
    assert alert["meta"]["destination_ip"] == dst_ip
    assert alert["meta"]["destination_port"] == dst_port
    assert 58.0 <= alert["meta"]["observed_interval"] <= 62.0
    assert alert["meta"]["observed_jitter"] < 0.15
    assert alert["meta"]["event_count"] >= 10


def test_random_poisson_stream_does_not_alert() -> None:
    detector = BeaconDetector()
    src_ip = "192.168.1.105"
    dst_ip = "198.51.100.80"
    dst_port = 443

    # Random Poisson-like inter-arrival times with high variance
    intervals = [5.0, 85.0, 12.0, 140.0, 3.0, 95.0, 22.0, 180.0, 7.0, 110.0, 15.0, 130.0]
    current_time = 2000000.0

    for dt in intervals:
        current_time += dt
        alert = detector.record_connection(src_ip, dst_ip, dst_port, timestamp=current_time)
        assert alert is None  # High jitter must never trigger a beacon alert


def test_low_volume_stream_does_not_alert() -> None:
    detector = BeaconDetector()
    src_ip = "192.168.1.110"
    dst_ip = "203.0.113.99"
    dst_port = 8443

    # Only 5 events (default minimum is 10)
    current_time = 3000000.0
    for _ in range(5):
        current_time += 60.0
        alert = detector.record_connection(src_ip, dst_ip, dst_port, timestamp=current_time)
        assert alert is None


def test_chatty_traffic_bursts_ignored() -> None:
    detector = BeaconDetector()
    src_ip = "192.168.1.115"
    dst_ip = "203.0.113.10"
    dst_port = 80

    # 15 events arriving very fast (every 0.05 seconds: mean <= 1.0s)
    current_time = 4000000.0
    for _ in range(15):
        current_time += 0.05
        alert = detector.record_connection(src_ip, dst_ip, dst_port, timestamp=current_time)
        assert alert is None


def test_cooldown_suppresses_repeat_alerts() -> None:
    # Set a 100-second cooldown
    detector = BeaconDetector(cooldown=100.0)
    src_ip = "192.168.1.120"
    dst_ip = "198.51.100.200"
    dst_port = 9001

    base_time = 5000000.0
    current_time = base_time

    # Send 10 events (interval exactly 60s) -> should trigger alert on 10th (at t = base_time + 540s)
    first_alert = None
    for _ in range(10):
        res = detector.record_connection(src_ip, dst_ip, dst_port, timestamp=current_time)
        if res:
            first_alert = res
        current_time += 60.0

    assert first_alert is not None
    assert first_alert["category"] == "Possible C2 Beaconing"

    # Event 11 arrives at current_time (t = 540 + 60 = 600s).
    # Since 60s < 100s cooldown, it must be suppressed!
    suppressed_alert = detector.record_connection(src_ip, dst_ip, dst_port, timestamp=current_time)
    assert suppressed_alert is None

    # Event 12 arrives 60s later (t = 600 + 60 = 660s).
    # Now 660 - 540 = 120s >= 100s cooldown -> Cooldown expired, alert triggers!
    current_time += 60.0
    second_alert = detector.record_connection(src_ip, dst_ip, dst_port, timestamp=current_time)
    assert second_alert is not None
    assert second_alert["category"] == "Possible C2 Beaconing"


def test_beacon_detector_pipeline_integration() -> None:
    from app import packet_engine, alerts

    alerts._items.clear()
    src = "192.168.1.130"
    dst = "203.0.113.88"
    port = 8080

    base_time = 6000000.0
    # Simulate 10 packet events routed to packet_engine's beacon detector
    for i in range(10):
        t = base_time + (i * 60.0)
        alert = packet_engine.beacon_detector.record_connection(src, dst, port, timestamp=t)
        if alert:
            alerts.add(
                source=alert["source"],
                severity=alert["severity"],
                category=alert["category"],
                message=alert["message"],
                meta=alert["meta"],
            )

    matching_alerts = [a for a in alerts.list() if a.get("category") == "Possible C2 Beaconing"]
    assert len(matching_alerts) >= 1
    assert matching_alerts[0]["severity"] == "high"
    assert matching_alerts[0]["meta"]["destination_ip"] == dst
