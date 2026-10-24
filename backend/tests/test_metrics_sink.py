"""Tests for Task 4: Time-Series Metrics Storage and Prometheus Exposition."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry
from prometheus_client.parser import text_string_to_metric_families

from app import app
from config import load_settings
from storage.metrics_sink import InMemorySink, PrometheusSink


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_metric_names_exist_and_increment() -> None:
    """PrometheusSink registers required metrics, increments values, and parses with Prometheus parser."""
    registry = CollectorRegistry(auto_describe=True)
    sink = PrometheusSink(registry=registry)

    # 1. Update values
    sink.set_packet_rate(142.5)
    sink.record_alert(severity="critical", category="Ransomware")
    sink.record_alert(severity="critical", category="Ransomware")
    sink.record_alert(severity="high", category="Port Scan")
    sink.record_dropped_events(7)
    sink.record_rate_limit_rejection("login")
    sink.record_containment_action("block_ip")
    sink.record_containment_action("isolate_host")
    sink.set_enforcement_mode("active")

    metrics_text = sink.get_metrics_text()
    assert metrics_text is not None
    assert len(metrics_text) > 0

    # 2. Parse using official prometheus_client text parser
    families = list(text_string_to_metric_families(metrics_text))
    all_sample_names = {s.name for f in families for s in f.samples}
    family_map = {f.name: f for f in families}

    assert "volcano_packet_rate" in all_sample_names
    assert "volcano_alerts_total" in all_sample_names
    assert "volcano_dropped_events_total" in all_sample_names
    assert "volcano_rate_limit_rejections_total" in all_sample_names
    assert "volcano_containment_actions_total" in all_sample_names
    assert "volcano_enforcement_mode" in all_sample_names

    # Check sample values
    packet_rate_sample = family_map["volcano_packet_rate"].samples[0]
    assert packet_rate_sample.value == 142.5

    dropped_sample = family_map["volcano_dropped_events"].samples[0]
    assert dropped_sample.value == 7.0

    # Check alert samples by severity
    alert_samples = {s.labels["severity"]: s.value for s in family_map["volcano_alerts"].samples if s.name == "volcano_alerts_total"}
    assert alert_samples["critical"] == 2.0
    assert alert_samples["high"] == 1.0


def test_in_memory_sink_default_behavior() -> None:
    """InMemorySink maintains counters and snapshots without external dependencies."""
    sink = InMemorySink()
    sink.set_packet_rate(50.0)
    sink.record_packet(10)
    sink.record_alert("medium", "DNS Tunneling")
    sink.record_dropped_events(3)
    sink.record_rate_limit_rejection("login")
    sink.record_containment_action("quarantine")
    sink.set_enforcement_mode("dry_run")

    snap = sink.snapshot()
    assert snap["packet_rate"] == 50.0
    assert snap["packet_count"] == 10
    assert snap["alerts_by_severity"]["medium"] == 1
    assert snap["dropped_events"] == 3
    assert snap["rate_limit_rejections"]["login"] == 1
    assert snap["containment_actions"]["quarantine"] == 1
    assert snap["enforcement_mode"] == "dry_run"

    text = sink.get_metrics_text()
    assert "volcano_packet_rate 50.0" in text
    assert "volcano_dropped_events_total 3" in text


def test_metrics_absent_when_disabled(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    """GET /metrics must return HTTP 404 when VOLCANO_METRICS_ENABLED=false."""
    monkeypatch.setenv("VOLCANO_METRICS_ENABLED", "false")
    load_settings()

    resp = client.get("/metrics")
    assert resp.status_code == 404
    assert "disabled" in resp.json()["detail"].lower()


def test_metrics_token_protection(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    """GET /metrics enforces bearer token authentication when configured."""
    monkeypatch.setenv("VOLCANO_METRICS_ENABLED", "true")
    monkeypatch.setenv("VOLCANO_METRICS_BEARER_TOKEN", "volcano-secret-metrics-token-99")
    load_settings()

    # 1. No token -> 401
    resp_no_token = client.get("/metrics")
    assert resp_no_token.status_code == 401

    # 2. Wrong token -> 401
    resp_bad_token = client.get("/metrics", headers={"Authorization": "Bearer wrong-token"})
    assert resp_bad_token.status_code == 401

    # 3. Correct token -> 200 and parses with prometheus parser
    resp_ok = client.get("/metrics", headers={"Authorization": "Bearer volcano-secret-metrics-token-99"})
    assert resp_ok.status_code == 200
    assert "text/plain" in resp_ok.headers.get("content-type", "")

    # Parse body
    parsed = list(text_string_to_metric_families(resp_ok.text))
    assert len(parsed) > 0
