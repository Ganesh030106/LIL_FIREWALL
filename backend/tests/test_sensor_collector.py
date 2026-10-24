"""Tests for Task 3: Sensor and Collector Split Architecture."""

from __future__ import annotations

import struct
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import app, db, alerts
from sensor.schema import SensorEvent, SensorEventBatch
from sensor.buffer import BoundedEventBuffer
from sensor.transport import InProcessTransport, HttpBatchTransport
from sensor.adapters.zeek import ZeekConnLogAdapter
from sensor.adapters.netflow import (
    NetFlowV9Parser,
    FIELD_IPV4_SRC_ADDR,
    FIELD_IPV4_DST_ADDR,
    FIELD_L4_DST_PORT,
)
from storage.auth import create_access_token


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def admin_headers() -> dict[str, str]:
    token = create_access_token(user_id="1", username="admin", role="admin")
    return {"Authorization": f"Bearer {token}"}


def test_schema_version_rejection() -> None:
    """SensorEvent and SensorEventBatch must reject unknown schema versions."""
    # Valid schema version
    valid_ev = SensorEvent(
        schema_version="1.0",
        event_type="alert",
        src_ip="192.168.1.1",
    )
    assert valid_ev.schema_version == "1.0"

    # Unsupported schema version in model
    with pytest.raises(ValidationError) as exc_info:
        SensorEvent(
            schema_version="99.0",
            event_type="alert",
        )
    assert "Unsupported schema version" in str(exc_info.value)

    with pytest.raises(ValidationError):
        SensorEventBatch(
            schema_version="2.5",
            sensor_id="sensor-bad",
            events=[],
        )


def test_sensor_token_hashing_and_revocation(client: TestClient, admin_headers: dict[str, str]) -> None:
    """Sensor tokens must be securely generated, hashed, and revokable."""
    # 1. Create sensor token via admin endpoint
    create_resp = client.post(
        "/api/admin/sensor-tokens",
        json={"sensor_id": "sensor-alpha", "description": "Edge Tap alpha"},
        headers=admin_headers,
    )
    assert create_resp.status_code == 200
    token_data = create_resp.json()
    raw_token = token_data["token"]
    token_id = token_data["token_id"]
    assert raw_token.startswith("vst_")

    # 2. Token must verify against stored SHA-256 hash
    verified = db.verify_sensor_token(raw_token)
    assert verified is not None
    assert verified["sensor_id"] == "sensor-alpha"

    # 3. List tokens
    list_resp = client.get("/api/admin/sensor-tokens", headers=admin_headers)
    assert list_resp.status_code == 200
    token_ids = [t["token_id"] for t in list_resp.json()["sensor_tokens"]]
    assert token_id in token_ids

    # 4. Revoke token
    del_resp = client.delete(f"/api/admin/sensor-tokens/{token_id}", headers=admin_headers)
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "revoked"

    # 5. Revoked token must no longer verify
    assert db.verify_sensor_token(raw_token) is None


def test_ingest_endpoint_auth_and_schema_rejection(client: TestClient, admin_headers: dict[str, str]) -> None:
    """POST /api/ingest/events must enforce token auth and schema versioning."""
    # Unauthenticated request
    unauth_resp = client.post("/api/ingest/events", json={"schema_version": "1.0", "sensor_id": "s1", "events": []})
    assert unauth_resp.status_code == 401

    # Create sensor token
    tok_resp = client.post(
        "/api/admin/sensor-tokens",
        json={"sensor_id": "sensor-ingest-test"},
        headers=admin_headers,
    )
    raw_token = tok_resp.json()["token"]

    # Request with invalid token
    bad_tok_resp = client.post(
        "/api/ingest/events",
        json={"schema_version": "1.0", "sensor_id": "s1", "events": []},
        headers={"X-Sensor-Token": "vst_invalid_fake_token"},
    )
    assert bad_tok_resp.status_code == 401

    # Request with unsupported schema version
    bad_ver_resp = client.post(
        "/api/ingest/events",
        json={"schema_version": "99.0", "sensor_id": "s1", "events": []},
        headers={"X-Sensor-Token": raw_token},
    )
    assert bad_ver_resp.status_code == 400
    assert "Unsupported schema version" in bad_ver_resp.json()["detail"]


def test_batch_transport_round_trip(client: TestClient, admin_headers: dict[str, str]) -> None:
    """HttpBatchTransport round trip posting batches into Volcano core."""
    # Issue a token
    tok_resp = client.post(
        "/api/admin/sensor-tokens",
        json={"sensor_id": "sensor-roundtrip"},
        headers=admin_headers,
    )
    raw_token = tok_resp.json()["token"]

    initial_alert_count = len(alerts.list())

    # Use HttpBatchTransport with TestClient session
    transport = HttpBatchTransport(
        endpoint_url="http://testserver/api/ingest/events",
        sensor_token=raw_token,
        sensor_id="sensor-roundtrip",
        batch_size=2,
        session=client,  # TestClient compatible with requests.Session
    )

    ev1 = SensorEvent(
        sensor_id="sensor-roundtrip",
        event_type="alert",
        src_ip="203.0.113.10",
        dst_ip="10.0.0.5",
        data={
            "source": "sensor:sensor-roundtrip",
            "severity": "high",
            "category": "Brute Force Ingest",
            "message": "Multiple SSH failed attempts from sensor",
        },
    )

    ev2 = SensorEvent(
        sensor_id="sensor-roundtrip",
        event_type="flow",
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        protocol="UDP",
        data={"pkts": 5, "bytes": 450},
    )

    transport.emit(ev1)
    transport.emit(ev2)
    transport.close()

    # Verify alert was ingested into Volcano core
    updated_alerts = alerts.list()
    assert len(updated_alerts) == initial_alert_count + 1
    found = any(a["category"] == "Brute Force Ingest" and a["severity"] == "high" for a in updated_alerts)
    assert found is True


def test_in_process_transport() -> None:
    """InProcessTransport invokes handler directly in memory."""
    captured = []
    transport = InProcessTransport(handler=lambda ev: captured.append(ev))

    ev = SensorEvent(
        sensor_id="local",
        event_type="alert",
        src_ip="127.0.0.1",
        data={"message": "In-process event"},
    )
    transport.emit(ev)
    assert len(captured) == 1
    assert captured[0].data["message"] == "In-process event"


def test_bounded_buffer_drop_oldest_under_burst() -> None:
    """Under burst, BoundedEventBuffer drops oldest events without blocking and increments dropped_events."""
    buf = BoundedEventBuffer(max_size=5)
    assert buf.dropped_events == 0

    # Push 8 events into capacity-5 buffer
    for i in range(8):
        ev = SensorEvent(
            sensor_id="test-sensor",
            event_type="flow",
            data={"index": i},
        )
        pushed = buf.push(ev)
        assert pushed is True

    # Buffer must hold exactly 5 newest events (indices 3, 4, 5, 6, 7)
    assert buf.size == 5
    assert buf.dropped_events == 3

    batch = buf.pop_batch(max_batch_size=10)
    assert len(batch) == 5
    remaining_indices = [e.data["index"] for e in batch]
    assert remaining_indices == [3, 4, 5, 6, 7]
    assert buf.size == 0


def test_zeek_log_parsing_from_fixture() -> None:
    """Zeek conn.log TSV parser extracts structured SensorEvent records from fixture."""
    fixture_path = Path(__file__).parent / "fixtures" / "zeek_conn_sample.log"
    adapter = ZeekConnLogAdapter(sensor_id="zeek-edge-test")
    events = adapter.parse_file(fixture_path)

    assert len(events) == 2

    ev1 = events[0]
    assert ev1.event_type == "flow"
    assert ev1.src_ip == "192.168.1.50"
    assert ev1.dst_ip == "10.0.0.1"
    assert ev1.src_port == 45123
    assert ev1.dst_port == 80
    assert ev1.protocol == "TCP"
    assert ev1.data["service"] == "http"
    assert ev1.data["conn_state"] == "SF"

    ev2 = events[1]
    assert ev2.src_ip == "192.168.1.50"
    assert ev2.dst_ip == "8.8.8.8"
    assert ev2.src_port == 53000
    assert ev2.dst_port == 53
    assert ev2.protocol == "UDP"
    assert ev2.data["service"] == "dns"


def test_netflow_v9_binary_parsing() -> None:
    """Basic NetFlow v9 parser decodes template and data flowsets into SensorEvent records."""
    parser = NetFlowV9Parser(sensor_id="netflow-edge-test")

    # Construct NetFlow v9 header (20 bytes)
    # version=9, count=2, sys_uptime=10000, unix_secs=1700000000, seq=1, src_id=1
    hdr = struct.pack("!HHIIII", 9, 2, 10000, 1700000000, 1, 1)

    # Template FlowSet: flowset_id=0, length=20 bytes
    # template_id=256, field_count=3
    # fields: (FIELD_IPV4_SRC_ADDR=8, 4), (FIELD_IPV4_DST_ADDR=12, 4), (FIELD_L4_DST_PORT=11, 2)
    template_hdr = struct.pack("!HH", 0, 20)
    template_rec = struct.pack("!HH", 256, 3)
    fields = struct.pack("!HHHHHH", FIELD_IPV4_SRC_ADDR, 4, FIELD_IPV4_DST_ADDR, 4, FIELD_L4_DST_PORT, 2)
    template_flowset = template_hdr + template_rec + fields

    # Data FlowSet: flowset_id=256, length=14 bytes (4 byte flowset header + 10 bytes record)
    # src_ip=192.168.1.20, dst_ip=10.0.0.1, dst_port=443
    data_hdr = struct.pack("!HH", 256, 14)
    data_rec = struct.pack("!4s4sH", b"\xc0\xa8\x01\x14", b"\x0a\x00\x00\x01", 443)
    data_flowset = data_hdr + data_rec

    raw_packet = hdr + template_flowset + data_flowset

    events = parser.parse_packet(raw_packet)
    assert len(events) == 1
    ev = events[0]
    assert ev.event_type == "flow"
    assert ev.src_ip == "192.168.1.20"
    assert ev.dst_ip == "10.0.0.1"
    assert ev.dst_port == 443
    assert ev.sensor_id == "netflow-edge-test"
