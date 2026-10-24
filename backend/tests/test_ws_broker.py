"""Tests for Task 6: Horizontal WebSocket Scaling and Redis Pub/Sub Broker."""

from __future__ import annotations

import time
from typing import Any, List, Tuple
import pytest

from security.ws_broker import (
    InProcessWsBroker,
    RedisPubSubBroker,
    get_ws_broker,
)

try:
    import fakeredis
    FAKEREDIS_AVAILABLE = True
except ImportError:
    FAKEREDIS_AVAILABLE = False


def test_in_process_broker_default() -> None:
    """InProcessWsBroker immediately delivers published events to local subscribers."""
    broker = InProcessWsBroker(origin_id="in-process-test")
    received: List[Tuple[str, Any]] = []

    broker.subscribe(lambda etype, data, ts: received.append((etype, data)))

    broker.publish("test_event", {"status": "active"}, timestamp="2026-10-15T12:00:00Z")
    assert len(received) == 1
    assert received[0] == ("test_event", {"status": "active"})

    broker.close()


@pytest.mark.skipif(not FAKEREDIS_AVAILABLE, reason="fakeredis not installed")
def test_two_redis_brokers_deliver_to_each_other_exactly_once() -> None:
    """Two RedisPubSubBroker instances sharing one Redis deliver broadcasts to each other exactly once."""
    fake_server = fakeredis.FakeServer()
    redis_client1 = fakeredis.FakeRedis(server=fake_server, decode_responses=True)
    redis_client2 = fakeredis.FakeRedis(server=fake_server, decode_responses=True)

    broker1 = RedisPubSubBroker(
        redis_client=redis_client1,
        channel="volcano:ws:cluster",
        origin_id="node-alpha",
    )
    broker2 = RedisPubSubBroker(
        redis_client=redis_client2,
        channel="volcano:ws:cluster",
        origin_id="node-beta",
    )

    received_node1: List[Tuple[str, Any]] = []
    received_node2: List[Tuple[str, Any]] = []

    broker1.subscribe(lambda t, d, ts: received_node1.append((t, d)))
    broker2.subscribe(lambda t, d, ts: received_node2.append((t, d)))

    time.sleep(0.1)  # Allow pubsub subscription threads to settle

    # Node 1 publishes an alert broadcast
    broker1.publish("alert_created", {"id": 101, "title": "Lateral Movement"})

    # Wait for pubsub message dissemination
    time.sleep(0.5)

    # Node 1 local sockets must have received it exactly once (via direct local dispatch)
    assert len(received_node1) == 1
    assert received_node1[0] == ("alert_created", {"id": 101, "title": "Lateral Movement"})

    # Node 2 must have received it exactly once (via Redis Pub/Sub relay)
    assert len(received_node2) == 1
    assert received_node2[0] == ("alert_created", {"id": 101, "title": "Lateral Movement"})

    # Now Node 2 publishes a block notification
    broker2.publish("rule_blocked", {"ip": "198.51.100.22"})

    time.sleep(0.5)

    # Both nodes must now have exactly 2 received events
    assert len(received_node1) == 2
    assert received_node1[1] == ("rule_blocked", {"ip": "198.51.100.22"})

    assert len(received_node2) == 2
    assert received_node2[1] == ("rule_blocked", {"ip": "198.51.100.22"})

    broker1.close()
    broker2.close()


@pytest.mark.skipif(not FAKEREDIS_AVAILABLE, reason="fakeredis not installed")
def test_origin_id_filter_drops_reflected_messages() -> None:
    """A broker instance ignores incoming pubsub messages matching its own origin_id."""
    fake_server = fakeredis.FakeServer()
    redis_client = fakeredis.FakeRedis(server=fake_server, decode_responses=True)

    broker = RedisPubSubBroker(
        redis_client=redis_client,
        channel="volcano:ws:filter_test",
        origin_id="test-replica-77",
    )

    received: List[str] = []
    broker.subscribe(lambda t, d, ts: received.append(d["seq"]))

    time.sleep(0.1)

    # Publish message 1
    broker.publish("test", {"seq": "msg-1"})

    time.sleep(0.4)

    # Only 1 receipt must be registered (not 2 from self-reflection)
    assert received == ["msg-1"]

    broker.close()


def test_factory_defaults_to_in_process_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_ws_broker defaults to InProcessWsBroker when unconfigured."""
    monkeypatch.delenv("VOLCANO_WS_BROKER", raising=False)
    b = get_ws_broker()
    assert isinstance(b, InProcessWsBroker)
    b.close()
