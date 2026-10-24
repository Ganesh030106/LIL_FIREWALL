"""Unit tests for ResponseEngine allowlist safety and automatic unblock daemon."""

from __future__ import annotations

import time
from core.rule_engine import RuleEngine, RuleAction
from ai.response_engine import ResponseEngine, ResponseAction
from config import FirewallSettings


def test_response_engine_blocks_malicious_ip() -> None:
    rule_engine = RuleEngine()
    settings = FirewallSettings(
        auto_block_duration_minutes=1,
        allowlist_ips=["127.0.0.1", "10.0.0.1"],
    )
    engine = ResponseEngine(rule_engine=rule_engine, settings=settings)

    resp = engine.trigger_response(
        action=ResponseAction.BLOCK,
        target_ip="203.0.113.88",
        duration=60.0,
        reason="Port Scan",
    )

    assert resp is not None
    assert resp.id > 0
    assert resp.target_ip == "203.0.113.88"
    assert resp.metadata.get("blocked") is True

    # Check firewall rules
    rules = rule_engine.list_rules()
    matching = [r for r in rules if r.src_ip == "203.0.113.88"]
    assert len(matching) == 1
    assert matching[0].action in (RuleAction.DENY, RuleAction.DROP)

    engine.stop()


def test_response_engine_rejects_allowlisted_ips() -> None:
    rule_engine = RuleEngine()
    settings = FirewallSettings(
        allowlist_ips=["127.0.0.1", "10.0.0.1", "192.168.1.1"],
    )
    engine = ResponseEngine(rule_engine=rule_engine, settings=settings)

    # 1. Reject loopback
    resp_loopback = engine.trigger_response(
        action=ResponseAction.BLOCK,
        target_ip="127.0.0.1",
        reason="Test",
    )
    assert resp_loopback.id == 0
    assert resp_loopback.metadata.get("allowlisted") is True

    # 2. Reject configured allowlist IP
    resp_gateway = engine.trigger_response(
        action=ResponseAction.BLOCK,
        target_ip="10.0.0.1",
        reason="Test",
    )
    assert resp_gateway.id == 0
    assert resp_gateway.metadata.get("allowlisted") is True

    # Verify no rules created
    assert len(rule_engine.list_rules()) == 0

    engine.stop()


def test_response_engine_auto_unblock_expiry() -> None:
    rule_engine = RuleEngine()
    engine = ResponseEngine(rule_engine=rule_engine)

    # Trigger block with 1.0 second duration
    resp = engine.trigger_response(
        action=ResponseAction.BLOCK,
        target_ip="198.51.100.99",
        duration=1.0,
        reason="Quick Attack",
    )

    assert resp.id > 0
    assert len(rule_engine.list_rules()) == 1

    # Wait for the unblock daemon loop (sleeps 2s)
    time.sleep(3.0)

    # Rule should now have expired and been removed
    rules = rule_engine.list_rules()
    active_blocks = [r for r in rules if r.src_ip == "198.51.100.99"]
    assert len(active_blocks) == 0

    engine.stop()
