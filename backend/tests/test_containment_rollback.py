"""Unit tests for Containment Rollback and Dry-Run (Task 7)."""

from __future__ import annotations

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from ai.response_engine import ResponseAction, ResponseEngine
from core.rule_engine import RuleEngine
from storage.auth import create_access_token
from storage.database import Database


@pytest.fixture
def test_db(tmp_path: Path) -> Database:
    db_file = tmp_path / "test_rollback.db"
    return Database(str(db_file))


@pytest.fixture
def rule_engine() -> RuleEngine:
    return RuleEngine()


@pytest.fixture
def response_engine(rule_engine: RuleEngine, test_db: Database) -> ResponseEngine:
    return ResponseEngine(rule_engine=rule_engine, db=test_db, dry_run=False)


def test_snapshot_taken_before_each_change(response_engine: ResponseEngine) -> None:
    assert len(response_engine._snapshots) == 0

    # First change takes snapshot #1
    response_engine.trigger_response(ResponseAction.BLOCK, "198.51.100.10", duration=600)
    assert len(response_engine._snapshots) == 1

    # Second change takes snapshot #2
    response_engine.trigger_response(ResponseAction.BLOCK, "198.51.100.11", duration=600)
    assert len(response_engine._snapshots) == 2

    # Verify maximum 10 snapshots bounded queue
    for i in range(15):
        response_engine.trigger_response(ResponseAction.BLOCK, f"198.51.100.{20 + i}", duration=600)

    assert len(response_engine._snapshots) == 10


def test_rollback_restores_prior_state(response_engine: ResponseEngine) -> None:
    # Initial state: 0 rules
    assert len(response_engine.rule_engine.list_rules()) == 0

    # Block an IP
    response_engine.trigger_response(ResponseAction.BLOCK, "198.51.100.50", duration=1200)
    assert len(response_engine.rule_engine.list_rules()) == 1
    assert response_engine.is_ip_blocked("198.51.100.50") is True

    # Rollback restores state prior to the block
    res = response_engine.rollback(dry_run=False, username="admin")
    assert res["success"] is True
    assert res["dry_run"] is False
    assert len(response_engine.rule_engine.list_rules()) == 0
    assert response_engine.is_ip_blocked("198.51.100.50") is False


def test_dry_run_leaves_state_untouched(response_engine: ResponseEngine) -> None:
    # Block an IP
    response_engine.trigger_response(ResponseAction.BLOCK, "198.51.100.60", duration=1200)
    assert len(response_engine.rule_engine.list_rules()) == 1
    snapshots_before = len(response_engine._snapshots)

    # Rollback with dry_run=True returns diff without mutating state
    res = response_engine.rollback(dry_run=True, username="admin")
    assert res["success"] is True
    assert res["dry_run"] is True
    assert res["diff"]["rules_to_remove_count"] == 1
    assert "Auto Block: 198.51.100.60" in res["diff"]["rules_to_remove"]

    # State and snapshot count must remain unchanged
    assert len(response_engine.rule_engine.list_rules()) == 1
    assert len(response_engine._snapshots) == snapshots_before


def test_dry_run_containment_mode(rule_engine: RuleEngine, test_db: Database) -> None:
    # Explicit dry_run=True on response engine
    dry_engine = ResponseEngine(rule_engine=rule_engine, db=test_db, dry_run=True)
    assert dry_engine.is_dry_run() is True

    # Trigger block in dry-run mode
    resp = dry_engine.trigger_response(ResponseAction.BLOCK, "203.0.113.88", duration=3600)
    assert resp.metadata["dry_run"] is True
    assert resp.metadata["simulated"] is True
    assert resp.metadata["blocked"] is False

    # RuleEngine has 0 rules (firewall left untouched)
    assert len(rule_engine.list_rules()) == 0


def test_rollback_is_audited(response_engine: ResponseEngine, test_db: Database) -> None:
    response_engine.trigger_response(ResponseAction.BLOCK, "198.51.100.70", duration=1200)
    response_engine.rollback(dry_run=False, username="audit_admin")

    audits = test_db.get_audit_logs(limit=10)
    rollback_audits = [a for a in audits if a["action"] == "containment_rollback"]
    assert len(rollback_audits) >= 1
    assert rollback_audits[0]["user_id"] == "audit_admin"
    assert rollback_audits[0]["status"] == "success"


def test_rollback_api_endpoint() -> None:
    from app import app, response_engine as live_response_engine

    client = TestClient(app)

    # 1. Unauthenticated request -> 401 or 403
    res_unauth = client.post("/api/containment/rollback")
    assert res_unauth.status_code in (401, 403)

    # 2. Non-admin request -> 403
    analyst_token = create_access_token(user_id="2", username="analyst_user", role="analyst")
    res_forbidden = client.post("/api/containment/rollback", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res_forbidden.status_code == 403

    # 3. Trigger a block on live response engine to create a snapshot
    live_response_engine.trigger_response(ResponseAction.BLOCK, "198.51.100.80", duration=600)

    # 4. Admin dry-run rollback -> 200
    admin_token = create_access_token(user_id="1", username="admin", role="admin")
    headers = {"Authorization": f"Bearer {admin_token}"}
    res_dry = client.post("/api/containment/rollback", json={"dry_run": True}, headers=headers)
    assert res_dry.status_code == 200
    dry_data = res_dry.json()
    assert dry_data["success"] is True
    assert dry_data["dry_run"] is True
    assert "diff" in dry_data

    # 5. Admin live rollback -> 200
    res_live = client.post("/api/containment/rollback", json={"dry_run": False}, headers=headers)
    assert res_live.status_code == 200
    live_data = res_live.json()
    assert live_data["success"] is True
    assert live_data["dry_run"] is False


def test_health_endpoint_exposes_containment_mode() -> None:
    from app import app

    client = TestClient(app)
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()

    assert "containment_mode" in data
    assert data["containment_mode"] in ("dry_run", "live")
    assert "dry_run" in data
    assert isinstance(data["dry_run"], bool)
    assert "enforcement_mode" in data
    assert "enforcement_backend" in data
    assert "snapshots_available" in data
