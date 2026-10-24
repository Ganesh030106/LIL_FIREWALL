"""Unit tests for Playbook Automation Engine (Task 5)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ai.playbooks import (
    PlaybookExecutor,
    PlaybookLoader,
    PlaybookValidationError,
    validate_playbook_schema,
)
from ai.response_engine import ResponseEngine
from core.rule_engine import RuleEngine
from storage.database import Database


@pytest.fixture
def test_db(tmp_path: Path) -> Database:
    db_file = tmp_path / "test_playbooks.db"
    return Database(str(db_file))


@pytest.fixture
def rule_engine() -> RuleEngine:
    return RuleEngine()


@pytest.fixture
def response_engine(rule_engine: RuleEngine, test_db: Database) -> ResponseEngine:
    return ResponseEngine(rule_engine=rule_engine, db=test_db)


def test_valid_playbook_loads() -> None:
    loader = PlaybookLoader()
    playbooks = loader.list_playbooks()
    valid_pbs = [p for p in playbooks if p["status"] == "valid"]
    assert len(valid_pbs) >= 2
    names = [p["name"] for p in valid_pbs]
    assert "ssh-brute-force-response" in names
    assert "c2-beaconing-response" in names


def test_invalid_playbook_schema_rejections() -> None:
    # 1. Missing name
    with pytest.raises(PlaybookValidationError, match="Missing or empty required field: 'name'"):
        validate_playbook_schema({"actions": [{"type": "notify", "channels": ["slack"]}]})

    # 2. Unknown action type
    with pytest.raises(PlaybookValidationError, match="Unknown action type 'launch_missiles'"):
        validate_playbook_schema({
            "name": "bad-action",
            "actions": [{"type": "launch_missiles"}],
        })

    # 3. Prohibited killswitch action
    with pytest.raises(PlaybookValidationError, match="Playbooks must not be able to run killswitch actions"):
        validate_playbook_schema({
            "name": "killswitch-attempt",
            "actions": [{"type": "killswitch"}],
        })

    # 4. Out of range duration (<= 0)
    with pytest.raises(PlaybookValidationError, match="duration_seconds.*out of range"):
        validate_playbook_schema({
            "name": "bad-duration",
            "actions": [{"type": "block_ip", "duration_seconds": 0}],
        })

    # 5. Out of range duration (> 30 days)
    with pytest.raises(PlaybookValidationError, match="duration_seconds.*out of range"):
        validate_playbook_schema({
            "name": "bad-duration-excess",
            "actions": [{"type": "block_ip", "duration_seconds": 99999999}],
        })

    # 6. Missing channels in notify
    with pytest.raises(PlaybookValidationError, match="missing or invalid required field 'channels'"):
        validate_playbook_schema({
            "name": "bad-notify",
            "actions": [{"type": "notify"}],
        })

    # 7. Invalid channel in notify
    with pytest.raises(PlaybookValidationError, match="invalid channel 'carrier_pigeon'"):
        validate_playbook_schema({
            "name": "bad-channel",
            "actions": [{"type": "notify", "channels": ["carrier_pigeon"]}],
        })


def test_loader_records_invalid_playbooks(tmp_path: Path) -> None:
    bad_yaml = tmp_path / "broken_playbook.yaml"
    bad_yaml.write_text(
        "name: broken\nactions:\n  - type: forbidden_action\n",
        encoding="utf-8",
    )
    loader = PlaybookLoader(directory=tmp_path)
    pbs = loader.list_playbooks()
    assert len(pbs) == 1
    assert pbs[0]["status"] == "invalid"
    assert "Unknown action type 'forbidden_action'" in pbs[0]["error"]


def test_block_ip_respects_allowlist(response_engine: ResponseEngine, test_db: Database) -> None:
    executor = PlaybookExecutor(response_engine=response_engine, db=test_db, dry_run=False)

    playbook = {
        "name": "test-allowlist-protection",
        "actions": [
            {"type": "block_ip", "duration_seconds": 3600},
            {"type": "create_alert_note", "note": "Allowlist test"},
        ],
    }

    # Attempt containment against protected loopback IP 127.0.0.1
    alert = {
        "id": 101,
        "category": "Brute Force Attack",
        "severity": "critical",
        "meta": {"source_ip": "127.0.0.1"},
    }

    result = executor.execute_playbook(playbook, alert)
    assert result["success"] is True

    # Block step was skipped due to allowlist
    step1 = result["steps"][0]
    assert step1["type"] == "block_ip"
    assert step1["status"] == "skipped"
    assert step1["allowlisted"] is True

    # Active firewall rules were NOT modified
    assert len(response_engine.rule_engine.list_rules()) == 0

    # Step 2 continued
    step2 = result["steps"][1]
    assert step2["type"] == "create_alert_note"
    assert step2["status"] == "success"

    # Audited as skipped
    audits = test_db.get_audit_logs(limit=10)
    skipped_audits = [a for a in audits if a["action"] == "block_ip" and a["status"] == "skipped"]
    assert len(skipped_audits) >= 1


def test_failure_halts_sequence(test_db: Database) -> None:
    executor = PlaybookExecutor(db=test_db, dry_run=False)

    playbook = {
        "name": "test-halt-on-failure",
        "actions": [
            {"type": "attach_pcap", "packets": 50},
            {"type": "block_ip", "duration_seconds": 3600},  # Will fail: no source_ip in alert
            {"type": "create_alert_note", "note": "This must never run"},
        ],
    }

    # Alert without source IP
    alert = {
        "id": 102,
        "category": "DNS Threat",
        "severity": "high",
        "meta": {},
    }

    result = executor.execute_playbook(playbook, alert)
    assert result["success"] is False
    assert result["steps_count"] == 2  # Halts on step 2, step 3 never executed!
    assert "No source IP found in alert to block" in result["halted_reason"]

    assert result["steps"][0]["status"] == "success"
    assert result["steps"][1]["status"] == "failed"

    # Verify audit logs record the failure
    audits = test_db.get_audit_logs(limit=10)
    failed_audits = [a for a in audits if a["status"] == "failed"]
    assert len(failed_audits) >= 1
    assert failed_audits[0]["action"] == "block_ip"


def test_every_step_is_audited(test_db: Database, response_engine: ResponseEngine) -> None:
    executor = PlaybookExecutor(response_engine=response_engine, db=test_db, dry_run=False)

    playbook = {
        "name": "audit-verification-playbook",
        "actions": [
            {"type": "block_ip", "duration_seconds": 1800},
            {"type": "attach_pcap", "packets": 150},
            {"type": "notify", "channels": ["slack"]},
        ],
    }

    alert = {
        "id": 103,
        "category": "Port Scan",
        "severity": "high",
        "meta": {"source_ip": "198.51.100.77"},
    }

    result = executor.execute_playbook(playbook, alert)
    assert result["success"] is True
    assert result["steps_count"] == 3

    audits = test_db.get_audit_logs(limit=10)
    playbook_audits = [a for a in audits if a["user_id"] == "playbook:audit-verification-playbook"]
    assert len(playbook_audits) == 3

    actions_audited = {a["action"] for a in playbook_audits}
    assert actions_audited == {"block_ip", "attach_pcap", "notify"}


def test_dry_run_execution_end_to_end(response_engine: ResponseEngine, test_db: Database) -> None:
    executor = PlaybookExecutor(response_engine=response_engine, db=test_db, dry_run=True)

    playbook = {
        "name": "dry-run-playbook",
        "actions": [
            {"type": "block_ip", "duration_seconds": 3600},
            {"type": "notify", "channels": ["slack"]},
            {"type": "attach_pcap", "packets": 200},
        ],
    }

    alert = {
        "id": 104,
        "category": "Possible C2 Beaconing",
        "severity": "high",
        "meta": {"source_ip": "203.0.113.88"},
    }

    result = executor.execute_playbook(playbook, alert, dry_run=True)
    assert result["success"] is True
    assert result["dry_run"] is True

    # All steps report simulated
    for step in result["steps"]:
        assert step["status"] == "simulated"
        assert step["dry_run"] is True

    # Rule engine must have NO active rules created in dry-run
    assert len(response_engine.rule_engine.list_rules()) == 0


def test_playbook_api_endpoints() -> None:
    from fastapi.testclient import TestClient
    from app import app
    from storage.auth import create_access_token

    client = TestClient(app)

    # 1. GET /api/playbooks
    res = client.get("/api/playbooks")
    assert res.status_code == 200
    data = res.json()
    assert "playbooks" in data
    assert len(data["playbooks"]) >= 2

    # 2. POST /api/playbooks/reload without auth -> 401 or 403
    res_noauth = client.post("/api/playbooks/reload")
    assert res_noauth.status_code in (401, 403)

    # 3. POST /api/playbooks/reload with admin token
    admin_token = create_access_token(user_id="1", username="admin", role="admin")
    headers = {"Authorization": f"Bearer {admin_token}"}
    res_admin = client.post("/api/playbooks/reload", headers=headers)
    assert res_admin.status_code == 200
    reload_data = res_admin.json()
    assert reload_data["status"] == "reloaded"
    assert reload_data["valid_count"] >= 2
