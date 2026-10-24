"""Unit tests for Alert Triage, Bulk Operations, and Audit Logging."""

from __future__ import annotations

from storage.database import Database


def test_alert_triage_lifecycle(test_db: Database) -> None:
    # 1. Insert alert
    alert_payload = {
        "timestamp": 1700000000.0,
        "source": "network",
        "severity": "high",
        "category": "Port Scan",
        "message": "Potential port scan from 198.51.100.12",
        "meta": {"src_ip": "198.51.100.12"},
    }
    test_db.save_alert(alert_payload)

    alerts = test_db.get_recent_alerts(limit=10)
    assert len(alerts) >= 1
    alert_id = alerts[0]["id"]
    assert alerts[0]["status"] == "new"
    assert alerts[0]["assignee"] is None

    # 2. Update triage status
    updated = test_db.update_alert_triage(
        alert_id=alert_id,
        status="in_progress",
        assignee="analyst_alice",
        notes="Investigating traffic origin.",
    )
    assert updated is True

    # 3. Verify changes
    refreshed = test_db.get_alert(alert_id)
    assert refreshed is not None
    assert refreshed["status"] == "in_progress"
    assert refreshed["assignee"] == "analyst_alice"
    assert refreshed["notes"] == "Investigating traffic origin."


def test_bulk_triage_actions(test_db: Database) -> None:
    # Insert multiple test alerts
    ids = []
    for i in range(3):
        test_db.save_alert({
            "timestamp": 1700000000.0 + i,
            "source": "test",
            "severity": "medium",
            "category": "DNS Test",
            "message": f"Test alert {i}",
        })
    recent = test_db.get_recent_alerts(limit=5)
    ids = [a["id"] for a in recent[:3]]

    # Bulk resolve
    resolved_count = test_db.bulk_update_alerts(ids, action="resolve")
    assert resolved_count == len(ids)

    for aid in ids:
        a = test_db.get_alert(aid)
        assert a is not None
        assert a["status"] == "resolved"


def test_audit_logging(test_db: Database) -> None:
    test_db.log_audit(
        user_id="admin",
        action="UPDATE_CONFIG",
        resource="detection_thresholds",
        changes={"brute_force_threshold": 10},
        status="success",
    )

    logs = test_db.get_audit_logs(limit=10)
    assert len(logs) >= 1
    latest = logs[0]
    assert latest["user_id"] == "admin"
    assert latest["action"] == "UPDATE_CONFIG"
    assert latest["resource"] == "detection_thresholds"
    assert latest["changes"]["brute_force_threshold"] == 10
