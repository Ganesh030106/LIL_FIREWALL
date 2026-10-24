"""Unit tests for SQLite Database Maintenance, WAL Checkpointing, and VACUUM."""

from __future__ import annotations

import time
from storage.database import Database


def test_database_status_diagnostics(test_db: Database) -> None:
    status = test_db.get_database_status()
    assert isinstance(status, dict)
    assert status["engine"] == "sqlite"
    assert status["journal_mode"].lower() == "wal"
    assert status["integrity"] in ("ok", "healthy")
    assert "table_counts" in status
    assert "alerts" in status["table_counts"]
    assert "rules" in status["table_counts"]
    assert "users" in status["table_counts"]
    assert status["page_size"] > 0
    assert status["page_count"] > 0


def test_wal_checkpointing(test_db: Database) -> None:
    # 1. Passive checkpoint
    passive_res = test_db.checkpoint_wal(mode="PASSIVE")
    assert passive_res["status"] == "success"
    assert "checkpointed_pages" in passive_res

    # 2. Truncate checkpoint (resets wal file size)
    truncate_res = test_db.checkpoint_wal(mode="TRUNCATE")
    assert truncate_res["status"] == "success"
    assert truncate_res["mode"] == "TRUNCATE"


def test_vacuum_compaction(test_db: Database) -> None:
    res = test_db.vacuum()
    assert res["status"] == "success"
    assert "before_size_bytes" in res
    assert "after_size_bytes" in res
    assert res["after_size_bytes"] > 0


def test_database_integrity_check(test_db: Database) -> None:
    check = test_db.run_integrity_check()
    assert check["status"] == "healthy"
    assert check["foreign_key_violations"] == 0
    assert "ok" in check["integrity_check"]


def test_prune_stale_alerts_and_logs(test_db: Database) -> None:
    # Insert older resolved alert (40 days ago)
    old_timestamp = time.time() - (40 * 86400)
    test_db.save_alert({
        "timestamp": old_timestamp,
        "source": "test",
        "severity": "low",
        "category": "Historical Scan",
        "message": "Old test alert",
        "status": "resolved",
    })

    # Insert fresh alert (today)
    test_db.save_alert({
        "timestamp": time.time(),
        "source": "test",
        "severity": "critical",
        "category": "Live Attack",
        "message": "Current alert",
        "status": "new",
    })

    # Prune alerts older than 30 days
    prune_res = test_db.prune_stale_data(max_alert_age_days=30, keep_minimum_alerts=0)
    assert prune_res["pruned_alerts"] >= 1

    # Verify only fresh alert remains or active alerts preserved
    remaining = test_db.get_recent_alerts(limit=50)
    categories = [a["category"] for a in remaining]
    assert "Live Attack" in categories
    assert "Historical Scan" not in categories


def test_optimize_planner(test_db: Database) -> None:
    opt = test_db.optimize()
    assert opt["status"] == "success"
