"""Unit tests for Volcano Authentication, RBAC, and Token Management."""

from __future__ import annotations

import pytest
from datetime import timedelta
from pathlib import Path
from storage.auth import (
    get_password_hash,
    verify_password,
    create_access_token,
    verify_token,
)
from storage.database import Database


def test_password_hashing() -> None:
    raw = "SecureP@ssw0rd!"
    hashed = get_password_hash(raw)
    assert hashed != raw
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
    assert verify_password(raw, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_jwt_token_lifecycle() -> None:
    token = create_access_token(
        user_id="101",
        username="analyst_bob",
        role="analyst",
        expires_delta=timedelta(minutes=15),
    )
    assert isinstance(token, str) and len(token) > 20

    claims = verify_token(token)
    assert claims is not None
    assert claims["username"] == "analyst_bob"
    assert claims["role"] == "analyst"


def test_jwt_invalid_token() -> None:
    claims = verify_token("invalid.token.payload")
    assert claims is None


def test_jwt_different_key_rejected() -> None:
    import jwt
    payload = {
        "sub": "102",
        "user_id": "102",
        "username": "mallory",
        "role": "admin",
        "exp": 9999999999,
    }
    forged_token = jwt.encode(payload, "completely-different-signing-key-12345", algorithm="HS256")
    claims = verify_token(forged_token)
    assert claims is None


def test_jwt_expired_token_rejected() -> None:
    expired_token = create_access_token(
        user_id="103",
        username="expired_user",
        role="viewer",
        expires_delta=timedelta(seconds=-10),
    )
    claims = verify_token(expired_token)
    assert claims is None


def test_default_seeded_accounts(test_db: Database) -> None:
    admin = test_db.get_user_by_username("admin")
    assert admin is not None
    assert admin["role"] == "admin"
    assert admin["must_change_password"] is True


def test_user_crud(test_db: Database) -> None:
    hashed = get_password_hash("custom123")
    user = test_db.create_user("incident_commander", hashed, role="analyst")
    assert user["username"] == "incident_commander"
    assert user["role"] == "analyst"

    users = test_db.list_users()
    usernames = [u["username"] for u in users]
    assert "incident_commander" in usernames

    updated = test_db.update_user_role("incident_commander", "admin")
    assert updated is True
    refreshed = test_db.get_user_by_username("incident_commander")
    assert refreshed is not None
    assert refreshed["role"] == "admin"


def test_startup_refusal_with_sample_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from config import load_settings

    monkeypatch.setenv("VOLCANO_ENV", "production")
    monkeypatch.setenv("VOLCANO_JWT_SECRET_KEY", "volcano-secret-key-change-in-production")
    with pytest.raises(RuntimeError) as exc_info:
        load_settings()
    assert "FATAL: Insecure or missing VOLCANO_JWT_SECRET_KEY" in str(exc_info.value)

    monkeypatch.setenv("VOLCANO_JWT_SECRET_KEY", "")
    with pytest.raises(RuntimeError) as exc_info:
        load_settings()
    assert "FATAL: Insecure or missing VOLCANO_JWT_SECRET_KEY" in str(exc_info.value)


def test_dev_mode_key_generation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import config
    from config import load_settings

    monkeypatch.setenv("VOLCANO_ENV", "development")
    monkeypatch.delenv("VOLCANO_JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("VOLCANO_JWT_SECRET", raising=False)
    monkeypatch.setattr(config, "BASE_DIR", tmp_path)

    settings = load_settings()
    assert len(settings.jwt_secret_key) >= 32
    dev_key_file = tmp_path / ".secret_key"
    assert dev_key_file.exists()
    assert dev_key_file.read_text(encoding="utf-8").strip() == settings.jwt_secret_key


def test_first_run_password_generation() -> None:
    import os
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        clean_db_path = tmp.name

    try:
        db = Database(db_path=clean_db_path)
        admin = db.get_user_by_username("admin")
        assert admin is not None
        assert admin["must_change_password"] is True
        # Re-running seed_default_users when users exist returns None
        assert db.seed_default_users() is None
    finally:
        if os.path.exists(clean_db_path):
            try:
                os.unlink(clean_db_path)
            except Exception:
                pass


def test_forced_password_change(test_db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient
    from app import app
    import app as app_module

    # Point app.db to test_db
    monkeypatch.setattr(app_module, "db", test_db)
    client = TestClient(app)

    # 1. Create a user with must_change_password=True
    temp_pwd = "TempSecretPassword123!"
    hashed = get_password_hash(temp_pwd)
    test_db.create_user("forced_analyst", hashed, role="analyst")
    with test_db.engine.begin() as conn:
        conn.execute(
            test_db.users_t.update()
            .where(test_db.users_t.c.username == "forced_analyst")
            .values(must_change_password=True)
        )

    # 2. Login is blocked while must_change_password is True
    resp = client.post("/api/auth/login", json={"username": "forced_analyst", "password": temp_pwd})
    assert resp.status_code == 403
    assert "Password change required" in resp.json()["detail"]

    # 3. Change password via /api/auth/change-password
    new_pwd = "NewSecurePassword456!"
    chg_resp = client.post(
        "/api/auth/change-password",
        json={"username": "forced_analyst", "current_password": temp_pwd, "new_password": new_pwd},
    )
    assert chg_resp.status_code == 200
    assert chg_resp.json()["status"] == "success"

    # 4. Login now succeeds
    login_resp = client.post("/api/auth/login", json={"username": "forced_analyst", "password": new_pwd})
    assert login_resp.status_code == 200
    assert "access_token" in login_resp.json()


def test_password_never_appears_in_logs(test_db: Database, caplog: pytest.LogCaptureFixture) -> None:
    import logging
    caplog.set_level(logging.DEBUG)

    secret_phrase = "UltraConfidentialSecretPass!987"
    hashed = get_password_hash(secret_phrase)
    test_db.update_user_password("admin", hashed)
    test_db.log_audit("admin", "change_password", "user:admin", {"status": "success"})

    # Ensure secret phrase never logged
    assert secret_phrase not in caplog.text

    # Ensure secret phrase never written to audit_logs table
    logs = test_db.get_audit_logs()
    for entry in logs:
        assert secret_phrase not in str(entry.get("changes", ""))
        assert secret_phrase not in str(entry.get("action", ""))
        assert secret_phrase not in str(entry.get("resource", ""))


def test_login_rate_limiting_username(test_db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient
    from app import app
    import app as app_module

    monkeypatch.setattr(app_module, "db", test_db)
    app_module.login_rate_limiter.clear()
    client = TestClient(app)

    hashed = get_password_hash("CorrectPassword123!")
    test_db.create_user("rate_user", hashed, role="analyst")
    with test_db.engine.begin() as conn:
        conn.execute(
            test_db.users_t.update()
            .where(test_db.users_t.c.username == "rate_user")
            .values(must_change_password=False)
        )

    # 5 failed attempts per username should return 401
    for i in range(5):
        resp = client.post(
            "/api/auth/login",
            json={"username": "rate_user", "password": f"Wrong_{i}"},
            headers={"x-forwarded-for": f"10.0.0.{i + 1}"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid username or password."

    # 6th attempt for this username should be blocked by rate limit
    blocked_resp = client.post(
        "/api/auth/login",
        json={"username": "rate_user", "password": "Wrong_6"},
        headers={"x-forwarded-for": "10.0.0.99"},
    )
    assert blocked_resp.status_code == 429
    assert "Retry-After" in blocked_resp.headers
    assert int(blocked_resp.headers["Retry-After"]) >= 1
    assert "Too many failed login attempts for this account" in blocked_resp.json()["detail"]

    app_module.login_rate_limiter.clear()


def test_login_rate_limiting_ip(test_db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient
    from app import app
    import app as app_module

    monkeypatch.setattr(app_module, "db", test_db)
    app_module.login_rate_limiter.clear()
    client = TestClient(app)

    test_ip = "198.51.100.77"

    # 20 failed attempts from the same IP should return 401
    for i in range(20):
        resp = client.post(
            "/api/auth/login",
            json={"username": f"random_user_{i}", "password": "WrongPassword!"},
            headers={"x-forwarded-for": test_ip},
        )
        assert resp.status_code == 401

    # 21st attempt from this IP should be rate limited
    blocked_resp = client.post(
        "/api/auth/login",
        json={"username": "random_user_21", "password": "WrongPassword!"},
        headers={"x-forwarded-for": test_ip},
    )
    assert blocked_resp.status_code == 429
    assert "Retry-After" in blocked_resp.headers
    assert int(blocked_resp.headers["Retry-After"]) >= 1
    assert "Too many failed login attempts from this IP" in blocked_resp.json()["detail"]

    # Another IP is unaffected
    other_ip_resp = client.post(
        "/api/auth/login",
        json={"username": "random_user_22", "password": "WrongPassword!"},
        headers={"x-forwarded-for": "198.51.100.88"},
    )
    assert other_ip_resp.status_code == 401

    app_module.login_rate_limiter.clear()


def test_account_lockout_and_unlock(test_db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import datetime, timezone, timedelta
    from fastapi.testclient import TestClient
    from app import app
    import app as app_module

    monkeypatch.setattr(app_module, "db", test_db)
    app_module.login_rate_limiter.clear()
    client = TestClient(app)

    hashed = get_password_hash("SecretPassword123!")
    test_db.create_user("lockout_target", hashed, role="analyst")
    with test_db.engine.begin() as conn:
        conn.execute(
            test_db.users_t.update()
            .where(test_db.users_t.c.username == "lockout_target")
            .values(must_change_password=False)
        )

    # Record 9 failures directly in DB
    for _ in range(9):
        attempts, is_locked, _ = test_db.record_login_failure("lockout_target")
    assert attempts == 9
    assert is_locked is False

    u = test_db.get_user_by_username("lockout_target")
    assert u is not None
    assert u["is_locked"] is False
    assert u["failed_login_attempts"] == 9

    # 10th failure triggers lockout
    attempts, is_locked, locked_until = test_db.record_login_failure("lockout_target")
    assert attempts == 10
    assert is_locked is True
    assert locked_until is not None

    u_locked = test_db.get_user_by_username("lockout_target")
    assert u_locked is not None
    assert u_locked["is_locked"] is True

    # Login attempt via API is blocked with 403
    resp = client.post(
        "/api/auth/login",
        json={"username": "lockout_target", "password": "SecretPassword123!"},
    )
    assert resp.status_code == 403
    assert "Account is temporarily locked" in resp.json()["detail"]

    # Admin unlock via API
    admin_token = create_access_token(user_id="1", username="admin", role="admin")
    unlock_resp = client.post(
        "/api/auth/users/lockout_target/unlock",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert unlock_resp.status_code == 200
    assert unlock_resp.json()["status"] == "unlocked"

    # Account is now unlocked
    u_unlocked = test_db.get_user_by_username("lockout_target")
    assert u_unlocked is not None
    assert u_unlocked["is_locked"] is False
    assert u_unlocked["failed_login_attempts"] == 0

    # Test auto-unlock after 15 minutes expiration
    past_time = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
    with test_db.engine.begin() as conn:
        conn.execute(
            test_db.users_t.update()
            .where(test_db.users_t.c.username == "lockout_target")
            .values(failed_login_attempts=10, locked_until=past_time)
        )
    # Querying the user should auto-expire the lock
    u_auto_unlocked = test_db.get_user_by_username("lockout_target")
    assert u_auto_unlocked is not None
    assert u_auto_unlocked["is_locked"] is False
    assert u_auto_unlocked["failed_login_attempts"] == 0


def test_identical_error_responses_to_prevent_enumeration(test_db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient
    from app import app
    import app as app_module

    monkeypatch.setattr(app_module, "db", test_db)
    app_module.login_rate_limiter.clear()
    client = TestClient(app)

    hashed = get_password_hash("RealPassword123!")
    test_db.create_user("known_user", hashed, role="analyst")
    with test_db.engine.begin() as conn:
        conn.execute(
            test_db.users_t.update()
            .where(test_db.users_t.c.username == "known_user")
            .values(must_change_password=False)
        )

    # 1. Non-existent username
    resp_unknown = client.post(
        "/api/auth/login",
        json={"username": "ghost_unknown_user", "password": "WrongPassword123!"},
    )
    # 2. Existing username with wrong password
    resp_bad_pwd = client.post(
        "/api/auth/login",
        json={"username": "known_user", "password": "WrongPassword123!"},
    )

    assert resp_unknown.status_code == 401
    assert resp_bad_pwd.status_code == 401
    assert resp_unknown.json() == resp_bad_pwd.json()
    assert resp_unknown.json() == {"detail": "Invalid username or password."}

    app_module.login_rate_limiter.clear()


def test_failed_login_audit_and_detection_pipeline(test_db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient
    from app import app
    import app as app_module

    monkeypatch.setattr(app_module, "db", test_db)
    app_module.login_rate_limiter.clear()
    client = TestClient(app)

    test_ip = "192.0.2.144"

    # Make failed login attempt
    resp = client.post(
        "/api/auth/login",
        json={"username": "victim_audit_user", "password": "WrongPassword!"},
        headers={"x-forwarded-for": test_ip},
    )
    assert resp.status_code == 401

    # Check audit log entry
    logs = test_db.get_audit_logs()
    failed_log = next(
        (log for log in logs if log.get("action") == "login_failed" and log.get("user_id") == "victim_audit_user"),
        None,
    )
    assert failed_log is not None
    assert failed_log.get("status") == "failed"
    assert failed_log.get("changes", {}).get("ip") == test_ip

    # Trigger brute force detector (threshold is 5 within 10s)
    for _ in range(4):
        client.post(
            "/api/auth/login",
            json={"username": "victim_audit_user", "password": "WrongPassword!"},
            headers={"x-forwarded-for": test_ip},
        )

    # Check that alert was generated
    found_alert = any(
        getattr(a, "category", "") == "Brute Force Attack"
        or (isinstance(a, dict) and a.get("category") == "Brute Force Attack")
        for a in app_module.alerts.list()
    )
    assert found_alert is True

    app_module.login_rate_limiter.clear()


def test_login_failure_auto_block_setting_off_by_default(test_db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient
    from app import app
    import app as app_module
    from config import load_settings

    # Verify setting is False by default
    monkeypatch.delenv("VOLCANO_LOGIN_FAILURE_AUTO_BLOCK", raising=False)
    fresh_settings = load_settings()
    assert fresh_settings.login_failure_auto_block is False

    monkeypatch.setattr(app_module, "db", test_db)
    app_module.login_rate_limiter.clear()
    client = TestClient(app)

    attacker_ip = "198.51.100.11"
    for _ in range(5):
        client.post(
            "/api/auth/login",
            json={"username": "target_user_default", "password": "WrongPassword!"},
            headers={"x-forwarded-for": attacker_ip},
        )

    # When disabled, no firewall rules should be added for this IP
    blocked_rules = [r for r in app_module.rule_engine.list_rules() if r.src_ip == attacker_ip]
    assert len(blocked_rules) == 0

    app_module.login_rate_limiter.clear()


def test_login_failure_auto_block_triggered_at_threshold(test_db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient
    from app import app
    import app as app_module
    from config import load_settings

    # Enable auto block
    monkeypatch.setenv("VOLCANO_LOGIN_FAILURE_AUTO_BLOCK", "true")
    new_settings = load_settings()
    assert new_settings.login_failure_auto_block is True
    monkeypatch.setattr(app_module, "get_settings", lambda: new_settings)
    monkeypatch.setattr(app_module, "db", test_db)
    app_module.login_rate_limiter.clear()
    client = TestClient(app)

    attacker_ip = "198.51.100.22"
    # Send 5 failed attempts from attacker_ip to trigger brute force alert & auto-block
    for _ in range(5):
        client.post(
            "/api/auth/login",
            json={"username": "target_user_autoblock", "password": "WrongPassword!"},
            headers={"x-forwarded-for": attacker_ip},
        )

    # Verify that rule_engine now contains a block rule for attacker_ip
    blocked_rules = [r for r in app_module.rule_engine.list_rules() if r.src_ip == attacker_ip]
    assert len(blocked_rules) > 0
    assert blocked_rules[0].action.value == "deny"

    # Clean up rule
    for r in blocked_rules:
        app_module.rule_engine.delete_rule(r.id)
    app_module.login_rate_limiter.clear()


def test_login_failure_auto_block_respects_allowlist(test_db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient
    from app import app
    import app as app_module
    from config import load_settings

    # Enable auto block
    monkeypatch.setenv("VOLCANO_LOGIN_FAILURE_AUTO_BLOCK", "true")
    new_settings = load_settings()
    monkeypatch.setattr(app_module, "get_settings", lambda: new_settings)
    monkeypatch.setattr(app_module, "db", test_db)
    app_module.login_rate_limiter.clear()
    client = TestClient(app)

    # 127.0.0.1 is protected by the system allowlist invariant
    allowlisted_ip = "127.0.0.1"
    for _ in range(5):
        client.post(
            "/api/auth/login",
            json={"username": "target_user_allowlist", "password": "WrongPassword!"},
            headers={"x-forwarded-for": allowlisted_ip},
        )

    # Allowlisted IP must never have a DENY rule created
    blocked_rules = [r for r in app_module.rule_engine.list_rules() if r.src_ip == allowlisted_ip]
    assert len(blocked_rules) == 0

    app_module.login_rate_limiter.clear()



