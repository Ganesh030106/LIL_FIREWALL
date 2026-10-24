"""Tests for Task 2: Production Profile and PostgreSQL Connection Pool Configuration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from config import load_settings
from storage.database import Database


def test_dev_profile_allows_sqlite(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Development profile must allow SQLite database startup by default."""
    monkeypatch.setenv("VOLCANO_PROFILE", "development")
    monkeypatch.delenv("VOLCANO_ALLOW_SQLITE_PRODUCTION", raising=False)
    
    test_db = tmp_path / "dev_test.db"
    db = Database(db_path=str(test_db))
    assert db.is_postgres is False
    assert db.local_db_path is not None


def test_production_profile_refuses_sqlite(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Production profile must refuse SQLite by default and raise RuntimeError."""
    monkeypatch.setenv("VOLCANO_PROFILE", "production")
    monkeypatch.delenv("VOLCANO_ALLOW_SQLITE_PRODUCTION", raising=False)

    test_db = tmp_path / "prod_test.db"
    with pytest.raises(RuntimeError) as exc_info:
        Database(db_path=str(test_db))

    assert "refuses to start with SQLite backend" in str(exc_info.value)
    assert "PostgreSQL 16" in str(exc_info.value)


def test_production_profile_allows_sqlite_when_explicitly_configured(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Production profile permits SQLite only if VOLCANO_ALLOW_SQLITE_PRODUCTION=true."""
    monkeypatch.setenv("VOLCANO_PROFILE", "production")
    monkeypatch.setenv("VOLCANO_ALLOW_SQLITE_PRODUCTION", "true")

    test_db = tmp_path / "prod_override.db"
    db = Database(db_path=str(test_db))
    assert db.is_postgres is False
    assert db.local_db_path is not None


def test_postgres_unreachable_refuses_sqlite_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    """When PostgreSQL fails in production, it must refuse to silently fall back to SQLite."""
    monkeypatch.setenv("VOLCANO_PROFILE", "production")
    monkeypatch.delenv("VOLCANO_ALLOW_SQLITE_PRODUCTION", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        Database(db_path="postgresql://invalid_user:invalid_pass@127.0.0.1:59999/nonexistent")

    assert "refuses to start with SQLite backend" in str(exc_info.value)


def test_connection_pool_settings_from_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Connection pool settings must be parsed from environment variables into configuration."""
    monkeypatch.setenv("VOLCANO_DB_POOL_SIZE", "42")
    monkeypatch.setenv("VOLCANO_DB_MAX_OVERFLOW", "84")
    monkeypatch.setenv("VOLCANO_DB_POOL_PRE_PING", "false")
    monkeypatch.setenv("VOLCANO_DB_POOL_RECYCLE", "360")
    monkeypatch.setenv("VOLCANO_DB_CONNECT_TIMEOUT", "12")

    cfg = load_settings()
    assert cfg.db_pool_size == 42
    assert cfg.db_max_overflow == 84
    assert cfg.db_pool_pre_ping is False
    assert cfg.db_pool_recycle == 360
    assert cfg.db_connect_timeout == 12


def test_connection_pool_applied_to_create_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    """When creating a PostgreSQL engine, pool settings from config/env are applied."""
    monkeypatch.setenv("VOLCANO_DB_POOL_SIZE", "25")
    monkeypatch.setenv("VOLCANO_DB_MAX_OVERFLOW", "35")
    monkeypatch.setenv("VOLCANO_DB_POOL_PRE_PING", "true")
    monkeypatch.setenv("VOLCANO_DB_POOL_RECYCLE", "240")
    monkeypatch.setenv("VOLCANO_DB_CONNECT_TIMEOUT", "8")

    captured_kwargs = {}

    def mock_create_engine(url, **kwargs):
        captured_kwargs.update(kwargs)
        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_engine.connect.return_value.__enter__.return_value = mock_conn
        return mock_engine

    with patch("storage.database.create_engine", side_effect=mock_create_engine):
        Database(db_path="postgresql://volcano:secret@localhost:5432/volcano_test")

    assert captured_kwargs.get("pool_size") == 25
    assert captured_kwargs.get("max_overflow") == 35
    assert captured_kwargs.get("pool_pre_ping") is True
    assert captured_kwargs.get("pool_recycle") == 240
    assert captured_kwargs.get("connect_args") == {"connect_timeout": 8}
