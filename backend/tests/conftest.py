"""Pytest Configuration and Shared Fixtures for Volcano AI Firewall."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Generator

import pytest

# Ensure backend root is on Python module path
BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from config import FirewallSettings
from storage.database import Database
from storage.auth import create_access_token


@pytest.fixture
def test_db() -> Generator[Database, None, None]:
    """Provide an isolated, fresh SQLite database for tests."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        db = Database(db_path=db_path)
        yield db
    finally:
        if os.path.exists(db_path):
            try:
                os.unlink(db_path)
            except Exception:
                pass


@pytest.fixture
def test_settings() -> FirewallSettings:
    """Provide isolated configuration settings with safe test defaults."""
    return FirewallSettings(
        brute_force_threshold=5,
        brute_force_window=10,
        dns_tunneling_entropy=3.8,
        dns_tunneling_subdomain_len=45,
        dns_rate_spike_threshold=20,
        auto_block_duration_minutes=1,
        allowlist_ips=["127.0.0.1", "10.0.0.1", "192.168.1.1"],
        notification_enabled=False,
    )


@pytest.fixture
def admin_token() -> str:
    return create_access_token(data={"sub": "admin", "role": "admin"})


@pytest.fixture
def analyst_token() -> str:
    return create_access_token(data={"sub": "analyst", "role": "analyst"})


@pytest.fixture
def viewer_token() -> str:
    return create_access_token(data={"sub": "viewer", "role": "viewer"})
