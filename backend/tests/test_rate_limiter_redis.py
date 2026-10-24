"""Unit tests for Distributed Rate Limiting with Redis Backend (Task 1)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from security.rate_limiter import InMemoryRateLimiter
from security.rate_limiter_redis import (
    RedisRateLimiter,
    RedisRateLimiterUnavailableError,
    get_rate_limiter,
)

try:
    import fakeredis
    HAS_FAKEREDIS = True
except ImportError:
    HAS_FAKEREDIS = False


@pytest.fixture
def fake_redis_server():
    if not HAS_FAKEREDIS:
        pytest.skip("fakeredis library is not installed; skipping Redis tests.")
    server = fakeredis.FakeServer()
    client = fakeredis.FakeStrictRedis(server=server, decode_responses=True)
    yield client
    client.flushall()


def test_memory_default_behavior() -> None:
    """Default backend must be InMemoryRateLimiter."""
    limiter = get_rate_limiter()
    assert isinstance(limiter, InMemoryRateLimiter)

    # Basic sliding window check
    is_limited, retry_after = limiter.is_rate_limited("test:key", max_attempts=3, window_seconds=60.0)
    assert is_limited is False
    assert retry_after == 0.0

    limiter.record_failure("test:key")
    limiter.record_failure("test:key")
    limiter.record_failure("test:key")

    is_limited, retry_after = limiter.is_rate_limited("test:key", max_attempts=3, window_seconds=60.0)
    assert is_limited is True
    assert retry_after > 0.0


def test_two_limiters_share_state(fake_redis_server) -> None:
    """Two limiter instances pointing to the same Redis store share atomic attempt state."""
    limiter_worker1 = RedisRateLimiter(redis_client=fake_redis_server, profile="development")
    limiter_worker2 = RedisRateLimiter(redis_client=fake_redis_server, profile="development")

    key = "user:cluster_admin"

    # Worker 1 records 2 failures
    limiter_worker1.record_failure(key, window_seconds=60.0)
    limiter_worker1.record_failure(key, window_seconds=60.0)

    # Worker 2 checks: not limited yet (2 < 3)
    is_limited, _ = limiter_worker2.is_rate_limited(key, max_attempts=3, window_seconds=60.0)
    assert is_limited is False

    # Worker 2 records 1 failure
    limiter_worker2.record_failure(key, window_seconds=60.0)

    # Both workers now see rate limited
    is_limited1, retry1 = limiter_worker1.is_rate_limited(key, max_attempts=3, window_seconds=60.0)
    is_limited2, retry2 = limiter_worker2.is_rate_limited(key, max_attempts=3, window_seconds=60.0)

    assert is_limited1 is True
    assert is_limited2 is True
    assert retry1 > 0.0
    assert retry2 > 0.0


def test_retry_after_calculation(fake_redis_server) -> None:
    """Retry-After must accurately reflect the remaining TTL of the oldest failure."""
    limiter = RedisRateLimiter(redis_client=fake_redis_server, profile="development")
    key = "ip:203.0.113.19"

    for _ in range(5):
        limiter.record_failure(key, window_seconds=10.0)

    is_limited, retry_after = limiter.is_rate_limited(key, max_attempts=5, window_seconds=10.0)
    assert is_limited is True
    assert 1.0 <= retry_after <= 10.0

    # Reset clears attempts
    limiter.reset(key)
    is_limited_after_reset, _ = limiter.is_rate_limited(key, max_attempts=5, window_seconds=10.0)
    assert is_limited_after_reset is False


def test_fail_closed_in_production_when_unreachable() -> None:
    """When Redis is unreachable in production profile, it must fail closed and raise error."""
    # Use dummy invalid client that will fail
    class BrokenRedis:
        def eval(self, *args, **kwargs):
            raise ConnectionError("Connection refused to Redis cluster")

    prod_limiter = RedisRateLimiter(redis_client=BrokenRedis(), profile="production", allow_fallback_in_dev=False)

    with pytest.raises(RedisRateLimiterUnavailableError, match="Redis rate limiter unreachable"):
        prod_limiter.is_rate_limited("user:test", max_attempts=5, window_seconds=60.0)

    with pytest.raises(RedisRateLimiterUnavailableError, match="Redis error recording failure"):
        prod_limiter.record_failure("user:test")


def test_fallback_in_development_when_unreachable() -> None:
    """When Redis is unreachable in development profile, it falls back to memory with a warning."""
    class BrokenRedis:
        def eval(self, *args, **kwargs):
            raise ConnectionError("Connection refused in dev")

    dev_limiter = RedisRateLimiter(redis_client=BrokenRedis(), profile="development", allow_fallback_in_dev=True)

    # In dev, it should not raise; it falls back to internal memory limiter
    is_limited, _ = dev_limiter.is_rate_limited("user:dev_user", max_attempts=2, window_seconds=60.0)
    assert is_limited is False

    dev_limiter.record_failure("user:dev_user")
    dev_limiter.record_failure("user:dev_user")

    is_limited, retry_after = dev_limiter.is_rate_limited("user:dev_user", max_attempts=2, window_seconds=60.0)
    assert is_limited is True


def test_login_endpoint_fail_closed_503(monkeypatch: pytest.MonkeyPatch) -> None:
    """Login endpoint must return 503 when Redis rate limiter is down in production."""
    from app import app
    import app as app_module

    class BrokenLimiter:
        def is_rate_limited(self, key: str, max_attempts: int, window_seconds: float):
            raise RedisRateLimiterUnavailableError("Redis cluster offline")

        def record_failure(self, key: str):
            raise RedisRateLimiterUnavailableError("Redis cluster offline")

        def clear(self):
            pass

    monkeypatch.setattr(app_module, "login_rate_limiter", BrokenLimiter())
    client = TestClient(app)

    resp = client.post("/api/auth/login", json={"username": "admin", "password": "anypassword"})
    assert resp.status_code == 503
    assert "rate limiter unreachable" in resp.json()["detail"]
