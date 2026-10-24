"""Distributed Rate Limiter with Redis Backend (Phase 3).
Provides atomic sliding-window rate limiting using Redis sorted sets and Lua scripts,
ensuring consistent attempt tracking across multiple workers and replicas.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any, Optional, Tuple

from security.rate_limiter import BaseRateLimiter, InMemoryRateLimiter

logger = logging.getLogger("volcano.rate_limiter.redis")

# Atomic Lua script for sliding window rate check
LUA_CHECK_RATE_LIMIT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_attempts = tonumber(ARGV[3])

-- Remove timestamps older than (now - window)
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)

-- Count current entries in window
local count = redis.call('ZCARD', key)

if count >= max_attempts then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    if #oldest >= 2 then
        local oldest_ts = tonumber(oldest[2])
        local retry_after = (oldest_ts + window) - now
        if retry_after < 1 then
            retry_after = 1
        end
        return {1, tostring(retry_after)}
    else
        return {1, tostring(window)}
    end
else
    return {0, "0"}
end
"""

# Atomic Lua script for recording a failure attempt
LUA_RECORD_FAILURE = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local member = ARGV[2]
local expire_sec = math.ceil(tonumber(ARGV[3]))

redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, expire_sec)
return 1
"""


class RedisRateLimiterUnavailableError(Exception):
    """Raised when Redis is configured but unreachable and fail-closed is required."""


class RedisRateLimiter(BaseRateLimiter):
    """Atomic distributed sliding window rate limiter backed by Redis."""

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        redis_url: Optional[str] = None,
        key_prefix: str = "volcano:ratelimit:",
        allow_fallback_in_dev: bool = True,
        profile: Optional[str] = None,
    ) -> None:
        self.key_prefix = key_prefix
        self.allow_fallback_in_dev = allow_fallback_in_dev
        self.profile = profile or os.environ.get("VOLCANO_PROFILE", os.environ.get("VOLCANO_ENV", "development")).lower().strip()
        self._fallback_limiter = InMemoryRateLimiter()

        if redis_client is not None:
            self._redis = redis_client
        else:
            try:
                import redis
                target_url = redis_url or os.environ.get("VOLCANO_REDIS_URL", "redis://localhost:6379/0")
                self._redis = redis.Redis.from_url(target_url, decode_responses=True, socket_connect_timeout=2.0)
            except Exception as exc:
                logger.error("Failed to initialize Redis client: %s", exc)
                self._redis = None

    def is_production(self) -> bool:
        return self.profile == "production"

    def _format_key(self, key: str) -> str:
        return f"{self.key_prefix}{key}"

    def is_rate_limited(self, key: str, max_attempts: int, window_seconds: float) -> Tuple[bool, float]:
        redis_key = self._format_key(key)
        now = time.time()

        if self._redis is None:
            if self.is_production() or not self.allow_fallback_in_dev:
                logger.critical("Redis rate limiter unavailable (no client) in production")
                raise RedisRateLimiterUnavailableError("Redis rate limiter unavailable (no client)")
            logger.warning("Redis client unavailable in development mode, falling back to memory")
            return self._fallback_limiter.is_rate_limited(key, max_attempts, window_seconds)

        try:
            res = self._redis.eval(
                LUA_CHECK_RATE_LIMIT,
                1,
                redis_key,
                str(now),
                str(window_seconds),
                str(max_attempts),
            )
            is_limited = bool(res[0] == 1)
            retry_after = float(res[1]) if is_limited else 0.0
            return is_limited, retry_after
        except Exception as exc:
            if self.is_production() or not self.allow_fallback_in_dev:
                logger.critical("Redis rate limiter unreachable in production: %s", exc)
                raise RedisRateLimiterUnavailableError(f"Redis rate limiter unreachable: {exc}") from exc
            logger.warning("Redis error during rate limit check in dev mode; falling back to memory: %s", exc)
            return self._fallback_limiter.is_rate_limited(key, max_attempts, window_seconds)

    def record_failure(self, key: str, window_seconds: float = 300.0) -> None:
        redis_key = self._format_key(key)
        now = time.time()
        member_id = f"{now}:{uuid.uuid4().hex[:8]}"

        if self._redis is None:
            if self.is_production() or not self.allow_fallback_in_dev:
                logger.critical("Redis rate limiter unavailable to record failure in production")
                raise RedisRateLimiterUnavailableError("Redis rate limiter unavailable to record failure")
            self._fallback_limiter.record_failure(key)
            return

        try:
            self._redis.eval(
                LUA_RECORD_FAILURE,
                1,
                redis_key,
                str(now),
                member_id,
                str(window_seconds),
            )
        except Exception as exc:
            if self.is_production() or not self.allow_fallback_in_dev:
                logger.critical("Redis error recording failure in production: %s", exc)
                raise RedisRateLimiterUnavailableError(f"Redis error recording failure: {exc}") from exc
            logger.warning("Redis error recording failure in dev mode; falling back to memory: %s", exc)
            self._fallback_limiter.record_failure(key)

    def reset(self, key: str) -> None:
        redis_key = self._format_key(key)
        if self._redis is not None:
            try:
                self._redis.delete(redis_key)
            except Exception as exc:
                if self.is_production() or not self.allow_fallback_in_dev:
                    raise RedisRateLimiterUnavailableError(f"Redis error during reset: {exc}") from exc
                logger.warning("Redis error during reset in dev mode: %s", exc)
        self._fallback_limiter.reset(key)

    def clear(self) -> None:
        """Clear all rate limit keys (primarily for testing)."""
        if self._redis is not None:
            try:
                keys = self._redis.keys(f"{self.key_prefix}*")
                if keys:
                    self._redis.delete(*keys)
            except Exception:
                pass
        self._fallback_limiter.clear()


def get_rate_limiter(
    backend: Optional[str] = None,
    redis_client: Optional[Any] = None,
    redis_url: Optional[str] = None,
    profile: Optional[str] = None,
) -> BaseRateLimiter:
    """Factory creating appropriate rate limiter based on configuration or environment."""
    chosen_backend = (backend or os.environ.get("VOLCANO_RATE_LIMIT_BACKEND", "memory")).lower().strip()
    if chosen_backend == "redis":
        return RedisRateLimiter(
            redis_client=redis_client,
            redis_url=redis_url,
            profile=profile,
        )
    return InMemoryRateLimiter()
