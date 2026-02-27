"""Redis-backed sliding-window rate limiter.

Implements a true sliding window using a ZSET of request timestamps and a small
Lua script for atomicity.

Why not a fixed window?
  - Fixed window allows burst at boundary. Sliding window is more defensive.

Usage:
  limiter = RedisSlidingWindowLimiter(prefix="qc:rl:", window_seconds=60)
  allowed, remaining = limiter.hit("key_hash", limit=120)

Env:
  - QC_REDIS_URL: used via core.redis_client.get_redis()

"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from core.redis_client import get_redis

_HIT_LUA = r"""
-- KEYS[1] = rate limit key
-- ARGV[1] = now_ms
-- ARGV[2] = window_ms
-- ARGV[3] = limit
-- ARGV[4] = member

local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local cutoff = now - window

redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
local count = tonumber(redis.call('ZCARD', key))

if count >= limit then
    -- ensure key expires even under pressure
    redis.call('PEXPIRE', key, window + 1000)
    return {0, 0}
end

redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, window + 1000)

local remaining = limit - (count + 1)
if remaining < 0 then remaining = 0 end
return {1, remaining}
"""


@dataclass(frozen=True)
class RedisSlidingWindowLimiter:
    prefix: str = "qc:rl:"
    window_seconds: int = 60

    def __post_init__(self) -> None:
        object.__setattr__(self, "_window_ms", int(self.window_seconds * 1000))

    def _key(self, identity: str) -> str:
        return f"{self.prefix}{identity}"

    def hit(self, identity: str, limit: int) -> tuple[bool, int]:
        """Register a hit for `identity`.

        Returns (allowed, remaining). Remaining is 0 when disallowed.
        """
        limit = max(1, int(limit))
        r = get_redis()
        now_ms = int(time.time() * 1000)
        member = f"{now_ms}:{uuid.uuid4().hex}"
        key = self._key(identity)
        allowed, remaining = r.eval(_HIT_LUA, 1, key, now_ms, self._window_ms, limit, member)
        return bool(int(allowed)), int(remaining)

    def remaining(self, identity: str, limit: int) -> int:
        """Best-effort remaining requests in the current window."""
        limit = max(1, int(limit))
        r = get_redis()
        now_ms = int(time.time() * 1000)
        cutoff = now_ms - self._window_ms
        key = self._key(identity)
        r.zremrangebyscore(key, 0, cutoff)
        count = int(r.zcard(key))
        return max(0, limit - count)
