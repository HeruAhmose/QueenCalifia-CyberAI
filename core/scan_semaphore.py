"""Redis-backed scan capacity semaphore.

This provides a *global* concurrency cap across multiple Celery workers/nodes.
It's defensive: if tasks crash, the key expires via TTL.

Env:
  - QC_SCAN_MAX_CONCURRENT: global concurrent scans (default: 4)
  - QC_SCAN_SLOT_TTL_SECONDS: semaphore TTL (default: 1800)

"""

from __future__ import annotations

import os
from dataclasses import dataclass

from core.redis_client import get_redis, key_prefix

_ACQUIRE_LUA = r"""
-- KEYS[1] = semaphore key
-- ARGV[1] = max
-- ARGV[2] = ttl_ms

local key = KEYS[1]
local maxv = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])

local cur = tonumber(redis.call('GET', key) or '0')
if cur >= maxv then
    return 0
end

local nextv = redis.call('INCR', key)
redis.call('PEXPIRE', key, ttl)
return 1
"""

_RELEASE_LUA = r"""
-- KEYS[1] = semaphore key
local key = KEYS[1]
local cur = tonumber(redis.call('GET', key) or '0')
if cur <= 0 then
    redis.call('DEL', key)
    return 0
end
local nextv = redis.call('DECR', key)
if nextv <= 0 then
    redis.call('DEL', key)
end
return nextv
"""


@dataclass(frozen=True)
class ScanSemaphore:
    key: str = ""

    def __post_init__(self) -> None:
        if not self.key:
            object.__setattr__(self, "key", f"{key_prefix()}scan:active")

    @staticmethod
    def max_concurrent() -> int:
        return max(1, int(os.environ.get("QC_SCAN_MAX_CONCURRENT", "4")))

    @staticmethod
    def ttl_ms() -> int:
        return max(10_000, int(os.environ.get("QC_SCAN_SLOT_TTL_SECONDS", "1800")) * 1000)

    def acquire(self) -> bool:
        r = get_redis()
        ok = r.eval(_ACQUIRE_LUA, 1, self.key, self.max_concurrent(), self.ttl_ms())
        return bool(int(ok))

    def release(self) -> None:
        r = get_redis()
        r.eval(_RELEASE_LUA, 1, self.key)
