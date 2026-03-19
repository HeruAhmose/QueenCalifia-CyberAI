"""Redis-backed token bucket (global request budget).

This limiter is designed for *request budgeting*, not just RPM:
each request "charges" a configurable cost. Costs can be higher for expensive
endpoints (e.g., vuln scans) and lower for reads.

State model (Redis HASH):
  - tokens: current token balance (float)
  - ts_ms: last refill timestamp (ms)

Atomicity: implemented via Lua.

Why token bucket?
  - Smooths burst pressure while allowing controlled short bursts (capacity).
  - Supports "weighted" endpoints through costs.

Env is configured in api.gateway (BudgetPolicy); this module only enforces.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from core.redis_client import get_redis


_TOKEN_BUCKET_LUA = r"""
-- KEYS[1] = bucket key
-- ARGV[1] = now_ms
-- ARGV[2] = capacity
-- ARGV[3] = refill_per_sec
-- ARGV[4] = cost
-- ARGV[5] = ttl_ms

local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local refill_per_sec = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl_ms = tonumber(ARGV[5])

local data = redis.call('HMGET', key, 'tokens', 'ts_ms')
local tokens = tonumber(data[1])
local ts_ms = tonumber(data[2])

if tokens == nil then tokens = capacity end
if ts_ms == nil then ts_ms = now_ms end

local delta_ms = now_ms - ts_ms
if delta_ms < 0 then delta_ms = 0 end

local refill = (delta_ms / 1000.0) * refill_per_sec
tokens = tokens + refill
if tokens > capacity then tokens = capacity end

local allowed = 0
if cost <= 0 then
  allowed = 1
else
  if tokens >= cost then
    allowed = 1
    tokens = tokens - cost
  end
end

redis.call('HSET', key, 'tokens', tokens, 'ts_ms', now_ms)
redis.call('PEXPIRE', key, ttl_ms)

-- return remaining tokens (floor-ish for headers)
return {allowed, tokens}
"""


@dataclass(frozen=True)
class RedisTokenBucket:
    """Global token bucket (shared across API instances)."""

    prefix: str = "qc:budget:"
    # If a bucket is idle, let it expire to reduce Redis footprint.
    idle_ttl_seconds: int = 3600

    def _key(self, identity: str) -> str:
        return f"{self.prefix}{identity}"

    def charge(
        self,
        identity: str,
        *,
        capacity: float,
        refill_per_sec: float,
        cost: float,
    ) -> tuple[bool, float]:
        """Charge `cost` tokens.

        Returns (allowed, remaining_tokens_after_refill_and_charge).
        """
        capacity = float(max(1.0, capacity))
        refill_per_sec = float(max(0.0, refill_per_sec))
        cost = float(max(0.0, cost))

        r = get_redis()
        now_ms = int(time.time() * 1000)
        ttl_ms = int(max(1, self.idle_ttl_seconds) * 1000)

        key = self._key(identity)
        allowed, remaining = r.eval(
            _TOKEN_BUCKET_LUA,
            1,
            key,
            now_ms,
            capacity,
            refill_per_sec,
            cost,
            ttl_ms,
        )
        return bool(int(allowed)), float(remaining)
