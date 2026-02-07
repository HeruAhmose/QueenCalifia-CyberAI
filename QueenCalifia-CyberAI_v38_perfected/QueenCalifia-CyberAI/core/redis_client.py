"""Redis client utilities.

This project uses Redis for *horizontal scalability*:
- request/scan rate limiting (shared across API workers)
- scan capacity semaphore (shared across Celery workers)

Configuration (env):
  - QC_REDIS_URL: Redis connection URL (default: redis://localhost:6379/0)

Notes:
  - Use a dedicated Redis instance/DB for security telemetry controls if possible.
  - Prefer TLS + AUTH on Redis in production.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

try:
    import redis  # type: ignore
except Exception as exc:  # pragma: no cover
    redis = None  # type: ignore


def key_prefix() -> str:
    """Prefix for Redis keys (helps multi-tenant + tests)."""
    return os.environ.get("QC_REDIS_PREFIX", "qc:")


def redis_url() -> str:
    return os.environ.get("QC_REDIS_URL", "redis://localhost:6379/0")


@lru_cache(maxsize=1)
def get_redis() -> "redis.Redis":
    if redis is None:  # pragma: no cover
        raise RuntimeError("redis package not installed; add `redis` to requirements.txt")
    url = redis_url()
    return redis.Redis.from_url(url, decode_responses=True, socket_timeout=2, socket_connect_timeout=2)
