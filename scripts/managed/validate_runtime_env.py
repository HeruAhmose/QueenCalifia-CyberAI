#!/usr/bin/env python3
from __future__ import annotations

import os
from urllib.parse import parse_qs, urlparse


def fail(message: str) -> None:
    raise SystemExit(f"managed runtime gate closed: {message}")


def require_managed_runtime() -> None:
    if os.environ.get("QC_MANAGED_RUNTIME_GATE", "0") != "1":
        return

    if os.environ.get("QC_MANAGED_RUNTIME_AUTHORIZED") != "AUTHORIZED":
        fail("QC_MANAGED_RUNTIME_AUTHORIZED is not AUTHORIZED")

    role = os.environ.get("QC_SERVICE_ROLE", "")
    if role not in {"api", "worker"}:
        fail("QC_SERVICE_ROLE must be api or worker")

    if os.environ.get("QC_PRODUCTION") != "1":
        fail("QC_PRODUCTION must be 1")
    if os.environ.get("QC_USE_CELERY") != "1":
        fail("QC_USE_CELERY must be 1")
    if os.environ.get("QC_REQUIRE_REDIS") != "1":
        fail("QC_REQUIRE_REDIS must be 1")

    db_url = os.environ.get("QC_DATABASE_URL") or os.environ.get("DATABASE_URL") or ""
    parsed_db = urlparse(db_url)
    if parsed_db.scheme not in {"postgresql", "postgres"}:
        fail("PostgreSQL authority is required")
    db_query = parse_qs(parsed_db.query)
    if db_query.get("sslmode") != ["require"]:
        fail("PostgreSQL TLS must require sslmode=require")

    if os.environ.get("QC_MANAGED_POSTGRES_PROVIDER") == "neon":
        if os.environ.get("QC_DATABASE_CONNECTION_MODE") != "pooled":
            fail("Neon application runtime must use the pooled endpoint")
        if "-pooler." not in (parsed_db.hostname or ""):
            fail("Neon pooled endpoint hostname is required for application runtime")

    redis_url = os.environ.get("QC_REDIS_URL", "")
    parsed_redis = urlparse(redis_url)
    if parsed_redis.scheme != "rediss":
        fail("TLS Redis/Valkey URL using rediss:// is required")
    redis_query = parse_qs(parsed_redis.query)
    if redis_query.get("ssl_cert_reqs") != ["required"]:
        fail("Redis/Valkey TLS certificate verification must be required")

    if os.environ.get("QC_CELERY_BROKER_URL", redis_url) != redis_url:
        fail("managed runtime requires Celery broker to match QC_REDIS_URL")
    if os.environ.get("QC_CELERY_RESULT_BACKEND", redis_url) != redis_url:
        fail("managed runtime requires Celery result backend to match QC_REDIS_URL")


if __name__ == "__main__":
    require_managed_runtime()
