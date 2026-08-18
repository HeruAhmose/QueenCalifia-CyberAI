#!/usr/bin/env python3
from __future__ import annotations

import os
from urllib.parse import parse_qs, urlparse


def fail(message: str) -> None:
    raise SystemExit(f"OCI runtime gate closed: {message}")


def main() -> None:
    if os.environ.get("QC_PRODUCTION") != "1":
        fail("QC_PRODUCTION must be 1")
    if os.environ.get("QC_USE_CELERY") != "1" or os.environ.get("QC_REQUIRE_REDIS") != "1":
        fail("Celery and Redis authority are required")
    if os.environ.get("QC_SERVICE_ROLE") not in {"api", "worker"}:
        fail("QC_SERVICE_ROLE must be api or worker")

    db_url = os.environ.get("QC_DATABASE_URL") or os.environ.get("DATABASE_URL") or ""
    parsed_db = urlparse(db_url)
    if parsed_db.scheme not in {"postgresql", "postgres"}:
        fail("PostgreSQL authority is required")
    if parse_qs(parsed_db.query).get("sslmode") != ["require"]:
        fail("PostgreSQL must require sslmode=require")
    if os.environ.get("QC_OCI_POSTGRES_PROVIDER") != "neon":
        fail("OCI production candidate must use the isolated Neon authority")
    if os.environ.get("QC_DATABASE_CONNECTION_MODE") != "pooled" or "-pooler." not in (parsed_db.hostname or ""):
        fail("Neon application runtime must use the pooled endpoint")

    redis_url = os.environ.get("QC_REDIS_URL", "")
    parsed_redis = urlparse(redis_url)
    if parsed_redis.scheme != "rediss":
        fail("TLS Redis/Valkey URL using rediss:// is required")
    if parse_qs(parsed_redis.query).get("ssl_cert_reqs") != ["required"]:
        fail("Redis/Valkey certificate verification must be required")
    if os.environ.get("QC_CELERY_BROKER_URL") != redis_url:
        fail("Celery broker must exactly match QC_REDIS_URL")
    if os.environ.get("QC_CELERY_RESULT_BACKEND") != redis_url:
        fail("Celery result backend must exactly match QC_REDIS_URL")


if __name__ == "__main__":
    main()
