#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def fail(message: str) -> None:
    raise SystemExit(f"Sovereign Edge runtime gate closed: {message}")


def require_query(query: dict[str, list[str]], key: str, value: str) -> None:
    if query.get(key) != [value]:
        fail(f"queue URL must set {key}={value}")


def main() -> None:
    if os.environ.get("QC_PRODUCTION") != "1":
        fail("QC_PRODUCTION must be 1")
    if os.environ.get("QC_USE_CELERY") != "1" or os.environ.get("QC_REQUIRE_REDIS") != "1":
        fail("Celery and Redis-compatible queue authority are required")
    if os.environ.get("QC_SERVICE_ROLE") not in {"api", "worker"}:
        fail("QC_SERVICE_ROLE must be api or worker")

    db_url = os.environ.get("QC_DATABASE_URL") or os.environ.get("DATABASE_URL") or ""
    parsed_db = urlparse(db_url)
    if parsed_db.scheme not in {"postgresql", "postgres"}:
        fail("PostgreSQL authority is required")
    if parse_qs(parsed_db.query).get("sslmode") != ["require"]:
        fail("PostgreSQL must require sslmode=require")
    if os.environ.get("QC_EDGE_POSTGRES_PROVIDER") != "neon":
        fail("Sovereign Edge production candidate must use Neon PostgreSQL authority")
    if os.environ.get("QC_DATABASE_CONNECTION_MODE") != "pooled" or "-pooler." not in (parsed_db.hostname or ""):
        fail("Neon application runtime must use the pooled endpoint")

    redis_url = os.environ.get("QC_REDIS_URL", "")
    parsed_redis = urlparse(redis_url)
    if parsed_redis.scheme != "rediss":
        fail("TLS-only Valkey URL using rediss:// is required")
    if parsed_redis.hostname != "valkey" or parsed_redis.port != 6379:
        fail("queue authority must be the private Docker-network Valkey service")
    q = parse_qs(parsed_redis.query)
    require_query(q, "ssl_cert_reqs", "required")
    require_query(q, "ssl_ca_certs", "/run/valkey-pki/ca.crt")

    role = os.environ["QC_SERVICE_ROLE"]
    require_query(q, "ssl_certfile", f"/run/valkey-pki/{role}.crt")
    require_query(q, "ssl_keyfile", f"/run/valkey-pki/{role}.key")
    for path_key in ("ssl_ca_certs", "ssl_certfile", "ssl_keyfile"):
        path = Path(q[path_key][0])
        if not path.is_file() or path.stat().st_size == 0:
            fail(f"required mTLS material is missing or empty: {path}")

    if os.environ.get("QC_CELERY_BROKER_URL") != redis_url:
        fail("Celery broker must exactly match QC_REDIS_URL")
    if os.environ.get("QC_CELERY_RESULT_BACKEND") != redis_url:
        fail("Celery result backend must exactly match QC_REDIS_URL")


if __name__ == "__main__":
    main()
