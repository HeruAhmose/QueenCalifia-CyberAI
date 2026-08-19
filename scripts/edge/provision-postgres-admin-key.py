#!/usr/bin/env python3
"""Provision Queen Califia's first production admin API key into PostgreSQL.

The raw key is generated locally and written to a caller-selected secret file.
Only its PBKDF2 fingerprint is persisted in PostgreSQL. The raw key is never
printed. Provisioning fails closed unless qc_api_keys is empty.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.api_key_crypto import API_KEY_HASH_SCHEME, api_key_fingerprint  # noqa: E402


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def validate_direct_database_url(url: str) -> str:
    value = (url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise RuntimeError("QC_DATABASE_DIRECT_URL must use postgresql:// or postgres://")
    if not parsed.hostname:
        raise RuntimeError("QC_DATABASE_DIRECT_URL is missing a hostname")
    if "-pooler." in parsed.hostname:
        raise RuntimeError("QC_DATABASE_DIRECT_URL must use the direct Neon endpoint")
    query = parse_qs(parsed.query, keep_blank_values=True)
    if query.get("sslmode") != ["require"]:
        raise RuntimeError("QC_DATABASE_DIRECT_URL must require TLS with sslmode=require")
    return value


def _write_secret_file(path: Path, raw_key: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except PermissionError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (raw_key + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        path.unlink(missing_ok=True)
        raise RuntimeError(f"secret file permissions must be 0600, got {oct(mode)}")


def provision(database_url: str, pepper: str, secret_path: Path) -> dict[str, object]:
    if not pepper:
        raise RuntimeError("QC_API_KEY_PEPPER is required")
    if secret_path.exists():
        raise RuntimeError(f"refusing to overwrite existing secret file: {secret_path}")

    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("psycopg is required") from exc

    url = validate_direct_database_url(database_url)
    raw_key = secrets.token_hex(32)
    key_hash = api_key_fingerprint(raw_key, pepper)
    created_at = _utcnow()

    _write_secret_file(secret_path, raw_key)
    inserted = False
    try:
        with psycopg.connect(url) as conn:
            server_version_num = int(conn.execute("SHOW server_version_num").fetchone()[0])
            major = server_version_num // 10000
            if major != 18:
                raise RuntimeError(f"expected PostgreSQL 18, got major {major}")
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (72427219,))
            row = conn.execute("SELECT COUNT(*) FROM qc_api_keys").fetchone()
            if int(row[0]) != 0:
                raise RuntimeError("refusing admin-key provision: qc_api_keys is not empty")
            conn.execute(
                """
                INSERT INTO qc_api_keys (
                    key_hash, role, permissions_json, rate_limit, created_at,
                    description, budget_capacity, budget_refill_per_minute, revoked
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,0)
                """,
                (
                    key_hash,
                    "admin",
                    json.dumps(["read", "write", "execute", "admin"]),
                    240,
                    created_at,
                    "sovereign-edge initial admin",
                    None,
                    None,
                ),
            )
            inserted = True
    except Exception:
        secret_path.unlink(missing_ok=True)
        raise

    if not inserted:
        secret_path.unlink(missing_ok=True)
        raise RuntimeError("admin-key provision did not commit")

    return {
        "kind": "queen-califia-postgres-admin-key-provision",
        "version": 1,
        "postgresql_major": 18,
        "role": "admin",
        "permissions": ["read", "write", "execute", "admin"],
        "rate_limit": 240,
        "hash_scheme": API_KEY_HASH_SCHEME,
        "key_hash": key_hash,
        "raw_key_printed": False,
        "secret_file_mode": "0600",
        "secret_path": str(secret_path),
    }


def main() -> int:
    url = os.getenv("QC_DATABASE_DIRECT_URL", "")
    pepper = os.getenv("QC_API_KEY_PEPPER", "")
    secret_path = Path(
        os.getenv("QC_ADMIN_KEY_OUTPUT", "/srv/queen-califia/secrets/qc-admin-api-key")
    )
    print(json.dumps(provision(url, pepper, secret_path), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
