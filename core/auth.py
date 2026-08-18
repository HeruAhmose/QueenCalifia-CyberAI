"""
QC OS — Auth Layer
==================
API key validation and admin gating for internal endpoints.

This mirrors `backend/core/auth.py` so that dashboard route modules work when
the security gateway root app (which imports from `core.*`) is loaded.

When QC_DATABASE_URL/DATABASE_URL selects PostgreSQL, structured API keys are
read from the shared `qc_api_keys` authority so revocation is immediately
visible across API replicas. Local/dev retains JSON/env compatibility.
"""

from __future__ import annotations

import hmac
import json
import os
from functools import wraps
from typing import Callable

from flask import jsonify, request

from core.api_key_crypto import (
    API_KEY_HASH_SCHEME,
    API_KEY_STORE_VERSION,
    api_key_fingerprint,
)
from core.database import database_backend, database_url


def _development_auth_disabled() -> bool:
    return (
        os.getenv("QC_NO_AUTH", "0") == "1"
        and os.getenv("QC_PRODUCTION", "0") != "1"
    )


def _postgres_key_meta(provided: str):
    if database_backend() != "postgresql" or not provided:
        return None
    pepper = os.getenv("QC_API_KEY_PEPPER", "")
    if not pepper:
        return None
    try:
        import psycopg
        from psycopg.rows import dict_row

        key_hash = api_key_fingerprint(provided, pepper)
        with psycopg.connect(database_url(), row_factory=dict_row) as conn:
            row = conn.execute(
                """
                SELECT key_hash, role, permissions_json, rate_limit, created_at,
                       description, budget_capacity, budget_refill_per_minute, revoked
                FROM qc_api_keys
                WHERE key_hash=%s AND revoked=0
                """,
                (key_hash,),
            ).fetchone()
        if not row:
            return None
        return {
            "key_hash": row["key_hash"],
            "role": row["role"],
            "permissions": json.loads(row["permissions_json"]),
            "rate_limit": int(row["rate_limit"]),
            "created_at": row["created_at"],
            "description": row["description"],
            "budget_capacity": row["budget_capacity"],
            "budget_refill_per_minute": row["budget_refill_per_minute"],
            "revoked": bool(row["revoked"]),
        }
    except Exception:
        if os.getenv("QC_PRODUCTION", "0") == "1":
            raise
        return None


def _structured_key_meta(provided: str):
    if not provided:
        return None

    pg_meta = _postgres_key_meta(provided)
    if pg_meta is not None:
        return pg_meta
    if database_backend() == "postgresql" and os.getenv("QC_PRODUCTION", "0") == "1":
        # PostgreSQL is authoritative in production. Never fall through to a
        # stale local file/env representation after a DB miss/revocation.
        return None

    raw = (os.getenv("QC_API_KEYS_JSON", "") or "").strip()
    if not raw:
        file_path = (os.getenv("QC_API_KEYS_FILE", "") or "").strip()
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as handle:
                    raw = handle.read()
            except OSError:
                raw = ""
    if not raw:
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None

    if (
        not isinstance(data, dict)
        or data.get("version") != API_KEY_STORE_VERSION
        or data.get("hash_scheme") != API_KEY_HASH_SCHEME
    ):
        return None

    pepper = os.getenv("QC_API_KEY_PEPPER", "")
    if not pepper:
        return None

    provided_hash = api_key_fingerprint(provided, pepper)
    for item in data.get("keys", []):
        stored_hash = str(item.get("key_hash") or "")
        if (
            hmac.compare_digest(stored_hash, provided_hash)
            and not bool(item.get("revoked", False))
        ):
            return item
    return None


def require_api_key(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if _development_auth_disabled():
            return fn(*args, **kwargs)

        provided = request.headers.get("X-QC-API-Key", "")
        if _structured_key_meta(provided):
            return fn(*args, **kwargs)

        # Legacy fallback is local/dev only when PostgreSQL is not production authority.
        if database_backend() == "postgresql" and os.getenv("QC_PRODUCTION", "0") == "1":
            return jsonify({"error": "unauthorized"}), 401

        expected = (os.getenv("QC_API_KEY", "") or "").strip()
        if not expected or not hmac.compare_digest(provided, expected):
            return jsonify({"error": "unauthorized"}), 401

        return fn(*args, **kwargs)

    return wrapper


def require_admin(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if _development_auth_disabled():
            return fn(*args, **kwargs)

        provided_api_key = request.headers.get("X-QC-API-Key", "")
        meta = _structured_key_meta(provided_api_key)
        if meta and "admin" in list(meta.get("permissions", [])):
            return fn(*args, **kwargs)

        if database_backend() == "postgresql" and os.getenv("QC_PRODUCTION", "0") == "1":
            return jsonify({"error": "forbidden"}), 403

        admin_key = (os.getenv("QC_ADMIN_KEY", "") or "").strip()
        if not admin_key:
            return jsonify({"error": "admin access not configured"}), 403

        provided = request.headers.get("X-QC-Admin-Key", "")
        if not hmac.compare_digest(provided, admin_key):
            return jsonify({"error": "forbidden"}), 403

        return fn(*args, **kwargs)

    return wrapper
