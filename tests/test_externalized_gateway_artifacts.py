from __future__ import annotations

import os

import pytest
from flask import Flask

from core.api_key_crypto import api_key_fingerprint
from core.externalized_artifacts import PostgresAPIKeyStore, PostgresAuditLog


def _postgres_url() -> str:
    return os.environ.get("QC_TEST_POSTGRES_URL", "").strip()


def _clean(url: str) -> None:
    import psycopg

    with psycopg.connect(url) as conn:
        for table in ("qc_request_audit", "qc_api_keys"):
            if conn.execute("SELECT to_regclass(%s)", (table,)).fetchone()[0]:
                conn.execute(f'DELETE FROM "{table}"')


@pytest.mark.skipif(not _postgres_url(), reason="QC_TEST_POSTGRES_URL not configured")
def test_api_key_create_validate_and_revoke_are_cross_replica(monkeypatch):
    url = _postgres_url()
    _clean(url)
    monkeypatch.setenv("QC_DATABASE_URL", url)
    monkeypatch.setenv("QC_PRODUCTION", "0")
    monkeypatch.setenv("QC_API_KEY_PEPPER", "test-pepper-not-secret")
    monkeypatch.delenv("QC_API_KEYS_JSON", raising=False)
    monkeypatch.delenv("QC_API_KEY", raising=False)
    monkeypatch.delenv("QC_ADMIN_KEY", raising=False)
    try:
        first = PostgresAPIKeyStore("ignored.json", "test-pepper-not-secret")
        second = PostgresAPIKeyStore("ignored.json", "test-pepper-not-secret")

        raw = first.generate_key(
            role="admin",
            permissions=["read", "write", "admin"],
            rate_limit=240,
            description="cross-replica test",
        )
        meta = second.validate(raw)
        assert meta is not None
        assert meta["role"] == "admin"
        assert "admin" in meta["permissions"]

        key_hash = api_key_fingerprint(raw, "test-pepper-not-secret")
        assert second.revoke(key_hash) is True
        assert first.validate(raw) is None
    finally:
        _clean(url)


@pytest.mark.skipif(not _postgres_url(), reason="QC_TEST_POSTGRES_URL not configured")
def test_request_audit_chain_is_shared_and_verifiable(monkeypatch):
    url = _postgres_url()
    _clean(url)
    monkeypatch.setenv("QC_DATABASE_URL", url)
    app = Flask(__name__)
    try:
        first = PostgresAuditLog("ignored.jsonl", "test-audit-hmac")
        second = PostgresAuditLog("ignored.jsonl", "test-audit-hmac")

        with app.test_request_context("/first"):
            from flask import g

            g.request_id = "req-1"
            first.log("first", "127.0.0.1", "admin", 200, {"order": 1})
        with app.test_request_context("/second"):
            from flask import g

            g.request_id = "req-2"
            second.log("second", "127.0.0.2", "analyst", 202, {"order": 2})

        recent = first.recent(10)
        assert [item["action"] for item in recent] == ["first", "second"]
        assert recent[1]["previous_hash"] == recent[0]["hash"]
        verified = second.verify_integrity()
        assert verified == {"valid": True, "entries_checked": 2, "errors": []}
        assert second.probe_health()["entries"] == 2
    finally:
        _clean(url)
