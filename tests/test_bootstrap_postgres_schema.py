from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "edge" / "bootstrap-postgres-schema.py"
spec = importlib.util.spec_from_file_location("qc_bootstrap_postgres_schema", MODULE_PATH)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_direct_neon_url_contract():
    direct = (
        "postgresql://user:pass@ep-example.c-12.us-east-1.aws.neon.tech/neondb"
        "?sslmode=require"
    )
    assert module.validate_direct_database_url(direct) == direct


@pytest.mark.parametrize(
    "url, message",
    [
        ("", "must use postgresql://"),
        ("https://example.invalid/db?sslmode=require", "must use postgresql://"),
        (
            "postgresql://user:pass@ep-example-pooler.c-12.us-east-1.aws.neon.tech/neondb?sslmode=require",
            "direct Neon endpoint",
        ),
        (
            "postgresql://user:pass@ep-example.c-12.us-east-1.aws.neon.tech/neondb",
            "sslmode=require",
        ),
    ],
)
def test_invalid_direct_url_rejected(url: str, message: str):
    with pytest.raises(RuntimeError, match=message):
        module.validate_direct_database_url(url)


def test_schema_contract_covers_externalized_authorities():
    required = {
        "qc_api_keys",
        "qc_request_audit",
        "qc_spki_evidence",
        "qc_live_scans",
        "qc_live_baselines",
        "qc_live_findings",
        "qc_approval_records",
        "qc_audit_chain",
        "qc_ir_incidents",
        "qc_remediation_plans",
        "health_log",
        "threat_indicators",
        "sessions",
        "turns",
    }
    assert required <= module.REQUIRED_TABLES
    rendered = "\n".join(module.schema_statements())
    for table in required:
        assert table in rendered


def test_bootstrap_evidence_never_claims_historical_migration(monkeypatch):
    class FakeConn:
        def __init__(self):
            self.inventory_calls = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, sql, params=()):
            if sql == "SHOW server_version_num":
                return FakeResult([("180000",)])
            if "pg_advisory_xact_lock" in sql:
                return FakeResult([(None,)])
            return FakeResult([])

    class FakeResult:
        def __init__(self, rows):
            self._rows = rows

        def fetchone(self):
            return self._rows[0]

        def fetchall(self):
            return self._rows

    inventories = [([], []), (sorted(module.REQUIRED_TABLES), [])]
    monkeypatch.setattr(module, "_inventory", lambda conn: inventories.pop(0))
    monkeypatch.setitem(
        __import__("sys").modules,
        "psycopg",
        type("FakePsycopg", (), {"connect": staticmethod(lambda url: FakeConn())}),
    )
    monkeypatch.setattr(
        module,
        "build_database_manifest",
        lambda url: {
            "postgresql_major": 18,
            "tables": {table: {} for table in sorted(module.REQUIRED_TABLES)},
            "database_sha256": "a" * 64,
        },
    )
    evidence = module.bootstrap(
        "postgresql://user:pass@ep-example.c-12.us-east-1.aws.neon.tech/neondb?sslmode=require"
    )
    assert evidence["schema_only"] is True
    assert evidence["historical_data_migrated"] is False
    assert evidence["target_was_empty"] is True
