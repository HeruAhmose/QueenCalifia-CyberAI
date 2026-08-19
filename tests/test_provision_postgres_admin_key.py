from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "edge" / "provision-postgres-admin-key.py"
spec = importlib.util.spec_from_file_location("qc_provision_postgres_admin_key", MODULE_PATH)
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
        (
            "postgresql://u:p@ep-example-pooler.c-12.us-east-1.aws.neon.tech/neondb?sslmode=require",
            "direct Neon endpoint",
        ),
        (
            "postgresql://u:p@ep-example.c-12.us-east-1.aws.neon.tech/neondb",
            "sslmode=require",
        ),
    ],
)
def test_invalid_direct_url_rejected(url: str, message: str):
    with pytest.raises(RuntimeError, match=message):
        module.validate_direct_database_url(url)


def test_secret_file_is_exclusive_and_0600(monkeypatch, tmp_path: Path):
    path = tmp_path / "secret" / "admin"
    monkeypatch.setattr(module, "SECRET_PATH", path)
    module._write_secret_file("abc")
    assert path.read_text() == "abc\n"
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        module._write_secret_file("def")


def test_existing_secret_file_fails_before_database_access(monkeypatch, tmp_path: Path):
    path = tmp_path / "admin"
    path.write_text("existing\n")
    monkeypatch.setattr(module, "SECRET_PATH", path)
    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        module.provision(
            "postgresql://u:p@ep-example.c-12.us-east-1.aws.neon.tech/neondb?sslmode=require",
            "pepper",
        )


def test_evidence_does_not_disclose_secret_or_fingerprint(monkeypatch, tmp_path: Path):
    path = tmp_path / "admin"
    monkeypatch.setattr(module, "SECRET_PATH", path)

    class FakeResult:
        def __init__(self, rows):
            self._rows = rows

        def fetchone(self):
            return self._rows[0]

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, sql, params=()):
            if sql == "SHOW server_version_num":
                return FakeResult([("180000",)])
            if "COUNT(*) FROM qc_api_keys" in sql:
                return FakeResult([(0,)])
            return FakeResult([(None,)])

    fake_psycopg = type("FakePsycopg", (), {"connect": staticmethod(lambda url: FakeConn())})
    monkeypatch.setitem(__import__("sys").modules, "psycopg", fake_psycopg)

    evidence = module.provision(
        "postgresql://u:p@ep-example.c-12.us-east-1.aws.neon.tech/neondb?sslmode=require",
        "pepper",
    )
    assert evidence["raw_key_printed"] is False
    assert evidence["fingerprint_printed"] is False
    assert "key_hash" not in evidence
    assert "secret_path" not in evidence
