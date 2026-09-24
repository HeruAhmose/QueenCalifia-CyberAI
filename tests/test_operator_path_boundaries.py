"""Exercise operator-selected files and the HTTP/configuration trust boundary."""
from __future__ import annotations

import importlib
import json
import sqlite3

import pytest


@pytest.mark.parametrize("module_name", [
    "scripts.migrate_primary_sqlite_to_postgres",
    "scripts.migrate_runtime_state_to_postgres",
])
@pytest.mark.parametrize("filename", ["source.db", "source?#percent%.db"])
def test_migration_source_is_the_exact_selected_file_and_is_read_only(tmp_path, module_name, filename):
    source = tmp_path / filename
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE marker (value TEXT)")
        db.execute("INSERT INTO marker VALUES ('selected-source')")
    before = source.read_bytes()
    connect = importlib.import_module(module_name)._connect_source
    with connect(source) as db:
        assert db.execute("SELECT value FROM marker").fetchone()[0] == "selected-source"
        # query_only is defence in depth; the connection itself must still be
        # opened read-only when a caller turns the pragma back off.
        db.execute("PRAGMA query_only=OFF")
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            db.execute("INSERT INTO marker VALUES ('must-not-write')")
    assert source.read_bytes() == before


@pytest.mark.parametrize("module_name", [
    "scripts.migrate_primary_sqlite_to_postgres",
    "scripts.migrate_runtime_state_to_postgres",
])
def test_migration_never_creates_a_missing_source(tmp_path, module_name):
    missing = tmp_path / "missing.db"
    with pytest.raises((RuntimeError, SystemExit), match="does not exist"):
        importlib.import_module(module_name)._connect_source(missing)
    assert not missing.exists()


def test_http_parameters_cannot_choose_the_spki_file(app_factory, monkeypatch, tmp_path):
    configured = tmp_path / "operator-events.jsonl"
    other = tmp_path / "private-events.jsonl"
    configured.write_text(json.dumps({"event_type": "configured", "value": "allowed"}) + "\n")
    other.write_text(json.dumps({"event_type": "private", "value": "must-not-return"}) + "\n")
    monkeypatch.setenv("QC_SPKI_LOG_FILE", str(configured))
    app = app_factory(require_api_key=True)
    query = {name: str(other) for name in ("path", "file", "log_file", "QC_SPKI_LOG_FILE")}
    response = app.test_client().get("/api/infra/spki-log", query_string=query,
        headers={"X-QC-API-Key": "test-api-key", "QC_SPKI_LOG_FILE": str(other)})
    assert response.status_code == 200
    assert response.json["data"]["events"] == [{"event_type": "configured", "value": "allowed"}]
    assert "must-not-return" not in response.get_data(as_text=True)
    assert other.read_text().count("must-not-return") == 1


@pytest.mark.parametrize("limit", ["-5", "0", "invalid", "1.5"])
def test_spki_limit_rejects_nonpositive_values(app_factory, limit):
    response = app_factory(require_api_key=False).test_client().get(
        "/api/infra/spki-log", query_string={"limit": limit})
    assert response.status_code == 400


def test_readiness_request_cannot_redirect_audit_storage(app_factory, tmp_path):
    app = app_factory(require_api_key=False)
    unauthorized = tmp_path / "never-create" / "audit.jsonl"
    response = app.test_client().get("/readyz", query_string={
        "path": str(unauthorized), "QC_AUDIT_LOG_FILE": str(unauthorized),
    })
    assert response.status_code == 200
    assert not unauthorized.parent.exists()
    assert str(unauthorized) not in response.get_data(as_text=True)


def test_api_key_is_compared_as_a_credential_never_opened_as_a_path(app_factory, tmp_path):
    app = app_factory(require_api_key=True)
    other = tmp_path / "not-a-key-store.json"
    other.write_text('{"private": "must-not-return"}')
    response = app.test_client().get("/api/mesh/status", query_string={
        "QC_API_KEYS_FILE": str(other), "file_path": str(other),
    }, headers={"X-QC-API-Key": str(other)})
    assert response.status_code == 401
    assert "must-not-return" not in response.get_data(as_text=True)
    assert json.loads(other.read_text()) == {"private": "must-not-return"}
