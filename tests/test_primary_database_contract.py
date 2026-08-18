from __future__ import annotations

import concurrent.futures
import os
import threading
import uuid
from pathlib import Path

import pytest

from core import database


def _clear_database_env(monkeypatch):
    monkeypatch.delenv("QC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("QC_DB_PATH", raising=False)


def test_sqlite_primary_contract_remains_default(monkeypatch, tmp_path: Path):
    _clear_database_env(monkeypatch)
    db_path = tmp_path / "primary.db"

    assert database.database_backend() == "sqlite"
    database.init_db(db_path)
    database.log_event(db_path, "test", "sqlite", "primary-contract", {"ok": True})

    with database.get_db(db_path) as connection:
        row = connection.execute(
            "SELECT category, kind, subject FROM telemetry_events ORDER BY id DESC LIMIT 1"
        ).fetchone()

    assert dict(row) == {
        "category": "test",
        "kind": "sqlite",
        "subject": "primary-contract",
    }


def test_sqlite_primary_contract_rejects_untrusted_filesystem_path(monkeypatch):
    _clear_database_env(monkeypatch)
    # Exercise the runtime branch rather than pytest's isolated tempfile mapper.
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    forbidden = Path("/etc") / f"queen-califia-{uuid.uuid4().hex}.db"

    with pytest.raises(ValueError, match="not approved"):
        database.get_db(forbidden)

    assert not forbidden.exists()


def test_postgres_sql_translation_preserves_existing_call_surface():
    translated = database._postgres_sql(
        "INSERT OR IGNORE INTO memories (user_id,key,value) VALUES (?,?,?)"
    )
    assert translated == (
        "INSERT INTO memories (user_id,key,value) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING"
    )

    cycle = database._postgres_sql(
        "INSERT OR REPLACE INTO identity_cycle_gate (id, last_auto_at) VALUES (1, ?)"
    )
    assert cycle == (
        "INSERT INTO identity_cycle_gate (id, last_auto_at) VALUES (1, %s) "
        "ON CONFLICT (id) DO UPDATE SET last_auto_at = EXCLUDED.last_auto_at"
    )
    assert database._postgres_sql("BEGIN IMMEDIATE") == "SELECT pg_advisory_xact_lock(72427201)"


def _postgres_url() -> str:
    return os.getenv("QC_TEST_POSTGRES_URL", "").strip()


@pytest.mark.skipif(not _postgres_url(), reason="QC_TEST_POSTGRES_URL not configured")
def test_postgresql_migration_identity_and_concurrent_writes(monkeypatch, tmp_path: Path):
    url = _postgres_url()

    _clear_database_env(monkeypatch)
    source_path = tmp_path / "migration-source.db"
    database.init_db(source_path)
    migration_marker = f"migrated-{uuid.uuid4()}"
    database.log_event(source_path, "migration-test", "source", migration_marker, {"ok": True})

    from core import autonomy_loop

    assert autonomy_loop._acquire_lease(source_path, "migration-owner", ttl_seconds=300) is True

    from scripts.migrate_primary_sqlite_to_postgres import migrate

    copied = migrate(source_path, url)
    assert copied["trusted_sources"] == 6
    assert copied["telemetry_events"] == 1
    assert copied["qc_autonomy_lease"] == 1

    with database.get_db(source_path) as source:
        source_count = source.execute(
            "SELECT COUNT(*) AS n FROM telemetry_events WHERE subject=?",
            (migration_marker,),
        ).fetchone()["n"]
        lease_count = source.execute(
            "SELECT COUNT(*) AS n FROM qc_autonomy_lease WHERE lease_name='autonomy_loop'"
        ).fetchone()["n"]
    assert source_count == 1
    assert lease_count == 1

    monkeypatch.setenv("QC_DATABASE_URL", url)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert database.database_backend() == "postgresql"
    database.init_db(tmp_path / "ignored.db")

    with database.get_db(tmp_path / "ignored.db") as connection:
        migrated_count = connection.execute(
            "SELECT COUNT(*) AS n FROM telemetry_events WHERE subject=?",
            (migration_marker,),
        ).fetchone()["n"]
    assert migrated_count == 1

    from backend.modules.identity import store

    marker = f"pg-contract-{uuid.uuid4()}"
    proposal = store.create_proposal(
        tmp_path / "ignored.db",
        "cyber",
        "contract_test",
        marker,
        score=0.91,
        source="pytest",
    )
    assert isinstance(proposal["id"], int)
    assert proposal["content"] == marker

    promoted = store.promote_proposal_to_memory(tmp_path / "ignored.db", proposal["id"])
    assert promoted["status"] == "approved"

    with database.get_db(tmp_path / "ignored.db") as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS identity_cycle_gate (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_auto_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT OR REPLACE INTO identity_cycle_gate (id, last_auto_at) VALUES (1, ?)",
            (database.utc_now(),),
        )

    event_subject = f"concurrent-{uuid.uuid4()}"

    def write_event(index: int) -> None:
        database.log_event(
            tmp_path / "ignored.db",
            "postgres-contract",
            f"writer-{index}",
            event_subject,
            {"index": index},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(write_event, range(12)))

    with database.get_db(tmp_path / "ignored.db") as connection:
        count = connection.execute(
            "SELECT COUNT(*) AS n FROM telemetry_events WHERE subject=?",
            (event_subject,),
        ).fetchone()["n"]
        memory = connection.execute(
            "SELECT value FROM memories WHERE user_id='qc_identity' AND value=?",
            (marker,),
        ).fetchone()
        connection.execute("DELETE FROM qc_autonomy_lease WHERE lease_name='autonomy_loop'")

    assert count == 12
    assert memory["value"] == marker

    barrier = threading.Barrier(2)

    def acquire(owner: str) -> bool:
        barrier.wait()
        return autonomy_loop._acquire_lease(tmp_path / "ignored.db", owner, ttl_seconds=300)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(acquire, ("postgres-owner-a", "postgres-owner-b")))

    assert sorted(results) == [False, True]
