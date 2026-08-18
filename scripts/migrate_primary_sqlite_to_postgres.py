#!/usr/bin/env python3
"""Migrate Queen Califia's primary SQLite state into PostgreSQL.

Safety properties:
- source SQLite database is opened read-only;
- target must be empty;
- copy + sequence reset + count verification happen in one PostgreSQL transaction;
- any mismatch rolls the PostgreSQL transaction back;
- the script does not change deployment configuration or delete the SQLite source.

This is a cutover preparation tool, not a completed rollback workflow. Until a
post-cutover reverse-sync/snapshot restore procedure is validated, issue #72's
rollback/HA gates must remain open.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.database import POSTGRES_SCHEMA  # noqa: E402


PRIMARY_TABLES = (
    "sessions",
    "turns",
    "memories",
    "trusted_sources",
    "source_cache",
    "market_snapshots",
    "features",
    "forecast_runs",
    "portfolio_scenarios",
    "telemetry_events",
    "audit_log",
    "identity_proposals",
    "identity_reflections",
    "identity_persona_rules",
    "identity_self_notes",
    "identity_provider",
    "identity_missions",
    "identity_findings",
    "identity_remediation",
)

SERIAL_TABLES = (
    "turns",
    "memories",
    "source_cache",
    "market_snapshots",
    "features",
    "telemetry_events",
    "audit_log",
    "identity_proposals",
    "identity_reflections",
    "identity_persona_rules",
    "identity_self_notes",
    "identity_missions",
    "identity_findings",
    "identity_remediation",
)

DYNAMIC_TABLES = {
    "identity_cycle_gate": """
        CREATE TABLE IF NOT EXISTS identity_cycle_gate (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            last_auto_at TEXT NOT NULL
        )
    """
}


def _schema_statements(schema: str) -> list[str]:
    return [statement.strip() for statement in schema.split(";") if statement.strip()]


def _quote_sqlite_identifier(name: str) -> str:
    if name not in set(PRIMARY_TABLES) | set(DYNAMIC_TABLES):
        raise ValueError(f"unexpected table name: {name}")
    return '"' + name.replace('"', '""') + '"'


def _source_tables(source: sqlite3.Connection) -> set[str]:
    rows = source.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {str(row[0]) for row in rows if not str(row[0]).startswith("sqlite_")}


def _columns(source: sqlite3.Connection, table: str) -> list[str]:
    quoted = _quote_sqlite_identifier(table)
    rows = source.execute(f"PRAGMA table_info({quoted})").fetchall()
    return [str(row[1]) for row in rows]


def _row_count_sqlite(source: sqlite3.Connection, table: str) -> int:
    quoted = _quote_sqlite_identifier(table)
    return int(source.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0])


def _connect_source(path: Path) -> sqlite3.Connection:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise SystemExit(f"SQLite source does not exist: {resolved}")
    source = sqlite3.connect(f"file:{resolved.as_posix()}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    source.execute("PRAGMA query_only=ON")
    return source


def _connect_postgres(url: str):
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise SystemExit("psycopg is required; install backend/requirements.txt") from exc
    return psycopg.connect(url, row_factory=dict_row)


def _ensure_target_schema(target, source_tables: set[str]) -> None:
    for statement in _schema_statements(POSTGRES_SCHEMA):
        target.execute(statement)
    for table, ddl in DYNAMIC_TABLES.items():
        if table in source_tables:
            target.execute(ddl)


def _assert_target_empty(target, source_tables: Iterable[str]) -> None:
    occupied = []
    for table in source_tables:
        if table not in set(PRIMARY_TABLES) | set(DYNAMIC_TABLES):
            continue
        count = int(target.execute(f'SELECT COUNT(*) AS n FROM "{table}"').fetchone()["n"])
        if count:
            occupied.append((table, count))
    if occupied:
        detail = ", ".join(f"{table}={count}" for table, count in occupied)
        raise RuntimeError(
            "PostgreSQL target is not empty; refusing to merge authorities. "
            f"Occupied tables: {detail}"
        )


def _copy_table(source: sqlite3.Connection, target, table: str) -> int:
    columns = _columns(source, table)
    if not columns:
        return 0
    quoted_table = _quote_sqlite_identifier(table)
    rows = source.execute(f"SELECT * FROM {quoted_table}").fetchall()
    if not rows:
        return 0

    column_sql = ", ".join(f'"{column}"' for column in columns)
    placeholders = ", ".join(["%s"] * len(columns))
    insert_sql = f'INSERT INTO "{table}" ({column_sql}) VALUES ({placeholders})'
    values = [tuple(row[column] for column in columns) for row in rows]
    with target.cursor() as cursor:
        cursor.executemany(insert_sql, values)
    return len(rows)


def _reset_sequence(target, table: str) -> None:
    row = target.execute("SELECT pg_get_serial_sequence(%s, 'id') AS seq", (table,)).fetchone()
    sequence = row["seq"] if row else None
    if not sequence:
        return
    max_id = int(target.execute(f'SELECT COALESCE(MAX(id), 0) AS max_id FROM "{table}"').fetchone()["max_id"])
    if max_id > 0:
        target.execute("SELECT setval(%s::regclass, %s, true)", (sequence, max_id))
    else:
        target.execute("SELECT setval(%s::regclass, 1, false)", (sequence,))


def migrate(sqlite_path: Path, database_url: str) -> dict[str, int]:
    source = _connect_source(sqlite_path)
    target = _connect_postgres(database_url)
    try:
        source_tables = _source_tables(source)
        unknown = sorted(source_tables - set(PRIMARY_TABLES) - set(DYNAMIC_TABLES))
        if unknown:
            raise RuntimeError(
                "SQLite source contains unrecognized application tables; update the migration inventory before cutover: "
                + ", ".join(unknown)
            )

        expected_tables = [table for table in PRIMARY_TABLES if table in source_tables]
        expected_tables.extend(table for table in DYNAMIC_TABLES if table in source_tables)

        with target.transaction():
            _ensure_target_schema(target, source_tables)
            _assert_target_empty(target, expected_tables)

            copied: dict[str, int] = {}
            for table in expected_tables:
                copied[table] = _copy_table(source, target, table)

            for table in SERIAL_TABLES:
                if table in source_tables:
                    _reset_sequence(target, table)

            for table in expected_tables:
                source_count = _row_count_sqlite(source, table)
                target_count = int(
                    target.execute(f'SELECT COUNT(*) AS n FROM "{table}"').fetchone()["n"]
                )
                if target_count != source_count:
                    raise RuntimeError(
                        f"Verification failed for {table}: source={source_count}, target={target_count}"
                    )
        return copied
    finally:
        source.close()
        target.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite", required=True, type=Path, help="Path to the source SQLite database")
    parser.add_argument(
        "--database-url",
        default=(os.getenv("QC_DATABASE_URL") or os.getenv("DATABASE_URL") or ""),
        help="PostgreSQL URL; defaults to QC_DATABASE_URL or DATABASE_URL",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.database_url.startswith(("postgresql://", "postgres://")):
        raise SystemExit("--database-url must be a postgresql:// or postgres:// URL")
    copied = migrate(args.sqlite, args.database_url)
    print("Primary SQLite -> PostgreSQL migration verified.")
    for table, count in copied.items():
        print(f"  {table}: {count}")
    print("SQLite source was not modified. Deployment cutover remains a separate controlled step.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
