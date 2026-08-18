#!/usr/bin/env python3
"""Emit or verify a secret-free content manifest for the PostgreSQL public schema.

This is a cutover/restore evidence primitive. It never prints row values or a
connection URL. Every public base table is covered with schema metadata, row
count, and a deterministic SHA-256 over canonical JSONB row representations.

Usage:
  QC_DATABASE_URL=... python scripts/postgres_database_manifest.py > manifest.json
  QC_DATABASE_URL=... python scripts/postgres_database_manifest.py --verify-stdin < manifest.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any, Iterable

ROOT_SCHEMA = "public"
MANIFEST_KIND = "queen-califia-postgres-database-manifest"
MANIFEST_VERSION = 1
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _database_url() -> str:
    url = (os.getenv("QC_DATABASE_URL") or os.getenv("DATABASE_URL") or "").strip()
    if not url:
        raise RuntimeError("QC_DATABASE_URL or DATABASE_URL is required")
    if not (url.startswith("postgresql://") or url.startswith("postgres://")):
        raise RuntimeError("database URL must use postgresql:// or postgres://")
    return url


def _connect(url: str):
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - dependency contract
        raise RuntimeError("psycopg is required") from exc
    return psycopg.connect(url)


def _public_tables(conn) -> list[str]:
    rows = conn.execute(
        """
        SELECT c.relname
        FROM pg_class AS c
        JOIN pg_namespace AS n ON n.oid = c.relnamespace
        WHERE n.nspname = %s AND c.relkind = 'r'
        ORDER BY c.relname
        """,
        (ROOT_SCHEMA,),
    ).fetchall()
    return [row[0] for row in rows]


def _columns(conn, table: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT
            a.attname,
            pg_catalog.format_type(a.atttypid, a.atttypmod),
            a.attnotnull,
            pg_get_expr(d.adbin, d.adrelid),
            a.attidentity,
            a.attgenerated
        FROM pg_attribute AS a
        JOIN pg_class AS c ON c.oid = a.attrelid
        JOIN pg_namespace AS n ON n.oid = c.relnamespace
        LEFT JOIN pg_attrdef AS d
          ON d.adrelid = a.attrelid AND d.adnum = a.attnum
        WHERE n.nspname = %s
          AND c.relname = %s
          AND a.attnum > 0
          AND NOT a.attisdropped
        ORDER BY a.attnum
        """,
        (ROOT_SCHEMA, table),
    ).fetchall()
    return [
        {
            "name": name,
            "type": data_type,
            "not_null": bool(not_null),
            "default": default,
            "identity": identity or "",
            "generated": generated or "",
        }
        for name, data_type, not_null, default, identity, generated in rows
    ]


def _primary_key(conn, table: str) -> list[str]:
    rows = conn.execute(
        """
        SELECT a.attname
        FROM pg_index AS i
        JOIN pg_class AS c ON c.oid = i.indrelid
        JOIN pg_namespace AS n ON n.oid = c.relnamespace
        JOIN unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) ON TRUE
        JOIN pg_attribute AS a ON a.attrelid = c.oid AND a.attnum = k.attnum
        WHERE n.nspname = %s AND c.relname = %s AND i.indisprimary
        ORDER BY k.ord
        """,
        (ROOT_SCHEMA, table),
    ).fetchall()
    return [row[0] for row in rows]


def _schema_sha256(columns: list[dict[str, Any]], primary_key: list[str]) -> str:
    payload = json.dumps(
        {"columns": columns, "primary_key": primary_key},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _row_query(table: str, primary_key: list[str]):
    from psycopg import sql

    table_ident = sql.Identifier(ROOT_SCHEMA, table)
    base = sql.SQL("SELECT to_jsonb(t)::text FROM {} AS t").format(table_ident)
    if primary_key:
        order = sql.SQL(", ").join(sql.Identifier(name) for name in primary_key)
        # Canonical JSON is a deterministic final tiebreaker even if a malformed
        # legacy table somehow exposes a non-unique declared key.
        return base + sql.SQL(" ORDER BY {}, to_jsonb(t)::text").format(order)
    return base + sql.SQL(" ORDER BY to_jsonb(t)::text")


def _table_digest(conn, table: str, primary_key: list[str]) -> tuple[int, str]:
    """Stream canonical rows through a length-delimited SHA-256 accumulator."""
    digest = hashlib.sha256()
    count = 0
    cursor_name = "qc_manifest_" + hashlib.sha256(table.encode()).hexdigest()[:16]
    with conn.cursor(name=cursor_name) as cur:
        cur.itersize = 1000
        cur.execute(_row_query(table, primary_key))
        while True:
            rows = cur.fetchmany(1000)
            if not rows:
                break
            for (row_json,) in rows:
                raw = row_json.encode("utf-8")
                digest.update(len(raw).to_bytes(8, "big"))
                digest.update(raw)
                count += 1
    return count, digest.hexdigest()


def build_database_manifest(database_url: str | None = None) -> dict[str, Any]:
    url = database_url or _database_url()
    conn = _connect(url)
    try:
        # REPEATABLE READ makes all table digests a single logical snapshot.
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        server_version_num = int(conn.execute("SHOW server_version_num").fetchone()[0])
        tables: dict[str, Any] = {}
        for table in _public_tables(conn):
            columns = _columns(conn, table)
            primary_key = _primary_key(conn, table)
            rows, data_sha256 = _table_digest(conn, table, primary_key)
            tables[table] = {
                "columns": columns,
                "primary_key": primary_key,
                "schema_sha256": _schema_sha256(columns, primary_key),
                "rows": rows,
                "data_sha256": data_sha256,
            }
        manifest = {
            "kind": MANIFEST_KIND,
            "version": MANIFEST_VERSION,
            "postgresql_major": server_version_num // 10000,
            "schema": ROOT_SCHEMA,
            "tables": tables,
        }
        manifest["database_sha256"] = database_manifest_sha256(manifest)
        return manifest
    finally:
        conn.close()


def database_manifest_sha256(manifest: dict[str, Any]) -> str:
    material = {
        key: value
        for key, value in manifest.items()
        if key != "database_sha256"
    }
    raw = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _validate_manifest_shape(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise RuntimeError("manifest must be a JSON object")
    if manifest.get("kind") != MANIFEST_KIND or manifest.get("version") != MANIFEST_VERSION:
        raise RuntimeError("unsupported PostgreSQL database manifest")
    if manifest.get("schema") != ROOT_SCHEMA:
        raise RuntimeError("manifest schema must be public")
    expected_digest = manifest.get("database_sha256")
    if not isinstance(expected_digest, str) or not _SHA256_RE.fullmatch(expected_digest):
        raise RuntimeError("manifest database_sha256 is invalid")
    if database_manifest_sha256(manifest) != expected_digest:
        raise RuntimeError("manifest self-digest verification failed")
    tables = manifest.get("tables")
    if not isinstance(tables, dict):
        raise RuntimeError("manifest tables must be an object")
    for table, entry in tables.items():
        if not isinstance(table, str) or not table or not isinstance(entry, dict):
            raise RuntimeError("manifest contains an invalid table entry")
        for field in ("schema_sha256", "data_sha256"):
            value = entry.get(field)
            if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
                raise RuntimeError(f"manifest {table}.{field} is invalid")
        if not isinstance(entry.get("rows"), int) or entry["rows"] < 0:
            raise RuntimeError(f"manifest {table}.rows is invalid")
    return manifest


def verify_database_manifest(
    expected: dict[str, Any], database_url: str | None = None
) -> dict[str, Any]:
    expected = _validate_manifest_shape(expected)
    actual = build_database_manifest(database_url)
    if actual != expected:
        expected_tables = expected["tables"]
        actual_tables = actual["tables"]
        missing = sorted(set(expected_tables) - set(actual_tables))
        unexpected = sorted(set(actual_tables) - set(expected_tables))
        changed = sorted(
            table
            for table in set(expected_tables) & set(actual_tables)
            if expected_tables[table] != actual_tables[table]
        )
        detail = {
            "missing_tables": missing,
            "unexpected_tables": unexpected,
            "changed_tables": changed,
        }
        raise RuntimeError(
            "PostgreSQL restore does not match source database manifest: "
            + json.dumps(detail, sort_keys=True)
        )
    return {
        "verified": True,
        "database_sha256": actual["database_sha256"],
        "tables": len(actual["tables"]),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify-stdin",
        action="store_true",
        help="Read a source database manifest from stdin and verify this database",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.verify_stdin:
        result = verify_database_manifest(json.load(sys.stdin))
        print(
            "PostgreSQL whole-database restore verified: "
            f"tables={result['tables']} sha256={result['database_sha256']}"
        )
        return 0
    print(json.dumps(build_database_manifest(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
