#!/usr/bin/env python3
"""Seed representative migrated runtime state and emit its verification manifest.

CI-only helper for the pg_dump -> pg_restore contract. SQLite bytes are created
through the repository's test-only trusted path resolver; no caller-provided
filesystem path is accepted.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import database  # noqa: E402
from engines.auto_remediation import AutoRemediation  # noqa: E402
from engines.incident_response import (  # noqa: E402
    IncidentCategory,
    IncidentResponseOrchestrator,
    IncidentSeverity,
)
from scripts.migrate_runtime_state_to_postgres import SourceSpec, migrate_runtime_state  # noqa: E402
from sovereignty.approvals import SQLiteApprovalStore  # noqa: E402
from sovereignty.audit_chain import SQLiteAuditChain  # noqa: E402


def _clean_target(url: str) -> None:
    import psycopg
    from psycopg import sql

    if not url.endswith("/queen_backup_ci"):
        raise RuntimeError("backup contract target must be queen_backup_ci")
    with psycopg.connect(url) as conn:
        rows = conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='public'"
        ).fetchall()
        for (table,) in rows:
            conn.execute(sql.SQL("DROP TABLE {} CASCADE").format(sql.Identifier(table)))


def main() -> int:
    url = (os.environ.get("QC_BACKUP_SOURCE_URL") or "").strip()
    if not url:
        raise RuntimeError("QC_BACKUP_SOURCE_URL is required")
    _clean_target(url)

    os.environ["PYTEST_CURRENT_TEST"] = "ci-backup-restore-contract"
    requested_primary = Path("data/queen.db")
    database.init_db(requested_primary)
    database.log_event(
        requested_primary,
        "backup-restore-contract",
        "runtime",
        "representative-state",
        {"verified": True},
    )
    primary = database._resolve_sqlite_path(requested_primary)

    approvals = SQLiteApprovalStore(str(primary))
    approval = approvals.create(
        tenant_id="backup-contract",
        decision_hash="b" * 64,
        requested_by="ci",
    )
    approvals.mark_nonce_used(approval.nonce)

    audit = SQLiteAuditChain(str(primary))
    audit.append({"event": "backup-restore-contract", "actor": "ci"})

    incident = IncidentResponseOrchestrator({"db_path": str(primary)})
    incident.create_incident(
        title="Backup contract incident",
        description="Representative state for PostgreSQL restore verification",
        severity=IncidentSeverity.MEDIUM,
        category=IncidentCategory.UNAUTHORIZED_ACCESS,
        indicators=["127.0.0.1"],
        affected_assets={"ci-asset"},
        auto_respond=False,
    )

    remediation = AutoRemediation({"db_path": str(primary), "allow_execute": False})
    remediation.generate_plan(
        [{"finding_id": "backup-finding", "title": "Backup finding", "category": "custom"}],
        target_host="ci-asset",
    )

    manifest = migrate_runtime_state(
        sources=[SourceSpec("primary+sovereignty+incident+remediation", primary)],
        database_url=url,
        topology_path=ROOT / "config" / "runtime-state-topology.json",
        require_cutover_ready=False,
    )

    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
