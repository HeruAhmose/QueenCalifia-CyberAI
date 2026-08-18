from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from core import database
from engines.auto_remediation import AutoRemediation
from engines.evolution_engine import EvolutionEngine
from engines.incident_response import (
    IncidentCategory,
    IncidentResponseOrchestrator,
    IncidentSeverity,
)
from engines.threat_intel_auto import ThreatIntelEngine
from scripts.migrate_runtime_state_to_postgres import (
    SourceSpec,
    migrate_runtime_state,
    verify_postgres_manifest,
)
from sovereignty.approvals import SQLiteApprovalStore
from sovereignty.audit_chain import SQLiteAuditChain


def _postgres_url() -> str:
    return os.getenv("QC_TEST_POSTGRES_URL", "").strip()


def _clear_database_env(monkeypatch) -> None:
    monkeypatch.delenv("QC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("QC_DB_PATH", raising=False)
    monkeypatch.delenv("QC_EVOLUTION_DB", raising=False)
    monkeypatch.delenv("QC_THREAT_INTEL_DB", raising=False)


def _clean_target(url: str) -> None:
    import psycopg

    tables = (
        "qc_remediation_action_log",
        "qc_remediation_plans",
        "qc_ir_runtime_state",
        "qc_ir_incidents",
        "qc_audit_chain",
        "qc_used_nonces",
        "qc_approval_records",
        "health_log",
        "learned_patterns",
        "evolutions",
        "scan_intelligence",
        "false_positives",
        "network_baselines",
        "processed_scan_learning",
        "threat_feeds",
        "threat_indicators",
        "threat_cves",
        "threat_actors",
        "threat_sync_log",
        "threat_scheduler_lease",
        "qc_autonomy_lease",
        "identity_cycle_gate",
        "identity_remediation",
        "identity_findings",
        "identity_missions",
        "identity_provider",
        "identity_self_notes",
        "identity_persona_rules",
        "identity_reflections",
        "identity_proposals",
        "audit_log",
        "telemetry_events",
        "portfolio_scenarios",
        "forecast_runs",
        "features",
        "market_snapshots",
        "source_cache",
        "trusted_sources",
        "memories",
        "turns",
        "sessions",
    )
    with psycopg.connect(url) as conn:
        for table in tables:
            exists = conn.execute("SELECT to_regclass(%s)", (table,)).fetchone()[0]
            if exists:
                conn.execute(f'DELETE FROM "{table}"')


def _seed_sources(tmp_path: Path, monkeypatch):
    _clear_database_env(monkeypatch)
    primary = tmp_path / "queen.db"
    evolution = tmp_path / "qc_evolution.db"
    threat = tmp_path / "qc_threat_intel.db"

    database.init_db(primary)
    database.log_event(primary, "migration-test", "runtime", "full-state", {"ok": True})

    approvals = SQLiteApprovalStore(str(primary))
    approval = approvals.create(
        tenant_id="tenant-1",
        decision_hash="a" * 64,
        requested_by="alice",
    )
    assert approvals.mark_nonce_used(approval.nonce)

    audit = SQLiteAuditChain(str(primary))
    audit.append({"event": "migration-test", "actor": "pytest"})

    incident_engine = IncidentResponseOrchestrator({"db_path": str(primary)})
    incident = incident_engine.create_incident(
        title="Migration incident",
        description="Persisted before PostgreSQL cutover",
        severity=IncidentSeverity.HIGH,
        category=IncidentCategory.UNAUTHORIZED_ACCESS,
        indicators=["10.0.0.8"],
        affected_assets={"srv-migration"},
        auto_respond=False,
    )

    remediation = AutoRemediation({"db_path": str(primary), "allow_execute": False})
    plan = remediation.generate_plan(
        [{"finding_id": "finding-1", "title": "Migration finding", "category": "custom"}],
        target_host="srv-migration",
    )

    # Deliberate non-authoritative runtime writer: it MUST remain a blocker and
    # MUST NOT be silently migrated or dropped.
    with sqlite3.connect(primary) as conn:
        conn.execute(
            """
            CREATE TABLE qc_vuln_scan_jobs (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT,
                started_at TEXT,
                completed_at TEXT,
                error TEXT,
                result_json TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO qc_vuln_scan_jobs (scan_id, target, scan_type, status) VALUES (?, ?, ?, ?)",
            ("scan-blocker", "10.0.0.8", "quick", "queued"),
        )

    evolution_engine = EvolutionEngine({"db_path": str(evolution), "backup_dir": str(tmp_path / "backups")})
    with sqlite3.connect(evolution_engine.db_path) as conn:
        conn.execute(
            """
            INSERT INTO network_baselines (baseline_key, baseline_json, updated_at)
            VALUES (?, ?, ?)
            """,
            ("host:10.0.0.8", '{"ports":[443]}', "2026-08-17T00:00:00+00:00"),
        )

    threat_engine = ThreatIntelEngine(
        db_path=str(threat),
        auto_start=False,
        load_default_feeds=False,
    )
    with sqlite3.connect(threat_engine.db_path) as conn:
        conn.execute(
            """
            INSERT INTO threat_scheduler_lease
                (lease_name, owner_id, acquired_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            ("scheduler", "migration-owner", 1.0, 2.0),
        )

    return primary, evolution, threat, incident.incident_id, plan.plan_id


@pytest.mark.skipif(not _postgres_url(), reason="QC_TEST_POSTGRES_URL not configured")
def test_runtime_state_migration_is_verified_and_cutover_stays_blocked(monkeypatch, tmp_path: Path):
    url = _postgres_url()
    _clean_target(url)
    try:
        primary, evolution, threat, incident_id, plan_id = _seed_sources(tmp_path, monkeypatch)
        sources = [
            SourceSpec("primary+sovereignty+incident+remediation", primary),
            SourceSpec("evolution", evolution),
            SourceSpec("threat-intelligence", threat),
        ]

        manifest = migrate_runtime_state(
            sources=sources,
            database_url=url,
            topology_path=Path("config/runtime-state-topology.json"),
            require_cutover_ready=False,
        )

        assert manifest["cutover_ready"] is False
        assert any("vulnerability-scan-job-db" in item for item in manifest["cutover_blockers"])
        assert manifest["tables"]["telemetry_events"]["rows"] == 1
        assert manifest["tables"]["qc_approval_records"]["rows"] == 1
        assert manifest["tables"]["qc_audit_chain"]["rows"] == 1
        assert manifest["tables"]["qc_ir_incidents"]["rows"] == 1
        assert manifest["tables"]["qc_remediation_plans"]["rows"] == 1
        assert manifest["tables"]["network_baselines"]["rows"] == 1
        assert manifest["tables"]["threat_scheduler_lease"]["rows"] == 1
        assert "qc_vuln_scan_jobs" not in manifest["tables"]

        verified = verify_postgres_manifest(url, manifest)
        assert verified["verified"] is True

        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(url, row_factory=dict_row) as conn:
            incident_row = conn.execute(
                "SELECT incident_id, attack_chain_id FROM qc_ir_incidents WHERE incident_id=%s",
                (incident_id,),
            ).fetchone()
            plan_row = conn.execute(
                "SELECT plan_id FROM qc_remediation_plans WHERE plan_id=%s",
                (plan_id,),
            ).fetchone()
            assert incident_row["incident_id"] == incident_id
            assert plan_row["plan_id"] == plan_id
            assert conn.execute("SELECT to_regclass('qc_vuln_scan_jobs')").fetchone()[0] is None

        _clean_target(url)
        with pytest.raises(RuntimeError, match="Cutover is not ready"):
            migrate_runtime_state(
                sources=sources,
                database_url=url,
                topology_path=Path("config/runtime-state-topology.json"),
                require_cutover_ready=True,
            )
    finally:
        _clean_target(url)
