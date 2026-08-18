"""Replica-aware runtime state adapters for security engines.

The original engine modules retain their SQLite behavior for local tooling and
single-writer development. The production composition layer uses the factories
in this module: when QC_DATABASE_URL/DATABASE_URL selects PostgreSQL, these
adapters replace filesystem SQLite authority with the canonical PostgreSQL
contract from core.database.

This module deliberately does not enable horizontal API replicas. It supplies
external durable authority plus targeted concurrency controls; the repository's
runtime-state topology remains the source of truth for the still-closed HA,
backup/restore, rolling-update, and read-only-rootfs gates.
"""
from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from core.database import database_backend, get_db
from engines.auto_remediation import AutoRemediation as _SQLiteAutoRemediation
from engines.evolution_engine import (
    FALSE_POSITIVE_THRESHOLD,
    EvolutionEngine as _SQLiteEvolutionEngine,
    EvolutionEvent,
    EvolutionType,
    LearnedPattern,
    LearningType,
)
from engines.incident_response import (
    IncidentResponseOrchestrator as _SQLiteIncidentResponseOrchestrator,
    IncidentStatus,
)
from engines.threat_intel_auto import (
    CVERecord,
    FeedFormat,
    FeedStatus,
    ThreatActorProfile,
    ThreatFeed,
    ThreatIndicator,
    ThreatIntelEngine as _SQLiteThreatIntelEngine,
)


def _advisory_key(namespace: str, value: str) -> int:
    digest = hashlib.sha256(f"{namespace}:{value}".encode("utf-8")).digest()[:8]
    return int.from_bytes(digest, "big") & 0x7FFF_FFFF_FFFF_FFFF


def _lock(conn, namespace: str, value: str) -> None:
    if getattr(conn, "dialect", "") != "postgresql":
        raise RuntimeError("replica-aware runtime adapter requires PostgreSQL")
    conn.execute("SELECT pg_advisory_xact_lock(?)", (_advisory_key(namespace, value),))


class PostgresIncidentResponseOrchestrator(_SQLiteIncidentResponseOrchestrator):
    """Incident authority backed by PostgreSQL with per-incident serialization."""

    def _connect_state_store(self):
        return get_db(self.db_path)

    def _init_state_store(self) -> None:
        with self._connect_state_store() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_ir_incidents (
                    incident_id TEXT PRIMARY KEY,
                    attack_chain_id TEXT,
                    incident_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute("ALTER TABLE qc_ir_incidents ADD COLUMN IF NOT EXISTS attack_chain_id TEXT")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_qc_ir_attack_chain "
                "ON qc_ir_incidents(attack_chain_id) WHERE attack_chain_id IS NOT NULL"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_ir_runtime_state (
                    state_key TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def _load_persisted_state(self) -> None:
        with self._connect_state_store() as conn:
            rows = conn.execute(
                "SELECT incident_json FROM qc_ir_incidents ORDER BY updated_at ASC"
            ).fetchall()
            runtime_rows = {
                row["state_key"]: json.loads(row["state_json"])
                for row in conn.execute(
                    "SELECT state_key, state_json FROM qc_ir_runtime_state"
                ).fetchall()
            }

        for row in rows:
            incident = self._incident_from_dict(json.loads(row["incident_json"]))
            self.incidents[incident.incident_id] = incident
            if incident.attack_chain_id:
                self.incident_index_by_chain[incident.attack_chain_id] = incident.incident_id

        self.blocked_ips = runtime_rows.get("blocked_ips", {})
        self.isolated_hosts = set(runtime_rows.get("isolated_hosts", []))
        self.disabled_accounts = set(runtime_rows.get("disabled_accounts", []))
        self.quarantined_files = runtime_rows.get("quarantined_files", [])
        self.metrics.update(runtime_rows.get("metrics", {}))
        self.executed_actions = [
            self._action_from_dict(item)
            for item in runtime_rows.get("executed_actions", [])
        ]
        self.metrics["active_incidents"] = sum(
            1
            for incident in self.incidents.values()
            if incident.status not in {IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE}
        )

    def _persist_incident(self, incident) -> None:
        payload = json.dumps(self._incident_to_dict(incident), default=str)
        with self._connect_state_store() as conn:
            conn.execute(
                """
                INSERT INTO qc_ir_incidents
                    (incident_id, attack_chain_id, incident_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    attack_chain_id=excluded.attack_chain_id,
                    incident_json=excluded.incident_json,
                    updated_at=excluded.updated_at
                """,
                (
                    incident.incident_id,
                    incident.attack_chain_id,
                    payload,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def _persist_runtime_state(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        payloads = {
            "blocked_ips": self.blocked_ips,
            "isolated_hosts": sorted(self.isolated_hosts),
            "disabled_accounts": sorted(self.disabled_accounts),
            "quarantined_files": self.quarantined_files,
            "metrics": self.metrics,
            "executed_actions": [self._action_to_dict(action) for action in self.executed_actions[-500:]],
        }
        with self._connect_state_store() as conn:
            for key, value in payloads.items():
                conn.execute(
                    """
                    INSERT INTO qc_ir_runtime_state (state_key, state_json, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(state_key) DO UPDATE SET
                        state_json=excluded.state_json,
                        updated_at=excluded.updated_at
                    """,
                    (key, json.dumps(value, default=str), now),
                )

    def _refresh_incident(self, incident_id: str):
        with self._connect_state_store() as conn:
            row = conn.execute(
                "SELECT incident_json FROM qc_ir_incidents WHERE incident_id=?",
                (incident_id,),
            ).fetchone()
        if not row:
            self.incidents.pop(incident_id, None)
            return None
        incident = self._incident_from_dict(json.loads(row["incident_json"]))
        self.incidents[incident_id] = incident
        if incident.attack_chain_id:
            self.incident_index_by_chain[incident.attack_chain_id] = incident_id
        return incident

    def _refresh_all_incidents(self) -> None:
        with self._connect_state_store() as conn:
            rows = conn.execute("SELECT incident_json FROM qc_ir_incidents").fetchall()
        seen = set()
        for row in rows:
            incident = self._incident_from_dict(json.loads(row["incident_json"]))
            seen.add(incident.incident_id)
            self.incidents[incident.incident_id] = incident
            if incident.attack_chain_id:
                self.incident_index_by_chain[incident.attack_chain_id] = incident.incident_id
        for incident_id in set(self.incidents) - seen:
            self.incidents.pop(incident_id, None)

    @contextmanager
    def _incident_guard(self, incident_id: str):
        with self._connect_state_store() as lock_conn:
            _lock(lock_conn, "qc-ir-incident", incident_id)
            self._refresh_incident(incident_id)
            yield

    def list_incidents(self, limit: int = 100):
        with self._lock:
            self._refresh_all_incidents()
        return super().list_incidents(limit=limit)

    def get_incident_report(self, incident_id: str):
        with self._lock:
            self._refresh_incident(incident_id)
        return super().get_incident_report(incident_id)

    def list_evidence(self, incident_id: str):
        with self._lock:
            self._refresh_incident(incident_id)
        return super().list_evidence(incident_id)

    def get_evidence(self, incident_id: str, evidence_id: str):
        with self._lock:
            self._refresh_incident(incident_id)
        return super().get_evidence(incident_id, evidence_id)

    def add_evidence(self, *, incident_id: str, **kwargs):
        with self._incident_guard(incident_id):
            return super().add_evidence(incident_id=incident_id, **kwargs)

    def tombstone_evidence(self, *, incident_id: str, evidence_id: str, actor: str, reason: str = ""):
        with self._incident_guard(incident_id):
            return super().tombstone_evidence(
                incident_id=incident_id,
                evidence_id=evidence_id,
                actor=actor,
                reason=reason,
            )

    def update_incident(self, incident_id: str, *args, **kwargs):
        with self._incident_guard(incident_id):
            return super().update_incident(incident_id, *args, **kwargs)

    def approve_action(self, incident_id: str, action_id: str, approver: str) -> bool:
        with self._incident_guard(incident_id):
            return super().approve_action(incident_id, action_id, approver)

    def deny_action(self, incident_id: str, action_id: str, denier: str, *, reason: str | None = None) -> bool:
        with self._incident_guard(incident_id):
            return super().deny_action(incident_id, action_id, denier, reason=reason)

    def rollback_action(self, incident_id: str, action_id: str, actor: str, *, reason: str | None = None) -> bool:
        with self._incident_guard(incident_id):
            return super().rollback_action(incident_id, action_id, actor, reason=reason)

    def probe_health(self) -> Dict[str, Any]:
        with self._connect_state_store() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM qc_ir_incidents").fetchone()
        return {
            "healthy": True,
            "metrics": {
                "backend": "postgresql",
                "persisted_incidents": int(row["count"]) if row else 0,
                "active_incidents": self.metrics.get("active_incidents", 0),
            },
        }


class PostgresAutoRemediation(_SQLiteAutoRemediation):
    """Remediation-plan authority backed by PostgreSQL with single-plan claims."""

    def _connect_state_store(self):
        return get_db(self.db_path)

    def _init_state_store(self) -> None:
        with self._connect_state_store() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_remediation_plans (
                    plan_id TEXT PRIMARY KEY,
                    plan_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_remediation_action_log (
                    log_id BIGSERIAL PRIMARY KEY,
                    action_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

    def _load_persisted_state(self) -> None:
        with self._connect_state_store() as conn:
            rows = conn.execute("SELECT plan_json FROM qc_remediation_plans").fetchall()
            logs = conn.execute(
                "SELECT action_json FROM qc_remediation_action_log ORDER BY log_id ASC"
            ).fetchall()
        self.plans = {}
        for row in rows:
            plan = self._plan_from_dict(json.loads(row["plan_json"]))
            self.plans[plan.plan_id] = plan
        self.action_log = [json.loads(row["action_json"]) for row in logs]

    def _write_plan(self, conn, plan) -> None:
        conn.execute(
            """
            INSERT INTO qc_remediation_plans (plan_id, plan_json, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(plan_id) DO UPDATE SET
                plan_json=excluded.plan_json,
                updated_at=excluded.updated_at
            """,
            (
                plan.plan_id,
                json.dumps(plan.to_dict(), default=str),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    def _persist_plan(self, plan) -> None:
        with self._connect_state_store() as conn:
            self._write_plan(conn, plan)

    def _append_action_log(self, entry: Dict[str, Any]) -> None:
        with self._connect_state_store() as conn:
            conn.execute(
                """
                INSERT INTO qc_remediation_action_log (action_json, created_at)
                VALUES (?, ?)
                """,
                (
                    json.dumps(entry, default=str),
                    entry.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                ),
            )
        self.action_log.append(entry)

    def _load_plan(self, conn, plan_id: str):
        row = conn.execute(
            "SELECT plan_json FROM qc_remediation_plans WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        return self._plan_from_dict(json.loads(row["plan_json"])) if row else None

    def get_plan(self, plan_id: str):
        with self._connect_state_store() as conn:
            plan = self._load_plan(conn, plan_id)
        if plan is None:
            self.plans.pop(plan_id, None)
            return None
        self.plans[plan_id] = plan
        return plan.to_dict()

    def get_all_plans(self):
        with self._connect_state_store() as conn:
            rows = conn.execute("SELECT plan_json FROM qc_remediation_plans").fetchall()
        plans = [self._plan_from_dict(json.loads(row["plan_json"])) for row in rows]
        self.plans = {plan.plan_id: plan for plan in plans}
        return [plan.to_dict() for plan in plans]

    def execute_plan(self, plan_id: str, approved_by: str = "operator") -> Dict:
        if not self.allow_execute:
            return {"error": "Execution disabled. Set allow_execute=True in config."}

        with self._connect_state_store() as claim_conn:
            _lock(claim_conn, "qc-remediation-plan", plan_id)
            plan = self._load_plan(claim_conn, plan_id)
            if not plan:
                return {"error": f"Plan {plan_id} not found"}
            if plan.status == "executing":
                return {"error": f"Plan {plan_id} is already executing"}
            if plan.status in {"completed", "partial"}:
                self.plans[plan_id] = plan
                return plan.to_dict()
            plan.status = "executing"
            plan.executed_at = datetime.now(timezone.utc).isoformat()
            self._write_plan(claim_conn, plan)

        self.plans[plan_id] = plan
        for action in plan.actions:
            action.approved_by = approved_by
            result = self.execute_action(action, plan.target_host)
            if result["status"] == "completed":
                plan.completed_actions += 1
            else:
                plan.failed_actions += 1

        plan.status = "completed" if plan.failed_actions == 0 else "partial"
        self._persist_plan(plan)
        self.plans[plan_id] = plan
        return plan.to_dict()

    def approve_action(self, plan_id: str, action_id: str, approved_by: str = "operator") -> Dict:
        with self._connect_state_store() as conn:
            _lock(conn, "qc-remediation-plan", plan_id)
            plan = self._load_plan(conn, plan_id)
            if not plan:
                return {"error": "Plan not found"}
            for action in plan.actions:
                if action.action_id == action_id:
                    action.status = "approved"
                    action.approved_by = approved_by
                    self._write_plan(conn, plan)
                    self.plans[plan_id] = plan
                    return action.to_dict()
        return {"error": "Action not found"}

    def probe_health(self) -> Dict[str, Any]:
        with self._connect_state_store() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM qc_remediation_plans").fetchone()
        return {
            "healthy": True,
            "metrics": {
                "backend": "postgresql",
                "persisted_plans": int(row["count"]) if row else 0,
                "active_plans": len(self.plans),
            },
        }


class PostgresEvolutionEngine(_SQLiteEvolutionEngine):
    """Evolution authority backed by PostgreSQL with exactly-once scan learning."""

    def _connect_evolution(self):
        return get_db(self.db_path)

    def _init_db(self):
        with self._connect_evolution() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS health_log (
                    id BIGSERIAL PRIMARY KEY,
                    component_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT,
                    healed INTEGER DEFAULT 0,
                    timestamp TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS learned_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    learning_type TEXT NOT NULL,
                    source_engine TEXT NOT NULL,
                    pattern_json TEXT NOT NULL,
                    confidence DOUBLE PRECISION DEFAULT 0,
                    observations INTEGER DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    applied INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS evolutions (
                    evolution_id TEXT PRIMARY KEY,
                    evolution_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    source_patterns TEXT,
                    created_at TEXT NOT NULL,
                    applied INTEGER DEFAULT 0,
                    success INTEGER,
                    impact_score DOUBLE PRECISION DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS scan_intelligence (
                    id BIGSERIAL PRIMARY KEY,
                    host_ip TEXT NOT NULL,
                    port INTEGER,
                    service TEXT,
                    version TEXT,
                    finding_type TEXT,
                    severity TEXT,
                    scan_time TEXT NOT NULL,
                    remediated INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS false_positives (
                    id BIGSERIAL PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    finding_hash TEXT NOT NULL,
                    marked_by TEXT DEFAULT 'operator',
                    timestamp TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS network_baselines (
                    baseline_key TEXT PRIMARY KEY,
                    baseline_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS processed_scan_learning (
                    scan_id TEXT PRIMARY KEY,
                    learned_at TEXT NOT NULL,
                    source TEXT,
                    learning_json TEXT,
                    evolution_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_health_component ON health_log(component_id);
                CREATE INDEX IF NOT EXISTS idx_patterns_type ON learned_patterns(learning_type);
                CREATE INDEX IF NOT EXISTS idx_scan_intel_host ON scan_intelligence(host_ip);
                CREATE INDEX IF NOT EXISTS idx_evolutions_type ON evolutions(evolution_type);
                """
            )

    def _load_persisted_state(self):
        with self._connect_evolution() as conn:
            pattern_rows = conn.execute(
                """SELECT pattern_id, learning_type, source_engine, pattern_json,
                          confidence, observations, first_seen, last_seen, applied
                   FROM learned_patterns"""
            ).fetchall()
            baseline_rows = conn.execute(
                "SELECT baseline_key, baseline_json FROM network_baselines"
            ).fetchall()
            evo_rows = conn.execute(
                """SELECT evolution_id, evolution_type, description, payload_json,
                          source_patterns, created_at, applied, success, impact_score
                   FROM evolutions"""
            ).fetchall()
            fp_rows = conn.execute(
                "SELECT rule_id, COUNT(*) AS cnt FROM false_positives GROUP BY rule_id"
            ).fetchall()
            processed_rows = conn.execute(
                "SELECT scan_id FROM processed_scan_learning"
            ).fetchall()

        self._patterns = {}
        for row in pattern_rows:
            try:
                learning_type = LearningType(row["learning_type"])
            except Exception:
                continue
            self._patterns[row["pattern_id"]] = LearnedPattern(
                pattern_id=row["pattern_id"],
                learning_type=learning_type,
                source_engine=row["source_engine"],
                pattern_data=json.loads(row["pattern_json"] or "{}"),
                confidence=float(row["confidence"] or 0),
                observations=int(row["observations"] or 0),
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                applied=bool(row["applied"]),
            )

        self._network_baselines = {
            row["baseline_key"]: json.loads(row["baseline_json"] or "{}")
            for row in baseline_rows
        }
        self._evolutions = {}
        for row in evo_rows:
            try:
                evo_type = EvolutionType(row["evolution_type"])
            except Exception:
                continue
            self._evolutions[row["evolution_id"]] = EvolutionEvent(
                evolution_id=row["evolution_id"],
                evolution_type=evo_type,
                description=row["description"],
                payload=json.loads(row["payload_json"] or "{}"),
                source_patterns=json.loads(row["source_patterns"] or "[]"),
                created_at=row["created_at"],
                applied=bool(row["applied"]),
                success=row["success"],
                impact_score=float(row["impact_score"] or 0),
            )

        self._fp_tracker.clear()
        self._suppressed_rules.clear()
        for row in fp_rows:
            count = int(row["cnt"] or 0)
            self._fp_tracker[row["rule_id"]] = count
            if count >= FALSE_POSITIVE_THRESHOLD:
                self._suppressed_rules.add(row["rule_id"])
        self._processed_scan_ids = {row["scan_id"] for row in processed_rows if row["scan_id"]}
        self._auto_rules_generated = sum(
            1 for evo in self._evolutions.values()
            if evo.evolution_type == EvolutionType.DETECTION_RULE
        )
        self._scan_optimizations = sum(
            1 for evo in self._evolutions.values()
            if evo.evolution_type == EvolutionType.SCAN_PROFILE
        )
        self._remediation_improvements = sum(
            1 for evo in self._evolutions.values()
            if evo.evolution_type == EvolutionType.REMEDIATION_PLAYBOOK
        )

    def _log_health(self, health):
        with self._connect_evolution() as conn:
            conn.execute(
                "INSERT INTO health_log (component_id, status, error, timestamp) VALUES (?, ?, ?, ?)",
                (
                    health.component_id,
                    health.status.value,
                    health.last_error,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def _log_healing(self, component_id: str, action: str, detail: str):
        with self._connect_evolution() as conn:
            conn.execute(
                "INSERT INTO health_log (component_id, status, error, healed, timestamp) VALUES (?, ?, ?, 1, ?)",
                (
                    component_id,
                    "healing",
                    f"{action}: {detail}",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def learn_from_completed_scan(self, scan_report: Dict[str, Any], source: str = "scan_status") -> Dict[str, Any]:
        scan_id = str(scan_report.get("scan_id") or "").strip()
        if not scan_id:
            learning = self.learn_from_scan(scan_report) if scan_report.get("hosts") else self._learn_from_scan_summary(scan_report)
            evolution = self.evolve()
            return {
                "scan_id": None,
                "already_processed": False,
                "learning": learning,
                "evolution": evolution,
            }

        with self._connect_evolution() as claim_conn:
            _lock(claim_conn, "qc-evolution-scan", scan_id)
            existing = claim_conn.execute(
                "SELECT scan_id FROM processed_scan_learning WHERE scan_id=?",
                (scan_id,),
            ).fetchone()
            if existing:
                self._processed_scan_ids.add(scan_id)
                return {"scan_id": scan_id, "already_processed": True}

            learning = self.learn_from_scan(scan_report) if scan_report.get("hosts") else self._learn_from_scan_summary(scan_report)
            evolution = self.evolve()
            claim_conn.execute(
                """
                INSERT INTO processed_scan_learning
                    (scan_id, learned_at, source, learning_json, evolution_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    datetime.now(timezone.utc).isoformat(),
                    source,
                    json.dumps(learning, default=str),
                    json.dumps(evolution, default=str),
                ),
            )

        self._processed_scan_ids.add(scan_id)
        return {
            "scan_id": scan_id,
            "already_processed": False,
            "learning": learning,
            "evolution": evolution,
        }

    def _record_scan_intel(self, ip: str, finding: Dict[str, Any]):
        with self._connect_evolution() as conn:
            conn.execute(
                """INSERT INTO scan_intelligence
                   (host_ip, port, service, version, finding_type, severity, scan_time)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    ip,
                    finding.get("port"),
                    finding.get("service"),
                    finding.get("version"),
                    finding.get("category"),
                    finding.get("severity"),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def _persist_patterns(self):
        with self._connect_evolution() as conn:
            for pattern in self._patterns.values():
                conn.execute(
                    """
                    INSERT INTO learned_patterns
                        (pattern_id, learning_type, source_engine, pattern_json,
                         confidence, observations, first_seen, last_seen, applied)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(pattern_id) DO UPDATE SET
                        learning_type=excluded.learning_type,
                        source_engine=excluded.source_engine,
                        pattern_json=excluded.pattern_json,
                        confidence=excluded.confidence,
                        observations=excluded.observations,
                        first_seen=excluded.first_seen,
                        last_seen=excluded.last_seen,
                        applied=excluded.applied
                    """,
                    (
                        pattern.pattern_id,
                        pattern.learning_type.value,
                        pattern.source_engine,
                        json.dumps(pattern.pattern_data, default=str),
                        pattern.confidence,
                        pattern.observations,
                        pattern.first_seen,
                        pattern.last_seen,
                        int(pattern.applied),
                    ),
                )

    def _persist_baselines(self):
        now = datetime.now(timezone.utc).isoformat()
        with self._connect_evolution() as conn:
            for key, baseline in self._network_baselines.items():
                conn.execute(
                    """
                    INSERT INTO network_baselines (baseline_key, baseline_json, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(baseline_key) DO UPDATE SET
                        baseline_json=excluded.baseline_json,
                        updated_at=excluded.updated_at
                    """,
                    (key, json.dumps(baseline, default=str), now),
                )

    def mark_false_positive(self, rule_id: str, finding_hash: str, marked_by: str = "operator") -> Dict[str, Any]:
        with self._connect_evolution() as conn:
            conn.execute(
                "INSERT INTO false_positives (rule_id, finding_hash, marked_by, timestamp) VALUES (?, ?, ?, ?)",
                (rule_id, finding_hash, marked_by, datetime.now(timezone.utc).isoformat()),
            )
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM false_positives WHERE rule_id=?",
                (rule_id,),
            ).fetchone()
        count = int(row["cnt"] or 0) if row else 0
        self._fp_tracker[rule_id] = count
        suppressed = count >= FALSE_POSITIVE_THRESHOLD
        if suppressed:
            self._suppressed_rules.add(rule_id)
        return {
            "rule_id": rule_id,
            "total_fps": count,
            "suppressed": suppressed,
            "threshold": FALSE_POSITIVE_THRESHOLD,
        }

    def _persist_evolutions(self):
        with self._connect_evolution() as conn:
            for event in self._evolutions.values():
                conn.execute(
                    """
                    INSERT INTO evolutions
                        (evolution_id, evolution_type, description, payload_json,
                         source_patterns, created_at, applied, success, impact_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(evolution_id) DO UPDATE SET
                        evolution_type=excluded.evolution_type,
                        description=excluded.description,
                        payload_json=excluded.payload_json,
                        source_patterns=excluded.source_patterns,
                        created_at=excluded.created_at,
                        applied=excluded.applied,
                        success=excluded.success,
                        impact_score=excluded.impact_score
                    """,
                    (
                        event.evolution_id,
                        event.evolution_type.value,
                        event.description,
                        json.dumps(event.payload, default=str),
                        json.dumps(event.source_patterns),
                        event.created_at,
                        int(event.applied),
                        event.success,
                        event.impact_score,
                    ),
                )

    def get_storage_status(self) -> Dict[str, Any]:
        return {
            "backend": "postgresql",
            "db_path": None,
            "db_exists": True,
            "db_size_bytes": None,
            "backup_dir": None,
            "backup_dir_exists": False,
            "backup_count": 0,
            "persistent_db": True,
            "persistent_backups": False,
            "backup_strategy": "external-postgresql-backup-required",
        }

    def list_backups(self, limit: int = 20):
        return []

    def create_backup(self, label: Optional[str] = None):
        raise RuntimeError(
            "PostgreSQL is authoritative; use the external PostgreSQL backup/restore runbook. "
            "The backup_restore_tested topology gate remains false until that runbook is validated."
        )


class PostgresThreatIntelEngine(_SQLiteThreatIntelEngine):
    """Threat-intelligence authority backed by PostgreSQL."""

    def _connect(self):
        return get_db(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS threat_feeds (
                    feed_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    feed_format TEXT NOT NULL,
                    status TEXT NOT NULL,
                    update_interval_sec INTEGER NOT NULL,
                    last_sync DOUBLE PRECISION NOT NULL DEFAULT 0,
                    last_success DOUBLE PRECISION NOT NULL DEFAULT 0,
                    error_count INTEGER NOT NULL DEFAULT 0,
                    ioc_count INTEGER NOT NULL DEFAULT 0,
                    confidence_weight DOUBLE PRECISION NOT NULL DEFAULT 1.0,
                    tags_json TEXT NOT NULL,
                    auth_required INTEGER NOT NULL DEFAULT 0,
                    created_at DOUBLE PRECISION NOT NULL,
                    parser_config_json TEXT NOT NULL,
                    headers_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    indicator_id TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    confidence DOUBLE PRECISION NOT NULL,
                    severity TEXT NOT NULL,
                    sources_json TEXT NOT NULL,
                    first_seen DOUBLE PRECISION NOT NULL,
                    last_seen DOUBLE PRECISION NOT NULL,
                    last_updated DOUBLE PRECISION NOT NULL,
                    expires_at DOUBLE PRECISION NOT NULL DEFAULT 0,
                    tags_json TEXT NOT NULL,
                    mitre_techniques_json TEXT NOT NULL,
                    threat_actor TEXT,
                    campaign TEXT,
                    context_json TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    decay_rate DOUBLE PRECISION NOT NULL DEFAULT 0.01
                );
                CREATE TABLE IF NOT EXISTS threat_cves (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0,
                    severity TEXT NOT NULL,
                    affected_products_json TEXT NOT NULL,
                    exploit_available INTEGER NOT NULL DEFAULT 0,
                    in_the_wild INTEGER NOT NULL DEFAULT 0,
                    patch_available INTEGER NOT NULL DEFAULT 0,
                    first_published DOUBLE PRECISION NOT NULL,
                    last_modified DOUBLE PRECISION NOT NULL,
                    references_json TEXT NOT NULL,
                    mitre_techniques_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS threat_actors (
                    actor_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    aliases_json TEXT NOT NULL,
                    nation_state TEXT,
                    motivation TEXT,
                    sophistication TEXT,
                    target_industries_json TEXT NOT NULL,
                    target_regions_json TEXT NOT NULL,
                    known_techniques_json TEXT NOT NULL,
                    known_tools_json TEXT NOT NULL,
                    campaigns_json TEXT NOT NULL,
                    ioc_count INTEGER NOT NULL DEFAULT 0,
                    last_activity DOUBLE PRECISION NOT NULL DEFAULT 0,
                    confidence DOUBLE PRECISION NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS threat_sync_log (
                    id BIGSERIAL PRIMARY KEY,
                    feed_id TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    iocs_ingested INTEGER NOT NULL DEFAULT 0,
                    cves_ingested INTEGER NOT NULL DEFAULT 0,
                    actors_ingested INTEGER NOT NULL DEFAULT 0,
                    detail_json TEXT,
                    timestamp DOUBLE PRECISION NOT NULL
                );
                CREATE TABLE IF NOT EXISTS threat_scheduler_lease (
                    lease_name TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    acquired_at DOUBLE PRECISION NOT NULL,
                    expires_at DOUBLE PRECISION NOT NULL
                );
                """
            )

    def _write_feed(self, conn, feed: ThreatFeed) -> None:
        conn.execute(
            """
            INSERT INTO threat_feeds
                (feed_id, name, source_url, feed_format, status, update_interval_sec, last_sync,
                 last_success, error_count, ioc_count, confidence_weight, tags_json, auth_required,
                 created_at, parser_config_json, headers_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(feed_id) DO UPDATE SET
                name=excluded.name,
                source_url=excluded.source_url,
                feed_format=excluded.feed_format,
                status=excluded.status,
                update_interval_sec=excluded.update_interval_sec,
                last_sync=excluded.last_sync,
                last_success=excluded.last_success,
                error_count=excluded.error_count,
                ioc_count=excluded.ioc_count,
                confidence_weight=excluded.confidence_weight,
                tags_json=excluded.tags_json,
                auth_required=excluded.auth_required,
                parser_config_json=excluded.parser_config_json,
                headers_json=excluded.headers_json
            """,
            (
                feed.feed_id,
                feed.name,
                feed.source_url,
                feed.feed_format.value,
                feed.status.value,
                int(feed.update_interval_sec),
                float(feed.last_sync),
                float(feed.last_success),
                int(feed.error_count),
                int(feed.ioc_count),
                float(feed.confidence_weight),
                json.dumps(feed.tags, ensure_ascii=False, sort_keys=True, default=str),
                int(feed.auth_required),
                float(feed.created_at),
                json.dumps(feed.parser_config, ensure_ascii=False, sort_keys=True, default=str),
                json.dumps(feed.headers, ensure_ascii=False, sort_keys=True, default=str),
            ),
        )

    def _persist_feed(self, feed: ThreatFeed) -> None:
        with self._connect() as conn:
            self._write_feed(conn, feed)

    def _write_indicator(self, conn, indicator: ThreatIndicator) -> None:
        conn.execute(
            """
            INSERT INTO threat_indicators
                (indicator_id, value, indicator_type, confidence, severity, sources_json, first_seen,
                 last_seen, last_updated, expires_at, tags_json, mitre_techniques_json, threat_actor,
                 campaign, context_json, active, decay_rate)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator_id) DO UPDATE SET
                value=excluded.value,
                indicator_type=excluded.indicator_type,
                confidence=excluded.confidence,
                severity=excluded.severity,
                sources_json=excluded.sources_json,
                first_seen=excluded.first_seen,
                last_seen=excluded.last_seen,
                last_updated=excluded.last_updated,
                expires_at=excluded.expires_at,
                tags_json=excluded.tags_json,
                mitre_techniques_json=excluded.mitre_techniques_json,
                threat_actor=excluded.threat_actor,
                campaign=excluded.campaign,
                context_json=excluded.context_json,
                active=excluded.active,
                decay_rate=excluded.decay_rate
            """,
            (
                indicator.indicator_id,
                indicator.value,
                indicator.indicator_type,
                float(indicator.confidence),
                indicator.severity,
                json.dumps(indicator.sources, ensure_ascii=False, sort_keys=True, default=str),
                float(indicator.first_seen),
                float(indicator.last_seen),
                float(indicator.last_updated),
                float(indicator.expires_at or 0),
                json.dumps(indicator.tags, ensure_ascii=False, sort_keys=True, default=str),
                json.dumps(indicator.mitre_techniques, ensure_ascii=False, sort_keys=True, default=str),
                indicator.threat_actor,
                indicator.campaign,
                json.dumps(indicator.context, ensure_ascii=False, sort_keys=True, default=str),
                int(indicator.active),
                float(indicator.decay_rate),
            ),
        )

    def _persist_indicator(self, indicator: ThreatIndicator) -> None:
        with self._connect() as conn:
            self._write_indicator(conn, indicator)

    @staticmethod
    def _indicator_from_row(row) -> ThreatIndicator:
        return ThreatIndicator(
            indicator_id=row["indicator_id"],
            value=row["value"],
            indicator_type=row["indicator_type"],
            confidence=float(row["confidence"]),
            severity=row["severity"],
            sources=json.loads(row["sources_json"] or "[]"),
            first_seen=float(row["first_seen"]),
            last_seen=float(row["last_seen"]),
            last_updated=float(row["last_updated"]),
            expires_at=float(row["expires_at"]),
            tags=json.loads(row["tags_json"] or "[]"),
            mitre_techniques=json.loads(row["mitre_techniques_json"] or "[]"),
            threat_actor=row["threat_actor"] or "",
            campaign=row["campaign"] or "",
            context=json.loads(row["context_json"] or "{}"),
            active=bool(row["active"]),
            decay_rate=float(row["decay_rate"]),
        )

    def ingest_indicator(self, indicator: ThreatIndicator) -> str:
        with self._lock:
            with self._connect() as conn:
                _lock(conn, "qc-threat-indicator", indicator.indicator_id)
                row = conn.execute(
                    "SELECT * FROM threat_indicators WHERE indicator_id=? FOR UPDATE",
                    (indicator.indicator_id,),
                ).fetchone()
                if row:
                    existing = self._indicator_from_row(row)
                    existing.confidence = max(existing.confidence, indicator.confidence)
                    existing.last_seen = max(existing.last_seen, indicator.last_seen)
                    existing.last_updated = max(existing.last_updated, indicator.last_updated)
                    existing.active = True
                    existing.expires_at = max(existing.expires_at, indicator.expires_at)
                    existing.severity = indicator.severity or existing.severity
                    existing.threat_actor = indicator.threat_actor or existing.threat_actor
                    existing.campaign = indicator.campaign or existing.campaign
                    for source in indicator.sources:
                        if source not in existing.sources:
                            existing.sources.append(source)
                    for tag in indicator.tags:
                        if tag not in existing.tags:
                            existing.tags.append(tag)
                    for technique in indicator.mitre_techniques:
                        if technique not in existing.mitre_techniques:
                            existing.mitre_techniques.append(technique)
                    if indicator.context:
                        existing.context.update(indicator.context)
                    self._write_indicator(conn, existing)
                    self._indicators[existing.indicator_id] = existing
                    return existing.indicator_id

                self._write_indicator(conn, indicator)
                self._indicators[indicator.indicator_id] = indicator
                return indicator.indicator_id

    def _persist_cve(self, cve: CVERecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO threat_cves
                    (cve_id, description, cvss_score, severity, affected_products_json, exploit_available,
                     in_the_wild, patch_available, first_published, last_modified, references_json,
                     mitre_techniques_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    description=excluded.description,
                    cvss_score=excluded.cvss_score,
                    severity=excluded.severity,
                    affected_products_json=excluded.affected_products_json,
                    exploit_available=excluded.exploit_available,
                    in_the_wild=excluded.in_the_wild,
                    patch_available=excluded.patch_available,
                    first_published=excluded.first_published,
                    last_modified=excluded.last_modified,
                    references_json=excluded.references_json,
                    mitre_techniques_json=excluded.mitre_techniques_json
                """,
                (
                    cve.cve_id,
                    cve.description,
                    float(cve.cvss_score),
                    cve.severity,
                    json.dumps(cve.affected_products, ensure_ascii=False, sort_keys=True, default=str),
                    int(cve.exploit_available),
                    int(cve.in_the_wild),
                    int(cve.patch_available),
                    float(cve.first_published),
                    float(cve.last_modified),
                    json.dumps(cve.references, ensure_ascii=False, sort_keys=True, default=str),
                    json.dumps(cve.mitre_techniques, ensure_ascii=False, sort_keys=True, default=str),
                ),
            )

    def _persist_actor(self, actor: ThreatActorProfile) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO threat_actors
                    (actor_id, name, aliases_json, nation_state, motivation, sophistication,
                     target_industries_json, target_regions_json, known_techniques_json, known_tools_json,
                     campaigns_json, ioc_count, last_activity, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(actor_id) DO UPDATE SET
                    name=excluded.name,
                    aliases_json=excluded.aliases_json,
                    nation_state=excluded.nation_state,
                    motivation=excluded.motivation,
                    sophistication=excluded.sophistication,
                    target_industries_json=excluded.target_industries_json,
                    target_regions_json=excluded.target_regions_json,
                    known_techniques_json=excluded.known_techniques_json,
                    known_tools_json=excluded.known_tools_json,
                    campaigns_json=excluded.campaigns_json,
                    ioc_count=excluded.ioc_count,
                    last_activity=excluded.last_activity,
                    confidence=excluded.confidence
                """,
                (
                    actor.actor_id,
                    actor.name,
                    json.dumps(actor.aliases, ensure_ascii=False, sort_keys=True, default=str),
                    actor.nation_state,
                    actor.motivation,
                    actor.sophistication,
                    json.dumps(actor.target_industries, ensure_ascii=False, sort_keys=True, default=str),
                    json.dumps(actor.target_regions, ensure_ascii=False, sort_keys=True, default=str),
                    json.dumps(actor.known_techniques, ensure_ascii=False, sort_keys=True, default=str),
                    json.dumps(actor.known_tools, ensure_ascii=False, sort_keys=True, default=str),
                    json.dumps(actor.campaigns, ensure_ascii=False, sort_keys=True, default=str),
                    int(actor.ioc_count),
                    float(actor.last_activity),
                    float(actor.confidence),
                ),
            )

    def _acquire_scheduler_lease(self) -> bool:
        now = __import__("time").time()
        expires_at = now + self._lease_ttl_seconds
        with self._connect() as conn:
            _lock(conn, "qc-threat-scheduler", self.LEASE_NAME)
            row = conn.execute(
                "SELECT owner_id, expires_at FROM threat_scheduler_lease WHERE lease_name=? FOR UPDATE",
                (self.LEASE_NAME,),
            ).fetchone()
            if row and row["owner_id"] != self._owner_id and float(row["expires_at"]) > now:
                return False
            conn.execute(
                """
                INSERT INTO threat_scheduler_lease (lease_name, owner_id, acquired_at, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(lease_name) DO UPDATE SET
                    owner_id=excluded.owner_id,
                    acquired_at=excluded.acquired_at,
                    expires_at=excluded.expires_at
                """,
                (self.LEASE_NAME, self._owner_id, now, expires_at),
            )
        return True

    def probe_health(self) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM threat_feeds").fetchone()
        return {
            "healthy": True,
            "metrics": {
                "backend": "postgresql",
                "feeds_registered": int(row["count"]) if row else 0,
                "scheduler_running": bool(self._scheduler_thread and self._scheduler_thread.is_alive()),
            },
        }


def build_incident_response_orchestrator(config: Optional[Dict[str, Any]] = None):
    if database_backend() == "postgresql":
        return PostgresIncidentResponseOrchestrator(config=config or {})
    return _SQLiteIncidentResponseOrchestrator(config=config or {})


def build_auto_remediation(config: Optional[Dict[str, Any]] = None):
    if database_backend() == "postgresql":
        return PostgresAutoRemediation(config=config or {})
    return _SQLiteAutoRemediation(config=config or {})


def build_evolution_engine(config: Optional[Dict[str, Any]] = None):
    if database_backend() == "postgresql":
        return PostgresEvolutionEngine(config=config or {})
    return _SQLiteEvolutionEngine(config=config or {})


def build_threat_intel_engine(*args, **kwargs):
    if database_backend() == "postgresql":
        return PostgresThreatIntelEngine(*args, **kwargs)
    return _SQLiteThreatIntelEngine(*args, **kwargs)
