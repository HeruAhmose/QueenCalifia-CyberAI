from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from engines.incident_response import IncidentCategory, IncidentSeverity
from engines.runtime_state import (
    PostgresAutoRemediation,
    PostgresEvolutionEngine,
    PostgresIncidentResponseOrchestrator,
    PostgresThreatIntelEngine,
    build_auto_remediation,
    build_evolution_engine,
    build_incident_response_orchestrator,
    build_threat_intel_engine,
)
from engines.threat_intel_auto import ThreatIndicator


@pytest.fixture()
def postgres_url(monkeypatch):
    url = os.environ["QC_TEST_POSTGRES_URL"]
    monkeypatch.setenv("QC_DATABASE_URL", url)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    tables = [
        "qc_ir_runtime_state",
        "qc_ir_incidents",
        "qc_remediation_action_log",
        "qc_remediation_plans",
        "processed_scan_learning",
        "network_baselines",
        "false_positives",
        "scan_intelligence",
        "evolutions",
        "learned_patterns",
        "health_log",
        "threat_scheduler_lease",
        "threat_sync_log",
        "threat_actors",
        "threat_cves",
        "threat_indicators",
        "threat_feeds",
    ]
    with psycopg.connect(url) as conn:
        for table in tables:
            conn.execute(f'DROP TABLE IF EXISTS "{table}" CASCADE')
    yield url


def test_factories_select_postgresql_contract(postgres_url):
    incident = build_incident_response_orchestrator({})
    remediation = build_auto_remediation({"allow_execute": False})
    evolution = build_evolution_engine({})
    threat = build_threat_intel_engine(auto_start=False, load_default_feeds=False)
    try:
        assert isinstance(incident, PostgresIncidentResponseOrchestrator)
        assert isinstance(remediation, PostgresAutoRemediation)
        assert isinstance(evolution, PostgresEvolutionEngine)
        assert isinstance(threat, PostgresThreatIntelEngine)
        assert incident.probe_health()["metrics"]["backend"] == "postgresql"
        assert remediation.probe_health()["metrics"]["backend"] == "postgresql"
        assert threat.probe_health()["metrics"]["backend"] == "postgresql"
    finally:
        threat.stop_scheduler()


def test_incident_evidence_updates_serialize_across_replicas(postgres_url):
    left = PostgresIncidentResponseOrchestrator({})
    right = PostgresIncidentResponseOrchestrator({})
    incident = left.create_incident(
        title="replica-race",
        description="concurrent evidence",
        severity=IncidentSeverity.HIGH,
        category=IncidentCategory.UNAUTHORIZED_ACCESS,
        auto_respond=False,
    )
    barrier = threading.Barrier(2)

    def add(store, suffix):
        barrier.wait()
        return store.add_evidence(
            incident_id=incident.incident_id,
            evidence_type="log",
            source=f"sensor-{suffix}",
            storage_location=f"worm://evidence/{suffix}",
            hash_sha256=(suffix * 64)[:64],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda args: add(*args), [(left, "a"), (right, "b")]))

    fresh = PostgresIncidentResponseOrchestrator({})
    evidence = fresh.list_evidence(incident.incident_id)
    assert len(evidence) == 2
    assert {item["source"] for item in evidence} == {"sensor-a", "sensor-b"}


def test_remediation_plan_executes_at_most_once_across_replicas(postgres_url):
    left = PostgresAutoRemediation({"allow_execute": True})
    plan = left.generate_plan(
        [{"finding_id": "f-race", "title": "Manual review", "category": "custom"}],
        target_host="localhost",
    )
    right = PostgresAutoRemediation({"allow_execute": True})
    barrier = threading.Barrier(2)

    def execute(store):
        barrier.wait()
        return store.execute_plan(plan.plan_id, approved_by="replica-test")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(execute, [left, right]))

    with psycopg.connect(postgres_url) as conn:
        count = conn.execute("SELECT COUNT(*) FROM qc_remediation_action_log").fetchone()[0]
    assert count == 1
    assert any(result.get("status") == "completed" for result in results)


def test_completed_scan_learning_is_exactly_once_across_replicas(postgres_url):
    left = PostgresEvolutionEngine({})
    right = PostgresEvolutionEngine({})
    barrier = threading.Barrier(2)
    report = {
        "scan_id": "scan-replica-race",
        "target": "10.20.30.40",
        "scan_type": "quick",
        "risk_score": 2.0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 1,
        "low_count": 1,
        "assets_discovered": 1,
    }

    def learn(store):
        barrier.wait()
        return store.learn_from_completed_scan(report)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(learn, [left, right]))

    assert sorted(result["already_processed"] for result in results) == [False, True]
    with psycopg.connect(postgres_url) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM processed_scan_learning WHERE scan_id=%s",
            (report["scan_id"],),
        ).fetchone()[0]
    assert count == 1


def test_threat_scheduler_lease_has_one_owner(postgres_url):
    left = PostgresThreatIntelEngine(auto_start=False, load_default_feeds=False)
    right = PostgresThreatIntelEngine(auto_start=False, load_default_feeds=False)
    barrier = threading.Barrier(2)

    def acquire(store):
        barrier.wait()
        return store._acquire_scheduler_lease()

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(acquire, [left, right]))
        assert sorted(results) == [False, True]
    finally:
        left.stop_scheduler()
        right.stop_scheduler()


def test_threat_indicator_merge_preserves_replica_contributions(postgres_url):
    left = PostgresThreatIntelEngine(auto_start=False, load_default_feeds=False)
    right = PostgresThreatIntelEngine(auto_start=False, load_default_feeds=False)
    barrier = threading.Barrier(2)

    def ingest(store, source, tag, context, confidence):
        barrier.wait()
        return store.ingest_indicator(
            ThreatIndicator(
                indicator_id="shared-indicator",
                value="198.51.100.25",
                indicator_type="ip",
                confidence=confidence,
                sources=[source],
                tags=[tag],
                context={context: True},
            )
        )

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(
                pool.map(
                    lambda args: ingest(*args),
                    [
                        (left, "feed-a", "tag-a", "a", 0.7),
                        (right, "feed-b", "tag-b", "b", 0.9),
                    ],
                )
            )
        fresh = PostgresThreatIntelEngine(auto_start=False, load_default_feeds=False)
        try:
            indicator = fresh._indicators["shared-indicator"]
            assert set(indicator.sources) == {"feed-a", "feed-b"}
            assert set(indicator.tags) == {"tag-a", "tag-b"}
            assert indicator.context == {"a": True, "b": True}
            assert indicator.confidence == pytest.approx(0.9)
        finally:
            fresh.stop_scheduler()
    finally:
        left.stop_scheduler()
        right.stop_scheduler()
