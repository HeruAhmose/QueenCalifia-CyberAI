import hashlib

from core.tamerian_mesh import TamerianCircuit, TamerianSecurityMesh
from engines.auto_remediation import AutoRemediation
from engines.evolution_engine import EvolutionEngine, HealthStatus
from engines.incident_response import (
    IncidentCategory,
    IncidentResponseOrchestrator,
    IncidentSeverity,
)
from engines.vulnerability_engine import Asset, AssetType, ComplianceFramework, VulnerabilityEngine
from sovereignty.approvals import SQLiteApprovalStore
from sovereignty.audit_chain import SQLiteAuditChain
from sovereignty.schemas import ApprovalSignature, SignatureAlg


def test_incident_response_state_persists(tmp_path):
    db_path = tmp_path / "queen.db"
    orchestrator = IncidentResponseOrchestrator({"db_path": str(db_path)})
    incident = orchestrator.create_incident(
        title="Unauthorized access",
        description="Credential abuse detected",
        severity=IncidentSeverity.HIGH,
        category=IncidentCategory.UNAUTHORIZED_ACCESS,
        indicators=["10.10.10.9"],
        affected_assets={"srv-1"},
        auto_respond=True,
    )

    restored = IncidentResponseOrchestrator({"db_path": str(db_path)})
    report = restored.get_incident_report(incident.incident_id)

    assert report is not None
    assert "10.10.10.9" in restored.blocked_ips
    assert report["incident_id"] == incident.incident_id
    assert len(report["response_actions"]) >= 1


def test_auto_remediation_state_persists(tmp_path):
    db_path = tmp_path / "queen.db"
    remediation = AutoRemediation({"db_path": str(db_path), "allow_execute": True})
    plan = remediation.generate_plan(
        [{"finding_id": "f-1", "title": "Unknown issue", "category": "custom"}],
        target_host="localhost",
    )
    result = remediation.execute_plan(plan.plan_id, approved_by="tester")

    restored = AutoRemediation({"db_path": str(db_path), "allow_execute": True})
    loaded = restored.get_plan(plan.plan_id)

    assert result["plan_id"] == plan.plan_id
    assert loaded is not None
    assert loaded["plan_id"] == plan.plan_id
    assert len(restored.get_action_log()) >= 1


def test_sqlite_approval_store_persists_records(tmp_path):
    db_path = tmp_path / "queen.db"
    store = SQLiteApprovalStore(str(db_path))
    rec = store.create(tenant_id="t1", decision_hash="a" * 64, requested_by="alice")
    sig = ApprovalSignature(
        approver_id="bob",
        key_id="bob-key",
        alg=SignatureAlg.ed25519,
        signature_b64="A" * 88,
    )
    store.add_signature(rec.approval_id, sig)
    store.mark_nonce_used(rec.nonce)

    restored = SQLiteApprovalStore(str(db_path))
    loaded = restored.get(rec.approval_id)

    assert loaded is not None
    assert len(loaded.signatures) == 1
    assert not restored.mark_nonce_used(rec.nonce)


def test_sqlite_audit_chain_persists_entries(tmp_path):
    db_path = tmp_path / "queen.db"
    chain = SQLiteAuditChain(str(db_path))
    chain.append({"event": "first"})
    chain.append({"event": "second"})

    restored = SQLiteAuditChain(str(db_path))
    valid, bad_idx = restored.verify()

    assert restored.length == 2
    assert valid and bad_idx is None
    assert restored.export_chain()[-1]["record"]["event"] == "second"


def test_compliance_checks_use_real_evidence(tmp_path):
    engine = VulnerabilityEngine(
        {
            "db_path": str(tmp_path / "queen.db"),
            "compliance_evidence": {
                "default": {
                    "password_max_age": 90,
                    "password_min_length": 16,
                    "firewall_enabled": True,
                    "audit_logging_enabled": True,
                    "encryption_at_rest": True,
                    "account_management_policy": True,
                    "audit_events_defined": True,
                    "mfa_enabled": True,
                }
            },
        }
    )
    asset = Asset(asset_id="asset-1", ip_address="10.0.0.5", asset_type=AssetType.SERVER)
    asset.services[443] = {"service": "https", "version": "tls1.3"}

    findings = engine._check_compliance(
        asset,
        [ComplianceFramework.CIS.value, ComplianceFramework.NIST_800_53.value],
    )

    assert findings == []
    assert all(status == "passed" for status in asset.compliance_status.values())


def test_webapp_scan_populates_remediation_inventory(tmp_path):
    engine = VulnerabilityEngine({"db_path": str(tmp_path / "vuln_web.db")})
    r = engine.scan_web_application("https://example.com")
    assert r.get("findings")
    plan = engine.generate_remediation_plan()
    assert int(plan.get("total_vulnerabilities") or 0) >= 1
    assert len(plan.get("priority_actions") or []) >= 1


def test_missing_compliance_evidence_is_honest(tmp_path):
    engine = VulnerabilityEngine({"db_path": str(tmp_path / "queen.db")})
    asset = Asset(asset_id="asset-2", ip_address="10.0.0.6", asset_type=AssetType.SERVER)
    asset.open_ports = [22]

    findings = engine._check_compliance(asset, [ComplianceFramework.CIS.value])

    assert findings
    assert any(f["status"] == "evidence_missing" for f in findings)
    assert "requires_review" not in {f["status"] for f in findings}


def test_evolution_healing_requires_probe_verification(tmp_path):
    engine = EvolutionEngine({"db_path": str(tmp_path / "evo.db")})
    health = engine.register_component("db", "database")
    health.status = HealthStatus.CRITICAL
    engine.register_component_recovery("db", lambda cid: {"healed": True, "strategy": "restart"})

    engine._attempt_heal("db", health)
    assert health.auto_healed == 0

    engine.register_component_probe("db", lambda: {"healthy": True, "metrics": {"latency_ms": 2}})
    engine._attempt_heal("db", health)

    assert health.auto_healed == 1
    assert health.status == HealthStatus.RECOVERING


def test_runtime_reload_helpers_restore_state(tmp_path):
    db_path = tmp_path / "queen.db"

    ir = IncidentResponseOrchestrator({"db_path": str(db_path)})
    incident = ir.create_incident(
        title="Reload test",
        description="IR state reload",
        severity=IncidentSeverity.MEDIUM,
        category=IncidentCategory.PHISHING,
        indicators=["bad.example"],
        auto_respond=True,
    )
    ir.incidents = {}
    ir.reload_persisted_state()
    assert incident.incident_id in ir.incidents

    remediation = AutoRemediation({"db_path": str(db_path), "allow_execute": True})
    plan = remediation.generate_plan(
        [{"finding_id": "f-2", "title": "Manual issue", "category": "custom"}],
        target_host="localhost",
    )
    remediation.plans = {}
    remediation.reload_persisted_state()
    assert plan.plan_id in remediation.plans


def test_mesh_circuit_healing_requires_real_recovery_check():
    mesh = TamerianSecurityMesh({"detection_threads": 1})
    try:
        circuit = TamerianCircuit(circuit_id="test-circuit", pipeline_type="test", is_healthy=False, integrity_hash="bad")
        mesh.circuits[circuit.circuit_id] = circuit

        mesh._heal_circuit(circuit.circuit_id)
        assert not circuit.is_healthy

        expected_hash = hashlib.sha256(circuit.circuit_id.encode()).hexdigest()[:16]
        mesh.register_circuit_recovery_check(
            circuit.circuit_id,
            lambda cid: {"healthy": True, "integrity_hash": expected_hash},
        )
        mesh._heal_circuit(circuit.circuit_id)

        assert circuit.is_healthy
    finally:
        mesh.shutdown()
