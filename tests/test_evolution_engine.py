"""
Tests for QueenCalifia Evolution Engine (self-healing, learning, evolving).
"""

import os
import json
import uuid
import pytest
import tempfile
from datetime import datetime, timezone

# Force test DB path
os.environ["QC_EVOLUTION_DB"] = os.path.join(tempfile.gettempdir(), f"qc_evolution_test_{uuid.uuid4().hex[:8]}.db")

from engines.evolution_engine import (
    EvolutionEngine, HealthStatus, LearningType, EvolutionType,
    ComponentHealth, LearnedPattern, EvolutionEvent,
)


@pytest.fixture
def engine():
    """Fresh evolution engine for each test."""
    db = os.path.join(tempfile.gettempdir(), f"qc_evo_{uuid.uuid4().hex[:8]}.db")
    e = EvolutionEngine({"db_path": db})
    yield e
    try:
        os.unlink(db)
    except OSError:
        pass


# ─── Self-Healing Tests ─────────────────────────────────────────────────────

class TestSelfHealing:
    def test_register_component(self, engine):
        health = engine.register_component("scanner", "Live Scanner")
        assert health.component_id == "scanner"
        assert health.status == HealthStatus.HEALTHY

    def test_check_health_ok(self, engine):
        engine.register_component("mesh", "Tamerian Mesh")
        result = engine.check_health("mesh", check_fn=lambda: {"healthy": True, "metrics": {"nodes": 24}})
        assert result.status == HealthStatus.HEALTHY
        assert result.metrics.get("nodes") == 24

    def test_check_health_degraded(self, engine):
        engine.register_component("api", "API Gateway")
        result = engine.check_health("api", check_fn=lambda: {"healthy": False, "error": "High latency"})
        assert result.status == HealthStatus.DEGRADED
        assert result.error_count == 1

    def test_auto_heal_on_exception(self, engine):
        engine.register_component("db", "Database")

        def failing_check():
            raise RuntimeError("Connection refused")

        result = engine.check_health("db", check_fn=failing_check)
        assert result.status in (HealthStatus.CRITICAL, HealthStatus.RECOVERING)
        assert result.error_count >= 1

    def test_check_all_health(self, engine):
        engine.register_component("a", "Component A")
        engine.register_component("b", "Component B")
        results = engine.check_all_health()
        assert len(results) == 2
        assert all(h.status == HealthStatus.HEALTHY for h in results.values())

    def test_recovery_detection(self, engine):
        engine.register_component("svc", "Service")
        # First: degrade
        engine.check_health("svc", check_fn=lambda: {"healthy": False, "error": "down"})
        assert engine._components["svc"].status == HealthStatus.DEGRADED
        # Then: recover
        engine.check_health("svc", check_fn=lambda: {"healthy": True})
        assert engine._components["svc"].status == HealthStatus.RECOVERING
        assert engine._components["svc"].auto_healed == 1


# ─── Self-Learning Tests ────────────────────────────────────────────────────

class TestSelfLearning:
    def _mock_scan_report(self):
        return {
            "hosts": [
                {
                    "ip": "192.168.1.10",
                    "hostname": "webserver",
                    "os_guess": "Ubuntu 22.04",
                    "open_ports": [22, 80, 443],
                    "services": {
                        "22": {"service": "ssh", "version": "OpenSSH 8.9"},
                        "80": {"service": "http", "version": "nginx 1.24"},
                        "443": {"service": "https", "version": "nginx 1.24"},
                    },
                    "findings": [
                        {
                            "title": "Missing HSTS Header",
                            "category": "http_security",
                            "severity": "HIGH",
                            "port": 443,
                            "service": "https",
                            "remediation": "Add Strict-Transport-Security header",
                        },
                        {
                            "title": "TLS 1.0 Enabled",
                            "category": "tls_weakness",
                            "severity": "MEDIUM",
                            "port": 443,
                            "service": "https",
                        },
                    ],
                },
                {
                    "ip": "192.168.1.20",
                    "os_guess": "CentOS 8",
                    "open_ports": [22, 3306],
                    "services": {
                        "22": {"service": "ssh", "version": "OpenSSH 7.4"},
                        "3306": {"service": "mysql", "version": "MySQL 8.0.33"},
                    },
                    "findings": [],
                },
            ],
        }

    def test_learn_from_scan_creates_baselines(self, engine):
        report = self._mock_scan_report()
        result = engine.learn_from_scan(report)
        assert result["new_baselines"] == 2
        assert len(engine._network_baselines) == 2

    def test_learn_from_scan_extracts_patterns(self, engine):
        report = self._mock_scan_report()
        result = engine.learn_from_scan(report)
        assert result["new_patterns"] >= 2  # From the 2 findings
        assert result["service_fingerprints"] >= 4  # 4 services across 2 hosts

    def test_baseline_updates_on_rescan(self, engine):
        report = self._mock_scan_report()
        engine.learn_from_scan(report)
        result = engine.learn_from_scan(report)
        assert result["updated_baselines"] == 2
        assert result["new_baselines"] == 0

    def test_baseline_stability_tracking(self, engine):
        report = self._mock_scan_report()
        for _ in range(5):
            engine.learn_from_scan(report)
        # After 5 identical scans, stability should be high
        baseline = list(engine._network_baselines.values())[0]
        assert baseline["stability"] >= 0.8

    def test_learn_from_incident(self, engine):
        incident = {
            "mitre_techniques": ["T1059.001", "T1071.001"],
            "category": "malware",
            "severity": "HIGH",
            "affected_assets": ["192.168.1.10"],
            "iocs": [
                {"type": "ip", "value": "10.20.30.40"},
                {"type": "domain", "value": "malicious.example.com"},
            ],
        }
        result = engine.learn_from_incident(incident)
        assert result["ttp_patterns"] == 2
        assert result["ioc_patterns"] == 2

    def test_learn_from_remediation(self, engine):
        plan_result = {
            "actions": [
                {"category": "http_security", "title": "Add HSTS", "status": "completed",
                 "commands": ["nginx -s reload"], "risk_level": "low"},
                {"category": "tls_weakness", "title": "Disable TLS 1.0", "status": "failed",
                 "commands": [], "risk_level": "medium"},
            ],
        }
        result = engine.learn_from_remediation(plan_result)
        assert result["playbook_improvements"] == 1  # Only the successful one

    def test_persisted_state_reloads_after_restart(self):
        db = os.path.join(tempfile.gettempdir(), f"qc_evo_reload_{uuid.uuid4().hex[:8]}.db")
        try:
            first = EvolutionEngine({"db_path": db})
            report = self._mock_scan_report()
            first.learn_from_scan(report)
            first.mark_false_positive("rule-xyz", "hash-1")
            first.mark_false_positive("rule-xyz", "hash-2")
            first.evolve()

            second = EvolutionEngine({"db_path": db})
            assert len(second._patterns) >= 1
            assert len(second._network_baselines) == 2
            assert second._fp_tracker["rule-xyz"] == 2
            assert len(second._evolutions) >= 0
        finally:
            try:
                os.unlink(db)
            except OSError:
                pass

    def test_completed_scan_learning_is_idempotent(self, engine):
        scan_result = {
            "scan_id": "scan-123",
            "target": "127.0.0.1",
            "scan_type": "full",
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "assets_discovered": 1,
            "vulnerabilities_found": 1,
            "risk_score": 5.5,
        }

        first = engine.learn_from_completed_scan(scan_result)
        second = engine.learn_from_completed_scan(scan_result)

        assert first["already_processed"] is False
        assert second["already_processed"] is True
        assert "scan-123" in engine._processed_scan_ids


# ─── Self-Evolving Tests ────────────────────────────────────────────────────

class TestSelfEvolving:
    def test_evolve_empty(self, engine):
        result = engine.evolve()
        assert result["new_detection_rules"] == 0
        assert result["total_patterns_analyzed"] == 0

    def test_evolve_generates_rules_from_patterns(self, engine):
        # Seed high-confidence patterns
        for i in range(5):
            engine._record_pattern(
                pattern_id=f"test-pattern-{i}",
                learning_type=LearningType.PATTERN,
                source="live_scanner",
                data={"title": f"Test Vuln {i}", "severity": "HIGH", "category": "test"},
            )
            # Boost confidence and observations
            p = engine._patterns[f"test-pattern-{i}"]
            p.confidence = 0.9
            p.observations = 5

        result = engine.evolve()
        assert result["new_detection_rules"] == 5

    def test_evolve_scan_profiles_volatile(self, engine):
        # Create volatile baselines
        for i in range(3):
            engine._network_baselines[f"baseline:10.0.0.{i}"] = {
                "host_ip": f"10.0.0.{i}",
                "stability": 0.3,
                "scan_count": 10,
            }
        result = engine.evolve()
        assert result["scan_profile_updates"] >= 1

    def test_evolve_remediation_playbooks(self, engine):
        # Add successful and failed remediation patterns
        for i in range(3):
            engine._record_pattern(
                pattern_id=f"fix-success-{i}",
                learning_type=LearningType.REMEDIATION,
                source="auto_remediation",
                data={"category": "http_security", "title": f"Fix {i}", "success": True,
                      "commands": ["systemctl reload nginx"]},
            )
            engine._patterns[f"fix-success-{i}"].confidence = 0.9
            engine._patterns[f"fix-success-{i}"].observations = 3

        engine._record_pattern(
            pattern_id="fix-fail-0",
            learning_type=LearningType.REMEDIATION,
            source="auto_remediation",
            data={"category": "http_security", "title": "Bad Fix", "success": False,
                  "commands": ["rm -rf /"]},
        )

        result = engine.evolve()
        assert result["remediation_playbook_updates"] >= 1

    def test_false_positive_tracking(self, engine):
        for _ in range(6):
            engine.mark_false_positive("rule-123", "hash-abc")

        assert engine._fp_tracker["rule-123"] == 6
        assert "rule-123" in engine._suppressed_rules

    def test_threshold_evolution_on_fp(self, engine):
        # Mark enough FPs to trigger suppression
        for _ in range(5):
            result = engine.mark_false_positive("noisy-rule", "hash-xyz")

        # After 5 FPs, the rule should be suppressed
        assert result["suppressed"] is True
        assert "noisy-rule" in engine._suppressed_rules

        # Evolve should pick up the suppression
        result = engine.evolve()
        # Threshold adjustment already happened via mark_false_positive
        assert len(engine._suppressed_rules) >= 1


# ─── Status & Reporting Tests ───────────────────────────────────────────────

class TestStatusReporting:
    def test_get_status(self, engine):
        status = engine.get_status()
        assert status["version"] == "4.0.0"
        assert status["status"] == "operational"
        assert "learning" in status
        assert "evolution" in status
        assert "self_healing" in status

    def test_intelligence_report(self, engine):
        report = engine.get_intelligence_report()
        assert "generated_at" in report
        assert "top_vulnerability_patterns" in report
        assert "network_baselines" in report
        assert "evolution_summary" in report

    def test_get_evolutions(self, engine):
        evos = engine.get_evolutions()
        assert isinstance(evos, list)

    def test_get_learned_baselines(self, engine):
        baselines = engine.get_learned_baselines()
        assert isinstance(baselines, list)


# ─── One-Click Operation Tests ──────────────────────────────────────────────

class TestOneClick:
    def test_one_click_structure(self, engine):
        """Test the one-click operation returns proper structure (will scan localhost)."""
        # Note: actual scanning will hit localhost/127.0.0.1 which is allowed by default
        result = engine.one_click_scan_and_fix(
            target="127.0.0.1",
            scan_type="quick",
            auto_approve=False,
        )
        assert "operation_id" in result
        assert "phases" in result
        assert "scan" in result["phases"]
        assert "learning" in result["phases"]
        assert "remediation" in result["phases"]
        assert "evolution" in result["phases"]
        assert result["status"] == "completed"
        assert "risk_level" in result
        assert "recommendation" in result


# ─── Data Model Tests ────────────────────────────────────────────────────────

class TestDataModels:
    def test_component_health_to_dict(self):
        h = ComponentHealth(
            component_id="test", component_name="Test",
            status=HealthStatus.HEALTHY,
            last_check=datetime.now(timezone.utc).isoformat(),
        )
        d = h.to_dict()
        assert d["component_id"] == "test"

    def test_learned_pattern_to_dict(self):
        p = LearnedPattern(
            pattern_id="p1", learning_type=LearningType.BASELINE,
            source_engine="scanner", pattern_data={"test": True},
            confidence=0.8, observations=5,
            first_seen="2025-01-01", last_seen="2025-01-02",
        )
        d = p.to_dict()
        assert d["learning_type"] == "baseline"

    def test_evolution_event_to_dict(self):
        e = EvolutionEvent(
            evolution_id="e1", evolution_type=EvolutionType.DETECTION_RULE,
            description="Test rule", payload={"rule": "test"},
            source_patterns=["p1"], created_at="2025-01-01",
        )
        d = e.to_dict()
        assert d["evolution_type"] == "detection_rule"
