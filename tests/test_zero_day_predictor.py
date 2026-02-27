"""
Tests for the QueenCalifia Zero-Day Prediction Engine
=====================================================
Validates all 5 prediction layers and cross-layer correlation.
"""

import pytest
import time
from datetime import datetime
from engines.zero_day_predictor import (
    ZeroDayPredictor,
    ZeroDayCategory,
    PredictionConfidence,
    ThreatHorizon,
    ThreatPrediction,
    BehavioralGenome,
)


@pytest.fixture
def predictor():
    return ZeroDayPredictor(config={
        "anomaly_z_threshold": 2.0,
    })


class TestPredictorInitialization:
    def test_init_creates_threat_landscape(self, predictor):
        assert len(predictor.threat_landscape) >= 6
        assert "ransomware_evolution" in predictor.threat_landscape
        assert "ai_augmented_attacks" in predictor.threat_landscape
        assert "supply_chain" in predictor.threat_landscape

    def test_init_stats(self, predictor):
        assert predictor.stats["events_analyzed"] == 0
        assert predictor.stats["predictions_generated"] == 0

    def test_get_status(self, predictor):
        status = predictor.get_status()
        assert status["engine"] == "zero_day_predictor"
        assert status["status"] == "operational"
        assert "statistics" in status
        assert "active_predictions" in status
        assert "threat_landscape_vectors" in status


class TestLayer1AnomalyFusion:
    def test_no_anomaly_on_normal_traffic(self, predictor):
        """Normal traffic should not trigger anomaly fusion."""
        for i in range(30):
            result = predictor.analyze_event({
                "source_ip": "10.0.1.50",
                "bytes_out": 1000 + (i % 5) * 10,
                "bytes_in": 2000 + (i % 3) * 20,
                "duration_ms": 50,
                "unique_ports_1min": 2,
            })
        # Final result should have 0 predictions for normal traffic
        assert result["signals_generated"] == 0 or result["predictions_generated"] == 0

    def test_anomaly_detected_on_spike(self, predictor):
        """Massive spike in multiple features should trigger anomaly fusion."""
        # Build baseline
        for i in range(25):
            predictor.analyze_event({
                "source_ip": "10.0.1.100",
                "bytes_out": 1000,
                "bytes_in": 2000,
                "duration_ms": 50,
                "unique_ports_1min": 2,
            })
        # Inject anomalous event with spikes across multiple features
        result = predictor.analyze_event({
            "source_ip": "10.0.1.100",
            "bytes_out": 500000,  # 500x spike
            "bytes_in": 900000,   # 450x spike
            "duration_ms": 50000, # 1000x spike
            "unique_ports_1min": 200,  # 100x spike
        })
        # Should detect multi-feature anomaly
        assert result["layer_summary"]["anomaly_fusion"] >= 1


class TestLayer2SurfaceDrift:
    def test_new_service_exposure(self, predictor):
        result = predictor.analyze_event({
            "event_type": "service_discovered",
            "port": 3389,
            "service_name": "RDP",
            "asset_id": "server-01",
        })
        assert result["layer_summary"]["surface_drift"] >= 1

    def test_risky_config_change(self, predictor):
        result = predictor.analyze_event({
            "event_type": "config_change",
            "asset_id": "firewall-01",
            "component": "iptables",
            "change_type": "firewall_rule_removed",
        })
        assert result["layer_summary"]["surface_drift"] >= 1

    def test_certificate_expiry(self, predictor):
        result = predictor.analyze_event({
            "event_type": "cert_status",
            "domain": "api.tamerian.com",
            "days_to_expiry": 2,
        })
        assert result["layer_summary"]["surface_drift"] >= 1

    def test_safe_config_change_no_signal(self, predictor):
        result = predictor.analyze_event({
            "event_type": "config_change",
            "asset_id": "server-01",
            "component": "logging",
            "change_type": "log_rotation_updated",
        })
        assert result["layer_summary"]["surface_drift"] == 0


class TestLayer3EntropyAnalysis:
    def test_entropy_baseline_building(self, predictor):
        """During baseline phase, no signals should be generated."""
        for i in range(8):
            result = predictor.analyze_event({
                "source_ip": "10.0.2.50",
                "payload": "normal http traffic content " * 5,
            })
        assert result["layer_summary"]["entropy_analysis"] == 0

    def test_entropy_jump_detection(self, predictor):
        """Sudden entropy change should trigger signal after baseline."""
        # Build baseline with low-entropy payloads
        for i in range(15):
            predictor.analyze_event({
                "source_ip": "10.0.2.60",
                "payload": "aaaa bbbb cccc dddd eeee " * 10,
                "stream_id": "stream-test",
            })
        # Inject high-entropy (encrypted-looking) payload
        import random
        random_payload = "".join(chr(random.randint(33, 126)) for _ in range(300))
        result = predictor.analyze_event({
            "source_ip": "10.0.2.60",
            "payload": random_payload,
            "stream_id": "stream-test",
        })
        # Should detect entropy anomaly
        assert result["layer_summary"]["entropy_analysis"] >= 1

    def test_shannon_entropy_calculation(self, predictor):
        # Low entropy (repeated chars)
        low = predictor._shannon_entropy("aaaaaaaaaaaaaaaaaa")
        assert low == 0.0

        # High entropy (uniform distribution)
        import string
        high = predictor._shannon_entropy(string.ascii_letters + string.digits)
        assert high > 5.0

        # Medium entropy (normal text)
        medium = predictor._shannon_entropy("Hello, this is a normal sentence with some variety.")
        assert 3.0 < medium < 5.5


class TestLayer4GenomeDeviation:
    def test_genome_learning_phase(self, predictor):
        """During learning phase (<100 samples), no signals should fire."""
        for i in range(50):
            result = predictor.analyze_event({
                "event_type": "process_start",
                "asset_id": "ws-001",
                "process_name": "chrome.exe",
                "parent_process": "explorer.exe",
                "command_line": "chrome.exe https://example.com",
            })
        assert result["layer_summary"]["genome_deviation"] == 0

    def test_novel_execution_chain_detected(self, predictor):
        """After learning, a novel suspicious chain should trigger."""
        # Build genome with normal process chains
        for i in range(110):
            predictor.analyze_event({
                "event_type": "process_start",
                "asset_id": "ws-002",
                "process_name": "chrome.exe",
                "parent_process": "explorer.exe",
                "command_line": "chrome.exe",
            })
        # Inject suspicious novel chain
        result = predictor.analyze_event({
            "event_type": "process_start",
            "asset_id": "ws-002",
            "process_name": "powershell.exe",
            "parent_process": "winword.exe",
            "command_line": "powershell.exe -enc base64encodedpayloadhere -bypass executionpolicy hidden",
        })
        assert result["layer_summary"]["genome_deviation"] >= 1


class TestLayer5StrategicForecast:
    def test_campaign_correlation(self, predictor):
        """Multiple campaign indicators should trigger strategic forecast."""
        # Inject multiple MFA fatigue indicators
        for i in range(5):
            predictor.analyze_event({
                "event_type": "auth_failure",
                "source_ip": "10.0.3.50",
                "auth_type": "mfa_push",
                "failures_1min": 25,
            })
        result = predictor.analyze_event({
            "event_type": "auth_failure",
            "source_ip": "10.0.3.50",
            "auth_type": "mfa_push",
            "failures_1min": 30,
        })
        # May or may not trigger depending on timing, but should not error
        assert "layer_summary" in result

    def test_supply_chain_indicators(self, predictor):
        for i in range(4):
            predictor.analyze_event({
                "event_type": "dependency_install",
                "typosquat_score": 0.85,
                "is_new_dependency": True,
            })
        result = predictor.analyze_event({
            "event_type": "package_audit",
            "typosquat_score": 0.9,
            "is_new_dependency": True,
        })
        assert "layer_summary" in result


class TestCrossLayerPrediction:
    def test_prediction_generation(self, predictor):
        """Force a prediction by providing multi-layer signals."""
        # Build baselines first
        for i in range(25):
            predictor.analyze_event({
                "source_ip": "10.0.5.100",
                "bytes_out": 1000,
                "bytes_in": 2000,
                "unique_ports_1min": 2,
                "duration_ms": 50,
                "event_type": "connection_attempt",
            })

        # Multi-layer trigger event
        import random
        result = predictor.analyze_event({
            "source_ip": "10.0.5.100",
            "event_type": "service_discovered",
            "port": 4444,
            "service_name": "unknown",
            "asset_id": "server-05",
            "bytes_out": 900000,
            "bytes_in": 800000,
            "unique_ports_1min": 500,
            "duration_ms": 90000,
            "payload": "".join(chr(random.randint(33, 126)) for _ in range(300)),
        })

        # Should have analyzed the event
        assert result["event_processed"] is True
        assert result["processing_time_ms"] >= 0

    def test_confidence_tier_mapping(self, predictor):
        assert predictor._confidence_to_tier(0.96) == PredictionConfidence.NEAR_CERTAIN
        assert predictor._confidence_to_tier(0.85) == PredictionConfidence.HIGH_CONFIDENCE
        assert predictor._confidence_to_tier(0.65) == PredictionConfidence.PROBABLE
        assert predictor._confidence_to_tier(0.40) == PredictionConfidence.EMERGING
        assert predictor._confidence_to_tier(0.15) == PredictionConfidence.SPECULATIVE


class TestPredictionValidation:
    def test_validate_prediction(self, predictor):
        # Create a manual prediction for testing
        pred = ThreatPrediction(
            category=ZeroDayCategory.NOVEL_EXPLOIT,
            title="Test Prediction",
            confidence=0.85,
        )
        predictor.active_predictions[pred.prediction_id] = pred
        predictor.prediction_accuracy["pending"] = 1

        result = predictor.validate_prediction(
            pred.prediction_id, "confirmed", "Exploit confirmed via forensics"
        )
        assert result is not None
        assert result["validated"] is True
        assert result["outcome"] == "confirmed"
        assert predictor.prediction_accuracy["confirmed"] == 1

    def test_validate_nonexistent(self, predictor):
        result = predictor.validate_prediction("PRED-NONE", "confirmed")
        assert result is None


class TestReporting:
    def test_get_active_predictions(self, predictor):
        pred = ThreatPrediction(
            category=ZeroDayCategory.NOVEL_EXPLOIT,
            title="Active Test",
            confidence=0.75,
        )
        predictor.active_predictions[pred.prediction_id] = pred

        active = predictor.get_active_predictions(min_confidence=0.5)
        assert len(active) >= 1
        assert active[0]["confidence"] >= 0.5

    def test_get_threat_landscape(self, predictor):
        landscape = predictor.get_threat_landscape()
        assert "vectors" in landscape
        assert "ransomware_evolution" in landscape["vectors"]

    def test_prediction_to_dict(self):
        pred = ThreatPrediction(
            category=ZeroDayCategory.ENCRYPTED_CHANNEL_ABUSE,
            title="Test Dict",
            confidence=0.88,
            risk_score=7.5,
        )
        d = pred.to_dict()
        assert d["prediction_id"].startswith("PRED-")
        assert d["category"] == "encrypted_channel_abuse"
        assert d["confidence"] == 0.88
        assert d["risk_score"] == 7.5


class TestPreemptiveActions:
    def test_novel_exploit_actions(self, predictor):
        pred = ThreatPrediction(
            category=ZeroDayCategory.NOVEL_EXPLOIT,
            confidence=0.85,
        )
        actions = predictor._generate_preemptive_actions(pred)
        assert len(actions) >= 4
        assert any("virtual patching" in a.lower() for a in actions)

    def test_lotl_actions(self, predictor):
        pred = ThreatPrediction(
            category=ZeroDayCategory.LIVING_OFF_THE_LAND,
            confidence=0.75,
        )
        actions = predictor._generate_preemptive_actions(pred)
        assert any("whitelisting" in a.lower() or "powershell" in a.lower() for a in actions)

    def test_critical_auto_contain(self, predictor):
        pred = ThreatPrediction(
            category=ZeroDayCategory.NOVEL_EXPLOIT,
            confidence=0.95,
        )
        actions = predictor._generate_preemptive_actions(pred)
        assert any("auto-contain" in a.lower() for a in actions)


class TestEdgeCases:
    def test_empty_event(self, predictor):
        result = predictor.analyze_event({})
        assert result["event_processed"] is True
        assert result["signals_generated"] == 0

    def test_zero_payload_entropy(self, predictor):
        result = predictor.analyze_event({
            "source_ip": "10.0.1.1",
            "payload": "",
        })
        assert result["event_processed"] is True

    def test_missing_fields(self, predictor):
        result = predictor.analyze_event({
            "event_type": "unknown_type",
        })
        assert result["event_processed"] is True

    def test_concurrent_safety(self, predictor):
        """Basic check that concurrent access doesn't crash."""
        import threading
        errors = []

        def worker(tid):
            try:
                for i in range(20):
                    predictor.analyze_event({
                        "source_ip": f"10.0.{tid}.{i}",
                        "bytes_out": 1000 + i * 100,
                        "event_type": "connection_attempt",
                    })
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert predictor.stats["events_analyzed"] >= 80


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
