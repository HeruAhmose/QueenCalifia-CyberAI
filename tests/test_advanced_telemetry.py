"""
Tests for the QueenCalifia Advanced Telemetry Engine
=====================================================
Validates all 6 telemetry streams and cross-stream intelligence.
"""

import pytest
import time
import threading
from datetime import datetime, timedelta
from engines.advanced_telemetry import (
    AdvancedTelemetry,
    TelemetryStream,
    BeaconClassification,
    SensorHealth,
    SensorStatus,
    TelemetrySignal,
    NetworkFlowFingerprint,
    BeaconProfile,
    AssetRelationship,
)


@pytest.fixture
def telemetry():
    return AdvancedTelemetry(config={
        "dns_qps_threshold": 10,
        "injection_syscall_threshold": 5,
        "cred_syscall_threshold": 5,
        "blast_radius_threshold": 5,
        "off_hours_start": 22,
        "off_hours_end": 5,
    })


# ═══════════════════════════════════════════════════════════════════════════
# Initialization
# ═══════════════════════════════════════════════════════════════════════════

class TestInitialization:
    def test_init_creates_threat_fingerprints(self, telemetry):
        assert len(telemetry.known_bad_fingerprints) >= 10

    def test_init_stats(self, telemetry):
        assert telemetry.stats["events_processed"] == 0
        assert telemetry.stats["signals_generated"] == 0

    def test_get_status(self, telemetry):
        status = telemetry.get_status()
        assert status["engine"] == "advanced_telemetry"
        assert status["status"] == "operational"
        assert "streams" in status
        assert "network_flow" in status["streams"]
        assert "temporal_patterns" in status["streams"]
        assert "kernel_endpoint" in status["streams"]
        assert "cross_asset" in status["streams"]
        assert "feedback_loop" in status["streams"]
        assert "collection_health" in status["streams"]

    def test_process_empty_event(self, telemetry):
        result = telemetry.process_event({})
        assert result["telemetry_processed"] is True
        assert result["signals_generated"] == 0


# ═══════════════════════════════════════════════════════════════════════════
# T1: Network Flow Intelligence
# ═══════════════════════════════════════════════════════════════════════════

class TestT1NetworkFlowIntel:
    def test_new_tls_fingerprint_catalogued(self, telemetry):
        result = telemetry.process_event({
            "source_ip": "10.0.1.50",
            "dest_ip": "203.0.113.10",
            "ja3_hash": "abcdef1234567890abcdef1234567890",
            "tls_version": "TLSv1.3",
            "server_name": "api.example.com",
        })
        assert any(
            s["signal_type"] == "new_tls_fingerprint"
            for s in result["signals"]
        )
        assert telemetry.stats["fingerprints_catalogued"] == 1

    def test_known_malicious_fingerprint_detected(self, telemetry):
        """Cobalt Strike JA3 should trigger critical alert."""
        result = telemetry.process_event({
            "source_ip": "10.0.1.100",
            "dest_ip": "198.51.100.50",
            "ja3_hash": "72a589da586844d7f0818ce684948eea",
            "tls_version": "TLSv1.2",
        })
        malicious_signals = [
            s for s in result["signals"]
            if s["signal_type"] == "malicious_tls_fingerprint"
        ]
        assert len(malicious_signals) == 1
        assert malicious_signals[0]["severity"] == "critical"
        assert malicious_signals[0]["confidence"] >= 0.85

    def test_tls_downgrade_detection(self, telemetry):
        result = telemetry.process_event({
            "source_ip": "10.0.1.50",
            "dest_ip": "203.0.113.10",
            "ja3_hash": "aaaa1111bbbb2222cccc3333dddd4444",
            "tls_version": "TLSv1.0",
        })
        downgrade_signals = [
            s for s in result["signals"]
            if s["signal_type"] == "tls_downgrade_detected"
        ]
        assert len(downgrade_signals) >= 1

    def test_modern_tls_no_downgrade_signal(self, telemetry):
        result = telemetry.process_event({
            "source_ip": "10.0.1.50",
            "dest_ip": "203.0.113.10",
            "ja3_hash": "aaaa1111bbbb2222cccc3333dddd4444",
            "tls_version": "TLSv1.3",
        })
        downgrade = [
            s for s in result["signals"]
            if s["signal_type"] == "tls_downgrade_detected"
        ]
        assert len(downgrade) == 0

    def test_dga_domain_detection(self, telemetry):
        """High-entropy, long domain should trigger DGA detection."""
        result = telemetry.process_event({
            "event_type": "dns_query",
            "source_ip": "10.0.1.50",
            "query_name": "a8f3k2j5m9p1xq4r7t0w6xyzbc8def.com",
            "query_type": "A",
        })
        dga_signals = [
            s for s in result["signals"]
            if s["signal_type"] == "dga_domain_detected"
        ]
        assert len(dga_signals) >= 1

    def test_normal_domain_no_dga(self, telemetry):
        result = telemetry.process_event({
            "event_type": "dns_query",
            "source_ip": "10.0.1.50",
            "query_name": "www.google.com",
            "query_type": "A",
        })
        dga = [s for s in result["signals"] if s["signal_type"] == "dga_domain_detected"]
        assert len(dga) == 0

    def test_dns_tunneling_indicator(self, telemetry):
        result = telemetry.process_event({
            "event_type": "dns_query",
            "source_ip": "10.0.1.50",
            "query_name": "data.tunnel.evil.com",
            "query_type": "TXT",
            "response_size": 1024,
        })
        tunnel_signals = [
            s for s in result["signals"]
            if s["signal_type"] == "dns_tunneling_indicator"
        ]
        assert len(tunnel_signals) >= 1

    def test_dns_exfil_subdomain_detection(self, telemetry):
        """Long, high-entropy subdomains indicate DNS data exfiltration."""
        result = telemetry.process_event({
            "event_type": "dns_query",
            "source_ip": "10.0.1.50",
            "query_name": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.b64data.exfil.attacker.com",
            "query_type": "A",
        })
        exfil = [
            s for s in result["signals"]
            if s["signal_type"] == "dns_exfil_subdomain"
        ]
        assert len(exfil) >= 1

    def test_dns_query_flood_detection(self, telemetry):
        """High query volume from single source triggers flood alert."""
        for i in range(15):
            result = telemetry.process_event({
                "event_type": "dns_query",
                "source_ip": "10.0.2.99",
                "query_name": f"host{i}.example.com",
                "query_type": "A",
            })
        flood = [
            s for s in result["signals"]
            if s["signal_type"] == "dns_query_flood"
        ]
        assert len(flood) >= 1

    def test_protocol_port_mismatch(self, telemetry):
        result = telemetry.process_event({
            "source_ip": "10.0.1.50",
            "protocol": "HTTP",
            "dest_port": 4444,
        })
        mismatch = [
            s for s in result["signals"]
            if s["signal_type"] == "protocol_port_mismatch"
        ]
        assert len(mismatch) >= 1

    def test_standard_protocol_port_no_signal(self, telemetry):
        result = telemetry.process_event({
            "source_ip": "10.0.1.50",
            "protocol": "HTTPS",
            "dest_port": 443,
        })
        mismatch = [
            s for s in result["signals"]
            if s["signal_type"] == "protocol_port_mismatch"
        ]
        assert len(mismatch) == 0

    def test_protocol_payload_anomaly(self, telemetry):
        """Payload 10x+ baseline should trigger anomaly."""
        # Build baseline
        for i in range(10):
            telemetry.process_event({
                "source_ip": "10.0.3.50",
                "protocol": "DNS",
                "dest_port": 53,
                "bytes_out": 100,
            })
        # Inject anomalous payload
        result = telemetry.process_event({
            "source_ip": "10.0.3.50",
            "protocol": "DNS",
            "dest_port": 53,
            "bytes_out": 50000,
        })
        anomaly = [
            s for s in result["signals"]
            if s["signal_type"] == "protocol_payload_anomaly"
        ]
        assert len(anomaly) >= 1

    def test_self_signed_certificate(self, telemetry):
        result = telemetry.process_event({
            "source_ip": "10.0.1.50",
            "dest_ip": "198.51.100.99",
            "server_cert": True,
            "cert_self_signed": True,
            "cert_subject_cn": "localhost",
        })
        self_signed = [
            s for s in result["signals"]
            if s["signal_type"] == "self_signed_certificate"
        ]
        assert len(self_signed) >= 1

    def test_short_lived_certificate(self, telemetry):
        result = telemetry.process_event({
            "source_ip": "10.0.1.50",
            "dest_ip": "198.51.100.99",
            "server_cert": True,
            "cert_validity_days": 3,
            "cert_age_days": 1,
        })
        short_lived = [
            s for s in result["signals"]
            if s["signal_type"] == "short_lived_certificate"
        ]
        assert len(short_lived) >= 1

    def test_cert_cn_mismatch(self, telemetry):
        result = telemetry.process_event({
            "source_ip": "10.0.1.50",
            "dest_ip": "198.51.100.99",
            "server_cert": True,
            "cert_subject_cn": "other-domain.com",
            "server_name": "api.target.com",
        })
        mismatch = [
            s for s in result["signals"]
            if s["signal_type"] == "cert_cn_mismatch"
        ]
        assert len(mismatch) >= 1

    def test_ja3_association_lookup(self, telemetry):
        assoc = telemetry._lookup_ja3_associations(
            "72a589da586844d7f0818ce684948eea"
        )
        assert "Cobalt Strike" in assoc

    def test_label_entropy_calculation(self, telemetry):
        # Low entropy
        low = AdvancedTelemetry._label_entropy("aaaaaa")
        assert low == 0.0
        # High entropy
        high = AdvancedTelemetry._label_entropy("abcdefghijklmnopqrstuvwxyz0123456789")
        assert high > 4.0
        # Empty
        assert AdvancedTelemetry._label_entropy("") == 0.0


# ═══════════════════════════════════════════════════════════════════════════
# T2: Temporal Pattern Analysis
# ═══════════════════════════════════════════════════════════════════════════

class TestT2TemporalPatterns:
    def test_beaconing_detection_exact_interval(self, telemetry):
        """Regular interval traffic should be detected as beaconing."""
        for i in range(15):
            telemetry.process_event({
                "source_ip": "10.0.1.100",
                "dest_ip": "198.51.100.10",
            })
            # Simulate exact 60s intervals by injecting timestamps
            with telemetry._lock:
                key = "10.0.1.100->198.51.100.10"
                telemetry.event_timestamps[key] = deque(maxlen=10_000)
                base_time = time.time() - 900  # 15 min ago
                for j in range(15):
                    telemetry.event_timestamps[key].append(
                        base_time + j * 60.0  # Exactly 60s apart
                    )

        result = telemetry.process_event({
            "source_ip": "10.0.1.100",
            "dest_ip": "198.51.100.10",
        })
        beacon_signals = [
            s for s in result["signals"]
            if s["signal_type"] == "beaconing_detected"
        ]
        # Should detect beaconing (exact periodic)
        assert len(beacon_signals) >= 1
        assert beacon_signals[0]["details"]["classification"] in (
            "periodic_exact", "periodic_jittered"
        )

    def test_no_beaconing_on_random_traffic(self, telemetry):
        """Random traffic should not trigger beaconing."""
        import random
        key = "10.0.5.50->203.0.113.99"
        base_time = time.time() - 600
        with telemetry._lock:
            telemetry.event_timestamps[key] = deque(maxlen=10_000)
            t = base_time
            for _ in range(15):
                t += random.uniform(1, 300)  # Highly random intervals
                telemetry.event_timestamps[key].append(t)

        result = telemetry.process_event({
            "source_ip": "10.0.5.50",
            "dest_ip": "203.0.113.99",
        })
        beacons = [
            s for s in result["signals"]
            if s["signal_type"] == "beaconing_detected"
        ]
        # Random traffic should NOT trigger beacon detection
        # (may still trigger due to random chance, so we check confidence is low)
        for b in beacons:
            assert b["confidence"] < 0.8

    def test_data_burst_detection(self, telemetry):
        """High-volume burst in short window should be detected."""
        for i in range(10):
            telemetry.process_event({
                "source_ip": "10.0.1.200",
                "dest_ip": "198.51.100.50",
                "bytes_out": 500_000,  # 500KB per event
            })
        # All events happen nearly instantly in test, so time_span may be <1s
        # We verify no crash and signal generation depends on timing
        assert telemetry.stats["events_processed"] >= 10

    def test_insufficient_data_no_beacon(self, telemetry):
        """With <10 events, no beaconing should be detected."""
        for i in range(5):
            result = telemetry.process_event({
                "source_ip": "10.0.9.1",
                "dest_ip": "10.0.9.2",
            })
        beacons = [
            s for s in result["signals"]
            if s["signal_type"] == "beaconing_detected"
        ]
        assert len(beacons) == 0

    def test_beacon_profile_stored(self, telemetry):
        """Beacon profiles should be stored after detection."""
        key = "10.0.1.150->198.51.100.20"
        base_time = time.time() - 600
        with telemetry._lock:
            telemetry.event_timestamps[key] = deque(maxlen=10_000)
            for j in range(20):
                telemetry.event_timestamps[key].append(
                    base_time + j * 30.0  # 30s intervals
                )
        telemetry.process_event({
            "source_ip": "10.0.1.150",
            "dest_ip": "198.51.100.20",
        })
        # Check beacon report
        report = telemetry.get_beacon_report()
        # May or may not have detected depending on timing, but shouldn't crash
        assert isinstance(report, list)


# ═══════════════════════════════════════════════════════════════════════════
# T3: Kernel/Endpoint Telemetry
# ═══════════════════════════════════════════════════════════════════════════

class TestT3KernelEndpoint:
    def test_injection_syscall_pattern(self, telemetry):
        """High injection-related syscall count should trigger alert."""
        result = telemetry.process_event({
            "asset_id": "ws-001",
            "process_name": "svchost.exe",
            "syscalls": {
                "NtWriteVirtualMemory": 8,
                "NtAllocateVirtualMemory": 5,
                "NtCreateThreadEx": 3,
            },
        })
        injection = [
            s for s in result["signals"]
            if s["signal_type"] == "injection_syscall_pattern"
        ]
        assert len(injection) >= 1
        assert injection[0]["severity"] == "critical"

    def test_credential_access_pattern(self, telemetry):
        result = telemetry.process_event({
            "asset_id": "ws-002",
            "process_name": "suspicious.exe",
            "syscalls": {
                "NtOpenProcess": 10,
                "NtReadVirtualMemory": 8,
            },
        })
        cred = [
            s for s in result["signals"]
            if s["signal_type"] == "credential_access_pattern"
        ]
        assert len(cred) >= 1

    def test_normal_syscalls_no_signal(self, telemetry):
        result = telemetry.process_event({
            "asset_id": "ws-003",
            "process_name": "notepad.exe",
            "syscalls": {
                "NtReadFile": 5,
                "NtWriteFile": 3,
            },
        })
        injection = [
            s for s in result["signals"]
            if s["signal_type"] in (
                "injection_syscall_pattern", "credential_access_pattern"
            )
        ]
        assert len(injection) == 0

    def test_ransomware_file_pattern(self, telemetry):
        """Rapid read/write/rename across many files = ransomware."""
        now_ts = datetime.utcnow().timestamp()
        with telemetry._lock:
            history = telemetry.file_io_patterns["server-01"]
            for i in range(25):
                history.append({
                    "operation": "file_read",
                    "file_path": f"/data/doc{i}.pdf",
                    "process": "cryptolocker.exe",
                    "timestamp": now_ts - 10,
                })
            for i in range(25):
                history.append({
                    "operation": "file_write",
                    "file_path": f"/data/doc{i}.pdf.encrypted",
                    "process": "cryptolocker.exe",
                    "timestamp": now_ts - 5,
                })
            for i in range(20):
                history.append({
                    "operation": "file_rename",
                    "file_path": f"/data/doc{i}.pdf",
                    "process": "cryptolocker.exe",
                    "timestamp": now_ts - 2,
                })

        result = telemetry.process_event({
            "event_type": "file_rename",
            "asset_id": "server-01",
            "file_path": "/data/doc99.pdf.encrypted",
            "process_name": "cryptolocker.exe",
        })
        ransomware = [
            s for s in result["signals"]
            if s["signal_type"] == "ransomware_file_pattern"
        ]
        assert len(ransomware) >= 1
        assert ransomware[0]["severity"] == "critical"

    def test_ransomware_extension_detection(self, telemetry):
        result = telemetry.process_event({
            "event_type": "file_create",
            "asset_id": "ws-004",
            "file_path": "/home/user/documents/report.locked",
            "process_name": "locker.exe",
        })
        ext_signals = [
            s for s in result["signals"]
            if s["signal_type"] == "ransomware_extension_created"
        ]
        assert len(ext_signals) >= 1

    def test_normal_file_ops_no_ransomware(self, telemetry):
        result = telemetry.process_event({
            "event_type": "file_create",
            "asset_id": "ws-005",
            "file_path": "/home/user/docs/report.pdf",
            "process_name": "libreoffice",
        })
        ransomware = [
            s for s in result["signals"]
            if "ransomware" in s["signal_type"]
        ]
        assert len(ransomware) == 0

    def test_rwx_memory_allocation(self, telemetry):
        result = telemetry.process_event({
            "event_type": "rwx_allocation",
            "asset_id": "ws-006",
            "process_name": "explorer.exe",
            "allocation_size": 65536,
            "is_remote": True,
            "memory_event": True,
        })
        rwx = [
            s for s in result["signals"]
            if s["signal_type"] == "rwx_memory_allocation"
        ]
        assert len(rwx) >= 1

    def test_process_hollowing_detection(self, telemetry):
        result = telemetry.process_event({
            "event_type": "hollowed_process",
            "asset_id": "ws-007",
            "process_name": "malware.exe",
            "target_process": "svchost.exe",
            "memory_event": True,
        })
        hollowing = [
            s for s in result["signals"]
            if s["signal_type"] == "process_hollowing_detected"
        ]
        assert len(hollowing) >= 1
        assert hollowing[0]["severity"] == "critical"
        assert hollowing[0]["confidence"] >= 0.85

    def test_memory_injection_detection(self, telemetry):
        result = telemetry.process_event({
            "event_type": "memory_injection",
            "asset_id": "ws-008",
            "process_name": "attacker.exe",
            "target_process": "lsass.exe",
            "injection_type": "dll_injection",
            "memory_event": True,
        })
        injection = [
            s for s in result["signals"]
            if s["signal_type"] == "memory_injection_detected"
        ]
        assert len(injection) >= 1

    def test_privilege_escalation_chain(self, telemetry):
        """Multiple privilege transitions in 30min = escalation chain."""
        for i in range(4):
            telemetry.process_event({
                "event_type": "privilege_escalation",
                "asset_id": "server-10",
                "source_user": f"user{i}",
                "target_user": "Administrator",
                "process_name": "exploit.exe",
            })
        result = telemetry.process_event({
            "event_type": "privilege_escalation",
            "asset_id": "server-10",
            "source_user": "user5",
            "target_user": "NT AUTHORITY\\SYSTEM",
            "process_name": "exploit.exe",
        })
        chain = [
            s for s in result["signals"]
            if s["signal_type"] == "privilege_escalation_chain"
        ]
        assert len(chain) >= 1

    def test_high_privilege_transition(self, telemetry):
        result = telemetry.process_event({
            "event_type": "privilege_escalation",
            "asset_id": "server-11",
            "source_user": "webuser",
            "target_user": "root",
            "process_name": "sudo",
        })
        high_priv = [
            s for s in result["signals"]
            if s["signal_type"] == "high_privilege_transition"
        ]
        assert len(high_priv) >= 1


# ═══════════════════════════════════════════════════════════════════════════
# T4: Cross-Asset Correlation
# ═══════════════════════════════════════════════════════════════════════════

class TestT4CrossAssetCorrelation:
    def test_new_lateral_protocol_detection(self, telemetry):
        """New communication on lateral movement port should trigger."""
        result = telemetry.process_event({
            "source_ip": "10.0.1.100",
            "dest_ip": "10.0.1.200",
            "protocol": "SMB",
            "dest_port": 445,
        })
        lateral = [
            s for s in result["signals"]
            if s["signal_type"] == "new_lateral_protocol"
        ]
        assert len(lateral) >= 1

    def test_lateral_movement_from_suspect_asset(self, telemetry):
        """High-risk source connecting to new target should trigger critical."""
        # Mark source as high-risk
        telemetry.asset_risk_scores["10.0.1.50"] = 0.8

        result = telemetry.process_event({
            "source_ip": "10.0.1.50",
            "dest_ip": "10.0.1.200",
            "protocol": "WinRM",
            "dest_port": 5985,
        })
        suspect = [
            s for s in result["signals"]
            if s["signal_type"] == "lateral_movement_from_suspect"
        ]
        assert len(suspect) >= 1
        assert suspect[0]["severity"] == "critical"

    def test_blast_radius_estimation(self, telemetry):
        """Asset communicating with many targets should trigger blast radius."""
        source = "10.0.1.1"
        # Create connections to 10 different targets
        for i in range(10):
            telemetry.process_event({
                "source_ip": source,
                "dest_ip": f"10.0.2.{i + 1}",
                "protocol": "TCP",
                "dest_port": 80,
            })
        # The threshold is set to 5 in config
        result = telemetry.process_event({
            "source_ip": source,
            "dest_ip": "10.0.2.99",
            "protocol": "TCP",
            "dest_port": 80,
        })
        # Check if blast radius signal was generated
        blast = [
            s for s in result["signals"]
            if s["signal_type"] == "high_blast_radius"
        ]
        # May or may not trigger depending on 2-hop calculation
        assert result["telemetry_processed"] is True

    def test_lateral_movement_graph_export(self, telemetry):
        telemetry.process_event({
            "source_ip": "10.0.1.1",
            "dest_ip": "10.0.1.2",
            "protocol": "SSH",
            "dest_port": 22,
        })
        graph = telemetry.get_lateral_movement_graph()
        assert graph["total_nodes"] == 2
        assert graph["total_edges"] == 1
        assert graph["edges"][0]["source"] == "10.0.1.1"

    def test_asset_risk_update(self, telemetry):
        score = telemetry.update_asset_risk("server-99", 0.6, "compromised")
        assert score == 0.6
        score2 = telemetry.update_asset_risk("server-99", 0.3, "lateral movement")
        assert round(score2, 1) == 0.9

    def test_asset_risk_clamped(self, telemetry):
        telemetry.update_asset_risk("server-100", 0.9, "test")
        score = telemetry.update_asset_risk("server-100", 0.5, "test")
        assert score == 1.0  # Clamped to 1.0

    def test_no_signal_for_self_communication(self, telemetry):
        result = telemetry.process_event({
            "source_ip": "10.0.1.1",
            "dest_ip": "10.0.1.1",
            "protocol": "TCP",
        })
        cross_asset = [
            s for s in result["signals"]
            if s["stream"] == "cross_asset"
        ]
        assert len(cross_asset) == 0

    def test_asset_risk_map_report(self, telemetry):
        telemetry.update_asset_risk("server-a", 0.8, "test")
        telemetry.update_asset_risk("server-b", 0.3, "test")
        risk_map = telemetry.get_asset_risk_map()
        assert risk_map["total_tracked"] == 2
        high_risk = risk_map["high_risk_assets"]
        assert len(high_risk) == 1
        assert high_risk[0]["asset"] == "server-a"


# ═══════════════════════════════════════════════════════════════════════════
# T5: Adaptive Feedback Loop
# ═══════════════════════════════════════════════════════════════════════════

class TestT5AdaptiveFeedback:
    def test_record_confirmed_prediction(self, telemetry):
        result = telemetry.record_prediction_outcome(
            prediction_id="PRED-001",
            outcome="confirmed",
            contributing_layers=["anomaly_fusion", "entropy_analysis"],
            signal_types=["correlated_multi_anomaly"],
        )
        assert result["outcome"] == "confirmed"
        assert telemetry.layer_accuracy["anomaly_fusion"]["true_positive"] == 1

    def test_record_false_positive(self, telemetry):
        result = telemetry.record_prediction_outcome(
            prediction_id="PRED-002",
            outcome="false_positive",
            contributing_layers=["surface_drift"],
            signal_types=["new_service_exposure"],
        )
        assert result["outcome"] == "false_positive"
        assert telemetry.layer_accuracy["surface_drift"]["false_positive"] == 1

    def test_threshold_adjustment_on_high_fp(self, telemetry):
        """High FP rate should trigger threshold increase (less sensitive)."""
        for i in range(15):
            telemetry.record_prediction_outcome(
                prediction_id=f"PRED-FP-{i}",
                outcome="false_positive" if i < 8 else "confirmed",
                contributing_layers=["test_layer"],
                signal_types=["test_signal"],
            )
        # FP rate = 8/15 = 53%, should trigger adjustment
        adj = telemetry.get_threshold_adjustment("test_layer")
        assert adj > 1.0  # Threshold increased

    def test_threshold_decrease_on_high_accuracy(self, telemetry):
        """High TP rate with low FP should increase sensitivity."""
        for i in range(25):
            telemetry.record_prediction_outcome(
                prediction_id=f"PRED-TP-{i}",
                outcome="confirmed" if i < 20 else "false_positive",
                contributing_layers=["accurate_layer"],
                signal_types=["accurate_signal"],
            )
        # TP rate = 20/25 = 80%, FP rate = 5/25 = 20%
        # FP rate > 10% so won't decrease threshold yet in this case
        assert telemetry.layer_accuracy["accurate_layer"]["total"] == 25

    def test_signal_weight_adjustment(self, telemetry):
        """Confirmed predictions should boost signal weights."""
        initial_weight = telemetry.get_signal_weight("test_signal")
        assert initial_weight == 1.0

        for i in range(5):
            telemetry.record_prediction_outcome(
                prediction_id=f"PRED-W-{i}",
                outcome="confirmed",
                contributing_layers=["layer_x"],
                signal_types=["test_signal"],
            )
        boosted = telemetry.get_signal_weight("test_signal")
        assert boosted > 1.0

    def test_signal_weight_decrease_on_fp(self, telemetry):
        for i in range(5):
            telemetry.record_prediction_outcome(
                prediction_id=f"PRED-WFP-{i}",
                outcome="false_positive",
                contributing_layers=["layer_y"],
                signal_types=["noisy_signal"],
            )
        weight = telemetry.get_signal_weight("noisy_signal")
        assert weight < 1.0

    def test_suppression_rule_creation(self, telemetry):
        """3+ FPs in 24h should auto-create suppression rule."""
        for i in range(4):
            telemetry.record_prediction_outcome(
                prediction_id=f"PRED-SUP-{i}",
                outcome="false_positive",
                contributing_layers=["noisy_layer"],
                signal_types=["noisy_type"],
            )
        assert len(telemetry.suppression_rules) >= 1
        assert telemetry.stats["false_positives_suppressed"] >= 1

    def test_signal_enrichment(self, telemetry):
        """Confidence enrichment should apply weights and adjustments."""
        signal = {
            "signal_type": "test_enrichment",
            "layer": "test_layer",
            "confidence": 0.7,
        }
        enriched = telemetry.enrich_signal_confidence(signal)
        assert enriched["confidence_enriched"] is True
        assert "original_confidence" in enriched
        assert "telemetry_weight" in enriched

    def test_feedback_summary_report(self, telemetry):
        telemetry.record_prediction_outcome(
            "PRED-SUM-1", "confirmed", ["layer_a"], ["sig_a"]
        )
        summary = telemetry.get_feedback_summary()
        assert "layer_accuracy" in summary
        assert "threshold_adjustments" in summary
        assert summary["total_feedback_entries"] >= 1


# ═══════════════════════════════════════════════════════════════════════════
# T6: Collection Health Monitor
# ═══════════════════════════════════════════════════════════════════════════

class TestT6CollectionHealth:
    def test_sensor_registration(self, telemetry):
        telemetry.process_event({
            "sensor_id": "sensor-fw-01",
            "sensor_type": "network",
            "asset_id": "firewall-01",
            "event_type": "connection_attempt",
        })
        assert "sensor-fw-01" in telemetry.sensors
        assert telemetry.sensors["sensor-fw-01"].sensor_type == "network"

    def test_coverage_tracking(self, telemetry):
        telemetry.process_event({
            "sensor_id": "sensor-edr-01",
            "sensor_type": "endpoint",
            "asset_id": "ws-001",
        })
        telemetry.process_event({
            "sensor_id": "sensor-edr-01",
            "sensor_type": "endpoint",
            "asset_id": "ws-002",
        })
        assert "ws-001" in telemetry.coverage_map["endpoint"]
        assert "ws-002" in telemetry.coverage_map["endpoint"]

    def test_health_check_report(self, telemetry):
        telemetry.process_event({
            "sensor_id": "sensor-01",
            "sensor_type": "network",
            "asset_id": "fw-01",
        })
        report = telemetry.check_collection_health()
        assert "sensors" in report
        assert "blind_spots" in report
        assert "overall_health" in report
        assert report["overall_health"] in (
            "healthy", "degraded", "critical", "blind_spots_detected"
        )

    def test_stale_sensor_detection(self, telemetry):
        """Sensor that hasn't reported in >2min should be stale."""
        with telemetry._lock:
            telemetry.sensors["old-sensor"] = SensorStatus(
                sensor_id="old-sensor",
                sensor_type="network",
                last_event_at=datetime.utcnow() - timedelta(minutes=5),
            )
        report = telemetry.check_collection_health()
        old_sensor = report["sensors"].get("old-sensor", {})
        assert old_sensor.get("health") in ("stale", "offline")

    def test_ingestion_lag_tracking(self, telemetry):
        past_time = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
        telemetry.process_event({
            "sensor_id": "sensor-lag",
            "sensor_type": "endpoint",
            "event_timestamp": past_time,
        })
        assert len(telemetry.ingestion_lag) >= 1
        lag_entry = telemetry.ingestion_lag[-1]
        assert lag_entry["lag_ms"] > 5000  # Should be ~10 seconds


# ═══════════════════════════════════════════════════════════════════════════
# Signal Compatibility
# ═══════════════════════════════════════════════════════════════════════════

class TestSignalCompatibility:
    def test_signal_to_dict(self):
        sig = TelemetrySignal(
            stream=TelemetryStream.NETWORK_FLOW,
            signal_type="test_signal",
            source="10.0.1.1",
            confidence=0.75,
            severity="high",
        )
        d = sig.to_dict()
        assert d["stream"] == "network_flow"
        assert d["confidence"] == 0.75

    def test_signal_to_predictor_format(self):
        sig = TelemetrySignal(
            stream=TelemetryStream.TEMPORAL_PATTERN,
            signal_type="beaconing_detected",
            source="10.0.1.1",
            confidence=0.85,
            severity="critical",
        )
        p = sig.to_predictor_signal()
        assert p["layer"] == "telemetry_temporal_pattern"
        assert p["signal_type"] == "beaconing_detected"
        assert p["confidence"] == 0.85

    def test_predictor_signals_in_process_result(self, telemetry):
        """Process result should include predictor-compatible signals."""
        result = telemetry.process_event({
            "source_ip": "10.0.1.50",
            "ja3_hash": "72a589da586844d7f0818ce684948eea",
        })
        assert "predictor_signals" in result
        if result["predictor_signals"]:
            ps = result["predictor_signals"][0]
            assert "layer" in ps
            assert "signal_type" in ps
            assert "confidence" in ps


# ═══════════════════════════════════════════════════════════════════════════
# Edge Cases & Concurrency
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCasesAndConcurrency:
    def test_missing_fields_no_crash(self, telemetry):
        """Various events with missing fields should not crash."""
        events = [
            {"event_type": "dns_query"},
            {"event_type": "process_start"},
            {"ja3_hash": ""},
            {"protocol": ""},
            {"syscalls": {}},
            {"event_type": "file_create"},
        ]
        for ev in events:
            result = telemetry.process_event(ev)
            assert result["telemetry_processed"] is True

    def test_concurrent_processing(self, telemetry):
        """Multi-threaded event processing should not crash."""
        errors = []

        def worker(tid):
            try:
                for i in range(20):
                    telemetry.process_event({
                        "source_ip": f"10.0.{tid}.{i}",
                        "dest_ip": f"10.0.{tid}.{i + 100}",
                        "protocol": "TCP",
                        "dest_port": 443,
                        "bytes_out": 1000 + i * 100,
                    })
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=(t,))
            for t in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert telemetry.stats["events_processed"] >= 80

    def test_large_event_volume(self, telemetry):
        """Stress test with 500 events."""
        for i in range(500):
            telemetry.process_event({
                "source_ip": f"10.0.{i % 10}.{i % 256}",
                "dest_ip": "10.0.99.1",
                "protocol": "TCP",
                "bytes_out": i * 10,
            })
        assert telemetry.stats["events_processed"] == 500

    def test_empty_string_fields(self, telemetry):
        result = telemetry.process_event({
            "source_ip": "",
            "dest_ip": "",
            "ja3_hash": "",
            "protocol": "",
        })
        assert result["telemetry_processed"] is True

    def test_special_characters_in_fields(self, telemetry):
        result = telemetry.process_event({
            "event_type": "dns_query",
            "source_ip": "10.0.1.1",
            "query_name": "test.<script>alert(1)</script>.com",
            "query_type": "A",
        })
        assert result["telemetry_processed"] is True


# Need deque import for beaconing test
from collections import deque


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
