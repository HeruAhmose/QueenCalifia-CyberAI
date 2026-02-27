"""Tests for LiveScanner and AutoRemediation engines."""

import json
import time
import http.server
import threading
import pytest

from engines.live_scanner import (
    LiveScanner, LiveScanner as LS, Severity, ServiceInfo, Finding,
    HostResult, ScanReport, COMMON_PORTS, HTTP_SECURITY_HEADERS,
    SERVICE_CVE_PATTERNS, QUANTUM_VULNERABLE_CIPHERS,
)
from engines.auto_remediation import (
    AutoRemediation, RemediationAction, RemediationPlan,
    RemediationMode, RemediationStatus, Platform,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def http_server():
    """Start a real HTTP server for testing"""
    server = http.server.HTTPServer(("127.0.0.1", 18899), http.server.SimpleHTTPRequestHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    yield server
    server.shutdown()


@pytest.fixture
def scanner():
    return LiveScanner({"deny_public": False, "db_path": "/tmp/qc_test_scans.db"})


@pytest.fixture
def remediator():
    return AutoRemediation({"mode": "preview"})


# ─── LiveScanner Tests ───────────────────────────────────────────────────────

class TestLiveScannerInit:
    def test_init_defaults(self, scanner):
        assert scanner.max_threads == 50
        assert scanner.scan_mode == "full"
        assert scanner.port_timeout == 1.5

    def test_status(self, scanner):
        status = scanner.get_status()
        assert status["engine"] == "LiveScanner"
        assert status["version"] == "3.1"
        assert status["quantum_audit"] is True
        assert status["drift_detection"] is True
        assert status["learning"] is True

    def test_allowlist_default_private(self):
        s = LiveScanner({"db_path": "/tmp/qc_test2.db"})
        # Should allow private IPs
        s._assert_target_allowed("192.168.1.1")
        s._assert_target_allowed("10.0.0.1")
        s._assert_target_allowed("172.16.0.1")

    def test_allowlist_blocks_public(self):
        s = LiveScanner({"db_path": "/tmp/qc_test3.db"})
        with pytest.raises(PermissionError, match="Public IP"):
            s._assert_target_allowed("8.8.8.8")

    def test_allowlist_custom(self):
        s = LiveScanner({"scan_allowlist": "192.168.1.0/24", "db_path": "/tmp/qc_test4.db"})
        s._assert_target_allowed("192.168.1.50")
        with pytest.raises(PermissionError):
            s._assert_target_allowed("10.0.0.1")


class TestTargetResolution:
    def test_resolve_single_ip(self, scanner):
        targets = scanner._resolve_targets("127.0.0.1")
        assert targets == ["127.0.0.1"]

    def test_resolve_cidr(self, scanner):
        targets = scanner._resolve_targets("127.0.0.0/30")
        assert len(targets) == 2  # .1 and .2 (hosts only)

    def test_resolve_hostname(self, scanner):
        targets = scanner._resolve_targets("localhost")
        assert len(targets) >= 1
        assert targets[0] == "127.0.0.1"

    def test_resolve_invalid(self, scanner):
        targets = scanner._resolve_targets("nonexistent.invalid.tld")
        assert targets == []


class TestPortScanning:
    def test_scan_open_port(self, scanner, http_server):
        open_ports = scanner._scan_ports("127.0.0.1", [18899], "quick")
        assert 18899 in open_ports

    def test_scan_closed_port(self, scanner):
        open_ports = scanner._scan_ports("127.0.0.1", [19999], "quick")
        assert 19999 not in open_ports


class TestBannerGrabbing:
    def test_grab_http_banner(self, scanner, http_server):
        svc = scanner._grab_banner("127.0.0.1", 18899)
        # Port 18899 isn't standard, but banner should contain HTTP data
        assert svc.port == 18899
        assert len(svc.banner) > 0
        assert "HTTP" in svc.banner or svc.service == "http"

    def test_closed_port_banner(self, scanner):
        svc = scanner._grab_banner("127.0.0.1", 19999)
        assert "connect failed" in svc.banner or svc.banner == ""


class TestServiceIdentification:
    def test_identify_ssh(self, scanner):
        svc = ServiceInfo(port=22)
        scanner._identify_service(svc, "SSH-2.0-OpenSSH_9.6")
        assert svc.service == "ssh"
        assert "OpenSSH" in svc.version

    def test_identify_apache(self, scanner):
        svc = ServiceInfo(port=80)
        scanner._identify_service(svc, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.58")
        assert svc.service == "http"
        assert "Apache" in svc.version

    def test_identify_nginx(self, scanner):
        svc = ServiceInfo(port=80)
        scanner._identify_service(svc, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0")
        assert svc.service == "http"
        assert "nginx" in svc.version

    def test_identify_redis(self, scanner):
        svc = ServiceInfo(port=6379)
        scanner._identify_service(svc, "redis_version:7.2.4\r\nredis_mode:standalone")
        assert svc.service == "redis"
        assert "7.2.4" in svc.version

    def test_identify_ftp(self, scanner):
        svc = ServiceInfo(port=21)
        scanner._identify_service(svc, "220 (vsFTPd 3.0.5)")
        assert svc.service == "ftp"

    def test_identify_by_port_fallback(self, scanner):
        svc = ServiceInfo(port=3389)
        scanner._identify_service(svc, "")
        assert svc.service == "rdp"


class TestHTTPAnalysis:
    def test_http_security_headers(self, scanner, http_server):
        findings = scanner._analyze_http("127.0.0.1", 18899)
        assert len(findings) > 0
        header_names = [f.title for f in findings]
        assert any("Strict-Transport-Security" in h for h in header_names)
        assert any("Content-Security-Policy" in h for h in header_names)

    def test_findings_have_remediation(self, scanner, http_server):
        findings = scanner._analyze_http("127.0.0.1", 18899)
        for f in findings:
            assert f.remediation != ""
            assert f.affected_asset == "127.0.0.1"

    def test_info_disclosure_detection(self, scanner, http_server):
        findings = scanner._analyze_http("127.0.0.1", 18899)
        server_findings = [f for f in findings if "Information Disclosure" in f.title]
        assert len(server_findings) > 0  # SimpleHTTPServer sends Server header


class TestCVECorrelation:
    def test_openssh_cve_match(self, scanner):
        svc = ServiceInfo(port=22, service="ssh", version="SSH-2.0-OpenSSH_8.9")
        findings = scanner._correlate_cves("10.0.0.1", 22, svc)
        assert len(findings) > 0
        cve_ids = [f.cve_id for f in findings]
        assert any("CVE-2024-6387" in c for c in cve_ids)  # regreSSHion

    def test_no_match_for_latest(self, scanner):
        svc = ServiceInfo(port=22, service="ssh", version="SSH-2.0-OpenSSH_99.0")
        findings = scanner._correlate_cves("10.0.0.1", 22, svc)
        assert len(findings) == 0


class TestServiceRiskAssessment:
    def test_cleartext_ftp(self, scanner):
        services = {21: ServiceInfo(port=21, service="ftp")}
        findings = scanner._assess_service_risks("10.0.0.1", services)
        assert any("Cleartext" in f.title for f in findings)

    def test_exposed_rdp(self, scanner):
        services = {3389: ServiceInfo(port=3389, service="rdp")}
        findings = scanner._assess_service_risks("10.0.0.1", services)
        assert any("RDP" in f.title for f in findings)

    def test_exposed_smb(self, scanner):
        services = {445: ServiceInfo(port=445, service="smb")}
        findings = scanner._assess_service_risks("10.0.0.1", services)
        assert any("SMB" in f.title for f in findings)

    def test_redis_no_auth(self, scanner):
        services = {6379: ServiceInfo(port=6379, service="redis", banner="redis_version:7.0.0")}
        findings = scanner._assess_service_risks("10.0.0.1", services)
        assert any("Redis" in f.title for f in findings)


class TestQuantumAssessment:
    def test_quantum_vulnerable_cipher(self, scanner):
        services = {443: ServiceInfo(
            port=443, tls_enabled=True, tls_cipher="ECDHE-RSA-AES256-GCM-SHA384",
            quantum_vulnerable=True, quantum_risk_reason="ECDHE-RSA vulnerable to Shor's"
        )}
        findings = scanner._assess_quantum_risk("10.0.0.1", services)
        assert any("Quantum" in f.title for f in findings)

    def test_quantum_safe_tls13(self, scanner):
        services = {443: ServiceInfo(
            port=443, tls_enabled=True, tls_cipher="TLS_AES_256_GCM_SHA384",
            quantum_vulnerable=False
        )}
        findings = scanner._assess_quantum_risk("10.0.0.1", services)
        quantum_findings = [f for f in findings if "Quantum" in f.title]
        assert len(quantum_findings) == 0

    def test_expired_cert_detection(self, scanner):
        services = {443: ServiceInfo(
            port=443, tls_enabled=True, tls_cert_subject="example.com",
            tls_cert_days_remaining=0, tls_cert_expires="Jan 01 2024"
        )}
        findings = scanner._assess_quantum_risk("10.0.0.1", services)
        assert any("EXPIRED" in f.title for f in findings)


class TestRiskCalculation:
    def test_no_findings_zero_risk(self, scanner):
        host = HostResult(ip="10.0.0.1")
        assert scanner._calculate_risk(host) == 0.0

    def test_critical_finding_high_risk(self, scanner):
        host = HostResult(ip="10.0.0.1", findings=[
            Finding(severity="CRITICAL", cvss_score=9.8)
        ])
        risk = scanner._calculate_risk(host)
        assert risk >= 9.0

    def test_multiple_findings_bonus(self, scanner):
        findings = [Finding(severity="LOW", cvss_score=3.0) for _ in range(10)]
        host = HostResult(ip="10.0.0.1", findings=findings)
        risk = scanner._calculate_risk(host)
        assert risk > 3.0  # Should have count bonus


class TestFullScanPipeline:
    def test_full_scan_localhost(self, scanner, http_server):
        report = scanner.scan("127.0.0.1", scan_type="quick", ports=[18899])
        assert report.total_hosts_alive >= 1
        assert report.total_open_ports >= 1
        assert report.total_findings > 0
        assert report.duration_seconds > 0
        assert report.scan_id != ""

    def test_scan_report_structure(self, scanner, http_server):
        report = scanner.scan("127.0.0.1", scan_type="quick", ports=[18899])
        d = report.to_dict()
        assert "scan_id" in d
        assert "hosts" in d
        assert "total_findings" in d
        assert "overall_risk" in d
        assert "quantum_risk_summary" in d

    def test_scan_persistence(self, scanner, http_server):
        report = scanner.scan("127.0.0.1", scan_type="quick", ports=[18899])
        retrieved = scanner.get_scan(report.scan_id)
        assert retrieved is not None
        assert retrieved["scan_id"] == report.scan_id


class TestLearning:
    def test_baseline_created(self, scanner, http_server):
        scanner.scan("127.0.0.1", scan_type="quick", ports=[18899])
        baselines = scanner.get_baselines()
        assert len(baselines) >= 1
        assert baselines[0]["host_ip"] == "127.0.0.1"

    def test_findings_persisted(self, scanner, http_server):
        scanner.scan("127.0.0.1", scan_type="quick", ports=[18899])
        findings = scanner.get_all_findings()
        assert len(findings) > 0


# ─── AutoRemediation Tests ───────────────────────────────────────────────────

class TestRemediationInit:
    def test_init_defaults(self, remediator):
        assert remediator.default_mode == RemediationMode.PREVIEW
        assert remediator.allow_execute is True

    def test_status(self, remediator):
        status = remediator.get_status()
        assert status["engine"] == "AutoRemediation"
        assert status["version"] == "3.1"


class TestPlanGeneration:
    def test_generate_plan_missing_headers(self, remediator):
        findings = [{
            "finding_id": "QC-TEST001",
            "title": "Missing Security Header: X-Frame-Options",
            "severity": "MEDIUM",
            "category": "web_security",
            "port": 443,
            "affected_component": "https://10.0.0.1:443",
            "remediation": "Add X-Frame-Options header",
        }]
        plan = remediator.generate_plan(findings)
        assert plan.total_actions >= 1
        assert plan.actions[0].category == "web_hardening"
        assert len(plan.actions[0].commands) > 0

    def test_generate_plan_firewall(self, remediator):
        findings = [{
            "finding_id": "QC-TEST002",
            "title": "RDP Exposed to Network",
            "severity": "HIGH",
            "category": "exposed_service",
            "port": 3389,
            "affected_component": "RDP",
            "remediation": "Restrict RDP via VPN",
        }]
        plan = remediator.generate_plan(findings)
        fw_actions = [a for a in plan.actions if a.category == "firewall"]
        assert len(fw_actions) >= 1
        assert any("3389" in str(a.commands) for a in fw_actions)

    def test_generate_plan_redis_hardening(self, remediator):
        findings = [{
            "finding_id": "QC-TEST003",
            "title": "Redis Exposed Without Authentication",
            "severity": "CRITICAL",
            "category": "no_auth",
            "port": 6379,
            "affected_component": "Redis",
            "remediation": "Set requirepass",
        }]
        plan = remediator.generate_plan(findings)
        redis_actions = [a for a in plan.actions if "redis" in a.title.lower()]
        assert len(redis_actions) >= 1
        assert any("requirepass" in str(a.commands) for a in redis_actions)

    def test_generate_plan_cve(self, remediator):
        findings = [{
            "finding_id": "QC-TEST004",
            "title": "CVE-2024-6387: regreSSHion",
            "severity": "HIGH",
            "category": "cve_match",
            "port": 22,
            "affected_component": "OpenSSH 8.9",
            "remediation": "Upgrade OpenSSH to 9.8+",
            "cve_id": "CVE-2024-6387",
        }]
        plan = remediator.generate_plan(findings)
        upgrade_actions = [a for a in plan.actions if a.category == "service_upgrade"]
        assert len(upgrade_actions) >= 1

    def test_plan_has_rollback(self, remediator):
        findings = [{
            "finding_id": "QC-TEST005",
            "title": "Missing Security Header: HSTS",
            "severity": "HIGH",
            "category": "web_security",
            "port": 443,
            "affected_component": "HTTPS",
            "remediation": "Add HSTS",
        }]
        plan = remediator.generate_plan(findings)
        for action in plan.actions:
            if action.category == "web_hardening":
                assert len(action.rollback_commands) > 0

    def test_plan_persistence(self, remediator):
        plan = remediator.generate_plan([{
            "finding_id": "QC-TEST006", "title": "Test", "severity": "LOW",
            "category": "manual", "port": 0, "affected_component": "",
            "remediation": "test",
        }])
        retrieved = remediator.get_plan(plan.plan_id)
        assert retrieved is not None
        assert retrieved["plan_id"] == plan.plan_id


class TestRemediationActions:
    def test_action_serialization(self):
        action = RemediationAction(
            title="Test Action",
            commands=["echo hello"],
            rollback_commands=["echo rollback"],
        )
        d = action.to_dict()
        assert d["title"] == "Test Action"
        assert "echo hello" in d["commands"]

    def test_plan_serialization(self):
        plan = RemediationPlan(actions=[
            RemediationAction(title="A1"),
            RemediationAction(title="A2"),
        ])
        plan.total_actions = 2
        d = plan.to_dict()
        assert len(d["actions"]) == 2
        assert d["total_actions"] == 2


class TestApproval:
    def test_approve_action(self, remediator):
        plan = remediator.generate_plan([{
            "finding_id": "QC-APPROVE", "title": "Test", "severity": "LOW",
            "category": "web_security", "port": 80,
            "affected_component": "", "remediation": "test",
        }])
        if plan.actions:
            result = remediator.approve_action(plan.plan_id, plan.actions[0].action_id, "tester")
            assert result.get("status") == "approved" or "approved_by" in result


# ─── Integration Test ────────────────────────────────────────────────────────

class TestEndToEnd:
    def test_scan_then_remediate(self, scanner, remediator, http_server):
        """Full pipeline: scan → findings → remediation plan"""
        report = scanner.scan("127.0.0.1", scan_type="quick", ports=[18899])
        assert report.total_findings > 0

        # Get findings as dicts
        findings = scanner.get_all_findings()
        assert len(findings) > 0

        # Generate plan
        plan = remediator.generate_plan(findings)
        assert plan.total_actions > 0

        # Verify plan has actionable commands
        for action in plan.actions:
            assert action.title != ""
            assert action.category != ""
