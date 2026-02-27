"""
Tests for QC_REQUIRE_AUTHZ_ACK authorization acknowledgement guardrail.

This guardrail prevents accidental or unauthorized scanning by requiring
an explicit `acknowledge_authorized: true` in all scan request bodies.

Covered endpoints:
  - POST /api/vulns/scan
  - POST /api/vulns/webapp
  - POST /api/v1/scanner/scan   (if live_scanner present)
  - POST /api/v1/one-click/scan-and-fix   (if evolution_engine present)
"""

from __future__ import annotations

import os
import json
import pytest


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _post(client, path, body):
    """POST JSON, return (status, json_body)."""
    rv = client.post(path, data=json.dumps(body), content_type="application/json")
    try:
        data = rv.get_json()
    except Exception:
        data = {}
    return rv.status_code, data or {}


# ═══════════════════════════════════════════════════════════════════════════
#  /api/vulns/scan — Vulnerability Engine Scan
# ═══════════════════════════════════════════════════════════════════════════

class TestVulnsScanAuthzAck:
    """The vuln scan endpoint must require authorization acknowledgement."""

    def test_rejected_without_ack(self, app_factory, monkeypatch):
        monkeypatch.setenv("QC_REQUIRE_AUTHZ_ACK", "1")
        app = app_factory(require_api_key=False)
        status, data = _post(app.test_client(), "/api/vulns/scan", {
            "target": "127.0.0.1",
        })
        assert status == 400
        assert data.get("error") == "authorization_ack_required"

    def test_rejected_with_false_ack(self, app_factory, monkeypatch):
        monkeypatch.setenv("QC_REQUIRE_AUTHZ_ACK", "1")
        app = app_factory(require_api_key=False)
        status, data = _post(app.test_client(), "/api/vulns/scan", {
            "target": "127.0.0.1",
            "acknowledge_authorized": False,
        })
        assert status == 400
        assert data.get("error") == "authorization_ack_required"

    def test_rejected_with_null_ack(self, app_factory, monkeypatch):
        monkeypatch.setenv("QC_REQUIRE_AUTHZ_ACK", "1")
        app = app_factory(require_api_key=False)
        status, data = _post(app.test_client(), "/api/vulns/scan", {
            "target": "127.0.0.1",
            "acknowledge_authorized": None,
        })
        assert status == 400
        assert data.get("error") == "authorization_ack_required"

    def test_accepted_with_true_ack(self, app_factory, monkeypatch):
        monkeypatch.setenv("QC_REQUIRE_AUTHZ_ACK", "1")
        app = app_factory(require_api_key=False)
        status, data = _post(app.test_client(), "/api/vulns/scan", {
            "target": "127.0.0.1",
            "acknowledge_authorized": True,
        })
        # Should pass the authz gate — may still fail on target validation
        assert data.get("error") != "authorization_ack_required"

    def test_still_requires_target(self, app_factory, monkeypatch):
        monkeypatch.setenv("QC_REQUIRE_AUTHZ_ACK", "1")
        app = app_factory(require_api_key=False)
        status, data = _post(app.test_client(), "/api/vulns/scan", {
            "acknowledge_authorized": True,
        })
        assert status == 400
        err = data.get("error", "").lower()
        assert "target" in err or "required" in err


# ═══════════════════════════════════════════════════════════════════════════
#  /api/vulns/webapp — Web Application Scan
# ═══════════════════════════════════════════════════════════════════════════

class TestWebAppScanAuthzAck:
    def test_rejected_without_ack(self, app_factory, monkeypatch):
        monkeypatch.setenv("QC_REQUIRE_AUTHZ_ACK", "1")
        app = app_factory(require_api_key=False)
        status, data = _post(app.test_client(), "/api/vulns/webapp", {
            "url": "https://example.com",
        })
        assert status == 400
        assert data.get("error") == "authorization_ack_required"

    def test_accepted_with_ack(self, app_factory, monkeypatch):
        monkeypatch.setenv("QC_REQUIRE_AUTHZ_ACK", "1")
        app = app_factory(require_api_key=False)
        status, data = _post(app.test_client(), "/api/vulns/webapp", {
            "url": "https://example.com",
            "acknowledge_authorized": True,
        })
        assert data.get("error") != "authorization_ack_required"


# ═══════════════════════════════════════════════════════════════════════════
#  QC_REQUIRE_AUTHZ_ACK=0 — Disabled mode
# ═══════════════════════════════════════════════════════════════════════════

class TestAuthzAckDisabled:
    def test_bypassed_when_disabled(self, app_factory, monkeypatch):
        monkeypatch.setenv("QC_REQUIRE_AUTHZ_ACK", "0")
        app = app_factory(require_api_key=False)
        status, data = _post(app.test_client(), "/api/vulns/scan", {
            "target": "127.0.0.1",
        })
        # Should NOT get authorization_ack_required
        assert data.get("error") != "authorization_ack_required"


# ═══════════════════════════════════════════════════════════════════════════
#  Security Hardening Tests (bug-bounty grade)
# ═══════════════════════════════════════════════════════════════════════════

class TestSecurityHardening:
    """Tests for bug-bounty / TryHackMe competition safety."""

    def test_no_stack_traces_in_404(self, app_factory):
        app = app_factory(require_api_key=False)
        rv = app.test_client().get("/api/nonexistent/endpoint")
        assert rv.status_code == 404
        body = json.dumps(rv.get_json() or {})
        assert "Traceback" not in body
        assert "File " not in body

    def test_no_stack_traces_in_405(self, app_factory):
        app = app_factory(require_api_key=False)
        rv = app.test_client().get("/api/vulns/scan")
        assert rv.status_code == 405
        body = json.dumps(rv.get_json() or {})
        assert "Traceback" not in body

    def test_non_json_body_handled(self, app_factory):
        app = app_factory(require_api_key=False)
        rv = app.test_client().post("/api/vulns/scan", data="not json", content_type="text/plain")
        # Should not crash — may return 400 or 415
        assert rv.status_code in (400, 415)

    def test_public_target_denied_by_default(self, app_factory, monkeypatch):
        monkeypatch.setenv("QC_REQUIRE_AUTHZ_ACK", "1")
        app = app_factory(require_api_key=False)
        status, data = _post(app.test_client(), "/api/vulns/scan", {
            "target": "8.8.8.8",
            "acknowledge_authorized": True,
        })
        # Should be rejected by scan policy (denied by default)
        assert status in (400, 403)
        error_msg = json.dumps(data).lower()
        assert "denied" in error_msg or "not allowed" in error_msg or "error" in error_msg

    def test_health_endpoint_unauthenticated(self, app_factory):
        app = app_factory(require_api_key=True)
        rv = app.test_client().get("/api/health")
        assert rv.status_code == 200

    def test_no_wildcard_cors(self, app_factory):
        app = app_factory(require_api_key=False)
        rv = app.test_client().get("/api/health")
        cors = rv.headers.get("Access-Control-Allow-Origin", "")
        assert cors != "*"

    def test_sensitive_headers_absent(self, app_factory):
        """Response should not leak server version info."""
        app = app_factory(require_api_key=False)
        rv = app.test_client().get("/api/health")
        assert "X-Powered-By" not in rv.headers

    def test_api_key_required_when_enabled(self, app_factory):
        app = app_factory(require_api_key=True)
        status, data = _post(app.test_client(), "/api/vulns/scan", {
            "target": "127.0.0.1",
            "acknowledge_authorized": True,
        })
        assert status == 401 or "auth" in json.dumps(data).lower()

    def test_xss_in_target_sanitized(self, app_factory, monkeypatch):
        """XSS payloads in target should be blocked by input sanitizer."""
        monkeypatch.setenv("QC_REQUIRE_AUTHZ_ACK", "1")
        app = app_factory(require_api_key=False)
        app.testing = False  # Use production error handling
        status, data = _post(app.test_client(), "/api/vulns/scan", {
            "target": "<script>alert(1)</script>",
            "acknowledge_authorized": True,
        })
        body = json.dumps(data)
        # Input sanitizer blocks prohibited patterns — XSS must not be reflected
        assert "<script>" not in body
        assert status in (400, 500)

    def test_path_traversal_in_scan_id(self, app_factory):
        app = app_factory(require_api_key=False)
        rv = app.test_client().get("/api/vulns/scan/../../etc/passwd")
        # Should be a 404, not file disclosure
        assert rv.status_code in (404, 400)

    def test_empty_body_handled(self, app_factory, monkeypatch):
        monkeypatch.setenv("QC_REQUIRE_AUTHZ_ACK", "1")
        app = app_factory(require_api_key=False)
        rv = app.test_client().post("/api/vulns/scan", data="", content_type="application/json")
        assert rv.status_code in (400, 415)
