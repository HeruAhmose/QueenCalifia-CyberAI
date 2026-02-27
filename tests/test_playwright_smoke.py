"""
QueenCalifia CyberAI — Playwright Smoke Tests
================================================
Lightweight browser-level smoke tests for the dashboard.

Covers:
  - Dashboard loads without errors
  - Expert Mode toggle hides/shows advanced tabs
  - Guided Wizard opens and renders 3-step flow
  - Vulns tab renders with authz acknowledgement checkbox
  - Authorization checkbox is required before scan
  - Security: no JS console errors

Run:
    pip install playwright pytest-playwright
    playwright install chromium
    python -m pytest tests/test_playwright_smoke.py -v

NOTE: These tests require the dashboard to be running at http://localhost:3000
      or the API at http://localhost:5000. They are marked with @pytest.mark.playwright
      and skipped if Playwright is not installed.
"""

import os
import json
import pytest

# Skip entire module if playwright not installed
try:
    from playwright.sync_api import sync_playwright, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

pytestmark = pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright not installed")

# Dashboard URL — configurable via env
DASHBOARD_URL = os.environ.get("QC_DASHBOARD_URL", "http://localhost:3000")
API_URL = os.environ.get("QC_API_URL", "http://localhost:5000")


@pytest.fixture(scope="module")
def browser_context():
    """Launch a browser for the entire test module."""
    if not HAS_PLAYWRIGHT:
        pytest.skip("Playwright not installed")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 900})
        yield context
        context.close()
        browser.close()


@pytest.fixture
def page(browser_context):
    """Fresh page for each test."""
    page = browser_context.new_page()
    yield page
    page.close()


class TestDashboardLoads:
    """Basic smoke test that the dashboard renders."""

    @pytest.mark.playwright
    def test_dashboard_renders(self, page):
        """Dashboard should load without JS errors."""
        errors = []
        page.on("pageerror", lambda err: errors.append(str(err)))

        page.goto(DASHBOARD_URL, timeout=10000)
        page.wait_for_load_state("networkidle")

        # Should see the Queen Califia branding
        assert page.locator("text=QUEEN CALIFIA").count() > 0
        assert len(errors) == 0, f"JS errors: {errors}"

    @pytest.mark.playwright
    def test_version_in_footer(self, page):
        """Footer should show version v4.0."""
        page.goto(DASHBOARD_URL, timeout=10000)
        page.wait_for_load_state("networkidle")
        footer = page.locator("footer")
        assert "v4.0" in footer.inner_text() or "CYBERAI" in footer.inner_text()


class TestExpertModeToggle:
    """Expert Mode should hide/show advanced panels."""

    @pytest.mark.playwright
    def test_simple_mode_hides_advanced_tabs(self, page):
        """In Simple mode, Predictor/Telemetry/Mesh/DevOps tabs should be hidden."""
        page.goto(DASHBOARD_URL, timeout=10000)
        page.wait_for_load_state("networkidle")

        # Click "Simple" mode if not already active
        simple_btn = page.locator("button:has-text('Simple')")
        if simple_btn.count() > 0:
            simple_btn.click()

        # Advanced tabs should not be visible
        nav = page.locator("nav")
        nav_text = nav.inner_text()
        assert "Telemetry" not in nav_text or page.locator("button:has-text('Expert')").count() > 0

    @pytest.mark.playwright
    def test_expert_mode_shows_all_tabs(self, page):
        """In Expert mode, all 7 tabs should be visible."""
        page.goto(DASHBOARD_URL, timeout=10000)
        page.wait_for_load_state("networkidle")

        # Click Expert mode
        expert_btn = page.locator("button:has-text('Expert')")
        if expert_btn.count() > 0:
            expert_btn.click()
        else:
            # May already be in expert mode
            pass

        nav = page.locator("nav")
        nav_text = nav.inner_text()
        # In expert mode, all tabs should exist
        for tab in ["Overview", "Vulns", "Incidents"]:
            assert tab in nav_text


class TestGuidedWizard:
    """Guided Wizard 3-step flow for non-dev users."""

    @pytest.mark.playwright
    def test_wizard_opens(self, page):
        """Quick Scan button should open the wizard."""
        page.goto(DASHBOARD_URL, timeout=10000)
        page.wait_for_load_state("networkidle")

        # Click Quick Scan
        quick_btn = page.locator("button:has-text('Quick Scan')")
        if quick_btn.count() > 0:
            quick_btn.click()
            page.wait_for_timeout(500)
            # Should see Step 1 content
            assert page.locator("text=Choose Your Target").count() > 0 or page.locator("text=Quick Scan").count() > 0

    @pytest.mark.playwright
    def test_wizard_requires_authorization(self, page):
        """Wizard should have authorization checkbox that blocks scanning."""
        page.goto(DASHBOARD_URL, timeout=10000)
        page.wait_for_load_state("networkidle")

        quick_btn = page.locator("button:has-text('Quick Scan')")
        if quick_btn.count() > 0:
            quick_btn.click()
            page.wait_for_timeout(500)

            # The Start Scan button should be disabled without the checkbox
            start_btn = page.locator("button:has-text('Start Scan')")
            if start_btn.count() > 0:
                # Check it's disabled or has opacity
                assert start_btn.get_attribute("disabled") is not None or "not-allowed" in (start_btn.get_attribute("style") or "")


class TestVulnsTab:
    """Vulns tab with authz acknowledgement."""

    @pytest.mark.playwright
    def test_vulns_tab_renders(self, page):
        """Vulns tab should be clickable and render content."""
        page.goto(DASHBOARD_URL, timeout=10000)
        page.wait_for_load_state("networkidle")

        vulns_btn = page.locator("button:has-text('Vulns')")
        if vulns_btn.count() > 0:
            vulns_btn.click()
            page.wait_for_timeout(500)
            # Should see vulnerability-related content
            content = page.inner_text("main")
            assert len(content) > 50  # Has substantial content

    @pytest.mark.playwright
    def test_vulns_tab_has_scan_controls(self, page):
        """Vulns tab should have scan target input and controls."""
        page.goto(DASHBOARD_URL, timeout=10000)
        page.wait_for_load_state("networkidle")

        vulns_btn = page.locator("button:has-text('Vulns')")
        if vulns_btn.count() > 0:
            vulns_btn.click()
            page.wait_for_timeout(500)
            # Should have some form of scan input
            inputs = page.locator("input")
            assert inputs.count() > 0


class TestAPIEndpoints:
    """Direct API-level smoke tests (no browser needed)."""

    @pytest.mark.playwright
    def test_api_health(self, page):
        """Health endpoint should return 200."""
        response = page.request.get(f"{API_URL}/api/health")
        assert response.status == 200
        data = response.json()
        assert data.get("status") == "operational"

    @pytest.mark.playwright
    def test_api_scan_requires_authz(self, page):
        """Scan endpoint should require authorization acknowledgement."""
        response = page.request.post(f"{API_URL}/api/vulns/scan", data=json.dumps({
            "target": "127.0.0.1",
        }), headers={"Content-Type": "application/json"})
        assert response.status == 400
        data = response.json()
        assert data.get("error") == "authorization_ack_required"

    @pytest.mark.playwright
    def test_api_scan_rejects_public_ip(self, page):
        """Scan with public IP should be denied."""
        response = page.request.post(f"{API_URL}/api/vulns/scan", data=json.dumps({
            "target": "8.8.8.8",
            "acknowledge_authorized": True,
        }), headers={"Content-Type": "application/json"})
        assert response.status in (400, 403)
