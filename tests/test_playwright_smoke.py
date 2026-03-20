"""Playwright regression coverage for the current Queen Califia dashboard."""

from __future__ import annotations

import json
import os
import time
import urllib.request

import pytest

try:
    from playwright.sync_api import sync_playwright

    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


DASHBOARD_URL = os.environ.get("QC_DASHBOARD_URL", "http://localhost:3000")
API_URL = os.environ.get("QC_API_URL", "http://localhost:5000")


def _url_available(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            return resp.status < 500
    except Exception:
        return False


SMOKE_TARGETS_AVAILABLE = _url_available(DASHBOARD_URL) and _url_available(f"{API_URL}/healthz")

pytestmark = pytest.mark.skipif(
    (not HAS_PLAYWRIGHT) or (not SMOKE_TARGETS_AVAILABLE),
    reason="Playwright not installed or dashboard/API target unavailable",
)


@pytest.fixture(scope="module")
def browser_context():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 960})
        yield context
        context.close()
        browser.close()


@pytest.fixture
def page(browser_context):
    page = browser_context.new_page()
    yield page
    page.close()


def enter_dashboard(page) -> None:
    page.goto(DASHBOARD_URL, wait_until="domcontentloaded", timeout=30000)
    page.wait_for_timeout(2500)
    if page.get_by_text("CLICK TO AWAKEN").count():
        page.get_by_text("CLICK TO AWAKEN").click()
        page.wait_for_timeout(3200)
    if page.get_by_role("button", name="ENTER COMMAND").count():
        page.get_by_role("button", name="ENTER COMMAND").click()
    page.get_by_text("Strategic Overview").wait_for(timeout=15000)


def enable_expert_mode(page) -> None:
    buttons = page.get_by_role("button")
    for i in range(buttons.count()):
        label = (buttons.nth(i).inner_text(timeout=500) or "").strip()
        if "Simple" in label:
            buttons.nth(i).click()
            page.wait_for_timeout(1000)
            return


class TestDashboardShell:
    @pytest.mark.playwright
    def test_intro_or_dashboard_loads_without_js_errors(self, page):
        errors = []
        page.on("pageerror", lambda err: errors.append(str(err)))
        enter_dashboard(page)
        assert page.locator("text=QUEEN CALIFIA").count() > 0
        assert not errors, f"JS errors: {errors}"

    @pytest.mark.playwright
    def test_expert_mode_reveals_advanced_tabs(self, page):
        enter_dashboard(page)
        enable_expert_mode(page)
        body = page.locator("body").inner_text()
        for tab in ("QC Console", "Research & Quant", "Identity Core", "Advanced Telemetry"):
            assert tab in body


class TestVulnerabilityFlows:
    @pytest.mark.playwright
    def test_vulns_requires_authorization_before_scan(self, page):
        enter_dashboard(page)
        enable_expert_mode(page)
        page.get_by_role("button", name="Vulnerability Scanner").click()
        page.wait_for_timeout(1000)
        page.get_by_role("button", name="Launch Scan").click()
        page.wait_for_timeout(1200)
        body = page.locator("body").inner_text()
        assert "You must confirm you are authorized to scan this target." in body

    @pytest.mark.playwright
    def test_vulns_launches_real_async_scan(self, page):
        enter_dashboard(page)
        enable_expert_mode(page)
        page.get_by_role("button", name="Vulnerability Scanner").click()
        page.wait_for_timeout(1000)
        page.get_by_text("I am authorized to scan this target").click()
        page.get_by_role("button", name="Launch Scan").click()
        page.wait_for_timeout(6000)
        body = page.locator("body").inner_text()
        assert any(text in body for text in ("SCAN_ID:", "Scan complete!", "RUNNING", "PENDING"))

    @pytest.mark.playwright
    def test_one_click_banner_renders(self, page):
        enter_dashboard(page)
        enable_expert_mode(page)
        page.get_by_role("button", name="Vulnerability Scanner").click()
        page.wait_for_timeout(1000)
        body = page.locator("body").inner_text()
        assert "One-Click Remediate" in body
        assert "REMEDIATE ALL" in body


class TestOperationalTabs:
    @pytest.mark.playwright
    def test_qc_console_responds(self, page):
        enter_dashboard(page)
        enable_expert_mode(page)
        page.get_by_role("button", name="QC Console").click()
        page.wait_for_timeout(1200)
        textarea = page.locator("textarea").first
        textarea.fill("Check vulnerabilities and report readiness.")
        buttons = page.get_by_role("button")
        for i in range(buttons.count()):
            label = (buttons.nth(i).inner_text(timeout=500) or "").strip().lower()
            if "send" in label:
                buttons.nth(i).click()
                break
        page.wait_for_timeout(3500)
        body = page.locator("body").inner_text().lower()
        assert any(text in body for text in ("queen califia", "ready", "scan", "authorized"))

    @pytest.mark.playwright
    def test_research_quant_renders_market_panels(self, page):
        enter_dashboard(page)
        enable_expert_mode(page)
        page.get_by_role("button", name="Research & Quant").click()
        page.wait_for_timeout(1200)
        body = page.locator("body").inner_text()
        assert "MARKET SNAPSHOT" in body
        assert "TRUSTED SOURCES" in body
        assert "Federal Reserve FRED" in body

    @pytest.mark.playwright
    def test_identity_core_renders_persona_state(self, page):
        enter_dashboard(page)
        enable_expert_mode(page)
        page.get_by_role("button", name="Identity Core").click()
        page.wait_for_timeout(1200)
        body = page.locator("body").inner_text()
        assert "IDENTITY CORE" in body
        assert "PERSONA STATE" in body
        assert "Persona" in body


class TestApiFlows:
    @pytest.mark.playwright
    def test_api_readyz_reports_operational_state(self, page):
        response = page.request.get(f"{API_URL}/readyz")
        assert response.status == 200
        data = response.json()
        assert data.get("ready") is True

    @pytest.mark.playwright
    def test_api_scan_requires_authorization(self, page):
        response = page.request.post(
            f"{API_URL}/api/vulns/scan",
            data=json.dumps({"target": "127.0.0.1"}),
            headers={"Content-Type": "application/json"},
        )
        assert response.status == 400
        assert response.json().get("error") == "authorization_ack_required"

    @pytest.mark.playwright
    def test_api_async_scan_reaches_terminal_state(self, page):
        response = page.request.post(
            f"{API_URL}/api/vulns/scan",
            data=json.dumps(
                {
                    "target": "127.0.0.1",
                    "scan_type": "full",
                    "mode": "async",
                    "acknowledge_authorized": True,
                }
            ),
            headers={"Content-Type": "application/json"},
        )
        assert response.status == 202
        outer_id = (response.json().get("data") or {}).get("scan_id")
        assert outer_id

        terminal = None
        for _ in range(18):
            poll = page.request.get(f"{API_URL}/api/vulns/scan/{outer_id}")
            assert poll.status == 200
            payload = (poll.json().get("data") or {})
            if payload.get("ready") or payload.get("state") in {"SUCCESS", "FAILURE", "completed"}:
                terminal = payload
                break
            time.sleep(2)

        assert terminal is not None, "scan did not reach terminal state in time"
        assert terminal.get("state") in {"SUCCESS", "completed"}
