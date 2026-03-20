#!/usr/bin/env python3
"""
Repeatable live smoke test for Queen Califia CyberAI deployments.

Checks:
- public dashboard entry page is reachable
- backend health/debug/identity routes are live
- market providers are mounted and optionally fully configured
- authz guardrails still protect vulnerability scans
- optional Playwright browser click-through of the live intro -> dashboard path

Examples:
  python scripts/live_smoke.py
  python scripts/live_smoke.py --require-fred --require-nasdaq
  python scripts/live_smoke.py --browser
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any
from urllib import error, parse, request


DEFAULT_DASHBOARD_URL = os.environ.get("QC_DASHBOARD_URL", "https://queencalifia-cyberai.web.app").rstrip("/")
DEFAULT_API_URL = os.environ.get("QC_API_URL", "https://queencalifia-cyberai.onrender.com").rstrip("/")


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


def fetch_json(url: str, method: str = "GET", payload: dict[str, Any] | None = None, timeout: int = 20) -> tuple[int, Any]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(url, method=method, data=data, headers=headers)
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"raw": body}
        return exc.code, parsed


def fetch_text(url: str, timeout: int = 20) -> tuple[int, str]:
    req = request.Request(url, headers={"Accept": "text/html,application/xhtml+xml"})
    with request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", errors="replace")


def add(results: list[Check], name: str, ok: bool, detail: str) -> None:
    results.append(Check(name=name, ok=ok, detail=detail))


def require_source(sources: dict[str, dict[str, Any]], source_id: str, require_configured: bool) -> tuple[bool, str]:
    source = sources.get(source_id)
    if not source:
        return False, f"{source_id} missing from /api/market/sources"
    configured = bool(source.get("configured"))
    if require_configured and not configured:
        return False, f"{source_id} present but not configured"
    return True, f"{source_id} present; configured={configured}"


def run_browser_clickthrough(dashboard_url: str) -> Check:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return Check(
            name="browser_clickthrough",
            ok=False,
            detail="Playwright is not installed. Install with: python -m pip install playwright && python -m playwright install chromium",
        )

    errors: list[str] = []
    console_errors: list[str] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 960})
            page.on("pageerror", lambda err: errors.append(str(err)))
            page.on(
                "console",
                lambda msg: console_errors.append(msg.text)
                if msg.type == "error"
                else None,
            )

            page.goto(dashboard_url, wait_until="domcontentloaded", timeout=30000)
            try:
                page.locator("text=CLICK TO AWAKEN").wait_for(timeout=8000)
                page.get_by_text("CLICK TO AWAKEN").click()
                page.locator("text=ENTER COMMAND").wait_for(timeout=10000)
                page.get_by_role("button", name="ENTER COMMAND").click()
            except Exception:
                # Some deployments may land directly on the dashboard if the intro
                # is bypassed or already completed in the current bundle/runtime.
                pass
            page.locator("text=Strategic Overview").wait_for(timeout=15000)

            browser.close()
    except Exception as exc:
        return Check(name="browser_clickthrough", ok=False, detail=f"click-through failed: {exc}")

    if errors:
        return Check(name="browser_clickthrough", ok=False, detail=f"page errors: {errors}")
    if console_errors:
        return Check(name="browser_clickthrough", ok=False, detail=f"console errors: {console_errors[:5]}")
    return Check(name="browser_clickthrough", ok=True, detail="dashboard loaded via intro or direct landing")


def run_async_scan_gate(api_url: str, timeout: int) -> list[Check]:
    checks: list[Check] = []
    status, queued = fetch_json(
        f"{api_url}/api/vulns/scan",
        method="POST",
        payload={
            "target": "127.0.0.1",
            "scan_type": "full",
            "mode": "async",
            "acknowledge_authorized": True,
        },
        timeout=timeout,
    )
    scan_payload = queued.get("data") if isinstance(queued, dict) else None
    scan_id = None
    if isinstance(scan_payload, dict):
        scan_id = scan_payload.get("scan_id") or scan_payload.get("scanId")

    add(
        checks,
        "async_scan_queued",
        status == 202 and bool(scan_id),
        f"status={status} body={queued}",
    )
    if not scan_id:
        return checks

    deadline = time.monotonic() + max(timeout, 15)
    last_payload: Any = None
    poll_count = 0
    not_found = False
    while time.monotonic() < deadline:
        poll_count += 1
        status, last_payload = fetch_json(f"{api_url}/api/vulns/scan/{parse.quote(scan_id)}", timeout=timeout)
        if status == 404:
            not_found = True
            break
        payload = last_payload.get("data") if isinstance(last_payload, dict) else None
        if isinstance(payload, dict) and (payload.get("ready") or payload.get("state") in {"SUCCESS", "completed"}):
            result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
            add(
                checks,
                "async_scan_completed",
                True,
                f"polls={poll_count} payload={last_payload}",
            )
            add(
                checks,
                "async_scan_id_alignment",
                result.get("scan_id") == scan_id,
                f"outer={scan_id} inner={result.get('scan_id')}",
            )
            return checks
        time.sleep(2)

    if not_found:
        add(
            checks,
            "async_scan_completed",
            False,
            f"scan returned 404 during polling for {scan_id}",
        )
        add(
            checks,
            "async_scan_id_alignment",
            False,
            f"outer={scan_id} inner=None",
        )
        return checks

    add(
        checks,
        "async_scan_completed",
        False,
        f"scan did not reach terminal state before timeout; last={last_payload}",
    )
    add(
        checks,
        "async_scan_id_alignment",
        False,
        f"outer={scan_id} inner={(last_payload.get('data') or {}).get('result', {}).get('scan_id') if isinstance(last_payload, dict) and isinstance(last_payload.get('data'), dict) else None}",
    )
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test a live Queen Califia deployment.")
    parser.add_argument("--dashboard-url", default=DEFAULT_DASHBOARD_URL)
    parser.add_argument("--api-url", default=DEFAULT_API_URL)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--require-fred", action="store_true", help="Fail if FRED is not configured in production.")
    parser.add_argument("--require-nasdaq", action="store_true", help="Fail if Nasdaq Data Link is not configured in production.")
    parser.add_argument("--browser", action="store_true", help="Also run a Playwright click-through of the live dashboard.")
    parser.add_argument("--skip-async-scan", action="store_true", help="Skip the real async scan queue/completion gate.")
    args = parser.parse_args()

    dashboard_url = args.dashboard_url.rstrip("/")
    api_url = args.api_url.rstrip("/")

    results: list[Check] = []

    status, html = fetch_text(dashboard_url, timeout=args.timeout)
    add(
        results,
        "dashboard_entry",
        status == 200 and "<div id=\"root\"></div>" in html and "Queen Califia" in html,
        f"status={status}",
    )

    status, health = fetch_json(f"{api_url}/healthz", timeout=args.timeout)
    add(
        results,
        "api_health",
        status == 200 and health.get("status") == "operational",
        f"status={status} body={health}",
    )

    status, ready = fetch_json(f"{api_url}/readyz", timeout=args.timeout)
    add(
        results,
        "api_ready",
        status == 200 and ready.get("ready") is True,
        f"status={status} body={ready}",
    )

    status, debug_mount = fetch_json(f"{api_url}/api/debug/mount", timeout=args.timeout)
    add(
        results,
        "api_debug_mount",
        status == 200
        and bool(debug_mount.get("has_identity_state"))
        and bool(debug_mount.get("has_market_sources"))
        and bool(debug_mount.get("has_vuln_scan")),
        f"status={status} body={debug_mount}",
    )

    status, identity = fetch_json(f"{api_url}/api/identity/state", timeout=args.timeout)
    add(
        results,
        "identity_state",
        status == 200 and isinstance(identity.get("memory_lanes"), dict) and isinstance(identity.get("storage_contract"), dict),
        f"status={status} pending_items={identity.get('pending_items')}",
    )

    status, market_sources = fetch_json(f"{api_url}/api/market/sources", timeout=args.timeout)
    sources_ok = status == 200 and isinstance(market_sources.get("sources"), list)
    add(results, "market_sources", sources_ok, f"status={status}")

    source_index = {row["id"]: row for row in market_sources.get("sources", []) if isinstance(row, dict)}
    for source_id, required in (("fred_api", args.require_fred), ("nasdaq_data", args.require_nasdaq)):
        ok, detail = require_source(source_index, source_id, require_configured=required)
        add(results, source_id, ok, detail)

    status, provider = fetch_json(f"{api_url}/api/identity/provider-status", timeout=args.timeout)
    add(
        results,
        "provider_status",
        status == 200 and provider.get("current", {}).get("provider") in {"local_symbolic_core", "ollama", "vllm_local", "auto"},
        f"status={status} current={provider.get('current')}",
    )

    status, missions = fetch_json(f"{api_url}/api/identity/missions", timeout=args.timeout)
    add(
        results,
        "missions",
        status == 200 and isinstance(missions.get("items"), list),
        f"status={status} count={len(missions.get('items', [])) if isinstance(missions, dict) else 'n/a'}",
    )

    status, scan_guardrail = fetch_json(
        f"{api_url}/api/vulns/scan",
        method="POST",
        payload={"target": "127.0.0.1"},
        timeout=args.timeout,
    )
    add(
        results,
        "scan_authz_guardrail",
        status == 400 and scan_guardrail.get("error") == "authorization_ack_required",
        f"status={status} body={scan_guardrail}",
    )

    if not args.skip_async_scan:
        results.extend(run_async_scan_gate(api_url, timeout=args.timeout))

    if args.browser:
        results.append(run_browser_clickthrough(dashboard_url))

    print(f"Dashboard URL: {dashboard_url}")
    print(f"API URL: {api_url}")
    print("")
    failures = 0
    for item in results:
        state = "PASS" if item.ok else "FAIL"
        print(f"[{state}] {item.name}: {item.detail}")
        if not item.ok:
            failures += 1

    print("")
    if failures:
        print(f"Smoke test failed with {failures} failing checks.")
        return 1
    print("Smoke test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
