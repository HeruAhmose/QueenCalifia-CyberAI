#!/usr/bin/env python3
"""
QueenCalifia CyberAI — Command Line Interface
===============================================
One-command network scanning and remediation.

Usage:
    python cli.py scan 192.168.1.0/24          # Full network scan
    python cli.py scan 192.168.1.1 --quick     # Quick scan single host
    python cli.py scan-web https://example.com  # Web application scan
    python cli.py findings                      # List all open findings
    python cli.py remediate                     # Generate remediation plan
    python cli.py remediate --execute           # Execute remediation (with confirmation)
    python cli.py status                        # System status
    python cli.py baselines                     # Show learned network baselines
    python cli.py history                       # Scan history
    python cli.py monitor 192.168.1.0/24        # Continuous monitoring (re-scans every N minutes)

Environment:
    QC_SCAN_ALLOWLIST   Comma-separated CIDRs (default: private ranges)
    QC_SCAN_THREADS     Max parallel threads (default: 50)
    QC_SCAN_MODE        full|quick|stealth (default: full)
    NVD_API_KEY         NVD API key for CVE enrichment
"""

import os
import sys
import json
import time
import signal
import argparse
from datetime import datetime, timezone

# ─── Colors ──────────────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_CYAN = "\033[46m"


def severity_color(sev):
    return {
        "CRITICAL": C.BG_RED + C.WHITE,
        "HIGH": C.RED,
        "MEDIUM": C.YELLOW,
        "LOW": C.BLUE,
        "INFO": C.DIM,
    }.get(sev.upper(), C.DIM)


def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   🛡  QUEEN CALIFIA CyberAI  v4.0                        ║
    ║   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                        ║
    ║   Autonomous Threat Intelligence Platform                 ║
    ║   Tamerian Materials • Defense-Grade Security             ║
    ║                                                           ║
    ║   ⚡ One-Command Scan + Fix    🧬 Self-Evolving           ║
    ║   🕷  Spider Web Mesh          🧠 Self-Learning           ║
    ║   🔮 Zero-Day Predictor        🔧 Self-Repairing         ║
    ║   ⚛️  Quantum-Ready             🎯 Live Scanner            ║
    ║   🟣 Purple Team               🔵 Blue Team SOAR         ║
    ║   🔴 Red Team Simulation       📡 Threat Intel            ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
{C.RESET}""")


def print_section(title, icon="═"):
    width = 60
    print(f"\n{C.CYAN}{'═' * width}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {title}{C.RESET}")
    print(f"{C.CYAN}{'═' * width}{C.RESET}\n")


def print_finding(f, index=None):
    sev = f.get("severity", "INFO")
    sc = severity_color(sev)
    prefix = f"  [{index}]" if index is not None else "  •"
    cvss = f.get("cvss_score", 0)
    cve = f.get("cve_id", "")
    cve_str = f" ({cve})" if cve else ""

    print(f"{prefix} {sc}{C.BOLD} {sev:8s} {C.RESET} {f.get('title', 'Unknown')}{cve_str}")
    print(f"      CVSS: {cvss:.1f} │ Asset: {f.get('affected_asset', '?')} │ Port: {f.get('port', '?')}")
    if f.get("evidence"):
        print(f"      {C.DIM}Evidence: {f['evidence'][:100]}{C.RESET}")
    if f.get("remediation"):
        print(f"      {C.GREEN}Fix: {f['remediation'][:120]}{C.RESET}")
    print()


def print_host(host, index):
    risk = host.get("risk_score", 0)
    risk_color = C.RED if risk >= 7 else C.YELLOW if risk >= 4 else C.GREEN
    qr = host.get("quantum_readiness", "unknown")
    qr_icon = "⚠️" if qr == "at_risk" else "✓"

    print(f"  {C.BOLD}[{index}] {host['ip']}{C.RESET}", end="")
    if host.get("hostname"):
        print(f" ({host['hostname']})", end="")
    print(f"  │  OS: {host.get('os_guess', '?')} ({host.get('os_confidence', 0)*100:.0f}%)")
    print(f"      Risk: {risk_color}{risk:.1f}/10{C.RESET} │ Ports: {len(host.get('open_ports', []))} │ Findings: {len(host.get('findings', []))} │ Quantum: {qr_icon} {qr}")

    # Show open ports and services
    services = host.get("services", {})
    if services:
        port_strs = []
        for p, svc in sorted(services.items(), key=lambda x: int(x[0])):
            name = svc.get("service", "?")
            ver = svc.get("version", "")
            tls = " 🔒" if svc.get("tls_enabled") else ""
            qv = " ⚛️" if svc.get("quantum_vulnerable") else ""
            ver_str = f" ({ver})" if ver and ver != "unknown" else ""
            port_strs.append(f"{p}/{name}{ver_str}{tls}{qv}")
        print(f"      Services: {', '.join(port_strs[:8])}")
        if len(port_strs) > 8:
            print(f"                ...and {len(port_strs) - 8} more")
    print()


# ─── Commands ────────────────────────────────────────────────────────────────

def cmd_scan(args):
    """Execute a live network scan"""
    from engines.live_scanner import LiveScanner

    config = {
        "max_threads": int(os.environ.get("QC_SCAN_THREADS", "50")),
        "scan_mode": args.mode or os.environ.get("QC_SCAN_MODE", "full"),
        "deny_public": not args.allow_public,
    }

    scanner = LiveScanner(config)

    print_section(f"🔍 LIVE SCAN: {args.target}")
    print(f"  Mode: {C.BOLD}{args.mode or 'full'}{C.RESET}")
    print(f"  Threads: {config['max_threads']}")
    print(f"  Target: {C.CYAN}{args.target}{C.RESET}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    start = time.time()
    report = scanner.scan(args.target, scan_type=args.mode or "full")
    elapsed = time.time() - start

    # Results
    print_section("📊 SCAN RESULTS")

    # Summary
    risk_color = C.RED if report.overall_risk >= 7 else C.YELLOW if report.overall_risk >= 4 else C.GREEN
    print(f"  Scan ID:    {C.BOLD}{report.scan_id}{C.RESET}")
    print(f"  Duration:   {elapsed:.1f} seconds")
    print(f"  Hosts:      {report.total_hosts_alive}/{report.total_hosts_scanned} alive")
    print(f"  Open Ports: {report.total_open_ports}")
    print(f"  Risk Score: {risk_color}{C.BOLD}{report.overall_risk}/10{C.RESET}")
    print()

    # Severity breakdown
    print(f"  Findings:   {report.total_findings} total")
    if report.critical_findings:
        print(f"              {C.BG_RED}{C.WHITE} {report.critical_findings} CRITICAL {C.RESET}")
    if report.high_findings:
        print(f"              {C.RED} {report.high_findings} HIGH {C.RESET}")
    if report.medium_findings:
        print(f"              {C.YELLOW} {report.medium_findings} MEDIUM {C.RESET}")
    if report.low_findings:
        print(f"              {C.BLUE} {report.low_findings} LOW {C.RESET}")
    if report.info_findings:
        print(f"              {C.DIM} {report.info_findings} INFO {C.RESET}")
    print()

    # Quantum risk
    if report.quantum_risk_summary:
        qc = C.RED if "vulnerable" in report.quantum_risk_summary.lower() else C.GREEN
        print(f"  ⚛️  Quantum: {qc}{report.quantum_risk_summary}{C.RESET}")
        print()

    # Host details
    if report.hosts:
        print_section("🖥  DISCOVERED HOSTS")
        for i, host in enumerate(report.hosts):
            h = host if isinstance(host, dict) else host.__dict__ if hasattr(host, '__dict__') else {}
            if not isinstance(h, dict):
                from dataclasses import asdict
                h = asdict(host)
            print_host(h, i + 1)

    # Findings
    all_findings = []
    for host in report.hosts:
        findings = host.findings if hasattr(host, 'findings') else host.get("findings", [])
        for f in findings:
            fd = f if isinstance(f, dict) else f.__dict__ if hasattr(f, '__dict__') else {}
            if not isinstance(fd, dict):
                from dataclasses import asdict
                fd = asdict(f)
            all_findings.append(fd)

    if all_findings:
        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "INFO"), 5))

        print_section("🚨 FINDINGS")
        for i, f in enumerate(all_findings):
            print_finding(f, i + 1)

    # Save report
    report_path = f"qc_scan_{report.scan_id}.json"
    with open(report_path, "w") as fp:
        json.dump(report.to_dict() if hasattr(report, 'to_dict') else report, fp, indent=2, default=str)
    print(f"\n  {C.GREEN}Report saved: {report_path}{C.RESET}")

    # Remediation hint
    if report.critical_findings or report.high_findings:
        print(f"\n  {C.YELLOW}{C.BOLD}⚡ Run 'python cli.py remediate' to generate a fix plan{C.RESET}")

    return report


def cmd_scan_web(args):
    """Scan a web application for security issues"""
    from engines.live_scanner import LiveScanner
    import socket

    scanner = LiveScanner()
    print_section(f"🌐 WEB SCAN: {args.url}")

    # Resolve URL to IP
    from urllib.parse import urlparse
    parsed = urlparse(args.url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f"  {C.RED}Cannot resolve hostname: {hostname}{C.RESET}")
        return

    print(f"  URL:  {args.url}")
    print(f"  Host: {hostname} → {ip}")
    print(f"  Port: {port}")
    print()

    # Scan just the web port + analyze HTTP
    report = scanner.scan(ip, scan_type="quick", ports=[port])

    # Print findings
    all_findings = []
    for host in report.hosts:
        for f in (host.findings if hasattr(host, 'findings') else []):
            fd = f if isinstance(f, dict) else (f.__dict__ if hasattr(f, '__dict__') else {})
            if not isinstance(fd, dict):
                from dataclasses import asdict
                fd = asdict(f)
            all_findings.append(fd)

    if all_findings:
        print_section("🚨 WEB SECURITY FINDINGS")
        for i, f in enumerate(all_findings):
            print_finding(f, i + 1)
    else:
        print(f"  {C.GREEN}✓ No issues found{C.RESET}")

    return report


def cmd_findings(args):
    """List all open findings from scan history"""
    from engines.live_scanner import LiveScanner

    scanner = LiveScanner()
    findings = scanner.get_all_findings(severity=args.severity)

    if not findings:
        print(f"\n  {C.GREEN}✓ No open findings{C.RESET}")
        print(f"  Run 'python cli.py scan <target>' to scan your network\n")
        return

    print_section(f"🚨 OPEN FINDINGS ({len(findings)})")
    for i, f in enumerate(findings):
        print_finding(f, i + 1)


def cmd_remediate(args):
    """Generate and optionally execute remediation plan"""
    from engines.live_scanner import LiveScanner
    from engines.auto_remediation import AutoRemediation

    scanner = LiveScanner()
    remediator = AutoRemediation({"allow_execute": args.execute})

    # Get all open findings
    findings = scanner.get_all_findings()
    if not findings:
        print(f"\n  {C.GREEN}✓ No open findings to remediate{C.RESET}\n")
        return

    print_section(f"🔧 REMEDIATION PLAN ({len(findings)} findings)")

    # Generate plan
    plan = remediator.generate_plan(findings, target_host=args.target or "localhost")

    # Display actions
    for i, action in enumerate(plan.actions):
        risk_color = {"low": C.GREEN, "medium": C.YELLOW, "high": C.RED}.get(action.risk_level, C.DIM)
        print(f"  [{i+1}] {C.BOLD}{action.title}{C.RESET}")
        print(f"      Category: {action.category} │ Risk: {risk_color}{action.risk_level}{C.RESET}")
        if action.description:
            print(f"      {C.DIM}{action.description}{C.RESET}")
        if action.commands:
            print(f"      {C.CYAN}Commands:{C.RESET}")
            for cmd in action.commands[:5]:
                print(f"        {C.DIM}{cmd}{C.RESET}")
            if len(action.commands) > 5:
                print(f"        {C.DIM}... +{len(action.commands)-5} more{C.RESET}")
        if action.requires_restart:
            print(f"      {C.YELLOW}Restarts: {', '.join(action.requires_restart)}{C.RESET}")
        print()

    print(f"  Plan ID: {C.BOLD}{plan.plan_id}{C.RESET}")
    print(f"  Actions: {plan.total_actions}")

    if args.execute:
        print(f"\n  {C.BG_RED}{C.WHITE} ⚠  EXECUTION MODE {C.RESET}")
        confirm = input(f"  Type 'EXECUTE' to proceed: ")
        if confirm == "EXECUTE":
            print(f"\n  {C.YELLOW}Executing remediation...{C.RESET}\n")
            result = remediator.execute_plan(plan.plan_id)
            print(f"  {C.GREEN}✓ Completed: {result.get('completed_actions', 0)}/{result.get('total_actions', 0)} actions{C.RESET}")
            if result.get("failed_actions", 0):
                print(f"  {C.RED}✗ Failed: {result['failed_actions']} actions{C.RESET}")
        else:
            print(f"  {C.YELLOW}Execution cancelled.{C.RESET}")
    else:
        print(f"\n  {C.DIM}Add --execute to run these fixes (will ask for confirmation){C.RESET}")


def cmd_status(args):
    """Show system status"""
    from engines.live_scanner import LiveScanner
    from engines.auto_remediation import AutoRemediation
    from engines.zero_day_predictor import ZeroDayPredictor
    from engines.advanced_telemetry import AdvancedTelemetryMatrix

    print_section("🛡 QUEEN CALIFIA — SYSTEM STATUS")

    # Live Scanner
    try:
        scanner = LiveScanner()
        s = scanner.get_status()
        print(f"  {C.CYAN}Live Scanner{C.RESET}")
        print(f"    Version:     {s.get('version', '?')}")
        print(f"    Scans:       {s.get('scans_completed', 0)} completed")
        print(f"    Findings:    {s.get('total_findings', 0)} total ({s.get('open_critical', 0)} critical, {s.get('open_high', 0)} high)")
        print(f"    Baselines:   {s.get('hosts_baselined', 0)} hosts learned")
        print(f"    Quantum:     {'✓ Enabled' if s.get('quantum_audit') else '✗ Disabled'}")
        print(f"    Drift:       {'✓ Enabled' if s.get('drift_detection') else '✗ Disabled'}")
        print(f"    Learning:    {'✓ Active' if s.get('learning') else '✗ Disabled'}")
        print()
    except Exception as e:
        print(f"  {C.RED}Live Scanner: {e}{C.RESET}\n")

    # Auto Remediation
    try:
        remediator = AutoRemediation()
        r = remediator.get_status()
        print(f"  {C.CYAN}Auto Remediation{C.RESET}")
        print(f"    Platform:    {r.get('platform', '?')}")
        print(f"    Mode:        {r.get('mode', '?')}")
        print(f"    Execution:   {'✓ Enabled' if r.get('execution_enabled') else '✗ Disabled'}")
        print()
    except Exception as e:
        print(f"  {C.RED}Auto Remediation: {e}{C.RESET}\n")

    # Zero-Day Predictor
    try:
        predictor = ZeroDayPredictor()
        p = predictor.get_status()
        print(f"  {C.CYAN}Zero-Day Predictor{C.RESET}")
        print(f"    Layers:      {p.get('analysis_layers', '?')}")
        print(f"    Active:      {p.get('active_predictions', 0)} predictions")
        print(f"    Accuracy:    {p.get('prediction_accuracy', 0)*100:.0f}%")
        print()
    except Exception as e:
        print(f"  {C.DIM}Zero-Day Predictor: not initialized{C.RESET}\n")

    # Telemetry
    try:
        telemetry = AdvancedTelemetryMatrix()
        t = telemetry.get_status()
        print(f"  {C.CYAN}Advanced Telemetry{C.RESET}")
        print(f"    Streams:     {t.get('active_streams', '?')}")
        print(f"    Events:      {t.get('events_processed', 0)}")
        print()
    except Exception as e:
        print(f"  {C.DIM}Advanced Telemetry: not initialized{C.RESET}\n")


def cmd_baselines(args):
    """Show learned network baselines"""
    from engines.live_scanner import LiveScanner

    scanner = LiveScanner()
    baselines = scanner.get_baselines()

    if not baselines:
        print(f"\n  {C.DIM}No baselines learned yet. Run a scan first.{C.RESET}\n")
        return

    print_section(f"📚 LEARNED BASELINES ({len(baselines)} hosts)")
    for b in baselines:
        print(f"  {C.BOLD}{b['host_ip']}{C.RESET}  │  OS: {b.get('os_guess', '?')}")
        print(f"    Ports:      {b.get('open_ports', [])}")
        print(f"    Services:   {b.get('services', {})}")
        print(f"    Scans:      {b.get('scan_count', 0)} │ First: {b.get('first_seen', '?')[:10]} │ Last: {b.get('last_seen', '?')[:10]}")
        print()


def cmd_history(args):
    """Show scan history"""
    from engines.live_scanner import LiveScanner
    import sqlite3

    scanner = LiveScanner()
    try:
        with sqlite3.connect(scanner.db_path) as conn:
            rows = conn.execute(
                "SELECT scan_id, target, scan_type, start_time, total_hosts, total_findings, critical, high, risk_score FROM scans ORDER BY start_time DESC LIMIT 20"
            ).fetchall()

        if not rows:
            print(f"\n  {C.DIM}No scan history yet.{C.RESET}\n")
            return

        print_section(f"📋 SCAN HISTORY (last {len(rows)})")
        for r in rows:
            risk_color = C.RED if (r[8] or 0) >= 7 else C.YELLOW if (r[8] or 0) >= 4 else C.GREEN
            print(f"  {C.BOLD}{r[0]}{C.RESET}  │  {r[1]}")
            print(f"    Type: {r[2]} │ Time: {(r[3] or '')[:19]} │ Hosts: {r[4]} │ Findings: {r[5]} │ Risk: {risk_color}{r[8]}{C.RESET}")
            if r[6] or r[7]:
                print(f"    {C.RED}Critical: {r[6]}{C.RESET} │ {C.YELLOW}High: {r[7]}{C.RESET}")
            print()
    except Exception as e:
        print(f"  {C.RED}Error: {e}{C.RESET}")


def cmd_monitor(args):
    """Continuous monitoring mode — re-scans at intervals"""
    from engines.live_scanner import LiveScanner

    interval = args.interval * 60  # Convert to seconds
    scanner = LiveScanner()

    print_section(f"🔄 CONTINUOUS MONITORING: {args.target}")
    print(f"  Interval: every {args.interval} minutes")
    print(f"  Press Ctrl+C to stop\n")

    scan_count = 0
    running = True

    def handle_sigint(sig, frame):
        nonlocal running
        running = False
        print(f"\n\n  {C.YELLOW}Monitoring stopped. {scan_count} scans completed.{C.RESET}\n")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    while running:
        scan_count += 1
        print(f"\n{'─' * 60}")
        print(f"  Scan #{scan_count} at {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'─' * 60}")

        report = scanner.scan(args.target, scan_type="quick")

        risk_color = C.RED if report.overall_risk >= 7 else C.YELLOW if report.overall_risk >= 4 else C.GREEN
        print(f"  Hosts: {report.total_hosts_alive} │ Findings: {report.total_findings} │ Risk: {risk_color}{report.overall_risk}{C.RESET}")

        if report.critical_findings:
            print(f"  {C.BG_RED}{C.WHITE} ⚠  {report.critical_findings} CRITICAL FINDINGS DETECTED {C.RESET}")

        # Check for drift
        drift = [f for h in report.hosts for f in (h.findings if hasattr(h, 'findings') else [])
                 if (f.category if hasattr(f, 'category') else f.get('category', '')) == 'drift_detection']
        if drift:
            print(f"  {C.YELLOW}⚠  DRIFT DETECTED: {len(drift)} changes from baseline{C.RESET}")

        if running:
            print(f"  Next scan in {args.interval} minutes...")
            time.sleep(interval)


def cmd_one_click(args):
    """THE ONE-COMMAND OPERATION: Scan → Learn → Predict → Fix → Evolve"""
    from engines.evolution_engine import EvolutionEngine

    engine = EvolutionEngine()

    print_section("⚡ ONE-CLICK OPERATION")
    print(f"  Target:       {C.CYAN}{args.target}{C.RESET}")
    print(f"  Scan Type:    {args.mode or 'full'}")
    print(f"  Auto-Execute: {'YES' if args.execute else 'NO (preview only)'}")
    print(f"  Started:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    if args.execute:
        print(f"  {C.BG_RED}{C.WHITE} ⚠  AUTO-EXECUTE MODE {C.RESET}")
        confirm = input(f"  Type 'EXECUTE' to proceed with automatic remediation: ")
        if confirm != "EXECUTE":
            print(f"  {C.YELLOW}Cancelled. Run without --execute for preview mode.{C.RESET}")
            return
        print()

    start = time.time()
    result = engine.one_click_scan_and_fix(
        target=args.target,
        scan_type=args.mode or "full",
        auto_approve=args.execute,
    )
    elapsed = time.time() - start

    # Display results
    print_section("📊 OPERATION RESULTS")

    risk_level = result.get("risk_level", "UNKNOWN")
    risk_colors = {"CRITICAL": C.BG_RED + C.WHITE, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.GREEN}
    rc = risk_colors.get(risk_level, C.DIM)

    print(f"  Operation ID: {C.BOLD}{result['operation_id']}{C.RESET}")
    print(f"  Duration:     {elapsed:.1f} seconds")
    print(f"  Risk Level:   {rc}{C.BOLD} {risk_level} {C.RESET}")
    print()

    # Phase results
    phases = result.get("phases", {})

    if "scan" in phases:
        s = phases["scan"]
        print(f"  {C.CYAN}🔍 Scan{C.RESET}")
        print(f"    Hosts: {s.get('hosts_alive', 0)} │ Findings: {s.get('total_findings', 0)} │ Risk: {s.get('overall_risk', 0)}/10")
        if s.get("critical"):
            print(f"    {C.RED}Critical: {s['critical']}{C.RESET} │ {C.YELLOW}High: {s.get('high', 0)}{C.RESET}")
        if s.get("quantum_risk"):
            print(f"    ⚛️  Quantum: {s['quantum_risk']}")
        print()

    if "learning" in phases:
        l = phases["learning"]
        print(f"  {C.CYAN}🧠 Learning{C.RESET}")
        print(f"    New baselines: {l.get('new_baselines', 0)} │ Updated: {l.get('updated_baselines', 0)}")
        print(f"    Patterns: {l.get('new_patterns', 0)} │ Fingerprints: {l.get('service_fingerprints', 0)}")
        print()

    if "zero_day" in phases:
        z = phases["zero_day"]
        if "error" not in z:
            print(f"  {C.CYAN}🔮 Zero-Day Predictions{C.RESET}")
            print(f"    Predictions: {z.get('predictions_generated', 0)} │ High-Risk: {z.get('high_risk_predictions', 0)}")
            print()

    if "remediation" in phases:
        r = phases["remediation"]
        print(f"  {C.CYAN}🔧 Remediation{C.RESET}")
        print(f"    Plan ID: {r.get('plan_id', 'N/A')} │ Actions: {r.get('total_actions', 0)}")
        cats = r.get("categories", {})
        if cats:
            cat_str = " │ ".join(f"{k}: {v}" for k, v in cats.items())
            print(f"    {cat_str}")
        print()

    if "execution" in phases:
        e = phases["execution"]
        completed = e.get("completed_actions", 0)
        failed = e.get("failed_actions", 0)
        print(f"  {C.CYAN}⚡ Execution{C.RESET}")
        print(f"    {C.GREEN}Completed: {completed}{C.RESET} │ {C.RED if failed else C.DIM}Failed: {failed}{C.RESET}")
        print()

    if "evolution" in phases:
        ev = phases["evolution"]
        print(f"  {C.CYAN}🧬 Evolution{C.RESET}")
        print(f"    New rules: {ev.get('new_detection_rules', 0)} │ Profile updates: {ev.get('scan_profile_updates', 0)}")
        print(f"    Playbook improvements: {ev.get('remediation_playbook_updates', 0)}")
        print()

    # Recommendation
    print(f"  {C.BOLD}Recommendation:{C.RESET} {result.get('recommendation', '')}")

    if not args.execute and phases.get("remediation", {}).get("total_actions", 0) > 0:
        print(f"\n  {C.YELLOW}{C.BOLD}⚡ Add --execute to automatically fix these issues{C.RESET}")


def cmd_quantum(args):
    """Quantum cryptographic readiness assessment"""
    from engines.quantum_engine import assess_quantum_readiness, QuantumKeyVault, LatticeKeyGenerator, EntropyPool

    print_section("⚛️  QUANTUM READINESS ASSESSMENT")

    report = assess_quantum_readiness()

    rc = C.GREEN if report.score >= 0.7 else C.YELLOW if report.score >= 0.4 else C.RED
    print(f"  Overall Readiness: {rc}{C.BOLD}{report.score*100:.0f}%{C.RESET}")
    print(f"  Entropy Health:    {C.GREEN if report.entropy_health else C.RED}{'✓ Healthy' if report.entropy_health else '✗ Degraded'}{C.RESET}")
    print(f"  Key Vault:         {C.GREEN if report.key_vault_active else C.YELLOW}{'✓ Active' if report.key_vault_active else '○ Inactive'}{C.RESET}")
    print(f"  Hybrid Mode:       {C.GREEN if report.hybrid_mode_enabled else C.YELLOW}{'✓ Enabled' if report.hybrid_mode_enabled else '○ Disabled'}{C.RESET}")
    if report.pq_algorithms_available:
        print(f"  PQ Algorithms:     {C.GREEN}{', '.join(report.pq_algorithms_available)}{C.RESET}")
    if report.classical_algorithms_in_use:
        print(f"  Classical (vuln):  {C.YELLOW}{', '.join(report.classical_algorithms_in_use)}{C.RESET}")
    if report.recommendations:
        print(f"\n  {C.BOLD}Recommendations:{C.RESET}")
        for r in report.recommendations:
            print(f"    • {r}")

    if args.keygen:
        print_section("🔑 GENERATING POST-QUANTUM KEYPAIR")
        entropy = EntropyPool()
        keygen = LatticeKeyGenerator(entropy)
        vault = QuantumKeyVault(keygen)
        key_id = vault.generate_and_store(algorithm="ML-KEM-768", label="cli-generated")
        print(f"  Key ID:     {C.CYAN}{key_id}{C.RESET}")
        print(f"  Algorithm:  ML-KEM-768 (NIST PQC Standard)")
        print(f"  Status:     {C.GREEN}✓ Stored in vault{C.RESET}")


def cmd_evolution(args):
    """Show evolution engine status and intelligence"""
    from engines.evolution_engine import EvolutionEngine

    engine = EvolutionEngine()

    if args.sub == "status":
        status = engine.get_status()
        print_section("🧬 EVOLUTION ENGINE STATUS")
        print(f"  Version:   {status['version']}")
        print(f"  Status:    {C.GREEN}{status['status']}{C.RESET}")
        print()
        l = status.get("learning", {})
        print(f"  {C.CYAN}Learning{C.RESET}")
        print(f"    Patterns:   {l.get('total_patterns', 0)}")
        print(f"    Baselines:  {l.get('baselines', 0)}")
        print(f"    Confidence: {l.get('avg_confidence', 0)*100:.0f}%")
        print()
        e = status.get("evolution", {})
        print(f"  {C.CYAN}Evolution{C.RESET}")
        print(f"    Auto rules:    {e.get('auto_rules_generated', 0)}")
        print(f"    Optimizations: {e.get('scan_optimizations', 0)}")
        print(f"    Improvements:  {e.get('remediation_improvements', 0)}")
        print(f"    Suppressed:    {e.get('suppressed_rules', 0)}")
        print()
        h = status.get("self_healing", {})
        print(f"  {C.CYAN}Self-Healing{C.RESET}")
        print(f"    Healing actions: {h.get('healing_actions', 0)}")
        print(f"    Auto-heals:     {h.get('total_auto_heals', 0)}")

    elif args.sub == "intel":
        report = engine.get_intelligence_report()
        print_section("🧠 INTELLIGENCE REPORT")
        print(f"  Generated: {report['generated_at'][:19]}")
        print()

        baselines = report.get("network_baselines", {})
        print(f"  {C.CYAN}Network Baselines{C.RESET}")
        print(f"    Total hosts:   {baselines.get('total_hosts', 0)}")
        print(f"    Stable:        {C.GREEN}{baselines.get('stable_hosts', 0)}{C.RESET}")
        print(f"    Volatile:      {C.RED}{baselines.get('volatile_hosts', 0)}{C.RESET}")
        print()

        evo = report.get("evolution_summary", {})
        print(f"  {C.CYAN}Evolutions{C.RESET}")
        print(f"    Total: {evo.get('total_evolutions', 0)}")
        for etype, count in evo.get("by_type", {}).items():
            print(f"    {etype}: {count}")

    elif args.sub == "evolve":
        print_section("🧬 RUNNING EVOLUTION CYCLE")
        result = engine.evolve()
        print(f"  Patterns analyzed:  {result.get('total_patterns_analyzed', 0)}")
        print(f"  New rules:          {C.CYAN}{result.get('new_detection_rules', 0)}{C.RESET}")
        print(f"  Profile updates:    {result.get('scan_profile_updates', 0)}")
        print(f"  Playbook updates:   {result.get('remediation_playbook_updates', 0)}")
        print(f"  Threshold adjusts:  {result.get('threshold_adjustments', 0)}")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🛡 Queen Califia CyberAI — Predictive Threat Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py go 192.168.1.0/24                ONE COMMAND — scan + learn + fix + evolve
  python cli.py go 10.0.0.1 --execute            Same but auto-execute remediation
  python cli.py scan 192.168.1.0/24              Full network scan
  python cli.py scan 10.0.0.1 --quick            Quick scan single host
  python cli.py scan-web https://mysite.com       Web security audit
  python cli.py findings --severity CRITICAL      List critical findings
  python cli.py remediate                         Generate fix plan
  python cli.py remediate --execute               Execute fixes (with confirmation)
  python cli.py monitor 192.168.1.0/24 -i 5      Re-scan every 5 minutes
  python cli.py quantum                           Quantum readiness report
  python cli.py quantum --keygen                  Generate post-quantum keypair
  python cli.py evolution status                  Self-healing/learning status
  python cli.py evolution intel                   Intelligence report
  python cli.py evolution evolve                  Trigger evolution cycle
  python cli.py status                            System status
        """
    )

    sub = parser.add_subparsers(dest="command", help="Command to run")

    # go (one-click)
    p_go = sub.add_parser("go", help="⚡ ONE COMMAND: scan + learn + predict + fix + evolve")
    p_go.add_argument("target", help="IP, CIDR, or hostname")
    p_go.add_argument("--mode", "-m", choices=["full", "quick", "stealth"], default="full")
    p_go.add_argument("--execute", "-x", action="store_true", help="Auto-execute remediation")

    # scan
    p_scan = sub.add_parser("scan", help="Scan a network target")
    p_scan.add_argument("target", help="IP, CIDR, or hostname")
    p_scan.add_argument("--mode", "-m", choices=["full", "quick", "stealth"], default="full")
    p_scan.add_argument("--allow-public", action="store_true", help="Allow scanning public IPs")

    # scan-web
    p_web = sub.add_parser("scan-web", help="Scan a web application")
    p_web.add_argument("url", help="URL to scan (e.g., https://example.com)")

    # findings
    p_find = sub.add_parser("findings", help="List open findings")
    p_find.add_argument("--severity", "-s", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    # remediate
    p_rem = sub.add_parser("remediate", help="Generate/execute remediation plan")
    p_rem.add_argument("--execute", "-x", action="store_true", help="Execute the plan (with confirmation)")
    p_rem.add_argument("--target", "-t", default="localhost", help="Target host for remediation")

    # status
    sub.add_parser("status", help="System status")

    # baselines
    sub.add_parser("baselines", help="Show learned network baselines")

    # history
    sub.add_parser("history", help="Show scan history")

    # monitor
    p_mon = sub.add_parser("monitor", help="Continuous monitoring")
    p_mon.add_argument("target", help="Target to monitor")
    p_mon.add_argument("--interval", "-i", type=int, default=10, help="Minutes between scans (default: 10)")

    # quantum
    p_q = sub.add_parser("quantum", help="⚛️ Quantum cryptographic readiness")
    p_q.add_argument("--keygen", action="store_true", help="Generate a post-quantum keypair")

    # evolution
    p_evo = sub.add_parser("evolution", help="🧬 Self-healing / learning / evolution")
    p_evo.add_argument("sub", choices=["status", "intel", "evolve"], help="Subcommand")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        return

    print_banner()

    commands = {
        "go": cmd_one_click,
        "scan": cmd_scan,
        "scan-web": cmd_scan_web,
        "findings": cmd_findings,
        "remediate": cmd_remediate,
        "status": cmd_status,
        "baselines": cmd_baselines,
        "history": cmd_history,
        "monitor": cmd_monitor,
        "quantum": cmd_quantum,
        "evolution": cmd_evolution,
    }

    fn = commands.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
