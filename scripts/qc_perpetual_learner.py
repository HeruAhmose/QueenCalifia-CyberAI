#!/usr/bin/env python3
"""
QC Perpetual Learner — next-gen continuous platform stimulation
================================================================

Randomized, high-concurrency, long-running harness that keeps the live QC OS
"warmed" and subtly exercises memory, identity cycles, mesh, market, evolution,
predictor, and chat — without replacing structured QA (use qc_sovereign_training
for pass/fail reports).

Design goals:
  * Varied: shuffled task mix every cycle; rotating prompts and parameters
  * Intensive: ThreadPoolExecutor + many parallel I/O-bound requests
  * Perpetual: run until Ctrl+C or --max-cycles
  * Subtle: mostly cheap GETs + short "whisper" chats; occasional writes

Environment (same as sovereign training):
  QC_BASE_URL     API root (default: Render production URL)
  QC_API_KEY      X-QC-API-Key
  QC_ADMIN_KEY    X-QC-Admin-Key (optional; unlocks a few admin probes)

Examples:
  python scripts/qc_perpetual_learner.py
  python scripts/qc_perpetual_learner.py --workers 16 --chat-fraction 0.3
  python scripts/qc_perpetual_learner.py --max-cycles 5 --no-jitter
  python scripts/qc_perpetual_learner.py --heavy  # rare vuln/one-click style calls

Windows: UTF-8 console is configured automatically when possible.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import random
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# Console (Windows)
# ---------------------------------------------------------------------------


def _configure_stdio_utf8() -> None:
    if sys.platform != "win32":
        return
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        else:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

QC_BASE_URL = os.getenv("QC_BASE_URL", "https://queencalifia-cyberai.onrender.com").rstrip("/")
QC_API_KEY = os.getenv("QC_API_KEY", "")
QC_ADMIN_KEY = os.getenv("QC_ADMIN_KEY", "")

_lock = threading.Lock()
_stats = {
    "cycles": 0,
    "tasks": 0,
    "ok": 0,
    "fail": 0,
    "lat_sum_ms": 0,
    "by_kind": {},  # kind -> {"ok": n, "fail": n}
}


def _bump(kind: str, ok: bool, lat_ms: int) -> None:
    with _lock:
        _stats["tasks"] += 1
        if ok:
            _stats["ok"] += 1
        else:
            _stats["fail"] += 1
        _stats["lat_sum_ms"] += lat_ms
        bk = _stats["by_kind"].setdefault(kind, {"ok": 0, "fail": 0})
        bk["ok" if ok else "fail"] += 1


def _headers(admin: bool = False) -> Dict[str, str]:
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if QC_API_KEY:
        h["X-QC-API-Key"] = QC_API_KEY
    if admin and QC_ADMIN_KEY:
        h["X-QC-Admin-Key"] = QC_ADMIN_KEY
    return h


def _get(path: str, admin: bool = False, timeout: float = 45) -> Tuple[int, Any, int]:
    url = f"{QC_BASE_URL}{path}"
    req = Request(url, headers=_headers(admin), method="GET")
    t0 = time.time()
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            try:
                body = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                body = {"_raw": raw[:500]}
            return resp.status, body, int((time.time() - t0) * 1000)
    except HTTPError as e:
        body: Any = {}
        try:
            body = json.loads(e.read().decode())
        except Exception:
            pass
        return e.code, body, int((time.time() - t0) * 1000)
    except (URLError, TimeoutError, OSError) as e:
        return 0, {"error": str(e)}, int((time.time() - t0) * 1000)


def _post(path: str, payload: Any, admin: bool = False, timeout: float = 90, auth: bool = True) -> Tuple[int, Any, int]:
    url = f"{QC_BASE_URL}{path}"
    data = json.dumps(payload).encode()
    hdrs = _headers(admin) if auth else {"Content-Type": "application/json"}
    req = Request(url, data=data, headers=hdrs, method="POST")
    t0 = time.time()
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            try:
                body = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                body = {"_raw": raw[:500]}
            return resp.status, body, int((time.time() - t0) * 1000)
    except HTTPError as e:
        body = {}
        try:
            body = json.loads(e.read().decode())
        except Exception:
            pass
        return e.code, body, int((time.time() - t0) * 1000)
    except (URLError, TimeoutError, OSError) as e:
        return 0, {"error": str(e)}, int((time.time() - t0) * 1000)


def _snap(asset_type: str, symbol: str) -> str:
    return "/api/market/snapshot?" + urlencode({"asset_type": asset_type, "symbol": symbol})


# Rotating market / FRED / identity / mesh / evolution / intel probes
def _all_get_paths() -> List[str]:
    paths = [
        "/healthz",
        "/readyz",
        "/api/health",
        "/api/ready",
        "/api/training/readiness",
        "/api/training/capabilities-catalog",
        "/api/config",
        "/api/mesh/status",
        "/api/threats/active",
        "/api/dashboard",
        "/api/iocs",
        "/api/vulns/status",
        "/api/vulns/remediation",
        "/api/incidents",
        "/api/ir/status",
        "/api/audit/log",
        "/api/audit/integrity",
        "/api/chat/memories",
        "/api/forecast/portfolio/list",
        "/api/market/sources",
        _snap("crypto", "BTC-USD"),
        _snap("crypto", "ETH-USD"),
        _snap("crypto", "SOL-USD"),
        _snap("stock", "AAPL"),
        _snap("stock", "MSFT"),
        _snap("stock", "GOOGL"),
        _snap("stock", "NVDA"),
        _snap("forex", "USD/EUR"),
        "/api/market/fred/UNRATE",
        "/api/market/fred/CPIAUCSL",
        "/api/market/fred/GDP",
        "/api/identity/state",
        "/api/identity/memory/pending",
        "/api/identity/reflections/pending",
        "/api/identity/rules/pending",
        "/api/identity/self-notes/pending",
        "/api/v1/predictor/predictions",
        "/api/v1/predictor/status",
        "/api/v1/predictor/landscape",
        "/api/v1/telemetry/summary",
        "/api/v1/scanner/status",
        "/api/v1/scanner/findings",
        "/api/v1/scanner/baselines",
        "/api/v1/remediate/status",
        "/api/v1/remediate/log",
        "/api/v1/evolution/status",
        "/api/v1/evolution/health",
        "/api/v1/evolution/intelligence",
        "/api/v1/evolution/baselines",
        "/api/v1/evolution/storage",
        "/api/v1/evolution/backups",
        "/api/v1/evolution/evolutions",
        "/api/v1/quantum/readiness",
        "/api/v1/quantum/vault",
        "/api/v1/threat-intel/status",
        "/api/v1/threat-intel/feeds",
        "/api/v1/threat-intel/indicators",
        "/api/v1/threat-intel/cves/critical",
        "/api/v1/threat-intel/actors",
        "/api/v1/purple-team/heatmap",
        "/api/v1/blue-team/rules",
        "/api/v1/blue-team/iocs",
        "/api/v1/blue-team/soar/playbooks",
        "/api/v1/telemetry/advanced/status",
        "/api/v1/telemetry/advanced/beacons",
        "/api/v1/telemetry/advanced/risk-map",
        "/api/v1/telemetry/advanced/graph",
        "/api/v1/telemetry/advanced/health",
        "/metrics",
    ]
    if QC_ADMIN_KEY:
        paths.append("/api/admin/keys")
    return paths


_WHISPER_PROMPTS: List[str] = [
    "Briefly: what is your current operational posture?",
    "One sentence on how you prioritize defender workflows.",
    "Name one MITRE tactic you weigh heavily in triage.",
    "Micro-summary: supply-chain risk vs phishing — how do you separate them?",
    "What signal would make you escalate a market + cyber correlation?",
    "Give a 12-word stance on zero-trust logging.",
    "How do you treat uncertain intel vs confirmed IOCs?",
    "One line: when to involve legal/comms in IR.",
    "Tiny fact check: what is HSTS for?",
    "What does 'provenance' mean for your market answers?",
    "Acknowledge this telemetry ping in one clause.",
    "Hypothetical: user asks for passwords — your response shape?",
    "Nudge: preferred tone for executive summaries.",
    "Lab mode: one experimental hypothesis about regime shifts.",
    "Research mode: cite uncertainty explicitly in one sentence.",
    "Cyber mode: sovereign acknowledgment (one line).",
    "What would you log from this session (conceptually)?",
    "Contrast volatility spike vs credit stress in one phrase.",
    "When is 'no recommendation' the right recommendation?",
    "How do you avoid overfitting narratives to single indicators?",
    "Name a false-positive pattern you watch for.",
    "One sentence on quantum-readiness framing for operators.",
    "If Redis is slow, how should an operator interpret latency?",
    "What is the smallest useful incident timeline?",
    "Give a one-line containment heuristic for lateral movement hints.",
]


def _random_whisper_session() -> str:
    return f"pl-{uuid.uuid4().hex[:10]}"


def _task_get(path: str) -> Tuple[str, bool, int]:
    st, _, lat = _get(path)
    ok = st == 200 or st in (401, 403, 404, 400, 503)
    return ("get", ok, lat)


def _task_chat(message: str, mode: str, session: str) -> Tuple[str, bool, int]:
    st, data, lat = _post(
        "/api/chat/",
        {
            "message": message,
            "session_id": session,
            "user_id": "qc-perpetual-learner",
            "mode": mode,
        },
        timeout=120,
    )
    ok = st == 200 and bool((data or {}).get("reply") if isinstance(data, dict) else False)
    return ("chat", ok, lat)


def _task_event_ingest() -> Tuple[str, bool, int]:
    sip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    dip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    st, _, lat = _post(
        "/api/events/ingest",
        {
            "source_ip": sip,
            "dest_ip": dip,
            "source_port": random.randint(1024, 65535),
            "dest_port": random.choice([80, 443, 53, 22]),
            "protocol": random.choice(["tcp", "udp"]),
            "event_type": random.choice(["flow", "dns_query", "auth_failure", "beacon_suspect"]),
            "raw_data": {"perpetual": True, "ts": datetime.utcnow().isoformat() + "Z"},
        },
    )
    ok = st in (200, 400, 401, 403, 429)
    return ("event", ok, lat)


def _task_forecast() -> Tuple[str, bool, int]:
    st, _, lat = _post(
        "/api/forecast/run",
        {"experiment_type": "regime_detection", "parameters": {"lookback_days": random.choice([14, 30, 60])}},
    )
    ok = st in (200, 400, 401, 403)
    return ("forecast", ok, lat)


def _task_predictor_probe() -> Tuple[str, bool, int]:
    st, _, lat = _post(
        "/api/v1/predictor/analyze",
        {
            "type": random.choice(["network", "vulnerability", "identity", "market"]),
            "source": f"10.0.0.{random.randint(1, 200)}",
            "data": {"severity": random.choice(["low", "medium", "high"]), "perpetual": True},
        },
    )
    ok = st in (200, 400, 401, 403, 503)
    return ("predictor", ok, lat)


def _task_evolution_learn() -> Tuple[str, bool, int]:
    st, _, lat = _post("/api/v1/evolution/learn", {"scan_report": {"perpetual_tick": True, "hosts": []}})
    ok = st in (200, 401, 403, 503)
    return ("evo_learn", ok, lat)


def _task_evolution_evolve() -> Tuple[str, bool, int]:
    st, _, lat = _post("/api/v1/evolution/evolve", {})
    ok = st in (200, 401, 403, 503)
    return ("evo_evolve", ok, lat)


def _task_telemetry_process() -> Tuple[str, bool, int]:
    st, _, lat = _post(
        "/api/v1/telemetry/advanced/process",
        {
            "stream": random.choice(["network", "identity", "market", "threat"]),
            "event": {"id": uuid.uuid4().hex[:12], "perpetual": True},
        },
    )
    ok = st in (200, 400, 401, 403, 503)
    return ("telemetry", ok, lat)


def _task_heavy_vuln_scan() -> Tuple[str, bool, int]:
    st, _, lat = _post(
        "/api/vulns/scan",
        {
            "target": "127.0.0.1",
            "scan_type": random.choice(["quick", "full"]),
            "mode": "async",
            "acknowledge_authorized": True,
        },
        timeout=60,
    )
    ok = st in (200, 202, 401, 403, 429)
    return ("vuln_scan", ok, lat)


def _task_heavy_one_click() -> Tuple[str, bool, int]:
    st, _, lat = _post(
        "/api/v1/one-click/scan-and-fix",
        {
            "target": "127.0.0.1",
            "scan_type": "quick",
            "auto_approve": False,
            "acknowledge_authorized": True,
        },
        timeout=180,
    )
    ok = st in (200, 401, 403, 503)
    return ("one_click", ok, lat)


def _build_cycle_tasks(
    *,
    batch_size: int,
    chat_fraction: float,
    write_fraction: float,
    heavy_fraction: float,
    heavy_enabled: bool,
) -> List[Callable[[], Tuple[str, bool, int]]]:
    paths = _all_get_paths()
    random.shuffle(paths)
    tasks: List[Callable[[], Tuple[str, bool, int]]] = []

    n_chat = max(1, int(batch_size * chat_fraction))
    n_write = max(0, int(batch_size * write_fraction))
    n_get = max(1, batch_size - n_chat - n_write)

    for p in paths[:n_get]:
        tasks.append(lambda p=p: _task_get(p))

    modes = ["cyber", "research", "lab"]
    for _ in range(n_chat):
        msg = random.choice(_WHISPER_PROMPTS)
        mode = random.choice(modes)
        sess = _random_whisper_session()
        tasks.append(lambda m=msg, md=mode, s=sess: _task_chat(m, md, s))

    write_ops: List[Callable[[], Tuple[str, bool, int]]] = [
        _task_event_ingest,
        _task_forecast,
        _task_predictor_probe,
        _task_evolution_learn,
        _task_evolution_evolve,
        _task_telemetry_process,
    ]
    for _ in range(n_write):
        tasks.append(random.choice(write_ops))

    if heavy_enabled and heavy_fraction > 0 and random.random() < heavy_fraction * 5:
        if random.random() < 0.5:
            tasks.append(_task_heavy_vuln_scan)
        else:
            tasks.append(_task_heavy_one_click)

    random.shuffle(tasks)
    return tasks


def run_cycles(
    *,
    workers: int,
    batch_size: int,
    chat_fraction: float,
    write_fraction: float,
    heavy: bool,
    heavy_fraction: float,
    max_cycles: int,
    sleep_base: float,
    sleep_jitter: float,
    stats_interval: float,
) -> None:
    paths = _all_get_paths()
    print(f"[perpetual] base={QC_BASE_URL} probes={len(paths)} workers={workers} batch={batch_size}")
    print(f"[perpetual] chat={chat_fraction:.0%} write={write_fraction:.0%} heavy={heavy} (Ctrl+C to stop)\n")

    cycle = 0
    last_stats = time.time()
    try:
        while True:
            cycle += 1
            if max_cycles and cycle > max_cycles:
                break
            with _lock:
                _stats["cycles"] = cycle

            tasks = _build_cycle_tasks(
                batch_size=batch_size,
                chat_fraction=chat_fraction,
                write_fraction=write_fraction,
                heavy_fraction=heavy_fraction,
                heavy_enabled=heavy,
            )

            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = [ex.submit(t) for t in tasks]
                for fut in as_completed(futs):
                    try:
                        kind, ok, lat = fut.result()
                        _bump(kind, ok, lat)
                    except Exception:
                        _bump("error", False, 0)

            now = time.time()
            if now - last_stats >= stats_interval:
                last_stats = now
                with _lock:
                    t = _stats["tasks"]
                    avg = int(_stats["lat_sum_ms"] / t) if t else 0
                    print(
                        f"[stats] cycle={_stats['cycles']} tasks={t} ok={_stats['ok']} fail={_stats['fail']} avg_lat={avg}ms kinds={_stats['by_kind']}"
                    )

            jitter = random.uniform(0, sleep_jitter) if sleep_jitter > 0 else 0
            time.sleep(sleep_base + jitter)
    except KeyboardInterrupt:
        print("\n[perpetual] stopped by user")
    with _lock:
        t = _stats["tasks"]
        avg = int(_stats["lat_sum_ms"] / t) if t else 0
        print(
            f"\n[final] cycles={_stats['cycles']} tasks={t} ok={_stats['ok']} fail={_stats['fail']} avg_lat={avg}ms"
        )


def main() -> None:
    _configure_stdio_utf8()
    global QC_BASE_URL, QC_API_KEY, QC_ADMIN_KEY

    p = argparse.ArgumentParser(description="QC Perpetual Learner — randomized concurrent API stimulation")
    p.add_argument("--base-url", default=None, help="Override QC_BASE_URL")
    p.add_argument("--workers", type=int, default=12, help="Thread pool size (default 12)")
    p.add_argument("--batch", type=int, default=48, help="Tasks per cycle (default 48)")
    p.add_argument("--chat-fraction", type=float, default=0.22, help="Fraction of batch that are chat whispers")
    p.add_argument("--write-fraction", type=float, default=0.12, help="Fraction that are POST writes (events, forecast, …)")
    p.add_argument("--heavy", action="store_true", help="Allow rare heavy vuln / one-click calls")
    p.add_argument("--heavy-fraction", type=float, default=0.02, help="Per-cycle probability scale for heavy tasks")
    p.add_argument("--max-cycles", type=int, default=0, help="Stop after N cycles (0 = infinite)")
    p.add_argument("--sleep", type=float, default=1.5, help="Base sleep seconds between cycles")
    p.add_argument("--jitter", type=float, default=3.0, help="Random extra 0..jitter seconds between cycles")
    p.add_argument("--no-jitter", action="store_true", help="Disable sleep jitter")
    p.add_argument("--stats-interval", type=float, default=45.0, help="Seconds between stats lines")
    args = p.parse_args()

    if args.base_url:
        QC_BASE_URL = args.base_url.rstrip("/")

    if not QC_API_KEY.strip():
        print(
            "WARNING: QC_API_KEY unset — most routes will 401; set it for real learning traffic.\n",
            file=sys.stderr,
        )

    run_cycles(
        workers=max(1, args.workers),
        batch_size=max(4, args.batch),
        chat_fraction=min(0.6, max(0.05, args.chat_fraction)),
        write_fraction=min(0.4, max(0.0, args.write_fraction)),
        heavy=args.heavy,
        heavy_fraction=min(0.2, max(0.0, args.heavy_fraction)),
        max_cycles=max(0, args.max_cycles),
        sleep_base=max(0.0, args.sleep),
        sleep_jitter=0.0 if args.no_jitter else max(0.0, args.jitter),
        stats_interval=max(10.0, args.stats_interval),
    )


if __name__ == "__main__":
    main()
