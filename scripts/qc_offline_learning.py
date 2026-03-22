#!/usr/bin/env python3
"""
QC Offline Learning — evolution + optional identity (no HTTP)
==============================================================

Trains the **EvolutionEngine** locally from JSON/JSONL corpora and/or synthetic
scan/incident data. No Render, no API keys, no browser.

  • Persists to a SQLite DB (default: ./qc_offline_evolution.db or QC_EVOLUTION_DB)
  • Uses the same code paths as production: learn_from_scan, learn_from_completed_scan,
    learn_from_incident, learn_from_remediation, evolve()

Optional **identity** one-shot (requires a real **queen.db** schema — e.g. copy
from /var/data): runs ``run_learning_cycle`` once to generate proposals/reflections
from existing turns/market rows (still no external network).

Examples:
  python scripts/qc_offline_learning.py --synthetic 30
  python scripts/qc_offline_learning.py --corpus scripts/offline_corpus/sample_scan.json
  python scripts/qc_offline_learning.py --corpus scripts/offline_corpus/ --evolve-every 5
  python scripts/qc_offline_learning.py --identity-db ./queen.db --identity-once

Environment:
  QC_EVOLUTION_DB   Default evolution DB path when --db omitted
"""

from __future__ import annotations

import argparse
import io
import json
import os
import random
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional, Tuple

# Repo root on sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


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


def _synthetic_scan_report(i: int) -> Dict[str, Any]:
    """Varied synthetic host/findings for offline pattern learning."""
    ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    ports = sorted(random.sample(range(1, 1024), k=random.randint(2, 6)))
    services = {}
    for p in ports:
        svc = random.choice(
            [
                ("ssh", "OpenSSH_8.9"),
                ("http", "nginx/1.22"),
                ("https", "nginx/1.22"),
                ("mysql", "8.0.33"),
                ("redis", "7.0"),
                ("smb", "SMB 3.1.1"),
            ]
        )
        services[str(p)] = {"service": svc[0], "version": svc[1], "banner": f"{svc[0]} {i}"}

    n_find = random.randint(0, 4)
    findings = []
    for _ in range(n_find):
        findings.append(
            {
                "title": random.choice(
                    [
                        "TLS 1.0 supported",
                        "Exposed admin panel",
                        "Default credentials risk",
                        "Missing CSP",
                        "Weak cipher suite",
                    ]
                ),
                "category": random.choice(["tls", "http_security", "auth", "misconfig"]),
                "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
                "port": random.choice(ports),
                "service": "https" if 443 in ports else "http",
                "remediation": "Review vendor hardening guide",
            }
        )

    return {
        "scan_id": f"offline-syn-{uuid.uuid4().hex[:12]}",
        "target": ip,
        "scan_type": random.choice(["quick", "full"]),
        "hosts": [
            {
                "ip": ip,
                "os_guess": random.choice(["Linux", "Windows", "Unknown"]),
                "open_ports": ports,
                "services": services,
                "findings": findings,
            }
        ],
    }


def _synthetic_incident(i: int) -> Dict[str, Any]:
    techniques = random.sample(
        ["T1059.001", "T1071.001", "T1566.002", "T1486", "T1190", "T1021.001"],
        k=random.randint(1, 3),
    )
    return {
        "mitre_techniques": techniques,
        "category": random.choice(["malware", "ransomware", "unauthorized_access", "phishing"]),
        "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
        "affected_assets": [f"10.0.{i % 255}.1"],
        "iocs": [
            {"type": "ip", "value": f"198.51.100.{random.randint(1, 200)}"},
            {"type": "domain", "value": f"evil-{uuid.uuid4().hex[:6]}.invalid"},
        ],
    }


def _synthetic_remediation() -> Dict[str, Any]:
    return {
        "actions": [
            {
                "category": random.choice(["patch", "tls", "http_security"]),
                "title": random.choice(["Apply patch", "Rotate secrets", "Disable legacy TLS"]),
                "status": random.choice(["completed", "failed"]),
                "commands": [],
                "risk_level": random.choice(["low", "medium", "high"]),
            }
            for _ in range(random.randint(1, 3))
        ]
    }


def _iter_corpus_records(paths: List[Path]) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
    for path in paths:
        if path.is_dir():
            for child in sorted(path.glob("*.json")):
                yield from _iter_corpus_file(child)
            for child in sorted(path.glob("*.jsonl")):
                yield from _iter_corpus_file(child)
        else:
            yield from _iter_corpus_file(path)


def _iter_corpus_file(path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".jsonl":
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            yield path.name, rec
        return
    data = json.loads(text)
    if isinstance(data, list):
        for rec in data:
            yield path.name, rec
    elif isinstance(data, dict) and "records" in data:
        for rec in data["records"]:
            yield path.name, rec
    else:
        yield path.name, data


def _apply_record(engine: Any, rec: Dict[str, Any]) -> Dict[str, Any]:
    rtype = (rec.get("type") or "").strip().lower()
    payload = rec.get("payload") or rec.get("data") or rec

    # Bare scan export: top-level "hosts" without wrapper
    if not rtype and isinstance(payload, dict) and "hosts" in payload:
        rtype = "scan"

    if rtype == "scan":
        learned = engine.learn_from_scan(payload)
        return {"kind": "scan", "learned": learned}

    if rtype == "completed_scan":
        out = engine.learn_from_completed_scan(payload, source="offline_corpus")
        return {"kind": "completed_scan", **out}

    if rtype == "incident":
        learned = engine.learn_from_incident(payload)
        return {"kind": "incident", "learned": learned}

    if rtype == "remediation":
        learned = engine.learn_from_remediation(payload)
        return {"kind": "remediation", "learned": learned}

    raise ValueError(f"Unknown record type: {rtype!r} (expected scan|completed_scan|incident|remediation)")


def main() -> None:
    _configure_stdio_utf8()
    parser = argparse.ArgumentParser(description="QC offline evolution learning (no HTTP)")
    parser.add_argument(
        "--db",
        default=os.environ.get("QC_EVOLUTION_DB", str(_ROOT / "qc_offline_evolution.db")),
        help="EvolutionEngine SQLite path",
    )
    parser.add_argument("--corpus", action="append", help="JSON/JSONL file or directory (repeatable)")
    parser.add_argument("--synthetic", type=int, default=0, help="Number of synthetic bundles to generate")
    parser.add_argument(
        "--mix",
        default="scan,incident,remediation,completed",
        help="Comma list for synthetic rotation: scan,incident,remediation,completed",
    )
    parser.add_argument("--evolve-every", type=int, default=1, help="Call evolve() after every N applied records (0=never)")
    parser.add_argument("--final-evolve", action="store_true", help="Force one evolve() at end")
    parser.add_argument(
        "--identity-db",
        default=None,
        help="Path to queen.db (copy of production) for optional identity learning",
    )
    parser.add_argument(
        "--identity-once",
        action="store_true",
        help="Run one identity run_learning_cycle (no throttle gate)",
    )
    args = parser.parse_args()

    from engines.evolution_engine import EvolutionEngine

    db_path = os.path.abspath(args.db)
    engine = EvolutionEngine({"db_path": db_path})
    print(f"[offline] evolution db: {db_path}")

    applied = 0
    errors = 0
    evolve_counter = 0
    mix_kinds = [k.strip().lower() for k in args.mix.split(",") if k.strip()]

    def maybe_evolve() -> None:
        nonlocal evolve_counter
        if args.evolve_every <= 0:
            return
        evolve_counter += 1
        if evolve_counter % args.evolve_every == 0:
            ev = engine.evolve()
            print(f"  evolve -> rules={ev.get('new_detection_rules')} patterns={ev.get('total_patterns_analyzed')}")

    # Corpus files
    if args.corpus:
        files: List[Path] = []
        for raw in args.corpus:
            files.append(Path(raw).resolve())
        for fname, rec in _iter_corpus_records(files):
            try:
                out = _apply_record(engine, rec)
                applied += 1
                print(f"  + [{fname}] {out.get('kind', '?')} ok")
                maybe_evolve()
            except Exception as exc:
                errors += 1
                print(f"  ! [{fname}] {exc}")

    # Synthetic stream
    for i in range(max(0, args.synthetic)):
        kind = random.choice(mix_kinds) if mix_kinds else "scan"
        try:
            if kind == "scan":
                payload = _synthetic_scan_report(i)
                learned = engine.learn_from_scan(payload)
                print(f"  + [synthetic {i+1}] scan scan_id={payload['scan_id']} baselines+={learned.get('new_baselines',0)}")
            elif kind == "incident":
                payload = _synthetic_incident(i)
                learned = engine.learn_from_incident(payload)
                print(f"  + [synthetic {i+1}] incident ttps={learned.get('ttp_patterns')}")
            elif kind == "remediation":
                payload = _synthetic_remediation()
                learned = engine.learn_from_remediation(payload)
                print(f"  + [synthetic {i+1}] remediation improvements={learned.get('playbook_improvements')}")
            elif kind == "completed":
                # Summary-only completed scan (exercises _learn_from_scan_summary path)
                payload = {
                    "scan_id": f"offline-sum-{uuid.uuid4().hex[:10]}",
                    "target": "192.168.0.0/24",
                    "scan_type": "quick",
                    "critical_count": random.randint(0, 2),
                    "high_count": random.randint(0, 5),
                    "medium_count": random.randint(0, 8),
                    "low_count": random.randint(0, 10),
                    "assets_discovered": random.randint(1, 50),
                    "vulnerabilities_found": random.randint(0, 100),
                    "risk_score": round(random.uniform(0, 10), 2),
                }
                out = engine.learn_from_completed_scan(payload, source="offline_synthetic")
                print(f"  + [synthetic {i+1}] completed_scan id={payload['scan_id']} new={not out.get('already_processed')}")
            else:
                print(f"  ! unknown mix kind {kind!r}, skip")
                continue
            applied += 1
            maybe_evolve()
        except Exception as exc:
            errors += 1
            print(f"  ! [synthetic {i+1}] {exc}")

    if args.final_evolve or args.evolve_every > 0:
        ev = engine.evolve()
        print(f"[offline] final evolve: new_rules={ev.get('new_detection_rules')} analyzed={ev.get('total_patterns_analyzed')}")

    print(f"[offline] done. applied={applied} errors={errors}")

    if args.identity_once:
        if not args.identity_db:
            print("[offline] --identity-once requires --identity-db", file=sys.stderr)
            sys.exit(2)
        idb = Path(args.identity_db).resolve()
        if not idb.is_file():
            print(f"[offline] identity db not found: {idb}", file=sys.stderr)
            sys.exit(2)
        sys.path.insert(0, str(_ROOT / "backend"))
        from modules.identity.engine import run_learning_cycle

        print(f"[offline] identity learning cycle: {idb}")
        result = run_learning_cycle(str(idb))
        print(f"[offline] identity result: {json.dumps(result, default=str)[:500]}")


if __name__ == "__main__":
    main()
