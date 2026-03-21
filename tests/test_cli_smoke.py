"""Smoke tests for repository-root cli.py (no network)."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "cli.py"), *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env={**os.environ, "PYTHONUTF8": "1"},
    )


def test_cli_status_exits_zero():
    r = _run_cli("status")
    assert r.returncode == 0, r.stderr or r.stdout
    out = r.stdout or ""
    assert "SYSTEM STATUS" in out or "Live Scanner" in out


def test_cli_evolution_status_exits_zero():
    r = _run_cli("evolution", "status")
    assert r.returncode == 0, r.stderr or r.stdout
    out = r.stdout or ""
    assert "EVOLUTION" in out.upper() or "evolution" in out.lower()


def test_cli_quantum_exits_zero_without_oqs():
    r = _run_cli("quantum")
    assert r.returncode == 0, r.stderr or r.stdout
    out = r.stdout or ""
    assert "READINESS" in out.upper() or "readiness" in out.lower()
