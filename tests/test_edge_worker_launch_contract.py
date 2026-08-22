from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy" / "edge" / "docker-compose.edge.yml"


def _worker_block() -> str:
    text = COMPOSE.read_text(encoding="utf-8")
    start = text.index("  worker:\n")
    end = text.index("\n  frontend:\n", start)
    return text[start:end]


def test_edge_worker_launches_from_repository_root() -> None:
    worker = _worker_block()
    assert "working_dir: /opt/queen-califia" in worker
    assert 'command: ["celery", "-A", "celery_app.celery_app", "worker"' in worker


def test_root_celery_modules_import_from_worker_launch_context() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import core.logging_setup; "
                "import celery_app; "
                "import tasks; "
                "assert celery_app.celery_app.main == 'queencalifia'; "
                "assert tasks.run_vuln_scan.name == 'qc.run_vuln_scan'; "
                "print('CELERY_WORKER_IMPORT_CONTRACT=PASS')"
            ),
        ],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "CELERY_WORKER_IMPORT_CONTRACT=PASS" in result.stdout
