from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "managed" / "validate_runtime_env.py"


def run_validator(**overrides: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "QC_MANAGED_RUNTIME_GATE": "1",
            "QC_MANAGED_RUNTIME_AUTHORIZED": "AUTHORIZED",
            "QC_SERVICE_ROLE": "api",
            "QC_PRODUCTION": "1",
            "QC_USE_CELERY": "1",
            "QC_REQUIRE_REDIS": "1",
            "QC_MANAGED_POSTGRES_PROVIDER": "neon",
            "QC_DATABASE_CONNECTION_MODE": "pooled",
            "QC_DATABASE_URL": "postgresql://user:pass@ep-test-pooler.c-1.us-east-1.aws.neon.tech/neondb?sslmode=require",
            "DATABASE_URL": "postgresql://user:pass@ep-test-pooler.c-1.us-east-1.aws.neon.tech/neondb?sslmode=require",
            "QC_REDIS_URL": "rediss://user:pass@valkey.example:25061/0?ssl_cert_reqs=required",
            "QC_CELERY_BROKER_URL": "rediss://user:pass@valkey.example:25061/0?ssl_cert_reqs=required",
            "QC_CELERY_RESULT_BACKEND": "rediss://user:pass@valkey.example:25061/0?ssl_cert_reqs=required",
        }
    )
    env.update(overrides)
    return subprocess.run(
        [sys.executable, str(VALIDATOR)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_managed_runtime_accepts_authorized_tls_external_state():
    result = run_validator()
    assert result.returncode == 0, result.stderr


def test_managed_runtime_refuses_closed_authorization_gate():
    result = run_validator(QC_MANAGED_RUNTIME_AUTHORIZED="NOT_AUTHORIZED")
    assert result.returncode != 0
    assert "runtime gate closed" in result.stderr


def test_managed_runtime_refuses_unpooled_neon_application_endpoint():
    result = run_validator(
        QC_DATABASE_URL="postgresql://user:pass@ep-test.c-1.us-east-1.aws.neon.tech/neondb?sslmode=require",
        DATABASE_URL="postgresql://user:pass@ep-test.c-1.us-east-1.aws.neon.tech/neondb?sslmode=require",
    )
    assert result.returncode != 0
    assert "pooled endpoint" in result.stderr


def test_managed_runtime_refuses_plaintext_queue():
    plaintext = "redis://user:pass@valkey.example:25061/0"
    result = run_validator(
        QC_REDIS_URL=plaintext,
        QC_CELERY_BROKER_URL=plaintext,
        QC_CELERY_RESULT_BACKEND=plaintext,
    )
    assert result.returncode != 0
    assert "rediss" in result.stderr


def test_managed_runtime_refuses_tls_without_certificate_verification():
    weak = "rediss://user:pass@valkey.example:25061/0?ssl_cert_reqs=none"
    result = run_validator(
        QC_REDIS_URL=weak,
        QC_CELERY_BROKER_URL=weak,
        QC_CELERY_RESULT_BACKEND=weak,
    )
    assert result.returncode != 0
    assert "certificate verification" in result.stderr
