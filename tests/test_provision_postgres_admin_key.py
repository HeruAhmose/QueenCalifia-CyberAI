from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "edge" / "provision-postgres-admin-key.py"
spec = importlib.util.spec_from_file_location("qc_provision_postgres_admin_key", MODULE_PATH)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_direct_neon_url_contract():
    direct = (
        "postgresql://user:pass@ep-example.c-12.us-east-1.aws.neon.tech/neondb"
        "?sslmode=require"
    )
    assert module.validate_direct_database_url(direct) == direct


@pytest.mark.parametrize(
    "url, message",
    [
        ("", "must use postgresql://"),
        (
            "postgresql://u:p@ep-example-pooler.c-12.us-east-1.aws.neon.tech/neondb?sslmode=require",
            "direct Neon endpoint",
        ),
        (
            "postgresql://u:p@ep-example.c-12.us-east-1.aws.neon.tech/neondb",
            "sslmode=require",
        ),
    ],
)
def test_invalid_direct_url_rejected(url: str, message: str):
    with pytest.raises(RuntimeError, match=message):
        module.validate_direct_database_url(url)


def test_secret_file_is_exclusive_and_0600(tmp_path: Path):
    path = tmp_path / "secret" / "admin"
    module._write_secret_file(path, "abc")
    assert path.read_text() == "abc\n"
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        module._write_secret_file(path, "def")


def test_existing_secret_file_fails_before_database_access(monkeypatch, tmp_path: Path):
    path = tmp_path / "admin"
    path.write_text("existing\n")
    monkeypatch.setenv("QC_API_KEY_PEPPER", "pepper")
    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        module.provision(
            "postgresql://u:p@ep-example.c-12.us-east-1.aws.neon.tech/neondb?sslmode=require",
            "pepper",
            path,
        )
