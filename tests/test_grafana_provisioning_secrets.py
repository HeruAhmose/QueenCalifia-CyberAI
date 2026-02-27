import os
import subprocess
from pathlib import Path


def test_grafana_entrypoint_does_not_write_bearer_token(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    entrypoint = repo_root / "grafana" / "entrypoint.sh"
    assert entrypoint.exists()

    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir(parents=True, exist_ok=True)
    dst.mkdir(parents=True, exist_ok=True)

    # Minimal src tree; script should still create alerting files.
    token = "SUPERSECRET_BEARER_TOKEN_SHOULD_NOT_APPEAR"
    env = os.environ.copy()
    env.update(
        {
            "QC_GRAFANA_PROVISIONING_SRC": str(src),
            "QC_GRAFANA_PROVISIONING_DST": str(dst),
            "QC_ALERT_WEBHOOK_URL": "http://example.invalid/webhook",
            "QC_ALERT_WEBHOOK_BEARER_TOKEN": token,
            "QC_ENTRYPOINT_NO_EXEC": "1",
        }
    )

    subprocess.run(
        ["/bin/sh", str(entrypoint)],
        check=True,
        env=env,
        cwd=str(repo_root),
    )

    contactpoints = dst / "alerting" / "qc-contactpoints-webhook.yaml"
    assert contactpoints.exists()
    data = contactpoints.read_text(encoding="utf-8")

    # Guard: token must not be in the file (prevents accidental shell expansion in heredocs).
    assert token not in data

    # Ensure env interpolation placeholder is present.
    assert "$QC_ALERT_WEBHOOK_BEARER_TOKEN" in data
