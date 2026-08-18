"""Render and apply Argo CD Application + ImageUpdater manifests.

The applied Argo Applications must themselves carry deployment-time overrides.
Mutating Helm values only in the GitHub Actions workspace is insufficient because
Argo subsequently reads value files from the configured Git targetRevision.

Requirements (workflow installs these):
  - python
  - pyyaml
  - kubectl
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml


def _req(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise SystemExit(f"Missing env var: {name}")
    return value


def _run(cmd: list[str]) -> None:
    subprocess.check_call(cmd)


def _load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _dump_yaml(path: Path, obj: dict) -> None:
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(obj, handle, sort_keys=False)


def _upsert_helm_parameter(parameters: list[dict], name: str, value: str) -> None:
    for item in parameters:
        if item.get("name") == name:
            item["value"] = value
            item["forceString"] = True
            return
    parameters.append({"name": name, "value": value, "forceString": True})


def _render_application(
    path: Path,
    *,
    org: str,
    repo: str,
    api_image: str,
    frontend_image: str,
    host: str,
    cluster_issuer: str,
) -> None:
    """Make deployment inputs part of the persisted Argo Application spec."""
    obj = _load_yaml(path)
    source = obj.setdefault("spec", {}).setdefault("source", {})
    source["repoURL"] = f"https://github.com/{org}/{repo}.git"

    helm = source.setdefault("helm", {})
    parameters = helm.setdefault("parameters", [])
    if not isinstance(parameters, list):
        raise SystemExit(f"Invalid helm.parameters in {path}")

    for name, value in [
        ("api.image.repository", api_image),
        ("frontend.image.repository", frontend_image),
        ("ingress.host", host),
        ("ingress.certManager.clusterIssuer", cluster_issuer),
    ]:
        _upsert_helm_parameter(parameters, name, value)

    _dump_yaml(path, obj)


def _render_image_updater(path: Path, *, org: str, repo: str, api_image: str, frontend_image: str) -> None:
    """Patch non-secret ImageUpdater/repository placeholders before kubectl apply."""
    text = path.read_text(encoding="utf-8")
    text = text.replace("https://github.com/YOUR_ORG/QueenCalifia-CyberAI.git", f"https://github.com/{org}/{repo}.git")
    text = text.replace("ghcr.io/YOUR_ORG/queencalifia-api", api_image)
    text = text.replace("ghcr.io/YOUR_ORG/queencalifia-frontend", frontend_image)
    text = text.replace("YOUR_ORG", org)
    path.write_text(text, encoding="utf-8")


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]

    org = _req("QC_GIT_ORG")
    repo = os.getenv("QC_GIT_REPO", "QueenCalifia-CyberAI").strip() or "QueenCalifia-CyberAI"
    api_image = _req("QC_API_IMAGE")
    frontend_image = _req("QC_FRONTEND_IMAGE")
    staging_host = _req("QC_STAGING_HOST")
    prod_host = _req("QC_PROD_HOST")

    staging_app = repo_root / "k8s/argocd/application-queen-califia-staging.yaml"
    production_app = repo_root / "k8s/argocd/application-queen-califia-production.yaml"
    image_updater = repo_root / "k8s/argocd/image-updater-queen-califia-staging.yaml"

    # Persist deployment-time values in each applied Argo Application. Argo then
    # combines these parameters with the valueFiles it reads from Git, so the
    # bootstrap inputs remain authoritative after the CI workspace disappears.
    _render_application(
        staging_app,
        org=org,
        repo=repo,
        api_image=api_image,
        frontend_image=frontend_image,
        host=staging_host,
        cluster_issuer="letsencrypt-staging",
    )
    _render_application(
        production_app,
        org=org,
        repo=repo,
        api_image=api_image,
        frontend_image=frontend_image,
        host=prod_host,
        cluster_issuer="letsencrypt-prod",
    )
    _render_image_updater(
        image_updater,
        org=org,
        repo=repo,
        api_image=api_image,
        frontend_image=frontend_image,
    )

    _run(["kubectl", "apply", "-n", "argocd", "-f", str(staging_app)])
    _run(["kubectl", "apply", "-n", "argocd", "-f", str(production_app)])
    _run(["kubectl", "apply", "-f", str(image_updater)])

    print("Applied Argo CD Applications + staging ImageUpdater with persisted Helm overrides.")


if __name__ == "__main__":
    main()
