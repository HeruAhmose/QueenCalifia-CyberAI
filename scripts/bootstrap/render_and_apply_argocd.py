"""Render and apply Argo CD Application + ImageUpdater manifests (GitHub Actions friendly).

This script is designed to be used from CI (Bootstrap K8s workflow). It performs
minimal templating (replacing YOUR_ORG and updating a few known Helm values),
then kubectl-applies the Argo CD Applications and ImageUpdater resource.

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
    v = os.getenv(name, "").strip()
    if not v:
        raise SystemExit(f"Missing env var: {name}")
    return v


def _run(cmd: list[str]) -> None:
    subprocess.check_call(cmd)


def _load_yaml(p: Path) -> dict:
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _dump_yaml(p: Path, obj: dict) -> None:
    with p.open("w", encoding="utf-8") as f:
        yaml.safe_dump(obj, f, sort_keys=False)


def _replace_org_repo(p: Path, org: str, repo: str) -> None:
    s = p.read_text(encoding="utf-8")
    s = s.replace("YOUR_ORG", org)
    s = s.replace("https://github.com/YOUR_ORG/QueenCalifia-CyberAI.git", f"https://github.com/{org}/{repo}.git")
    p.write_text(s, encoding="utf-8")


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]

    org = _req("QC_GIT_ORG")
    repo = os.getenv("QC_GIT_REPO", "QueenCalifia-CyberAI").strip() or "QueenCalifia-CyberAI"
    api_img = _req("QC_API_IMAGE")
    fe_img = _req("QC_FRONTEND_IMAGE")
    staging_host = _req("QC_STAGING_HOST")
    prod_host = _req("QC_PROD_HOST")

    # Patch Helm values files (structural YAML)
    for fname, host, issuer in [
        ("helm/queen-califia/values-argocd-staging.yaml", staging_host, "letsencrypt-staging"),
        ("helm/queen-califia/values-argocd-production.yaml", prod_host, "letsencrypt-prod"),
    ]:
        p = repo_root / fname
        obj = _load_yaml(p)

        obj["api"]["image"]["repository"] = api_img
        obj["frontend"]["image"]["repository"] = fe_img

        obj.setdefault("ingress", {}).setdefault("certManager", {})["clusterIssuer"] = issuer
        obj["ingress"]["host"] = host

        _dump_yaml(p, obj)

    # Patch repoURL/ORG placeholders in manifests
    for fname in [
        "k8s/argocd/application-queen-califia-staging.yaml",
        "k8s/argocd/application-queen-califia-production.yaml",
        "k8s/argocd/image-updater-queen-califia-staging.yaml",
    ]:
        _replace_org_repo(repo_root / fname, org, repo)

    # Also patch imageName placeholders in the ImageUpdater CR
    iu_path = repo_root / "k8s/argocd/image-updater-queen-califia-staging.yaml"
    s = iu_path.read_text(encoding="utf-8").replace("ghcr.io/YOUR_ORG/queencalifia-api", api_img).replace(
        "ghcr.io/YOUR_ORG/queencalifia-frontend", fe_img
    )
    iu_path.write_text(s, encoding="utf-8")

    # Apply
    _run(["kubectl", "apply", "-n", "argocd", "-f", str(repo_root / "k8s/argocd/application-queen-califia-staging.yaml")])
    _run(["kubectl", "apply", "-n", "argocd", "-f", str(repo_root / "k8s/argocd/application-queen-califia-production.yaml")])
    _run(["kubectl", "apply", "-f", str(repo_root / "k8s/argocd/image-updater-queen-califia-staging.yaml")])

    print("✅ Applied Argo CD Applications + ImageUpdater (staging only).")


if __name__ == "__main__":
    main()
