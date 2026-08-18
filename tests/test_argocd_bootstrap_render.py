from __future__ import annotations

from pathlib import Path

import yaml

from scripts.bootstrap.render_and_apply_argocd import (
    _render_application,
    _render_image_updater,
)


def test_render_application_persists_runtime_overrides_in_argo_spec(tmp_path):
    path = tmp_path / "application.yaml"
    path.write_text(
        """apiVersion: argoproj.io/v1alpha1
kind: Application
spec:
  source:
    repoURL: https://github.com/YOUR_ORG/QueenCalifia-CyberAI.git
    targetRevision: production
    path: helm/queen-califia
    helm:
      valueFiles:
        - values-argocd-production.yaml
""",
        encoding="utf-8",
    )

    _render_application(
        path,
        org="HeruAhmose",
        repo="QueenCalifia-CyberAI",
        api_image="ghcr.io/heruahmose/queencalifia-api",
        frontend_image="ghcr.io/heruahmose/queencalifia-frontend",
        host="qc.example.org",
        cluster_issuer="letsencrypt-prod",
    )

    app = yaml.safe_load(path.read_text(encoding="utf-8"))
    source = app["spec"]["source"]
    assert source["repoURL"] == "https://github.com/HeruAhmose/QueenCalifia-CyberAI.git"
    assert source["helm"]["valueFiles"] == ["values-argocd-production.yaml"]

    params = {item["name"]: item for item in source["helm"]["parameters"]}
    assert params["api.image.repository"]["value"] == "ghcr.io/heruahmose/queencalifia-api"
    assert params["frontend.image.repository"]["value"] == "ghcr.io/heruahmose/queencalifia-frontend"
    assert params["ingress.host"]["value"] == "qc.example.org"
    assert params["ingress.certManager.clusterIssuer"]["value"] == "letsencrypt-prod"
    assert all(item["forceString"] is True for item in params.values())


def test_render_application_updates_existing_parameter_without_duplicates(tmp_path):
    path = tmp_path / "application.yaml"
    path.write_text(
        """spec:
  source:
    helm:
      parameters:
        - name: ingress.host
          value: old.example.org
""",
        encoding="utf-8",
    )

    _render_application(
        path,
        org="HeruAhmose",
        repo="QueenCalifia-CyberAI",
        api_image="ghcr.io/heruahmose/api",
        frontend_image="ghcr.io/heruahmose/frontend",
        host="new.example.org",
        cluster_issuer="letsencrypt-prod",
    )

    app = yaml.safe_load(path.read_text(encoding="utf-8"))
    parameters = app["spec"]["source"]["helm"]["parameters"]
    ingress_host = [item for item in parameters if item["name"] == "ingress.host"]
    assert len(ingress_host) == 1
    assert ingress_host[0]["value"] == "new.example.org"


def test_render_image_updater_replaces_only_declared_placeholders(tmp_path):
    path = tmp_path / "image-updater.yaml"
    path.write_text(
        """repo: https://github.com/YOUR_ORG/QueenCalifia-CyberAI.git
api: ghcr.io/YOUR_ORG/queencalifia-api
frontend: ghcr.io/YOUR_ORG/queencalifia-frontend
owner: YOUR_ORG
""",
        encoding="utf-8",
    )

    _render_image_updater(
        path,
        org="HeruAhmose",
        repo="QueenCalifia-CyberAI",
        api_image="ghcr.io/heruahmose/queencalifia-api",
        frontend_image="ghcr.io/heruahmose/queencalifia-frontend",
    )

    rendered = path.read_text(encoding="utf-8")
    assert "YOUR_ORG" not in rendered
    assert "https://github.com/HeruAhmose/QueenCalifia-CyberAI.git" in rendered
    assert "ghcr.io/heruahmose/queencalifia-api" in rendered
    assert "ghcr.io/heruahmose/queencalifia-frontend" in rendered


def test_bootstrap_script_does_not_rewrite_git_helm_values():
    script = Path("scripts/bootstrap/render_and_apply_argocd.py").read_text(encoding="utf-8")

    assert "values-argocd-staging.yaml" not in script
    assert "values-argocd-production.yaml" not in script
    assert "spec.source.helm.parameters" not in script or "parameters" in script
