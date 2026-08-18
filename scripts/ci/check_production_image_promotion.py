"""Fail closed unless production promotes the exact staged image digests.

This guard is intended for pull requests whose base branch is ``production``.
Argo Image Updater writes immutable digests to the staging Helm values file. A
staging -> production branch merge alone does not copy those values into the
separate production values file, so the promotion PR must explicitly carry the
same digests before production is allowed to advance.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
STAGING_VALUES = ROOT / "helm/queen-califia/values-argocd-staging.yaml"
PRODUCTION_VALUES = ROOT / "helm/queen-califia/values-argocd-production.yaml"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMPONENTS = ("api", "frontend")


def _load(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise SystemExit(f"Invalid YAML object: {path}")
    return value


def _digest(values: dict, component: str, path: Path) -> str:
    try:
        digest = str(values[component]["image"]["digest"]).strip().lower()
    except (KeyError, TypeError) as exc:
        raise SystemExit(f"Missing {component}.image.digest in {path}") from exc

    if not DIGEST_RE.fullmatch(digest):
        raise SystemExit(
            f"{component}.image.digest in {path} must be an immutable sha256:<64 hex> digest; got {digest!r}"
        )
    return digest


def validate_promotion(staging_path: Path = STAGING_VALUES, production_path: Path = PRODUCTION_VALUES) -> None:
    staging = _load(staging_path)
    production = _load(production_path)

    for component in COMPONENTS:
        staged_digest = _digest(staging, component, staging_path)
        production_digest = _digest(production, component, production_path)
        if production_digest != staged_digest:
            raise SystemExit(
                f"{component} production digest does not match staged digest: "
                f"staging={staged_digest} production={production_digest}"
            )


def main() -> None:
    validate_promotion()
    print("Production image promotion verified: API and frontend digests are immutable and match staging.")


if __name__ == "__main__":
    main()
