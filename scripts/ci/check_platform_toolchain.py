#!/usr/bin/env python3
"""Validate Queen Califia's pinned platform toolchain contract."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ROOT / "scripts/bootstrap/versions.env"
REQUIREMENTS = ROOT / "scripts/bootstrap/requirements.txt"
WORKFLOWS = ROOT / ".github/workflows"

REQUIRED_KEYS = (
    "KUBECTL_VERSION",
    "HELM_VERSION",
    "ARGOCD_CLI_VERSION",
    "ARGOCD_CLI_SHA256",
    "INGRESS_NGINX_CHART_VERSION",
    "CERT_MANAGER_CHART_VERSION",
    "ARGOCD_CHART_VERSION",
    "ARGOCD_IMAGE_UPDATER_CHART_VERSION",
)


def fail(message: str) -> None:
    raise SystemExit(message)


def read_manifest() -> dict[str, str]:
    if not VERSIONS.is_file():
        fail(f"missing canonical version manifest: {VERSIONS.relative_to(ROOT)}")
    values: dict[str, str] = {}
    for raw in VERSIONS.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f"invalid version-manifest line: {raw!r}")
        key, value = line.split("=", 1)
        if key in values:
            fail(f"duplicate version key: {key}")
        values[key] = value.strip()
    for key in REQUIRED_KEYS:
        if not values.get(key):
            fail(f"missing or empty version key: {key}")
    return values


def main() -> int:
    values = read_manifest()

    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", values["KUBECTL_VERSION"]):
        fail("KUBECTL_VERSION must be an explicit vX.Y.Z release")
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", values["HELM_VERSION"]):
        fail("HELM_VERSION must be an explicit vX.Y.Z release")
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", values["ARGOCD_CLI_VERSION"]):
        fail("ARGOCD_CLI_VERSION must be an explicit vX.Y.Z release")
    if not re.fullmatch(r"[0-9a-f]{64}", values["ARGOCD_CLI_SHA256"]):
        fail("ARGOCD_CLI_SHA256 must be a lowercase SHA-256 digest")

    if not REQUIREMENTS.is_file():
        fail("missing scripts/bootstrap/requirements.txt")
    req = REQUIREMENTS.read_text(encoding="utf-8")
    if not re.search(r"(?mi)^PyYAML==\d+\.\d+(?:\.\d+)?$", req):
        fail("bootstrap PyYAML dependency must be exactly version-pinned")

    mutable_binary = re.compile(r"releases/latest/download", re.IGNORECASE)
    unpinned_pyyaml = re.compile(r"pip\s+install[^\n]*\bpyyaml\b(?!==)", re.IGNORECASE)
    checked = 0
    for path in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]):
        text = path.read_text(encoding="utf-8")
        checked += 1
        if mutable_binary.search(text):
            fail(f"mutable release executable download found in {path.relative_to(ROOT)}")
        if unpinned_pyyaml.search(text):
            fail(f"unpinned PyYAML install found in {path.relative_to(ROOT)}")

    subprocess.run([sys.executable, str(ROOT / "scripts/ci/check_oci_deployment.py")], check=True)
    subprocess.run([sys.executable, str(ROOT / "scripts/ci/check_managed_free_deployment.py")], check=True)
    subprocess.run([sys.executable, str(ROOT / "scripts/ci/check_sovereign_edge_deployment.py")], check=True)
    subprocess.run([sys.executable, str(ROOT / "scripts/ci/check_final_host_evidence_contract.py")], check=True)
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/edge/check-production-readiness.py"),
            "--stage",
            "authorization",
            "--expect-blocked",
        ],
        check=True,
    )
    print(
        f"platform toolchain guard: {len(REQUIRED_KEYS)} pins valid; {checked} workflows clean; "
        "OCI historical, managed-free staging, Sovereign Edge deployment, and final-host evidence contracts clean; "
        "production authorization readiness remains explicitly fail-closed"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
