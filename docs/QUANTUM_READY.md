# Quantum-ready + resistant (production posture)

"Quantum capable/resistant" means building a system today that can absorb tomorrow's cryptographic transitions without architectural changes.

## Quantum-ready (crypto agility)

- **TLS 1.3** end-to-end (edge nginx → Ingress → in-cluster)
- **Centralized crypto configuration**: all TLS settings live in Ingress annotations and edge `ssl_protocols` — swap algorithms in one place when PQC standards land
- **Short-lived certificates**: automated ACME renewal (certbot profile or cert-manager) minimizes exposure window
- **SPKI pinning**: public-key pinning for Redis TLS connections — pins to the SubjectPublicKeyInfo hash, not the full cert, so CA migrations are transparent
- **Digest-pinned images**: container images referenced by `sha256` digest, not mutable tags — immune to supply-chain tag-swap attacks

When your platform supports **hybrid post-quantum TLS** (PQC + classical KEM), enable it at the edge/ingress layer. Zero app-level changes required.

## Resistant (operational + security posture)

- **Immutable deploys**: digest pinning via Argo CD Image Updater ensures every running pod is byte-identical to what CI tested
- **Deterministic lockfiles** with hashes: `pip-tools` lockfiles are generated in a Linux container and verified in CI — supply-chain drift is caught before merge
- **Liveness / readiness probes**: `/healthz` and `/readyz` give Kubernetes real-time health signals
- **Least-privilege runtime**: non-root container images, optional pod/container security contexts, NetworkPolicy support
- **Pod Disruption Budgets**: protect against voluntary disruption during rollouts and node drains
- **HorizontalPodAutoscaler**: scale to load with configurable CPU/memory targets
- **End-to-end Ingress E2E tests**: CI spins up a KIND cluster, installs ingress-nginx, creates a self-signed TLS cert, and validates HTTP→HTTPS redirect + API routing
- **PR-gated updates**: every change — dependency refresh, image update, version sync — arrives as a PR that must pass CI before merge
- **Helm values schema**: `values.schema.json` validates all configuration knobs at `helm lint` time — typos and invalid values are caught before deploy

This is the practical "production" meaning: **secure-by-default**, **observable**, **patchable**, **rollbackable**, **crypto-agile**.
