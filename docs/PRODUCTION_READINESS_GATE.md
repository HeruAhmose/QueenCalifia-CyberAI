# Queen Califia Sovereign Edge Production Readiness Gate

Queen Califia uses a fail-closed, staged readiness model. This control does **not** create, edit, repair, or remove the runtime authorization marker.

The authoritative evidence inputs are:

- `config/sovereign-edge-deployment-state.json`
- `config/runtime-state-topology.json`

The checker is:

```bash
python3 scripts/edge/check-production-readiness.py --stage authorization --json
```

## Stage 1 — authorization

This stage answers one question only: **are all prerequisites satisfied for a human-reviewed decision to open the single-API/single-worker runtime authorization gate?**

It requires evidence that can exist while the runtime gate is still closed:

- validated restricted Hyper-V control plane
- final production-host provisioning and identity evidence
- final production-host full-disk encryption
- final production-host default-deny firewall evidence
- BIOS/UEFI restore-after-power-loss evidence
- UPS evidence
- verified Cloudflare tunnel identity, hostname, origin route, registration, and dormant fail-closed return
- zero host-published HTTP ports
- verified PostgreSQL manifest and independent encrypted backup/restore
- completed historical-source migration/disposition
- provider-backed resolution of the historical Render `qc_scans.db` source
- final-host Valkey PKI and authority verification
- Valkey preauthorization TLS success and plaintext refusal
- fresh fail-closed runtime preauthorization proof with zero published host ports
- at least one verified encrypted backup copy away from the edge host

This stage deliberately does **not** require API health, Celery completion, scanner PostgreSQL-write probes, restart/reboot persistence, production cutover, HA, multi-replica operation, or read-only-rootfs evidence. Those facts cannot all be proven before authorization and must not create a circular gate.

Current protected CI executes:

```bash
python3 scripts/edge/check-production-readiness.py \
  --stage authorization \
  --expect-blocked
```

That is intentional. When every authorization prerequisite is genuinely evidenced, CI must fail until a separate reviewed change deliberately changes the expected transition state. Evidence cannot silently make the authorization boundary disappear.

## Stage 2 — cutover

After authorization has been deliberately approved and the runtime marker has been opened through an approved operator procedure, evaluate:

```bash
python3 scripts/edge/check-production-readiness.py --stage cutover --json
```

Cutover inherits all authorization prerequisites and additionally requires:

- repository deployment state records production authorization
- runtime authorization is recorded
- API/readiness probes verified
- representative Celery task completion verified
- scanner PostgreSQL writes verified
- restart persistence verified
- real-reboot persistence verified
- production source capture/migration/disposition evidence complete
- production backup/restore evidence complete
- production authority probes verified
- immutable cutover evidence recorded
- production cutover explicitly recorded complete

Authorization is therefore **not** equivalent to cutover.

## Stage 3 — HA / read-only-rootfs

Only after cutover is complete may the later architecture gate be evaluated:

```bash
python3 scripts/edge/check-production-readiness.py --stage ha --json
```

HA inherits authorization and cutover requirements and additionally requires the #72 completion evidence for externalized authoritative writers, backup/restore, concurrent writers, rolling updates, writable-path enumeration, read-only-rootfs enablement, multi-replica API enablement, explicit HA authorization, and legacy-storage retirement authorization.

The Stage 3 gate must never be used to justify opening the initial authorization marker.

## Exit behavior

Without an expectation flag, a blocked stage exits nonzero and a ready stage exits zero.

`--expect-blocked` succeeds only while the stage has one or more blockers. `--expect-ready` succeeds only when every prerequisite for that stage is satisfied.

Use `--json` when recording or reviewing evidence. The report contains the selected stage, every check, observed/required values, blocker list, and blocker count. It contains no secret material.

## Non-authorization guarantee

Merging the checker or running it does not authorize production. The marker remains authoritative:

```text
/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED
```

No readiness script may create, modify, repair, or bypass that file.
