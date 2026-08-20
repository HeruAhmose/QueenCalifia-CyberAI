# Sovereign Local Edge Production-Candidate Runbook

Queen Califia's preferred production candidate is the Sovereign Local Edge. The currently validated candidate runs as an Ubuntu Server guest on Microsoft Hyper-V and uses the `systemd-hyperv-v1` restricted host-control plane. This is a validated production candidate, **not** final production authorization and **not** proof of dedicated physical-host controls.

Neon PostgreSQL 18 remains the authoritative application datastore. Valkey is local task infrastructure only. Public ingress is designed around Cloudflare Tunnel, and the application topology publishes no HTTP, HTTPS, PostgreSQL, or Valkey host ports.

## Architecture

- Microsoft Hyper-V production-candidate VM: `QueenCalifia-Sovereign-Edge-HyperV`
- Ubuntu Server guest hostname: `qc-edge-01`
- canonical guest repository: `/opt/queen-califia`
- restricted Windows-to-guest control plane: `systemd-hyperv-v1`
- one API container
- one Celery worker
- one frontend container
- one private Caddy reverse proxy on Docker port 8080 only
- one `cloudflared` connector using a named remotely-managed tunnel
- one Valkey 9.1.1 container on an internal Docker network
- Valkey plaintext listener disabled (`port 0`)
- Valkey TLS listener on 6379 with mandatory client certificates
- Valkey AOF persistence (`appendonly yes`, `appendfsync everysec`)
- Neon PostgreSQL 18 pooled endpoint for application runtime
- Neon direct endpoint for migration, manifest, `pg_dump`, and restore evidence

Hyper-V host control is intentionally narrow. The enrolled Ed25519 key is attached to the non-root guest user and is restricted by `authorized_keys` forced command plus sudoers to only `ACTIVATE`, `STATUS`, `STOP`, and `RESTART`. That control path cannot create, edit, or repair the production authorization marker.

## Safety state

`config/sovereign-edge-deployment-state.json` is authoritative for deployment claims. Repository merge alone must never create live evidence.

The current v2 ledger distinguishes three categories:

1. **Validated production-candidate evidence** — facts already demonstrated on the Hyper-V candidate.
2. **Final production-host/provider evidence** — physical-host and Cloudflare claims that remain open.
3. **Authorized-runtime/cutover evidence** — facts that cannot be proven until production authorization is deliberately opened after prerequisite review.

### Validated candidate evidence

The ledger records the following facts as proven:

- Hyper-V deployment form and VM identity
- guest hostname `qc-edge-01`
- `systemd-hyperv-v1` control plane
- restricted forced-command control-key operation
- fresh fail-closed preauthorization runtime verification at protected-main SHA `770803fa52b5fc4279257da33a6817322df8cd98`
- no host-published application ports in that preauthorization proof
- Valkey TLS success and plaintext refusal in that preauthorization proof
- independent whole-database source/restore manifest equality
- encrypted PostgreSQL backup plus independent restore verification

The recorded preauthorization evidence file is:

```text
/srv/queen-califia/evidence/runtime-20260820T031522Z.json
```

The recorded database manifest digest is:

```text
efd4ec38a752f41255309635638aaa1c59e0f59dbd5953c0b7b89871882eaaed
```

The recorded encrypted PostgreSQL backup digest is:

```text
20a473c2e5312d357b1cb4fb92691f33bb192f429deba9a5af00e870d81d2ca0
```

### Gates that remain closed

The following must remain false until their own evidence exists:

- production authorization
- final production host provisioned/identity verified
- full-disk encryption verified
- final production-host firewall verified
- BIOS/UEFI restore-after-power-loss verified
- UPS verified
- Cloudflare Tunnel provisioned/identity/public-hostname verified
- final production-host Valkey PKI generation/authority verification
- historical-source production migration completion
- authorized API/readiness/Celery/scanner-write probes
- restart and real-reboot persistence
- production cutover
- HA, multi-replica API, read-only-rootfs conversion, legacy-storage retirement

Historical Render `backend/data/qc_scans.db` remains `unrecoverable-unverified`. Never synthesize it as empty or absent.

## 0. Hyper-V production-candidate contract

The current VM is a controlled production candidate. Hyper-V is part of the trust boundary. Do not treat VM-level evidence as proof of host full-disk encryption, BIOS/UEFI power-loss behavior, UPS behavior, or other physical-host resilience.

The Windows launcher is:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\edge\windows\qc.ps1 status
```

Expected fail-closed status before production authorization:

```text
CONTROL_PLANE=systemd-hyperv-v1
QUEEN_CALIFIA=BLOCKED
DETAIL=runtime authorization gate is closed
```

A `BLOCKED` result is correct until the authorization prerequisites are satisfied.

## 1. Canonical guest installation

The guest checkout lives at:

```text
/opt/queen-califia
```

Before evidence work, require the guest checkout to match the intended protected-main SHA exactly.

```bash
cd /opt/queen-califia
git fetch origin main
git merge --ff-only origin/main
git rev-parse HEAD
```

## 2. Guest network hardening

The Ubuntu guest should retain default-deny inbound policy and expose SSH only to the intended private host/admin source. No guest firewall or Docker configuration may expose 80, 443, 5432, or 6379 directly.

Guest UFW evidence is useful candidate evidence, but `host.firewall_default_deny_incoming_verified` in the deployment ledger remains reserved for the final production-host trust boundary.

## 3. Valkey mTLS

Valkey remains private task infrastructure and must satisfy the indivisible queue contract:

- no plaintext listener (`port 0`)
- TLS listener on 6379
- mandatory client certificates
- internal Docker network
- no published host port
- AOF persistence enabled

Generate or rotate PKI only with:

```bash
cd /opt/queen-califia
sudo bash scripts/edge/generate-valkey-mtls.sh
```

Do not mark final production-host `pki_generated` or `authority_verified` merely because candidate PKI exists; those flags close only when the selected final production host is reconciled and evidenced.

## 4. Neon PostgreSQL 18

Application runtime uses the pooled TLS endpoint. Migration, manifest, `pg_dump`, and restore evidence use the direct TLS endpoint.

The independent source/restore manifest equality and encrypted backup/restore proof are already recorded in the v2 deployment ledger. This does **not** imply that historical-source migration is complete: the Render container-local `qc_scans.db` remains unresolved.

## 5. Cloudflare Tunnel

The intended public ingress remains outbound-only Cloudflare Tunnel with origin service:

```text
http://caddy:8080
```

Before any production authorization or cutover claim, verify from the Cloudflare control plane:

- tunnel UUID/name
- intended connector identity and health
- public hostname route
- origin service `http://caddy:8080`
- absence of alternate origin records that bypass the tunnel

Until that review is complete, `tunnel_provisioned`, `tunnel_identity_verified`, and `public_hostname_verified` remain false.

## 6. Preauthorization proof

With the authorization marker closed, run:

```bash
cd /opt/queen-califia
sudo -E scripts/edge/verify-runtime.sh --preauth
```

The proof must demonstrate:

- no published host ports
- Valkey TLS/mTLS request succeeds
- plaintext Valkey request fails
- authorized application runtime is not probed

This proof must never be interpreted as API health, Celery completion, scanner PostgreSQL-write, restart, reboot, or production-cutover evidence.

## 7. Historical-source disposition

The suspended Render container-local source remains:

```text
unrecoverable-unverified
```

Do not synthesize an empty replacement, do not mark it `verified_absent`, and do not retire retained Render evidence unless provider-backed recovery/disposition evidence becomes available.

Because of this unresolved historical source, `postgresql.production_migration_verified` remains false even though the current Neon database backup/restore and manifest proofs are valid.

## 8. Encrypted PostgreSQL backup and independent restore

Future backup refreshes use the existing guarded scripts:

```bash
sudo -E scripts/edge/backup-postgres.sh
sudo -E scripts/edge/restore-postgres.sh /srv/queen-califia/backups/queen-<timestamp>.dump.age
```

The restore target must be independent and empty, must use a direct TLS endpoint, and must not be the live production database. Regenerate the whole-database manifest on the restore target and require equality before replacing the recorded evidence digest.

## 9. Encrypted host-state backup

Create host-state backup with:

```bash
sudo -E scripts/edge/backup-host-state.sh
```

The backup must remain encrypted end-to-end and at least one encrypted copy must be stored off the edge host before production authorization.

## 10. Production authorization gate

Do **not** create or modify:

```text
/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED
```

until all required source-disposition, database, queue, host, Cloudflare identity, and off-host-backup evidence has been reviewed.

When authorization is eventually approved, the marker authorizes only one API and one worker. It does not authorize HA, multiple API replicas, read-only-rootfs conversion, historical-source deletion, or production traffic cutover.

## 11. Authorized runtime proof

Only after authorization is deliberately opened:

```bash
cd /opt/queen-califia
sudo -E scripts/edge/verify-runtime.sh --authorized
```

Then separately complete a representative Celery task and prove its expected PostgreSQL writes before setting `celery_task_completion_verified` or `scanner_postgres_writes_verified` true.

## 12. Watchdog

The watchdog may recover unhealthy services only when the existing authorization marker already contains `AUTHORIZED`. It must never create, edit, or repair that marker.

Install with the repository systemd installer rather than manually weakening unit policy.

## 13. Restart and reboot persistence

Restart persistence and real reboot persistence are separate evidence gates. A container restart cannot satisfy the real-reboot proof.

For reboot evidence:

```bash
cd /opt/queen-califia
sudo -E scripts/edge/reboot-persistence-proof.sh prepare
sudo reboot
```

After the guest returns:

```bash
cd /opt/queen-califia
sudo -E scripts/edge/reboot-persistence-proof.sh verify
```

Physical AC-loss/UPS behavior remains a separate final-host control and cannot be inferred from a Hyper-V guest reboot.

## 14. Final production-host reconciliation and cutover

If Hyper-V remains the chosen architecture for final production, explicitly define and evidence the physical Windows host trust boundary before clearing final-host gates. If Queen Califia moves to a dedicated physical Ubuntu host instead, re-run host-bound evidence there rather than carrying VM evidence forward as equivalent.

Before production traffic cutover, retain evidence for:

- protected-main SHA and build identity
- final host identity and OS/hypervisor architecture
- full-disk encryption state
- final host firewall policy
- BIOS/UEFI power-loss behavior and UPS status when applicable
- Cloudflare tunnel UUID/connector/public hostname
- Valkey CA fingerprint and final-host PKI authority
- historical-source disposition
- source/restore database manifests
- encrypted database backup checksum
- independent restore equality
- encrypted host-state backup checksum and off-host copy
- authorized API/readiness/Celery/scanner-write probes
- restart and real-reboot persistence

Only then advance `production_authorized` or `production_cutover_complete` through a protected PR backed by the corresponding evidence.

## Rollback

If runtime validation fails, preserve all evidence and state and stop public delivery without deleting data:

```bash
cd /opt/queen-califia
docker compose --env-file .env.edge -f deploy/edge/docker-compose.edge.yml stop cloudflared caddy frontend worker api
```

Do not delete `/srv/queen-califia`, encrypted backups, PKI, recovered historical sources, or retained issue evidence during rollback.
