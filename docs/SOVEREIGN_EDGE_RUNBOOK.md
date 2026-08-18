# Sovereign Local Edge Production-Candidate Runbook

This profile replaces OCI as Queen Califia's preferred production candidate without claiming HA or weakening issue #72. The host is a dedicated Ubuntu Server machine. Neon PostgreSQL 18 remains the authoritative application datastore. Valkey is local task infrastructure only. Public web ingress is through Cloudflare Tunnel; the host publishes no HTTP, HTTPS, PostgreSQL, or Valkey ports.

## Architecture

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

Cloudflare documents Tunnel as outbound-only connectivity that does not require a publicly routable origin IP. For a restrictive firewall, `cloudflared` requires outbound TCP/UDP 7844. The tunnel token is a secret: anyone holding it can run the tunnel.

Valkey documents `port 0` as disabling the non-TLS listener and enables mutual TLS client authentication by default when TLS is configured with a CA.

## Safety state

`config/sovereign-edge-deployment-state.json` is authoritative for deployment claims. Repository merge alone must not set any live evidence flag true.

The following remain false until real host/provider evidence exists:

- host provisioned and identity verified
- full-disk encryption verified
- firewall policy verified
- Cloudflare Tunnel provisioned/identity/hostname verified
- Valkey PKI generated and authority verified
- production migration verified
- whole-database manifest verified
- independent backup/restore verified
- health/task/scanner-write probes verified
- restart and real-reboot persistence verified
- runtime authorization
- production cutover
- HA, multi-replica API, read-only-rootfs conversion, legacy-storage retirement

Historical Render `backend/data/qc_scans.db` remains `unrecoverable-unverified`, never synthesized as empty or absent.

## 0. Dedicated host prerequisites

Use a dedicated Ubuntu Server installation rather than a daily workstation for permanent service. During OS installation, enable full-disk encryption if compatible with the intended unattended-boot model. Record the actual encryption configuration; do not mark it verified merely because the runbook recommends it.

Recommended physical controls:

- wired Ethernet
- BIOS/UEFI restore-after-AC-power-loss enabled and tested
- small UPS if available
- router with no inbound port-forward for this host
- SSH permitted only from a private LAN/VPN administration CIDR

## 1. Install repository at the canonical host path

```bash
sudo install -d -m 0755 /opt/queen-califia
sudo chown "$USER":"$USER" /opt/queen-califia
git clone https://github.com/HeruAhmose/QueenCalifia-CyberAI.git /opt/queen-califia
cd /opt/queen-califia
git checkout main
```

Record and verify the exact protected-main SHA before any production evidence run.

## 2. Harden the host

Choose the private LAN/VPN network that is allowed to administer SSH. The bootstrap refuses a public CIDR.

```bash
cd /opt/queen-califia
export QC_ADMIN_CIDR='192.168.1.0/24'   # replace with the actual private admin network
sudo -E bash scripts/edge/bootstrap-ubuntu.sh
sudo ufw status verbose
```

The expected firewall has default-deny incoming and no 80/443/5432/6379 allow rules. SSH is allowed only from the private administration CIDR. Do not add router port forwarding.

## 3. Generate local Valkey mTLS PKI

```bash
cd /opt/queen-califia
sudo bash scripts/edge/generate-valkey-mtls.sh
```

This creates a private CA plus distinct server, health, API, and worker certificates under `/srv/queen-califia/pki/valkey`. The CA private key stays root-only. Runtime private keys are readable only by UID/GID 10001. Never commit this directory.

Back up the CA/private material only through encrypted host-state backup or another explicitly encrypted offline mechanism.

## 4. Configure Neon and application secrets

```bash
cd /opt/queen-califia
cp deploy/edge/.env.edge.example .env.edge
chmod 600 .env.edge
```

Populate:

- `QC_DATABASE_URL` and `DATABASE_URL` with the Neon pooled hostname and `sslmode=require`
- `QC_DATABASE_DIRECT_URL` with the Neon direct hostname and `sslmode=require`
- production API/audit/metrics secrets
- later, the Cloudflare tunnel token

Never commit `.env.edge`.

## 5. Create the Cloudflare Tunnel

Create a named remotely-managed Cloudflare Tunnel for Queen Califia using the Cloudflare dashboard or API. Configure exactly one public hostname route for the application whose origin service is:

```text
http://caddy:8080
```

The `cloudflared` container and Caddy share the private Docker `edge` network. Caddy publishes no host port.

For remote API creation, use a least-privilege Cloudflare API token with the documented Tunnel/Connector write permission and DNS write permission only where DNS creation is required. Do not store that API token in the repository. Only the resulting tunnel token belongs in `.env.edge` as `CF_TUNNEL_TOKEN`.

Before production cutover, verify from the Cloudflare control plane that:

- tunnel UUID/name are real and recorded
- connector status is healthy
- public hostname points to the intended tunnel
- origin service is `http://caddy:8080`
- there are no alternate public origin records that bypass Cloudflare

## 6. Pre-authorization queue proof

The API and worker remain fail-closed because the authorization marker does not exist. Validate the queue independently:

```bash
cd /opt/queen-califia
sudo -E scripts/edge/verify-runtime.sh --preauth
```

The proof must demonstrate:

- compose declares no published host ports
- TLS/mTLS Valkey ping succeeds
- a plaintext Valkey request fails
- no production runtime authorization is inferred

Do not create the authorization marker yet.

## 7. Historical-source disposition and authentic migration

Run the existing source-disposition/migration contracts only against artifacts that actually exist. The suspended Render container-local `qc_scans.db` remains `unrecoverable-unverified` unless provider-backed recovery evidence becomes available.

Use the direct Neon endpoint for migration/evidence operations. After migration, generate the repository's whole-database manifest and retain it in the production evidence package.

Never synthesize an empty source and never mark a missing historical artifact `verified_absent` without evidence.

## 8. Encrypted PostgreSQL backup and independent restore

Create an age recipients file outside Git:

```bash
export QC_BACKUP_AGE_RECIPIENTS_FILE=/root/qc-backup-recipients.txt
sudo -E scripts/edge/backup-postgres.sh
```

Create a separate empty Neon verification database/branch and set its direct TLS URL:

```bash
export QC_BACKUP_AGE_IDENTITY_FILE=/root/qc-backup-age-key.txt
export QC_RESTORE_DATABASE_URL='postgresql://...DIRECT-VERIFY.../neondb?sslmode=require'
sudo -E scripts/edge/restore-postgres.sh /srv/queen-califia/backups/queen-<timestamp>.dump.age
```

The restore verifier refuses a pooled endpoint, refuses a nonempty target, and refuses the live direct URL by default.

Regenerate the whole-database manifest from the restored target and require equality with the source manifest before backup/restore is considered verified.

## 9. Encrypted local host-state backup

```bash
export QC_BACKUP_AGE_RECIPIENTS_FILE=/root/qc-backup-recipients.txt
sudo -E scripts/edge/backup-host-state.sh
```

This streams `app`, `evidence`, Valkey AOF data, and PKI directly into age encryption. No plaintext tar archive is written.

Store at least one encrypted copy away from the edge host before production authorization.

## 10. Authorize only after evidence review

Only after authentic migration/disposition, source database manifest, encrypted database backup, independent restore/manifest equality, queue proof, and host/tunnel identity review may the single-node runtime be authorized:

```bash
sudo install -d -m 0750 -o 10001 -g 10001 /srv/queen-califia/app/cutover
printf 'AUTHORIZED\n' | sudo tee /srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED >/dev/null
sudo chown 10001:10001 /srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED
sudo chmod 0440 /srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED
```

This marker authorizes only one local API + one worker. It does not authorize HA, multiple API replicas, read-only-rootfs conversion, historical source deletion, or production DNS cutover by itself.

## 11. Start and prove the authorized runtime

```bash
cd /opt/queen-califia
sudo -E scripts/edge/verify-runtime.sh --authorized
```

This verifies queue TLS/plaintext refusal, API health/readiness, private Caddy routing, Celery worker response, cloudflared container liveness, Neon PostgreSQL 18 direct authority, and absence of published host ports. It writes a machine-readable evidence record under `/srv/queen-califia/evidence`.

Complete an actual representative Celery scan task and verify its expected PostgreSQL writes before setting the corresponding ledger flags true.

## 12. Install fail-closed health watchdog

```bash
cd /opt/queen-califia
sudo install -m 0644 deploy/edge/systemd/queen-califia-edge-watchdog.service /etc/systemd/system/
sudo install -m 0644 deploy/edge/systemd/queen-califia-edge-watchdog.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now queen-califia-edge-watchdog.timer
```

The watchdog can recover unhealthy containers only when the existing authorization marker contains `AUTHORIZED`. It never creates, edits, or repairs the marker.

## 13. Real reboot persistence proof

Prepare a challenge on the current boot:

```bash
cd /opt/queen-califia
sudo -E scripts/edge/reboot-persistence-proof.sh prepare
sudo reboot
```

After the machine returns:

```bash
cd /opt/queen-califia
sudo -E scripts/edge/reboot-persistence-proof.sh verify
```

Verification requires the Linux boot ID to be different, the Valkey challenge value to survive from AOF, the API to become healthy, and cloudflared to be running. A same-boot container restart cannot satisfy this proof.

Also perform a controlled AC-loss/UPS test separately if that physical-resilience claim is to be recorded.

## 14. Production traffic cutover

Production routing remains the final gate. Before changing it, retain evidence for:

- protected-main SHA and image/build identity
- dedicated-host identity and OS version
- disk-encryption state
- UFW rules
- Tunnel UUID/connector health/public hostname
- Valkey CA fingerprint and TLS-only/mTLS proof
- migration/disposition results
- source manifest
- encrypted database dump checksum
- independent restore manifest equality
- host-state backup checksum
- API/readiness/Celery/scanner-write probes
- restart and real-reboot persistence

Only then update `config/sovereign-edge-deployment-state.json` through a protected PR with evidence-backed flags. Do not mark HA or multi-replica support true for this single physical host.

## Rollback

If runtime validation fails, preserve all evidence and state, then stop public delivery without deleting data:

```bash
cd /opt/queen-califia
docker compose --env-file .env.edge -f deploy/edge/docker-compose.edge.yml stop cloudflared caddy frontend worker api
```

Valkey and Neon data/evidence remain intact. Do not delete `/srv/queen-califia`, encrypted backups, PKI, recovered historical sources, or issue #72 evidence during rollback.
