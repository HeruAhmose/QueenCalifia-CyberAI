# Queen Califia Sovereign Production Architecture

## Canonical production target

Queen Califia's canonical long-term production architecture is the sovereign local edge:

```text
Internet
  |
  v
Cloudflare DNS / TLS / Tunnel
  |
  | outbound-only tunnel; no public origin IP required
  v
Windows physical host
  |
  v
Hyper-V: QueenCalifia-Sovereign-Edge-HyperV
  |
  +-- Ubuntu Server guest: qc-edge-01
      |
      +-- API: one replica
      +-- Celery worker: one replica
      +-- Caddy origin
      +-- cloudflared connector
      +-- Valkey 9.1.1, private Docker network, TLS + mutual TLS, AOF
      |
      +--> Neon PostgreSQL 18 over TLS
```

The machine-readable deployment identity is:

```text
target=sovereign-local-edge
canonical_production_architecture=hyperv-cloudflare-neon-valkey
compute_location=sovereign-local
```

This architecture is the preferred production candidate. `preferred_production_candidate=true` does not imply authorization; production remains fail-closed until every authorization-stage gate is actually satisfied.

## Authority boundaries

### Compute

The production compute authority is the dedicated Windows physical host running the Hyper-V Ubuntu guest `QueenCalifia-Sovereign-Edge-HyperV`. Windows owns VM power/control-plane authority; the Ubuntu guest owns the systemd/Docker application runtime.

### Edge, DNS, and TLS

Cloudflare is the external edge. `cloudflared` establishes an outbound-only tunnel to `qc.tamerian-materials.com`. The origin publishes no host HTTP/HTTPS ports and requires no publicly routable origin IP.

### Database

Neon PostgreSQL 18 is authoritative application state. Application traffic uses the pooled connection mode; migration and backup operations use the direct TLS connection contract. Local SQLite is not production authority.

### Queue

Valkey 9.1.1 is self-hosted inside the sovereign edge private Docker network. It requires TLS and mutual TLS, refuses plaintext, uses AOF persistence, is not Internet exposed, and is not authoritative application state.

### Source

GitHub protected `main` is the source-code authority. Production evidence and deployment-state changes are reconciled through protected pull requests rather than by evidence scripts mutating authorization state.

## Render status

Render is historical context only:

```text
render_deployment_authority=false
render_historical_only=true
render_blueprint_retained=true
```

The former Render container-local scanner database path is:

```text
/opt/render/project/src/backend/data/qc_scans.db
```

Its evidence status remains:

```text
status=unrecoverable-unverified
captured=false
verified_absent=false
production_migration_verified=false
```

Operator context records that the one-click remediation and full brain-to-brain integration never completed successfully before Render suspension, so the database is expected to contain no meaningful production data. That observation is not provider-backed proof that the file was empty or absent and must never be converted into `verified_absent=true`, `captured=true`, or `production_migration_verified=true` without stronger evidence.

Render billing, suspension, or retirement must not control the sovereign runtime. Restoring or paying for Render is not required to operate the selected production architecture. Provider-backed recovery evidence, if later obtained, is handled only through the historical-source disposition/recovery procedure.

## Fail-closed production boundary

The selected architecture does not weaken the production gate. At the time this decision is recorded, authorization remains blocked by real external controls/evidence, including:

- physical-host BIOS restore-after-power-loss verification;
- UPS verification;
- independent encrypted off-host host-state backup proof;
- formal resolution of the historical Render source through verified recovery/migration, provider-verified absence, or evidence-backed disposition.

The authorization marker must remain absent until the repository readiness gate reports the authorization stage ready. No architectural-selection change may manufacture, bypass, or reinterpret those controls.

## Non-goals

This decision does not authorize production, does not enable multiple API replicas, does not authorize HA or read-only-rootfs, does not retire retained historical evidence, and does not claim recovery or migration of the Render SQLite source.
