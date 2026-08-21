# Queen Califia Render Historical-Source Disposition

The suspended Render container-local historical source remains:

```text
/opt/render/project/src/backend/data/qc_scans.db
```

with authoritative status:

```text
unrecoverable-unverified
```

This procedure exists only for a future **formal evidence-backed disposition review** if retained Render/provider evidence establishes that recovery is unavailable. It does not treat the source as empty, absent, captured, or migrated.

## Evidence boundary

The canonical local dossier lives at:

```text
/srv/queen-califia/evidence/render-source-disposition
```

Required request:

```text
/srv/queen-califia/evidence/render-source-disposition/request.json
```

Retained provider evidence bytes:

```text
/srv/queen-califia/evidence/render-source-disposition/provider-evidence/
```

Generated verification:

```text
/srv/queen-califia/evidence/render-source-disposition/verification.json
```

The verifier accepts no alternate paths.

## 1. Retain provider-backed evidence

Place one or more non-empty regular evidence files under `provider-evidence/`. Examples may include exported support correspondence, provider console exports, or other retained provider material relevant to recovery availability.

Do not place credentials, API tokens, private keys, or secrets in the dossier. Preserve sensitive provider material outside Git.

Symlinks are rejected. The verifier hashes every retained regular evidence file and stores only its relative-path hash, byte size, and SHA-256 in the verification record.

## 2. Create the disposition request

Create `request.json` with this contract:

```json
{
  "schema": "queen-califia-render-source-disposition-request-v1",
  "provider": "render",
  "former_path": "/opt/render/project/src/backend/data/qc_scans.db",
  "current_status": "unrecoverable-unverified",
  "requested_disposition": "formally-dispositioned",
  "provider_recovery_unavailable": true,
  "provider_contact_attempted": true,
  "verified_absent": false,
  "captured": false,
  "production_migration_verified": false,
  "provider_evidence_observed_at_utc": "YYYY-MM-DDTHH:MM:SSZ",
  "provider_evidence_reference": "concise identifier for the retained provider interaction",
  "disposition_rationale": "A substantive explanation, at least forty characters, of why the retained provider-backed evidence supports formal disposition while preserving the unresolved historical-loss truth.",
  "operator_attestation": "I attest that this request does not claim the historical source was recovered, migrated, or verified absent."
}
```

The three false fields are mandatory. The request is rejected if it attempts to claim verified absence, capture, or migration.

## 3. Verify the dossier

With the production authorization marker still absent:

```bash
cd /opt/queen-califia
sudo python3 scripts/edge/verify-render-source-disposition.py
```

The verifier:

1. requires the fixed request and provider-evidence locations;
2. refuses to run after production authorization has been opened;
3. refuses request or evidence symlinks;
4. requires at least one retained provider-evidence file;
5. validates the exact historical source and status boundary;
6. requires explicit provider recovery-unavailable and provider-contact assertions;
7. forbids verified-absence, capture, and migration claims;
8. hashes the request and every retained provider-evidence file;
9. refuses to overwrite an existing verification;
10. emits a verification record marked only `eligible_for_human_review=true`.

Expected successful output includes:

```text
RENDER_SOURCE_DISPOSITION=ELIGIBLE_FOR_HUMAN_REVIEW
RENDER_SOURCE_DISPOSITION_VERIFICATION=/srv/queen-califia/evidence/render-source-disposition/verification.json
RENDER_SOURCE_DISPOSITION_VERIFICATION_SHA256=<sha256>
RENDER_SOURCE_VERIFIED_ABSENT=NO
RENDER_SOURCE_CAPTURED=NO
RENDER_SOURCE_MIGRATION_VERIFIED=NO
RENDER_SOURCE_LEDGER_UPDATED=NO
RENDER_SOURCE_AUTHORIZATION_UPDATED=NO
```

## 4. Human review remains mandatory

A successful verifier result does **not** prove the contents of the provider evidence are truthful and does not change the deployment ledger. It proves only that a structurally complete, immutable-hashable dossier exists and preserves the required historical semantics.

Before any protected PR changes the historical-source status to `formally-dispositioned`, a human reviewer must inspect the retained provider evidence itself and confirm it supports the requested disposition.

That protected PR must preserve:

```text
verified_absent=false
captured=false
postgresql.production_migration_verified=false
```

unless separate, stronger evidence independently supports changing one of those facts.

## Recovery evidence takes precedence

If provider-backed recovery becomes available before formal disposition is approved, stop this procedure. Preserve the disposition dossier as historical process evidence, recover the source through a separate controlled path, and validate the recovered database before making any migration or absence claim.

## Non-authorization guarantee

The verifier never creates, edits, repairs, or removes:

```text
/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED
```

It never edits:

```text
config/sovereign-edge-deployment-state.json
```

and never automatically clears the production-readiness blocker.
