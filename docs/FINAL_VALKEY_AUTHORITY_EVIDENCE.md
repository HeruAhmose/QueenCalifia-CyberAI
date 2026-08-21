# Queen Califia Final Valkey Authority Evidence

`queue.pki_generated` and `queue.authority_verified` are separate production-authorization facts.

- Offline PKI verification proves the selected final host has a valid certificate authority and the expected server/client identities.
- Live authority verification proves that the same final host is actually running Valkey with those identities, requires client certificates, refuses plaintext, and keeps the application runtime closed while the production authorization marker is absent.

Neither proof edits the deployment ledger or opens production authorization.

## Required order

Run these steps only on the selected dedicated bare-metal final production host.

### 1. Collect final-host machine evidence

```bash
cd /opt/queen-califia
sudo python3 scripts/edge/collect-final-host-evidence.py
```

A machine result must be review-ready and must identify the protected Git commit used for the final host.

BIOS restore-after-power-loss and UPS controls remain separate manual evidence and are not satisfied by this procedure.

### 2. Generate and verify final-host Valkey PKI

If the final host does not yet have its canonical PKI:

```bash
cd /opt/queen-califia
sudo bash scripts/edge/generate-valkey-mtls.sh
```

Then verify it:

```bash
sudo python3 scripts/edge/verify-final-valkey-pki.py
```

A passing offline result is eligible for later human review of:

```text
queue.pki_generated=true
```

It is not live authority evidence.

### 3. Run the live preauthorization proof

With the production authorization marker still absent:

```bash
cd /opt/queen-califia
sudo -E scripts/edge/verify-runtime.sh --preauth
```

The preauthorization proof is deliberately stricter than an ordinary TLS health check.

It requires:

- `/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED` to be absent before, during, and immediately before evidence write;
- no host-published container ports;
- Valkey to become healthy on its private Docker queue network;
- the health client certificate to authenticate successfully;
- the API client certificate to authenticate successfully;
- the worker client certificate to authenticate successfully;
- TLS with the CA but **without any client certificate** to fail;
- plaintext Valkey access to fail;
- API, worker, frontend, Caddy, and cloudflared containers to remain stopped in preauthorization mode.

The generated runtime evidence uses schema:

```text
queen-califia-sovereign-edge-runtime-evidence-v2
```

and records:

- a host-identity fingerprint derived by the same method as the final-host collector;
- current boot ID;
- protected repository Git head and clean-state result;
- rendered Compose SHA-256;
- SHA-256 fingerprints of the CA, server, health, API, and worker certificates;
- explicit mTLS/plaintext/no-client-certificate/no-host-port/application-runtime-absent claims.

No private-key bytes or private-key hashes are written to the evidence record.

### 4. Bind the evidence chain

After the preceding three records exist on the same final host:

```bash
cd /opt/queen-califia
sudo python3 scripts/edge/bind-final-valkey-authority-evidence.py
```

The binder selects the newest canonical final-host, final-Valkey-PKI, and runtime evidence records and requires all of the following:

1. final-host evidence is machine-review-ready and bare-metal;
2. authorization marker was absent in host and runtime evidence and is still absent when binding;
3. final-host and live-runtime host identity fingerprints are identical;
4. final-host and live-runtime Git heads are identical;
5. offline-PKI and live-runtime certificate fingerprint maps are identical for exactly `ca`, `server`, `health`, `api`, and `worker`;
6. runtime evidence is `--preauth`, not authorized-runtime evidence;
7. repository was clean during the live proof;
8. health/API/worker mTLS identities all worked;
9. no-client-certificate TLS was rejected;
10. plaintext Valkey was rejected;
11. no host ports were published;
12. no application-runtime container was running.

A successful result emits a new immutable evidence record:

```text
/srv/queen-califia/evidence/final-valkey-authority-<UTC>.json
```

It also embeds the SHA-256 of each source evidence file so the review record is cryptographically tied to the exact host, PKI, and runtime records reviewed.

Expected output:

```text
FINAL_VALKEY_AUTHORITY_EVIDENCE=PASS
FINAL_VALKEY_AUTHORITY_VERIFIED=ELIGIBLE_FOR_HUMAN_REVIEW
FINAL_VALKEY_AUTHORITY_EVIDENCE_PATH=/srv/queen-califia/evidence/final-valkey-authority-<UTC>.json
FINAL_VALKEY_AUTHORITY_EVIDENCE_SHA256=<sha256>
FINAL_VALKEY_AUTHORITY_LEDGER_UPDATED=NO
FINAL_VALKEY_AUTHORIZATION_UPDATED=NO
```

## What a passing binder result means

A passing result supports **human review** of the factual claim that the selected final host's Valkey authority passed the required live preauthorization mTLS proof using the exact PKI previously reviewed on that same host/repository state.

It does **not** update:

```text
queue.authority_verified
production_authorized
runtime.runtime_authorized
```

and it does not create the runtime authorization marker.

A separate protected ledger PR is still required after the evidence has been reviewed. That PR should reference the bound evidence filename and SHA-256 and should change only facts directly supported by the reviewed evidence.

## Failure handling

If binding fails because the host fingerprint, Git head, or certificate fingerprints differ, do not edit evidence files to make them agree. Determine which host, checkout, or PKI changed and repeat the appropriate evidence collection on the intended final host.

If the runtime proof detects an application container already running or the authorization marker already exists, stop. Preauthorization authority evidence must be captured while application production remains closed.

If TLS succeeds without a client certificate or plaintext access succeeds, treat that as a Valkey security defect. Do not promote either queue ledger flag until the actual configuration is corrected and new evidence is collected.

## Non-authorization guarantee

The live verifier and binder never create, edit, repair, or remove:

```text
/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED
```

The binder never edits:

```text
config/sovereign-edge-deployment-state.json
```

Production remains fail-closed until every authorization-stage blocker is separately evidenced, reviewed, and promoted through protected repository control.
