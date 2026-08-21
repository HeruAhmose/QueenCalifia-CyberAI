# Queen Califia Final-Host Valkey PKI Evidence

The Sovereign Edge authorization gate distinguishes two queue claims:

1. `queue.pki_generated` — final-host PKI material exists and its offline cryptographic/permission contract is valid.
2. `queue.authority_verified` — the final-host Valkey authority has also passed a live preauthorization mTLS proof.

These are not interchangeable. Offline PKI verification must never be treated as live authority verification.

## Canonical paths

Final-host PKI:

```text
/srv/queen-califia/pki/valkey
```

Generated review evidence:

```text
/srv/queen-califia/evidence/final-valkey-pki-<UTC>.json
```

The verifier accepts no alternate path arguments.

## 1. Generate PKI on the selected final host

Only on the selected dedicated bare-metal production host, with the production authorization marker still closed:

```bash
cd /opt/queen-califia
sudo bash scripts/edge/generate-valkey-mtls.sh
```

The generator is intentionally non-overwriting. Do not copy the Hyper-V candidate's private PKI into the final-host evidence boundary merely to satisfy the gate.

## 2. Verify offline PKI material

Run:

```bash
cd /opt/queen-califia
sudo python3 scripts/edge/verify-final-valkey-pki.py
```

The verifier requires:

- `systemd-detect-virt` to report bare metal (`none`);
- the production authorization marker to remain absent;
- fixed CA, server, health, API, and worker certificate/key files;
- no symlink substitution for those files;
- `ca.key` mode `0400` and root ownership;
- runtime private-key mode `0440` and UID/GID `10001:10001`;
- certificate/private-key public-key equality for server/health/API/worker;
- CA verification of every issued certificate;
- at least 30 days of remaining validity for issued certificates;
- distinct SHA-256 certificate fingerprints;
- server EKU `TLS Web Server Authentication`;
- server SANs `DNS:valkey` and `IP Address:127.0.0.1`;
- client EKU `TLS Web Client Authentication`;
- exact health/API/worker DNS identities;
- `CA:FALSE` on leaf certificates and `CA:TRUE` on the CA.

Private-key bytes and private-key hashes are not written to the evidence JSON. Certificate fingerprints are safe public identity material.

Expected successful output:

```text
FINAL_VALKEY_PKI_MATERIAL=PASS
FINAL_VALKEY_PKI_GENERATED=ELIGIBLE_FOR_HUMAN_REVIEW
FINAL_VALKEY_AUTHORITY_VERIFIED=NO
FINAL_VALKEY_PKI_EVIDENCE=/srv/queen-califia/evidence/final-valkey-pki-<UTC>.json
FINAL_VALKEY_PKI_EVIDENCE_SHA256=<sha256>
FINAL_VALKEY_LEDGER_UPDATED=NO
FINAL_VALKEY_AUTHORIZATION_UPDATED=NO
```

## 3. What offline evidence may support

After human review of a passing final-host PKI evidence file, a separate protected ledger PR may consider:

```text
queue.pki_generated=true
```

That PR must cite/record the evidence path and SHA-256 through an appropriate evidence schema before changing the claim.

The offline verifier explicitly emits:

```text
live_valkey_authority_verified=false
eligible_for_authority_verified_review=false
```

so it cannot support `queue.authority_verified=true` by itself.

## 4. Live authority proof remains separate

After final-host PKI is generated and reviewed, repeat the existing **preauthorization** runtime proof on that same selected final host while the authorization marker remains closed:

```bash
cd /opt/queen-califia
sudo -E scripts/edge/verify-runtime.sh --preauth
```

The live proof must demonstrate at minimum:

- Valkey TLS/mTLS success using the final-host authority;
- plaintext Valkey refusal;
- zero host-published application ports;
- no authorized application-runtime probing.

Only final-host evidence tying the reviewed PKI identities to that live preauthorization proof can support a later protected review of:

```text
queue.authority_verified=true
```

The current Hyper-V candidate's earlier TLS proof remains valid candidate evidence but does not prove final-host queue authority.

## Failure behavior

If any chain, key match, SAN, EKU, permission, ownership, expiry, bare-metal, or authorization-boundary check fails:

- preserve existing evidence and PKI material;
- do not rewrite files to make the verifier pass without understanding the defect;
- do not promote either queue ledger flag;
- correct or deliberately rotate the PKI through the approved procedure;
- generate new timestamped evidence.

## Non-authorization guarantee

The verifier never creates, edits, repairs, or removes:

```text
/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED
```

It never edits:

```text
config/sovereign-edge-deployment-state.json
```

and a passing offline result does not authorize Queen Califia.
