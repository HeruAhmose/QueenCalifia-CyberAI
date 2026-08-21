# Queen Califia Off-Host Encrypted Backup Evidence

Production authorization requires at least one verified encrypted host-state backup copy away from the Sovereign Edge host. This procedure creates that copy and evidence without changing the deployment ledger or authorization marker.

## Canonical paths

Source encrypted backups:

```text
/srv/queen-califia/backups
```

Required independent mount point:

```text
/mnt/qc-offhost-backup
```

Destination archive directory:

```text
/mnt/qc-offhost-backup/queen-califia/host-state
```

Local evidence directory:

```text
/srv/queen-califia/evidence
```

These paths are fixed by contract. The operator does not accept alternate command-line paths.

## 1. Prepare independent storage

Mount an independent filesystem at exactly:

```bash
sudo mkdir -p /mnt/qc-offhost-backup
# Mount the selected external/off-host filesystem here using the platform's approved procedure.
findmnt --target /mnt/qc-offhost-backup
```

The proof operator requires `/mnt/qc-offhost-backup` itself to be the mount target and requires its filesystem device ID to differ from `/srv/queen-califia/backups`.

A directory on the same root filesystem does **not** qualify.

## 2. Create or refresh the encrypted source backup

Use the existing guarded host-state backup operation:

```bash
cd /opt/queen-califia
sudo -E scripts/edge/backup-host-state.sh
```

That operation streams the host-state archive directly into `age` encryption. It does not create a plaintext tar archive.

## 3. Copy and verify off-host

With the runtime authorization gate still closed:

```bash
cd /opt/queen-califia
sudo bash scripts/edge/copy-offhost-backup.sh
```

The operator:

1. refuses to run if the production authorization marker exists;
2. requires the canonical off-host mount to be a dedicated mount point;
3. requires source and destination filesystem device IDs to differ;
4. selects only a canonical `edge-state-YYYYMMDDTHHMMSSZ.tar.age` source archive;
5. validates that archive against its existing SHA-256 manifest;
6. refuses to overwrite an existing off-host archive or manifest;
7. copies only the already-encrypted archive;
8. re-hashes the off-host copy and requires exact SHA-256 equality;
9. creates a secret-free evidence JSON locally;
10. copies that evidence record to the independent mount and verifies its hash too.

Expected successful output includes:

```text
OFFHOST_BACKUP_PROOF=PASS
OFFHOST_BACKUP_ARCHIVE_SHA256=<sha256>
OFFHOST_BACKUP_EVIDENCE=/srv/queen-califia/evidence/offhost-backup-<UTC>.json
OFFHOST_BACKUP_EVIDENCE_SHA256=<sha256>
OFFHOST_BACKUP_LEDGER_UPDATED=NO
OFFHOST_BACKUP_AUTHORIZATION_UPDATED=NO
```

## 4. Evidence review

A successful copy is **evidence for review**, not automatic authorization.

Before a protected ledger PR may set:

```text
backup.off_host_encrypted_copy_verified=true
```

review and retain:

- the local evidence JSON;
- the evidence JSON SHA-256;
- the encrypted archive SHA-256;
- the matching off-host encrypted archive;
- the off-host evidence copy;
- confirmation that the authorization marker was absent during the operation;
- the protected-main repository SHA used for the procedure.

If the external mount is later removed, the historical evidence remains valid for the copy that was proven at that time, but future backup freshness should be handled as a separate policy rather than rewriting the old evidence.

## Failure behavior

Any source manifest mismatch, same-filesystem destination, mount ambiguity, destination collision, copy hash mismatch, or evidence-copy hash mismatch aborts the procedure.

Do not change the deployment ledger to compensate for a failed proof. Correct the actual storage or backup problem and run a new proof.

## Non-authorization guarantee

This procedure never creates, modifies, repairs, or removes:

```text
/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED
```

It also never edits:

```text
config/sovereign-edge-deployment-state.json
```
