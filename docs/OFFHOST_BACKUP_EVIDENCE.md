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

## 1. Prepare genuinely independent storage

Mount the selected off-host filesystem at exactly:

```bash
sudo mkdir -p /mnt/qc-offhost-backup
# Mount the selected external disk or approved network filesystem here.
findmnt --target /mnt/qc-offhost-backup
```

A successful proof requires one of two independence modes:

1. **distinct physical disk** — the off-host mount is backed by a block device whose top-level physical disk differs from the physical disk backing `/srv/queen-califia/backups`; or
2. **network filesystem** — the mount uses an explicitly supported remote filesystem (`nfs`, `nfs4`, `cifs`, `smb3`, or `fuse.sshfs`).

The operator also requires `/mnt/qc-offhost-backup` itself to be the dedicated mount target and requires its filesystem device ID to differ from the source backup filesystem.

The following do **not** qualify:

- another directory on the Sovereign Edge root filesystem;
- a second partition or logical volume on the same physical disk;
- `/dev/loop*` storage;
- `tmpfs`, RAM-backed, overlay, or other unrecognized pseudo-filesystems.

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
2. requires the canonical off-host path to be a dedicated mount point;
3. rejects same-filesystem storage;
4. proves either a different top-level physical disk or a supported network filesystem;
5. rejects loop-device and pseudo-filesystem shortcuts;
6. selects only a canonical `edge-state-YYYYMMDDTHHMMSSZ.tar.age` source archive;
7. validates that archive against its existing SHA-256 manifest;
8. refuses to overwrite an existing off-host archive or manifest;
9. copies only the already-encrypted archive;
10. re-hashes the off-host copy and requires exact SHA-256 equality;
11. creates a secret-free evidence JSON locally, including the independence mode;
12. copies that evidence record to the independent storage and verifies its hash too.

Expected successful output includes:

```text
OFFHOST_BACKUP_PROOF=PASS
OFFHOST_BACKUP_INDEPENDENCE=distinct-physical-disk
OFFHOST_BACKUP_ARCHIVE_SHA256=<sha256>
OFFHOST_BACKUP_EVIDENCE=/srv/queen-califia/evidence/offhost-backup-<UTC>.json
OFFHOST_BACKUP_EVIDENCE_SHA256=<sha256>
OFFHOST_BACKUP_LEDGER_UPDATED=NO
OFFHOST_BACKUP_AUTHORIZATION_UPDATED=NO
```

For an approved network mount, `OFFHOST_BACKUP_INDEPENDENCE=network-filesystem`.

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
- the recorded independence mode and hashed mount/device identity evidence;
- confirmation that the authorization marker was absent during the operation;
- the protected-main repository SHA used for the procedure.

If the external mount is later removed, the historical evidence remains valid for the copy that was proven at that time, but future backup freshness should be handled as a separate policy rather than rewriting the old evidence.

## Failure behavior

Any source manifest mismatch, same-filesystem or same-physical-disk destination, unapproved mount type, mount ambiguity, destination collision, copy hash mismatch, or evidence-copy hash mismatch aborts the procedure.

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
