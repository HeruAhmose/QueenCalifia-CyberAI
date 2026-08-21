# Queen Califia Final Production-Host Evidence

This procedure applies only to the **selected final production host**. It does not promote the current Hyper-V guest into final-production status and does not authorize Queen Califia.

The authoritative deployment ledger remains:

```text
config/sovereign-edge-deployment-state.json
```

The runtime authorization marker remains:

```text
/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED
```

The evidence collector never creates, edits, repairs, or removes either authority.

## Machine-observable controls

Run on the selected dedicated Ubuntu production host only:

```bash
cd /opt/queen-califia
sudo python3 scripts/edge/collect-final-host-evidence.py
```

The collector records a secret-free JSON evidence file under:

```text
/srv/queen-califia/evidence/final-host-<UTC>.json
```

It evaluates only machine-observable controls:

- the authorization marker is still absent;
- `systemd-detect-virt` reports bare metal (`none`);
- a stable host-identity fingerprint can be generated without storing raw DMI identifiers;
- the root storage chain contains a dm-crypt/LUKS layer;
- no configured swap device is detected outside an encrypted block chain;
- UFW is active with default-deny incoming policy;
- host TCP listeners do not expose 80, 443, 5432, or 6379;
- the canonical repository checkout is clean and has a valid commit SHA.

A passing machine result is **evidence ready for review**, not ledger authorization.

## Controls that remain manual

The collector deliberately leaves the following false:

- BIOS/UEFI restore-after-power-loss verification;
- UPS verification.

These require physical/vendor evidence. They must never be inferred from a VM reboot, Linux boot, ACPI text, or the presence of UPS-related software.

### BIOS/UEFI power-loss evidence

Record, outside Git if it contains sensitive host details:

- final host make/model;
- firmware/UEFI version;
- configured restore-after-power-loss setting;
- controlled AC-loss test procedure;
- observed power-restoration behavior;
- timestamp and operator identity.

Do not set `host.bios_restore_after_power_loss_verified=true` until the physical behavior has actually been demonstrated on the selected host.

### UPS evidence

Record:

- UPS make/model;
- host-to-UPS connection method;
- monitored power state;
- low-battery/shutdown policy;
- controlled utility-power interruption result;
- graceful shutdown or runtime-continuity result;
- timestamp and operator identity.

Do not set `host.ups_verified=true` from product specifications alone.

## Review requirements before ledger promotion

Before a protected PR may change any final-host ledger field from `false` to `true`, retain:

1. the collector JSON;
2. SHA-256 of that JSON;
3. matching protected-main repository SHA;
4. manual BIOS/UEFI evidence where applicable;
5. manual UPS evidence where applicable;
6. confirmation that the authorization marker remained absent during collection.

The evidence PR should update only claims that the evidence actually supports. It must not combine evidence capture with runtime authorization.

## Hyper-V candidate boundary

Running the collector inside `QueenCalifia-Sovereign-Edge-HyperV` should produce:

```text
FINAL_HOST_MACHINE_EVIDENCE=BLOCKED
```

because the collector requires bare-metal detection. This is intentional. Existing Hyper-V evidence remains valid production-candidate evidence, but it is not physical-host evidence.

## Failure handling

If any machine-observable control fails:

- preserve the JSON evidence;
- do not edit the ledger to make the result pass;
- do not create the authorization marker;
- correct the actual host control first;
- collect a new timestamped evidence file.

Evidence files are never overwritten by the collector.
