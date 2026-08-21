# Queen Califia Final-Host BIOS and UPS Evidence

Two production-authorization facts cannot be proven reliably by Linux software alone:

- `host.bios_restore_after_power_loss_verified`
- `host.ups_verified`

The final-host collector deliberately leaves these controls manual. This procedure creates a hashable, host-bound dossier **after real physical testing** and validates that the dossier is structurally complete. It does not make software the witness of the physical event.

## Evidence boundary

Canonical dossier root:

```text
/srv/queen-califia/evidence/final-host-manual-controls
```

Required request:

```text
/srv/queen-califia/evidence/final-host-manual-controls/request.json
```

BIOS evidence files:

```text
/srv/queen-califia/evidence/final-host-manual-controls/bios-evidence/
```

UPS evidence files:

```text
/srv/queen-califia/evidence/final-host-manual-controls/ups-evidence/
```

Generated verification:

```text
/srv/queen-califia/evidence/final-host-manual-controls/verification.json
```

The verifier accepts no alternate path arguments.

## 1. Collect final-host machine evidence first

On the selected dedicated bare-metal final host, while production authorization remains closed:

```bash
cd /opt/queen-califia
sudo python3 scripts/edge/collect-final-host-evidence.py
```

Use the resulting `identity.fingerprint_sha256` in the manual-controls request. This prevents BIOS/UPS evidence from a different machine from being attached to the final-host review.

## 2. Perform the BIOS/UEFI power-loss test

The physical test should establish all of these facts on the selected final host:

1. the firmware restore-after-power-loss setting was directly observed;
2. a controlled AC-loss event was actually performed;
3. after power was restored, the machine automatically returned to the intended powered-on state.

Retain at least one non-empty evidence file under `bios-evidence/`. Appropriate evidence may include photographs, exported firmware configuration, operator notes, or a controlled test record. Do not place passwords, recovery keys, private keys, API tokens, or other secrets in the dossier.

## 3. Perform the UPS test

The physical UPS test should establish:

1. a real UPS is physically present and supplies the selected final host;
2. a controlled utility-power interruption was actually performed;
3. the host either maintained appropriate runtime continuity or followed the approved graceful-shutdown behavior;
4. normal operation was observed after the test/recovery condition.

Retain at least one non-empty evidence file under `ups-evidence/`.

A UPS product specification, software package, USB device enumeration, or vendor marketing page by itself is not sufficient evidence of the physical integration and test.

## 4. Create `request.json`

Use this schema, replacing timestamps, host fingerprint, and evidence references with the real values from the test:

```json
{
  "schema": "queen-califia-final-host-manual-controls-request-v1",
  "host_identity_fingerprint_sha256": "<64 lowercase hex characters>",
  "bios_restore_after_power_loss": {
    "firmware_setting_observed": true,
    "controlled_ac_loss_test_performed": true,
    "automatic_power_restore_observed": true,
    "observed_at_utc": "YYYY-MM-DDTHH:MM:SSZ",
    "evidence_reference": "concise operator reference"
  },
  "ups": {
    "physical_ups_present": true,
    "controlled_utility_interruption_test_performed": true,
    "host_power_continuity_or_graceful_shutdown_observed": true,
    "post_test_normal_operation_observed": true,
    "observed_at_utc": "YYYY-MM-DDTHH:MM:SSZ",
    "evidence_reference": "concise operator reference"
  },
  "operator_attestation": "I attest that the BIOS restore-after-power-loss and UPS results in this request describe physical tests performed on the selected final production host, and that this verifier only prepares those assertions for human review."
}
```

Do not set a test assertion to `true` until the corresponding physical action and observation actually occurred.

## 5. Verify the dossier

Run:

```bash
cd /opt/queen-califia
sudo python3 scripts/edge/verify-final-host-manual-controls.py
```

The verifier requires:

- production authorization marker still absent;
- latest final-host evidence to be bare-metal and machine-review-ready;
- request host fingerprint to match that final-host record;
- every required BIOS and UPS physical-test assertion to be `true`;
- exact operator attestation preserving the human-review boundary;
- at least one non-empty regular BIOS evidence file;
- at least one non-empty regular UPS evidence file;
- no symlink substitution in the evidence trees;
- no overwrite of an existing verification.

It hashes the final-host evidence, request, and each retained physical-test evidence file.

Expected output includes:

```text
FINAL_HOST_MANUAL_CONTROLS=ELIGIBLE_FOR_HUMAN_REVIEW
FINAL_HOST_BIOS_RESTORE_AFTER_POWER_LOSS=ELIGIBLE_FOR_HUMAN_REVIEW
FINAL_HOST_UPS=ELIGIBLE_FOR_HUMAN_REVIEW
FINAL_HOST_MANUAL_CONTROLS_VERIFICATION=/srv/queen-califia/evidence/final-host-manual-controls/verification.json
FINAL_HOST_MANUAL_CONTROLS_VERIFICATION_SHA256=<sha256>
FINAL_HOST_PHYSICAL_TRUTH_AUTOMATICALLY_VERIFIED=NO
FINAL_HOST_MANUAL_CONTROLS_LEDGER_UPDATED=NO
FINAL_HOST_MANUAL_CONTROLS_AUTHORIZATION_UPDATED=NO
```

## 6. Human review remains mandatory

The verification record explicitly contains:

```text
physical_truth_automatically_verified=false
human_review_required=true
automatic_ledger_promotion=false
```

A human reviewer must inspect the retained BIOS and UPS evidence and determine whether the physical tests support the requested claims.

Only after that review may a separate protected ledger PR consider changing:

```text
host.bios_restore_after_power_loss_verified=true
host.ups_verified=true
```

That PR should identify the verification SHA-256 and retain the evidence packet outside Git if the physical evidence contains machine-specific or sensitive material.

## Failure behavior

Do not edit the request merely to satisfy validation if a physical test was not performed or did not succeed. Correct the firmware, electrical, or UPS integration issue first and repeat the physical test.

If the host fingerprint differs from the latest final-host evidence, stop and determine whether the test was performed on the wrong machine or the selected final host changed.

## Non-authorization guarantee

The verifier never creates, edits, repairs, or removes:

```text
/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED
```

and it never edits:

```text
config/sovereign-edge-deployment-state.json
```

A structurally valid manual-control dossier is evidence for human review only. Production remains fail-closed.
