# Queen Califia Hyper-V Final Physical-Host Evidence

The existing `QueenCalifia-Sovereign-Edge-HyperV` Ubuntu guest is already the validated Sovereign Edge production candidate. This procedure exists for the alternative final-production architecture in which that guest remains in Hyper-V and the **physical Windows computer hosting Hyper-V becomes the final production trust boundary**.

This path does **not** require rebuilding the Ubuntu guest.

## Trust boundary

The final architecture is:

```text
physical Windows host
  -> Hyper-V
    -> QueenCalifia-Sovereign-Edge-HyperV
      -> Ubuntu guest qc-edge-01
        -> private Docker topology
```

The Windows host must therefore provide the final-production evidence for:

- physical host identity;
- BitLocker protection of Windows and every local volume containing VM configuration, checkpoints, smart-paging state, or virtual disks;
- TPM readiness;
- Secure Boot;
- Windows virtualization-based security;
- LSA protection;
- Windows Firewall enabled on every profile with default inbound Block;
- absence of host listeners on ports 80, 443, 5432, and 6379;
- exact Hyper-V VM identity and Generation 2 configuration;
- VM Secure Boot;
- VM automatic restart/start behavior after physical-host recovery;
- clean protected-main repository state;
- the existing restricted guest-control boundary reporting the runtime authorization gate closed.

BIOS/UEFI restore-after-power-loss and physical UPS behavior remain manual evidence because Windows software cannot truthfully prove the physical event occurred.

## Canonical collector

From an elevated **PowerShell 7** window in the repository checkout:

```powershell
cd <QueenCalifia-CyberAI checkout>

$script = '.\scripts\edge\windows\Collect-QueenCalifia-FinalHostEvidence.ps1'

$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $script),
    [ref]$tokens,
    [ref]$errors
) | Out-Null

if ($errors.Count -gt 0) {
    $errors | Format-List Message,Extent
    throw 'HYPERV FINAL-HOST COLLECTOR PARSER FAILED — NOTHING EXECUTED.'
}

Write-Host 'HYPERV FINAL-HOST COLLECTOR PARSER PASSED' -ForegroundColor Green
& $script
```

The collector accepts no arbitrary VM name or evidence output path. Its fixed target is:

```text
QueenCalifia-Sovereign-Edge-HyperV
```

and evidence is written beneath:

```text
%ProgramData%\QueenCalifia\evidence\hyperv-final-host
```

## Automated evidence

A passing automated result requires all of the following:

1. the host does not exhibit a known nested-VM manufacturer/model signature;
2. Windows system storage and every local drive containing Hyper-V VM state are fully BitLocker encrypted;
3. BitLocker protection is On for each required volume;
4. TPM is present, ready, enabled, and activated;
5. physical-host Secure Boot is enabled;
6. VBS reports running;
7. LSA protection is enabled;
8. every Windows Firewall profile is enabled;
9. every firewall profile has default inbound Block;
10. host TCP ports 80, 443, 5432, and 6379 are not listening;
11. the exact expected Hyper-V VM exists as Generation 2;
12. the guest has Hyper-V Secure Boot enabled;
13. Hyper-V is configured to start/recover the VM after host boot rather than `AutomaticStartAction=Nothing`;
14. the repository checkout is clean and on `main`;
15. the existing restricted QC guest-control path confirms the VM is running and application authorization remains blocked.

The evidence deliberately hashes sensitive host/VM identifiers instead of exporting raw hardware serials or MAC addresses.

Expected output:

```text
HYPERV_FINAL_HOST_EVIDENCE=PASS
HYPERV_FINAL_HOST_EVIDENCE_PATH=C:\ProgramData\QueenCalifia\evidence\hyperv-final-host\hyperv-final-host-<UTC>.json
HYPERV_FINAL_HOST_EVIDENCE_SHA256=<sha256>
HYPERV_FINAL_HOST_VM_ID=<Hyper-V VM GUID>
HYPERV_FINAL_HOST_GIT_HEAD=<protected-main sha>
HYPERV_FINAL_HOST_MANUAL_CONTROLS=BIOS_AND_UPS_REQUIRED
HYPERV_FINAL_HOST_LEDGER_UPDATED=NO
HYPERV_FINAL_HOST_AUTHORIZATION_UPDATED=NO
```

A `BLOCKED` result is not a software failure by itself. Review the generated JSON and correct the real host condition before repeating evidence collection.

## Manual BIOS and UPS evidence

After the automated Windows-host evidence is review-ready, perform the same physical controls required by the final-host policy:

### BIOS/UEFI restore-after-power-loss

Establish and retain evidence that:

- the firmware restore-after-power-loss setting was directly observed;
- a controlled AC-loss test was actually performed on the **physical Windows host**;
- after utility power returned, the physical host automatically returned to the intended powered-on state;
- Hyper-V subsequently restored/started the Queen Califia VM according to the recorded Hyper-V automatic-start configuration.

### UPS

Establish and retain evidence that:

- a real UPS physically supplies the Windows host and relevant network equipment required for the intended failure mode;
- a controlled utility interruption was performed;
- host continuity or the approved graceful shutdown behavior was observed;
- the host and Queen Califia VM returned to normal operation after the test.

Do not treat a UPS product specification, USB enumeration, or vendor application screenshot by itself as proof of the physical interruption test.

## Guest evidence remains separate

The existing Ubuntu guest remains the runtime execution environment. Continue to use its established evidence paths for:

- final Valkey PKI validation;
- strengthened `verify-runtime.sh --preauth` proof;
- final Valkey authority evidence binding;
- encrypted host-state backup;
- independent off-host copy verification;
- Render historical-source recovery/disposition.

Windows-host evidence must not be used to infer guest runtime facts that were not tested inside the Ubuntu guest.

## Ledger semantics

A successful Windows-host collector result is **eligible for human review only**. It never edits:

```text
config/sovereign-edge-deployment-state.json
```

and never creates, edits, repairs, or removes the guest authorization marker:

```text
/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED
```

After reviewing the Windows-host evidence and separate physical BIOS/UPS evidence, a protected ledger PR may reconcile the final-production architecture from the current candidate-only host description to the evidenced physical-Windows-host + Hyper-V trust boundary.

Production authorization remains a later, separate decision after all authorization-stage evidence is complete.
