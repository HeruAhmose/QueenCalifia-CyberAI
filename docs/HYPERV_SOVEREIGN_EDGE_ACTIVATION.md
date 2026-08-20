# Hyper-V Sovereign Edge activation

Hyper-V is the preferred Windows hypervisor for Queen Califia when Windows VBS / Hyper-V is already active. This path does not disable VBS, does not expose application ports on the Windows host, and does not weaken the existing production authorization marker.

## Security boundary

The Windows launcher owns VM power and sends only four runtime verbs: `ACTIVATE`, `STATUS`, `STOP`, and `RESTART`. The guest remains systemd-owned. A dedicated Ed25519 SSH key is enrolled once for `qcadmin` with OpenSSH `restrict` plus a forced command. That key cannot open a shell, allocate a PTY, forward ports, or select an arbitrary command. The forced command can invoke only four exact `sudo -n` entries in `/etc/sudoers.d/queen-califia-hyperv-control`.

The control path never creates, repairs, changes, or bypasses `/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED`. If that marker is absent or invalid, activation remains fail-closed and returns `QUEEN_CALIFIA=BLOCKED`.

## One-time guest installation

After the repository is at a commit containing Hyper-V support, install the systemd units once inside the guest:

```bash
cd /opt/queen-califia
sudo bash scripts/edge/install-systemd.sh
```

On Hyper-V this explicitly disables the VirtualBox two-second command timer, even if stale `VBoxControl` binaries happen to exist.

## One-time Windows key enrollment

From PowerShell 7 on the Windows Hyper-V host:

```powershell
pwsh -NoLogo -NoProfile -File scripts/edge/windows/Initialize-QueenCalifia-HyperV.ps1
```

The enrollment step creates `%USERPROFILE%\.ssh\queen-califia-hyperv-control` if needed, discovers the VM address, and asks for the existing guest password / sudo authentication only for this one-time installation. The private key remains on the Windows host and is never copied to the guest or repository.

The public key is transferred with `scp` as a randomized temporary public-key file under `/tmp`. The remote guest reads that file locally, removes it before invoking the root-owned installer, and passes the key to the installer entirely inside Linux. The public-key text is never interpolated into the Windows `ssh.exe` command line. A best-effort cleanup also removes the temporary file if enrollment fails before the remote command consumes it.

## Normal operation

After enrollment, normal Windows control is noninteractive:

```powershell
pwsh -NoLogo -NoProfile -File scripts/edge/windows/qc.ps1 activate
pwsh -NoLogo -NoProfile -File scripts/edge/windows/qc.ps1 status
pwsh -NoLogo -NoProfile -File scripts/edge/windows/qc.ps1 restart
pwsh -NoLogo -NoProfile -File scripts/edge/windows/qc.ps1 stop
```

`QueenCalifia-Activate.cmd` continues to call the same `qc.ps1 activate` entry point. With the Hyper-V VM present, `qc.ps1` auto-selects Hyper-V; otherwise it retains the existing VirtualBox path.

## Hyper-V VM expectations

- VM name defaults to `QueenCalifia-Sovereign-Edge-HyperV`.
- The launcher uses `Start-VM` for a powered-off guest.
- IP discovery first uses `Get-VMNetworkAdapter` IP data and falls back to the Windows neighbor table matched by the Hyper-V adapter MAC address when KVP does not report an address.
- SSH must be reachable only through the intended host/guest management boundary. Existing UFW restrictions should remain in force.
- Production runtime authorization remains a separate evidence-backed cutover step.

## VirtualBox compatibility

VirtualBox remains supported. Its guest-property dispatcher is enabled only when `systemd-detect-virt -v` reports `oracle` **and** `VBoxControl` exists. Binary presence by itself is no longer treated as proof that VirtualBox is the active hypervisor.
