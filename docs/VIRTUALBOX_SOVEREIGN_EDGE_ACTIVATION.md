# Queen Califia Sovereign Edge — One-Command VirtualBox Activation

This optional control plane makes the Windows-hosted Sovereign Edge appliance behave like one system instead of a sequence of manual VM and Guest Control operations.

The ownership boundary is intentional:

```text
Windows qc.ps1
  -> starts/opens QueenCalifia-Sovereign-Edge in VirtualBox
  -> waits for Guest Additions
  -> sends a narrow host command through VirtualBox guest properties
Ubuntu systemd
  -> owns privileged QC startup inside the guest
  -> enforces the existing runtime authorization marker
  -> starts the private Docker Compose runtime
  -> publishes STARTING / READY / BLOCKED / FAILED back to the host
```

The normal activation path does **not** use `VBoxManage guestcontrol`, does not store a Linux password, and does not enable direct root Guest Control. VirtualBox guest properties are used only as a narrow command/status channel. The guest-side dispatcher runs as a root-owned systemd service and accepts only `ACTIVATE`, `STOP`, `RESTART`, and `STATUS` with a per-command UUID nonce.

This VirtualBox layer is optional. On a dedicated physical Ubuntu Sovereign Edge host, `VBoxControl` is absent and the installer leaves the VirtualBox command timer disabled while still installing the native QC boot service and watchdog.

## Safety boundary

One-command activation does **not** create or repair `/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED`. If that runtime authorization gate is closed, the VM may boot normally but QC reports `BLOCKED` and the application runtime remains fail-closed. Existing migration, backup/restore, production authorization, HA, and cutover evidence requirements remain unchanged.

## One-time guest installation

The production repository must be at the canonical guest path `/opt/queen-califia`.

From the Ubuntu VM console, after the repository contains these activation files:

```bash
cd /opt/queen-califia
sudo bash scripts/edge/install-systemd.sh
```

Expected terminal evidence on a VirtualBox guest:

```text
VIRTUALBOX_HOST_CONTROL=ENABLED
QC_EDGE_SYSTEMD_INSTALL=PASS
```

The installer:

- installs and enables `queen-califia-edge.service` for boot;
- installs and starts the fail-closed watchdog timer;
- enables the VirtualBox host-command timer only when `VBoxControl` exists;
- never creates the production authorization marker;
- publishes `ControlPlane=systemd-v1` through Guest Additions.

No direct root Guest Control login is required.

## Windows activation

From a Windows checkout containing `scripts\edge\windows`:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\edge\windows\qc.ps1 activate
```

Or double-click:

```text
scripts\edge\windows\QueenCalifia-Activate.cmd
```

Default VM name:

```text
QueenCalifia-Sovereign-Edge
```

When the VM is powered off or saved, the launcher opens it with the VirtualBox GUI, waits for Guest Additions, confirms `systemd-v1`, requests activation, and waits for the guest to publish `READY`.

Expected steady-state output:

```text
VM_START=PASS (gui)
GUEST_ADDITIONS=PASS (...)
CONTROL_PLANE=systemd-v1
COMMAND=ACTIVATE
QC_STATE=STARTING
QC_STATE=READY
QUEEN_CALIFIA=READY
```

If the production runtime is not yet authorized, the expected result is deliberately different:

```text
QC_STATE=BLOCKED
QC activation is fail-closed: runtime authorization gate is closed
```

That is a safety result, not a reason to enable direct root login.

## Lifecycle commands

```powershell
# Start/open the VM if necessary and bring QC to READY.
pwsh .\scripts\edge\windows\qc.ps1 activate

# Read VM and QC state without changing it.
pwsh .\scripts\edge\windows\qc.ps1 status

# Stop the QC runtime while leaving the VM running.
pwsh .\scripts\edge\windows\qc.ps1 stop

# Restart the QC runtime through systemd.
pwsh .\scripts\edge\windows\qc.ps1 restart
```

To use a different registered VM name:

```powershell
pwsh .\scripts\edge\windows\qc.ps1 activate -VmName 'My-QC-VM'
```

To start a powered-off VM with VirtualBox detachable/separate mode instead of the standard GUI:

```powershell
pwsh .\scripts\edge\windows\qc.ps1 activate -Frontend separate
```

## Linux service controls

Inside the VM, systemd owns runtime privilege:

```bash
sudo systemctl status queen-califia-edge.service
sudo systemctl restart queen-califia-edge.service
sudo journalctl -u queen-califia-edge.service -n 200 --no-pager
```

The host launcher does not need those root credentials. It communicates through the restricted command property, and the root-owned dispatcher performs only the predefined service actions.

## Recovery

If Windows reports `CONTROL_PLANE` missing, Guest Additions may be running while the one-time service installation has not been completed. Use the VM console and rerun:

```bash
cd /opt/queen-califia
sudo bash scripts/edge/install-systemd.sh
```

If QC reports `FAILED`, inspect:

```bash
sudo systemctl status queen-califia-edge.service --no-pager
sudo journalctl -u queen-califia-edge.service -n 200 --no-pager
```

If QC reports `BLOCKED`, resolve the underlying provisioning/evidence gate. Do not bypass it by enabling direct root Guest Control or weakening the authorization marker contract.
