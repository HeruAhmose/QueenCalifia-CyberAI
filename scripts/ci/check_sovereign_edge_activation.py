#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ACTIVATE = ROOT / "scripts/edge/activate-runtime.sh"
STATE = ROOT / "scripts/edge/runtime-state.sh"
VBOX_STATE = ROOT / "scripts/edge/vbox-runtime-state.sh"
DISPATCH = ROOT / "scripts/edge/command-dispatch.sh"
INSTALL = ROOT / "scripts/edge/install-systemd.sh"
HYPERV_CONTROL = ROOT / "scripts/edge/hyperv-control.sh"
HYPERV_ROOT = ROOT / "scripts/edge/hyperv-control-root.sh"
HYPERV_INSTALL = ROOT / "scripts/edge/install-hyperv-control.sh"
WINDOWS = ROOT / "scripts/edge/windows/qc.ps1"
WINDOWS_INIT = ROOT / "scripts/edge/windows/Initialize-QueenCalifia-HyperV.ps1"
CMD = ROOT / "scripts/edge/windows/QueenCalifia-Activate.cmd"
RUNTIME_UNIT = ROOT / "deploy/edge/systemd/queen-califia-edge.service"
COMMAND_UNIT = ROOT / "deploy/edge/systemd/queen-califia-edge-command.service"
COMMAND_TIMER = ROOT / "deploy/edge/systemd/queen-califia-edge-command.timer"
VBOX_DOC = ROOT / "docs/VIRTUALBOX_SOVEREIGN_EDGE_ACTIVATION.md"
HYPERV_DOC = ROOT / "docs/HYPERV_SOVEREIGN_EDGE_ACTIVATION.md"

def text(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"missing activation artifact: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")

def require(body: str, *needles: str) -> None:
    missing = [needle for needle in needles if needle not in body]
    if missing:
        raise SystemExit(f"activation invariant missing: {missing}")

activate = text(ACTIVATE)
require(activate, "SOVEREIGN_EDGE_RUNTIME_AUTHORIZED", '== "AUTHORIZED"', "compose config", "refusing Sovereign Edge runtime with published host ports", "QUEEN_CALIFIA=READY", "signal_state BLOCKED")
if "guestcontrol" in activate.lower():
    raise SystemExit("guest runtime activation must not depend on VirtualBox Guest Control login")

state = text(STATE)
require(state, "systemd-detect-virt -v", '== "oracle"', "VBoxControl guestproperty set", "QC_EDGE_STATE=")
vbox_state = text(VBOX_STATE)
require(vbox_state, "runtime-state.sh")

dispatch = text(DISPATCH)
require(dispatch, '== "oracle"', "VBoxControl guestproperty enumerate --patterns", "ACTIVATE|STOP|RESTART|STATUS", "CommandAck")

install = text(INSTALL)
require(install, 'CANONICAL_ROOT="/opt/queen-califia"', "systemctl enable queen-califia-edge.service", "systemctl enable --now queen-califia-edge-watchdog.timer", '[[ "$virt" == "oracle" ]]', "systemctl disable --now queen-califia-edge-command.timer", '[[ "$virt" == "microsoft" ]]', "HYPERV_HOST_CONTROL=AVAILABLE_AFTER_KEY_ENROLLMENT")
if "if command -v VBoxControl" in install:
    raise SystemExit("VBox control must not be enabled from binary presence alone")

hyperv = text(HYPERV_CONTROL)
require(hyperv, "SSH_ORIGINAL_COMMAND", "ACTIVATE|STATUS|STOP|RESTART", "sudo -n", "hyperv-control-root.sh")
hyperv_root = text(HYPERV_ROOT)
require(hyperv_root, '== "microsoft"', "SOVEREIGN_EDGE_RUNTIME_AUTHORIZED", "QUEEN_CALIFIA=BLOCKED", "systemctl start", "systemctl restart")
if any(token in hyperv_root for token in ("touch $AUTH_MARKER", "echo AUTHORIZED", ">\"$AUTH_MARKER\"")):
    raise SystemExit("Hyper-V control must never create or modify the authorization marker")

hyperv_install = text(HYPERV_INSTALL)
require(hyperv_install, "ssh-ed25519", "restrict,command=", "/etc/sudoers.d/queen-califia-hyperv-control", "visudo -cf", "NOPASSWD:")

launcher = text(WINDOWS)
require(launcher, "#requires -Version 7.0", "ValidateSet('auto', 'hyperv', 'virtualbox')", "QueenCalifia-Sovereign-Edge-HyperV", "Get-VMNetworkAdapter", "Get-NetNeighbor", "Start-VM", "BatchMode=yes", "IdentitiesOnly=yes", "StrictHostKeyChecking=accept-new", "VBoxManage.exe", "TRANSRESET,RDONLYGUEST")
for forbidden in ("--passwordfile", "Read-Host", "SecureString"):
    if forbidden.lower() in launcher.lower():
        raise SystemExit(f"normal Windows launcher must remain noninteractive; found {forbidden}")

initializer = text(WINDOWS_INIT)
require(
    initializer,
    "scp.exe",
    "ssh-keygen.exe",
    "ed25519",
    "/tmp/queen-califia-hyperv-control-",
    "install-hyperv-control.sh",
    "rm -f",
    "HYPERV_CONTROL_ENROLLMENT=PASS",
)
if "$publicKey =" in initializer or "install-hyperv-control.sh '$publicKey'" in initializer:
    raise SystemExit("Hyper-V enrollment must never interpolate public-key text into the Windows OpenSSH command line")
if "Get-Content -LiteralPath \"$KeyPath.pub\" -Raw" in initializer:
    raise SystemExit("Hyper-V enrollment must stage the public-key file rather than reading key text for remote command interpolation")

cmd = text(CMD)
require(cmd, "pwsh.exe", "qc.ps1", "activate")

runtime_unit = text(RUNTIME_UNIT)
require(runtime_unit, "After=docker.service network-online.target", "ExecStart=/opt/queen-califia/scripts/edge/activate-runtime.sh start", "NoNewPrivileges=true", "ProtectSystem=strict", "WantedBy=multi-user.target")
if "vboxadd-service.service" in runtime_unit:
    raise SystemExit("runtime unit must not order after a VirtualBox-only service")
command_unit = text(COMMAND_UNIT)
require(command_unit, "ExecStart=/opt/queen-califia/scripts/edge/command-dispatch.sh", "NoNewPrivileges=true", "ProtectSystem=strict")
if "vboxadd-service.service" in command_unit:
    raise SystemExit("generic command unit must not order after a VirtualBox-only service")
command_timer = text(COMMAND_TIMER)
require(command_timer, "OnBootSec=5s", "OnUnitActiveSec=2s", "Unit=queen-califia-edge-command.service")
require(text(VBOX_DOC).lower(), "one-time guest installation", "runtime authorization gate")
require(text(HYPERV_DOC).lower(), "one-time guest installation", "forced command", "production authorization", "virtualbox compatibility", "temporary public-key file")

print("Sovereign Edge activation guard verified: Hyper-V and VirtualBox are explicit, enrollment stages public-key files safely, host control is credentialless after enrollment, and production authorization remains fail-closed")
