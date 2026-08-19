#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

ACTIVATE = ROOT / "scripts/edge/activate-runtime.sh"
STATE = ROOT / "scripts/edge/vbox-runtime-state.sh"
DISPATCH = ROOT / "scripts/edge/command-dispatch.sh"
INSTALL = ROOT / "scripts/edge/install-systemd.sh"
WINDOWS = ROOT / "scripts/edge/windows/qc.ps1"
CMD = ROOT / "scripts/edge/windows/QueenCalifia-Activate.cmd"
RUNTIME_UNIT = ROOT / "deploy/edge/systemd/queen-califia-edge.service"
COMMAND_UNIT = ROOT / "deploy/edge/systemd/queen-califia-edge-command.service"
COMMAND_TIMER = ROOT / "deploy/edge/systemd/queen-califia-edge-command.timer"
DOC = ROOT / "docs/VIRTUALBOX_SOVEREIGN_EDGE_ACTIVATION.md"


def text(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"missing one-command activation artifact: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def require(body: str, *needles: str) -> None:
    missing = [needle for needle in needles if needle not in body]
    if missing:
        raise SystemExit(f"activation invariant missing: {missing}")


activate = text(ACTIVATE)
require(
    activate,
    "SOVEREIGN_EDGE_RUNTIME_AUTHORIZED",
    '== "AUTHORIZED"',
    "compose config",
    "refusing Sovereign Edge runtime with published host ports",
    "docker compose --env-file",
    "queen-califia-api",
    "queen-califia-cloudflared",
    "QUEEN_CALIFIA=READY",
    "signal_state BLOCKED",
    "signal_state FAILED",
)
if "guestcontrol" in activate.lower():
    raise SystemExit("guest runtime activation must not depend on VirtualBox Guest Control login")

state = text(STATE)
require(
    state,
    "VBoxControl guestproperty set",
    "/QueenCalifia/SovereignEdge",
    "ControlPlane",
    "systemd-v1",
    "BootId",
    "GitHead",
)

dispatch = text(DISPATCH)
require(
    dispatch,
    "VBoxControl guestproperty enumerate --patterns",
    "ACTIVATE|STOP|RESTART|STATUS",
    "systemctl start",
    "systemctl stop",
    "systemctl restart",
    "CommandAck",
)

install = text(INSTALL)
require(
    install,
    'CANONICAL_ROOT="/opt/queen-califia"',
    "systemctl enable queen-califia-edge.service",
    "systemctl enable --now queen-califia-edge-watchdog.timer",
    "if command -v VBoxControl",
    "systemctl enable --now queen-califia-edge-command.timer",
    "VIRTUALBOX_HOST_CONTROL=NOT_APPLICABLE",
)

launcher = text(WINDOWS)
require(
    launcher,
    "#requires -Version 7.0",
    "QueenCalifia-Sovereign-Edge",
    "startvm",
    "--type=$Frontend",
    "/VirtualBox/GuestAdd/Version",
    "systemd-v1",
    "TRANSRESET,RDONLYGUEST",
    "ACTIVATE",
    "STOP",
    "RESTART",
    "QUEEN_CALIFIA=READY",
)
for forbidden in (
    "guestcontrol",
    "--username",
    "--passwordfile",
    "Read-Host",
    "SecureString",
):
    if forbidden.lower() in launcher.lower():
        raise SystemExit(f"Windows launcher must remain credentialless; found forbidden token: {forbidden}")

cmd = text(CMD)
require(cmd, "pwsh.exe", "qc.ps1", "activate")

runtime_unit = text(RUNTIME_UNIT)
require(
    runtime_unit,
    "After=docker.service network-online.target",
    "ExecStart=/opt/queen-califia/scripts/edge/activate-runtime.sh start",
    "ExecStop=/opt/queen-califia/scripts/edge/activate-runtime.sh stop",
    "RemainAfterExit=yes",
    "NoNewPrivileges=true",
    "ProtectSystem=strict",
    "DOCKER_CONFIG=/run/queen-califia-edge-docker",
    "RuntimeDirectory=queen-califia-edge-docker",
    "ReadWritePaths=/srv/queen-califia /run/docker.sock /run/queen-califia-edge-docker",
    "WantedBy=multi-user.target",
)

command_unit = text(COMMAND_UNIT)
require(
    command_unit,
    "ExecStart=/opt/queen-califia/scripts/edge/command-dispatch.sh",
    "RuntimeDirectory=queen-califia-edge",
    "NoNewPrivileges=true",
    "ProtectSystem=strict",
)

command_timer = text(COMMAND_TIMER)
require(command_timer, "OnBootSec=5s", "OnUnitActiveSec=2s", "Unit=queen-califia-edge-command.service")

doc = text(DOC)
require(
    doc.lower(),
    "one-time guest installation",
    "queencalifia-activate.cmd",
    "runtime authorization gate",
    "does not enable direct root guest control",
)

print("Sovereign Edge activation guard verified: VM boot is host-owned, QC boot is systemd-owned, host control is credentialless, and the production authorization gate remains fail-closed")
