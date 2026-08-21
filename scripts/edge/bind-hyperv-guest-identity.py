#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_ROOT = Path('/srv/queen-califia/evidence')
AUTH_MARKER = Path('/srv/queen-califia/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED')
REPO_ROOT = Path('/opt/queen-califia')
HEX40 = re.compile(r'^[0-9a-f]{40}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
MAC_RE = re.compile(r'^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$')


def fail(message: str) -> None:
    raise SystemExit(f'HYPERV_GUEST_IDENTITY_ERROR={message}')


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_windows_text(value: str) -> str:
    digest = hashlib.sha256()
    digest.update(value.encode('utf-8'))
    digest.update(b'\0')
    return digest.hexdigest()


def run(*args: str, cwd: Path | None = None) -> str:
    proc = subprocess.run(args, cwd=str(cwd) if cwd else None, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        fail(proc.stderr.strip() or proc.stdout.strip() or f'command failed: {args[0]}')
    return proc.stdout.strip()


def newest_pki() -> Path:
    matches = sorted(EVIDENCE_ROOT.glob('hyperv-final-valkey-pki-*.json'), key=lambda p: p.stat().st_mtime_ns, reverse=True)
    if not matches:
        fail('no Hyper-V Valkey PKI evidence found')
    path = matches[0]
    if path.is_symlink() or not path.is_file():
        fail('PKI source evidence must be a canonical regular file')
    return path


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f'invalid JSON source evidence: {exc}')
    raise AssertionError


def guest_fingerprint() -> str:
    values = [socket.gethostname()]
    for path in (Path('/etc/machine-id'), Path('/sys/class/dmi/id/product_uuid'), Path('/sys/class/dmi/id/board_serial')):
        try:
            value = path.read_text(encoding='utf-8', errors='replace').strip()
        except (FileNotFoundError, PermissionError, OSError):
            value = ''
        if value:
            values.append(value)
    digest = hashlib.sha256()
    for value in values:
        digest.update(value.encode('utf-8', errors='replace'))
        digest.update(b'\0')
    return digest.hexdigest()


def dmi_uuid() -> str:
    try:
        value = Path('/sys/class/dmi/id/product_uuid').read_text(encoding='utf-8', errors='replace').strip().lower()
    except (FileNotFoundError, PermissionError, OSError):
        value = ''
    if not UUID_RE.fullmatch(value):
        fail('guest DMI product_uuid is missing or invalid')
    return value


def network_identities() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for iface in sorted(Path('/sys/class/net').iterdir()):
        if iface.name == 'lo':
            continue
        try:
            mac = (iface / 'address').read_text(encoding='utf-8').strip().lower()
            operstate = (iface / 'operstate').read_text(encoding='utf-8').strip().lower()
        except OSError:
            continue
        if not MAC_RE.fullmatch(mac):
            continue
        normalized = mac.replace(':', '').upper()
        result.append({
            'interface': iface.name,
            'operstate': operstate,
            'mac_address_sha256': sha256_windows_text(normalized),
            'raw_mac_included': False,
        })
    active = [item for item in result if item['operstate'] == 'up']
    if not active:
        fail('no active non-loopback guest NIC identity found')
    return result


def main() -> int:
    if os.geteuid() != 0:
        fail('run as root so DMI guest identity is evaluated consistently')
    if AUTH_MARKER.exists():
        fail('authorization marker exists; preauthorization guest identity binding refused')
    virt = run('systemd-detect-virt', '-v').lower()
    if virt != 'microsoft':
        fail(f'expected Microsoft Hyper-V virtualization, detected {virt or "unknown"}')
    if not (REPO_ROOT / '.git').is_dir():
        fail('canonical repository checkout is missing')

    head = run('git', 'rev-parse', 'HEAD', cwd=REPO_ROOT)
    if not HEX40.fullmatch(head):
        fail('invalid repository head')
    if run('git', 'status', '--porcelain', cwd=REPO_ROOT):
        fail('canonical repository checkout must be clean')

    pki_path = newest_pki()
    pki = load_json(pki_path)
    if pki.get('schema') != 'queen-califia-hyperv-final-valkey-pki-evidence-v1':
        fail('unsupported PKI source evidence schema')
    if pki.get('pki_material_verified') is not True or pki.get('repository_clean') is not True:
        fail('PKI source evidence is not review-ready')
    if str(pki.get('git_head') or '') != head:
        fail('PKI source Git head differs from current protected checkout')

    fingerprint = guest_fingerprint()
    if not HEX64.fullmatch(fingerprint) or str(pki.get('guest_host_identity_fingerprint_sha256') or '') != fingerprint:
        fail('PKI source guest fingerprint differs from current guest')
    uuid = dmi_uuid()
    if str(pki.get('hyperv_guest_vm_id_raw') or '').lower() != uuid:
        fail('PKI source DMI UUID differs from current guest')

    record = {
        'schema': 'queen-califia-hyperv-guest-identity-binding-evidence-v1',
        'bound_at_utc': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'virtualization': 'microsoft',
        'git_head': head,
        'guest_host_identity_fingerprint_sha256': fingerprint,
        'guest_dmi_product_uuid': uuid,
        'network_adapters': network_identities(),
        'source_pki': {'name': pki_path.name, 'sha256': sha256_file(pki_path)},
        'cross_host_binding_method': 'hyperv-nic-mac-sha256-with-trailing-nul',
        'raw_mac_addresses_included': False,
        'authorization_marker_absent_verified': True,
        'automatic_ledger_promotion': False,
        'authorization_modified': False,
        'deployment_ledger_modified': False,
    }

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output = EVIDENCE_ROOT / f'hyperv-guest-identity-{stamp}.json'
    if output.exists():
        fail(f'refusing to overwrite evidence: {output}')
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    os.chmod(output, 0o600)

    print('HYPERV_GUEST_IDENTITY_BINDING=PASS')
    print(f'HYPERV_GUEST_IDENTITY_EVIDENCE={output}')
    print(f'HYPERV_GUEST_IDENTITY_EVIDENCE_SHA256={sha256_file(output)}')
    print(f'HYPERV_GUEST_DMI_UUID_INFORMATIONAL={uuid}')
    print('HYPERV_GUEST_NETWORK_IDENTITY=ELIGIBLE_FOR_WINDOWS_BINDING')
    print('HYPERV_GUEST_IDENTITY_LEDGER_UPDATED=NO')
    print('HYPERV_GUEST_IDENTITY_AUTHORIZATION_UPDATED=NO')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
