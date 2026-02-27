"""
scripts/redis_ping.py

Lightweight Redis reachability probe used by Makefile.
- Stdlib only (no redis-py).
- Supports redis:// and rediss:// (TLS).
- Supports mutual TLS (mTLS) via QC_REDIS_TLS_CA/CERT/KEY.
- Supports strict SNI/hostname override via QC_REDIS_TLS_SERVERNAME.
- Supports cert pinning by SHA256(SPKI DER) via QC_REDIS_TLS_SPKI_SHA256.
- Optional AUTH via URL password or QC_REDIS_PASSWORD.
- Exits 0 on success, 1 on failure.

Env:
  QC_REDIS_TLS=1                     Enable TLS (also enabled automatically for rediss://).
  QC_REDIS_TLS_INSECURE=1            Disable certificate verification (NOT recommended).
  QC_REDIS_TLS_CA=/path/ca.pem       Custom CA bundle (PEM).
  QC_REDIS_TLS_CERT=/path/cert.pem   Client certificate (PEM).
  QC_REDIS_TLS_KEY=/path/key.pem     Client private key (PEM).
  QC_REDIS_TLS_SERVERNAME=...        Override SNI/hostname used for certificate validation.
  QC_REDIS_TLS_SPKI_SHA256=...       Pin SHA256 of DER SubjectPublicKeyInfo.
                                     Accepts hex or base64; comma-separated allowed.
  QC_REDIS_CONNECT_TIMEOUT=1.5       Seconds (float).
  QC_REDIS_PASSWORD=...              Password if URL doesn't include it.
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl
import sys
import urllib.parse
from dataclasses import dataclass


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def _connect_timeout() -> float:
    v = os.getenv("QC_REDIS_CONNECT_TIMEOUT", "1.5").strip()
    try:
        return float(v)
    except ValueError:
        return 1.5


def _parse(url: str) -> tuple[str, int, str | None, bool]:
    u = urllib.parse.urlparse(url)
    if u.scheme not in {"redis", "rediss"}:
        raise ValueError(f"Unsupported scheme: {u.scheme!r}")
    host = u.hostname or "localhost"
    port = int(u.port or (6380 if u.scheme == "rediss" else 6379))
    password = u.password or os.getenv("QC_REDIS_PASSWORD")
    tls = (u.scheme == "rediss") or _env_bool("QC_REDIS_TLS", default=False)
    return host, port, password, tls


def _resp(*parts: bytes) -> bytes:
    out = []
    for p in parts:
        out.append(b"$" + str(len(p)).encode("ascii") + b"\r\n" + p + b"\r\n")
    return b"*" + str(len(parts)).encode("ascii") + b"\r\n" + b"".join(out)


def _read_line(sock: socket.socket) -> bytes:
    buf = b""
    while not buf.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 10_000:
            break
    return buf


@dataclass(frozen=True)
class _Tlv:
    tag: int
    start: int
    end: int
    value_start: int
    value_end: int


def _read_len(data: bytes, i: int) -> tuple[int, int]:
    first = data[i]
    i += 1
    if first < 0x80:
        return first, i
    n = first & 0x7F
    if n == 0 or n > 4:
        raise ValueError("unsupported length")
    if i + n > len(data):
        raise ValueError("truncated length")
    l = int.from_bytes(data[i : i + n], "big")
    return l, i + n


def _read_tlv(data: bytes, i: int) -> tuple[_Tlv, int]:
    if i >= len(data):
        raise ValueError("truncated")
    tag = data[i]
    i0 = i
    i += 1
    length, i = _read_len(data, i)
    v0 = i
    v1 = i + length
    if v1 > len(data):
        raise ValueError("truncated value")
    tlv = _Tlv(tag=tag, start=i0, end=v1, value_start=v0, value_end=v1)
    return tlv, v1


def _children_of_sequence(data: bytes, tlv: _Tlv) -> list[_Tlv]:
    if tlv.tag != 0x30:  # SEQUENCE
        raise ValueError("not a sequence")
    i = tlv.value_start
    out: list[_Tlv] = []
    while i < tlv.value_end:
        child, i = _read_tlv(data, i)
        out.append(child)
    return out


def _extract_spki_der_from_cert(cert_der: bytes) -> bytes:
    """
    Extracts the DER-encoded SubjectPublicKeyInfo element from an X.509 certificate.
    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    tbsCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, ... }
    """
    outer, _ = _read_tlv(cert_der, 0)
    outer_children = _children_of_sequence(cert_der, outer)
    if not outer_children:
        raise ValueError("bad cert")
    tbs = outer_children[0]
    tbs_children = _children_of_sequence(cert_der, tbs)
    if not tbs_children:
        raise ValueError("bad tbs")

    idx = 0
    # Optional version is [0] EXPLICIT => context-specific constructed tag A0
    if tbs_children[0].tag == 0xA0:
        idx = 1

    # After (optional) version: serial(0), signature(1), issuer(2), validity(3), subject(4), spki(5)
    spki_index = idx + 5
    if spki_index >= len(tbs_children):
        raise ValueError("missing spki")
    spki = tbs_children[spki_index]
    return cert_der[spki.start : spki.end]


def _normalize_pin(pin: str) -> bytes:
    p = pin.strip()
    if not p:
        raise ValueError("empty pin")
    # hex?
    if all(c in "0123456789abcdefABCDEF" for c in p) and len(p) in {64}:
        return bytes.fromhex(p)
    # base64
    return base64.b64decode(p, validate=True)


def _pins_from_env() -> list[bytes]:
    raw = os.getenv("QC_REDIS_TLS_SPKI_SHA256", "").strip()
    if not raw:
        return []
    out = []
    for part in raw.split(","):
        if part.strip():
            out.append(_normalize_pin(part))
    return out


def _check_spki_pins(ssl_sock: ssl.SSLSocket) -> None:
    pins = _pins_from_env()
    if not pins:
        return

    cert_der = ssl_sock.getpeercert(binary_form=True)
    if not cert_der:
        raise ValueError("missing peer cert")

    spki_der = _extract_spki_der_from_cert(cert_der)
    digest = hashlib.sha256(spki_der).digest()

    if not any(digest == p for p in pins):
        hex_fp = digest.hex()
        b64_fp = base64.b64encode(digest).decode("ascii")
        raise ValueError(f"SPKI pin mismatch (sha256 hex={hex_fp} b64={b64_fp})")


def _tls_wrap(raw: socket.socket, host: str) -> ssl.SSLSocket:
    insecure = _env_bool("QC_REDIS_TLS_INSECURE", default=False)
    ca_path = os.getenv("QC_REDIS_TLS_CA")
    cert_path = os.getenv("QC_REDIS_TLS_CERT")
    key_path = os.getenv("QC_REDIS_TLS_KEY")
    servername = os.getenv("QC_REDIS_TLS_SERVERNAME") or host

    if insecure:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context()
        if ca_path:
            ctx.load_verify_locations(cafile=ca_path)

    if cert_path:
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path or None)

    ssl_sock = ctx.wrap_socket(raw, server_hostname=servername if not insecure else None)
    _check_spki_pins(ssl_sock)
    return ssl_sock


def ping(url: str) -> bool:
    host, port, password, tls = _parse(url)
    timeout = _connect_timeout()

    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        sock: socket.socket = _tls_wrap(raw, host) if tls else raw
        sock.settimeout(timeout)

        if password:
            sock.sendall(_resp(b"AUTH", password.encode("utf-8")))
            line = _read_line(sock)
            if not line.startswith(b"+OK"):
                return False

        sock.sendall(_resp(b"PING"))
        line = _read_line(sock)
        return line.startswith(b"+PONG")
    finally:
        try:
            raw.close()
        except Exception:
            pass


def main(argv: list[str]) -> int:
    url = argv[1] if len(argv) > 1 else os.getenv("QC_REDIS_URL", "redis://localhost:6379/0")
    try:
        ok = ping(url)
    except Exception:
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
