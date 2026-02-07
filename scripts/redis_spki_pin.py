"""
scripts/redis_spki_pin.py

Print SHA256(SPKI DER) fingerprints for a TLS Redis endpoint to bootstrap pinning.

- Stdlib only.
- Uses the same SPKI extraction approach as scripts/redis_ping.py.
- Does NOT speak Redis; it only performs a TLS handshake and inspects the peer certificate.

Usage:
  python scripts/redis_spki_pin.py host port
  python scripts/redis_spki_pin.py --url rediss://host:port/0

Env:
  QC_REDIS_TLS_CA=/path/ca.pem        Custom CA (PEM).
  QC_REDIS_TLS_SERVERNAME=...         Override SNI/hostname validation name.
  QC_REDIS_TLS_INSECURE=1             Disable verification (NOT recommended).
"""

from __future__ import annotations

import argparse
import json
import datetime
import time
import random
import base64
import hashlib
import os
import socket
import ssl

try:
    import fcntl  # type: ignore
except Exception:  # pragma: no cover
    fcntl = None  # type: ignore

import sys
import urllib.parse
from dataclasses import dataclass

EXIT_OK = 0
EXIT_TLS_HANDSHAKE = 1
EXIT_LOCK_TIMEOUT = 2
EXIT_CERT_PARSE = 3
EXIT_OTHER = 4


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


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
    return _Tlv(tag=tag, start=i0, end=v1, value_start=v0, value_end=v1), v1


def _children_of_sequence(data: bytes, tlv: _Tlv) -> list[_Tlv]:
    if tlv.tag != 0x30:
        raise ValueError("not a sequence")
    i = tlv.value_start
    out: list[_Tlv] = []
    while i < tlv.value_end:
        child, i = _read_tlv(data, i)
        out.append(child)
    return out


def _extract_spki_der_from_cert(cert_der: bytes) -> bytes:
    outer, _ = _read_tlv(cert_der, 0)
    outer_children = _children_of_sequence(cert_der, outer)
    if not outer_children:
        raise ValueError("bad cert")
    tbs = outer_children[0]
    tbs_children = _children_of_sequence(cert_der, tbs)
    if not tbs_children:
        raise ValueError("bad tbs")

    idx = 0
    if tbs_children[0].tag == 0xA0:  # [0] EXPLICIT version
        idx = 1

    spki_index = idx + 5
    if spki_index >= len(tbs_children):
        raise ValueError("missing spki")
    spki = tbs_children[spki_index]
    return cert_der[spki.start : spki.end]


def _connect_tls(host: str, port: int) -> ssl.SSLSocket:
    insecure = _env_bool("QC_REDIS_TLS_INSECURE", default=False)
    ca_path = os.getenv("QC_REDIS_TLS_CA")
    servername = os.getenv("QC_REDIS_TLS_SERVERNAME") or host

    if insecure:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context()
        if ca_path:
            ctx.load_verify_locations(cafile=ca_path)

    raw = socket.create_connection((host, port), timeout=5.0)
    try:
        ssl_sock = ctx.wrap_socket(raw, server_hostname=servername if not insecure else None)
        return ssl_sock
    except Exception:
        raw.close()
        raise


def _parse_url(url: str) -> tuple[str, int]:
    u = urllib.parse.urlparse(url)
    if u.scheme not in {"rediss", "https"}:
        raise ValueError("URL must be rediss://host:port[/db]")
    host = u.hostname or ""
    if not host:
        raise ValueError("missing host in url")
    port = int(u.port or 6380)
    return host, port



def _der_to_pem(cert_der: bytes, redact_body: bool = False) -> str:
    if redact_body:
        return "-----BEGIN CERTIFICATE-----\n<redacted>\n-----END CERTIFICATE-----"
    b64 = base64.b64encode(cert_der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    body = "\n".join(lines)
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----"



def _lock_settings() -> tuple[float, float, float]:
    """
    Returns (timeout_s, backoff_s, max_backoff_s) from env.
    """
    timeout_s = float(os.getenv("QC_JSONL_LOCK_TIMEOUT_SEC", "5.0"))
    backoff_s = float(os.getenv("QC_JSONL_LOCK_BACKOFF_MS", "50")) / 1000.0
    max_backoff_s = float(os.getenv("QC_JSONL_LOCK_MAX_BACKOFF_MS", "500")) / 1000.0
    return timeout_s, backoff_s, max_backoff_s


def _lock_exclusive_with_timeout(
    f,
    *,
    path: str,
    timeout_s: float,
    backoff_s: float,
    max_backoff_s: float,
) -> None:
    """
    Best-effort POSIX exclusive lock with timeout/backoff.

    When fcntl is unavailable (non-POSIX), this is a no-op.
    """
    if fcntl is None:
        return

    deadline = time.monotonic() + max(0.0, timeout_s)
    delay = max(0.0, backoff_s)

    while True:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            now = time.monotonic()
            if now >= deadline:
                raise TimeoutError(
                    "timed out acquiring JSONL file lock "
                    f"path={path!r} timeout_s={timeout_s} backoff_s={backoff_s} max_backoff_s={max_backoff_s}"
                )
            jitter = random.uniform(0.0, delay * 0.2) if delay > 0 else 0.0
            time.sleep(delay + jitter)
            delay = min(max_backoff_s, max(delay * 1.5, 0.01))


def _unlock(f) -> None:
    if fcntl is None:
        return
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            'Exit codes:',
            '  0  Success',
            '  1  TLS handshake/connect failure',
            '  2  JSONL lock timeout (when using --json --out)',
            '  3  Certificate parse / SPKI extraction failure',
            '  4  Other/unexpected errors',
        ),
    )
    p.add_argument("host", nargs="?")
    p.add_argument("port", nargs="?", type=int)
    p.add_argument("--url", help="rediss://host:port/0")
    p.add_argument("--print-pem", action="store_true", help="Print leaf certificate PEM (for audits/tickets)")
    p.add_argument("--redact-pem", action="store_true", help="When printing PEM, omit base64 body (headers only)")
    p.add_argument("--json", action="store_true", help="Emit a single-line JSON record (ticket/SIEM friendly)")
    p.add_argument("--out", help="Append JSON line to this file (requires --json)")
    args = p.parse_args(argv[1:])

    if args.out and not args.json:
        p.error("--out requires --json")

    if args.url:
        try:
            host, port = _parse_url(args.url)
        except Exception as e:
            print(f"ERROR: invalid url: {e}", file=sys.stderr)
            return EXIT_OTHER
    else:
        if not args.host or not args.port:
            p.error("Provide host and port or --url")
        host, port = args.host, args.port

    try:
        ssl_sock = _connect_tls(host, port)
    except (ssl.SSLError, OSError) as e:
        print(f"ERROR: TLS handshake/connect failed: {e}", file=sys.stderr)
        return EXIT_TLS_HANDSHAKE

    try:
        cert_der = ssl_sock.getpeercert(binary_form=True)
        if not cert_der:
            raise RuntimeError("missing peer cert")

        parsed = ssl_sock.getpeercert(binary_form=False) or {}
        subject = parsed.get("subject")
        sans = parsed.get("subjectAltName")
        not_before = parsed.get("notBefore")
        not_after = parsed.get("notAfter")

        spki_der = _extract_spki_der_from_cert(cert_der)
        digest = hashlib.sha256(spki_der).digest()

        hex_fp = digest.hex()
        b64_fp = base64.b64encode(digest).decode("ascii")

        record = {
            "event_type": "qc.redis.spki_pin",
            "timestamp": datetime.datetime.now(datetime.timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "schema_version": 1,
            "host": host,
            "port": port,
            "servername": os.getenv("QC_REDIS_TLS_SERVERNAME") or host,
            "subject": subject,
            "subjectAltName": sans,
            "notBefore": not_before,
            "notAfter": not_after,
            "sha256_spki_hex": hex_fp,
            "sha256_spki_b64": b64_fp,
        }

        if args.print_pem:
            record["leaf_cert_pem"] = _der_to_pem(cert_der, redact_body=args.redact_pem)

        if args.json:
            line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
            try:
                if args.out:
                    out_path = os.path.abspath(args.out)
                    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
                    with open(out_path, "a", encoding="utf-8") as f:
                        timeout_s, backoff_s, max_backoff_s = _lock_settings()
                        _lock_exclusive_with_timeout(
                            f,
                            path=out_path,
                            timeout_s=timeout_s,
                            backoff_s=backoff_s,
                            max_backoff_s=max_backoff_s,
                        )
                        try:
                            f.write(line + "\n")
                            f.flush()
                            os.fsync(f.fileno())
                        finally:
                            _unlock(f)
                else:
                    print(line)
                return EXIT_OK
            except TimeoutError as e:
                print(f"ERROR: {e}", file=sys.stderr)
                return EXIT_LOCK_TIMEOUT

        # human-friendly output
        print(f"host={host} port={port}")
        print("leaf_cert:")
        if subject:
            print(f"  subject={subject}")
        if sans:
            print(f"  subjectAltName={sans}")
        if not_before or not_after:
            print(f"  validity_notBefore={not_before} notAfter={not_after}")
        print("")
        print(f"sha256_spki_hex={hex_fp}")
        print(f"sha256_spki_b64={b64_fp}")
        print("")
        if args.print_pem:
            print("leaf_cert_pem:")
            print(_der_to_pem(cert_der, redact_body=args.redact_pem))
            print("")
        print("Example:")
        print(f'  export QC_REDIS_TLS_SPKI_SHA256="{hex_fp}"')
        return EXIT_OK

    except (ValueError, RuntimeError) as e:
        print(f"ERROR: cert parse/spki extract failed: {e}", file=sys.stderr)
        return EXIT_CERT_PARSE
    except Exception as e:
        print(f"ERROR: unexpected failure: {e}", file=sys.stderr)
        return EXIT_OTHER
    finally:
        try:
            ssl_sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
