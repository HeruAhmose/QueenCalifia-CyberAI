"""
API-key fingerprinting for Queen Califia.

API keys are high-entropy machine credentials. CodeQL treats credentials from
request headers as password-like sensitive data, so the persisted verifier uses
PBKDF2-HMAC-SHA-256 rather than a fast digest. The pepper remains server-side
and is domain-separated into the deterministic KDF salt.
"""
from __future__ import annotations

import hashlib

API_KEY_STORE_VERSION = 3
API_KEY_HASH_SCHEME = "pbkdf2-hmac-sha256-v1"
API_KEY_KDF_ITERATIONS = 300_000
_API_KEY_SALT_DOMAIN = b"QueenCalifia|api-key-fingerprint|v1|"


def api_key_fingerprint(value: str, pepper: str) -> str:
    """Return the deterministic PBKDF2 fingerprint for a machine API key."""
    if not isinstance(value, str) or not value:
        return ""
    if len(value) > 1024:
        return ""
    if not isinstance(pepper, str) or not pepper:
        raise ValueError(
            "QC_API_KEY_PEPPER is required for structured API-key verification"
        )

    salt = _API_KEY_SALT_DOMAIN + pepper.encode("utf-8")
    return hashlib.pbkdf2_hmac(
        "sha256",
        value.encode("utf-8"),
        salt,
        API_KEY_KDF_ITERATIONS,
        dklen=32,
    ).hex()