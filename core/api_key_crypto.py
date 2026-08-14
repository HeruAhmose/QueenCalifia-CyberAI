"""
API-key fingerprinting for Queen Califia.

API keys are generated high-entropy machine credentials, not human passwords.
Use HMAC-SHA-256 as a keyed, non-portable fingerprint and compare fingerprints
in constant time.  hmac.digest is used directly so the secret never enters a
generic hashlib password-hash path.
"""
from __future__ import annotations

import hmac

API_KEY_STORE_VERSION = 2
API_KEY_HASH_SCHEME = "hmac-sha256-v1"


def api_key_fingerprint(value: str, pepper: str) -> str:
    """Return the deterministic keyed fingerprint for a high-entropy API key."""
    if not isinstance(value, str) or not value:
        return ""
    if not isinstance(pepper, str) or not pepper:
        raise ValueError("QC_API_KEY_PEPPER is required for structured API-key verification")
    return hmac.digest(
        pepper.encode("utf-8"),
        value.encode("utf-8"),
        "sha256",
    ).hex()