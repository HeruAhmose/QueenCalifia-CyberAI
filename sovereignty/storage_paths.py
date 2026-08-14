"""
Static persistence destinations for sovereignty SQLite stores.

Environment variables may select only exact, deployment-owned database paths.
They never become arbitrary filesystem paths.  Render mounts /var/data and
Docker Compose mounts /data; local development may use the repository data/
directory.  Direct store construction remains available to unit tests.
"""
from __future__ import annotations

from pathlib import Path
from typing import Final

_REPO_DATA = Path(__file__).resolve().parents[1] / "data"

_APPROVAL_PATHS: Final[dict[str, Path]] = {
    "/var/data/queen.db": Path("/var/data/queen.db"),
    "/var/data/approvals.db": Path("/var/data/approvals.db"),
    "/data/queen.db": Path("/data/queen.db"),
    "/data/approvals.db": Path("/data/approvals.db"),
    "data/queen.db": _REPO_DATA / "queen.db",
    "./data/queen.db": _REPO_DATA / "queen.db",
    "data/approvals.db": _REPO_DATA / "approvals.db",
    "./data/approvals.db": _REPO_DATA / "approvals.db",
}

_AUDIT_PATHS: Final[dict[str, Path]] = {
    "/var/data/queen.db": Path("/var/data/queen.db"),
    "/var/data/audit-chain.db": Path("/var/data/audit-chain.db"),
    "/var/data/audit_chain.db": Path("/var/data/audit_chain.db"),
    "/data/queen.db": Path("/data/queen.db"),
    "/data/audit-chain.db": Path("/data/audit-chain.db"),
    "/data/audit_chain.db": Path("/data/audit_chain.db"),
    "data/queen.db": _REPO_DATA / "queen.db",
    "./data/queen.db": _REPO_DATA / "queen.db",
    "data/audit-chain.db": _REPO_DATA / "audit-chain.db",
    "./data/audit-chain.db": _REPO_DATA / "audit-chain.db",
    "data/audit_chain.db": _REPO_DATA / "audit_chain.db",
    "./data/audit_chain.db": _REPO_DATA / "audit_chain.db",
}

_PRODUCTION_APPROVAL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "/var/data/queen.db",
        "/var/data/approvals.db",
        "/data/queen.db",
        "/data/approvals.db",
    }
)

_PRODUCTION_AUDIT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "/var/data/queen.db",
        "/var/data/audit-chain.db",
        "/var/data/audit_chain.db",
        "/data/queen.db",
        "/data/audit-chain.db",
        "/data/audit_chain.db",
    }
)


def resolve_configured_sqlite_path(
    raw_path: str | None,
    purpose: str,
    *,
    production: bool,
) -> Path | None:
    """Resolve only an exact application-owned SQLite destination."""
    if purpose == "approval database":
        allowed = _APPROVAL_PATHS
        production_keys = _PRODUCTION_APPROVAL_KEYS
    elif purpose == "audit-chain database":
        allowed = _AUDIT_PATHS
        production_keys = _PRODUCTION_AUDIT_KEYS
    else:
        raise ValueError(f"Unknown sovereignty persistence purpose: {purpose}")

    value = (raw_path or "").strip()
    if not value:
        if not production:
            return None

        if Path("/var/data").is_dir():
            return Path("/var/data/queen.db")
        if Path("/data").is_dir():
            return Path("/data/queen.db")
        raise RuntimeError(
            f"{purpose} requires the Render /var/data or Compose /data persistent mount"
        )

    if production and value not in production_keys:
        raise ValueError(
            f"{purpose} must use an approved production database path"
        )

    resolved = allowed.get(value)
    if resolved is None:
        raise ValueError(
            f"{purpose} path is not in the application-owned allowlist"
        )

    return resolved