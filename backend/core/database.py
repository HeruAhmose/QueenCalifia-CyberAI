"""Compatibility export for the canonical root primary database contract.

The backend entrypoint prepends the repository root before importing dashboard
modules, but direct backend imports may still resolve this module first. Load
one canonical implementation so SQLite/PostgreSQL behavior cannot drift between
`core.database` copies during issue #72.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_ROOT_DATABASE = Path(__file__).resolve().parents[2] / "core" / "database.py"
_SPEC = importlib.util.spec_from_file_location("_qc_primary_database", _ROOT_DATABASE)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"Unable to load primary database contract: {_ROOT_DATABASE}")
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

_EXPORTS = (
    "DatabaseConnection",
    "DatabaseCursor",
    "SQLITE_SCHEMA",
    "POSTGRES_SCHEMA",
    "TRUSTED_SOURCES",
    "audit",
    "database_backend",
    "database_url",
    "get_db",
    "get_market_history",
    "init_db",
    "json_dumps",
    "log_event",
    "save_market_snapshot",
    "sha256",
    "utc_now",
)
for _name in _EXPORTS:
    globals()[_name] = getattr(_MODULE, _name)

__all__ = list(_EXPORTS)
