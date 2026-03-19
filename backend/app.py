"""
QC OS backend entrypoint for Render.

Your onrender service runs `gunicorn app:app` with `rootDir: backend`.
This repository includes a *root* `app.py` (from a previous working release)
that wires `api/gateway.py` + `engines/vulnerability_engine.py`, exposing the
real vulnerability scan/remediation endpoints under `/api/vulns/*`.

This file intentionally re-exports that root WSGI app so the Render command
remains unchanged while vulnerability routes work end-to-end.
"""

from __future__ import annotations

import importlib.util
import os
import sys


def _load_root_app():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    root_app_path = os.path.join(repo_root, "app.py")
    spec = importlib.util.spec_from_file_location("qc_root_app", root_app_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load root app module from: {root_app_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


app = _load_root_app()


__all__ = ["app"]
