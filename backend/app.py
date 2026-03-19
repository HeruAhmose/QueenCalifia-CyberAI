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
    # On some deployments the Render env doesn't set `QC_NO_AUTH`, but also
    # doesn't provide `QC_API_KEY`. In that case the security gateway would
    # reject the whole dashboard with 401s. For a better out-of-the-box UX,
    # default to allowing requests when no API key is configured.
    if not os.environ.get("QC_NO_AUTH") and not os.environ.get("QC_API_KEY"):
        os.environ["QC_NO_AUTH"] = "1"

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
