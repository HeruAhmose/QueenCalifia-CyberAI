"""
tests/test_smoketest_diff_window_env.py

Regression: ensure QC_SMOKETEST_DIFF_WINDOW is honored by _uid_diff default.
"""

from __future__ import annotations

import importlib
import os
import types


def test_diff_window_env_is_honored(monkeypatch):
    monkeypatch.setenv("QC_SMOKETEST_DIFF_WINDOW", "1")
    # Import module fresh under env
    import smoketest.provisioned_smoketest as mod
    mod = importlib.reload(mod)

    expected = ["a", "b", "c"]
    observed = ["a", "X", "c"]
    out = mod._uid_diff(expected, observed, window=None)
    assert "context_expected[0:3]" in out  # with window=1, show 1 item of context on each side of index 1 => slice 0:3
