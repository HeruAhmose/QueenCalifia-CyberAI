#!/usr/bin/env python3
"""Reject unsafe GitHub expression interpolation inside workflow run scripts.

GitHub expressions in `env:`/`with:` are data. The same expressions embedded
inside `run:` become shell or PowerShell source before execution and can turn
workflow inputs, secrets, or cross-job outputs into command-injection surfaces.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

WORKFLOW_DIR = Path(".github/workflows")
FORBIDDEN = (
    "${{ inputs.",
    "${{ github.event.inputs.",
    "${{ secrets.",
    "${{ needs.",
)
RUN_RE = re.compile(r"^(?P<indent>\s*)run:\s*(?P<value>.*)$")


def violations(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    found: list[str] = []
    i = 0

    while i < len(lines):
        line = lines[i]
        match = RUN_RE.match(line)
        if not match:
            i += 1
            continue

        base_indent = len(match.group("indent"))
        value = match.group("value").strip()
        script_lines: list[tuple[int, str]] = []

        if value.startswith(("|", ">")):
            j = i + 1
            while j < len(lines):
                candidate = lines[j]
                if candidate.strip():
                    indent = len(candidate) - len(candidate.lstrip())
                    if indent <= base_indent:
                        break
                script_lines.append((j + 1, candidate))
                j += 1
            i = j
        else:
            script_lines.append((i + 1, value))
            i += 1

        for lineno, script_line in script_lines:
            for token in FORBIDDEN:
                if token in script_line:
                    found.append(f"{path}:{lineno}: forbidden expression in run script: {token}")

    return found


def main() -> int:
    paths = sorted([*WORKFLOW_DIR.glob("*.yml"), *WORKFLOW_DIR.glob("*.yaml")])
    errors = [item for path in paths for item in violations(path)]
    if errors:
        print("Unsafe workflow interpolation detected:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        print("Pass dynamic values through step env:/with: and read them as data instead.", file=sys.stderr)
        return 1

    print(f"workflow shell-context guard: {len(paths)} workflow files clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
