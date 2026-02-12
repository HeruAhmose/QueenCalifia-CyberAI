"""Release-time version synchronization.

This updates:
  - helm/queen-califia/Chart.yaml: version + appVersion
  - helm/queen-califia/values.yaml: default image tags for api/worker/frontend

It avoids external YAML deps by performing small, targeted line replacements.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def _replace_chart_kv(chart_path: Path, key: str, value: str) -> None:
    lines = chart_path.read_text(encoding="utf-8").splitlines(True)
    out: list[str] = []
    changed = False

    pat = re.compile(rf"^({re.escape(key)}:\s*)(.*)$")
    for ln in lines:
        m = pat.match(ln)
        if m:
            out.append(m.group(1) + value + "\n")
            changed = True
        else:
            out.append(ln)

    if not changed:
        raise SystemExit(f"Key '{key}' not found in {chart_path}")

    chart_path.write_text("".join(out), encoding="utf-8")


def _replace_values_section_tag(values_path: Path, section: str, new_tag: str) -> None:
    lines = values_path.read_text(encoding="utf-8").splitlines(True)
    out: list[str] = []

    top_level = re.compile(r"^([A-Za-z0-9_-]+):\s*$")
    current_section: str | None = None
    in_image = False
    replaced = False

    for ln in lines:
        m = top_level.match(ln)
        if m:
            current_section = m.group(1)
            in_image = False
            out.append(ln)
            continue

        if current_section != section:
            out.append(ln)
            continue

        if re.match(r"^\s+image:\s*$", ln):
            in_image = True
            out.append(ln)
            continue

        if in_image and re.match(r"^\s+tag:\s*", ln):
            indent = re.match(r"^(\s*)tag:\s*", ln).group(1)
            out.append(f'{indent}tag: "{new_tag}"\n')
            replaced = True
            in_image = False  # replace only the first tag under image
            continue

        out.append(ln)

    if not replaced:
        raise SystemExit(f"Did not update '{section}.image.tag' in {values_path}")

    values_path.write_text("".join(out), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", help="Release version (e.g. 0.1.0 or v0.1.0)")
    args = parser.parse_args()

    version = args.version.lstrip("v").strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?", version):
        raise SystemExit(f"Invalid version: {version}")

    chart = Path("helm/queen-califia/Chart.yaml")
    values = Path("helm/queen-califia/values.yaml")

    _replace_chart_kv(chart, "version", version)
    _replace_chart_kv(chart, "appVersion", f'"{version}"')

    for section in ("api", "worker", "frontend"):
        _replace_values_section_tag(values, section, version)

    print(f"Synced Helm chart version/appVersion + default image tags to {version}")


if __name__ == "__main__":
    main()
