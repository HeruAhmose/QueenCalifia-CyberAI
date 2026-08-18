#!/usr/bin/env bash
set -euo pipefail

python /opt/queen-califia/scripts/managed/validate_runtime_env.py
exec "$@"
