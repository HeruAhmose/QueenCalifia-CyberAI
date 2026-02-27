#!/usr/bin/env sh
set -eu

# Generates deterministic lockfiles with hashes using a Python 3.12 Linux container.
# Requires: Docker (and network access to your configured package index).
#
# Usage:
#   scripts/lock.sh            # write requirements.lock + requirements-dev.lock
#   scripts/lock.sh --upgrade  # upgrade within constraints
#   scripts/lock.sh --check    # fail if lockfiles are out of date (does not modify working tree)

IMAGE="${QC_LOCK_IMAGE:-python:3.12-slim}"
PIP_INDEX_URL="${PIP_INDEX_URL:-}"
PIP_EXTRA_INDEX_URL="${PIP_EXTRA_INDEX_URL:-}"

MODE="${1:-}"
UPGRADE="0"
CHECK="0"

if [ "${MODE:-}" = "--upgrade" ]; then
  UPGRADE="1"
elif [ "${MODE:-}" = "--check" ]; then
  CHECK="1"
elif [ -n "${MODE:-}" ]; then
  echo "Unknown argument: ${MODE}" >&2
  exit 64
fi

docker run --rm   -e PIP_DISABLE_PIP_VERSION_CHECK=1   -e PIP_NO_CACHE_DIR=0   -e PIP_INDEX_URL="$PIP_INDEX_URL"   -e PIP_EXTRA_INDEX_URL="$PIP_EXTRA_INDEX_URL"   -e QC_LOCK_UPGRADE="$UPGRADE"   -e QC_LOCK_CHECK="$CHECK"   -v "$(pwd)":/src   -w /src   "$IMAGE"   sh -lc '
    set -eu
    python -m pip install -U pip
    python -m pip install "pip-tools>=7.4.1,<8.0"

    if [ "${QC_LOCK_UPGRADE:-0}" = "1" ]; then UPG="--upgrade"; else UPG=""; fi

    if [ "${QC_LOCK_CHECK:-0}" = "1" ]; then
      TMP="$(mktemp -d)"
      pip-compile --resolver=backtracking --generate-hashes $UPG -o "$TMP/requirements.lock" requirements.in
      pip-compile --resolver=backtracking --generate-hashes $UPG -o "$TMP/requirements-dev.lock" requirements-dev.in

      if ! diff -q "$TMP/requirements.lock" requirements.lock >/dev/null 2>&1; then
        echo "❌ requirements.lock is out of date. Run: make lock" >&2
        exit 3
      fi
      if ! diff -q "$TMP/requirements-dev.lock" requirements-dev.lock >/dev/null 2>&1; then
        echo "❌ requirements-dev.lock is out of date. Run: make lock" >&2
        exit 3
      fi
      echo "✅ Lockfiles are up to date"
      exit 0
    fi

    pip-compile --resolver=backtracking --generate-hashes $UPG -o requirements.lock requirements.in
    pip-compile --resolver=backtracking --generate-hashes $UPG -o requirements-dev.lock requirements-dev.in
  '

if [ "$CHECK" = "0" ]; then
  echo "✅ Wrote requirements.lock + requirements-dev.lock"
fi
