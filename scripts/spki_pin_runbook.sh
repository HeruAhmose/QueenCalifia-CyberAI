#!/usr/bin/env bash
# scripts/spki_pin_runbook.sh
#
# Retries redis_spki_pin.py for transient TLS handshake/connect failures (exit 1),
# with exponential backoff + jitter. Fails fast on cert/SPKI errors (exit 3).
#
# Usage:
#   chmod +x scripts/spki_pin_runbook.sh
#   scripts/spki_pin_runbook.sh --url rediss://host:6380/0 --json --out ./spki.jsonl
#   scripts/spki_pin_runbook.sh host port
#
# Env:
#   QC_SPKI_RETRIES=6             Total attempts (default: 6)
#   QC_SPKI_BACKOFF_MS=250        Initial backoff in ms (default: 250)
#   QC_SPKI_MAX_BACKOFF_MS=8000   Max backoff in ms (default: 8000)
#   QC_SPKI_RETRY_LOCK_TIMEOUT=0     Retry lock timeouts (exit 2) when set to 1 (default: 0)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python}"
TARGET="${SCRIPT_DIR}/redis_spki_pin.py"

RETRIES="${QC_SPKI_RETRIES:-6}"
BACKOFF_MS="${QC_SPKI_BACKOFF_MS:-250}"
MAX_BACKOFF_MS="${QC_SPKI_MAX_BACKOFF_MS:-8000}"

now_ms() {
  if date +%s%3N >/dev/null 2>&1; then
    date +%s%3N
  else
    echo $(( $(date +%s) * 1000 ))
  fi
}

start_ms="$(now_ms)"

# Best-effort extract --out value so we can append JSON summary to the same JSONL.
TARGET_INPUT=""
OUT_PATH=""
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  if [ "${args[i]}" = "--out" ] && [ $((i+1)) -lt ${#args[@]} ]; then
    OUT_PATH="${args[i+1]}"
  fi
  if [ "${args[i]}" = "--url" ] && [ $((i+1)) -lt ${#args[@]} ]; then
    TARGET_INPUT="${args[i+1]}"
  fi
done
if [ -z "$TARGET_INPUT" ] && [ "${#args[@]}" -ge 2 ] && [[ "${args[0]}" != --* ]]; then
  TARGET_INPUT="${args[0]}:${args[1]}"
fi

append_jsonl_locked() {
  local path="$1"
  local line="$2"
  "$PY" - "$path" "$line" <<'PY'
import os, sys
try:
    import fcntl  # type: ignore
except Exception:
    fcntl = None  # type: ignore

path = sys.argv[1]
line = sys.argv[2]
out_path = os.path.abspath(path)
os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

with open(out_path, "a", encoding="utf-8") as f:
    if fcntl is not None:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    try:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())
    finally:
        if fcntl is not None:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
PY
}
emit_attempt_json() {
  local rc="$1"
  local sleep_ms="${2:-0}"
  if [ "${QC_SPKI_ATTEMPT_JSON:-0}" != "1" ] && [ "${QC_SPKI_ATTEMPT_JSON:-0}" != "true" ] && [ "${QC_SPKI_ATTEMPT_JSON:-0}" != "True" ]; then
    return 0
  fi

  local end_ms
  end_ms="$(now_ms)"
  local elapsed_ms=$(( end_ms - start_ms ))

  local json_line
  json_line="$(
    QC_SPKI_TARGET="$TARGET_INPUT" \
    QC_SPKI_ATTEMPT="$attempts_run" \
    QC_SPKI_RC="$rc" \
    QC_SPKI_SLEEP_MS="$sleep_ms" \
    QC_SPKI_ELAPSED_MS="$elapsed_ms" \
    "$PY" - <<'PY'
import datetime, json, os
target = os.getenv("QC_SPKI_TARGET", "")
attempt = int(os.getenv("QC_SPKI_ATTEMPT", "0"))
rc = int(os.getenv("QC_SPKI_RC", "0"))
sleep_ms = int(os.getenv("QC_SPKI_SLEEP_MS", "0"))
elapsed_ms = int(os.getenv("QC_SPKI_ELAPSED_MS", "0"))

rec = {
  "event_type": "qc.redis.spki_pin.runbook.retry_attempt",
  "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z"),
  "schema_version": 1,
  "target": target,
  "attempt": attempt,
  "rc": rc,
  "scheduled_sleep_ms": sleep_ms,
  "elapsed_ms": elapsed_ms,
}
print(json.dumps(rec, separators=(",",":"), ensure_ascii=False))
PY
  )"

  if [ -n "$OUT_PATH" ]; then
    append_jsonl_locked "$OUT_PATH" "$json_line" || true
  else
    echo "$json_line" >&2
  fi
}

RETRY_LOCK_TIMEOUT="${QC_SPKI_RETRY_LOCK_TIMEOUT:-0}"

attempt=1
backoff_ms="$BACKOFF_MS"

attempts_run=0
total_sleep_ms=0
last_rc=0

summary() {
  local rc="${1:-$?}"
  local end_ms
  end_ms="$(now_ms)"
  local elapsed_ms=$(( end_ms - start_ms ))

  echo "[summary] attempts=${attempts_run} total_sleep_ms=${total_sleep_ms} elapsed_ms=${elapsed_ms} rc=${rc}" >&2

  if [ "${QC_SPKI_SUMMARY_JSON:-0}" = "1" ] || [ "${QC_SPKI_SUMMARY_JSON:-0}" = "true" ] || [ "${QC_SPKI_SUMMARY_JSON:-0}" = "True" ]; then
    local json_line
    json_line="$(
      QC_SPKI_LAST_RC="$rc" \
      QC_SPKI_ATTEMPTS="$attempts_run" \
      QC_SPKI_TOTAL_SLEEP_MS="$total_sleep_ms" \
      QC_SPKI_ELAPSED_MS="$elapsed_ms" \
      QC_SPKI_OUT_PATH="$OUT_PATH" \
      QC_SPKI_TARGET="$TARGET_INPUT" \
      "$PY" - <<'PY'
import datetime, json, os
rc = int(os.getenv("QC_SPKI_LAST_RC", "0"))
attempts = int(os.getenv("QC_SPKI_ATTEMPTS", "0"))
total_sleep_ms = int(os.getenv("QC_SPKI_TOTAL_SLEEP_MS", "0"))
elapsed_ms = int(os.getenv("QC_SPKI_ELAPSED_MS", "0"))
out_path = os.getenv("QC_SPKI_OUT_PATH", "")
target = os.getenv("QC_SPKI_TARGET", "")

rec = {
  "event_type": "qc.redis.spki_pin.runbook",
  "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z"),
  "schema_version": 1,
  "target": target,
  "attempts": attempts,
  "total_sleep_ms": total_sleep_ms,
  "elapsed_ms": elapsed_ms,
  "rc": rc,
}
if out_path:
  rec["out_path"] = out_path
print(json.dumps(rec, separators=(",",":"), ensure_ascii=False))
PY
    )"

    if [ -n "$OUT_PATH" ]; then
      append_jsonl_locked "$OUT_PATH" "$json_line" || true
    else
      echo "$json_line" >&2
    fi
  fi
}

trap 'summary $?' EXIT

jitter_ms() {
  local base="$1"
  local jitter=$(( base / 5 )) # 0..20%
  if [ "$jitter" -le 0 ]; then
    echo 0
  else
    echo $(( RANDOM % (jitter + 1) ))
  fi
}

sleep_ms() {
  local ms="$1"
  local s
  s="$(awk -v ms="$ms" 'BEGIN { printf "%.3f", ms/1000 }')"
  sleep "$s"
}

while true; do
  attempts_run=$(( attempts_run + 1 ))
  set +e
  "$PY" "$TARGET" "$@"
  rc=$?
  last_rc=$rc
  set -e

  if [ "$rc" -eq 0 ]; then
    exit 0
  fi

  if [ "$rc" -eq 3 ]; then
    echo "ERROR: cert parse/SPKI extraction failure (rc=3); refusing to retry." >&2
    exit 3
  fi

  if [ "$rc" -ne 1 ]; then
    if [ "$rc" -eq 2 ] && { [ "$RETRY_LOCK_TIMEOUT" = "1" ] || [ "$RETRY_LOCK_TIMEOUT" = "true" ] || [ "$RETRY_LOCK_TIMEOUT" = "True" ]; }; then
      :
    else
      echo "ERROR: non-retryable failure rc=${rc}; exiting." >&2
      exit "$rc"
    fi
  fi

  if [ "$attempt" -ge "$RETRIES" ]; then
    echo "ERROR: TLS handshake/connect failure persisted after ${RETRIES} attempts (rc=1)." >&2
    exit 1
  fi

  j="$(jitter_ms "$backoff_ms")"
  wait_ms=$(( backoff_ms + j ))
  emit_attempt_json "$rc" "$wait_ms"
  if [ "$rc" -eq 2 ]; then
    echo "[retry] rc=2 (lock timeout) attempt=${attempt}/${RETRIES} sleeping=${wait_ms}ms" >&2
  else
    echo "[retry] rc=1 attempt=${attempt}/${RETRIES} sleeping=${wait_ms}ms" >&2
  fi
  total_sleep_ms=$(( total_sleep_ms + wait_ms ))
  sleep_ms "$wait_ms"

  backoff_ms=$(( backoff_ms * 2 ))
  if [ "$backoff_ms" -gt "$MAX_BACKOFF_MS" ]; then
    backoff_ms="$MAX_BACKOFF_MS"
  fi
  attempt=$(( attempt + 1 ))
done
