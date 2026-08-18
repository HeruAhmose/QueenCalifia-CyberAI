#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
case "$ACTION" in
  prepare|verify) ;;
  *) echo "usage: reboot-persistence-proof.sh prepare|verify" >&2; exit 2 ;;
esac

ROOT="${QC_EDGE_STATE_ROOT:-/srv/queen-califia}"
ENV_FILE="${QC_EDGE_ENV_FILE:-.env.edge}"
COMPOSE_FILE="${QC_EDGE_COMPOSE_FILE:-deploy/edge/docker-compose.edge.yml}"
CHALLENGE="$ROOT/evidence/reboot-challenge.json"
GATE="$ROOT/app/cutover/SOVEREIGN_EDGE_RUNTIME_AUTHORIZED"
[[ -f "$ENV_FILE" ]] || { echo "missing $ENV_FILE" >&2; exit 2; }
[[ -f "$GATE" && "$(tr -d '\r\n' < "$GATE")" == "AUTHORIZED" ]] || { echo "reboot persistence proof requires an already-authorized runtime" >&2; exit 3; }
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
compose=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")
mkdir -p "$ROOT/evidence"

valkey_cli=(docker exec queen-califia-valkey valkey-cli --tls --cacert /run/valkey-pki/ca.crt --cert /run/valkey-pki/health.crt --key /run/valkey-pki/health.key -h valkey -p 6379)

if [[ "$ACTION" == "prepare" ]]; then
  [[ "$(docker inspect -f '{{.State.Health.Status}}' queen-califia-valkey 2>/dev/null || true)" == "healthy" ]] || { echo "Valkey must be healthy before preparing reboot proof" >&2; exit 4; }
  nonce="$(openssl rand -hex 32)"
  "${valkey_cli[@]}" SET qc:edge:reboot-proof "$nonce" | grep -qx OK
  sleep 2
  boot_id="$(cat /proc/sys/kernel/random/boot_id)"
  NONCE="$nonce" BOOT_ID="$boot_id" CHALLENGE="$CHALLENGE" python3 - <<'PY'
import datetime, hashlib, json, os, pathlib
nonce = os.environ["NONCE"]
record = {
    "schema": 1,
    "prepared_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "boot_id_before": os.environ["BOOT_ID"],
    "nonce": nonce,
    "nonce_sha256": hashlib.sha256(nonce.encode()).hexdigest(),
    "verified": False,
}
path = pathlib.Path(os.environ["CHALLENGE"])
path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
path.chmod(0o600)
PY
  echo "Reboot challenge prepared at $CHALLENGE"
  echo "Perform a real host reboot, then run: scripts/edge/reboot-persistence-proof.sh verify"
  exit 0
fi

[[ -f "$CHALLENGE" ]] || { echo "missing reboot challenge; run prepare before reboot" >&2; exit 4; }
"${compose[@]}" up -d
for _ in $(seq 1 45); do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' queen-califia-valkey 2>/dev/null || true)" == "healthy" ]] && break
  sleep 2
done
[[ "$(docker inspect -f '{{.State.Health.Status}}' queen-califia-valkey)" == "healthy" ]] || { echo "Valkey unhealthy after reboot" >&2; exit 5; }

current_boot="$(cat /proc/sys/kernel/random/boot_id)"
before_boot="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["boot_id_before"])' "$CHALLENGE")"
[[ "$current_boot" != "$before_boot" ]] || { echo "boot ID did not change; this is not a real reboot proof" >&2; exit 6; }
expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["nonce"])' "$CHALLENGE")"
actual="$("${valkey_cli[@]}" GET qc:edge:reboot-proof)"
[[ "$actual" == "$expected" ]] || { echo "Valkey AOF reboot persistence failed" >&2; exit 7; }

for _ in $(seq 1 45); do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' queen-califia-api 2>/dev/null || true)" == "healthy" ]] && break
  sleep 2
done
[[ "$(docker inspect -f '{{.State.Health.Status}}' queen-califia-api)" == "healthy" ]] || { echo "API unhealthy after reboot" >&2; exit 8; }
[[ "$(docker inspect -f '{{.State.Running}}' queen-califia-cloudflared)" == "true" ]] || { echo "cloudflared not running after reboot" >&2; exit 9; }

CURRENT_BOOT="$current_boot" CHALLENGE="$CHALLENGE" python3 - <<'PY'
import datetime, json, os, pathlib
path = pathlib.Path(os.environ["CHALLENGE"])
record = json.loads(path.read_text(encoding="utf-8"))
record.update({
    "verified": True,
    "verified_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "boot_id_after": os.environ["CURRENT_BOOT"],
    "valkey_aof_value_persisted": True,
    "api_healthy_after_reboot": True,
    "cloudflared_running_after_reboot": True,
})
path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
path.chmod(0o600)
PY

echo "REAL_REBOOT_PERSISTENCE_VERIFIED=$CHALLENGE"
