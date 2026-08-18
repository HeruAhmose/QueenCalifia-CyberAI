import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(path: str, *needles: str) -> None:
    text = read(path)
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{path}: missing runtime-security invariant(s): {missing}")


def reject(path: str, *needles: str) -> None:
    text = read(path)
    found = [needle for needle in needles if needle in text]
    if found:
        raise SystemExit(f"{path}: forbidden mutable/privileged pattern(s): {found}")


require(
    "Dockerfile",
    "--uid 10001",
    "--gid 10001",
    "USER 10001:10001",
)

require(
    "backend/Dockerfile",
    "ARG LIBOQS_VERSION=0.16.0",
    "ARG LIBOQS_PYTHON_VERSION=0.16.0",
    'git clone --depth=1 --branch "${LIBOQS_VERSION}"',
    'git clone --depth=1 --branch "${LIBOQS_PYTHON_VERSION}"',
    "python -m pip install /tmp/liboqs-python",
    "USER 10001:10001",
)
reject(
    "backend/Dockerfile",
    "git clone --depth=1 https://github.com/open-quantum-safe/liboqs",
    "git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python",
    "python -m pip install liboqs-python\n",
)

for path in (
    "helm/queen-califia/templates/api-deployment.yaml",
    "helm/queen-califia/templates/worker-deployment.yaml",
    "helm/queen-califia/templates/frontend-deployment.yaml",
    "helm/queen-califia/templates/redis.yaml",
    "k8s/api.yaml",
    "k8s/worker.yaml",
    "k8s/frontend.yaml",
    "k8s/redis.yaml",
):
    require(path, "automountServiceAccountToken: false")

for path in ("k8s/api.yaml", "k8s/worker.yaml"):
    require(
        path,
        "runAsNonRoot: true",
        "runAsUser: 10001",
        "runAsGroup: 10001",
        "type: RuntimeDefault",
        "allowPrivilegeEscalation: false",
        'drop: ["ALL"]',
    )

require(
    "helm/queen-califia/values.yaml",
    "runAsNonRoot: true",
    "runAsUser: 10001",
    "runAsGroup: 10001",
    "fsGroup: 10001",
    "fsGroupChangePolicy: OnRootMismatch",
    "type: RuntimeDefault",
    "allowPrivilegeEscalation: false",
    'drop: ["ALL"]',
    "replicaCount: 1",
    "minReplicas: 1",
    "maxReplicas: 1",
)

require(
    "helm/queen-califia/templates/api-deployment.yaml",
    "gt (int .Values.api.replicaCount) 1",
    ".Values.api.autoscaling.enabled",
    "multi-replica/autoscaling is unsupported while authoritative runtime state is local SQLite/file-backed",
    "name: api-state",
    "mountPath: /var/data",
    "claimName: qc-api-state",
    "name: QC_DB_PATH",
    "value: /var/data/queen.db",
    "name: QC_EVOLUTION_DB",
    "value: /var/data/qc_evolution.db",
    "name: QC_MEMORY_BACKUP_DIR",
    "value: /var/data/memory-backups",
    "name: QC_THREAT_INTEL_DB",
    "value: /var/data/qc_threat_intel.db",
    "name: QC_API_KEYS_FILE",
    "value: /var/data/keys.json",
    "name: QC_AUDIT_LOG_FILE",
    "value: /var/data/audit.log.jsonl",
    "name: QC_AUDIT_CHAIN_DB",
    "name: QC_APPROVALS_DB",
    "name: QC_SPKI_LOG_FILE",
    "value: /var/data/spki.jsonl",
)

require(
    "helm/queen-califia/templates/api-pvc.yaml",
    "kind: PersistentVolumeClaim",
    "name: qc-api-state",
    "ReadWriteOnce",
    "storage: 10Gi",
)

require(
    "k8s/api.yaml",
    "replicas: 1",
    "fsGroup: 10001",
    "fsGroupChangePolicy: OnRootMismatch",
    "name: api-state",
    "mountPath: /var/data",
    "claimName: qc-api-state",
    "name: QC_DB_PATH",
    "value: /var/data/queen.db",
    "name: QC_EVOLUTION_DB",
    "value: /var/data/qc_evolution.db",
    "name: QC_MEMORY_BACKUP_DIR",
    "value: /var/data/memory-backups",
    "name: QC_THREAT_INTEL_DB",
    "value: /var/data/qc_threat_intel.db",
    "name: QC_API_KEYS_FILE",
    "value: /var/data/keys.json",
    "name: QC_AUDIT_LOG_FILE",
    "value: /var/data/audit.log.jsonl",
    "name: QC_AUDIT_CHAIN_DB",
    "name: QC_APPROVALS_DB",
    "name: QC_SPKI_LOG_FILE",
    "value: /var/data/spki.jsonl",
)

require(
    "k8s/api-pvc.yaml",
    "kind: PersistentVolumeClaim",
    "name: qc-api-state",
    "ReadWriteOnce",
    "storage: 10Gi",
)

# The worker's distributed result channel is Redis/Celery. Never attach the
# single-writer API SQLite volume to a different pod while #72 remains open.
for path in (
    "helm/queen-califia/templates/worker-deployment.yaml",
    "k8s/worker.yaml",
):
    reject(path, "api-state", "qc-api-state", "mountPath: /var/data")

# ---------------------------------------------------------------------------
# Runtime-state topology gate (#72)
# ---------------------------------------------------------------------------
# A partial external-state migration is more dangerous than an explicit
# single-writer deployment: it can make Kubernetes look horizontally safe
# while a forgotten SQLite/file writer still diverges between pods. Keep a
# machine-readable inventory and fail CI whenever production code adds or
# removes a direct sqlite3.connect call without updating the architecture map.
topology_path = ROOT / "config/runtime-state-topology.json"
try:
    topology = json.loads(topology_path.read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"{topology_path.relative_to(ROOT)}: invalid state topology: {exc}") from exc

if topology.get("version") != 1:
    raise SystemExit("runtime-state topology version must be 1")
if topology.get("architecture_state") != "sqlite-single-writer":
    raise SystemExit("runtime-state topology must remain sqlite-single-writer until #72 migration completes")
if topology.get("external_authority_target") != "postgresql":
    raise SystemExit("runtime-state topology must declare PostgreSQL as the external authority target")
if topology.get("multi_replica_api_permitted") is not False:
    raise SystemExit("runtime-state topology must not permit multi-replica API while SQLite writers remain")

connectors = topology.get("sqlite_connectors")
if not isinstance(connectors, list) or not connectors:
    raise SystemExit("runtime-state topology must inventory sqlite_connectors")

inventory_paths = set()
for connector in connectors:
    if not isinstance(connector, dict):
        raise SystemExit("runtime-state topology sqlite_connectors entries must be objects")
    path = connector.get("path")
    if not isinstance(path, str) or not path:
        raise SystemExit("runtime-state topology sqlite connector missing path")
    if path in inventory_paths:
        raise SystemExit(f"runtime-state topology duplicates sqlite connector: {path}")
    inventory_paths.add(path)
    if connector.get("authoritative") and connector.get("migration_required") is not True:
        raise SystemExit(f"authoritative SQLite writer must require migration: {path}")

production_roots = {"api", "backend", "core", "engines", "sovereignty"}
discovered_sqlite_paths = set()
for candidate in ROOT.rglob("*.py"):
    rel = candidate.relative_to(ROOT)
    if any(part in {"tests", "test", "__pycache__", ".venv", "venv"} for part in rel.parts):
        continue
    include = rel.parts[0] in production_roots or rel.as_posix() == "cli.py"
    if not include:
        continue
    try:
        text = candidate.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    if "sqlite3.connect" in text:
        discovered_sqlite_paths.add(rel.as_posix())

untracked = sorted(discovered_sqlite_paths - inventory_paths)
stale = sorted(inventory_paths - discovered_sqlite_paths)
if untracked or stale:
    raise SystemExit(
        "runtime-state topology drift: "
        f"untracked sqlite writers={untracked}; stale inventory entries={stale}"
    )

# File-backed API state must remain explicitly bound to the single API PVC.
api_file_state = topology.get("api_file_state")
if not isinstance(api_file_state, list) or not api_file_state:
    raise SystemExit("runtime-state topology must inventory api_file_state")

helm_api = read("helm/queen-califia/templates/api-deployment.yaml")
direct_api = read("k8s/api.yaml")
for state in api_file_state:
    if not isinstance(state, dict):
        raise SystemExit("runtime-state topology api_file_state entries must be objects")
    env_name = state.get("environment")
    state_path = state.get("path")
    disposition = state.get("migration_disposition")
    if not all(isinstance(v, str) and v for v in (env_name, state_path, disposition)):
        raise SystemExit(f"invalid api_file_state entry: {state}")
    if not state_path.startswith("/var/data/"):
        raise SystemExit(f"API file state must remain under the single-writer PVC: {env_name}={state_path}")
    for manifest_name, manifest in (
        ("helm API deployment", helm_api),
        ("direct API deployment", direct_api),
    ):
        if f"name: {env_name}" not in manifest or f"value: {state_path}" not in manifest:
            raise SystemExit(f"{manifest_name}: missing topology binding {env_name}={state_path}")

completion_gate = topology.get("completion_gate")
if not isinstance(completion_gate, dict) or not completion_gate:
    raise SystemExit("runtime-state topology must declare completion_gate")
if any(value is not False for value in completion_gate.values()):
    raise SystemExit(
        "#72 completion flags cannot be marked true while architecture_state is sqlite-single-writer"
    )

print(
    "Container/Kubernetes isolation and runtime-state topology verified "
    f"({len(discovered_sqlite_paths)} direct SQLite writer files inventoried)."
)
