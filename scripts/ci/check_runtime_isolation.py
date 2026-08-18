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

print("Container and Kubernetes runtime-isolation invariants verified.")
