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
    'git clone --depth=1 --branch "${LIBOQS_VERSION}"',
    'liboqs-python==${LIBOQS_PYTHON_VERSION}',
    "USER 10001:10001",
)
reject(
    "backend/Dockerfile",
    "git clone --depth=1 https://github.com/open-quantum-safe/liboqs",
    "python -m pip install liboqs-python\n",
)

for path in (
    "helm/queen-califia/templates/api-deployment.yaml",
    "helm/queen-califia/templates/worker-deployment.yaml",
    "helm/queen-califia/templates/frontend-deployment.yaml",
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
    "type: RuntimeDefault",
    "allowPrivilegeEscalation: false",
    'drop: ["ALL"]',
)

print("Container and Kubernetes runtime-isolation invariants verified.")
