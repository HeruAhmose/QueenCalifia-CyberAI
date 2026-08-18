FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OQS_INSTALL_DIR=/opt/queen-califia/liboqs \
    LD_LIBRARY_PATH=/opt/queen-califia/liboqs/lib:/usr/local/lib \
    PYTHONPATH=/opt/queen-califia

ARG LIBOQS_VERSION=0.16.0
ARG LIBOQS_PYTHON_VERSION=0.16.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    cmake \
    git \
    libssl-dev \
    ninja-build \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/queen-califia
COPY backend/requirements.txt /tmp/requirements.txt

RUN python -m pip install --upgrade pip setuptools wheel \
    && git clone --depth=1 --branch "${LIBOQS_VERSION}" https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
    && test "$(git -C /tmp/liboqs describe --tags --exact-match)" = "${LIBOQS_VERSION}" \
    && git clone --depth=1 --branch "${LIBOQS_PYTHON_VERSION}" https://github.com/open-quantum-safe/liboqs-python /tmp/liboqs-python \
    && test "$(git -C /tmp/liboqs-python describe --tags --exact-match)" = "${LIBOQS_PYTHON_VERSION}" \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX="${OQS_INSTALL_DIR}" \
    && cmake --build /tmp/liboqs/build \
    && cmake --install /tmp/liboqs/build \
    && python -m pip install -r /tmp/requirements.txt \
    && python -m pip install /tmp/liboqs-python \
    && rm -rf /tmp/liboqs /tmp/liboqs-python

RUN groupadd --system --gid 10001 queencalifia \
    && useradd --system --uid 10001 --gid 10001 --home-dir /opt/queen-califia --shell /usr/sbin/nologin queencalifia

COPY --chown=10001:10001 . /opt/queen-califia
RUN mkdir -p /var/lib/queen-califia \
    && chown -R 10001:10001 /var/lib/queen-califia "${OQS_INSTALL_DIR}" \
    && chmod 0755 /opt/queen-califia/scripts/edge/container-entrypoint.sh

WORKDIR /opt/queen-califia/backend
USER 10001:10001

ENTRYPOINT ["/opt/queen-califia/scripts/edge/container-entrypoint.sh"]
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "2", "--timeout", "180", "--keep-alive", "30", "--graceful-timeout", "30"]
