FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OQS_INSTALL_DIR=/opt/render/project/.render/liboqs \
    LD_LIBRARY_PATH=/opt/render/project/.render/liboqs/lib:/usr/local/lib

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

WORKDIR /opt/render/project/src

# Celery worker runs with cwd=backend; celery_app.py and tasks.py live at repo root.
ENV PYTHONPATH=/opt/render/project/src

COPY backend/requirements.txt /tmp/requirements.txt

RUN python -m pip install --upgrade pip setuptools wheel
RUN git clone --depth=1 --branch "${LIBOQS_VERSION}" https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
    && test "$(git -C /tmp/liboqs describe --tags --exact-match)" = "${LIBOQS_VERSION}" \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX="${OQS_INSTALL_DIR}" \
    && cmake --build /tmp/liboqs/build \
    && cmake --install /tmp/liboqs/build \
    && python -m pip install -r /tmp/requirements.txt \
    && python -m pip install "liboqs-python==${LIBOQS_PYTHON_VERSION}" \
    && rm -rf /tmp/liboqs

RUN groupadd --system --gid 10001 queencalifia \
    && useradd --system --uid 10001 --gid 10001 --home-dir /opt/render/project/src --shell /usr/sbin/nologin queencalifia

COPY --chown=10001:10001 . /opt/render/project/src
RUN mkdir -p /opt/render/project/src/backend/data \
    && chown -R 10001:10001 /opt/render/project/src/backend/data "${OQS_INSTALL_DIR}"

WORKDIR /opt/render/project/src/backend
USER 10001:10001

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:10000", "--workers", "2", "--threads", "4", "--timeout", "180", "--keep-alive", "30", "--graceful-timeout", "30"]
