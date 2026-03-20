FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OQS_INSTALL_DIR=/opt/render/project/.render/liboqs \
    LD_LIBRARY_PATH=/opt/render/project/.render/liboqs/lib:/usr/local/lib

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

COPY backend/requirements.txt /tmp/requirements.txt

RUN python -m pip install --upgrade pip setuptools wheel
RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX="${OQS_INSTALL_DIR}" \
    && cmake --build /tmp/liboqs/build \
    && cmake --install /tmp/liboqs/build \
    && python -m pip install -r /tmp/requirements.txt \
    && python -m pip install liboqs-python \
    && rm -rf /tmp/liboqs

COPY . /opt/render/project/src

WORKDIR /opt/render/project/src/backend

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:10000", "--workers", "2", "--threads", "4", "--timeout", "120"]
