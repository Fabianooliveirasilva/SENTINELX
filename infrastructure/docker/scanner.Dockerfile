# syntax=docker/dockerfile:1.7
#
# SentinelX scanner sandbox: runs the scanner adapters (DNS, CT, TLS, HTTP,
# Nmap TCP-connect profiles, Nuclei with pinned templates, and the ZAP driver).
# The same image serves the `scanner` (queue `scans`) and `scanner-zap`
# (queue `scans.zap`) services.
# Build context: repository root.
#
#   docker build -f infrastructure/docker/scanner.Dockerfile -t sentinelx/scanner .
#
# Isolation (see docs/SCANNING_POLICY.md §7): non-root, no Linux capabilities
# (Nmap uses unprivileged TCP connect scans), read-only root filesystem, no
# database credentials or signing secrets, CPU/memory/PID limits set in compose.

ARG PYTHON_IMAGE=python:3.12.16-slim-trixie
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.7

ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_TEMPLATES_VERSION=10.5.1
ARG NUCLEI_TEMPLATES_SHA256=30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb

FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------------------
# Nuclei binary and template release, both verified against pinned SHA-256s.
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS nuclei
ARG NUCLEI_VERSION
ARG NUCLEI_SHA256
ARG NUCLEI_TEMPLATES_VERSION
ARG NUCLEI_TEMPLATES_SHA256
ADD --checksum=sha256:${NUCLEI_SHA256} \
    https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip \
    /tmp/nuclei.zip
ADD --checksum=sha256:${NUCLEI_TEMPLATES_SHA256} \
    https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz \
    /tmp/templates.tar.gz
RUN python -c "import zipfile; zipfile.ZipFile('/tmp/nuclei.zip').extract('nuclei', '/out')" \
 && chmod 0555 /out/nuclei \
 && mkdir -p /out/nuclei-templates \
 && tar -xzf /tmp/templates.tar.gz -C /out/nuclei-templates --strip-components=1 \
 && chmod -R a-w /out/nuclei-templates

FROM ${PYTHON_IMAGE} AS builder

COPY --from=uv /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /src

COPY pyproject.toml uv.lock .python-version ./
COPY apps/api/pyproject.toml apps/api/pyproject.toml
COPY workers/pyproject.toml workers/pyproject.toml
COPY security-engine/pyproject.toml security-engine/pyproject.toml
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --all-packages --no-install-workspace

COPY apps/api apps/api
COPY workers workers
COPY security-engine security-engine
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --all-packages --no-editable

FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="sentinelx-scanner" \
      org.opencontainers.image.description="SentinelX sandboxed scanner worker" \
      org.opencontainers.image.licenses="MIT"

# Nmap only; no compilers, shells beyond the base image, or NSE script updates.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10002 scanner \
 && useradd --system --uid 10002 --gid scanner --no-create-home --shell /usr/sbin/nologin scanner

COPY --from=builder /opt/venv /opt/venv
COPY --from=nuclei /out/nuclei /usr/local/bin/nuclei
COPY --from=nuclei /out/nuclei-templates /opt/nuclei-templates

ARG NUCLEI_VERSION
ARG NUCLEI_TEMPLATES_VERSION
ENV SENTINELX_NUCLEI_VERSION=${NUCLEI_VERSION} \
    SENTINELX_NUCLEI_TEMPLATES_VERSION=${NUCLEI_TEMPLATES_VERSION} \
    SENTINELX_NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates \
    PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random

WORKDIR /tmp
USER 10002:10002

CMD ["celery", "-A", "sentinelx_workers.scanner_app:scanner_app", "worker", "-Q", "scans", "--loglevel=INFO", "--concurrency=2", "--without-gossip", "--without-mingle"]
