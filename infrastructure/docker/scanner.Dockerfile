# syntax=docker/dockerfile:1.7
#
# SentinelX scanner sandbox: consumes only the `scans` queue and runs the
# scanner adapters (DNS, CT, TLS, HTTP, Nmap TCP-connect profiles).
# Build context: repository root.
#
#   docker build -f infrastructure/docker/scanner.Dockerfile -t sentinelx/scanner .
#
# Isolation (see docs/SCANNING_POLICY.md §7): non-root, no Linux capabilities
# (Nmap uses unprivileged TCP connect scans), read-only root filesystem, no
# database credentials or signing secrets, CPU/memory/PID limits set in compose.

ARG PYTHON_IMAGE=python:3.12.16-slim-trixie
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.7

FROM ${UV_IMAGE} AS uv

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

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random

WORKDIR /tmp
USER 10002:10002

CMD ["celery", "-A", "sentinelx_workers.scanner_app:scanner_app", "worker", "-Q", "scans", "--loglevel=INFO", "--concurrency=2", "--without-gossip", "--without-mingle"]
