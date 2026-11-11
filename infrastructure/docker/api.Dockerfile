# syntax=docker/dockerfile:1.7
#
# SentinelX API + worker image (same image, different command).
# Build context: repository root.
#
#   docker build -f infrastructure/docker/api.Dockerfile -t sentinelx/api .

ARG PYTHON_IMAGE=python:3.12.16-slim-trixie
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.7

FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------------------
# Builder: resolve the locked dependency set into an isolated virtualenv.
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder

COPY --from=uv /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /src

# Dependency layer (cached until the lockfile changes).
COPY pyproject.toml uv.lock .python-version ./
COPY apps/api/pyproject.toml apps/api/pyproject.toml
COPY workers/pyproject.toml workers/pyproject.toml
COPY security-engine/pyproject.toml security-engine/pyproject.toml
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --all-packages --no-install-workspace

# Application layer.
COPY apps/api apps/api
COPY workers workers
COPY security-engine security-engine
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --all-packages --no-editable

# ---------------------------------------------------------------------------
# Runtime: minimal, non-root, no build tooling.
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="sentinelx-api" \
      org.opencontainers.image.description="SentinelX API and background workers" \
      org.opencontainers.image.licenses="MIT"

RUN groupadd --system --gid 10001 sentinelx \
 && useradd --system --uid 10001 --gid sentinelx --no-create-home --shell /usr/sbin/nologin sentinelx

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
# Alembic configuration and migration scripts (used by the `migrate` service).
COPY --chown=root:root apps/api/alembic.ini ./alembic.ini
COPY --chown=root:root apps/api/migrations ./migrations

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random

USER 10001:10001
EXPOSE 8000

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
