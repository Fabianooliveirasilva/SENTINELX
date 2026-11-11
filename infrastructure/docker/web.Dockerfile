# syntax=docker/dockerfile:1.7
#
# SentinelX web frontend: static build served by unprivileged Nginx, which also
# reverse-proxies /api to the API service (same-origin, no CORS required).
# Build context: repository root.

ARG NODE_IMAGE=node:24.22.2-alpine3.24
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.31.7-alpine3.24

FROM ${NODE_IMAGE} AS build

ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    CI=true
RUN npm install --global --no-fund --no-audit pnpm@10.20.0

WORKDIR /web
COPY apps/web/package.json apps/web/pnpm-lock.yaml ./
RUN --mount=type=cache,target=/pnpm/store \
    pnpm config set store-dir /pnpm/store \
 && pnpm install --frozen-lockfile

COPY apps/web/ ./
RUN pnpm build

FROM ${NGINX_IMAGE} AS runtime

LABEL org.opencontainers.image.title="sentinelx-web" \
      org.opencontainers.image.licenses="MIT"

COPY infrastructure/docker/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY infrastructure/docker/nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --from=build /web/dist /usr/share/nginx/html

EXPOSE 8080
