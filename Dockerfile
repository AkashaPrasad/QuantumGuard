# syntax=docker/dockerfile:1.7
# Base-image digests are synchronized with scripts/images.lock.

FROM docker.io/library/node:22-bookworm-slim@sha256:be979e5523c76fa4d5ca4ebd3099078f220aa47ec39c48ad5b5df9314debd6eb AS web-build
WORKDIR /build
RUN corepack enable && corepack prepare pnpm@10.11.0 --activate
COPY web/package.json web/pnpm-lock.yaml ./web/
RUN pnpm --dir web install --frozen-lockfile
COPY web/ ./web/
RUN pnpm --dir web run build

FROM ghcr.io/astral-sh/uv:0.9.13@sha256:f07d1bf7b1fb4b983eed2b31320e25a2a76625bdf83d5ff0208fe105d4d8d2f5 AS uv
FROM docker.io/library/python:3.12-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64 AS python-build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/ ./
RUN uv sync --frozen --no-dev --no-editable

FROM docker.io/library/python:3.12-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64 AS python-tools
COPY --from=uv /uv /usr/local/bin/uv
RUN pip install --no-cache-dir bandit==1.8.3 pip-audit==2.9.0
WORKDIR /src

FROM docker.io/library/python:3.12-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64 AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PATH=/app/backend/.venv/bin:/usr/local/bin \
    QG_DATA_DIR=/var/lib/quantumguard/data \
    QG_KEYS_DIR=/var/lib/quantumguard/keys \
    QG_PORT=8080 QG_WEB_DIST=/app/web/dist QG_DEMO=0
WORKDIR /app/backend
COPY --from=python-build /app/backend/.venv /app/backend/.venv
COPY --from=web-build /build/web/dist /app/web/dist
COPY scripts/container-entrypoint.py /app/entrypoint.py
COPY scripts/harden-runtime.py /build/harden-runtime.py
RUN ["/usr/local/bin/python3", "/build/harden-runtime.py"]
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/python3", "-c", "import json,os,urllib.request; r=urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('QG_PORT','8080')+'/healthz',timeout=2); assert r.status == 200 and json.load(r) == {'status':'ok'}"]
ENTRYPOINT ["/app/backend/.venv/bin/python", "/app/entrypoint.py"]
