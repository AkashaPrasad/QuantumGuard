# syntax=docker/dockerfile:1.7
# Base-image digests are synchronized with scripts/images.lock.

FROM docker.io/library/node:22-bookworm-slim@sha256:be979e5523c76fa4d5ca4ebd3099078f220aa47ec39c48ad5b5df9314debd6eb AS web-build
WORKDIR /build/web
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
# Corepack reads the exact packageManager from web/package.json.
RUN corepack enable && corepack install
RUN pnpm install --frozen-lockfile
COPY web/ ./
# BuildKit mounts let optional bench/ be absent without a failing COPY wildcard.
RUN --mount=type=bind,source=.,target=/source \
    for directory in spec bench; do \
        if [ -d "/source/$directory" ]; then cp -R "/source/$directory" "/build/$directory"; fi; \
    done
RUN pnpm run build

FROM ghcr.io/astral-sh/uv:0.9.13@sha256:f07d1bf7b1fb4b983eed2b31320e25a2a76625bdf83d5ff0208fe105d4d8d2f5 AS uv
FROM docker.io/library/python:3.12-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64 AS python-build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/ /app/backend/
COPY cli/ /app/cli/
COPY scripts/package-runtime.py /build/package-runtime.py
RUN python /build/package-runtime.py /app /build/runtime-package \
    && uv build --wheel --out-dir /build/wheels /build/runtime-package \
    && uv pip install --python /app/backend/.venv/bin/python --no-deps /build/wheels/*.whl \
    && /app/backend/.venv/bin/python -c "from importlib.metadata import distribution; files={str(p) for p in distribution('quantumguard').files}; assert {'qg/app.py','qg/admin.py'} <= files; assert any(p.startswith('qg/client') and p.endswith('.py') for p in files)"

FROM docker.io/library/python:3.12-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64 AS test
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 PATH=/app/backend/.venv/bin:/usr/local/bin \
    PYTHONPATH=/app/backend:/app/cli QG_DATA_DIR=/tmp/qg/data QG_KEYS_DIR=/tmp/qg/keys \
    HYPOTHESIS_STORAGE_DIRECTORY=/tmp/hypothesis
WORKDIR /app
COPY backend/pyproject.toml backend/uv.lock ./backend/
RUN uv sync --project backend --frozen --no-install-project
COPY backend/ ./backend/
COPY cli/ ./cli/
COPY tests/ ./tests/
COPY scenarios/ ./scenarios/
COPY spec/ ./spec/
COPY scripts/ ./scripts/
RUN python -c "import os; os.mkdir('/results'); os.chown('/results', 10001, 10001); os.chmod('/results', 0o700)"
USER 10001:10001
ENTRYPOINT ["/app/backend/.venv/bin/python", "/app/scripts/container-tests.py"]

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
