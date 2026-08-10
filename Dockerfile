# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Multi-stage build.
#
# Stage 1 compiles wheels (needs a toolchain); stage 2 ships only the runtime.
# The result is ~400 MB smaller than a single-stage build and, more importantly,
# contains no compiler — an attacker who gets code execution has nothing to
# build with.
#
# Security choices:
#   * runs as a non-root user with no shell
#   * no package manager caches, no build tools in the final image
#   * a read-only root filesystem is supported (writable volumes are declared)
#   * HEALTHCHECK targets /health/live, which touches no dependency
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md ./
COPY app ./app

# Build a wheel and resolve dependencies into /wheels so the runtime stage can
# install without a network or a compiler.
RUN python -m pip install --upgrade pip build \
    && python -m build --wheel --outdir /wheels \
    && python -m pip wheel --wheel-dir /wheels ".[postgres,api]"

# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    LOGA_STORAGE__DATA_ROOT=/data \
    LOGA_API__HOST=0.0.0.0 \
    LOGA_OBSERVABILITY__FORMAT=json

# libpq is needed by psycopg2 at runtime; curl is the healthcheck client.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 loga \
    && useradd --system --uid 10001 --gid loga --no-create-home --shell /usr/sbin/nologin loga

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels \
        big-data-log-analytics psycopg2-binary httpx \
    && rm -rf /wheels

WORKDIR /app
COPY configs ./configs

# Writable locations, kept explicit so the root filesystem can be mounted
# read-only in production.
RUN mkdir -p /data /var/log/loganalytics \
    && chown -R loga:loga /data /var/log/loganalytics /app
VOLUME ["/data"]

USER loga
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health/live || exit 1

ENTRYPOINT ["loganalytics"]
CMD ["serve"]
