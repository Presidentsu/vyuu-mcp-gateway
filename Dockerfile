################################################################################
# Vyuu MCP Gateway — production image.
#
# Multi-stage build: a builder layer compiles wheels, the runtime layer
# carries only what's needed to run.
#
# Notes:
# - Non-root user (`vyuu`) — gateway never needs root at runtime.
# - No `--reload` (dev pattern was leaving a watcher process alive in
#   prod images that wrapped this with `docker run`).
# - Healthcheck targets `/healthz` (added in Tier-1 stress-test fix);
#   liveness probes never queue behind tool calls.
# - uvicorn back-pressure flags (`--limit-concurrency`,
#   `--limit-max-requests`, `--backlog`, `--timeout-keep-alive`) are
#   driven by `Settings.inbound_*` env vars, NOT hardcoded here, so a
#   single image runs Starter / Standard / Production tiers via env.
################################################################################

# --- Builder stage -----------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Build deps for any wheels that need compilation. `psycopg[binary]`
# ships pre-built wheels for common platforms but pip falls back to
# building from source on uncommon arches; the build deps cover that.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY pyproject.toml README.md ./
COPY src ./src

# Install into a vendor prefix so the runtime stage can copy a
# self-contained tree without pulling pip's metadata.
RUN pip install --prefix=/install .


# --- Runtime stage -----------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PATH="/install/bin:${PATH}"

# Non-root runtime user. UID 10001 is conventional for K8s
# `runAsNonRoot` SecurityContext checks.
RUN groupadd --system --gid 10001 vyuu \
 && useradd --system --uid 10001 --gid vyuu --create-home --shell /sbin/nologin vyuu

# Runtime libs only — psql client + ca-certs + curl for healthchecks.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libpq5 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the prebuilt site-packages tree from the builder stage.
COPY --from=builder /install /install
COPY --chown=vyuu:vyuu src ./src

USER vyuu

EXPOSE 8000

# Liveness probe targets `/healthz` (mounted at app root, bypasses
# the per-tenant inflight gate so it stays green under burst).
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD curl --fail --silent --max-time 2 http://127.0.0.1:8000/healthz || exit 1

# Default command — single worker, production back-pressure flags.
# Override via `command:` in compose / `args:` in K8s for tier-tuned
# values (e.g. Production tier wants 4-12 workers and matching limits).
CMD ["uvicorn", \
     "vyuu_gateway.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--limit-concurrency", "200", \
     "--limit-max-requests", "10000", \
     "--backlog", "128", \
     "--timeout-keep-alive", "5", \
     "--no-access-log"]
