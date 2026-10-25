# syntax=docker/dockerfile:1.7
# NsureGRC application image (Phase 1). Multi-stage, non-root, no build tools or package managers in the runtime layer.
#
# HONEST STATUS
#  * Base-image and uv versions are pinned by TAG. Pinning by immutable DIGEST must be done in CI by the image-build job
#    (digests cannot be verified offline); tracked in docs/DEPENDENCIES.md.
#  * `config.settings.prod` REFUSES to start until the production KMS key provider and audit signer/WORM sink exist
#    (open item O-4). That is intentional: this image cannot silently run with dev-only stand-ins.
#  * The image has not been built or scanned in the Phase 1 workstation (no container runtime available): see
#    docs/BLOCKED_TESTS.md. The CI workflow builds and scans it.

FROM ghcr.io/astral-sh/uv:0.11.6 AS uv

FROM python:3.12-slim-bookworm AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
# dependencies first (cache-friendly); --frozen refuses to deviate from uv.lock; dev group is never installed
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY manage.py ./
COPY config ./config
COPY ngrc ./ngrc
COPY db/table_classification.yaml ./db/table_classification.yaml

FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=random PATH="/app/.venv/bin:$PATH" \
    DJANGO_SETTINGS_MODULE=config.settings.prod NGRC_ENV=prod
# Patch tzdata (DLA-4854-1) and remove pip/setuptools/wheel entirely, not just upgrade: pip vendors frozen,
# pinned-for-life copies of msgpack/urllib3/setuptools inside itself (pip 26.2.2's own vendor.txt still pins
# msgpack==1.1.2, urllib3==2.7.0, setuptools==70.3.0 - CVE-2025-47273, CVE-2026-97687, CVE-2026-97689,
# GHSA-6v7p-g79w-8964, all HIGH), so upgrading pip's own version never clears these; only removing it does.
# The application never invokes any of this - uv built /app/.venv in the build stage - and the header comment
# above has always said "no build tools or package managers in the runtime layer"; this makes that true.
RUN apt-get update && apt-get install --no-install-recommends --only-upgrade -y tzdata=2026e-0+deb12u1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && python -m pip uninstall --yes pip setuptools wheel
# fixed unprivileged uid/gid, no login shell, no home directory contents
RUN groupadd --system --gid 10001 ngrc && useradd --system --uid 10001 --gid ngrc --no-create-home --shell /usr/sbin/nologin ngrc
WORKDIR /app
COPY --from=build --chown=root:root /app /app
USER 10001:10001
EXPOSE 8000
# No secrets are baked in: every credential/key comes from the environment injected by the orchestrator (see config/settings/base.py).
# Access log omits query strings (%(U)s is the path only). TLS terminates at the trusted proxy in front of this process.
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "4", "--worker-tmp-dir", "/dev/shm", \
     "--timeout", "30", "--graceful-timeout", "30", "--limit-request-line", "4094", "--limit-request-fields", "50", \
     "--limit-request-field_size", "8190", "--access-logfile", "-", \
     "--access-logformat", "%(h)s %(t)s \"%(m)s %(U)s\" %(s)s %(b)s %(L)s"]
