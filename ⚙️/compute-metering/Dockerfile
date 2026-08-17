ARG SOURCE_DATE_EPOCH=1735689600

FROM python:3.12.13-slim-trixie@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf AS builder

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    UV_PROJECT_ENVIRONMENT=/.venv \
    UV_COMPILE_BYTECODE=0 \
    UV_LINK_MODE=copy

COPY --from=ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable && \
    rm /.venv/lib/python3.12/site-packages/dnai_compute_metering-0.1.0.dist-info/uv_cache.json && \
    sed -i '\|uv_cache.json,|d' /.venv/lib/python3.12/site-packages/dnai_compute_metering-0.1.0.dist-info/RECORD && \
    find /.venv -type d -name __pycache__ -prune -exec rm -rf '{}' + && \
    chmod -R a-w /.venv && \
    tar --sort=name --format=gnu --mtime="@${SOURCE_DATE_EPOCH}" --owner=65532 --group=65532 --numeric-owner -cf /tmp/venv.tar -C / .venv && \
    rm -rf /.venv && \
    tar -xf /tmp/venv.tar -C / && \
    rm /tmp/venv.tar

FROM python:3.12.13-slim-trixie@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf AS runtime

ARG SOURCE_DATE_EPOCH
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0

COPY --from=builder --chown=65532:65532 /.venv /.venv

USER 65532:65532
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/.venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8443/health', timeout=2).read()"]

ENTRYPOINT ["/.venv/bin/uvicorn"]
CMD ["compute_metering.service:create_production_app", "--factory", "--host", "0.0.0.0", "--port", "8443", "--workers", "1", "--no-access-log", "--no-server-header", "--no-proxy-headers"]
