ARG SOURCE_DATE_EPOCH=1735689600

FROM python:3.12.13-slim-trixie@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf AS builder

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    UV_PROJECT_ENVIRONMENT=/.venv \
    UV_COMPILE_BYTECODE=0 \
    UV_LINK_MODE=copy

COPY --from=ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY tinker_delegate/ tinker_delegate/
COPY scripts/fetch_pinned_qwen3_tokenizer.py scripts/

# Install only lockfile-selected artifacts, make the local project a real wheel
# rather than an editable source reference, and canonicalize every venv mtime.
RUN uv sync --frozen --no-dev --extra agent --no-editable && \
    /.venv/bin/python scripts/fetch_pinned_qwen3_tokenizer.py \
      --output /opt/dnai/qwen3-8b-tokenizer \
      --source-date-epoch "${SOURCE_DATE_EPOCH}" && \
    find /.venv -path '*/site-packages/*.dist-info/uv_cache.json' -delete && \
    find /.venv -path '*/site-packages/*.dist-info/RECORD' \
      -exec sed -i '\|uv_cache.json,|d' '{}' + && \
    find /.venv -type d -name __pycache__ -prune -exec rm -rf '{}' + && \
    chmod -R a-w /.venv && \
    tar --sort=name --format=gnu --mtime="@${SOURCE_DATE_EPOCH}" \
      --owner=0 --group=0 --numeric-owner -cf /tmp/venv.tar -C / .venv && \
    rm -rf /.venv /root/.cache && \
    tar -xf /tmp/venv.tar -C / && \
    rm /tmp/venv.tar

FROM python:3.12.13-slim-trixie@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf AS runtime

ARG SOURCE_DATE_EPOCH
ENV PATH="/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0

# The base image records 20260623 as its Debian snapshot. Replacing the live
# mirrors with that immutable archive fixes curl and every transitive .deb.
RUN set -eux; \
    sed -ri \
      's|^URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/20260623T000000Z|; s|^URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/20260623T000000Z|' \
      /etc/apt/sources.list.d/debian.sources; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      curl=8.14.1-2+deb13u3; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/cache/ldconfig/* /var/log/apt/*; \
    rm -f /var/log/dpkg.log

COPY --from=builder /.venv /.venv
COPY --from=builder /opt/dnai/qwen3-8b-tokenizer /opt/dnai/qwen3-8b-tokenizer

WORKDIR /app

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8080

CMD ["tinker-delegate", "serve", "--port", "8080"]
