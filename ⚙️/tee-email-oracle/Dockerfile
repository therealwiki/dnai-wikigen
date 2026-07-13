FROM python:3.12.13-slim-trixie@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf

# System deps for Tesseract (captcha fallback) + playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa /uv /usr/local/bin/uv

WORKDIR /app

# Copy project files
COPY pyproject.toml uv.lock ./
COPY captcha-solver/ captcha-solver/
COPY email_oracle/ email_oracle/

# Install dependencies (non-editable for Docker)
RUN uv venv /app/.venv && \
    uv sync --frozen --no-dev && \
    rm -rf /root/.cache /tmp/*

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Data volume for encrypted credentials
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

# Default: serve (auto-genesis if no creds)
CMD ["email-oracle", "serve"]
