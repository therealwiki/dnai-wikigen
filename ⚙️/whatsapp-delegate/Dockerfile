FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml .
COPY whatsapp_delegate/ whatsapp_delegate/

RUN uv venv /app/.venv && \
    . /app/.venv/bin/activate && \
    uv pip install "."

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

RUN mkdir -p /data

EXPOSE 8000

CMD ["python", "-m", "whatsapp_delegate.main", "serve"]
