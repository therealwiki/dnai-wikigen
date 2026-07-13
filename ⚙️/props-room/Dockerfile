FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY props_room ./props_room

RUN uv sync --no-dev

CMD ["uv", "run", "python", "-m", "props_room.main", "serve", "--port", "8300"]
