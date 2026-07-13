from __future__ import annotations

import argparse

import uvicorn

from .config import settings


def cli() -> None:
    parser = argparse.ArgumentParser(description="Props Room control plane")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Run the FastAPI server")
    serve.add_argument("--host", default=settings.host)
    serve.add_argument("--port", type=int, default=settings.port)
    serve.add_argument("--reload", action="store_true")

    args = parser.parse_args()

    if args.command == "serve":
        uvicorn.run(
            "props_room.api:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
        )


if __name__ == "__main__":
    cli()
