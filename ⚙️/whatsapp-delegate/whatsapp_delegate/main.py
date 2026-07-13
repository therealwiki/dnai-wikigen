"""WhatsApp Delegate — CLI + API server entry point.

CLI usage:
    python -m whatsapp_delegate.main serve
    python -m whatsapp_delegate.main screenshot

API usage:
    curl http://localhost:8000/health
    curl -X POST http://localhost:8000/login -H 'Content-Type: application/json' \
         -d '{"phone_number": "+1234567890"}'
"""

from __future__ import annotations

import asyncio
import sys

import uvicorn

from .api import app
from .automation import take_screenshot
from .config import settings


def cli():
    if len(sys.argv) < 2:
        print("Usage: python -m whatsapp_delegate.main <command>")
        print("Commands: serve, screenshot")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "serve":
        uvicorn.run(app, host=settings.host, port=settings.port)
    elif cmd == "screenshot":
        path = asyncio.run(take_screenshot())
        print(f"Screenshot saved: {path}")
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    cli()
