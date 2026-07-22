"""Local entrypoint; production uses the same Uvicorn application factory."""

from __future__ import annotations

import uvicorn


def main() -> None:
    uvicorn.run(
        "attestation_qvl.service:create_production_app",
        factory=True,
        host="0.0.0.0",
        port=8443,
        workers=1,
        access_log=False,
        server_header=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
