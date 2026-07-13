from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Configuration — all values come from environment variables (WA_ prefix)."""

    # Neko Chrome CDP endpoint
    cdp_url: str = "http://172.32.0.3:9222"

    # API server
    host: str = "0.0.0.0"
    port: int = 8000

    # Sealed data directory
    data_dir: str = "/data"

    # dstack TEE mode
    dstack_enabled: bool = False
    dstack_socket: str = "/var/run/dstack.sock"

    # Encryption key (hex) — only used when dstack_enabled=False
    # If empty and not dstack, auto-generates and persists a key
    seal_key_hex: str = ""

    # Pipeline registry: comma-separated list of approved pipeline docker
    # image digests (sha256:...). Only these images can request data access.
    approved_pipelines: str = ""

    model_config = {"env_prefix": "WA_"}


settings = Settings()
