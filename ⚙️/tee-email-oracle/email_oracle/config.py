"""Configuration from environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # --- Credential store ---
    # Local PoC: AES key from env or local sidecar file.
    # In dstack: derived deterministically from the enclave identity.
    cred_store_path: str = "/data/credentials.enc"
    cred_store_key: str = ""  # 32-byte hex key; auto-generated if empty

    # --- cock.li registration ---
    auto_genesis: bool = True
    cockli_register_url: str = "https://cock.li/register.php"
    cockli_domain: str = "cock.email"
    cockli_imap_host: str = "mail.cock.li"
    cockli_imap_port: int = 993

    # --- Neko / CDP browser fallback ---
    cdp_url: str = "http://neko:9222"
    use_browser_fallback: bool = False

    # --- API ---
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    runtime_auth_required: bool = False
    runtime_auth_token: str = ""
    runtime_auth_key_path: str = "oracle/runtime-auth"
    allow_credential_provisioning_endpoint: bool = False
    credential_provisioning_token: str = ""
    auth_required: bool = False
    auth_contract_address: str = ""
    auth_rpc_url: str = ""
    auth_consumer_app_id: str = ""
    auth_consumer_compose_hash: str = ""
    auth_expected_caller_identity: str = ""
    pin_max_length: int = 16
    otp_replay_store_path: str = "/data/otp_replay.enc"
    otp_replay_store_key: str = ""
    otp_replay_key_path: str = "email/otp_replay"

    # --- dstack (no-op locally, used in TEE) ---
    dstack_socket: str = "/var/run/dstack.sock"
    dstack_enabled: bool = False
    dstack_key_path: str = "email/creds"

    # --- IMAP polling ---
    imap_poll_interval: int = 5  # seconds
    imap_idle_timeout: int = 300  # seconds

    model_config = {"env_prefix": "ORACLE_"}
