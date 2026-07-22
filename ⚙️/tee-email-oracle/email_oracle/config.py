"""Configuration from environment variables."""

import re
from urllib.parse import urlsplit

from pydantic import model_validator
from pydantic_settings import BaseSettings


_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BYTES32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
_BASE_SEPOLIA_CHAIN_ID = 84_532
_CANONICAL_CALLER_IDENTITY = "tinker-delegate.signup"
_PRODUCTION_CRED_STORE_PATH = "/data/credentials.enc"
_PRODUCTION_REPLAY_STORE_PATH = "/data/otp_replay.enc"
_PRODUCTION_CHECKPOINT_STORE_PATH = "/data/email_auth_checkpoint.json"
_PRODUCTION_DSTACK_KEY_PATH = "email/creds"
_PRODUCTION_RUNTIME_KEY_PATH = "oracle/runtime-auth"
_PRODUCTION_REPLAY_KEY_PATH = "email/otp_replay"


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
    production_release: bool = False
    runtime_auth_required: bool = False
    runtime_auth_token: str = ""
    runtime_auth_key_path: str = "oracle/runtime-auth"
    allow_credential_provisioning_endpoint: bool = False
    credential_provisioning_token: str = ""
    auth_required: bool = False
    auth_contract_address: str = ""
    auth_rpc_url: str = ""
    auth_rpc_url_secondary: str = ""
    auth_chain_id: int = _BASE_SEPOLIA_CHAIN_ID
    auth_contract_runtime_code_hash: str = ""
    auth_consumer_app_id: str = ""
    auth_consumer_compose_hash: str = ""
    auth_expected_caller_identity: str = ""
    auth_max_finalized_block_age_seconds: int = 900
    auth_max_future_block_skew_seconds: int = 30
    auth_checkpoint_store_path: str = _PRODUCTION_CHECKPOINT_STORE_PATH
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

    @model_validator(mode="after")
    def require_production_consumer_policy(self) -> "Settings":
        """Make production mode an explicit fail-closed configuration contract.

        Local development remains opt-in so simulator/unit-test workflows can
        run without Base RPC access. A release descriptor must set
        ``ORACLE_PRODUCTION_RELEASE=true``; that single switch then makes both
        the same-CVM bearer and the on-chain EmailOracleAuth policy mandatory.
        """

        if not self.production_release:
            return self
        if not self.dstack_enabled:
            raise ValueError("production release requires dstack")
        if not self.runtime_auth_required:
            raise ValueError("production release requires runtime bearer auth")
        if self.runtime_auth_token:
            raise ValueError("production release must derive runtime auth inside dstack")
        if self.runtime_auth_key_path != _PRODUCTION_RUNTIME_KEY_PATH:
            raise ValueError("production release requires the exact runtime auth key path")
        if not self.auth_required:
            raise ValueError("production release requires EmailOracleAuth policy")
        if not _ADDRESS.fullmatch(self.auth_contract_address) or int(
            self.auth_contract_address, 16
        ) == 0:
            raise ValueError("production release requires a nonzero EmailOracleAuth address")
        primary_rpc_host = _https_rpc_host(self.auth_rpc_url, field="primary")
        secondary_rpc_host = _https_rpc_host(
            self.auth_rpc_url_secondary,
            field="secondary",
        )
        if primary_rpc_host == secondary_rpc_host:
            raise ValueError("production release requires two independent RPC hosts")
        if self.auth_chain_id != _BASE_SEPOLIA_CHAIN_ID:
            raise ValueError("production release requires Base Sepolia chain id 84532")
        if not _BYTES32.fullmatch(self.auth_contract_runtime_code_hash) or int(
            self.auth_contract_runtime_code_hash, 16
        ) == 0:
            raise ValueError("production release requires the EmailOracleAuth runtime code hash")
        if not _ADDRESS.fullmatch(self.auth_consumer_app_id) or int(
            self.auth_consumer_app_id, 16
        ) == 0:
            raise ValueError("production release requires a nonzero consumer app id")
        if not _BYTES32.fullmatch(self.auth_consumer_compose_hash) or int(
            self.auth_consumer_compose_hash, 16
        ) == 0:
            raise ValueError("production release requires a nonzero consumer compose hash")
        if self.auth_expected_caller_identity != _CANONICAL_CALLER_IDENTITY:
            raise ValueError("production release must bind the signup caller identity")
        if not 1 <= self.auth_max_finalized_block_age_seconds <= 900:
            raise ValueError("production finalized block age must be between 1 and 900 seconds")
        if not 0 <= self.auth_max_future_block_skew_seconds <= 60:
            raise ValueError("production future block skew must be between 0 and 60 seconds")
        if self.auth_checkpoint_store_path != _PRODUCTION_CHECKPOINT_STORE_PATH:
            raise ValueError("production release requires the exact durable checkpoint path")
        if self.allow_credential_provisioning_endpoint:
            raise ValueError("production release forbids credential provisioning")
        if self.credential_provisioning_token:
            raise ValueError("production release forbids a credential provisioning token")
        if self.auto_genesis:
            raise ValueError("production release forbids automatic credential genesis")
        if self.cred_store_path != _PRODUCTION_CRED_STORE_PATH:
            raise ValueError("production release requires the exact credential store path")
        if self.cred_store_key:
            raise ValueError("production release forbids a static credential store key")
        if self.dstack_key_path != _PRODUCTION_DSTACK_KEY_PATH:
            raise ValueError("production release requires the exact credential key path")
        if self.otp_replay_store_path != _PRODUCTION_REPLAY_STORE_PATH:
            raise ValueError("production release requires the exact OTP replay store path")
        if self.otp_replay_store_key:
            raise ValueError("production release forbids a static OTP replay key")
        if self.otp_replay_key_path != _PRODUCTION_REPLAY_KEY_PATH:
            raise ValueError("production release requires the exact OTP replay key path")
        return self

    # RPC URLs frequently carry provider credentials in their path. Never let
    # Pydantic echo the complete environment/input mapping in startup errors.
    model_config = {"env_prefix": "ORACLE_", "hide_input_in_errors": True}


def _https_rpc_host(value: str, *, field: str) -> str:
    """Return a normalized RPC host without ever including its URL in errors."""

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError(f"production release {field} RPC URL is invalid") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(f"production release requires an HTTPS {field} RPC URL")
    return f"{parsed.hostname.lower()}:{port or 443}"
