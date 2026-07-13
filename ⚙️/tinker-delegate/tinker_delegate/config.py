"""Configuration for tinker-delegate automation."""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "TINKER_"}

    # Remote Playwright browser server
    browser_ws_endpoint: str = ""
    browser_timeout: float = 180.0
    browser_poll_interval: float = 2.0
    browser_connect_timeout: float = 20.0

    # CDP browser
    cdp_url: str = "http://localhost:9222"
    cdp_timeout: float = 180.0
    cdp_poll_interval: float = 2.0
    cdp_connect_timeout: float = 20.0
    local_browser_fallback: bool = True
    local_browser_headless: bool = True
    local_browser_launch_timeout: float = 60.0

    # Email oracle
    oracle_url: str = "http://localhost:8000"
    oracle_auth_token: str = ""
    oracle_auth_key_path: str = "oracle/runtime-auth"
    runtime_auth_required: bool = False
    runtime_auth_token: str = ""
    runtime_auth_key_path: str = "tinker/runtime-auth"

    # Tinker auth
    tinker_console_url: str = "https://tinker-console.thinkingmachines.ai"
    project_id: str = ""
    base_url: str = ""

    # Account details (auto-fetched from oracle if not set)
    email: str = ""
    first_name: str = "Tinker"
    last_name: str = "Delegate"

    # Timing
    otp_poll_interval: float = 3.0  # seconds between OTP polls
    otp_poll_timeout: float = 120.0  # max seconds to wait for OTP
    otp_max_age: int = 300  # max age of OTP email in seconds

    # API key bootstrap / storage
    api_key_store_path: str = "./data/tinker_api_key.enc"
    api_key_store_key: str = ""
    dstack_key_path: str = "tinker/api_key"
    client_config_store_path: str = "./data/tinker_client_config.enc"
    client_config_store_key: str = ""
    client_config_key_path: str = "tinker/client_config"
    funding_receipt_store_path: str = "./data/funding_receipts.enc"
    funding_receipt_store_key: str = ""
    funding_receipt_key_path: str = "tinker/funding_receipts"
    browser_session_store_path: str = "./data/browser_session.enc"
    browser_session_store_key: str = ""
    browser_session_key_path: str = "tinker/browser_session"
    run_metadata_store_path: str = "./data/run_metadata.enc"
    run_metadata_store_key: str = ""

    # Sealed-retention store for retained (time-boxed/archived) artifacts. Empty
    # path = no store, so resolution always destroys (safe default). Set a path to
    # enable persisted retention under the sealed data volume.
    retention_store_path: str = ""
    retention_store_key: str = ""
    retention_dstack_key_path: str = "tinker/sealed_retention"
    retention_mode: str = "immediate"          # immediate | time_boxed | post_settlement_archive
    retention_seconds: int = 0
    retention_archive_key_ref: str = ""

    # Source-controller grants (JSON) gating TEE-held source-account use. Empty =
    # no gate (source access ungated). Set to a sealed-volume path to enforce.
    source_grants_path: str = ""
    # Bounded human-review queue (JSON) for held bio/dual-use items. Empty =
    # no persisted queue (the review API endpoints report empty / are inert).
    review_queue_path: str = ""
    run_metadata_key_path: str = "tinker/run_metadata"
    chain_rpc_url: str = ""
    chain_contract_address: str = ""
    chain_control_plane_url: str = "http://localhost:8080"
    chain_start_block: str = ""
    chain_poll_interval: float = 5.0
    chain_confirmations: int = 2
    chain_cursor_store_path: str = "./data/chain_watcher_cursor.json"
    chain_signer_key_path: str = "tinker/chain_signer"
    chain_result_verifier_key_path: str = "tinker/chain_result_verifier"
    chain_result_authorization_ttl_seconds: int = 300
    chain_submit_gas_limit: int = 0
    encumbrance_contract_address: str = ""
    encumbrance_rpc_url: str = ""
    encumbrance_required: bool = False
    encumbrance_compose_hash: str = ""
    encumbrance_policy_units_per_usd_wei: int = 10**18
    bootstrap_signup: bool = False
    bootstrap_fail_open: bool = False
    bootstrap_oracle_timeout: float = 300.0
    bootstrap_oracle_poll_interval: float = 5.0
    allow_auth_automation_endpoint: bool = False
    allow_key_management_endpoint: bool = False
    allow_tinker_train_endpoint: bool = False
    allow_selector_probe_endpoint: bool = False
    allow_browser_readiness_endpoint: bool = False
    debug_screenshots: bool = False
    debug_artifact_dir: str = ""
    purge_secret_debug_artifacts: bool = True
    allow_plaintext_card_endpoint: bool = False
    allow_plaintext_artifact_endpoint: bool = False
    allow_add_balance_endpoint: bool = False
    funding_mode: str = "manual_prefund"
    min_add_balance_usd: float = 10.0
    max_add_balance_usd: float = 10.0

    # Paid Tinker SDK smoke tests. Disabled by default; enable only for a
    # funded, attested operator-validation CVM or explicit local test context.
    allow_tinker_proxy_endpoint: bool = False
    allow_tinker_proxy_token_issuance: bool = False
    proxy_jwt_key: str = ""
    proxy_jwt_key_path: str = "tinker/proxy_jwt"
    proxy_jwt_default_ttl_seconds: int = 900
    proxy_jwt_max_ttl_seconds: int = 3600
    proxy_jwt_issuer: str = "dnai-wikigen:tinker-proxy"
    proxy_jwt_audience: str = "dnai-wikigen:tinker-delegate"
    proxy_approved_subjects: str = ""
    proxy_require_issue_policy: bool = False
    proxy_issue_policy_path: str = ""
    proxy_require_deployment_policy: bool = False
    proxy_require_grant_lifecycle: bool = False
    proxy_require_grant_lifecycle_signature: bool = False
    proxy_require_identity_registry: bool = False
    proxy_identity_registry_path: str = ""
    proxy_require_identity_registry_signature: bool = False
    proxy_identity_registry_signer: str = ""
    proxy_token_store_path: str = "./data/proxy_tokens.enc"
    proxy_token_store_key: str = ""
    proxy_token_key_path: str = "tinker/proxy_tokens"
    allow_tinker_smoke_endpoint: bool = False
    real_sdk_max_usd: float = 0.05
    real_sdk_model: str = "Qwen/Qwen3-8B"
    real_sdk_rank: int = 32
    # Default spend cap for a bounded delegated `tinker:train` run (hard-capped
    # at HARD_TRAIN_MAX_USD in tinker_training).
    train_max_usd: float = 0.25
    # Wall-clock cap on the first authenticated Tinker SDK calls (ServiceClient
    # connect, create_training) so a blocked/unactivated account fails fast with a
    # bounded transient_timeout verdict instead of hanging on SDK retries.
    smoke_connect_timeout: float = 45.0
