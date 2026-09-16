"""Configuration for tinker-delegate automation."""
import json
import re
import os
import stat
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings


_NONZERO_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_NONZERO_BYTES32 = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")
_NONZERO_ADDRESS = re.compile(r"^0x(?!0{40}$)[0-9a-f]{40}$")
PRODUCTION_DILIGENCE_EVALUATOR_MANIFEST_PATH = (
    "/sealed/diligence/diligence-evaluator-release-v1.json"
)


class Settings(BaseSettings):
    model_config = {"env_prefix": "TINKER_"}

    # Signed seven-CVM release lineage. Every independent-QVL challenge and
    # verdict carries this exact tuple; empty defaults disable those production
    # paths fail-closed until the release authority projector populates them.
    main_runtime_cvm_id: str = ""
    release_deployment_intent_sha256: str = ""
    release_authority_sha256: str = ""
    release_ceremony_nonce: str = ""
    diligence_qvl_measurement_policy_sha256: str = ""
    arena_qvl_measurement_policy_sha256: str = ""
    anchor_writer_qvl_measurement_policy_sha256: str = ""

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

    # Browser/API boundary. Origins are comma-separated exact origins; wildcard
    # values are rejected and credentialed CORS is never enabled.
    cors_allowed_origins: str = ""

    # Ethereum personal-sign authentication for seller artifact upload. The
    # explicit key is local-development only; dstack deployments derive the key
    # at wallet_auth_key_path inside the CVM.
    wallet_auth_signing_key: str = ""
    wallet_auth_key_path: str = "tinker/wallet_auth"
    wallet_auth_challenge_ttl_seconds: int = 300
    wallet_auth_token_ttl_seconds: int = 300
    wallet_auth_max_pending_challenges: int = 1024
    # One process-wide sliding-window admission gate is shared by Deal, Arena,
    # Compute, Collaboration, and Review challenge issuance. The 600-second
    # window covers every challenge TTL and the global limit must remain below
    # every configured nonce-store capacity. Forwarded client IPs are ignored
    # unless both an approved single-IP header and exact direct-proxy CIDRs are
    # configured.
    wallet_auth_challenge_limit_window_seconds: int = 600
    wallet_auth_challenge_global_limit: int = 768
    wallet_auth_challenge_address_limit: int = 64
    wallet_auth_challenge_peer_limit: int = 256
    wallet_auth_challenge_trusted_proxy_cidrs: str = ""
    wallet_auth_challenge_client_ip_header: str = ""
    wallet_auth_issuer: str = "dnai-wikigen:wallet-auth"
    wallet_auth_audience: str = "dnai-wikigen:tinker-delegate"
    wallet_auth_domain: str = "www.wikigen.me"
    wallet_auth_uri: str = "https://www.wikigen.me"
    wallet_auth_chain_id: int = 84532
    # Trusted, operator-owned Base Sepolia JSON-RPC used only for EIP-1271
    # contract-wallet verification. Empty preserves local EOA-only auth;
    # production dstack/Phala compose requires the encrypted URL. The request
    # schemas expose no RPC override.
    wallet_auth_rpc_url: str = ""
    wallet_auth_rpc_url_secondary: str = ""
    wallet_auth_rpc_timeout_seconds: float = 3.0
    wallet_auth_rpc_max_response_bytes: int = 131072
    wallet_auth_max_signature_bytes: int = 4096

    # Challenge-version-bound wallet authorization for encrypted Arena
    # submissions. The issuer, audience, and dstack key path are deliberately
    # separate from seller artifact-upload authentication.
    arena_wallet_auth_key_path: str = "tinker/arena_wallet_auth"
    arena_wallet_auth_challenge_ttl_seconds: int = 300
    arena_wallet_auth_token_ttl_seconds: int = 300
    arena_wallet_auth_max_pending_challenges: int = 1024
    arena_wallet_auth_issuer: str = "dnai-wikigen:arena-wallet-auth"
    arena_wallet_auth_audience: str = "dnai-wikigen:arena"

    # Challenge-version-scoped device credentials for autonomous Arena clients.
    # Their JWT, delivery, and persistence keys are separate from the wallet
    # session, Deal, Compute, and upstream proxy domains. Explicit secrets are
    # local-development only; CVMs derive the independent dstack paths.
    arena_agent_credential_signing_key: str = ""
    arena_agent_credential_key_path: str = "tinker/arena_agent_credentials"
    arena_agent_credential_max_ttl_seconds: int = 86400
    arena_agent_store_path: str = ""
    arena_agent_store_integrity_key: str = ""
    arena_agent_store_integrity_key_path: str = "tinker/arena_agent_store_integrity"

    # Independent ChallengeRegistry admission for Arena ciphertext ingress.
    # These are public release pins plus an operator-owned HTTPS Base Sepolia
    # RPC.  The browser sends a proposed finalized-block snapshot, but the API
    # re-reads every field at that exact block and fails before either durable
    # write when any pin, block identity, or contract state differs.  This is a
    # single-RPC finalized observation, not quorum or a consensus proof.
    arena_registry_rpc_url: str = ""
    arena_registry_address: str = ""
    arena_registry_runtime_code_hash: str = ""
    arena_registry_approved_challenge_bindings_json: str = ""
    arena_registry_approved_challenge_set_sha256: str = ""
    arena_registry_max_block_age_seconds: int = 300
    arena_registry_max_future_block_skew_seconds: int = 30

    # Durable bounded Arena catalog/submission/queue/leaderboard state. This
    # state contains commitments and encrypted-object references, never raw
    # candidate code. Its canonical schema-v4 envelope is HMAC authenticated
    # with a purpose-separated key. That integrity check is not an
    # anti-rollback primitive. Empty path or unavailable key disables the
    # persistent surface fail-closed. The legacy HTTP worker routes are local
    # development compatibility only and remain disabled in every dstack
    # process even if the false-by-default switch is set.
    arena_store_path: str = ""
    arena_store_integrity_key: str = ""
    arena_store_integrity_key_path: str = "tinker/arena_store_integrity"
    arena_legacy_internal_api_enabled: bool = False

    # Dedicated safe-IR worker bootstrap. The release manifest and sealed
    # synthetic evaluator are regular 0600 files. The manifest's exact bytes
    # are additionally pinned by SHA-256 in deployment configuration. An
    # authenticated HTTPS QVL endpoint is required by the real-dstack worker so
    # every job can authorize its newly collected quote. The 0600 verdict path
    # exists only for offline parser/tests and is rejected by production CLI.
    arena_worker_release_manifest_path: str = ""
    arena_worker_release_manifest_sha256: str = ""
    arena_worker_evaluator_path: str = ""
    arena_worker_qvl_verdict_path: str = ""
    arena_worker_qvl_verdict_url: str = ""
    arena_worker_qvl_release_policy_hash: str = ""
    arena_worker_poll_interval_seconds: float = 1.0
    # Authenticated process-presence projection. This is not TDX evidence and
    # defaults off even when the worker source is present. A release may enable
    # it only with the exact source SHA/image digest plus a fresh HMAC heartbeat
    # written under a distinct dstack-derived key.
    arena_worker_live_capability_enabled: bool = False
    arena_worker_release_sha: str = ""
    arena_worker_image_digest: str = ""
    arena_worker_approved_challenge_set_sha256: str = ""
    arena_worker_release_policy_commitment: str = ""
    arena_worker_compose_hash: str = ""
    arena_worker_app_id: str = ""
    arena_worker_os_image_hash: str = ""
    arena_worker_heartbeat_path: str = ""
    arena_worker_heartbeat_ttl_seconds: int = 30
    arena_worker_heartbeat_key_path: str = "tinker/arena_worker_heartbeat"
    arena_worker_heartbeat_integrity_key: str = ""

    # Compute Console authentication is isolated from deal, Arena, proxy, and
    # runtime bearer domains. Explicit keys are local-development only; CVMs
    # derive each purpose from its distinct dstack path.
    compute_wallet_auth_signing_key: str = ""
    compute_wallet_auth_key_path: str = "tinker/compute_wallet_auth"
    compute_wallet_auth_challenge_ttl_seconds: int = 300
    compute_wallet_auth_token_ttl_seconds: int = 600
    compute_wallet_auth_max_pending_challenges: int = 1024
    compute_wallet_auth_issuer: str = "dnai-wikigen:compute-wallet-auth"
    compute_wallet_auth_audience: str = "dnai-wikigen:compute-console"
    compute_credential_signing_key: str = ""
    compute_credential_key_path: str = "tinker/compute_credentials"
    compute_credential_issuer: str = "dnai-wikigen:compute-credential"
    compute_credential_audience: str = "dnai-wikigen:compute-jobs"
    compute_credential_max_ttl_seconds: int = 604800
    compute_store_path: str = ""
    compute_store_integrity_key: str = ""
    compute_store_integrity_key_path: str = "tinker/compute_store_integrity"
    compute_max_operator_grant_credits: int = 100000
    compute_max_project_balance_credits: int = 1000000

    # Multi-owner Collaboration Console authentication and current-state
    # authority. Wallet tokens, consent signatures, and the authenticated store
    # are purpose-separated from Deal, Arena, Compute, Review, proxy, and
    # runtime domains. Explicit keys are local-development only; CVMs derive
    # each purpose from its independent dstack path. The local HMAC store
    # detects corruption/tampering but remains explicitly non-monotonic. A live
    # dstack surface is constructed only with the release-bound Base Sepolia
    # ExecutionPolicyAnchor witness and fails closed when it is unavailable.
    collaboration_enabled: bool = False
    collaboration_wallet_auth_signing_key: str = ""
    collaboration_wallet_auth_key_path: str = (
        "tinker/collaboration_wallet_auth"
    )
    collaboration_wallet_auth_challenge_ttl_seconds: int = 300
    collaboration_wallet_auth_token_ttl_seconds: int = 600
    collaboration_wallet_auth_max_pending_challenges: int = 1024
    collaboration_wallet_auth_issuer: str = (
        "dnai-wikigen:collaboration-wallet-auth"
    )
    collaboration_wallet_auth_audience: str = (
        "dnai-wikigen:collaboration-console"
    )
    collaboration_consent_challenge_ttl_seconds: int = 300
    collaboration_store_path: str = ""
    collaboration_store_integrity_key: str = ""
    collaboration_store_integrity_key_path: str = (
        "tinker/collaboration_store_integrity"
    )

    # One-shot Collaboration execution is a separately authorized runtime
    # surface. Coordination may remain enabled while this worker stays off.
    # The production journal uses its own dstack-derived HMAC key and the
    # worker poll is intentionally bounded so a malformed environment value
    # cannot create a busy loop or an unbounded reconciliation delay.
    collaboration_execution_enabled: bool = False
    collaboration_execution_journal_path: str = ""
    collaboration_execution_journal_integrity_key: str = ""
    collaboration_execution_journal_integrity_key_path: str = (
        "tinker/collaboration_execution_journal_integrity"
    )
    collaboration_execution_release_git_sha: str = ""
    collaboration_execution_release_verification_sha256: str = ""
    collaboration_execution_grant_ttl_seconds: int = Field(
        300,
        ge=60,
        le=900,
    )
    collaboration_execution_royalty_reservation_safety_seconds: int = Field(
        900,
        ge=60,
        le=3600,
    )
    collaboration_execution_poll_interval_seconds: float = Field(
        1.0,
        ge=0.1,
        le=60.0,
    )
    collaboration_execution_worker_heartbeat_path: str = ""
    collaboration_execution_worker_heartbeat_ttl_seconds: int = Field(
        30,
        ge=5,
        le=300,
    )
    collaboration_execution_worker_heartbeat_key_path: str = (
        "tinker/collaboration_execution_worker_heartbeat"
    )
    collaboration_execution_worker_heartbeat_integrity_key: str = ""
    collaboration_royalty_settlement_store_path: str = ""
    collaboration_royalty_settlement_store_integrity_key_path: str = (
        "tinker/collaboration_royalty_settlement_store"
    )
    collaboration_royalty_settlement_store_integrity_key: str = ""

    # Complete server-derived RoyaltySettlementReleaseBinding for the
    # profile-gated Collaboration worker.  Contract-active values and the
    # independent Royalty-QVL policy are separate signed late inputs.  Main
    # runtime identity is projected from the canonical prepare observation;
    # the browser/client supplies none of these fields and no funding
    # commitment is accepted through environment configuration.
    royalty_distributor_address: str = ""
    royalty_distributor_runtime_code_hash: str = ""
    royalty_owner_address: str = ""
    royalty_authority_nonce: int = Field(0, ge=0, le=2**63 - 1)
    royalty_settlement_verifier: str = ""
    royalty_qvl_verifier: str = ""
    royalty_execution_policy_anchor: str = ""
    royalty_anchor_writer_release_commitment: str = ""
    royalty_release_policy_commitment: str = ""
    royalty_qvl_policy_commitment: str = ""
    royalty_qvl_signer_key_id: str = ""
    royalty_qvl_release_policy_hash: str = ""
    royalty_measurement_policy_sha256: str = ""
    royalty_main_runtime_compose_hash: str = ""
    royalty_main_runtime_app_id: str = ""
    royalty_main_runtime_os_image_hash: str = ""
    royalty_settlement_qvl_url: str = ""
    royalty_qvl_verdict_verifier_address: str = ""
    royalty_qvl_max_verdict_age_seconds: int = Field(120, ge=1, le=300)
    royalty_qvl_revoked_quote_hashes_json: str = "[]"

    # Exact-asset ComputeCreditVault dispatch is intentionally separate from
    # the modeled off-chain service-credit ledger above. The API journal holds
    # metadata and irreversible-boundary checkpoints only; the worker settles
    # the exact authorized asset on Base Sepolia.
    compute_dispatch_store_path: str = ""
    compute_dispatch_store_integrity_key: str = ""
    compute_dispatch_store_integrity_key_path: str = (
        "tinker/compute_dispatch_store_integrity"
    )
    compute_chain_rpc_url: str = ""
    compute_vault_address: str = ""
    compute_vault_runtime_code_hash: str = ""
    compute_vault_compose_hash: str = ""
    compute_metering_policy_set_hash: str = ""
    compute_execution_signer_key_path: str = "tinker/compute_execution_identity"
    compute_metering_url: str = ""
    compute_execution_confirmations: int = 2
    compute_execution_poll_interval_seconds: float = 1.0
    compute_execution_max_block_age_seconds: int = 300
    compute_execution_max_future_block_skew_seconds: int = 30

    # Release-pinned provider execution remains disabled unless every exact
    # adapter/SDK/source/request/base/tokenizer/runtime binding agrees and a
    # fresh authenticated worker-presence heartbeat is available. The adapter
    # intentionally makes no upstream idempotent-replay claim: it checkpoints
    # one at-most-once attempt and terminally holds ambiguous outcomes.
    compute_provider_execution_enabled: bool = False
    compute_provider_adapter_id: str = ""
    compute_provider_sdk_version: str = ""
    compute_provider_sdk_source_sha256: str = ""
    compute_provider_request_contract_sha256: str = ""
    compute_provider_base_url_sha256: str = ""
    compute_provider_tokenizer_path: str = ""
    compute_provider_tokenizer_release_sha256: str = ""
    compute_provider_result_key_path: str = "tinker/compute_provider_result"
    compute_provider_status_path: str = ""
    compute_provider_status_key_path: str = "tinker/compute_provider_status"
    compute_provider_status_integrity_key: str = ""
    compute_provider_status_ttl_seconds: int = 30
    compute_provider_request_timeout_seconds: float = 120.0

    # Wallet-owned Tinker customer lifecycle. The browser supplies only the
    # existing short-lived Compute wallet bearer plus bounded lifecycle input.
    # Every release/policy/evidence pin comes from one exact private authority
    # document whose bytes are SHA-256 pinned by the signed deployment.
    # These fields intentionally include ``tinker_customer`` in their Python
    # names, so the model-wide ``TINKER_`` prefix would otherwise make the
    # operational names ``TINKER_TINKER_CUSTOMER_*``.  Explicit validation
    # aliases preserve ergonomic Python construction while making the reviewed
    # one-prefix ``TINKER_CUSTOMER_*`` environment contract authoritative.
    tinker_customer_enabled: bool = Field(
        False,
        validation_alias=AliasChoices(
            "tinker_customer_enabled",
            "TINKER_CUSTOMER_ENABLED",
        ),
    )
    tinker_customer_authority_path: str = Field(
        "",
        validation_alias=AliasChoices(
            "tinker_customer_authority_path",
            "TINKER_CUSTOMER_AUTHORITY_PATH",
        ),
    )
    tinker_customer_authority_sha256: str = Field(
        "",
        validation_alias=AliasChoices(
            "tinker_customer_authority_sha256",
            "TINKER_CUSTOMER_AUTHORITY_SHA256",
        ),
    )
    tinker_customer_store_path: str = Field(
        "",
        validation_alias=AliasChoices(
            "tinker_customer_store_path",
            "TINKER_CUSTOMER_STORE_PATH",
        ),
    )
    # Explicit values are local-test-only. A real dstack deployment derives
    # purpose-separated keys at the two immutable paths below.
    tinker_customer_store_integrity_key: str = Field(
        "",
        validation_alias=AliasChoices(
            "tinker_customer_store_integrity_key",
            "TINKER_CUSTOMER_STORE_INTEGRITY_KEY",
        ),
    )
    tinker_customer_store_integrity_key_path: str = Field(
        "tinker/customer_store_integrity",
        validation_alias=AliasChoices(
            "tinker_customer_store_integrity_key_path",
            "TINKER_CUSTOMER_STORE_INTEGRITY_KEY_PATH",
        ),
    )
    tinker_customer_credential_signing_key: str = Field(
        "",
        validation_alias=AliasChoices(
            "tinker_customer_credential_signing_key",
            "TINKER_CUSTOMER_CREDENTIAL_SIGNING_KEY",
        ),
    )
    tinker_customer_credential_key_path: str = Field(
        "tinker/customer_credentials",
        validation_alias=AliasChoices(
            "tinker_customer_credential_key_path",
            "TINKER_CUSTOMER_CREDENTIAL_KEY_PATH",
        ),
    )
    tinker_customer_settlement_signing_key: str = Field(
        "",
        validation_alias=AliasChoices(
            "tinker_customer_settlement_signing_key",
            "TINKER_CUSTOMER_SETTLEMENT_SIGNING_KEY",
        ),
    )
    tinker_customer_settlement_key_path: str = Field(
        "tinker/customer_settlement_evidence",
        validation_alias=AliasChoices(
            "tinker_customer_settlement_key_path",
            "TINKER_CUSTOMER_SETTLEMENT_KEY_PATH",
        ),
    )

    # Ciphertext-only private workload ingress. The recipient and integrity
    # keys use distinct dstack derivation paths. Local key material exists only
    # for deterministic development/tests; real uploads additionally require a
    # fresh independently verified TDX recipient activation and therefore fail
    # closed outside a production CVM.
    compute_workload_ingress_store_path: str = ""
    compute_workload_ingress_integrity_key: str = ""
    compute_workload_ingress_integrity_key_path: str = (
        "tinker/compute_workload_ingress_integrity"
    )
    compute_workload_ingress_key_path: str = "tinker/compute_workload_ingress"
    compute_workload_ingress_local_key_file: str = ""
    compute_workload_ingress_private_key_hex: str = ""
    compute_workload_ingress_max_envelopes: int = 10_000
    compute_workload_wallet_adoption_enabled: bool = False
    # Fresh recipient activation is issued only by the fifth, dedicated QVL
    # CVM. The bearer remains a direct environment read and is never retained
    # in Settings/repr. Dynamic recipient/signing identity is dstack-derived;
    # these fields pin only the independent verifier/release and fresh chain
    # suite context projected by the signed release authority.
    compute_workload_qvl_url: str = ""
    compute_workload_qvl_verifier_address: str = ""
    compute_workload_qvl_release_policy_hash: str = ""
    compute_workload_qvl_max_verdict_age_seconds: int = 300
    compute_workload_qvl_revoked_quote_hashes_json: str = "[]"
    compute_workload_chain_id: int = 84_532
    compute_workload_fresh_deployment_receipt_sha256: str = ""
    compute_workload_cvm_id: str = ""
    compute_workload_deployment_intent_sha256: str = ""
    compute_workload_release_authority_sha256: str = ""
    compute_workload_ceremony_nonce: str = ""
    compute_workload_measurement_policy_set_sha256: str = ""
    compute_workload_qvl_measurement_policy_sha256: str = ""
    compute_workload_main_runtime_evidence_sha256: str = ""

    # Append-only, HMAC-authenticated execution-policy decisions. Records bind
    # only resource hashes to bounded kernel results; raw policy/request text
    # is never persisted. Empty path/key disables execution fail-closed.
    execution_policy_store_path: str = ""
    execution_policy_store_integrity_key: str = ""
    execution_policy_store_integrity_key_path: str = (
        "tinker/execution_policy_store_integrity"
    )
    # Comma-separated Ethereum addresses independently authorized to approve a
    # hash-only execution-policy PASS. Runtime bearer possession alone cannot
    # create a pass decision.
    execution_policy_approved_signers: str = ""
    # Canonical release commitment to the exact sorted signer-hash set. The
    # runtime recomputes and compares this before approvals or execution.
    execution_policy_approver_root_hash: str = ""
    # Public, deployment-unique domain (for example a chain-id + fresh contract
    # suite + compose commitment). Only its SHA-256 hash enters signatures and
    # records, preventing an approval from replaying across CVM deployments.
    execution_policy_approval_domain: str = ""

    # Monotonic Base Sepolia witness for the HMAC journal. Production writes
    # derive the exact release-bound writer from the distinct dstack path; no
    # raw private-key setting exists. Every read pins bytecode and all contract
    # state to one block hash at the older of a single RPC's reported finalized
    # tag and the configured confirmation-depth bound. This is not RPC quorum
    # or a consensus proof.
    execution_policy_anchor_rpc_url: str = ""
    execution_policy_anchor_address: str = ""
    execution_policy_anchor_runtime_code_hash: str = ""
    execution_policy_anchor_writer_address: str = ""
    execution_policy_anchor_writer_release_commitment: str = ""
    execution_policy_anchor_writer_key_path: str = (
        "tinker/execution_policy_anchor_writer"
    )
    execution_policy_anchor_confirmations: int = 12
    execution_policy_anchor_poll_interval_seconds: float = 1.0
    execution_policy_anchor_confirmation_wait_seconds: float = 60.0
    execution_policy_anchor_max_block_age_seconds: int = 3_600
    execution_policy_anchor_max_future_block_skew_seconds: int = 30
    # One-shot writer admission sends its fresh raw quote only to this
    # separately deployed, authenticated HTTPS QVL. The bearer is read
    # directly from TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN by the
    # CLI so it is never retained in Settings diagnostics or evidence output.
    execution_policy_anchor_writer_qvl_url: str = ""
    execution_policy_anchor_writer_qvl_verifier_address: str = ""
    execution_policy_anchor_writer_qvl_release_policy_hash: str = ""
    execution_policy_anchor_writer_qvl_max_verdict_age_seconds: int = 300

    # Browser-encrypted candidate envelopes. Ciphertext is stored separately
    # under server-generated sealed:// references and remains capped at 64 KiB.
    # Production derives a stable X25519 recipient at the distinct dstack path;
    # the 0600 local key file exists only so local queued ciphertext survives a
    # process restart. An explicit private hex key is test/local-only and must
    # never be passed to a dstack/Phala deployment.
    arena_candidate_ingress_store_path: str = ""
    arena_candidate_ingress_key_path: str = "tinker/arena_candidate_ingress"
    arena_candidate_ingress_local_key_file: str = ""
    arena_candidate_ingress_private_key_hex: str = ""
    arena_candidate_ingress_max_envelopes: int = 10_000

    # Tinker auth
    tinker_console_url: str = "https://tinker-console.thinkingmachines.ai"
    project_id: str = ""
    base_url: str = ""

    # Deal evaluator activation. ``deterministic`` is the only production lane:
    # it resolves the buyer's onchain policy commitment through one exact,
    # hashed three-recipe release manifest and performs no Tinker/provider I/O.
    # ``stub`` remains local-only and ``sft`` remains unavailable because it
    # would send artifact-derived tokens outside the attested boundary.
    evaluator_mode: Literal["disabled", "stub", "sft", "deterministic"] = "disabled"
    diligence_evaluator_release_manifest_path: str = ""
    diligence_evaluator_release_manifest_sha256: str = ""
    diligence_evaluator_policy_set_root: str = ""
    diligence_chain_id: int = 84532
    diligence_room_address: str = ""

    @field_validator("collaboration_enabled", mode="before")
    @classmethod
    def validate_exact_collaboration_enabled(cls, value):
        """Accept only booleans or exact lowercase env literals."""

        if isinstance(value, bool):
            return value
        if value == "true":
            return True
        if value == "false":
            return False
        raise ValueError(
            "collaboration_enabled must be exactly true or false"
        )

    @field_validator("collaboration_execution_enabled", mode="before")
    @classmethod
    def validate_exact_collaboration_execution_enabled(cls, value):
        """Accept only booleans or exact lowercase signed env literals."""

        if isinstance(value, bool):
            return value
        if value == "true":
            return True
        if value == "false":
            return False
        raise ValueError(
            "collaboration_execution_enabled must be exactly true or false"
        )

    @field_validator("compute_workload_wallet_adoption_enabled", mode="before")
    @classmethod
    def validate_exact_compute_workload_wallet_adoption_enabled(cls, value):
        """Reject loose truthy spellings at the signed release boundary."""

        if isinstance(value, bool):
            return value
        if value == "true":
            return True
        if value == "false":
            return False
        raise ValueError(
            "compute_workload_wallet_adoption_enabled must be exactly true or false"
        )

    @field_validator("collaboration_execution_release_git_sha")
    @classmethod
    def validate_collaboration_execution_release_git_sha(cls, value):
        if value and not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError(
                "collaboration_execution_release_git_sha must be empty or 40 lowercase hex"
            )
        return value

    @field_validator("collaboration_execution_release_verification_sha256")
    @classmethod
    def validate_collaboration_execution_release_verification_sha256(cls, value):
        if value and not _NONZERO_SHA256.fullmatch(value):
            raise ValueError(
                "collaboration_execution_release_verification_sha256 must be empty or a nonzero sha256 digest"
            )
        return value

    @field_validator(
        "royalty_distributor_address",
        "royalty_owner_address",
        "royalty_settlement_verifier",
        "royalty_qvl_verifier",
        "royalty_execution_policy_anchor",
        "royalty_qvl_verdict_verifier_address",
    )
    @classmethod
    def validate_royalty_release_address(cls, value):
        if value and not _NONZERO_ADDRESS.fullmatch(value):
            raise ValueError(
                "royalty release addresses must be empty or canonical nonzero lowercase addresses"
            )
        return value

    @field_validator("royalty_settlement_qvl_url")
    @classmethod
    def validate_royalty_settlement_qvl_url(cls, value):
        if not value:
            return value
        if value != value.strip() or len(value) > 2048:
            raise ValueError("royalty settlement QVL URL is invalid")
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/verify"
            or parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError(
                "royalty settlement QVL URL must be an exact public HTTPS /verify endpoint"
            )
        return value

    @field_validator("royalty_qvl_revoked_quote_hashes_json")
    @classmethod
    def validate_royalty_qvl_revoked_quote_hashes_json(cls, value):
        try:
            parsed = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            raise ValueError(
                "royalty QVL revoked quote hashes must be canonical JSON"
            ) from None
        if (
            not isinstance(parsed, list)
            or len(parsed) > 1024
            or any(
                not isinstance(item, str) or not _NONZERO_BYTES32.fullmatch(item)
                for item in parsed
            )
            or parsed != sorted(set(parsed))
            or json.dumps(parsed, separators=(",", ":"), ensure_ascii=True) != value
        ):
            raise ValueError(
                "royalty QVL revoked quote hashes must be a sorted unique bytes32 array"
            )
        return value

    @field_validator(
        "royalty_distributor_runtime_code_hash",
        "royalty_anchor_writer_release_commitment",
        "royalty_release_policy_commitment",
        "royalty_qvl_policy_commitment",
        "royalty_qvl_signer_key_id",
        "royalty_qvl_release_policy_hash",
    )
    @classmethod
    def validate_royalty_release_bytes32(cls, value):
        if value and not _NONZERO_BYTES32.fullmatch(value):
            raise ValueError(
                "royalty release commitments must be empty or canonical nonzero bytes32"
            )
        return value

    @field_validator("royalty_measurement_policy_sha256")
    @classmethod
    def validate_royalty_measurement_policy_sha256(cls, value):
        if value and not _NONZERO_SHA256.fullmatch(value):
            raise ValueError(
                "royalty measurement policy must be empty or a nonzero sha256 digest"
            )
        return value

    @field_validator("royalty_main_runtime_compose_hash")
    @classmethod
    def validate_royalty_main_runtime_compose_hash(cls, value):
        if value and not re.fullmatch(r"(?!0{64}$)[0-9a-f]{64}", value):
            raise ValueError(
                "royalty main runtime compose hash must be empty or 64 nonzero lowercase hex"
            )
        return value

    @field_validator("royalty_main_runtime_app_id")
    @classmethod
    def validate_royalty_main_runtime_app_id(cls, value):
        if value and not re.fullmatch(r"(?!0{40}$)[0-9a-f]{40}", value):
            raise ValueError(
                "royalty main runtime app ID must be empty or 40 nonzero lowercase hex"
            )
        return value

    @field_validator("royalty_main_runtime_os_image_hash")
    @classmethod
    def validate_royalty_main_runtime_os_image_hash(cls, value):
        if value and not re.fullmatch(r"(?!0{64}$)[0-9a-f]{64}", value):
            raise ValueError(
                "royalty main runtime OS image hash must be empty or 64 nonzero lowercase hex"
            )
        return value

    @model_validator(mode="after")
    def validate_production_wallet_auth_identity(self) -> "Settings":
        """Pin production personal-sign prompts to the deployed HTTPS origin."""

        if os.getenv("DSTACK_ENABLED", "").strip().lower() != "true":
            return self
        if self.wallet_auth_domain != "www.wikigen.me":
            raise ValueError("production wallet-auth domain must be www.wikigen.me")
        if self.wallet_auth_uri != "https://www.wikigen.me":
            raise ValueError(
                "production wallet-auth URI must be https://www.wikigen.me"
            )
        if self.wallet_auth_chain_id != 84_532:
            raise ValueError("production wallet-auth chain must be Base Sepolia")
        return self

    @model_validator(mode="after")
    def validate_deterministic_diligence_release(self) -> "Settings":
        """Fail closed before serving a partially bound production evaluator."""

        if self.evaluator_mode != "deterministic":
            return self
        manifest_path = self.diligence_evaluator_release_manifest_path.strip()
        manifest_sha256 = self.diligence_evaluator_release_manifest_sha256.strip()
        policy_root = self.diligence_evaluator_policy_set_root.strip()
        room = self.diligence_room_address.strip().lower()
        chain_room = self.chain_contract_address.strip().lower()
        if not manifest_path:
            raise ValueError("deterministic diligence manifest path is required")
        if _NONZERO_SHA256.fullmatch(manifest_sha256) is None:
            raise ValueError("deterministic diligence manifest SHA-256 is invalid")
        if _NONZERO_BYTES32.fullmatch(policy_root) is None:
            raise ValueError("deterministic diligence policy-set root is invalid")
        if self.diligence_chain_id != 84_532:
            raise ValueError("deterministic diligence chain must be Base Sepolia")
        if _NONZERO_ADDRESS.fullmatch(room) is None:
            raise ValueError("deterministic diligence room address is invalid")
        if chain_room and chain_room != room:
            raise ValueError("deterministic diligence room and watcher contract differ")
        if os.getenv("DSTACK_ENABLED", "").strip().lower() == "true":
            if manifest_path != PRODUCTION_DILIGENCE_EVALUATOR_MANIFEST_PATH:
                raise ValueError(
                    "production diligence manifest path is outside the sealed release volume"
                )
            if not chain_room:
                raise ValueError("production diligence watcher contract is required")
            try:
                info = Path(manifest_path).lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise OSError("not a regular file")
                from tinker_delegate.diligence_evaluator_registry import (
                    load_diligence_evaluator_registry,
                )

                load_diligence_evaluator_registry(
                    manifest_path,
                    expected_manifest_sha256=manifest_sha256,
                    expected_policy_set_root=policy_root,
                )
            except (OSError, TypeError, ValueError) as exc:
                raise ValueError(
                    "production diligence manifest is unavailable or invalid"
                ) from exc
        self.diligence_evaluator_release_manifest_path = manifest_path
        self.diligence_evaluator_release_manifest_sha256 = manifest_sha256
        self.diligence_evaluator_policy_set_root = policy_root
        self.diligence_room_address = room
        return self

    # Account details. The mailbox address is injected only inside the CVM;
    # the oracle API intentionally exposes a commitment, never the raw value.
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
    # Release-bound human-review queue. The private canonical policy maps each
    # role to at least two distinct wallet identities; only its exact SHA-256 is
    # public. Reviewer challenges share the global wallet admission limiter and
    # must remain below every configured nonce-store capacity. The queue holds
    # hashes only and is authenticated with a purpose-separated dstack key.
    review_queue_path: str = ""
    review_queue_store_integrity_key: str = ""
    review_queue_store_integrity_key_path: str = "tinker/review_queue_integrity"
    review_authority_policy_json: str = ""
    review_authority_policy_sha256: str = ""
    # Private canonical projection of the current release-reviewer roster.
    # Its public digest is descriptor-bound; every role assignment must map
    # address <-> reviewer_ref exactly to address <-> controller_id here.
    release_reviewer_authority_active_reviewers_json: str = ""
    release_reviewer_authority_active_reviewers_sha256: str = ""
    # Immutable public release provenance for the encrypted product-review
    # roster above. These values are descriptor-bound; the short-lived release
    # ceremony status is provenance, not a per-decision liveness clock.
    release_reviewer_authority_genesis_acceptance_sha256: str = ""
    release_reviewer_authority_current_status_epoch: int = 0
    release_reviewer_authority_current_status_sha256: str = ""
    review_authority_challenge_ttl_seconds: int = 300
    review_authority_max_pending_challenges: int = 1024
    review_ticket_ttl_seconds: int = 86_400
    # The public, hash-only queue is separately peer-limited and paginated; it
    # never consumes the reviewer challenge-admission budget.
    review_queue_read_limit_window_seconds: int = 60
    review_queue_read_peer_limit: int = 120
    review_queue_read_max_peers: int = 4096
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
    # Exact canonical release-policy hash for the independent Diligence QVL.
    # Production settlement requires this to match the room's timelocked,
    # permanently frozen attestation binding.
    chain_attestation_release_policy_hash: str = ""
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
    # Exact DNS host[:port] allowlist for the funding-preflight endpoint's
    # optional server-side attestation fetch. IP literals and wildcard hosts are
    # rejected.
    funding_preflight_allowed_hosts: str = ""

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
