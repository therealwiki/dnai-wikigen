"""FastAPI server for tinker-delegate.

Endpoints:
  GET  /health                    — public liveness only
  GET  /health/internal           — bounded operator diagnostics
  GET  /attestation               — TDX attestation quote + context-bound encryption public key
  POST /auth/wallet/challenge     — issue deal-bound Ethereum personal-sign challenge
  POST /auth/wallet/token         — exchange one-time signature for scoped token
  POST /auth/arena/challenge      — issue challenge-version-bound personal-sign challenge
  POST /auth/arena/token          — exchange signature for exact Arena session token
  GET  /arena/candidate-encryption-contract — current recipient + browser crypto contract
  GET  /arena/challenges          — immutable bounded challenge catalog
  GET  /arena/challenges/{id}/versions/{version} — exact public manifest
  POST /arena/challenges/{id}/versions/{version}/submissions — browser-ciphertext ingress
  GET  /arena/challenges/{id}/versions/{version}/queue — modeled queue projection
  GET  /arena/challenges/{id}/versions/{version}/leaderboard — bounded Ladder ranking
  GET  /arena/challenges/{id}/versions/{version}/submissions/mine — wallet-owned page
  GET  /arena/challenges/{id}/versions/{version}/worker-capability — bounded presence
  GET  /arena/submissions/{submission_id} — public bounded submission
  POST /compute/projects/{project_id}/dispatch-intents — exact-asset metadata-only intent
  POST /compute/projects/{project_id}/jobs/{job_id}/cancel — cancel an undispatched queued job
  POST /auth/reauth               — bounded Tinker OTP re-auth, disabled unless explicitly enabled
  GET  /browser/readiness         — bounded browser-control readiness probe, disabled unless explicitly enabled
  GET  /browser/selector-probe    — bounded read-only selector/frame probe, disabled unless explicitly enabled
  GET  /billing/balance           — authenticated bounded Tinker balance band
  GET  /billing/payment-method-status — bounded card-on-file status
  GET  /billing/account-access-status — bounded account access/billing-gate state
  POST /retention/sweep              — destroy expired retained artifacts (bounded)
  GET  /source/grants                — bounded source-controller grant manifest
  POST /verify/reward-run            — verify a private-reward run packet (bounded verdict)
  POST /verify/reward-mechanism      — aggregate mechanism audit: run + dataset + canary (bounded)
  GET  /review/queue                 — bounded human-review queue (optional ?routed_role=)
  POST /review/decide                — record a reviewer decision (fail-closed, persisted)
  POST /review/expire                — expire stale pending tickets (persisted sweep)
  GET  /billing/funding-policy    — bounded active funding mode
  GET  /billing/funding-preflight — bounded operator validation readiness
  GET  /billing/funding-receipts  — bounded funding attempt audit records
  POST /billing/card              — add payment method (plaintext — local dev only)
  POST /billing/card/encrypted    — add payment method (encrypted to TEE — production)
  POST /billing/card/remove       — remove payment method
  POST /billing/add-balance       — add credit balance
  POST /policy/approval-message   — hash-only owner/reviewer approval payload (internal)
  POST /policy/evaluate           — deterministic bounded policy decision (internal)
  POST /policy/status             — latest bounded execution-policy binding (internal)
  POST /coordination/consent-decision — bounded source-modeled owner consent receipt
  GET  /tinker/proxy/status       — bounded sealed Tinker proxy configuration
  GET  /tinker/proxy/client-config — bounded sealed Tinker client config status
  PUT  /tinker/proxy/client-config — seal Tinker project/base-url config
  GET  /tinker/proxy/issue-policy — bounded proxy issue-policy status
  PUT  /tinker/proxy/issue-policy — install hash-only proxy issue policy
  GET  /tinker/proxy/identity-registry — bounded proxy identity-registry status
  PUT  /tinker/proxy/identity-registry — install signed hash-only identity registry
  POST /tinker/proxy/token        — encrypted scoped proxy JWT issuance
  GET  /tinker/proxy/tokens       — bounded proxy token audit records
  POST /tinker/proxy/token/revoke — revoke proxy token by JWT-id hash
  POST /tinker/smoke              — opt-in bounded real SDK smoke test
  POST /deal/chain-event       — bounded chain event audit marker (internal)
  POST /deal/{deal_id}/artifact/encrypted — upload seller's encrypted artifact
  POST /deal/{deal_id}/artifact   — plaintext local-dev artifact hook
  GET  /deal/{deal_id}/result     — get bounded evaluation result
  GET  /deals                     — list active deals
  POST /deal/{deal_id}/evaluate   — trigger evaluation (internal)
  POST /deal/{deal_id}/resolve    — notify deal resolution (internal)
"""
import hashlib
import hmac
import math
import os
import re
import threading
from contextlib import contextmanager
from typing import Any, Literal, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from cryptography.exceptions import InvalidTag
from pydantic import BaseModel, ConfigDict, Field, field_validator

from tinker_delegate.api_key_store import resolve_api_key
from tinker_delegate.artifacts import (
    ARTIFACT_CIPHERTEXT_BYTES,
    ARTIFACT_COMMITMENT_SCHEME,
    ARTIFACT_ENVELOPE_SCHEME,
    ARTIFACT_FRAME_BYTES,
    ARTIFACT_PADDING_PROFILE,
    decode_artifact_hex,
    decode_artifact_wrapper,
    decrypt_artifact_payload,
    normalize_artifact_hash,
    zero_buffer,
)
from tinker_delegate.automation_receipts import (
    AutomationOutcome,
    AutomationStage,
    AutomationSurface,
    classify_automation_error,
    make_receipt,
)
from tinker_delegate.config import Settings
from tinker_delegate.crypto import EncryptedPayload
from tinker_delegate.dstack_utils import is_dstack_enabled
from tinker_delegate.funding_receipt_store import build_funding_receipt_store
from tinker_delegate.funding_policy import (
    FundingPolicyError,
    funding_policy_status,
    funding_validation_preflight,
)
from tinker_delegate.oracle_client import OracleClient
from tinker_delegate.redaction import redact_text
from tinker_delegate.run_metadata_store import build_run_metadata_store
from tinker_delegate.runtime_hardening import disable_core_dumps
from tinker_delegate.http_security import (
    HttpSecurityError,
    configure_cors,
    validate_https_allowlisted_url,
)
from tinker_delegate.runtime_auth import (
    RuntimeAuthUnavailable,
    resolve_runtime_auth_token,
    runtime_auth_enabled,
)
from tinker_delegate.runtime_state import get_runtime_state, update_runtime_state
from tinker_delegate.request_body_limits import (
    DEFAULT_ROUTE_BODY_LIMITS,
    RouteBodyLimitMiddleware,
)
from tinker_delegate.tinker_client_config_store import resolve_tinker_client_config
from tinker_delegate.card_channel import (
    AttestationResponse,
    CardPayload,
    EncryptedCardPayload,
    BalancePayload,
    BillingResponse,
    get_tee_keypair,
    get_attestation,
    handle_card_update,
    handle_encrypted_card_update,
    handle_add_balance,
    handle_account_access_status,
    handle_get_balance,
    handle_payment_method_status,
    handle_remove_payment_method,
)
from tinker_delegate.wallet_auth import (
    ARTIFACT_UPLOAD_SCOPE,
    WalletAuthError,
    WalletAuthService,
    WalletAuthUnavailable,
    WalletChallengeCapacityError,
    WalletChallengeStore,
    normalize_wallet_address,
)
from tinker_delegate.arena_auth import (
    ARENA_OWNER_READ_SCOPE,
    ARENA_SUBMIT_SCOPE,
    ArenaAuthError,
    ArenaAuthUnavailable,
    ArenaChallengeCapacityError,
    ArenaWalletAuthService,
    ArenaWalletChallengeStore,
)
from tinker_delegate.compute_auth import (
    COMPUTE_CONSOLE_SCOPE,
    ComputeAuthError,
    ComputeAuthUnavailable,
    ComputeChallengeCapacityError,
    ComputeWalletAuthService,
    ComputeWalletChallengeStore,
    classify_compute_token,
    compute_store_integrity_key,
    encrypt_compute_credential_token,
    issue_compute_credential_token,
    normalize_compute_scopes,
    verify_compute_credential_token,
)
from tinker_delegate.wallet_challenge_limiter import (
    WalletChallengeAdmissionLimiter,
    WalletChallengePeerPolicy,
    WalletChallengeRateLimited,
)

app = FastAPI(
    title="Tinker Delegate",
    description="TEE-hosted Tinker account management and NDAI deal orchestration.",
)
app.add_middleware(RouteBodyLimitMiddleware, limits=DEFAULT_ROUTE_BODY_LIMITS)


@app.exception_handler(RequestValidationError)
async def _sanitized_request_validation_error(_request, exc: RequestValidationError):
    """Preserve useful validation shape without reflecting submitted values.

    FastAPI's default response includes the rejected ``input`` value. That is
    unsafe for endpoints whose clients might accidentally post candidate code,
    card material, artifacts, or tokens in an unsupported field.
    """

    bounded_errors = [
        {
            "type": str(error.get("type", "validation_error"))[:96],
            "loc": [str(part)[:96] for part in error.get("loc", ())[:8]],
            "msg": str(error.get("msg", "Request validation failed"))[:256],
        }
        for error in exc.errors()[:32]
    ]
    return JSONResponse(
        status_code=422,
        content={"detail": bounded_errors},
    )

settings = Settings()
configure_cors(app, settings)
disable_core_dumps()

_wallet_challenges = WalletChallengeStore(
    max_pending=max(1, int(settings.wallet_auth_max_pending_challenges))
)
_arena_wallet_challenges = ArenaWalletChallengeStore(
    max_pending=max(1, int(settings.arena_wallet_auth_max_pending_challenges))
)
_compute_wallet_challenges = ComputeWalletChallengeStore(
    max_pending=max(1, int(settings.compute_wallet_auth_max_pending_challenges))
)
_wallet_challenge_limiter = WalletChallengeAdmissionLimiter.from_settings(settings)
_wallet_challenge_peer_policy = WalletChallengePeerPolicy.from_settings(settings)
_arena_store_instance = None
_arena_store_instance_path = ""
_arena_ingress_service_instance = None
_arena_ingress_service_identity: tuple[str, ...] | None = None
_compute_store_instance = None
_compute_store_instance_identity: tuple[str, str] | None = None
_compute_dispatch_journal_instance = None
_compute_dispatch_journal_instance_identity: tuple[str, str] | None = None
_compute_workload_ingress_instance = None
_compute_workload_ingress_instance_identity: tuple[str, ...] | None = None
_execution_policy_store_instance = None
_execution_policy_store_instance_identity: tuple[str, str] | None = None
_execution_policy_anchor_coordinator_instance = None
_execution_policy_anchor_coordinator_identity: tuple[str, ...] | None = None
_execution_policy_initialization_lock = threading.RLock()
# Tests may inject an in-memory chain witness directly. There is deliberately
# no configuration or environment-variable path to activate this override in a
# deployed process.
_execution_policy_anchor_coordinator_override = None

# ---------------------------------------------------------------------------
# Control plane (lazy init — only when Tinker API key is available)
# ---------------------------------------------------------------------------
_control_plane = None


def _agent_stack_available() -> bool:
    try:
        import tinker  # noqa: F401
        return True
    except Exception:
        return False


def _plaintext_card_endpoint_allowed() -> bool:
    """Plaintext card delivery is a local-dev escape hatch, never a TEE path."""
    return settings.allow_plaintext_card_endpoint and not is_dstack_enabled()


def _plaintext_artifact_endpoint_allowed() -> bool:
    """Plaintext artifacts are a local-dev escape hatch, never a TEE path."""
    return settings.allow_plaintext_artifact_endpoint and not is_dstack_enabled()


def _runtime_auth_enabled() -> bool:
    return runtime_auth_enabled(settings)


def _runtime_auth_token() -> str:
    try:
        return resolve_runtime_auth_token(settings)
    except RuntimeAuthUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Delegate runtime auth key is unavailable",
        ) from exc


def _require_runtime_auth(authorization: str = Header(default="")) -> None:
    """Protect operator-only Tinker account mutation endpoints."""
    if not _runtime_auth_enabled():
        return
    expected = _runtime_auth_token()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Delegate runtime auth is required but no token is configured",
        )
    scheme, _, supplied = authorization.partition(" ")
    if scheme.lower() != "bearer" or not supplied:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid bearer token")


def _require_configured_runtime_auth(authorization: str = Header(default="")) -> None:
    if not _runtime_auth_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Runtime bearer auth must be configured for this internal endpoint",
        )
    _require_runtime_auth(authorization)


def _wallet_auth_service() -> WalletAuthService:
    return WalletAuthService(settings, _wallet_challenges)


def _arena_wallet_auth_service() -> ArenaWalletAuthService:
    return ArenaWalletAuthService(settings, _arena_wallet_challenges)


def _compute_wallet_auth_service() -> ComputeWalletAuthService:
    return ComputeWalletAuthService(settings, _compute_wallet_challenges)


def _admit_wallet_challenge(request: Request, address: str) -> None:
    """Apply one shared, non-enumerating Deal/Arena/Compute admission gate."""

    canonical_address = normalize_wallet_address(address)
    peer_source = _wallet_challenge_peer_policy.source(
        direct_peer=request.client.host if request.client else "",
        headers=request.headers,
    )
    _wallet_challenge_limiter.admit(
        address=canonical_address,
        peer_source=peer_source,
    )


def _raise_wallet_challenge_rate_limit(retry_after: int, cause: Exception) -> None:
    raise HTTPException(
        status_code=429,
        detail="Wallet challenge issuance is rate limited",
        headers={"Retry-After": str(max(1, int(retry_after)))},
    ) from cause


def _get_compute_store():
    """Return the configured single-worker Compute store or fail closed."""

    global _compute_store_instance, _compute_store_instance_identity

    from tinker_delegate.compute_store import ComputeStore, ComputeStoreCorruptError

    path = str(settings.compute_store_path or "").strip()
    if not path:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Compute durable store is not configured",
        )
    try:
        integrity_key = compute_store_integrity_key(settings)
    except ComputeAuthUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Compute store integrity key is unavailable",
        ) from exc
    identity = (path, hashlib.sha256(integrity_key).hexdigest())
    if _compute_store_instance is None or _compute_store_instance_identity != identity:
        try:
            instance = ComputeStore(
                path,
                integrity_key=integrity_key,
                max_operator_grant_credits=int(settings.compute_max_operator_grant_credits),
                max_project_balance_credits=int(settings.compute_max_project_balance_credits),
            )
        except (ComputeStoreCorruptError, OSError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Compute durable store is unavailable",
            ) from exc
        _compute_store_instance = instance
        _compute_store_instance_identity = identity
    return _compute_store_instance


def _get_compute_dispatch_journal():
    """Return the exact-asset journal, never the legacy credit ledger."""

    global _compute_dispatch_journal_instance
    global _compute_dispatch_journal_instance_identity

    from tinker_delegate.compute_runtime import (
        ComputeExecutionJournal,
        ComputeRuntimeError,
        compute_execution_integrity_key,
    )

    path = str(settings.compute_dispatch_store_path or "").strip()
    if not path:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Exact-asset Compute dispatch journal is not configured",
        )
    try:
        integrity_key = compute_execution_integrity_key(settings)
        identity = (path, hashlib.sha256(integrity_key).hexdigest())
        if (
            _compute_dispatch_journal_instance is None
            or _compute_dispatch_journal_instance_identity != identity
        ):
            _compute_dispatch_journal_instance = ComputeExecutionJournal(
                path, integrity_key=integrity_key
            )
            _compute_dispatch_journal_instance_identity = identity
        return _compute_dispatch_journal_instance
    except (ComputeRuntimeError, OSError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Exact-asset Compute dispatch journal is unavailable",
        ) from exc


def _get_compute_workload_ingress():
    """Return the ciphertext-only ingress with a fail-closed activation gate."""

    global _compute_workload_ingress_instance
    global _compute_workload_ingress_instance_identity

    from tinker_delegate.compute_workload_ingress import (
        ComputeWorkloadIngressCorrupt,
        ComputeWorkloadIngressUnavailable,
        build_compute_workload_ingress,
    )
    from tinker_delegate.dstack_utils import is_dstack_enabled as _is_dstack_enabled

    path = str(settings.compute_workload_ingress_store_path or "").strip()
    if not path:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Compute workload ingress is not configured",
        )
    private_override = str(
        settings.compute_workload_ingress_private_key_hex or ""
    )
    local_integrity = str(
        settings.compute_workload_ingress_integrity_key or ""
    )
    identity = (
        path,
        str(settings.compute_workload_ingress_key_path or ""),
        str(settings.compute_workload_ingress_local_key_file or ""),
        hashlib.sha256(private_override.encode("utf-8")).hexdigest(),
        str(settings.compute_workload_ingress_integrity_key_path or ""),
        hashlib.sha256(local_integrity.encode("utf-8")).hexdigest(),
        str(int(settings.compute_workload_ingress_max_envelopes)),
        str(settings.compute_workload_qvl_url or ""),
        str(settings.compute_workload_qvl_verifier_address or ""),
        str(settings.compute_workload_qvl_release_policy_hash or ""),
        str(int(settings.compute_workload_qvl_max_verdict_age_seconds)),
        hashlib.sha256(
            str(settings.compute_workload_qvl_revoked_quote_hashes_json or "").encode(
                "utf-8"
            )
        ).hexdigest(),
        str(int(settings.compute_workload_chain_id)),
        str(settings.compute_vault_address or ""),
        str(settings.compute_vault_runtime_code_hash or ""),
        str(settings.compute_workload_fresh_deployment_receipt_sha256 or ""),
        str(settings.compute_workload_cvm_id or ""),
        str(settings.compute_workload_deployment_intent_sha256 or ""),
        str(settings.compute_workload_release_authority_sha256 or ""),
        str(settings.compute_workload_ceremony_nonce or ""),
        str(settings.compute_workload_measurement_policy_set_sha256 or ""),
        str(settings.compute_workload_qvl_measurement_policy_sha256 or ""),
        str(settings.compute_workload_main_runtime_evidence_sha256 or ""),
        "dstack" if _is_dstack_enabled() else "local",
    )
    if (
        _compute_workload_ingress_instance is None
        or _compute_workload_ingress_instance_identity != identity
    ):
        try:
            _compute_workload_ingress_instance = build_compute_workload_ingress(
                settings
            )
        except (
            ComputeWorkloadIngressCorrupt,
            ComputeWorkloadIngressUnavailable,
            OSError,
            ValueError,
        ) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Compute workload ingress is unavailable",
            ) from exc
        _compute_workload_ingress_instance_identity = identity
    return _compute_workload_ingress_instance


def _compute_execution_policy_context_hash(resource_id: str) -> str:
    """Derive Compute policy context from an authenticated authoritative store."""

    from tinker_delegate.compute_runtime import (
        ComputeDispatchIntent,
        ComputeIntentNotFound,
        ComputeRuntimePolicyError,
        ComputeRuntimeStateError,
        compute_execution_policy_context_hash,
    )
    from tinker_delegate.compute_store import (
        ComputeStoreCorruptError,
        ComputeStoreError,
    )

    if re.fullmatch(r"0x[0-9a-f]{64}", resource_id):
        try:
            record = _get_compute_dispatch_journal().get(resource_id)
            intent = ComputeDispatchIntent.from_dict(record["intent"])
            if intent.job_id != resource_id:
                raise ComputeRuntimeStateError(
                    "dispatch intent resource identity mismatch"
                )
            return compute_execution_policy_context_hash(intent)
        except ComputeIntentNotFound as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Compute execution resource does not exist",
            ) from exc
        except (ComputeRuntimePolicyError, ComputeRuntimeStateError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Compute execution context is unavailable",
            ) from exc
    try:
        return _get_compute_store().execution_policy_context_hash(resource_id)
    except ComputeStoreCorruptError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Compute execution context is unavailable",
        ) from exc
    except ComputeStoreError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Compute execution resource does not exist",
        ) from exc


def _bind_execution_policy_context(
    surface: str,
    resource_id: str,
    result,
):
    """Attach a server-derived immutable execution context to a kernel result.

    Deal and Arena keep their existing resource-identity semantics and carry
    the explicit zero sentinel. Compute PASS always requires a pre-existing
    authoritative exact-asset intent or service-credit job. Conservative
    HOLD/DENY decisions may still be appended after a resource disappears so
    revocation cannot be blocked by a failing execution store.
    """

    if surface != "compute_dispatch":
        return result
    from dataclasses import replace

    from tinker_delegate.policy_kernel import (
        PolicyDecision,
        ZERO_EXECUTION_CONTEXT_HASH,
    )

    try:
        context_hash = _compute_execution_policy_context_hash(resource_id)
    except HTTPException as exc:
        if (
            result.decision != PolicyDecision.PASS
            and exc.status_code == status.HTTP_400_BAD_REQUEST
        ):
            context_hash = ZERO_EXECUTION_CONTEXT_HASH
        else:
            raise
    return replace(result, execution_context_hash=context_hash)


def _get_execution_policy_store():
    """Return the configured integrity-protected policy-decision store."""

    global _execution_policy_store_instance, _execution_policy_store_instance_identity

    from tinker_delegate.execution_policy_store import (
        ExecutionPolicyStore,
        ExecutionPolicyStoreCorrupt,
        ExecutionPolicyStoreUnavailable,
        execution_policy_integrity_key,
    )

    with _execution_policy_initialization_lock:
        path = str(settings.execution_policy_store_path or "").strip()
        if not path:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Execution policy durable store is not configured",
            )
        try:
            integrity_key = execution_policy_integrity_key(settings)
        except ExecutionPolicyStoreUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Execution policy store integrity key is unavailable",
            ) from exc
        identity = (path, hashlib.sha256(integrity_key).hexdigest())
        if (
            _execution_policy_store_instance is None
            or _execution_policy_store_instance_identity != identity
        ):
            try:
                instance = ExecutionPolicyStore(path, integrity_key=integrity_key)
            except (ExecutionPolicyStoreCorrupt, OSError, ValueError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Execution policy durable store is unavailable",
                ) from exc
            _execution_policy_store_instance = instance
            _execution_policy_store_instance_identity = identity
        return _execution_policy_store_instance


def _get_execution_policy_anchor_coordinator():
    """Return the strict dstack-writer rollback coordinator or fail closed."""

    global _execution_policy_anchor_coordinator_instance
    global _execution_policy_anchor_coordinator_identity

    if _execution_policy_anchor_coordinator_override is not None:
        return _execution_policy_anchor_coordinator_override

    from tinker_delegate.execution_policy_anchor import (
        AnchoredExecutionPolicyCoordinator,
        ExecutionPolicyAnchorError,
        HttpsExecutionPolicyAnchorGateway,
        verify_live_execution_policy_release_binding,
    )

    with _execution_policy_initialization_lock:
        store = _get_execution_policy_store()
        identity = tuple(
            str(value)
            for value in (
                *_execution_policy_store_instance_identity,
                settings.execution_policy_anchor_rpc_url,
                settings.execution_policy_anchor_address,
                settings.execution_policy_anchor_runtime_code_hash,
                settings.execution_policy_anchor_writer_address,
                settings.execution_policy_anchor_writer_release_commitment,
                settings.execution_policy_anchor_writer_key_path,
                settings.execution_policy_anchor_confirmations,
                settings.execution_policy_anchor_poll_interval_seconds,
                settings.execution_policy_anchor_confirmation_wait_seconds,
                settings.execution_policy_anchor_max_block_age_seconds,
                settings.execution_policy_anchor_max_future_block_skew_seconds,
                settings.execution_policy_approval_domain,
            )
        )
        if (
            _execution_policy_anchor_coordinator_instance is None
            or _execution_policy_anchor_coordinator_identity != identity
        ):
            previous = _execution_policy_anchor_coordinator_instance
            gateway = None
            try:
                gateway = HttpsExecutionPolicyAnchorGateway.from_settings(
                    settings, read_only=False
                )
                verify_live_execution_policy_release_binding(settings, gateway)
                coordinator = AnchoredExecutionPolicyCoordinator(store, gateway)
            except (ExecutionPolicyAnchorError, OSError, ValueError) as exc:
                if gateway is not None:
                    gateway.close()
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Execution policy rollback anchor is unavailable",
                ) from exc
            if previous is not None:
                previous.close()
            _execution_policy_anchor_coordinator_instance = coordinator
            _execution_policy_anchor_coordinator_identity = identity
        return _execution_policy_anchor_coordinator_instance


def _require_execution_policy_pass(surface: str, resource_id: str) -> dict[str, Any]:
    """One-shot policy check for non-mutating callers and compatibility tests."""

    with _authorized_execution_policy_lease(surface, resource_id) as record:
        return record


@contextmanager
def _authorized_execution_policy_lease(
    surface: str,
    resource_id: str,
    *,
    expected_execution_context_hash: str | None = None,
):
    """Keep one verified policy PASS stable across protected execution."""

    import time as _time

    from tinker_delegate.execution_policy_store import (
        ExecutionPolicyNotPassed,
        ExecutionPolicyStoreError,
        ExecutionPolicyStoreUnavailable,
        execution_policy_trust_context,
    )
    from tinker_delegate.execution_policy_anchor import (
        ExecutionPolicyAnchorError,
    )
    from tinker_delegate.policy_kernel import ZERO_EXECUTION_CONTEXT_HASH

    try:
        if expected_execution_context_hash is None:
            expected_execution_context_hash = (
                _compute_execution_policy_context_hash(resource_id)
                if surface == "compute_dispatch"
                else ZERO_EXECUTION_CONTEXT_HASH
            )
        domain_hash, approver_hashes, approver_root_hash = (
            execution_policy_trust_context(settings)
        )
        lease = _get_execution_policy_anchor_coordinator().authorized_execution_lease(
            surface=surface,
            resource_id=resource_id,
            now=int(_time.time()),
            expected_approval_domain_hash=domain_hash,
            expected_approver_root_hash=approver_root_hash,
            approved_approver_hashes=approver_hashes,
            expected_execution_context_hash=expected_execution_context_hash,
        )
        with lease as record:
            yield record
    except (
        ExecutionPolicyStoreUnavailable,
        ExecutionPolicyStoreError,
        ExecutionPolicyAnchorError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Execution policy rollback anchor is unavailable",
        ) from exc
    except ExecutionPolicyNotPassed as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Execution policy gate is not passed for this resource",
        ) from exc


def _get_arena_store():
    """Return the configured durable Arena store or fail closed.

    The JSON store uses process-local locking, so deployed API containers must
    run one worker until a shared transactional store replaces this slice.
    """

    global _arena_store_instance, _arena_store_instance_path

    from tinker_delegate.arena_store import ArenaStore, ArenaStoreCorruptError

    path = str(settings.arena_store_path or "").strip()
    if not path:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Arena durable store is not configured",
        )
    if _arena_store_instance is None or _arena_store_instance_path != path:
        try:
            instance = ArenaStore(path)
        except (ArenaStoreCorruptError, OSError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Arena durable store is unavailable",
            ) from exc
        _arena_store_instance = instance
        _arena_store_instance_path = path
    return _arena_store_instance


def _get_arena_ingress():
    """Return the stable-key, ciphertext-only Arena ingress service."""

    global _arena_ingress_service_instance, _arena_ingress_service_identity

    from tinker_delegate.arena_ingress import (
        ArenaIngressCorruptError,
        ArenaIngressUnavailable,
        build_arena_candidate_ingress,
    )

    path = str(settings.arena_candidate_ingress_store_path or "").strip()
    if not path:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Arena candidate ingress durable store is not configured",
        )
    private_override = str(
        settings.arena_candidate_ingress_private_key_hex or ""
    ).strip()
    identity = (
        path,
        str(settings.arena_candidate_ingress_key_path or ""),
        str(settings.arena_candidate_ingress_local_key_file or ""),
        hashlib.sha256(private_override.encode("utf-8")).hexdigest(),
        str(int(settings.arena_candidate_ingress_max_envelopes)),
        "dstack" if is_dstack_enabled() else "local",
    )
    if (
        _arena_ingress_service_instance is None
        or _arena_ingress_service_identity != identity
    ):
        try:
            instance = build_arena_candidate_ingress(settings)
        except (ArenaIngressCorruptError, ArenaIngressUnavailable, OSError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Arena candidate ingress is unavailable",
            ) from exc
        _arena_ingress_service_instance = instance
        _arena_ingress_service_identity = identity
    return _arena_ingress_service_instance


def _rollback_arena_ingress_or_503(ingress, ingress_result) -> None:
    """Keep ciphertext and queue stores aligned after a queue-write failure."""

    from tinker_delegate.arena_ingress import ArenaIngressError

    try:
        ingress.store.rollback_created(ingress_result)
    except (ArenaIngressError, OSError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Arena coordinated persistence rollback failed",
        ) from exc


def _require_arena_challenge(challenge_id: str, challenge_version: str):
    from tinker_delegate.arena_store import ArenaStoreError, default_challenge_catalog

    # Require durable state for any operation that can lead to a write. The
    # configured store constructor also verifies that its persisted catalog is
    # byte-for-byte equivalent to this built-in versioned catalog.
    _get_arena_store()
    try:
        return default_challenge_catalog().get(challenge_id, challenge_version)
    except ArenaStoreError as exc:
        raise HTTPException(status_code=404, detail="Unknown Arena challenge version") from exc


def _require_wallet_auth(
    authorization: str,
    *,
    deal_id: str,
    required_scope: str,
):
    token = _bearer_token(authorization)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Wallet bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return _wallet_auth_service().verify_token(
            token,
            required_scope=required_scope,
            deal_id=deal_id,
        )
    except WalletAuthUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Wallet authentication is unavailable",
        ) from exc
    except WalletAuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def _require_arena_wallet_auth(
    authorization: str,
    *,
    challenge_id: str,
    challenge_version: str,
    required_scope: str = ARENA_SUBMIT_SCOPE,
):
    token = _bearer_token(authorization)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Arena wallet bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return _arena_wallet_auth_service().verify_token(
            token,
            required_scope=required_scope,
            challenge_id=challenge_id,
            challenge_version=challenge_version,
        )
    except ArenaAuthUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Arena wallet authentication is unavailable",
        ) from exc
    except ArenaAuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def _require_compute_wallet_auth(authorization: str):
    token = _bearer_token(authorization)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Compute wallet bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        if classify_compute_token(token) != "wallet":
            raise ComputeAuthError("Compute wallet token required")
        return _compute_wallet_auth_service().verify_token(
            token,
            required_scope=COMPUTE_CONSOLE_SCOPE,
        )
    except ComputeAuthUnavailable as exc:
        raise HTTPException(503, "Compute wallet authentication is unavailable") from exc
    except ComputeAuthError as exc:
        raise HTTPException(
            401,
            str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def _require_compute_job_principal(authorization: str, *, required_scope: str):
    """Authenticate exactly one Compute wallet or device credential domain."""

    import time as _time

    token = _bearer_token(authorization)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Compute bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        kind = classify_compute_token(token)
        if kind == "wallet":
            claims = _compute_wallet_auth_service().verify_token(
                token,
                required_scope=COMPUTE_CONSOLE_SCOPE,
            )
            return {"kind": "wallet", "wallet_address": claims.address}
        claims = verify_compute_credential_token(
            settings,
            token,
            required_scope=required_scope,
        )
        _get_compute_store().authorize_credential(
            claims,
            required_scope=required_scope,
            used_at=int(_time.time()),
        )
        return {
            "kind": "credential",
            "project_id": claims.project_id,
            "credential_id": claims.credential_id,
        }
    except ComputeAuthUnavailable as exc:
        raise HTTPException(503, "Compute authentication is unavailable") from exc
    except ComputeAuthError as exc:
        raise HTTPException(
            401,
            str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except Exception as exc:
        from tinker_delegate.compute_store import (
            ComputeAuthorizationError,
            ComputeStoreCorruptError,
            ComputeStoreError,
        )

        if isinstance(exc, ComputeAuthorizationError):
            raise HTTPException(
                403,
                str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        if isinstance(exc, ComputeStoreCorruptError) or isinstance(exc, OSError):
            raise HTTPException(503, "Compute credential store is unavailable") from exc
        if isinstance(exc, ComputeStoreError):
            raise HTTPException(
                403,
                "Compute credential is inactive or unknown",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        raise


def _bearer_token(authorization: str) -> str:
    scheme, _, supplied = authorization.partition(" ")
    if scheme.lower() != "bearer" or not supplied:
        return ""
    return supplied


def _raise_compute_store_error(exc: Exception) -> None:
    from tinker_delegate.compute_store import (
        ComputeAuthorizationError,
        ComputeCapExceeded,
        ComputeIdempotencyConflict,
        ComputeInsufficientCredits,
        ComputeJobStateConflict,
        ComputeStoreCorruptError,
        ComputeStoreError,
    )

    if isinstance(exc, ComputeAuthorizationError):
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if isinstance(
        exc,
        (
            ComputeCapExceeded,
            ComputeIdempotencyConflict,
            ComputeInsufficientCredits,
            ComputeJobStateConflict,
        ),
    ):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, (ComputeStoreCorruptError, OSError)):
        raise HTTPException(status_code=503, detail="Compute durable store write failed") from exc
    if isinstance(exc, ComputeStoreError):
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise exc


def _require_runtime_or_proxy_auth(required_scope: str, authorization: str = Header(default="")) -> dict[str, Any]:
    """Allow the operator runtime token or a scoped Tinker proxy JWT."""
    if _runtime_auth_enabled():
        try:
            _require_runtime_auth(authorization)
            return {
                "auth_kind": "runtime",
                "required_scope": required_scope,
                "raw_secret_egress": False,
            }
        except HTTPException:
            pass

    token = _bearer_token(authorization)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        from tinker_delegate.tinker_proxy import verify_proxy_token

        verification = verify_proxy_token(settings, token, required_scope=required_scope)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=redact_text(exc)) from exc
    return {
        "auth_kind": "proxy",
        "required_scope": required_scope,
        "subject_hash": verification["subject_hash"],
        "jwt_id_hash": verification["jwt_id_hash"],
        "scopes": verification["scopes"],
        "scope_limits": verification.get("scope_limits", {}),
        "expires_at": verification["expires_at"],
        "raw_secret_egress": False,
    }


def _enforce_proxy_amount_limit(
    auth_context: dict[str, Any],
    scope: str,
    amount_dollars: float,
    *,
    require_limit: bool = False,
) -> None:
    if auth_context.get("auth_kind") != "proxy":
        return
    limits = auth_context.get("scope_limits", {})
    if not isinstance(limits, dict):
        raise HTTPException(status_code=403, detail="Proxy token limits are invalid")
    scope_limit = limits.get(scope)
    if scope_limit is None:
        if require_limit:
            raise HTTPException(status_code=403, detail="Proxy token scope limit is required")
        return
    if not isinstance(scope_limit, dict):
        raise HTTPException(status_code=403, detail="Proxy token scope limit is invalid")
    max_amount = scope_limit.get("max_amount_usd")
    try:
        max_amount_float = float(max_amount)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=403, detail="Proxy token amount limit is invalid") from exc
    if not math.isfinite(max_amount_float) or max_amount_float <= 0:
        raise HTTPException(status_code=403, detail="Proxy token amount limit is invalid")
    if amount_dollars > max_amount_float:
        raise HTTPException(status_code=403, detail="Proxy token amount exceeds policy limit")


def _attach_proxy_auth_context(payload: Any, auth_context: dict[str, Any]) -> Any:
    """Attach bounded proxy auth evidence without changing runtime-token responses."""
    if auth_context.get("auth_kind") != "proxy":
        return payload
    if isinstance(payload, dict):
        bounded = dict(payload)
        bounded["proxy_auth_context"] = auth_context
        return bounded
    if hasattr(payload, "proxy_auth_context"):
        payload.proxy_auth_context = auth_context
    return payload


def _get_control_plane():
    global _control_plane
    if _control_plane is None:
        deterministic_evaluator = settings.evaluator_mode == "deterministic"
        api_key = "" if deterministic_evaluator else resolve_api_key(settings)
        if not api_key and not deterministic_evaluator:
            raise HTTPException(503, "TINKER_API_KEY not configured — control plane unavailable")
        try:
            from tinker_delegate.control_plane import ControlPlane
        except ModuleNotFoundError as exc:
            if exc.name == "tinker":
                raise HTTPException(
                    503,
                    "Tinker agent stack is not installed in this deployment",
                ) from exc
            raise
        client_config = (
            {"project_id": "", "base_url": ""}
            if deterministic_evaluator
            else resolve_tinker_client_config(settings)
        )
        from tinker_delegate.retention_policy import build_retention_policy
        from tinker_delegate.sealed_retention import build_retention_store
        from tinker_delegate.source_controller import build_source_registry
        _control_plane = ControlPlane(
            api_key,
            run_metadata_store=build_run_metadata_store(settings),
            project_id=client_config["project_id"],
            base_url=client_config["base_url"],
            retention_policy=build_retention_policy(settings),
            retention_store=build_retention_store(settings),
            source_registry=(
                None if deterministic_evaluator else build_source_registry(settings)
            ),
            enable_tinker_session=not deterministic_evaluator,
        )
        # On-boot sweep: destroy any retained artifacts whose window expired while
        # the service was down, so nothing lingers past its retention deadline.
        try:
            _control_plane.sweep_retention()
        except Exception:  # pragma: no cover - defensive; never block startup
            pass
    return _control_plane


# ---------------------------------------------------------------------------
# Deal API models
# ---------------------------------------------------------------------------

class ArtifactUpload(BaseModel):
    """Local-only plaintext transport of the exact constant-size v3 frame."""

    model_config = ConfigDict(extra="forbid")

    artifact_hex: str = Field(
        min_length=ARTIFACT_FRAME_BYTES * 2,
        max_length=ARTIFACT_FRAME_BYTES * 2 + 2,
        pattern=r"^(?:0x)?[0-9a-f]+$",
    )
    artifact_hash: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    commitment_scheme: Literal["dnai-wikigen/artifact-commitment/v2"]
    envelope_scheme: Literal["dnai-wikigen/artifact-envelope/v3"]
    padding_profile: Literal["fixed_1m_v3"]

class EncryptedArtifactUpload(BaseModel):
    """TEE-encrypted v3 frame plus its public on-chain commitment."""

    model_config = ConfigDict(extra="forbid")

    ephemeral_public_key: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    nonce: str = Field(min_length=24, max_length=24, pattern=r"^[0-9a-f]{24}$")
    ciphertext: str = Field(
        min_length=ARTIFACT_CIPHERTEXT_BYTES * 2,
        max_length=ARTIFACT_CIPHERTEXT_BYTES * 2,
        pattern=r"^[0-9a-f]+$",
    )
    artifact_hash: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    commitment_scheme: Literal["dnai-wikigen/artifact-commitment/v2"]
    envelope_scheme: Literal["dnai-wikigen/artifact-envelope/v3"]
    padding_profile: Literal["fixed_1m_v3"]


class WalletChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str = Field(min_length=42, max_length=42)
    deal_id: str = Field(min_length=1, max_length=128)


class WalletChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str
    deal_id: str
    scope: str
    nonce: str
    message: str
    issued_at: int
    expires_at: int


class WalletTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nonce: str = Field(min_length=32, max_length=32)
    # EIP-1271 signatures are contract-defined byte strings and may be longer
    # than a 65-byte EOA signature. The verifier applies the tighter
    # server-configured decoded-byte limit and strict hex validation.
    signature: str = Field(min_length=2, max_length=8194)


class WalletTokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str
    token_type: str = "Bearer"
    address: str
    deal_id: str
    scopes: list[str]
    issued_at: int
    expires_at: int


class ArenaWalletChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str = Field(min_length=42, max_length=42)
    challenge_id: str = Field(min_length=1, max_length=128)
    challenge_version: str = Field(min_length=1, max_length=64)


class ArenaWalletChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str
    challenge_id: str
    challenge_version: str
    scope: str
    nonce: str
    message: str
    issued_at: int
    expires_at: int


class ArenaWalletTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nonce: str = Field(min_length=32, max_length=32)
    signature: str = Field(min_length=2, max_length=8194)


class ArenaWalletTokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str
    token_type: str = "Bearer"
    address: str
    challenge_id: str
    challenge_version: str
    scopes: list[str]
    issued_at: int
    expires_at: int


class ComputeWalletChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str = Field(min_length=42, max_length=42)


class ComputeWalletChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str
    nonce: str
    message: str
    issued_at: int
    expires_at: int
    scope: str
    chain_id: int


class ComputeWalletTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nonce: str = Field(min_length=32, max_length=32)
    signature: str = Field(min_length=2, max_length=8194)


class ComputeWalletTokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str
    token_type: str = "Bearer"
    address: str
    scopes: list[str]
    issued_at: int
    expires_at: int


class ComputeProjectCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)


class ComputeMemberRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str = Field(min_length=42, max_length=42)
    role: str = Field(pattern=r"^(admin|developer|viewer)$")


class ComputeDeviceRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=64)
    kind: str = Field(pattern=r"^(developer_device|ci_service|autonomous_agent)$")
    public_key: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$")


class ComputeCredentialIssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(min_length=3, max_length=64)
    name: str = Field(min_length=1, max_length=64)
    scopes: list[str] = Field(min_length=1, max_length=5)
    expires_in_seconds: int = Field(ge=60, le=604800)
    daily_credit_cap: int = Field(ge=1, le=1_000_000)


class ComputeCredentialRotateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expires_in_seconds: int = Field(ge=60, le=604800)


class ComputeJobCreateRequest(BaseModel):
    """Metadata-only job request; prompts/examples are structurally absent."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    operation: str = Field(pattern=r"^(inference|training)$")
    model: str = Field(pattern=r"^qwen3_8b$")
    recipe: str = Field(pattern=r"^(qwen3_8b_bounded|qwen3_8b_lora_r32)$")
    max_credits: int = Field(ge=1, le=500)
    result_policy: str = Field(
        pattern=r"^(bounded_summary_receipt|score_band_hash)$"
    )
    environment_version: str = Field(min_length=1, max_length=64)


class ComputeWorkloadManifestRequest(BaseModel):
    """Public schema and hard caps; private input is structurally absent."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    workload_schema: Literal[
        "dnai.compute.workload.inference.v1",
        "dnai.compute.workload.sft-jsonl.v1",
    ] = Field(alias="schema")
    operation: Literal["inference", "training"]
    model: Literal["qwen3_8b"]
    recipe: Literal["qwen3_8b_bounded", "qwen3_8b_lora_r32"]
    payload_size_class: Literal["4k", "16k", "64k", "256k", "1m"]
    example_count_class: Literal["none", "1_8", "9_32", "33_128", "129_256"]
    max_prefill_tokens: int = Field(ge=0, le=100_000_000)
    max_sample_tokens: int = Field(ge=0, le=100_000_000)
    max_train_tokens: int = Field(ge=0, le=100_000_000)


class ComputeWorkloadEnvelopeRequest(BaseModel):
    """Ciphertext envelope only; no prompt/example/dataset field exists."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    algorithm: Literal["X25519-HKDF-SHA256-AES-256-GCM"]
    encoding: Literal["base64url-nopad"]
    key_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    attestation_report_data: str = Field(pattern=r"^[0-9a-f]{64}$")
    activation_commitment: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    aad: str = Field(min_length=1, max_length=10_923, pattern=r"^[A-Za-z0-9_-]+$")
    ephemeral_public_key: str = Field(
        min_length=43,
        max_length=43,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    nonce: str = Field(
        min_length=16,
        max_length=16,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    ciphertext: str = Field(
        min_length=23,
        max_length=1_398_102,
        pattern=r"^[A-Za-z0-9_-]+$",
    )


class ComputeWorkloadCreateRequest(BaseModel):
    """One exact private workload commitment plus its sealed envelope."""

    model_config = ConfigDict(extra="forbid")

    workload_commitment: str = Field(
        min_length=71,
        max_length=71,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    manifest: ComputeWorkloadManifestRequest
    envelope: ComputeWorkloadEnvelopeRequest


class ComputeDispatchIntentRequest(BaseModel):
    """Exact-chain metadata only; prompts/examples are structurally forbidden."""

    model_config = ConfigDict(extra="forbid")

    job_reference: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^(?:0x[0-9a-fA-F]{64}|[A-Za-z0-9][A-Za-z0-9._:-]{0,127})$",
    )
    workload_id: str = Field(pattern=r"^wrk_[0-9a-f]{32}$")
    asset: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    authorization_nonce: int = Field(ge=0, le=2**256 - 1)
    max_asset_debit: int = Field(ge=1, le=2**256 - 1)
    authorization_expiry: int = Field(ge=1, le=4_102_444_800)
    rate_policy_commitment: str = Field(
        pattern=r"^0x[0-9a-fA-F]{64}$"
    )
    compose_hash: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")
    operation: Literal["inference", "training"]
    model: Literal["qwen3_8b"]
    recipe: Literal["qwen3_8b_bounded", "qwen3_8b_lora_r32"]
    result_policy: Literal["bounded_summary_receipt", "score_band_hash"]
    max_prefill_tokens: int = Field(ge=0, le=100_000_000)
    max_sample_tokens: int = Field(ge=0, le=100_000_000)
    max_train_tokens: int = Field(ge=0, le=100_000_000)

    @field_validator("job_reference", mode="before")
    @classmethod
    def normalize_job_reference(cls, value: Any) -> Any:
        # Match the SolidJS canonical-ID helper, which trims before validating.
        return value.strip() if isinstance(value, str) else value


class ComputeGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    amount_credits: int = Field(ge=1, le=1_000_000)
    reason: str = Field(pattern=r"^operator_testnet_grant$")


class ComputeJobSettleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actual_credits: int = Field(ge=0, le=500)
    usage_receipt_hash: str = Field(
        min_length=71,
        max_length=71,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    metering_source: str = Field(pattern=r"^operator_bounded_receipt$")


class ComputeJobReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    terminal_status: str = Field(pattern=r"^(failed|canceled)$")
    reason: str = Field(
        pattern=r"^(operator_failed|operator_canceled|dispatch_unavailable)$"
    )


class ComputeJobCancelRequest(BaseModel):
    """The sole public cancellation intent; arbitrary reasons are not accepted."""

    model_config = ConfigDict(extra="forbid")

    reason: Literal["user_requested_before_dispatch"]


class ComputeJobCancelLedgerReceipt(BaseModel):
    """Immutable, bounded proof of the reservation reversal."""

    model_config = ConfigDict(extra="forbid")

    transaction_id: str = Field(
        min_length=3,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]{2,63}$",
    )
    sequence: int = Field(ge=1, le=40_000)
    kind: Literal["job_cancel"]
    transaction_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    previous_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    settlement_status: Literal["user_canceled_before_dispatch"]


class ComputeJobCancelResponse(BaseModel):
    """Exact public cancellation receipt; no job input or actor address egresses."""

    model_config = ConfigDict(extra="forbid")

    surface: Literal["compute_job_cancellation"]
    schema_version: Literal[1]
    project_id: str = Field(
        min_length=3,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]{2,63}$",
    )
    job_id: str = Field(
        min_length=3,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]{2,63}$",
    )
    status: Literal["canceled"]
    changed: bool
    idempotent_replay: bool
    released_credits: int = Field(ge=1, le=500)
    credit_reversal: Literal["reserved_to_available"]
    ledger: ComputeJobCancelLedgerReceipt
    provider_dispatch_performed: Literal[False]
    service_settlement_performed: Literal[False]


class ArenaSubmissionManifestRequest(BaseModel):
    """Allowlisted candidate metadata; source/code bytes are not a field."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1, le=1, strict=True)
    challenge_manifest_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    candidate_kind: str = Field(min_length=1, max_length=64)
    runtime: str = Field(min_length=1, max_length=64)
    entrypoint: str = Field(min_length=1, max_length=64)
    source_bytes: int = Field(ge=1, le=65_520, strict=True)
    mode: str = Field(pattern=r"^(test|benchmark|leaderboard)$")


class ArenaCandidateEnvelopeRequest(BaseModel):
    """Strict browser ciphertext envelope; candidate plaintext is not a field."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1, le=1, strict=True)
    algorithm: str = Field(
        min_length=30,
        max_length=30,
        pattern=r"^X25519-HKDF-SHA256-AES-256-GCM$",
    )
    encoding: str = Field(
        min_length=15,
        max_length=15,
        pattern=r"^base64url-nopad$",
    )
    key_id: str = Field(
        min_length=71,
        max_length=71,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    attestation_report_data: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    aad: str = Field(
        min_length=1,
        max_length=5_462,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    ephemeral_public_key: str = Field(
        min_length=43,
        max_length=43,
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )
    nonce: str = Field(
        min_length=16,
        max_length=16,
        pattern=r"^[A-Za-z0-9_-]{16}$",
    )
    ciphertext: str = Field(
        min_length=23,
        max_length=87_382,
        pattern=r"^[A-Za-z0-9_-]+$",
    )


class ArenaRegistryAuthorizationSnapshotRequest(BaseModel):
    """Browser-proposed block snapshot; the API never trusts it as authority."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1, le=1, strict=True)
    verification_model: Literal[
        "single_rpc_reported_finalized_pinned_block"
    ]
    chain_id: int = Field(ge=84_532, le=84_532, strict=True)
    block_number: str = Field(
        min_length=1, max_length=20, pattern=r"^(0|[1-9][0-9]*)$"
    )
    block_hash: str = Field(
        min_length=66, max_length=66, pattern=r"^0x[0-9a-f]{64}$"
    )
    block_timestamp: str = Field(
        min_length=1, max_length=20, pattern=r"^(0|[1-9][0-9]*)$"
    )
    registry_address: str = Field(
        min_length=42, max_length=42, pattern=r"^0x[0-9a-f]{40}$"
    )
    registry_runtime_code_hash: str = Field(
        min_length=66, max_length=66, pattern=r"^0x[0-9a-f]{64}$"
    )
    approved_challenge_set_sha256: str = Field(
        min_length=71,
        max_length=71,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    catalog_challenge_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9-]{0,63}$",
    )
    catalog_challenge_version: str = Field(
        min_length=5,
        max_length=32,
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$",
    )
    catalog_manifest_hash: str = Field(
        min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"
    )
    registry_challenge_id: str = Field(
        min_length=1,
        max_length=78,
        pattern=r"^(0|[1-9][0-9]*)$",
    )
    registry_version: int = Field(ge=1, le=2**32 - 1, strict=True)
    controller_address: str = Field(
        min_length=42, max_length=42, pattern=r"^0x[0-9a-f]{40}$"
    )
    pending_controller_address: str = Field(
        min_length=42, max_length=42, pattern=r"^0x[0-9a-f]{40}$"
    )
    metadata_uri: str = Field(
        min_length=1, max_length=256, pattern=r"^[\x21-\x7e]+$"
    )
    metadata_hash: str = Field(
        min_length=66, max_length=66, pattern=r"^0x[0-9a-f]{64}$"
    )
    sealed_artifact_commitment: str = Field(
        min_length=66, max_length=66, pattern=r"^0x[0-9a-f]{64}$"
    )
    evaluator_commitment: str = Field(
        min_length=66, max_length=66, pattern=r"^0x[0-9a-f]{64}$"
    )
    release_policy_commitment: str = Field(
        min_length=66, max_length=66, pattern=r"^0x[0-9a-f]{64}$"
    )
    registry_paused: Literal[False]
    challenge_paused: Literal[False]
    lifecycle: Literal[1]
    configuration_frozen: Literal[True]
    latest_version: int = Field(ge=1, le=2**32 - 1, strict=True)


class ArenaSubmissionCreateRequest(BaseModel):
    """Commitment plus browser ciphertext; plaintext and object refs are absent."""

    model_config = ConfigDict(extra="forbid")

    candidate_commitment: str = Field(
        min_length=71,
        max_length=71,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    manifest: ArenaSubmissionManifestRequest
    registry_authorization: ArenaRegistryAuthorizationSnapshotRequest
    envelope: ArenaCandidateEnvelopeRequest


class ArenaQueueTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_state: str = Field(min_length=1, max_length=32)
    reason: str = Field(min_length=1, max_length=64)


class ArenaLadderReleaseRequest(BaseModel):
    """Already-bounded Ladder release; exact evaluator score is never accepted."""

    model_config = ConfigDict(extra="forbid")

    submission_index: int = Field(ge=1, le=10_000)
    accepted: bool
    leaderboard_step_index: int = Field(ge=-1, le=10_000)
    step_denominator: int = Field(ge=1, le=10_000)
    improvement_steps_so_far: int = Field(ge=0, le=10_000)

class DealFundedNotification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deal_id: str
    buyer: str
    seller: str
    budget_cap: int          # wei
    reserve_price: int       # wei
    artifact_hash: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")
    evaluator_policy_commitment: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")

    @field_validator("evaluator_policy_commitment")
    @classmethod
    def require_nonzero_evaluator_policy_commitment(cls, value: str) -> str:
        if int(value[2:], 16) == 0:
            raise ValueError("evaluator policy commitment must be nonzero")
        return value.lower()

class ChainEventNotification(BaseModel):
    event_name: str
    deal_id: str
    block_number: int | None = None
    tx_hash: str = ""
    log_index: int | None = None
    fields: dict[str, Any] = Field(default_factory=dict)

class DealResolvedNotification(BaseModel):
    deal_id: str

class EvaluationResultResponse(BaseModel):
    """Fixed public projection; evaluator-authored strings never cross the API."""

    model_config = ConfigDict(extra="forbid")

    deal_id: str = Field(min_length=1, max_length=160)
    score_band: Literal["negligible", "low", "medium", "high", "exceptional"]
    quality_delta: Literal[
        "<1% quality-improvement band",
        "1-5% quality-improvement band",
        "5-10% quality-improvement band",
        "10-20% quality-improvement band",
        ">20% quality-improvement band",
    ]
    offer_price: int = Field(ge=0)
    recommendation: Literal["accept", "reject"]
    confidence: Literal["withheld"]
    methodology_summary: Literal["private_evaluator_details_withheld"]
    compute_cost_wei: int = Field(ge=0)
    fee_wei: int = Field(ge=0)

class TinkerSmokeRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deal_id: str = ""
    max_usd: Optional[float] = None
    model: str = ""
    rank: Optional[int] = None
    ttl_seconds: int = 3600
    compose_hash: str = ""
    require_encumbrance: bool = False


class TinkerProxyTokenIssueRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str
    scopes: list[str]
    recipient_public_key: str
    ttl_seconds: Optional[int] = None


class TinkerProxyIssuePolicyRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy: dict[str, Any]


class TinkerProxyIdentityRegistryRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    registry: dict[str, Any]


class TinkerProxyTokenRevokeRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    jwt_id_hash: str
    reason: str = ""


class TinkerClientConfigRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str = ""
    base_url: str = ""


class CoordinationConsentDecisionRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: dict[str, Any]
    decision: dict[str, Any]
    now: int = 0
    require_signature: bool = False
    expected_signer: str = ""


class PolicyApprovalMessageRequestBody(BaseModel):
    """Internal deterministic policy-kernel request and execution binding.

    Exact purpose/category strings enter the TEE but never return. The response
    contains only decisions, stable hashes, counts, and bounded reason codes.
    The policy kernel separately enforces canonical payload and field limits.
    """

    model_config = ConfigDict(extra="forbid")

    surface: Literal["deal_evaluation", "arena_execution", "compute_dispatch"]
    resource_id: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9_.:/-]+$",
    )
    expires_at: int = Field(ge=1, le=4_102_444_800)
    request: dict[str, Any]
    policy: dict[str, Any]


class PolicyEvaluateRequestBody(PolicyApprovalMessageRequestBody):
    """Policy request plus an independent approval for PASS decisions."""

    approver_address: str = Field(default="", max_length=42)
    approval_signature: str = Field(default="", max_length=132)
    previous_decision_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )


class ExecutionPolicyStatusRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    surface: Literal["deal_evaluation", "arena_execution", "compute_dispatch"]
    resource_id: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9_.:/-]+$",
    )


class RewardRunVerifyRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # A private-reward run packet (a demo output): certificate + transcript
    # commitment. Only its bounded public bytes are needed to verify.
    packet: dict[str, Any]


class RewardMechanismVerifyRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # The run packet plus the data-safe external inputs a third party posts: the
    # published sealed-dataset manifest (point 2) and canary calibration report
    # (point 3), both as JSON data. Code-source binding (point 1) is deliberately
    # NOT accepted here — it would require the server to read a caller-supplied
    # file path (a local-file-inclusion risk); that check stays CLI-local, run by
    # the reader against the source they hold.
    packet: dict[str, Any]
    manifest: dict[str, Any] | None = None
    canary_report: dict[str, Any] | None = None
    expected_signer: str | None = None
    # Anti-collusion + provenance layers (all data-safe): the witness quorum is
    # {"authorized_witnesses": [addr...], "threshold": M}; provenance runs when
    # require_provenance or expected_benchmark is set.
    witness_quorum: dict[str, Any] | None = None
    expected_benchmark: str | None = None
    require_provenance: bool = False


class ReviewDecideRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ticket_id: str
    decision: str  # "release" | "deny"
    reviewer_ref: str
    blocked_reviewer_refs: list[str] = []


@app.get("/tinker/proxy/status")
def tinker_proxy_status(authorization: str = Header(default="")):
    """Return bounded evidence that Tinker credentials stay inside the delegate."""
    if not settings.allow_tinker_proxy_endpoint:
        raise HTTPException(
            status_code=403,
            detail="Tinker proxy endpoint is disabled",
        )
    auth_context = _require_runtime_or_proxy_auth("proxy:status", authorization)
    from tinker_delegate.tinker_proxy import build_tinker_proxy_status

    return _attach_proxy_auth_context(build_tinker_proxy_status(settings), auth_context)


@app.get("/tinker/proxy/client-config")
def tinker_proxy_client_config(authorization: str = Header(default="")):
    """Return bounded evidence for the sealed Tinker SDK client config."""
    _require_runtime_auth(authorization)
    from tinker_delegate.tinker_client_config_store import build_tinker_client_config_status

    try:
        return build_tinker_client_config_status(settings)
    except ValueError as exc:
        raise HTTPException(400, redact_text(exc)) from exc


@app.put("/tinker/proxy/client-config")
def tinker_proxy_client_config_set(
    payload: TinkerClientConfigRequestBody,
    authorization: str = Header(default=""),
):
    """Seal Tinker project/base-url config for SDK calls inside the delegate."""
    global _control_plane

    _require_runtime_auth(authorization)
    from tinker_delegate.tinker_client_config_store import save_tinker_client_config

    try:
        result = save_tinker_client_config(
            settings,
            project_id=payload.project_id,
            base_url=payload.base_url,
        )
    except ValueError as exc:
        raise HTTPException(400, redact_text(exc)) from exc
    _control_plane = None
    return result


@app.get("/tinker/proxy/issue-policy")
def tinker_proxy_issue_policy(authorization: str = Header(default="")):
    """Return bounded hash-only proxy issue-policy status."""
    _require_runtime_auth(authorization)
    from tinker_delegate.tinker_proxy import get_proxy_issue_policy_status

    try:
        return get_proxy_issue_policy_status(settings)
    except ValueError as exc:
        raise HTTPException(400, redact_text(exc)) from exc


@app.put("/tinker/proxy/issue-policy")
def tinker_proxy_issue_policy_set(payload: TinkerProxyIssuePolicyRequestBody, authorization: str = Header(default="")):
    """Install a hash-only proxy issue policy for future token minting."""
    _require_runtime_auth(authorization)
    from tinker_delegate.tinker_proxy import save_proxy_issue_policy

    try:
        return save_proxy_issue_policy(settings, payload.policy)
    except ValueError as exc:
        raise HTTPException(400, redact_text(exc)) from exc


@app.get("/tinker/proxy/identity-registry")
def tinker_proxy_identity_registry(authorization: str = Header(default="")):
    """Return bounded hash-only proxy identity-registry status."""
    _require_runtime_auth(authorization)
    from tinker_delegate.tinker_proxy import get_proxy_identity_registry_status

    try:
        return get_proxy_identity_registry_status(settings)
    except ValueError as exc:
        raise HTTPException(400, redact_text(exc)) from exc


@app.put("/tinker/proxy/identity-registry")
def tinker_proxy_identity_registry_set(
    payload: TinkerProxyIdentityRegistryRequestBody,
    authorization: str = Header(default=""),
):
    """Install a signed hash-only proxy identity registry for future token minting."""
    _require_runtime_auth(authorization)
    from tinker_delegate.tinker_proxy import save_proxy_identity_registry

    try:
        return save_proxy_identity_registry(settings, payload.registry)
    except ValueError as exc:
        raise HTTPException(400, redact_text(exc)) from exc


@app.post("/tinker/proxy/token")
def tinker_proxy_token(payload: TinkerProxyTokenIssueRequestBody, authorization: str = Header(default="")):
    """Issue a scoped proxy JWT encrypted to an approved recipient public key."""
    if not settings.allow_tinker_proxy_token_issuance:
        raise HTTPException(
            status_code=403,
            detail="Tinker proxy token issuance is disabled",
        )
    if not _runtime_auth_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Runtime bearer auth must be configured before proxy token issuance",
        )
    _require_runtime_auth(authorization)
    from tinker_delegate.tinker_proxy import issue_encrypted_proxy_token

    try:
        return issue_encrypted_proxy_token(
            settings,
            subject=payload.subject,
            scopes=payload.scopes,
            recipient_public_key_hex=payload.recipient_public_key,
            ttl_seconds=payload.ttl_seconds,
        )
    except ValueError as exc:
        raise HTTPException(400, redact_text(exc)) from exc


@app.get("/tinker/proxy/tokens")
def tinker_proxy_tokens(authorization: str = Header(default="")):
    """Return bounded proxy-token issue/revoke audit records."""
    _require_runtime_auth(authorization)
    from tinker_delegate.tinker_proxy_store import (
        build_proxy_token_store,
        summarize_proxy_token_records,
    )

    return summarize_proxy_token_records(build_proxy_token_store(settings).load())


@app.post("/tinker/proxy/token/revoke")
def tinker_proxy_token_revoke(payload: TinkerProxyTokenRevokeRequestBody, authorization: str = Header(default="")):
    """Revoke a proxy token by bounded JWT-id hash."""
    _require_runtime_auth(authorization)
    from tinker_delegate.tinker_proxy_store import build_proxy_token_store

    try:
        record = build_proxy_token_store(settings).revoke(
            payload.jwt_id_hash,
            reason=payload.reason,
        )
    except ValueError as exc:
        raise HTTPException(400, redact_text(exc)) from exc
    return {
        "surface": "tinker_proxy_token_revoke",
        "success": True,
        "record": record,
        "raw_secret_egress": False,
    }


@app.get("/health")
def health():
    """Public liveness only; no network topology or sealed-state metadata."""
    return {"status": "ok", "service": "tinker-delegate"}


@app.get("/health/internal")
def health_internal(authorization: str = Header(default="")):
    """Bounded operator diagnostics, protected by mandatory runtime auth."""
    _require_configured_runtime_auth(authorization)
    oracle = OracleClient(settings)
    try:
        oracle_health = oracle.health()
    except Exception as e:
        oracle_health = {"error": redact_text(e)}

    return {
        "status": "ok",
        "oracle": oracle_health,
        "cdp_configured": bool(settings.cdp_url),
        "browser_ws_configured": bool(settings.browser_ws_endpoint),
        "api_key_configured": bool(resolve_api_key(settings)),
        "agent_stack_available": _agent_stack_available(),
        "runtime": get_runtime_state(),
        "raw_secret_egress": False,
    }


ATTESTATION_CONTEXTS = {
    "ingress",
    "artifact",
    "billing",
    "arena",
    "compute_workload",
}


@app.get("/attestation", response_model=AttestationResponse)
def attestation(context: str = "ingress") -> AttestationResponse:
    """Get TDX attestation quote + context-bound TEE encryption public key.

    Developer MUST:
    1. Verify the TDX quote (code measurements match expected values)
    2. Verify report_data binds context + encryption_public_key
    3. Extract encryption_public_key from the response
    4. Encrypt card details or artifacts to this key before sending them to an encrypted endpoint
    """
    if context not in ATTESTATION_CONTEXTS:
        raise HTTPException(400, "unsupported attestation context")
    if context == "arena":
        from tinker_delegate.arena_ingress import get_arena_ingress_attestation

        ingress = _get_arena_ingress()
        return AttestationResponse.model_validate(
            get_arena_ingress_attestation(
                settings,
                recipient=ingress.recipient,
            )
        )
    if context == "compute_workload":
        from tinker_delegate.compute_workload_ingress import (
            get_compute_workload_attestation,
        )

        ingress = _get_compute_workload_ingress()
        return AttestationResponse.model_validate(
            get_compute_workload_attestation(
                settings,
                recipient=ingress.recipient,
            )
        )
    # Validate through the bounded response model here as well as at FastAPI's
    # serialization boundary.  Any undeclared lower-layer metadata is dropped.
    return AttestationResponse.model_validate(get_attestation(context))


@app.post("/auth/wallet/challenge", response_model=WalletChallengeResponse)
def wallet_auth_challenge(
    payload: WalletChallengeRequest,
    request: Request,
) -> WalletChallengeResponse:
    """Create a short-lived, deal-bound Ethereum personal-sign challenge."""
    try:
        _admit_wallet_challenge(request, payload.address)
        challenge = _wallet_auth_service().issue_challenge(
            address=payload.address,
            deal_id=payload.deal_id,
        )
        return WalletChallengeResponse.model_validate(challenge.to_public_dict())
    except WalletChallengeRateLimited as exc:
        _raise_wallet_challenge_rate_limit(exc.retry_after, exc)
    except WalletChallengeCapacityError as exc:
        _raise_wallet_challenge_rate_limit(
            _wallet_challenge_limiter.window_seconds,
            exc,
        )
    except WalletAuthUnavailable as exc:
        raise HTTPException(503, "Wallet authentication is unavailable") from exc
    except WalletAuthError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/auth/wallet/token", response_model=WalletTokenResponse)
def wallet_auth_token(payload: WalletTokenRequest) -> WalletTokenResponse:
    """Consume one signed challenge and issue a short-lived scoped token."""
    try:
        claims, token = _wallet_auth_service().exchange_signature(
            nonce=payload.nonce,
            signature=payload.signature,
        )
    except WalletAuthUnavailable as exc:
        raise HTTPException(503, "Wallet authentication is unavailable") from exc
    except WalletAuthError as exc:
        raise HTTPException(401, str(exc), headers={"WWW-Authenticate": "Bearer"}) from exc
    return WalletTokenResponse(
        access_token=token,
        address=claims.address,
        deal_id=claims.deal_id,
        scopes=list(claims.scopes),
        issued_at=claims.issued_at,
        expires_at=claims.expires_at,
    )


@app.post("/auth/arena/challenge", response_model=ArenaWalletChallengeResponse)
def arena_wallet_auth_challenge(
    payload: ArenaWalletChallengeRequest,
    request: Request,
) -> ArenaWalletChallengeResponse:
    """Create a challenge-version-bound Arena personal-sign challenge."""

    try:
        _admit_wallet_challenge(request, payload.address)
        _require_arena_challenge(payload.challenge_id, payload.challenge_version)
        challenge = _arena_wallet_auth_service().issue_challenge(
            address=payload.address,
            challenge_id=payload.challenge_id,
            challenge_version=payload.challenge_version,
        )
        return ArenaWalletChallengeResponse.model_validate(challenge.to_public_dict())
    except WalletChallengeRateLimited as exc:
        _raise_wallet_challenge_rate_limit(exc.retry_after, exc)
    except ArenaChallengeCapacityError as exc:
        _raise_wallet_challenge_rate_limit(
            _wallet_challenge_limiter.window_seconds,
            exc,
        )
    except ArenaAuthUnavailable as exc:
        raise HTTPException(503, "Arena wallet authentication is unavailable") from exc
    except (ArenaAuthError, WalletAuthError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/auth/arena/token", response_model=ArenaWalletTokenResponse)
def arena_wallet_auth_token(payload: ArenaWalletTokenRequest) -> ArenaWalletTokenResponse:
    """Exchange one signature for the exact short-lived Arena session scopes."""

    try:
        claims, token = _arena_wallet_auth_service().exchange_signature(
            nonce=payload.nonce,
            signature=payload.signature,
        )
    except ArenaAuthUnavailable as exc:
        raise HTTPException(503, "Arena wallet authentication is unavailable") from exc
    except ArenaAuthError as exc:
        raise HTTPException(
            401,
            str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return ArenaWalletTokenResponse(
        access_token=token,
        address=claims.address,
        challenge_id=claims.challenge_id,
        challenge_version=claims.challenge_version,
        scopes=list(claims.scopes),
        issued_at=claims.issued_at,
        expires_at=claims.expires_at,
    )


@app.post(
    "/auth/compute/challenge",
    response_model=ComputeWalletChallengeResponse,
)
def compute_wallet_auth_challenge(
    payload: ComputeWalletChallengeRequest,
    request: Request,
) -> ComputeWalletChallengeResponse:
    """Issue a Base Sepolia personal-sign challenge for the Compute Console."""

    try:
        _admit_wallet_challenge(request, payload.address)
        challenge = _compute_wallet_auth_service().issue_challenge(
            address=payload.address
        )
        return ComputeWalletChallengeResponse.model_validate(
            challenge.to_public_dict()
        )
    except WalletChallengeRateLimited as exc:
        _raise_wallet_challenge_rate_limit(exc.retry_after, exc)
    except ComputeChallengeCapacityError as exc:
        _raise_wallet_challenge_rate_limit(
            _wallet_challenge_limiter.window_seconds,
            exc,
        )
    except ComputeAuthUnavailable as exc:
        raise HTTPException(503, "Compute wallet authentication is unavailable") from exc
    except (ComputeAuthError, WalletAuthError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/auth/compute/token", response_model=ComputeWalletTokenResponse)
def compute_wallet_auth_token(
    payload: ComputeWalletTokenRequest,
) -> ComputeWalletTokenResponse:
    """Exchange a one-time wallet signature for a console-only bearer."""

    try:
        claims, token = _compute_wallet_auth_service().exchange_signature(
            nonce=payload.nonce,
            signature=payload.signature,
        )
    except ComputeAuthUnavailable as exc:
        raise HTTPException(503, "Compute wallet authentication is unavailable") from exc
    except ComputeAuthError as exc:
        raise HTTPException(
            401, str(exc), headers={"WWW-Authenticate": "Bearer"}
        ) from exc
    return ComputeWalletTokenResponse(
        access_token=token,
        address=claims.address,
        scopes=list(claims.scopes),
        issued_at=claims.issued_at,
        expires_at=claims.expires_at,
    )


_COMPUTE_DISPATCH_MUTATION_ROUTE = (
    "/compute/projects/{project_id}/dispatch-intents"
)
_COMPUTE_DISPATCH_STATUS_ROUTE_TEMPLATE = (
    "/compute/projects/{project_id}/dispatch-intents/{job_reference}"
)


def _compute_dispatch_capability() -> dict[str, Any]:
    """Return the single reviewed release gate for exact-asset dispatch."""

    return {
        "metadata_intent_creation": False,
        "provider_dispatch": False,
        "independent_metering": False,
        "settlement": False,
        "exact_asset_only": True,
        "mutation_route": None,
        "status_route_template": _COMPUTE_DISPATCH_STATUS_ROUTE_TEMPLATE,
        "reason": "idempotent_tinker_provider_adapter_unavailable",
    }


def _compute_dispatch_creation_enabled(capability: dict[str, Any]) -> bool:
    """Fail closed unless every independent release capability agrees."""

    return bool(
        capability.get("metadata_intent_creation") is True
        and capability.get("provider_dispatch") is True
        and capability.get("independent_metering") is True
        and capability.get("settlement") is True
        and capability.get("exact_asset_only") is True
        and capability.get("mutation_route") == _COMPUTE_DISPATCH_MUTATION_ROUTE
        and capability.get("status_route_template")
        == _COMPUTE_DISPATCH_STATUS_ROUTE_TEMPLATE
    )


def _project_with_compute_dispatch_capability(
    project: dict[str, Any],
) -> dict[str, Any]:
    """Project the same release gate onto every public project response."""

    result = dict(project)
    result["provider_dispatch_enabled"] = _compute_dispatch_creation_enabled(
        _compute_dispatch_capability()
    )
    return result


@app.get("/compute/funding-capabilities")
def compute_funding_capabilities():
    """Describe funding adapters without accepting any payment material."""

    return {
        "surface": "compute_funding_capabilities",
        "schema_version": 1,
        "card": {
            "enabled": False,
            "mutation_route": None,
            "reason": "signed_webhook_and_hosted_checkout_not_configured",
            "card_data_accepted": False,
            "distinct_from_exact_asset_capacity": True,
        },
        "usdc": {
            "enabled": False,
            "mutation_route": None,
            "reason": "release_generated_base_sepolia_vault_evidence_required",
            "capacity_model": "same_asset_nontransferable_vault_claim",
        },
        "eth": {
            "enabled": False,
            "mutation_route": None,
            "reason": "release_generated_base_sepolia_vault_evidence_required",
            "capacity_model": "same_asset_nontransferable_vault_claim",
        },
        "exact_asset_vault": {
            "contract": "ComputeCreditVault",
            "release_bound": True,
            "review_status": "reviewed_and_extensively_tested_not_formally_audited",
            "provider_dispatch_authoritative": False,
        },
        "dispatch_intents": _compute_dispatch_capability(),
        "operator_testnet_grants": {
            "enabled": True,
            "auth": "configured_runtime_bearer",
            "cash_value": False,
        },
        "credits": {
            "kind": "closed_loop_service_credit",
            "transferable": False,
            "redeemable": False,
            "onchain_token": False,
            "nominal_usd_cents_per_credit": 1,
            "legacy_modeled_ledger": True,
            "distinct_from_exact_asset_vault": True,
        },
    }


@app.get("/compute/workload-encryption-contract")
def compute_workload_encryption_contract(response: Response):
    """Publish only the exact recipient and browser encryption contract.

    A configured local recipient remains visible as blocked. Upload becomes
    live only when the service can authenticate a fresh independent TDX
    verdict for the exact dstack-derived recipient and release.
    """

    response.headers["Cache-Control"] = "no-store"
    try:
        return _get_compute_workload_ingress().public_capability()
    except HTTPException:
        raise
    except Exception as exc:
        from tinker_delegate.compute_workload_ingress import (
            ComputeWorkloadIngressCorrupt,
            ComputeWorkloadIngressUnavailable,
        )

        if isinstance(
            exc,
            (ComputeWorkloadIngressCorrupt, ComputeWorkloadIngressUnavailable, OSError),
        ):
            raise HTTPException(503, "Compute workload ingress is unavailable") from exc
        raise


def _compute_workload_project_principal(
    project_id: str,
    authorization: str,
    *,
    required_scope: str,
    require_write_role: bool,
):
    """Bind one wallet membership or purpose-scoped device to one project."""

    from tinker_delegate.compute_workload_ingress import ComputeWorkloadPrincipal

    authenticated = _require_compute_job_principal(
        authorization,
        required_scope=required_scope,
    )
    if authenticated["kind"] == "credential":
        if authenticated["project_id"] != project_id:
            raise HTTPException(403, "credential is bound to a different project")
        return ComputeWorkloadPrincipal(
            kind="credential",
            project_id=project_id,
            actor_id=authenticated["credential_id"],
        )
    project = _get_compute_store().project(
        project_id,
        authenticated["wallet_address"],
    )
    if require_write_role and project["role"] not in {"owner", "admin", "developer"}:
        raise HTTPException(403, "project role cannot create Compute workloads")
    return ComputeWorkloadPrincipal(
        kind="wallet",
        project_id=project_id,
        actor_id=authenticated["wallet_address"],
    )


def _raise_compute_workload_error(exc: Exception, *, missing_is_404: bool = False):
    from tinker_delegate.compute_workload_ingress import (
        ComputeWorkloadIngressConflict,
        ComputeWorkloadIngressCorrupt,
        ComputeWorkloadIngressError,
        ComputeWorkloadIngressUnavailable,
    )

    if isinstance(exc, ComputeWorkloadIngressConflict):
        raise HTTPException(409, str(exc)) from exc
    if isinstance(exc, (ComputeWorkloadIngressCorrupt, ComputeWorkloadIngressUnavailable, OSError)):
        raise HTTPException(503, "Compute workload ingress is unavailable") from exc
    if isinstance(exc, ComputeWorkloadIngressError):
        raise HTTPException(404 if missing_is_404 else 400, str(exc)) from exc
    _raise_compute_store_error(exc)


@app.post("/compute/projects/{project_id}/workloads")
def compute_create_workload(
    project_id: str,
    payload: ComputeWorkloadCreateRequest,
    authorization: str = Header(default=""),
    idempotency_key: str = Header(default="", alias="Idempotency-Key"),
):
    """Persist one attestation-bound ciphertext envelope, never private input."""

    from tinker_delegate.compute_workload_ingress import (
        ComputeWorkloadManifest,
    )

    try:
        principal = _compute_workload_project_principal(
            project_id,
            authorization,
            required_scope="workloads:create",
            require_write_role=True,
        )
        manifest = ComputeWorkloadManifest.from_mapping(
            payload.manifest.model_dump(by_alias=True)
        )
        result = _get_compute_workload_ingress().ingest(
            principal=principal,
            manifest=manifest,
            workload_commitment=payload.workload_commitment,
            idempotency_key=idempotency_key,
            envelope=payload.envelope.model_dump(),
        )
        return result.to_public_dict()
    except HTTPException:
        raise
    except Exception as exc:
        _raise_compute_workload_error(exc)


@app.get("/compute/projects/{project_id}/workloads/{workload_id}")
def compute_get_workload_metadata(
    project_id: str,
    workload_id: str,
    authorization: str = Header(default=""),
):
    """Return project-authorized commitments and caps; ciphertext never egresses."""

    try:
        principal = _compute_workload_project_principal(
            project_id,
            authorization,
            required_scope="jobs:read",
            require_write_role=False,
        )
        return _get_compute_workload_ingress().store.public_metadata(
            workload_id,
            project_commitment=principal.project_commitment,
        )
    except HTTPException:
        raise
    except Exception as exc:
        _raise_compute_workload_error(exc, missing_is_404=True)


@app.delete("/compute/projects/{project_id}/workloads/{workload_id}")
def compute_delete_workload(
    project_id: str,
    workload_id: str,
    authorization: str = Header(default=""),
):
    """Durably erase an unconsumed ciphertext envelope; no ciphertext egress."""

    try:
        principal = _compute_workload_project_principal(
            project_id,
            authorization,
            required_scope="workloads:delete",
            require_write_role=True,
        )
        consumed = _get_compute_workload_ingress().store.consume_ciphertext_for_project(
            workload_id,
            project_commitment=principal.project_commitment,
        )
        del consumed
        return {
            "surface": "compute_workload_deletion",
            "schema_version": 1,
            "workload_id": workload_id,
            "deleted": True,
            "ciphertext_egress": False,
            "raw_workload_egress": False,
            "provider_dispatch_performed": False,
        }
    except HTTPException:
        raise
    except Exception as exc:
        _raise_compute_workload_error(exc, missing_is_404=True)


@app.post("/compute/projects")
def compute_create_project(
    payload: ComputeProjectCreateRequest,
    authorization: str = Header(default=""),
    idempotency_key: str = Header(default="", alias="Idempotency-Key"),
):
    """Create a wallet-owned project with immutable conservative policy caps."""

    import time as _time

    claims = _require_compute_wallet_auth(authorization)
    try:
        project, created = _get_compute_store().create_project(
            owner_address=claims.address,
            name=payload.name,
            idempotency_key=idempotency_key,
            created_at=int(_time.time()),
        )
        return {
            "surface": "compute_project_result",
            "created": created,
            "idempotent_replay": not created,
            "project": _project_with_compute_dispatch_capability(project),
        }
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.get("/compute/projects")
def compute_list_projects(authorization: str = Header(default="")):
    claims = _require_compute_wallet_auth(authorization)
    try:
        return {
            "surface": "compute_projects",
            "schema_version": 1,
            "projects": [
                _project_with_compute_dispatch_capability(project)
                for project in _get_compute_store().list_projects(claims.address)
            ],
        }
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.get("/compute/projects/{project_id}")
def compute_get_project(
    project_id: str,
    authorization: str = Header(default=""),
):
    claims = _require_compute_wallet_auth(authorization)
    try:
        return _project_with_compute_dispatch_capability(
            _get_compute_store().project(project_id, claims.address)
        )
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.post("/compute/projects/{project_id}/members")
def compute_add_project_member(
    project_id: str,
    payload: ComputeMemberRequest,
    authorization: str = Header(default=""),
):
    import time as _time

    claims = _require_compute_wallet_auth(authorization)
    try:
        return _project_with_compute_dispatch_capability(
            _get_compute_store().add_member(
                project_id,
                actor_address=claims.address,
                member_address=payload.address,
                role=payload.role,
                updated_at=int(_time.time()),
            )
        )
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.delete("/compute/projects/{project_id}/members/{member_address}")
def compute_remove_project_member(
    project_id: str,
    member_address: str,
    authorization: str = Header(default=""),
):
    import time as _time

    claims = _require_compute_wallet_auth(authorization)
    try:
        return _project_with_compute_dispatch_capability(
            _get_compute_store().remove_member(
                project_id,
                actor_address=claims.address,
                member_address=member_address,
                updated_at=int(_time.time()),
            )
        )
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.post("/compute/projects/{project_id}/devices")
def compute_register_device(
    project_id: str,
    payload: ComputeDeviceRegisterRequest,
    authorization: str = Header(default=""),
):
    import time as _time

    claims = _require_compute_wallet_auth(authorization)
    try:
        device = _get_compute_store().register_device(
            project_id,
            actor_address=claims.address,
            label=payload.label,
            kind=payload.kind,
            public_key_hex=payload.public_key,
            registered_at=int(_time.time()),
        )
        return {"surface": "compute_device", "device": device}
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.get("/compute/projects/{project_id}/devices")
def compute_list_devices(
    project_id: str,
    authorization: str = Header(default=""),
):
    claims = _require_compute_wallet_auth(authorization)
    try:
        return {
            "surface": "compute_devices",
            "devices": _get_compute_store().list_devices(project_id, claims.address),
        }
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.post("/compute/projects/{project_id}/devices/{device_id}/revoke")
def compute_revoke_device(
    project_id: str,
    device_id: str,
    authorization: str = Header(default=""),
):
    import time as _time

    claims = _require_compute_wallet_auth(authorization)
    try:
        device = _get_compute_store().revoke_device(
            project_id,
            actor_address=claims.address,
            device_id=device_id,
            revoked_at=int(_time.time()),
        )
        return {"surface": "compute_device", "device": device}
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.post("/compute/projects/{project_id}/credentials")
def compute_issue_credential(
    project_id: str,
    payload: ComputeCredentialIssueRequest,
    authorization: str = Header(default=""),
):
    """Issue a scoped token encrypted to a registered X25519 device key."""

    import secrets as _secrets
    import time as _time

    claims = _require_compute_wallet_auth(authorization)
    store = _get_compute_store()
    try:
        device = store.device_for_issuance(
            project_id,
            actor_address=claims.address,
            device_id=payload.device_id,
        )
        now = int(_time.time())
        expires_at = now + payload.expires_in_seconds
        credential_id = f"cred_{_secrets.token_hex(12)}"
        normalized_scopes = normalize_compute_scopes(payload.scopes)
        credential_claims, token = issue_compute_credential_token(
            settings,
            credential_id=credential_id,
            project_id=project_id,
            device_id=payload.device_id,
            generation=1,
            scopes=normalized_scopes,
            daily_credit_cap=payload.daily_credit_cap,
            expires_at=expires_at,
            now=now,
        )
        public_key_hex = device["public_key_hex"]
        capsule = encrypt_compute_credential_token(
            token,
            recipient_public_key_hex=public_key_hex,
            claims=credential_claims,
        )
        jwt_id_hash = hashlib.sha256(
            b"compute_credential_jti:" + credential_claims.jwt_id.encode()
        ).hexdigest()
        credential = store.create_credential(
            project_id,
            actor_address=claims.address,
            credential_id=credential_id,
            device_id=payload.device_id,
            name=payload.name,
            scopes=normalized_scopes,
            daily_credit_cap=payload.daily_credit_cap,
            generation=1,
            jwt_id_hash=jwt_id_hash,
            issued_at=now,
            expires_at=expires_at,
        )
        return {
            "surface": "compute_credential_issuance",
            "schema_version": 1,
            "credential": credential,
            "capsule": capsule,
            "plaintext_token_returned": False,
            "upstream_tinker_key_exposed": False,
        }
    except ComputeAuthUnavailable as exc:
        raise HTTPException(503, "Compute credential issuance is unavailable") from exc
    except ComputeAuthError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.get("/compute/projects/{project_id}/credentials")
def compute_list_credentials(
    project_id: str,
    authorization: str = Header(default=""),
):
    import time as _time

    claims = _require_compute_wallet_auth(authorization)
    try:
        return {
            "surface": "compute_credentials",
            "credentials": _get_compute_store().list_credentials(
                project_id, claims.address, now=int(_time.time())
            ),
        }
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.post(
    "/compute/projects/{project_id}/credentials/{credential_id}/rotate"
)
def compute_rotate_credential(
    project_id: str,
    credential_id: str,
    payload: ComputeCredentialRotateRequest,
    authorization: str = Header(default=""),
):
    import time as _time

    claims = _require_compute_wallet_auth(authorization)
    store = _get_compute_store()
    try:
        current, device = store.credential_for_rotation(
            project_id,
            actor_address=claims.address,
            credential_id=credential_id,
        )
        now = int(_time.time())
        expires_at = now + payload.expires_in_seconds
        credential_claims, token = issue_compute_credential_token(
            settings,
            credential_id=credential_id,
            project_id=project_id,
            device_id=current["device_id"],
            generation=current["generation"] + 1,
            scopes=current["scopes"],
            daily_credit_cap=current["daily_credit_cap"],
            expires_at=expires_at,
            now=now,
        )
        capsule = encrypt_compute_credential_token(
            token,
            recipient_public_key_hex=device["public_key_hex"],
            claims=credential_claims,
        )
        jwt_id_hash = hashlib.sha256(
            b"compute_credential_jti:" + credential_claims.jwt_id.encode()
        ).hexdigest()
        credential = store.rotate_credential(
            project_id,
            actor_address=claims.address,
            credential_id=credential_id,
            expected_generation=current["generation"],
            new_jwt_id_hash=jwt_id_hash,
            issued_at=now,
            expires_at=expires_at,
        )
        return {
            "surface": "compute_credential_rotation",
            "credential": credential,
            "capsule": capsule,
            "prior_generation_revoked": True,
            "plaintext_token_returned": False,
        }
    except ComputeAuthUnavailable as exc:
        raise HTTPException(503, "Compute credential rotation is unavailable") from exc
    except ComputeAuthError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.post(
    "/compute/projects/{project_id}/credentials/{credential_id}/revoke"
)
def compute_revoke_credential(
    project_id: str,
    credential_id: str,
    authorization: str = Header(default=""),
):
    import time as _time

    claims = _require_compute_wallet_auth(authorization)
    try:
        credential = _get_compute_store().revoke_credential(
            project_id,
            actor_address=claims.address,
            credential_id=credential_id,
            revoked_at=int(_time.time()),
        )
        return {"surface": "compute_credential", "credential": credential}
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.get("/compute/projects/{project_id}/balance")
def compute_project_balance(
    project_id: str,
    authorization: str = Header(default=""),
):
    claims = _require_compute_wallet_auth(authorization)
    try:
        return _get_compute_store().balance(project_id, claims.address)
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.get("/compute/projects/{project_id}/ledger")
def compute_project_ledger(
    project_id: str,
    limit: int = 100,
    authorization: str = Header(default=""),
):
    claims = _require_compute_wallet_auth(authorization)
    try:
        return _get_compute_store().ledger(
            project_id, claims.address, limit=limit
        )
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.post("/compute/projects/{project_id}/dispatch-intents")
def compute_create_dispatch_intent(
    project_id: str,
    payload: ComputeDispatchIntentRequest,
    authorization: str = Header(default=""),
    idempotency_key: str = Header(default="", alias="Idempotency-Key"),
):
    """Queue an exact-asset chain intent without reserving legacy credits.

    ``project_id`` remains the console's human-readable project reference. The
    response includes its byte-for-byte web-compatible ``bytes32`` chain ID.
    """

    import time as _time

    from tinker_delegate.compute_runtime import (
        ComputeDispatchIntent,
        ComputeIntentConflict,
        ComputeRuntimePolicyError,
        ComputeRuntimeStateError,
    )

    claims = _require_compute_wallet_auth(authorization)
    now = int(_time.time())
    try:
        # Membership is read from the existing console directory only. No
        # balance, reservation, job, or ledger method is called on that store.
        project = _project_with_compute_dispatch_capability(
            _get_compute_store().project(project_id, claims.address)
        )
        if project["role"] not in {"owner", "admin", "developer"}:
            raise HTTPException(403, "project role cannot create dispatch intents")
        if project["provider_dispatch_enabled"] is not True:
            raise HTTPException(
                503,
                "Exact-asset dispatch intent creation is disabled by this release",
            )
        if (
            payload.authorization_expiry <= now
            or payload.authorization_expiry > now + 30 * 24 * 60 * 60
        ):
            raise HTTPException(
                400, "authorization expiry must be future and at most 30 days"
            )
        from tinker_delegate.compute_workload_ingress import (
            ComputeWorkloadPrincipal,
        )

        workload_ingress = _get_compute_workload_ingress()
        workload_principal = ComputeWorkloadPrincipal(
            kind="wallet",
            project_id=project_id,
            actor_id=claims.address,
        )
        current_activation = workload_ingress.current_activation()
        stored_workload = workload_ingress.store.get_for_project(
            payload.workload_id,
            project_commitment=workload_principal.project_commitment,
        )
        workload_binding = stored_workload.binding
        workload_manifest = workload_binding.manifest
        if (
            workload_binding.recipient_key_id != workload_ingress.recipient.key_id
            or workload_binding.activation_commitment
            != current_activation.commitment
        ):
            raise HTTPException(
                503,
                "Compute workload recipient activation is no longer current",
            )
        if (
            workload_manifest.operation != payload.operation
            or workload_manifest.model != payload.model
            or workload_manifest.recipe != payload.recipe
            or workload_manifest.max_prefill_tokens != payload.max_prefill_tokens
            or workload_manifest.max_sample_tokens != payload.max_sample_tokens
            or workload_manifest.max_train_tokens != payload.max_train_tokens
        ):
            raise HTTPException(
                400,
                "Compute workload manifest does not match exact dispatch metadata",
            )
        intent = ComputeDispatchIntent.create(
            project_reference=project_id,
            job_reference=payload.job_reference,
            user=claims.address,
            asset=payload.asset,
            authorization_nonce=payload.authorization_nonce,
            max_asset_debit=payload.max_asset_debit,
            authorization_expiry=payload.authorization_expiry,
            rate_policy_commitment=payload.rate_policy_commitment,
            compose_hash=payload.compose_hash,
            operation=payload.operation,
            model=payload.model,
            recipe=payload.recipe,
            result_policy=payload.result_policy,
            max_prefill_tokens=payload.max_prefill_tokens,
            max_sample_tokens=payload.max_sample_tokens,
            max_train_tokens=payload.max_train_tokens,
            workload_id=stored_workload.workload_id,
            workload_schema=workload_manifest.schema,
            manifest_commitment=(
                "0x" + workload_binding.manifest_commitment.removeprefix("sha256:")
            ),
            workload_commitment=(
                "0x" + workload_binding.workload_commitment.removeprefix("sha256:")
            ),
        )
        record, created = _get_compute_dispatch_journal().enqueue(
            intent,
            idempotency_key=idempotency_key,
            created_at=now,
        )
        return {
            "surface": "compute_dispatch_intent_result",
            "schema_version": 2,
            "created": created,
            "idempotent_replay": not created,
            "intent": record,
            "legacy_credit_ledger_mutated": False,
            "provider_dispatch_status": record["provider_dispatch_status"],
            "provider_dispatch_may_have_occurred": record[
                "provider_dispatch_may_have_occurred"
            ],
            "provider_authoritative": False,
        }
    except HTTPException:
        raise
    except ComputeIntentConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ComputeRuntimePolicyError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ComputeRuntimeStateError as exc:
        raise HTTPException(503, "Exact-asset dispatch journal is unavailable") from exc
    except Exception as exc:
        from tinker_delegate.compute_workload_ingress import (
            ComputeWorkloadIngressError,
            ComputeWorkloadIngressUnavailable,
        )

        if isinstance(exc, (ComputeWorkloadIngressError, ComputeWorkloadIngressUnavailable)):
            _raise_compute_workload_error(exc)
        _raise_compute_store_error(exc)


@app.get(
    "/compute/projects/{project_id}/dispatch-intents/{job_reference}"
)
def compute_get_dispatch_intent(
    project_id: str,
    job_reference: str,
    authorization: str = Header(default=""),
):
    """Return bounded exact-asset status; never provider IDs or private input."""

    from tinker_delegate.compute_runtime import (
        ComputeIntentNotFound,
        ComputeRuntimePolicyError,
        ComputeRuntimeStateError,
        canonical_compute_job_id,
    )

    claims = _require_compute_wallet_auth(authorization)
    try:
        _get_compute_store().project(project_id, claims.address)
        record = _get_compute_dispatch_journal().public_get(
            canonical_compute_job_id(job_reference)
        )
        if record["project_reference"] != project_id:
            raise ComputeIntentNotFound("dispatch intent not found")
        return record
    except ComputeIntentNotFound as exc:
        raise HTTPException(404, "Exact-asset dispatch intent not found") from exc
    except ComputeRuntimePolicyError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ComputeRuntimeStateError as exc:
        raise HTTPException(503, "Exact-asset dispatch journal is unavailable") from exc
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.post("/compute/projects/{project_id}/jobs")
def compute_create_job(
    project_id: str,
    payload: ComputeJobCreateRequest,
    authorization: str = Header(default=""),
    idempotency_key: str = Header(default="", alias="Idempotency-Key"),
):
    """Reserve credits and create metadata only; no provider call is made."""

    import time as _time

    principal = _require_compute_job_principal(
        authorization, required_scope="jobs:create"
    )
    if principal["kind"] == "credential" and principal["project_id"] != project_id:
        raise HTTPException(403, "credential is bound to a different project")
    try:
        job, created = _get_compute_store().create_job(
            project_id,
            actor_kind=principal["kind"],
            actor_id=principal.get("wallet_address", principal.get("credential_id", "")),
            credential_id=principal.get("credential_id"),
            name=payload.name,
            operation=payload.operation,
            model=payload.model,
            recipe=payload.recipe,
            max_credits=payload.max_credits,
            result_policy=payload.result_policy,
            environment_version=payload.environment_version,
            idempotency_key=idempotency_key,
            created_at=int(_time.time()),
        )
        return {
            "surface": "compute_job_result",
            "created": created,
            "idempotent_replay": not created,
            "job": job,
            "provider_dispatch_performed": False,
        }
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.get("/compute/projects/{project_id}/jobs")
def compute_list_jobs(
    project_id: str,
    limit: int = 100,
    authorization: str = Header(default=""),
):
    principal = _require_compute_job_principal(
        authorization, required_scope="jobs:read"
    )
    if principal["kind"] == "credential" and principal["project_id"] != project_id:
        raise HTTPException(403, "credential is bound to a different project")
    try:
        return {
            "surface": "compute_jobs",
            "schema_version": 1,
            "jobs": _get_compute_store().jobs(
                project_id,
                wallet_address=principal.get("wallet_address"),
                credential_id=principal.get("credential_id"),
                limit=limit,
            ),
        }
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.get("/compute/projects/{project_id}/jobs/{job_id}")
def compute_get_job(
    project_id: str,
    job_id: str,
    authorization: str = Header(default=""),
):
    principal = _require_compute_job_principal(
        authorization, required_scope="jobs:read"
    )
    if principal["kind"] == "credential" and principal["project_id"] != project_id:
        raise HTTPException(403, "credential is bound to a different project")
    try:
        return _get_compute_store().job(
            project_id,
            job_id,
            wallet_address=principal.get("wallet_address"),
            credential_id=principal.get("credential_id"),
        )
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.post(
    "/compute/projects/{project_id}/jobs/{job_id}/cancel",
    response_model=ComputeJobCancelResponse,
)
def compute_cancel_job(
    project_id: str,
    job_id: str,
    payload: ComputeJobCancelRequest,
    authorization: str = Header(default=""),
    idempotency_key: str = Header(default="", alias="Idempotency-Key"),
) -> ComputeJobCancelResponse:
    """Release only a wallet-authorized, never-dispatched queued reservation."""

    import time as _time

    # Device credentials intentionally cannot cancel project reservations. A
    # current owner/admin/developer wallet membership is checked again inside
    # the same store lock that commits the reversal.
    claims = _require_compute_wallet_auth(authorization)
    try:
        job, transaction, changed = _get_compute_store().cancel_queued_job(
            project_id,
            job_id,
            actor_address=claims.address,
            reason=payload.reason,
            idempotency_key=idempotency_key,
            canceled_at=int(_time.time()),
        )
        return ComputeJobCancelResponse(
            surface="compute_job_cancellation",
            schema_version=1,
            project_id=project_id,
            job_id=job_id,
            status="canceled",
            changed=changed,
            idempotent_replay=not changed,
            released_credits=job["released_credits"],
            credit_reversal="reserved_to_available",
            ledger=ComputeJobCancelLedgerReceipt(
                transaction_id=transaction["transaction_id"],
                sequence=transaction["sequence"],
                kind="job_cancel",
                transaction_hash=transaction["transaction_hash"],
                previous_hash=transaction["previous_hash"],
                settlement_status="user_canceled_before_dispatch",
            ),
            provider_dispatch_performed=False,
            service_settlement_performed=False,
        )
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.post("/compute/internal/projects/{project_id}/grants")
def compute_internal_grant(
    project_id: str,
    payload: ComputeGrantRequest,
    authorization: str = Header(default=""),
    idempotency_key: str = Header(default="", alias="Idempotency-Key"),
):
    import time as _time

    _require_configured_runtime_auth(authorization)
    try:
        transaction, created = _get_compute_store().grant_credits(
            project_id,
            amount_credits=payload.amount_credits,
            reason=payload.reason,
            idempotency_key=idempotency_key,
            granted_at=int(_time.time()),
        )
        return {
            "surface": "compute_testnet_grant",
            "created": created,
            "idempotent_replay": not created,
            "transaction": transaction,
            "cash_value": False,
        }
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.post("/compute/internal/projects/{project_id}/jobs/{job_id}/start")
def compute_internal_start_job(
    project_id: str,
    job_id: str,
    authorization: str = Header(default=""),
    idempotency_key: str = Header(default="", alias="Idempotency-Key"),
):
    import time as _time

    _require_configured_runtime_auth(authorization)
    compute_store = _get_compute_store()
    try:
        execution_context_hash = compute_store.execution_policy_context_hash(
            job_id
        )
    except Exception as exc:
        _raise_compute_store_error(exc)
    with _authorized_execution_policy_lease(
        "compute_dispatch",
        job_id,
        expected_execution_context_hash=execution_context_hash,
    ):
        try:
            job, changed = compute_store.start_job(
                project_id,
                job_id,
                idempotency_key=idempotency_key,
                started_at=int(_time.time()),
            )
            return {
                "surface": "compute_job_transition",
                "changed": changed,
                "idempotent_replay": not changed,
                "job": job,
                "provider_dispatch_performed": False,
            }
        except Exception as exc:
            _raise_compute_store_error(exc)


@app.post("/compute/internal/projects/{project_id}/jobs/{job_id}/settle")
def compute_internal_settle_job(
    project_id: str,
    job_id: str,
    payload: ComputeJobSettleRequest,
    authorization: str = Header(default=""),
    idempotency_key: str = Header(default="", alias="Idempotency-Key"),
):
    import time as _time

    _require_configured_runtime_auth(authorization)
    try:
        job, changed = _get_compute_store().settle_job(
            project_id,
            job_id,
            actual_credits=payload.actual_credits,
            usage_receipt_hash=payload.usage_receipt_hash,
            metering_source=payload.metering_source,
            idempotency_key=idempotency_key,
            settled_at=int(_time.time()),
        )
        return {
            "surface": "compute_job_transition",
            "changed": changed,
            "idempotent_replay": not changed,
            "job": job,
            "provider_authoritative_settlement": False,
        }
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.post("/compute/internal/projects/{project_id}/jobs/{job_id}/release")
def compute_internal_release_job(
    project_id: str,
    job_id: str,
    payload: ComputeJobReleaseRequest,
    authorization: str = Header(default=""),
    idempotency_key: str = Header(default="", alias="Idempotency-Key"),
):
    import time as _time

    _require_configured_runtime_auth(authorization)
    try:
        job, changed = _get_compute_store().release_job(
            project_id,
            job_id,
            terminal_status=payload.terminal_status,
            reason=payload.reason,
            idempotency_key=idempotency_key,
            released_at=int(_time.time()),
        )
        return {
            "surface": "compute_job_transition",
            "changed": changed,
            "idempotent_replay": not changed,
            "job": job,
        }
    except Exception as exc:
        _raise_compute_store_error(exc)


@app.get("/arena/candidate-encryption-contract")
def arena_candidate_encryption_contract(response: Response):
    """Return the current recipient and byte-exact browser encryption rules."""

    from tinker_delegate.arena_ingress import arena_candidate_browser_contract

    # Recipient keys can change on a fresh CVM.  A browser must not reuse a
    # cached contract across an attestation/deployment boundary.
    response.headers["Cache-Control"] = "no-store, max-age=0"
    ingress = _get_arena_ingress()
    return arena_candidate_browser_contract(
        ingress.recipient,
        max_envelopes=ingress.store.max_envelopes,
    )


@app.get("/arena/challenges")
def arena_challenge_catalog():
    """Return only the allowlisted, versioned public challenge catalog."""

    from tinker_delegate.arena_store import default_challenge_catalog

    if not str(settings.arena_store_path or "").strip():
        return default_challenge_catalog().to_public_dict()
    return _get_arena_store().public_catalog()


@app.get("/arena/challenges/{challenge_id}/versions/{challenge_version}")
def arena_challenge_manifest(challenge_id: str, challenge_version: str):
    """Return one immutable public challenge manifest by exact version."""

    from tinker_delegate.arena_store import ArenaStoreError, default_challenge_catalog

    try:
        challenge = default_challenge_catalog().get(challenge_id, challenge_version)
    except ArenaStoreError as exc:
        raise HTTPException(status_code=404, detail="Unknown Arena challenge version") from exc
    if str(settings.arena_store_path or "").strip():
        # Fail closed on configured persistence corruption/catalog drift even
        # though the manifest itself is built into the image.
        _get_arena_store()
    return challenge.to_public_dict()


@app.post(
    "/arena/challenges/{challenge_id}/versions/{challenge_version}/submissions"
)
def arena_create_submission(
    challenge_id: str,
    challenge_version: str,
    payload: ArenaSubmissionCreateRequest,
    authorization: str = Header(default=""),
    idempotency_key: str = Header(default="", alias="Idempotency-Key"),
):
    """Persist browser ciphertext, then queue its server-generated sealed ref.

    The wallet token is bound to this exact challenge version. The API derives
    the identity from that token, uses server time, never accepts a source/code
    or caller-supplied object-reference field, and returns only public
    projections without the sealed reference.
    """

    import time as _time

    from tinker_delegate.arena_store import (
        ArenaIdempotencyConflict,
        ArenaStoreError,
        SubmissionIdentity,
        SubmissionManifest,
    )
    from tinker_delegate.arena_ingress import (
        ArenaIngressConflict,
        ArenaIngressCorruptError,
        ArenaIngressError,
        ArenaIngressUnavailable,
    )
    from tinker_delegate.arena_registry_admission import (
        ArenaRegistryAdmissionError,
        ArenaRegistryAuthorizationSnapshot,
        authorize_arena_registry_submission,
    )

    # Resolve the immutable in-image catalog without constructing either
    # durable store. Registry authorization below must precede even an empty
    # Arena store/index initialization write.
    from tinker_delegate.arena_store import default_challenge_catalog

    try:
        challenge = default_challenge_catalog().get(
            challenge_id, challenge_version
        )
    except ArenaStoreError as exc:
        raise HTTPException(
            status_code=404, detail="Unknown Arena challenge version"
        ) from exc
    claims = _require_arena_wallet_auth(
        authorization,
        challenge_id=challenge_id,
        challenge_version=challenge_version,
    )
    # There is not yet a project-membership registry, so the first slice uses a
    # deterministic personal project ID rather than trusting a caller-supplied
    # organization/project claim.
    project_id = "personal-" + hashlib.sha256(
        b"arena-personal-project:" + claims.address.encode("ascii")
    ).hexdigest()[:32]
    identity = SubmissionIdentity(
        wallet_address=claims.address,
        project_id=project_id,
    )
    try:
        manifest = SubmissionManifest.from_mapping(payload.manifest.model_dump())
    except ArenaStoreError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # The browser snapshot is a cryptographically bound proposal, not an
    # authority statement.  Resolve release pins and independently re-read the
    # exact finalized Base Sepolia block before constructing the ingress store
    # (which may create durable key/index files) or writing the queue store.
    try:
        registry_snapshot = ArenaRegistryAuthorizationSnapshot.from_mapping(
            payload.registry_authorization.model_dump()
        )
        registry_authorization = authorize_arena_registry_submission(
            settings,
            challenge=challenge,
            snapshot=registry_snapshot,
        )
    except ArenaRegistryAdmissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Arena registry admission is unavailable",
        ) from exc

    ingress = _get_arena_ingress()
    try:
        ingress_result = ingress.ingest(
            challenge=challenge,
            identity=identity,
            candidate_commitment=payload.candidate_commitment,
            manifest=manifest,
            idempotency_key=idempotency_key,
            registry_authorization_sha256=(
                registry_authorization.snapshot_sha256
            ),
            envelope=payload.envelope.model_dump(),
        )
    except ArenaIngressConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (ArenaIngressCorruptError, ArenaIngressUnavailable, OSError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Arena candidate ingress is unavailable",
        ) from exc
    except ArenaIngressError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    store = _get_arena_store()
    try:
        result = store.submit(
            challenge_id=challenge_id,
            challenge_version=challenge_version,
            identity=identity,
            candidate_commitment=payload.candidate_commitment,
            encrypted_reference=ingress_result.sealed_reference,
            manifest=manifest,
            idempotency_key=idempotency_key,
            submitted_at=int(_time.time()),
        )
    except ArenaIdempotencyConflict as exc:
        _rollback_arena_ingress_or_503(ingress, ingress_result)
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ArenaStoreError as exc:
        _rollback_arena_ingress_or_503(ingress, ingress_result)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        _rollback_arena_ingress_or_503(ingress, ingress_result)
        raise HTTPException(503, "Arena durable store write failed") from exc
    return {
        "surface": "arena_submission_result",
        "created": result.created,
        "idempotent_replay": not result.created,
        # This receipt covers only the exact proxy-side finalized-block check.
        # Queue acceptance still cannot authorize a worker execution; the
        # worker must repeat its independent release, registry, TDX/QVL, and
        # execution-policy gates when claiming the job.
        "registry_ingress_boundary": (
            registry_authorization.to_public_dict()
        ),
        "candidate_ingress": ingress_result.to_public_dict(),
        "submission": store.public_submission(result.submission.submission_id),
        "raw_candidate_accepted": False,
        "encrypted_reference_egress": False,
        "raw_secret_egress": False,
    }


@app.get("/arena/submissions/{submission_id}")
def arena_public_submission(submission_id: str):
    """Return one bounded public submission projection."""

    from tinker_delegate.arena_store import ArenaStoreError

    try:
        return _get_arena_store().public_submission(submission_id)
    except ArenaStoreError as exc:
        raise HTTPException(status_code=404, detail="Unknown Arena submission") from exc


@app.get(
    "/arena/challenges/{challenge_id}/versions/{challenge_version}/queue"
)
def arena_public_queue(
    challenge_id: str,
    challenge_version: str,
    limit: int = 100,
):
    """Return a bounded queue projection without encrypted object references."""

    from tinker_delegate.arena_store import ArenaStoreError

    _require_arena_challenge(challenge_id, challenge_version)
    try:
        return _get_arena_store().public_queue(
            challenge_id,
            challenge_version,
            limit=limit,
        )
    except ArenaStoreError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get(
    "/arena/challenges/{challenge_id}/versions/{challenge_version}/leaderboard"
)
def arena_public_leaderboard(
    challenge_id: str,
    challenge_version: str,
    limit: int = 100,
):
    """Return accepted, quantized Ladder improvements only; no exact scores."""

    from tinker_delegate.arena_store import ArenaStoreError

    _require_arena_challenge(challenge_id, challenge_version)
    try:
        return _get_arena_store().public_leaderboard(
            challenge_id,
            challenge_version,
            limit=limit,
        )
    except ArenaStoreError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get(
    "/arena/challenges/{challenge_id}/versions/{challenge_version}/submissions/mine"
)
def arena_owner_submissions(
    challenge_id: str,
    challenge_version: str,
    response: Response,
    limit: int = 25,
    cursor: str | None = None,
    authorization: str = Header(default=""),
):
    """Return a bounded page selected only by the authenticated wallet claim."""

    from tinker_delegate.arena_store import ArenaStoreError

    _require_arena_challenge(challenge_id, challenge_version)
    claims = _require_arena_wallet_auth(
        authorization,
        challenge_id=challenge_id,
        challenge_version=challenge_version,
        required_scope=ARENA_OWNER_READ_SCOPE,
    )
    response.headers["Cache-Control"] = "no-store, max-age=0"
    try:
        return _get_arena_store().owner_submissions(
            wallet_address=claims.address,
            challenge_id=challenge_id,
            challenge_version=challenge_version,
            limit=limit,
            cursor=cursor,
        )
    except ArenaStoreError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _project_arena_worker_capability(
    challenge_id: str,
    challenge_version: str,
):
    """Build a fresh fail-closed projection without accepting caller evidence."""

    import time as _time

    from tinker_delegate.arena_worker_evidence import (
        ArenaWorkerEvidenceError,
        ArenaWorkerHeartbeatStore,
        arena_worker_expected_release_bindings,
        arena_worker_heartbeat_integrity_key,
        project_arena_worker_capability,
    )

    enabled = bool(settings.arena_worker_live_capability_enabled)
    expected = None
    heartbeat_store = None
    if enabled:
        try:
            expected = arena_worker_expected_release_bindings(settings)
        except Exception:
            expected = None
        if expected is not None:
            try:
                heartbeat_store = ArenaWorkerHeartbeatStore(
                    str(settings.arena_worker_heartbeat_path or "").strip(),
                    integrity_key=arena_worker_heartbeat_integrity_key(settings),
                )
            except ArenaWorkerEvidenceError:
                heartbeat_store = None
    return project_arena_worker_capability(
        challenge_id=challenge_id,
        challenge_version=challenge_version,
        enabled=enabled,
        expected_bindings=expected,
        heartbeat_store=heartbeat_store,
        now=int(_time.time()),
        ttl_seconds=int(settings.arena_worker_heartbeat_ttl_seconds),
    )


@app.get(
    "/arena/challenges/{challenge_id}/versions/{challenge_version}/worker-capability"
)
def arena_worker_capability(
    challenge_id: str,
    challenge_version: str,
    response: Response,
):
    """Return authenticated presence, explicitly never self-attested TDX."""

    _require_arena_challenge(challenge_id, challenge_version)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    try:
        return _project_arena_worker_capability(challenge_id, challenge_version)
    except Exception:
        # A malformed TTL or other local configuration also fails closed into
        # the fixed modeled shape; it never becomes an internal-error oracle.
        from tinker_delegate.arena_worker_evidence import (
            project_arena_worker_capability,
        )

        return project_arena_worker_capability(
            challenge_id=challenge_id,
            challenge_version=challenge_version,
            enabled=False,
            expected_bindings=None,
            heartbeat_store=None,
            now=0,
            ttl_seconds=30,
        )


@app.get("/arena/internal/submissions/{submission_id}")
def arena_internal_submission(
    submission_id: str,
    authorization: str = Header(default=""),
):
    """Return the sealed reference to an authenticated in-boundary worker."""

    from tinker_delegate.arena_store import ArenaStoreError

    _require_configured_runtime_auth(authorization)
    try:
        return _get_arena_store().worker_submission(submission_id)
    except ArenaStoreError as exc:
        raise HTTPException(status_code=404, detail="Unknown Arena submission") from exc


@app.post("/arena/internal/submissions/{submission_id}/transition")
def arena_internal_transition(
    submission_id: str,
    payload: ArenaQueueTransitionRequest,
    authorization: str = Header(default=""),
):
    """Advance the durable queue state; does not execute candidate code."""

    import time as _time

    from tinker_delegate.arena_store import ArenaStoreError

    _require_configured_runtime_auth(authorization)
    store = _get_arena_store()
    try:
        store.transition_submission(
            submission_id,
            payload.to_state,
            reason=payload.reason,
            occurred_at=int(_time.time()),
        )
        return store.public_submission(submission_id)
    except ArenaStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(503, "Arena durable store write failed") from exc


@app.post("/arena/internal/submissions/{submission_id}/ladder-release")
def arena_internal_ladder_release(
    submission_id: str,
    payload: ArenaLadderReleaseRequest,
    authorization: str = Header(default=""),
):
    """Record an evaluator-produced bounded release, never an exact score."""

    import time as _time

    from tinker_delegate.arena_store import ArenaStoreError
    from tinker_delegate.ladder_release import LadderRelease

    _require_configured_runtime_auth(authorization)
    store = _get_arena_store()
    try:
        store.record_ladder_release(
            submission_id,
            LadderRelease(
                submission_index=payload.submission_index,
                accepted=payload.accepted,
                leaderboard_step_index=payload.leaderboard_step_index,
                step_denominator=payload.step_denominator,
                improvement_steps_so_far=payload.improvement_steps_so_far,
            ),
            occurred_at=int(_time.time()),
        )
        return store.public_submission(submission_id)
    except ArenaStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(503, "Arena durable store write failed") from exc


@app.post("/auth/reauth")
async def auth_reauth(authorization: str = Header(default="")):
    """Refresh Tinker browser auth through the OTP path.

    This endpoint is disabled by default because it can trigger account auth
    emails. Enable only for an internal/deployed control plane that already
    restricts who can invoke account operations.
    """
    if not settings.allow_auth_automation_endpoint:
        raise HTTPException(403, "auth automation endpoint is disabled")
    _require_runtime_auth(authorization)

    from tinker_delegate.signup import reauth

    try:
        result = await reauth(settings)
    except Exception as exc:
        outcome = classify_automation_error(redact_text(exc))
        receipt = make_receipt(
            surface=AutomationSurface.TINKER_AUTH,
            outcome=outcome,
            furthest_stage=AutomationStage.NOT_STARTED,
            evidence=redact_text(exc),
            bounded_message=outcome.value,
        ).to_public_dict()
        result = {
            "success": False,
            "authenticated": False,
            "error_kind": outcome.value,
            "attempt_record": receipt,
        }
    update_runtime_state(
        reauth_attempted=True,
        reauth_success=bool(result.get("success")),
        reauth_error_kind=result.get("error_kind", ""),
        last_reauth_attempt_record=result.get("attempt_record"),
    )
    return result


class KeyCreateRequestBody(BaseModel):
    name: str = ""


class KeyDeleteRequestBody(BaseModel):
    ref: str


def _bounded_key_mgmt_error(exc: Exception, operation: str) -> dict[str, Any]:
    outcome = classify_automation_error(redact_text(exc))
    return {
        "surface": "api_key_management",
        "operation": operation,
        "success": False,
        "outcome": outcome.value,
        "error_kind": outcome.value,
        "raw_secret_egress": False,
    }


@app.post("/tinker/keys/list")
async def tinker_keys_list(authorization: str = Header(default="")):
    """List the sealed account's Tinker API keys (operator-only, bounded).

    Disabled by default; drives the console keys page via CDP. Returns key
    names, id/prefix, and coarse timestamps only — never a full `tml-...` value.
    """
    if not settings.allow_key_management_endpoint:
        raise HTTPException(403, "key management endpoint is disabled")
    _require_runtime_auth(authorization)
    from tinker_delegate.tinker_keys import run_list_keys

    try:
        return await run_list_keys(settings)
    except Exception as exc:
        return _bounded_key_mgmt_error(exc, "list")


@app.post("/tinker/keys/create")
async def tinker_keys_create(payload: KeyCreateRequestBody, authorization: str = Header(default="")):
    """Create a (optionally named) Tinker API key and seal it (operator-only).

    Disabled by default; can trigger account auth emails via the OTP login. The
    new key is sealed inside the delegate and never returned in the response.
    """
    if not settings.allow_key_management_endpoint:
        raise HTTPException(403, "key management endpoint is disabled")
    _require_runtime_auth(authorization)
    from tinker_delegate.tinker_keys import run_create_key

    try:
        return await run_create_key(settings, payload.name)
    except Exception as exc:
        return _bounded_key_mgmt_error(exc, "create")


@app.post("/tinker/keys/delete")
async def tinker_keys_delete(payload: KeyDeleteRequestBody, authorization: str = Header(default="")):
    """Delete/revoke a Tinker API key by name, id, or prefix (operator-only).

    Disabled by default. Returns a bounded receipt; the key ref is hashed.
    """
    if not settings.allow_key_management_endpoint:
        raise HTTPException(403, "key management endpoint is disabled")
    _require_runtime_auth(authorization)
    from tinker_delegate.tinker_keys import run_delete_key

    try:
        return await run_delete_key(settings, payload.ref)
    except Exception as exc:
        return _bounded_key_mgmt_error(exc, "delete")


@app.get("/browser/selector-probe")
async def browser_selector_probe():
    """Return a bounded read-only browser selector/frame observation.

    Disabled by default. Enable only for one-shot deployed evidence capture.
    The probe must not navigate, click, type, screenshot, or return page text.
    """
    if not settings.allow_selector_probe_endpoint:
        raise HTTPException(403, "selector probe endpoint is disabled")

    from tinker_delegate.selector_map import probe_live_selector_map

    try:
        return await probe_live_selector_map(settings)
    except Exception:
        return JSONResponse(
            status_code=503,
            content={
                "surface": "tinker_console_and_stripe_billing",
                "raw_secret_egress": False,
                "bounded_output": True,
                "read_only": True,
                "success": False,
                "error_kind": "browser_unavailable",
                "bounded_message": "selector_probe_browser_unavailable",
            },
        )


@app.get("/browser/readiness")
async def browser_readiness_probe():
    """Return bounded browser-control readiness evidence.

    Disabled by default. Enable only for deployed debugging/measurement. The
    probe performs metadata and connection checks only; it must not navigate,
    click, type, screenshot, or return page text/raw browser URLs.
    """
    if not settings.allow_browser_readiness_endpoint:
        raise HTTPException(403, "browser readiness endpoint is disabled")

    from tinker_delegate.browser_diagnostics import browser_readiness

    return await browser_readiness(settings)


@app.get(
    "/billing/balance",
    response_model=BillingResponse,
    response_model_exclude_none=True,
)
async def billing_balance(authorization: str = Header(default="")):
    """Return only a stable balance band to an authenticated caller."""
    auth_context = _require_runtime_or_proxy_auth("billing:balance", authorization)
    result = await handle_get_balance(settings)
    return _attach_proxy_auth_context(result, auth_context)


@app.get(
    "/billing/payment-method-status",
    response_model=BillingResponse,
    response_model_exclude_none=True,
)
async def billing_payment_method_status(authorization: str = Header(default="")):
    """Return bounded card-on-file status without card details."""
    auth_context = _require_runtime_or_proxy_auth("billing:payment-method-status", authorization)
    result = await handle_payment_method_status(settings)
    return _attach_proxy_auth_context(result, auth_context)


@app.get("/billing/account-access-status")
async def billing_account_access_status(authorization: str = Header(default="")):
    """Return the bounded account access/billing-gate state (operator-only)."""
    _require_runtime_auth(authorization)
    return await handle_account_access_status(settings)


@app.get("/source/grants")
def source_grants_manifest(authorization: str = Header(default="")):
    """Return the bounded source-controller grant manifest (operator-only)."""
    _require_runtime_auth(authorization)
    import time as _time

    from tinker_delegate.source_controller import build_source_registry

    registry = build_source_registry(settings)
    if registry is None:
        return {"kind": "source_controller_manifest", "grant_count": 0, "grants": [], "raw_secret_egress": False}
    return registry.public_manifest(now=int(_time.time()))


@app.post("/retention/sweep")
def retention_sweep(authorization: str = Header(default="")):
    """Destroy expired retained artifacts; return bounded destruction records."""
    _require_runtime_auth(authorization)
    try:
        cp = _get_control_plane()
    except HTTPException:
        # Retention sweep does not need the Tinker agent stack; degrade gracefully.
        return {"swept_count": 0, "destruction_records": [], "raw_secret_egress": False}
    records = cp.sweep_retention()
    return {
        "swept_count": len(records),
        "destruction_records": records,
        "raw_secret_egress": False,
    }


@app.post("/verify/reward-run")
def verify_reward_run_endpoint(
    payload: RewardRunVerifyRequestBody, authorization: str = Header(default="")
):
    """Verify a posted private-reward run packet; return the bounded verdict.

    Auditor/operator surface for the run-verification chain (certificate +
    proof-carrying transcript + binding). Verification uses only the packet's
    bounded public bytes; nothing sealed is read and only a bounded verdict
    leaves.
    """
    _require_runtime_auth(authorization)
    from tinker_delegate.run_verification import verify_reward_run

    return verify_reward_run(payload.packet)


@app.post("/verify/reward-mechanism")
def verify_reward_mechanism_endpoint(
    payload: RewardMechanismVerifyRequestBody, authorization: str = Header(default="")
):
    """Aggregate third-party mechanism audit over posted data; bounded verdict.

    Composes the run-packet check with the data-safe external checks — sealed
    dataset binding (posted manifest) and canary calibration (posted report). The
    code-source binding (point 1) is intentionally excluded from the HTTP surface
    because it needs the reader's local source; run it via the
    `verify-reward-mechanism --source` CLI instead. Only bounded public bytes are
    read; nothing sealed leaves.
    """
    _require_runtime_auth(authorization)
    from tinker_delegate.run_verification import verify_reward_mechanism

    return verify_reward_mechanism(
        payload.packet,
        source_targets=None,
        manifest=payload.manifest,
        canary_report=payload.canary_report,
        expected_signer=payload.expected_signer or None,
        witness_quorum=payload.witness_quorum,
        expected_benchmark=payload.expected_benchmark or None,
        require_provenance=bool(payload.require_provenance),
    )


def _load_review_queue_state():
    """Load the persisted review queue, or an empty state if unconfigured."""
    from pathlib import Path

    from tinker_delegate.review_queue import ReviewQueueState, load_review_queue

    path = settings.review_queue_path
    if not path or not Path(path).exists():
        return ReviewQueueState.empty()
    return load_review_queue(path)


@app.get("/review/queue")
def review_queue_status(routed_role: str = "", authorization: str = Header(default="")):
    """Return the bounded human-review queue (operator-only).

    Optional ``routed_role`` filters to pending tickets for that review role.
    Bounded: ticket/reason/reviewer hashes and counts only — no raw hold reasons
    or reviewer identities.
    """
    _require_runtime_auth(authorization)
    import time as _time

    from tinker_delegate.review_queue import pending_tickets_for_role

    state = _load_review_queue_state()
    if routed_role:
        pending = pending_tickets_for_role(state, routed_role, now=int(_time.time()))
        return {
            "kind": "review_queue_pending",
            "routed_role": routed_role,
            "pending_count": len(pending),
            "tickets": [ticket.to_public_dict() for ticket in pending],
            "raw_secret_egress": False,
        }
    return state.to_public_dict()


@app.post("/review/decide")
def review_decide(payload: ReviewDecideRequestBody, authorization: str = Header(default="")):
    """Record a reviewer decision on a queued ticket; persist and return the queue.

    Fail-closed by construction (via `review_queue`): the submitter cannot
    self-approve, M-of-N thresholds are honored, and a single deny denies. The
    decision timestamp is server-side. Requires a configured `review_queue_path`.
    """
    _require_runtime_auth(authorization)
    import time as _time

    from tinker_delegate.review_queue import (
        ReviewQueueError,
        decide_review_ticket,
        save_review_queue,
    )

    if not settings.review_queue_path:
        raise HTTPException(503, "review queue is not configured")
    state = _load_review_queue_state()
    try:
        state = decide_review_ticket(
            state,
            payload.ticket_id,
            decision=payload.decision,
            reviewer_ref=payload.reviewer_ref,
            decided_at=int(_time.time()),
            blocked_reviewer_refs=tuple(payload.blocked_reviewer_refs),
        )
    except ReviewQueueError as e:
        raise HTTPException(409, redact_text(str(e))) from e
    save_review_queue(settings.review_queue_path, state)
    return state.to_public_dict()


@app.post("/review/expire")
def review_expire(authorization: str = Header(default="")):
    """Expire stale pending tickets at server time, persist, and return the queue.

    On-demand expiry sweep (a deployed cron/worker can poll this): a pending
    ticket past its TTL transitions to EXPIRED with an audit event and can no
    longer be released — fail-closed. Requires a configured `review_queue_path`.
    """
    _require_runtime_auth(authorization)
    import time as _time

    from tinker_delegate.review_queue import expire_review_tickets, save_review_queue

    if not settings.review_queue_path:
        raise HTTPException(503, "review queue is not configured")
    state = _load_review_queue_state()
    state = expire_review_tickets(state, now=int(_time.time()))
    save_review_queue(settings.review_queue_path, state)
    return state.to_public_dict()


@app.get("/billing/funding-policy")
def billing_funding_policy():
    """Return the bounded funding-mode policy for this delegate."""
    try:
        return funding_policy_status(settings).to_public_dict()
    except FundingPolicyError as e:
        raise HTTPException(503, redact_text(e)) from e


@app.get("/billing/funding-preflight")
def billing_funding_preflight(
    amount_dollars: Optional[float] = None,
    require_add_balance_endpoint: bool = False,
    api_url: str = "",
    expected_compose_hash: str = "",
    expected_app_id: str = "",
    expected_os_image_hash: str = "",
    allow_local_attestation: bool = False,
    fetch_attestation: bool = False,
    authorization: str = Header(default=""),
):
    """Return bounded readiness checks for an operator funding validation."""
    _require_configured_runtime_auth(authorization)
    try:
        normalized_api_url = ""
        if api_url:
            normalized_api_url = validate_https_allowlisted_url(
                api_url,
                settings.funding_preflight_allowed_hosts,
            )
        return funding_validation_preflight(
            settings,
            amount_dollars=amount_dollars,
            require_add_balance_endpoint=require_add_balance_endpoint,
            api_url=normalized_api_url,
            expected_compose_hash=expected_compose_hash,
            expected_app_id=expected_app_id,
            expected_os_image_hash=expected_os_image_hash,
            allow_local_attestation=allow_local_attestation,
            fetch_attestation=fetch_attestation,
        ).to_public_dict()
    except HttpSecurityError as e:
        raise HTTPException(400, str(e)) from e
    except FundingPolicyError as e:
        raise HTTPException(503, redact_text(e)) from e


@app.get("/billing/funding-receipts")
def billing_funding_receipts(authorization: str = Header(default="")):
    """Return bounded funding attempt records from sealed storage."""
    _require_runtime_auth(authorization)
    try:
        receipts = build_funding_receipt_store(settings).load()
    except Exception as e:
        raise HTTPException(503, AutomationOutcome.STORE_FAILED.value) from e
    return {"count": len(receipts), "receipts": receipts}


@app.post(
    "/billing/card",
    response_model=BillingResponse,
    response_model_exclude_none=True,
)
async def billing_card(payload: CardPayload, authorization: str = Header(default="")):
    """Add a payment method (plaintext — local dev only).

    In production, use POST /billing/card/encrypted instead.
    """
    if not _plaintext_card_endpoint_allowed():
        raise HTTPException(
            status_code=403,
            detail=(
                "Plaintext card endpoint is disabled; use "
                "POST /billing/card/encrypted after verifying attestation"
            ),
        )
    _require_runtime_auth(authorization)
    result = await handle_card_update(payload, settings)
    return result


@app.post(
    "/billing/card/encrypted",
    response_model=BillingResponse,
    response_model_exclude_none=True,
)
async def billing_card_encrypted(payload: EncryptedCardPayload, authorization: str = Header(default="")):
    """Add a payment method (encrypted to TEE — production).

    The payload must be encrypted using X25519 + AES-256-GCM to the
    TEE's public key from GET /attestation?context=billing.

    Protocol:
    1. GET /attestation?context=billing → verify TDX quote → extract encryption_public_key
    2. Generate ephemeral X25519 keypair
    3. ECDH(ephemeral_private, tee_public) → shared_secret
    4. HKDF-SHA256(shared_secret, info="tinker-delegate-card") → AES key
    5. AES-256-GCM encrypt CardPayload JSON → {ephemeral_public_key, nonce, ciphertext}
    6. POST this endpoint with the encrypted payload

    See tinker_delegate.crypto.encrypt_card_payload() for a reference implementation.
    """
    _require_runtime_auth(authorization)
    result = await handle_encrypted_card_update(payload, settings)
    return result


@app.post(
    "/billing/card/remove",
    response_model=BillingResponse,
    response_model_exclude_none=True,
)
async def billing_card_remove(authorization: str = Header(default="")):
    """Remove the card-on-file through bounded authenticated automation."""
    _require_runtime_auth(authorization)
    result = await handle_remove_payment_method(settings)
    return result


@app.post(
    "/billing/add-balance",
    response_model=BillingResponse,
    response_model_exclude_none=True,
)
async def billing_add_balance(payload: BalancePayload, authorization: str = Header(default="")):
    """Add credit balance to the Tinker account.

    Requires a payment method to already be on file.
    """
    if not settings.allow_add_balance_endpoint:
        raise HTTPException(
            status_code=403,
            detail=(
                "Add-balance endpoint is disabled; use the capped operator "
                "CLI path or explicitly enable TINKER_ALLOW_ADD_BALANCE_ENDPOINT"
            ),
        )
    auth_context = _require_runtime_or_proxy_auth("billing:add-balance", authorization)
    _enforce_proxy_amount_limit(auth_context, "billing:add-balance", payload.amount_dollars)
    result = await handle_add_balance(payload, settings)
    return _attach_proxy_auth_context(result, auth_context)


@app.post("/policy/approval-message")
def policy_approval_message(
    payload: PolicyApprovalMessageRequestBody,
    authorization: str = Header(default=""),
):
    """Return the exact hash-only message an independent approver signs."""

    _require_configured_runtime_auth(authorization)
    import time as _time

    from tinker_delegate.execution_policy_anchor import (
        ExecutionPolicyAnchorError,
    )
    from tinker_delegate.execution_policy_store import (
        ExecutionPolicyStoreUnavailable,
        execution_policy_approval_domain,
        execution_policy_approval_message,
        execution_policy_trust_context,
        execution_resource_hash,
    )
    from tinker_delegate.policy_kernel import (
        POLICY_CANONICALIZATION_VERSION,
        gate_access_request_payload,
    )

    result = gate_access_request_payload(payload.request, payload.policy)
    try:
        approval_domain_hash, _approver_hashes, approver_root_hash = (
            execution_policy_trust_context(settings)
        )
        result = _bind_execution_policy_context(
            payload.surface,
            payload.resource_id,
            result,
        )
        previous_record, anchor_snapshot = (
            _get_execution_policy_anchor_coordinator().latest(
                surface=payload.surface,
                resource_id=payload.resource_id,
                now=int(_time.time()),
            )
        )
        previous_decision_hash = (
            previous_record["decision_hash"]
            if previous_record is not None
            else "0" * 64
        )
        approval_domain = execution_policy_approval_domain(settings)
        message = execution_policy_approval_message(
            surface=payload.surface,
            resource_id=payload.resource_id,
            result=result,
            expires_at=payload.expires_at,
            approval_domain=approval_domain,
            approver_root_hash=approver_root_hash,
            previous_decision_hash=previous_decision_hash,
        )
    except ExecutionPolicyStoreUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Execution policy approval trust roots are unavailable",
        ) from exc
    except ExecutionPolicyAnchorError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Execution policy rollback anchor is unavailable",
        ) from exc
    return {
        "surface": "execution_policy_approval_message",
        "schema_version": 3,
        "canonicalization_version": POLICY_CANONICALIZATION_VERSION,
        "decision": result.decision.value,
        "request_hash": result.request_hash,
        "policy_hash": result.policy_hash,
        "execution_context_hash": result.execution_context_hash,
        "previous_decision_hash": previous_decision_hash,
        "resource_id_hash": execution_resource_hash(
            payload.surface, payload.resource_id
        ),
        "expires_at": payload.expires_at,
        "approval_message": message,
        "approval_message_hash": hashlib.sha256(message.encode("utf-8")).hexdigest(),
        "approval_domain_hash": approval_domain_hash,
        "approver_root_hash": approver_root_hash,
        "rollback_anchor": anchor_snapshot.to_bounded_dict(),
        "raw_policy_egress": False,
        "raw_resource_id_egress": False,
    }


@app.post("/policy/evaluate")
def policy_evaluate(
    payload: PolicyEvaluateRequestBody,
    authorization: str = Header(default=""),
):
    """Evaluate the deterministic policy kernel inside the protected runtime.

    This endpoint is an enforcement primitive, not an LLM judgment surface.
    It accepts only the kernel's strict versioned fields and returns no raw
    purpose, category, operation, policy text, requester, or corpus reference.
    Malformed policy material resolves to a bounded deny decision.
    """

    _require_configured_runtime_auth(authorization)
    import time as _time

    from tinker_delegate.execution_policy_store import (
        ExecutionPolicyStoreError,
        ExecutionPolicyStoreUnavailable,
        execution_policy_trust_context,
        verify_execution_policy_approval,
    )
    from tinker_delegate.execution_policy_anchor import (
        ExecutionPolicyAnchorError,
    )
    from tinker_delegate.policy_kernel import (
        POLICY_CANONICALIZATION_VERSION,
        gate_access_request_payload,
    )

    result = gate_access_request_payload(payload.request, payload.policy)
    try:
        _get_execution_policy_store()
        (
            current_approval_domain_hash,
            _approver_hashes,
            current_approver_root_hash,
        ) = (
            execution_policy_trust_context(settings)
        )
        result = _bind_execution_policy_context(
            payload.surface,
            payload.resource_id,
            result,
        )
        (
            approver_hash,
            approval_hash,
            approval_domain_hash,
            approver_root_hash,
        ) = verify_execution_policy_approval(
            settings=settings,
            surface=payload.surface,
            resource_id=payload.resource_id,
            result=result,
            expires_at=payload.expires_at,
            approver_address=payload.approver_address,
            approval_signature=payload.approval_signature,
            previous_decision_hash=payload.previous_decision_hash,
        )
        decision_record = _get_execution_policy_anchor_coordinator().append_and_anchor(
            surface=payload.surface,
            resource_id=payload.resource_id,
            result=result,
            recorded_at=int(_time.time()),
            expires_at=payload.expires_at,
            expected_previous_decision_hash=payload.previous_decision_hash,
            approver_hash=approver_hash,
            approval_hash=approval_hash,
            approval_domain_hash=approval_domain_hash,
            approver_root_hash=approver_root_hash,
        )
    except ExecutionPolicyStoreUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Execution policy approval trust roots are unavailable",
        ) from exc
    except ExecutionPolicyAnchorError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Execution policy rollback anchor is unavailable",
        ) from exc
    except ExecutionPolicyStoreError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Execution policy decision could not be persisted",
        ) from exc
    return {
        "surface": "policy_kernel",
        "schema_version": 3,
        "canonicalization_version": POLICY_CANONICALIZATION_VERSION,
        "approval_domain_hash": current_approval_domain_hash,
        "approver_root_hash": current_approver_root_hash,
        **result.to_bounded_api_dict(),
        "execution_binding": decision_record,
    }


@app.post("/policy/status")
def execution_policy_status(
    payload: ExecutionPolicyStatusRequestBody,
    authorization: str = Header(default=""),
):
    """Return the latest bounded binding without exposing its resource ID."""

    import time as _time

    _require_configured_runtime_auth(authorization)
    from tinker_delegate.execution_policy_store import (
        ExecutionPolicyStoreError,
        ExecutionPolicyStoreUnavailable,
        execution_policy_trust_context,
        execution_resource_hash,
    )
    from tinker_delegate.execution_policy_anchor import (
        ExecutionPolicyAnchorError,
    )
    from tinker_delegate.policy_kernel import POLICY_CANONICALIZATION_VERSION

    now = int(_time.time())
    from tinker_delegate.policy_kernel import ZERO_EXECUTION_CONTEXT_HASH

    expected_execution_context_hash = (
        _compute_execution_policy_context_hash(payload.resource_id)
        if payload.surface == "compute_dispatch"
        else ZERO_EXECUTION_CONTEXT_HASH
    )
    try:
        domain_hash, approver_hashes, approver_root_hash = (
            execution_policy_trust_context(settings)
        )
    except (ExecutionPolicyStoreError, ExecutionPolicyStoreUnavailable) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Execution policy approval trust roots are unavailable",
        ) from exc
    try:
        record, persisted, anchor_snapshot = (
            _get_execution_policy_anchor_coordinator().latest_with_pass_status(
                surface=payload.surface,
                resource_id=payload.resource_id,
                now=now,
                expected_approval_domain_hash=domain_hash,
                expected_approver_root_hash=approver_root_hash,
                approved_approver_hashes=approver_hashes,
                expected_execution_context_hash=(
                    expected_execution_context_hash
                ),
            )
        )
    except (
        ExecutionPolicyAnchorError,
        ExecutionPolicyStoreError,
        ExecutionPolicyStoreUnavailable,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Execution policy rollback anchor is unavailable",
        ) from exc
    if record is None:
        return {
            "surface": "execution_policy_status",
            "schema_version": 3,
            "canonicalization_version": POLICY_CANONICALIZATION_VERSION,
            "approval_domain_hash": domain_hash,
            "approver_root_hash": approver_root_hash,
            "found": False,
            "resource_id_hash": execution_resource_hash(
                payload.surface, payload.resource_id
            ),
            "current_pass": False,
            "rollback_anchor": anchor_snapshot.to_bounded_dict(),
            "raw_resource_id_egress": False,
            "record": None,
        }
    current_pass = persisted is not None
    return {
        "surface": "execution_policy_status",
        "schema_version": 3,
        "canonicalization_version": POLICY_CANONICALIZATION_VERSION,
        "approval_domain_hash": domain_hash,
        "approver_root_hash": approver_root_hash,
        "found": True,
        "resource_id_hash": record["resource_id_hash"],
        "current_pass": current_pass,
        "rollback_anchor": anchor_snapshot.to_bounded_dict(),
        "raw_resource_id_egress": False,
        "record": (
            persisted
            if current_pass
            else {**record, "rollback_anchor": anchor_snapshot.to_bounded_dict()}
        ),
    }


@app.post("/coordination/consent-decision")
def coordination_consent_decision(
    payload: CoordinationConsentDecisionRequestBody,
    authorization: str = Header(default=""),
):
    """Apply a source-modeled owner consent event and return a bounded receipt.

    This is an operator/authenticated proof endpoint for local/deployed
    coordination evidence. When require_signature is true, the consent decision
    must carry a valid Ethereum signed-message owner confirmation. The endpoint
    does not deliver owner email or return the updated raw coordination state.
    """
    _require_configured_runtime_auth(authorization)
    from tinker_delegate.consent_receipt import ConsentReceiptError, build_consent_decision_receipt

    try:
        return build_consent_decision_receipt(
            payload.state,
            payload.decision,
            now=payload.now,
            require_signature=payload.require_signature,
            expected_signer=payload.expected_signer,
        )
    except ConsentReceiptError as exc:
        raise HTTPException(status_code=400, detail=redact_text(exc)) from exc


@app.post("/tinker/smoke")
def tinker_smoke(payload: TinkerSmokeRequestBody, authorization: str = Header(default="")):
    """Run a tiny paid Tinker SDK smoke through the sealed account.

    Disabled by default. Enable only for an attested, funded validation CVM.
    The response must remain bounded: no API key, sample text, checkpoint path,
    or raw training-run id.
    """
    if not settings.allow_tinker_smoke_endpoint:
        raise HTTPException(
            status_code=403,
            detail="Tinker smoke endpoint is disabled",
        )
    auth_context = _require_runtime_or_proxy_auth("tinker:smoke", authorization)
    effective_max_usd = payload.max_usd if payload.max_usd is not None else settings.real_sdk_max_usd
    _enforce_proxy_amount_limit(auth_context, "tinker:smoke", effective_max_usd, require_limit=True)
    from tinker_delegate.tinker_smoke import TinkerSmokeRequest, run_tinker_sdk_smoke

    try:
        return _attach_proxy_auth_context(
            run_tinker_sdk_smoke(
                settings,
                TinkerSmokeRequest(
                    deal_id=payload.deal_id,
                    max_usd=payload.max_usd,
                    model=payload.model,
                    rank=payload.rank,
                    ttl_seconds=payload.ttl_seconds,
                    compose_hash=payload.compose_hash,
                    require_encumbrance=payload.require_encumbrance,
                ),
            ),
            auth_context,
        )
    except ValueError as exc:
        raise HTTPException(400, redact_text(exc)) from exc


class TinkerTrainRequestBody(BaseModel):
    deal_id: str = ""
    max_usd: float | None = None
    model: str = ""
    rank: int | None = None
    steps: int = 1
    learning_rate: float = 1e-4
    ttl_seconds: int | None = None
    compose_hash: str = ""
    require_encumbrance: bool = True
    examples: list[tuple[str, str]] | None = None


@app.post("/tinker/train")
def tinker_train(payload: TinkerTrainRequestBody, authorization: str = Header(default="")):
    """Run a bounded delegated LoRA training pass through the sealed account.

    Accepts the operator runtime token or a scoped `tinker:train` proxy JWT
    (spend limit required for proxy tokens). Disabled by default. The response
    is bounded: no API key, sample text, checkpoint path, or raw run id.
    """
    if not settings.allow_tinker_train_endpoint:
        raise HTTPException(403, "Tinker train endpoint is disabled")
    auth_context = _require_runtime_or_proxy_auth("tinker:train", authorization)
    from tinker_delegate.tinker_training import (
        DEFAULT_TRAIN_MAX_USD,
        TinkerTrainingRequest,
        run_tinker_training,
    )

    effective_max_usd = payload.max_usd if payload.max_usd is not None else getattr(
        settings, "train_max_usd", DEFAULT_TRAIN_MAX_USD
    )
    _enforce_proxy_amount_limit(auth_context, "tinker:train", effective_max_usd, require_limit=True)
    try:
        return _attach_proxy_auth_context(
            run_tinker_training(
                settings,
                TinkerTrainingRequest(
                    deal_id=payload.deal_id,
                    max_usd=payload.max_usd,
                    model=payload.model,
                    rank=payload.rank,
                    steps=payload.steps,
                    learning_rate=payload.learning_rate,
                    ttl_seconds=payload.ttl_seconds or 0,
                    compose_hash=payload.compose_hash,
                    require_encumbrance=payload.require_encumbrance,
                    examples=tuple(tuple(e) for e in payload.examples) if payload.examples else None,
                ),
            ),
            auth_context,
        )
    except ValueError as exc:
        raise HTTPException(400, redact_text(exc)) from exc


# ═══════════════════════════════════════════════════════════════════════════
# Deal lifecycle endpoints
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/deal/chain-event")
async def deal_chain_event(
    notification: ChainEventNotification,
    authorization: str = Header(default=""),
):
    """Called by the on-chain watcher for bounded event audit metadata."""
    _require_configured_runtime_auth(authorization)
    cp = _get_control_plane()
    cp.on_chain_event(
        notification.event_name,
        notification.deal_id,
        block_number=notification.block_number,
        tx_hash=notification.tx_hash,
        log_index=notification.log_index,
        fields=notification.fields,
    )
    return {"deal_id": notification.deal_id, "event": notification.event_name, "recorded": True}


@app.post("/deal/notify-funded")
async def deal_notify_funded(
    notification: DealFundedNotification,
    authorization: str = Header(default=""),
):
    """Called by the on-chain watcher when a deal is funded.

    Creates an IsolatedTinkerSession for this deal.
    """
    _require_configured_runtime_auth(authorization)
    cp = _get_control_plane()
    ctx = cp.on_deal_funded(
        deal_id=notification.deal_id,
        buyer=notification.buyer,
        seller=notification.seller,
        budget_cap=notification.budget_cap,
        reserve_price=notification.reserve_price,
        committed_artifact_hash=notification.artifact_hash,
        evaluator_policy_commitment=notification.evaluator_policy_commitment,
    )
    return {"deal_id": ctx.deal_id, "state": ctx.state.value}


@app.post("/deal/{deal_id}/artifact")
async def deal_upload_artifact(deal_id: str, upload: ArtifactUpload):
    """Seller uploads artifact payload. Local dev only; held in memory only."""
    if not _plaintext_artifact_endpoint_allowed():
        raise HTTPException(
            status_code=403,
            detail=(
                "Plaintext artifact endpoint is disabled; use "
                "POST /deal/{deal_id}/artifact/encrypted after verifying attestation"
            ),
        )
    wrapper_buffer = None
    artifact_buffer = None
    commitment_secret = None
    try:
        if upload.commitment_scheme != ARTIFACT_COMMITMENT_SCHEME:
            raise ValueError("unsupported artifact commitment scheme")
        if upload.envelope_scheme != ARTIFACT_ENVELOPE_SCHEME:
            raise ValueError("unsupported artifact envelope scheme")
        if upload.padding_profile != ARTIFACT_PADDING_PROFILE:
            raise ValueError("unsupported artifact padding profile")
        wrapper_buffer = decode_artifact_hex(upload.artifact_hex)
        artifact_buffer, commitment_secret = decode_artifact_wrapper(
            wrapper_buffer,
            upload.artifact_hash,
        )
        cp = _get_control_plane()
        cp.receive_artifact(
            deal_id,
            artifact_buffer,
            upload.artifact_hash,
            commitment_secret,
        )
        return {
            "deal_id": deal_id,
            "received": True,
            "artifact_commitment": upload.artifact_hash.lower(),
            "commitment_scheme": ARTIFACT_COMMITMENT_SCHEME,
            "envelope_scheme": ARTIFACT_ENVELOPE_SCHEME,
            "padding_profile": ARTIFACT_PADDING_PROFILE,
            "exact_plaintext_size_egress": False,
        }
    except KeyError:
        raise HTTPException(404, f"Deal {deal_id} not found")
    except (AssertionError, ValueError) as e:
        raise HTTPException(400, redact_text(e))
    except InvalidTag:
        raise HTTPException(400, "encrypted artifact could not be decrypted or verified")
    finally:
        zero_buffer(wrapper_buffer)
        zero_buffer(artifact_buffer)
        zero_buffer(commitment_secret)


@app.post("/deal/{deal_id}/artifact/encrypted")
async def deal_upload_artifact_encrypted(
    deal_id: str,
    upload: EncryptedArtifactUpload,
    authorization: str = Header(default=""),
):
    """Seller uploads artifact encrypted to the quote-bound TEE public key."""
    artifact_buffer = None
    commitment_secret = None
    try:
        wallet_claims = _require_wallet_auth(
            authorization,
            deal_id=deal_id,
            required_scope=ARTIFACT_UPLOAD_SCOPE,
        )
        cp = _get_control_plane()
        deal = cp.get_deal_context(deal_id)
        try:
            seller_address = normalize_wallet_address(deal.seller)
        except WalletAuthError as exc:
            raise HTTPException(403, "Funded deal seller is not a valid wallet address") from exc
        if not hmac.compare_digest(wallet_claims.address, seller_address):
            raise HTTPException(403, "Authenticated wallet is not the funded deal seller")
        submitted_hash = normalize_artifact_hash(upload.artifact_hash)
        if not hmac.compare_digest(submitted_hash, deal.committed_artifact_hash):
            raise HTTPException(400, "Artifact commitment does not match the on-chain deal")
        if upload.envelope_scheme != ARTIFACT_ENVELOPE_SCHEME:
            raise HTTPException(400, "Artifact envelope scheme is unsupported")
        if upload.padding_profile != ARTIFACT_PADDING_PROFILE:
            raise HTTPException(400, "Artifact padding profile is unsupported")
        encrypted = EncryptedPayload.from_hex({
            "ephemeral_public_key": upload.ephemeral_public_key,
            "nonce": upload.nonce,
            "ciphertext": upload.ciphertext,
        })
        ciphertext_sha256 = "sha256:" + hashlib.sha256(encrypted.ciphertext).hexdigest()
        artifact_buffer, commitment_secret = decrypt_artifact_payload(
            encrypted,
            get_tee_keypair(),
            deal_id=deal_id,
            artifact_hash=submitted_hash,
            chain_id=settings.diligence_chain_id,
            diligence_room_address=settings.diligence_room_address,
            evaluator_policy_commitment=deal.evaluator_policy_commitment,
        )
        cp.receive_artifact(
            deal_id,
            artifact_buffer,
            submitted_hash,
            commitment_secret,
        )
        return {
            "deal_id": deal_id,
            "received": True,
            "ciphertext_sha256": ciphertext_sha256,
            "commitment_scheme": ARTIFACT_COMMITMENT_SCHEME,
            "envelope_scheme": ARTIFACT_ENVELOPE_SCHEME,
            "padding_profile": ARTIFACT_PADDING_PROFILE,
            "exact_plaintext_size_egress": False,
        }
    except KeyError:
        raise HTTPException(404, f"Deal {deal_id} not found")
    except (AssertionError, ValueError) as e:
        raise HTTPException(400, redact_text(e))
    except InvalidTag:
        raise HTTPException(400, "encrypted artifact could not be decrypted or verified")
    finally:
        zero_buffer(artifact_buffer)
        zero_buffer(commitment_secret)


@app.post("/deal/{deal_id}/evaluate")
async def deal_evaluate(deal_id: str, authorization: str = Header(default="")):
    """Trigger evaluation for a deal that has received its artifact.

    The configured evaluator is resolved before the control plane. Synthetic
    evaluation is local-only. The current SFT implementation is deliberately
    unavailable because its external provider is not inside the attested
    confidentiality boundary.
    """
    _require_configured_runtime_auth(authorization)
    from tinker_delegate.evaluator import (
        EvaluatorUnavailable,
        resolve_deal_evaluator,
    )

    evaluator = None
    if settings.evaluator_mode != "deterministic":
        try:
            evaluator = resolve_deal_evaluator(settings)
        except EvaluatorUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Deal evaluator is unavailable for this runtime",
            ) from exc

    cp = _get_control_plane()
    if evaluator is None:
        try:
            deal = cp.get_deal_context(deal_id)
        except KeyError as exc:
            raise HTTPException(404, f"Deal {deal_id} not found") from exc
        try:
            evaluator = resolve_deal_evaluator(
                settings,
                evaluator_policy_commitment=deal.evaluator_policy_commitment,
            )
        except EvaluatorUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Deal evaluator is unavailable for this runtime",
            ) from exc

    with _authorized_execution_policy_lease("deal_evaluation", deal_id):
        try:
            result = await cp.evaluate(deal_id, evaluator)
            return EvaluationResultResponse(
                deal_id=result.deal_id,
                score_band=result.score_band.value,
                quality_delta=result.quality_delta,
                offer_price=result.offer_price,
                recommendation=result.recommendation,
                confidence=result.confidence,
                methodology_summary=result.methodology_summary,
                compute_cost_wei=result.compute_cost_wei,
                fee_wei=result.fee_wei,
            )
        except KeyError:
            raise HTTPException(404, f"Deal {deal_id} not found")
        except AssertionError as e:
            raise HTTPException(400, redact_text(e))


@app.get("/deal/{deal_id}/result", response_model=EvaluationResultResponse)
async def deal_get_result(deal_id: str):
    """Get bounded evaluation result for a completed deal."""
    cp = _get_control_plane()
    result = cp.get_result(deal_id)
    if result is None:
        raise HTTPException(404, f"No result for deal {deal_id}")
    return EvaluationResultResponse(
        deal_id=result.deal_id,
        score_band=result.score_band.value,
        quality_delta=result.quality_delta,
        offer_price=result.offer_price,
        recommendation=result.recommendation,
        confidence=result.confidence,
        methodology_summary=result.methodology_summary,
        compute_cost_wei=result.compute_cost_wei,
        fee_wei=result.fee_wei,
    )


@app.post("/deal/{deal_id}/resolve")
async def deal_resolve(deal_id: str, authorization: str = Header(default="")):
    """Notify that a deal has been resolved on-chain.

    Triggers cleanup: session destroyed, artifact zeroed.
    """
    _require_configured_runtime_auth(authorization)
    cp = _get_control_plane()
    cp.on_deal_resolved(deal_id)
    return {"deal_id": deal_id, "resolved": True}


@app.get("/deals")
async def list_deals(authorization: str = Header(default="")):
    """List active deal identifiers for the internal operator only."""
    _require_configured_runtime_auth(authorization)
    cp = _get_control_plane()
    return {"active_deals": cp.active_deals}
