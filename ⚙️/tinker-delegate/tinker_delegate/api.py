"""FastAPI server for tinker-delegate.

Endpoints:
  GET  /health                    — service health + oracle email
  GET  /attestation               — TDX attestation quote + context-bound encryption public key
  POST /auth/reauth               — bounded Tinker OTP re-auth, disabled unless explicitly enabled
  GET  /browser/readiness         — bounded browser-control readiness probe, disabled unless explicitly enabled
  GET  /browser/selector-probe    — bounded read-only selector/frame probe, disabled unless explicitly enabled
  GET  /billing/balance           — current Tinker balance
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
from typing import Any, Optional

from fastapi import FastAPI, Header, HTTPException, status
from fastapi.responses import JSONResponse
from cryptography.exceptions import InvalidTag
from pydantic import BaseModel, ConfigDict, Field

from tinker_delegate.api_key_store import resolve_api_key
from tinker_delegate.artifacts import (
    decode_artifact_hex,
    decrypt_artifact_payload,
    zero_buffer,
)
from tinker_delegate.automation_receipts import (
    AutomationStage,
    AutomationSurface,
    classify_automation_error,
    make_receipt,
)
from tinker_delegate.config import Settings
from tinker_delegate.crypto import EncryptedPayload
from tinker_delegate.dstack_utils import derive_storage_key, is_dstack_enabled
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
from tinker_delegate.runtime_state import get_runtime_state, update_runtime_state
from tinker_delegate.tinker_client_config_store import resolve_tinker_client_config
from tinker_delegate.card_channel import (
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

app = FastAPI(
    title="Tinker Delegate",
    description="TEE-hosted Tinker account management and NDAI deal orchestration.",
)

settings = Settings()
disable_core_dumps()

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
    return settings.runtime_auth_required or bool(settings.runtime_auth_token)


def _runtime_auth_token() -> str:
    if settings.runtime_auth_token:
        return settings.runtime_auth_token
    if is_dstack_enabled():
        key = derive_storage_key(settings.runtime_auth_key_path)
        return hashlib.sha256(b"tinker-delegate-runtime-auth:" + key).hexdigest()
    return ""


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
            detail="Runtime bearer auth must be configured for coordination consent decisions",
        )
    _require_runtime_auth(authorization)


def _bearer_token(authorization: str) -> str:
    scheme, _, supplied = authorization.partition(" ")
    if scheme.lower() != "bearer" or not supplied:
        return ""
    return supplied


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
        api_key = resolve_api_key(settings)
        if not api_key:
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
        client_config = resolve_tinker_client_config(settings)
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
            source_registry=build_source_registry(settings),
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
    artifact_hex: str        # hex-encoded artifact payload
    artifact_hash: str       # keccak256 of the artifact

class EncryptedArtifactUpload(BaseModel):
    ephemeral_public_key: str  # hex
    nonce: str                 # hex
    ciphertext: str            # hex
    artifact_hash: str         # keccak256 of the decrypted artifact

class DealFundedNotification(BaseModel):
    deal_id: str
    buyer: str
    seller: str
    budget_cap: int          # wei
    reserve_price: int       # wei

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
    deal_id: str
    score_band: str
    quality_delta: str
    offer_price: int
    recommendation: str
    confidence: str
    methodology_summary: str
    compute_cost_wei: int
    fee_wei: int

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
    oracle = OracleClient(settings)
    try:
        oracle_health = oracle.health()
    except Exception as e:
        oracle_health = {"error": redact_text(e)}

    return {
        "status": "ok",
        "oracle": oracle_health,
        "cdp_url": settings.cdp_url,
        "browser_ws_endpoint": settings.browser_ws_endpoint,
        "api_key_configured": bool(resolve_api_key(settings)),
        "agent_stack_available": _agent_stack_available(),
        "runtime": get_runtime_state(),
    }


ATTESTATION_CONTEXTS = {"ingress", "artifact", "billing"}


@app.get("/attestation")
def attestation(context: str = "ingress"):
    """Get TDX attestation quote + context-bound TEE encryption public key.

    Developer MUST:
    1. Verify the TDX quote (code measurements match expected values)
    2. Verify report_data binds context + encryption_public_key
    3. Extract encryption_public_key from the response
    4. Encrypt card details or artifacts to this key before sending them to an encrypted endpoint
    """
    if context not in ATTESTATION_CONTEXTS:
        raise HTTPException(400, "unsupported attestation context")
    return get_attestation(context)


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


@app.get("/billing/balance")
async def billing_balance():
    """Get current Tinker account balance."""
    result = await handle_get_balance(settings)
    return result.model_dump()


@app.get("/billing/payment-method-status", response_model=BillingResponse)
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
):
    """Return bounded readiness checks for an operator funding validation."""
    try:
        return funding_validation_preflight(
            settings,
            amount_dollars=amount_dollars,
            require_add_balance_endpoint=require_add_balance_endpoint,
            api_url=api_url,
            expected_compose_hash=expected_compose_hash,
            expected_app_id=expected_app_id,
            expected_os_image_hash=expected_os_image_hash,
            allow_local_attestation=allow_local_attestation,
            fetch_attestation=fetch_attestation,
        ).to_public_dict()
    except FundingPolicyError as e:
        raise HTTPException(503, redact_text(e)) from e


@app.get("/billing/funding-receipts")
def billing_funding_receipts(authorization: str = Header(default="")):
    """Return bounded funding attempt records from sealed storage."""
    _require_runtime_auth(authorization)
    try:
        receipts = build_funding_receipt_store(settings).load()
    except Exception as e:
        raise HTTPException(503, f"funding receipt store unavailable: {redact_text(e)}") from e
    return {"count": len(receipts), "receipts": receipts}


@app.post("/billing/card", response_model=BillingResponse)
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


@app.post("/billing/card/encrypted", response_model=BillingResponse)
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


@app.post("/billing/card/remove", response_model=BillingResponse)
async def billing_card_remove(authorization: str = Header(default="")):
    """Remove the card-on-file through bounded authenticated automation."""
    _require_runtime_auth(authorization)
    result = await handle_remove_payment_method(settings)
    return result


@app.post("/billing/add-balance", response_model=BillingResponse)
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
async def deal_chain_event(notification: ChainEventNotification):
    """Called by the on-chain watcher for bounded event audit metadata."""
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
async def deal_notify_funded(notification: DealFundedNotification):
    """Called by the on-chain watcher when a deal is funded.

    Creates an IsolatedTinkerSession for this deal.
    """
    cp = _get_control_plane()
    ctx = cp.on_deal_funded(
        deal_id=notification.deal_id,
        buyer=notification.buyer,
        seller=notification.seller,
        budget_cap=notification.budget_cap,
        reserve_price=notification.reserve_price,
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
    artifact_buffer = None
    try:
        artifact_buffer = decode_artifact_hex(upload.artifact_hex)
        cp = _get_control_plane()
        cp.receive_artifact(deal_id, artifact_buffer, upload.artifact_hash)
        return {"deal_id": deal_id, "received": True, "size": len(artifact_buffer)}
    except KeyError:
        raise HTTPException(404, f"Deal {deal_id} not found")
    except (AssertionError, ValueError) as e:
        raise HTTPException(400, redact_text(e))
    except InvalidTag:
        raise HTTPException(400, "encrypted artifact could not be decrypted or verified")
    finally:
        zero_buffer(artifact_buffer)


@app.post("/deal/{deal_id}/artifact/encrypted")
async def deal_upload_artifact_encrypted(deal_id: str, upload: EncryptedArtifactUpload):
    """Seller uploads artifact encrypted to the quote-bound TEE public key."""
    artifact_buffer = None
    try:
        encrypted = EncryptedPayload.from_hex({
            "ephemeral_public_key": upload.ephemeral_public_key,
            "nonce": upload.nonce,
            "ciphertext": upload.ciphertext,
        })
        artifact_buffer = decrypt_artifact_payload(
            encrypted,
            get_tee_keypair(),
            deal_id=deal_id,
            artifact_hash=upload.artifact_hash,
        )
        cp = _get_control_plane()
        cp.receive_artifact(deal_id, artifact_buffer, upload.artifact_hash)
        return {"deal_id": deal_id, "received": True, "size": len(artifact_buffer)}
    except KeyError:
        raise HTTPException(404, f"Deal {deal_id} not found")
    except (AssertionError, ValueError) as e:
        raise HTTPException(400, redact_text(e))
    except InvalidTag:
        raise HTTPException(400, "encrypted artifact could not be decrypted or verified")
    finally:
        zero_buffer(artifact_buffer)


@app.post("/deal/{deal_id}/evaluate")
async def deal_evaluate(deal_id: str):
    """Trigger evaluation for a deal that has received its artifact.

    Uses the stub evaluator. In production, the evaluator is pluggable.
    """
    cp = _get_control_plane()

    try:
        from tinker_delegate.evaluator import stub_evaluate
        result = await cp.evaluate(deal_id, stub_evaluate)
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
async def deal_resolve(deal_id: str):
    """Notify that a deal has been resolved on-chain.

    Triggers cleanup: session destroyed, artifact zeroed.
    """
    cp = _get_control_plane()
    cp.on_deal_resolved(deal_id)
    return {"deal_id": deal_id, "resolved": True}


@app.get("/deals")
async def list_deals():
    """List active deals."""
    cp = _get_control_plane()
    return {"active_deals": cp.active_deals}
