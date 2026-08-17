"""FastAPI service for the email oracle.

Endpoints:
  POST /pin          — extract a verification pin from inbox
  GET  /health       — liveness only (no mailbox state)
  GET  /email        — commitment-only mailbox readiness (no raw address)
  GET  /attestation  — TDX quote (no-op locally, real in TEE)

There is intentionally no mailbox-listing endpoint. Runtime authentication is
not authority to export mailbox identifiers, headers, dates, or message text.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from email_oracle.chain_auth import (
    EmailOracleAuthError,
    FinalizedBlockCheckpointStore,
    check_consumer_authorization,
)
from email_oracle.config import Settings
from email_oracle.crypto import (
    ORACLE_CREDENTIALS_HKDF_INFO,
    EncryptedPayload,
    TEEKeyPair,
    attestation_report_data,
)
from email_oracle.cred_store import CredentialStore, EmailCredentials
from email_oracle.dstack_utils import (
    derive_storage_key,
    get_attestation,
    get_attestation_details,
    is_dstack_simulator,
)
from email_oracle.imap_client import IMAPClient
from email_oracle.replay_store import OtpReplayStore
from email_oracle.redaction import redact_text


# --- Request / Response models ---

class PinRequest(BaseModel):
    """One narrow production capability: fetch Tinker's six-digit login OTP.

    The literal fields retain wire compatibility with the delegate while
    rejecting caller-selected mailbox filters and regexes.
    """

    target_service: Literal["tinker"] = Field(
        "tinker",
        description="Allowlisted OTP service",
    )
    expected_sender: Literal["no-reply@thinkingmachines.ai"] = Field(
        "no-reply@thinkingmachines.ai",
        description="Fixed allowlisted sender",
    )
    expected_subject_contains: Literal[""] = Field(
        "",
        description="Subject matching is intentionally unavailable",
    )
    max_age_seconds: int = Field(300, ge=1, le=900, description="Max email age in seconds")
    extract_pattern: Literal[r"\b\d{6}\b"] = Field(
        r"\b\d{6}\b",
        description="Fixed six-digit OTP pattern",
    )
    nonce: str = Field(
        ...,
        min_length=8,
        max_length=128,
        pattern=r"^[a-zA-Z0-9_.:-]+$",
        description="Caller-generated one-time request nonce",
    )
    caller_identity: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Bounded caller identity such as app id, compose hash, or service name",
    )
    reason: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Human-readable bounded purpose for audit logs",
    )
    delete_after: bool = Field(False, description="Delete email after extraction")

    model_config = {"extra": "forbid"}


class PinResponse(BaseModel):
    pin: str = Field(pattern=r"^\d{6}$")
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    attestation_report_data: str = Field(pattern=r"^[0-9a-f]{64}$")
    tdx_quote: str = Field("", max_length=262_144)

    model_config = {"extra": "forbid"}


class HealthResponse(BaseModel):
    service: Literal["tee-email-oracle"] = "tee-email-oracle"
    status: Literal["ok"] = "ok"

    model_config = {"extra": "forbid"}


EMAIL_COMMITMENT_SCHEME = "dnai-wikigen/oracle-email/v1"


class EmailCommitmentResponse(BaseModel):
    oracle_ready: bool
    oracle_email_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    commitment_scheme: Literal["dnai-wikigen/oracle-email/v1"]
    raw_email_egress: Literal[False] = False
    timestamp: str


class AttestationResponse(BaseModel):
    service: Literal["tee-email-oracle"] = "tee-email-oracle"
    report_context: Literal["attestation", "oracle-credentials", "pin"]
    encryption_public_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_data: str = Field(pattern=r"^[0-9a-f]{64}$")
    mode: Literal["local", "simulator", "tdx"]
    tdx_quote: str = Field(max_length=262_144)
    quote_report_data: str = Field("", max_length=256)
    app_id: str = Field(max_length=256)
    compose_hash: str = Field(max_length=256)
    os_image_hash: str = Field("", max_length=256)
    verified: Literal[False] = False

    model_config = {"extra": "forbid"}

    @field_validator("verified", mode="before")
    @classmethod
    def never_self_attest_verification(cls, _value: object) -> bool:
        """The quote-producing oracle cannot independently verify itself."""
        return False


class EncryptedCredentialPayload(BaseModel):
    ephemeral_public_key: str = Field(..., min_length=64, max_length=64)
    nonce: str = Field(..., min_length=24, max_length=24)
    ciphertext: str = Field(..., min_length=32, max_length=8192)

    @field_validator("ephemeral_public_key", "nonce", "ciphertext")
    @classmethod
    def validate_hex(cls, value: str) -> str:
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("must be lowercase hex") from exc
        return value


class CredentialProvisionResponse(BaseModel):
    status: str
    credential_email_hash: str
    credential_domain_hash: str
    imap_connected: bool
    tdx_quote_hash: str
    raw_secret_egress: bool = False
    timestamp: str


# --- App state ---

class OracleState:
    def __init__(self):
        self.settings: Settings | None = None
        self.store: CredentialStore | None = None
        self.creds: EmailCredentials | None = None
        self.imap: IMAPClient | None = None
        self.imap_connected: bool = False
        self.otp_replay_store: OtpReplayStore | None = None
        self.otp_replay_store_ready: bool = True
        self.used_otp_hashes: set[str] = set()
        self.tee_keypair: TEEKeyPair | None = None


state = OracleState()


def get_tee_keypair() -> TEEKeyPair:
    """Get or create the oracle's in-memory ingress keypair."""
    if state.tee_keypair is None:
        state.tee_keypair = TEEKeyPair()
    return state.tee_keypair


def _runtime_auth_enabled() -> bool:
    settings = state.settings
    if not settings:
        return False
    return settings.runtime_auth_required or bool(settings.runtime_auth_token)


def _runtime_auth_token() -> str:
    settings = state.settings
    if not settings:
        return ""
    if settings.runtime_auth_token:
        return settings.runtime_auth_token
    if settings.dstack_enabled:
        key = derive_storage_key(settings.runtime_auth_key_path)
        return hashlib.sha256(b"email-oracle-runtime-auth:" + key).hexdigest()
    return ""


def require_runtime_auth(authorization: str = Header(default="")) -> None:
    """Protect OTP and inbox egress with same-CVM bearer auth."""
    if not _runtime_auth_enabled():
        return

    expected = _runtime_auth_token()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Oracle runtime auth is required but no token is configured",
        )

    scheme, _, supplied = authorization.partition(" ")
    if scheme.lower() != "bearer" or not supplied:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid bearer token",
        )


def require_credential_provisioning_auth(authorization: str = Header(default="")) -> None:
    """Protect the credential mutation path with an explicit operator token."""
    settings = state.settings
    if not settings or not settings.allow_credential_provisioning_endpoint:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Credential provisioning endpoint is disabled",
        )
    expected = settings.credential_provisioning_token
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Credential provisioning token is not configured",
        )
    scheme, _, supplied = authorization.partition(" ")
    if scheme.lower() != "bearer" or not supplied:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid bearer token",
        )


def require_consumer_registry_authorization(*, caller_identity: str = "") -> None:
    """Fail closed unless configured EmailOracleAuth consumer policy allows egress."""
    settings = state.settings
    if not settings:
        return
    try:
        result = check_consumer_authorization(settings, caller_identity=caller_identity)
    except EmailOracleAuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"EmailOracleAuth policy check failed: {redact_text(exc)}",
        ) from exc
    if result.allowed:
        return
    status_code = (
        status.HTTP_403_FORBIDDEN
        if result.checked and result.reason == "consumer_not_authorized"
        else status.HTTP_503_SERVICE_UNAVAILABLE
    )
    raise HTTPException(
        status_code=status_code,
        detail=f"EmailOracleAuth policy denied: {result.reason}",
    )


def _hash_json(data: dict) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _email_commitment(value: str) -> str:
    """Commit to a normalized mailbox without exporting the raw address.

    The explicit domain and NUL separator prevent this digest from being
    confused with subject, sender, message-id, or other plain SHA-256 values.
    This remains a commitment, not an anonymity guarantee for guessable email
    addresses.
    """

    normalized = value.strip().lower()
    payload = EMAIL_COMMITMENT_SCHEME.encode("ascii") + b"\x00" + normalized.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _attestation_payload(context: str) -> dict:
    keypair = get_tee_keypair()
    report_data = attestation_report_data(
        "tee-email-oracle",
        context,
        keypair.public_key_bytes,
    )
    base = {
        "service": "tee-email-oracle",
        "encryption_public_key": keypair.public_key_bytes.hex(),
        "report_context": context,
        "report_data": report_data.hex(),
    }
    if not state.settings or not state.settings.dstack_enabled:
        return {
            **base,
            "tdx_quote": "local-mode-no-attestation",
            "app_id": "local-dev",
            "compose_hash": "local-dev",
            "mode": "local",
            "verified": False,
        }

    try:
        details = get_attestation_details(report_data)
        evidence_mode = "simulator" if is_dstack_simulator() else "tdx"
        return {
            **base,
            "tdx_quote": details["quote"],
            "app_id": details["app_id"],
            "compose_hash": details["compose_hash"],
            "mode": evidence_mode,
            "quote_report_data": str(details.get("quote_report_data") or ""),
            "os_image_hash": str(details.get("os_image_hash") or ""),
            # Quote retrieval is evidence transport only. No independent QVL
            # validates signature, collateral, and measurements in this service.
            "verified": False,
        }
    except Exception as exc:
        print(f"[api] attestation retrieval failed: {redact_text(exc)}")
        return {
            **base,
            "tdx_quote": "",
            "app_id": "",
            "compose_hash": "",
            "mode": "simulator" if is_dstack_simulator() else "tdx",
            "verified": False,
        }


def _connect_imap(creds: EmailCredentials) -> bool:
    settings = state.settings
    if not settings:
        state.imap_connected = False
        return False
    if state.imap:
        state.imap.disconnect()
    state.imap_connected = False
    state.imap = IMAPClient(creds, settings)
    try:
        state.imap.connect()
        state.imap_connected = True
        return True
    except Exception as exc:
        print(f"[api] IMAP connection failed after credential provisioning: {redact_text(exc)}")
        return False


def _decrypt_credential_payload(payload: EncryptedCredentialPayload) -> EmailCredentials:
    encrypted = EncryptedPayload.from_hex(payload.model_dump())
    plaintext = bytearray()
    try:
        plaintext.extend(
            get_tee_keypair().decrypt(
                encrypted,
                info=ORACLE_CREDENTIALS_HKDF_INFO,
                associated_data=b"tee-email-oracle:credentials:v1",
            )
        )
        data = json.loads(bytes(plaintext))
        creds = EmailCredentials.from_dict(data)
        if not creds.username or not creds.domain or not creds.password:
            raise ValueError("username, domain, and password are required")
        return creds
    finally:
        for index in range(len(plaintext)):
            plaintext[index] = 0


def _pin_request_hash(req: PinRequest) -> str:
    return _hash_json(
        {
            "target_service": req.target_service,
            "expected_sender": req.expected_sender,
            "expected_subject_contains": req.expected_subject_contains,
            "max_age_seconds": req.max_age_seconds,
            "extract_pattern": req.extract_pattern,
            "nonce": req.nonce,
            "caller_identity": req.caller_identity,
            "reason": req.reason,
            "delete_after": req.delete_after,
        }
    )


def _otp_use_hash(req: PinRequest, result, oracle_email: str) -> str:
    return _hash_json(
        {
            "target_service": req.target_service,
            "caller_identity": req.caller_identity,
            "oracle_email": oracle_email,
            "email_id": result.email_id,
            "pin_hash": hashlib.sha256(result.pin.encode()).hexdigest(),
        }
    )


def _pin_attestation_report_data(request_hash: str, pin: str) -> bytes:
    """Bind the released OTP to its bounded request without mailbox metadata.

    Message identifiers, headers, mailbox identity, extraction time, and the
    internal replay key are deliberately excluded. The returned digest is safe
    to quote and disclose alongside the OTP.
    """

    canonical = json.dumps(
        {
            "service": "tee-email-oracle",
            "context": "pin",
            "request_hash": request_hash,
            "pin_sha256": hashlib.sha256(pin.encode("ascii")).hexdigest(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(canonical).digest()


def _mark_otp_released(otp_use_hash: str) -> None:
    if otp_use_hash in state.used_otp_hashes:
        raise HTTPException(409, "OTP has already been released")

    if not state.otp_replay_store_ready:
        raise HTTPException(
            503,
            "OTP replay ledger is unavailable; refusing to release OTP",
        )

    updated_hashes = set(state.used_otp_hashes)
    updated_hashes.add(otp_use_hash)

    if state.otp_replay_store:
        try:
            state.otp_replay_store.save(updated_hashes)
        except Exception as exc:
            raise HTTPException(
                503,
                "Could not persist OTP replay ledger; refusing to release OTP",
            ) from exc

    state.used_otp_hashes = updated_hashes


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize oracle on startup."""
    settings = Settings()
    state.settings = settings
    if settings.production_release:
        # Monotonic finalized-block enforcement is a durable security boundary,
        # not an in-memory best effort.  Prove the checkpoint volume is readable
        # and writable before the service can become healthy.
        try:
            FinalizedBlockCheckpointStore(
                settings.auth_checkpoint_store_path
            ).ensure_ready()
        except EmailOracleAuthError:
            raise RuntimeError(
                "production EmailOracleAuth checkpoint store is unavailable"
            ) from None
    state.store = CredentialStore(
        settings.cred_store_path,
        settings.cred_store_key,
        dstack_enabled=settings.dstack_enabled,
        dstack_key_path=settings.dstack_key_path,
    )
    state.otp_replay_store = OtpReplayStore(
        settings.otp_replay_store_path,
        settings.otp_replay_store_key,
        dstack_enabled=settings.dstack_enabled,
        dstack_key_path=settings.otp_replay_key_path,
    )
    try:
        state.used_otp_hashes = state.otp_replay_store.load()
        state.otp_replay_store_ready = True
        print(f"[api] loaded {len(state.used_otp_hashes)} OTP replay entries")
    except Exception as e:
        print(f"[api] failed to decrypt OTP replay ledger: {redact_text(e)}")
        state.used_otp_hashes = set()
        state.otp_replay_store_ready = False
    state.tee_keypair = TEEKeyPair()

    # Load existing credentials
    if state.store.exists():
        try:
            state.creds = state.store.load()
            print(f"[api] loaded credentials email_hash={_hash_text(state.creds.email)}")
        except Exception as e:
            print(f"[api] failed to decrypt credentials (wrong key?): {redact_text(e)}")
            print("[api] delete the credential file or use the same dstack key path / ORACLE_CRED_STORE_KEY")
            state.creds = None
    else:
        print("[api] no credentials found — run genesis first")

    # Prepare IMAP if we have creds. Do not connect during startup: a slow or
    # flaky mailbox provider would prevent the API from serving health and
    # attestation. `/pin` performs the first real mailbox operation.
    if state.creds:
        state.imap = IMAPClient(state.creds, settings)
        state.imap_connected = False
        print("[api] IMAP connection deferred until pin request")

    yield

    # Cleanup
    if state.imap:
        state.imap.disconnect()
    state.imap_connected = False


app = FastAPI(
    title="TEE Email Oracle",
    description="Verification pin extraction from TEE-sealed email account",
    version="0.1.0",
    lifespan=lifespan,
)


@app.post("/pin", response_model=PinResponse, dependencies=[Depends(require_runtime_auth)])
async def extract_pin(req: PinRequest):
    """Extract a verification pin from the oracle's inbox."""
    require_consumer_registry_authorization(caller_identity=req.caller_identity)
    if not state.creds or not state.imap:
        raise HTTPException(503, "Oracle not initialized — no credentials")

    try:
        result = state.imap.search_and_extract(
            from_filter=req.expected_sender,
            subject_contains=req.expected_subject_contains,
            max_age_seconds=req.max_age_seconds,
        )
        state.imap_connected = True
    except Exception as exc:
        state.imap_connected = False
        print(f"[api] IMAP pin search failed: {redact_text(exc)}")
        raise HTTPException(503, "IMAP unavailable") from exc

    if not result:
        raise HTTPException(404, "No matching pin found in inbox")

    if not result.pin.isascii() or not result.pin.isdigit() or len(result.pin) != 6:
        raise HTTPException(400, "Extracted value is not a six-digit OTP")

    request_hash = _pin_request_hash(req)
    otp_use_hash = _otp_use_hash(req, result, state.creds.email)
    _mark_otp_released(otp_use_hash)
    report_data = _pin_attestation_report_data(request_hash, result.pin)

    if req.delete_after:
        try:
            state.imap.delete_email(result.email_id)
        except Exception as e:
            print(
                "[api] failed to delete email "
                f"email_id_hash={_hash_text(result.email_id)}: {redact_text(e)}"
            )

    tdx_quote = ""
    if state.settings.dstack_enabled:
        tdx_quote, _, _ = get_attestation(report_data)

    return PinResponse(
        pin=result.pin,
        request_hash=request_hash,
        attestation_report_data=report_data.hex(),
        tdx_quote=tdx_quote,
    )


@app.get("/health", response_model=HealthResponse)
def health():
    """Return process liveness only; authenticated routes own readiness state."""

    return HealthResponse()


@app.get(
    "/email",
    response_model=EmailCommitmentResponse,
    dependencies=[Depends(require_runtime_auth)],
)
async def email_address():
    """Return commitment-only mailbox readiness to authenticated callers."""
    if not state.creds:
        raise HTTPException(503, "Oracle not initialized — no credentials")
    return EmailCommitmentResponse(
        oracle_ready=True,
        oracle_email_commitment=_email_commitment(state.creds.email),
        commitment_scheme=EMAIL_COMMITMENT_SCHEME,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/attestation", response_model=AttestationResponse)
async def attestation(context: str = "attestation"):
    """Get bounded TDX evidence (no-op locally), never a self-issued verdict."""
    if context not in {"attestation", "oracle-credentials", "pin"}:
        raise HTTPException(400, "unsupported attestation context")
    return AttestationResponse(**_attestation_payload(context))


@app.post(
    "/credentials/encrypted",
    response_model=CredentialProvisionResponse,
    dependencies=[Depends(require_credential_provisioning_auth)],
)
async def provision_credentials_encrypted(payload: EncryptedCredentialPayload):
    """Provision existing mailbox credentials encrypted to the attested oracle key."""
    if not state.store:
        raise HTTPException(503, "Credential store is not initialized")
    try:
        creds = _decrypt_credential_payload(payload)
        state.store.save(creds)
        state.creds = creds
        imap_connected = _connect_imap(creds)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"encrypted credentials could not be decrypted or stored: {redact_text(exc)}",
        ) from exc

    quote = ""
    if state.settings and state.settings.dstack_enabled:
        quote = _attestation_payload("oracle-credentials").get("tdx_quote", "")
    return CredentialProvisionResponse(
        status="stored",
        credential_email_hash=_hash_text(creds.email),
        credential_domain_hash=_hash_text(creds.domain),
        imap_connected=imap_connected,
        tdx_quote_hash=_hash_text(quote) if quote else "",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# Keep the outbound Human Review capability in its own narrow module.  This
# service-level include is the only integration point with the OTP API; the
# router owns bounded parsing, release authorization, SMTP, and idempotency.
from email_oracle.review_notifications import router as review_notification_router

app.include_router(review_notification_router)
