"""FastAPI service for the email oracle.

Endpoints:
  POST /pin          — extract a verification pin from inbox
  GET  /health       — service health + credential status
  GET  /inbox        — list recent emails (debug)
  GET  /attestation  — TDX quote (no-op locally, real in TEE)
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from email_oracle.chain_auth import EmailOracleAuthError, check_consumer_authorization
from email_oracle.config import Settings
from email_oracle.crypto import (
    ORACLE_CREDENTIALS_HKDF_INFO,
    EncryptedPayload,
    TEEKeyPair,
    attestation_report_data,
)
from email_oracle.cred_store import CredentialStore, EmailCredentials
from email_oracle.dstack_utils import derive_storage_key, get_attestation, get_attestation_details
from email_oracle.imap_client import IMAPClient
from email_oracle.replay_store import OtpReplayStore
from email_oracle.redaction import redact_text


# --- Request / Response models ---

class PinRequest(BaseModel):
    target_service: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_.:-]+$",
        description="Service requesting the OTP, e.g. tinker",
    )
    expected_sender: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Expected sender substring/address",
    )
    expected_subject_contains: str = Field(
        "",
        max_length=255,
        description="Expected subject substring, empty only when the live subject is not stable",
    )
    max_age_seconds: int = Field(300, ge=1, le=900, description="Max email age in seconds")
    extract_pattern: str = Field(
        r"\b\d{6}\b",
        min_length=1,
        max_length=128,
        description="Regex to extract a bounded OTP/confirmation code",
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

    @field_validator("extract_pattern")
    @classmethod
    def validate_extract_pattern(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid extract_pattern: {exc}") from exc
        return value


class PinResponse(BaseModel):
    pin: str
    email_id: str
    subject: str
    sender: str
    received_at: str
    oracle_email: str
    timestamp: str
    request_hash: str
    otp_use_hash: str
    tdx_quote: str = ""  # populated in TEE mode


class HealthResponse(BaseModel):
    status: str
    oracle_ready: bool
    oracle_email: str = ""
    oracle_email_hash: str = ""
    imap_connected: bool
    dstack_enabled: bool
    timestamp: str


class EmailAddressResponse(BaseModel):
    oracle_email: str
    oracle_email_hash: str
    timestamp: str


class AttestationResponse(BaseModel):
    tdx_quote: str
    app_id: str
    compose_hash: str
    oracle_email: str = ""
    oracle_email_hash: str = ""
    oracle_ready: bool = False
    timestamp: str
    mode: str = "local"
    encryption_public_key: str = ""
    report_context: str = "attestation"
    report_data: str = ""
    quote_report_data: str = ""
    os_image_hash: str = ""
    verified: bool = False


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


def _attestation_payload(context: str) -> dict:
    keypair = get_tee_keypair()
    report_data = attestation_report_data(
        "tee-email-oracle",
        context,
        keypair.public_key_bytes,
    )
    oracle_email_hash = _hash_text(state.creds.email) if state.creds else ""
    base = {
        "encryption_public_key": keypair.public_key_bytes.hex(),
        "report_context": context,
        "report_data": report_data.hex(),
        "oracle_email": "",
        "oracle_email_hash": oracle_email_hash,
        "oracle_ready": bool(state.creds),
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
        return {
            **base,
            "tdx_quote": details["quote"],
            "app_id": details["app_id"],
            "compose_hash": details["compose_hash"],
            "mode": "tdx",
            "quote_report_data": str(details.get("quote_report_data") or ""),
            "os_image_hash": str(details.get("os_image_hash") or ""),
            "verified": True,
        }
    except Exception as exc:
        return {
            **base,
            "tdx_quote": "",
            "app_id": "",
            "compose_hash": "",
            "mode": "tdx",
            "verified": False,
            "error": redact_text(exc),
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
            extract_pattern=req.extract_pattern,
        )
        state.imap_connected = True
    except Exception as exc:
        state.imap_connected = False
        print(f"[api] IMAP pin search failed: {redact_text(exc)}")
        raise HTTPException(503, "IMAP unavailable") from exc

    if not result:
        raise HTTPException(404, "No matching pin found in inbox")

    if len(result.pin) > state.settings.pin_max_length:
        raise HTTPException(400, "Extracted value exceeds OTP length cap")

    request_hash = _pin_request_hash(req)
    otp_use_hash = _otp_use_hash(req, result, state.creds.email)
    _mark_otp_released(otp_use_hash)

    if req.delete_after:
        try:
            state.imap.delete_email(result.email_id)
        except Exception as e:
            print(f"[api] failed to delete email {result.email_id}: {redact_text(e)}")

    tdx_quote = ""
    if state.settings.dstack_enabled:
        tdx_quote, _, _ = get_attestation(f"pin:{request_hash}:{otp_use_hash}")

    return PinResponse(
        pin=result.pin,
        email_id=result.email_id,
        subject=result.subject,
        sender=result.sender,
        received_at=result.received_at,
        oracle_email=state.creds.email,
        timestamp=datetime.now(timezone.utc).isoformat(),
        request_hash=request_hash,
        otp_use_hash=otp_use_hash,
        tdx_quote=tdx_quote,
    )


@app.get("/health", response_model=HealthResponse)
def health():
    """Service health check.

    Keep this endpoint non-mutating. Docker and delegate health probes call it
    frequently; reconnecting IMAP here can block the API and create reconnect
    storms when the mailbox provider is flaky. `/pin` performs the real IMAP
    operation and updates this cached connection state.
    """
    imap_ok = bool(state.imap and state.imap_connected)

    oracle_email_hash = _hash_text(state.creds.email) if state.creds else ""
    return HealthResponse(
        status="ok" if state.creds and imap_ok else "degraded",
        oracle_ready=bool(state.creds and imap_ok),
        oracle_email="",
        oracle_email_hash=oracle_email_hash,
        imap_connected=imap_ok,
        dstack_enabled=state.settings.dstack_enabled if state.settings else False,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/email", response_model=EmailAddressResponse, dependencies=[Depends(require_runtime_auth)])
async def email_address():
    """Return the oracle address only to same-runtime authenticated callers."""
    if not state.creds:
        raise HTTPException(503, "Oracle not initialized — no credentials")
    return EmailAddressResponse(
        oracle_email=state.creds.email,
        oracle_email_hash=_hash_text(state.creds.email),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/inbox", dependencies=[Depends(require_runtime_auth)])
async def list_inbox(max_age: int = 3600, limit: int = 20):
    """List recent emails (debug endpoint)."""
    require_consumer_registry_authorization()
    if not state.imap:
        raise HTTPException(503, "IMAP not connected")
    return state.imap.list_recent(max_age_seconds=max_age, limit=limit)


@app.get("/attestation", response_model=AttestationResponse)
async def attestation(context: str = "attestation"):
    """Get TDX attestation quote (no-op locally)."""
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
