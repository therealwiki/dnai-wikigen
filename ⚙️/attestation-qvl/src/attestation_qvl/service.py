"""Least-privilege FastAPI boundary for independent quote verification."""

from __future__ import annotations

import asyncio
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import AsyncIterator

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import Settings
from .challenge import (
    OneTimeChallengeStore,
    qvl_profiles,
    validate_activation_challenge,
)
from .errors import (
    CapacityExceeded,
    InvalidRequest,
    MethodNotAllowed,
    NotEnabled,
    NotFound,
    QvlServiceError,
    RequestTooLarge,
    Unauthorized,
    VerifierUnavailable,
)
from .identity_attestation import DstackIdentityAttestor, IdentityAttestor
from .models import (
    IdentityAttestationRequest,
    IdentityResponse,
    IndependentVerificationRequest,
    MAX_BODY_BYTES,
    QvlChallengeRequest,
)
from .policy import LoadedReleasePolicy, load_release_policy, parse_duplicate_free_json
from .qvl import DcapQvlBackend, IndependentQuoteVerifier
from .signing import DstackVerdictSigner


@dataclass(frozen=True)
class Runtime:
    release: LoadedReleasePolicy
    verifier: IndependentQuoteVerifier
    auth_token: str = field(repr=False)
    identity_attestor: IdentityAttestor | None
    challenge_store: OneTimeChallengeStore
    max_concurrency: int
    rate_capacity: int
    rate_refill_per_second: float
    request_body_timeout_seconds: float
    verification_timeout_seconds: float


class GlobalCapacityGate:
    """One-process fail-fast concurrency cap plus global token bucket."""

    def __init__(self, *, maximum: int, capacity: int, refill_per_second: float):
        self._maximum = maximum
        self._capacity = float(capacity)
        self._tokens = float(capacity)
        self._refill = refill_per_second
        self._updated = time.monotonic()
        self._active = 0
        self._lock = asyncio.Lock()

    async def enter(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(self._capacity, self._tokens + (now - self._updated) * self._refill)
            self._updated = now
            if self._active >= self._maximum or self._tokens < 1:
                raise CapacityExceeded
            self._tokens -= 1
            self._active += 1

    async def exit(self) -> None:
        async with self._lock:
            self._active = max(0, self._active - 1)

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        await self.enter()
        try:
            yield
        finally:
            await self.exit()


def _authenticate(authorization: str, expected: str) -> None:
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        raise Unauthorized
    supplied = authorization[len(prefix):]
    try:
        authenticated = bool(supplied) and secrets.compare_digest(supplied, expected)
    except TypeError:
        authenticated = False
    if not authenticated:
        raise Unauthorized


async def _bounded_body(request: Request, *, timeout_seconds: float) -> bytes:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json" or request.headers.get("content-encoding"):
        raise InvalidRequest
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_size = int(declared)
        except ValueError as exc:
            raise InvalidRequest from exc
        if declared_size < 2:
            raise InvalidRequest
        if declared_size > MAX_BODY_BYTES:
            raise RequestTooLarge
    body = bytearray()
    try:
        async with asyncio.timeout(timeout_seconds):
            async for chunk in request.stream():
                if len(chunk) > MAX_BODY_BYTES - len(body):
                    raise RequestTooLarge
                body.extend(chunk)
    except TimeoutError as exc:
        raise InvalidRequest from exc
    if len(body) < 2:
        raise InvalidRequest
    return bytes(body)


def _parse_verification_request(raw: bytes) -> IndependentVerificationRequest:
    try:
        decoded = parse_duplicate_free_json(raw)
        return IndependentVerificationRequest.model_validate(decoded, strict=True)
    except (ValidationError, VerifierUnavailable, RecursionError) as exc:
        raise InvalidRequest from exc


def _parse_challenge_request(raw: bytes) -> QvlChallengeRequest:
    try:
        decoded = parse_duplicate_free_json(raw)
        return QvlChallengeRequest.model_validate(decoded, strict=True)
    except (ValidationError, VerifierUnavailable, RecursionError) as exc:
        raise InvalidRequest from exc


def _parse_identity_attestation_request(raw: bytes) -> IdentityAttestationRequest:
    try:
        decoded = parse_duplicate_free_json(raw)
        return IdentityAttestationRequest.model_validate(decoded, strict=True)
    except (ValidationError, VerifierUnavailable, RecursionError) as exc:
        raise InvalidRequest from exc


def _fixed_error(error: QvlServiceError) -> JSONResponse:
    headers = {"Cache-Control": "no-store"}
    if isinstance(error, Unauthorized):
        headers["WWW-Authenticate"] = "Bearer"
    if isinstance(error, CapacityExceeded):
        headers["Retry-After"] = "1"
    return JSONResponse(
        status_code=error.status_code,
        content={"error": error.public_code},
        headers=headers,
    )


def _create_app(runtime: Runtime) -> FastAPI:
    """Internal dependency boundary used by production bootstrap and tests only."""

    app = FastAPI(
        title="DNAI Independent Attestation QVL",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    gate = GlobalCapacityGate(
        maximum=runtime.max_concurrency,
        capacity=runtime.rate_capacity,
        refill_per_second=runtime.rate_refill_per_second,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.exception_handler(QvlServiceError)
    async def qvl_error_handler(_request: Request, exc: QvlServiceError) -> JSONResponse:
        return _fixed_error(exc)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        return _fixed_error(InvalidRequest())

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 404:
            return _fixed_error(NotFound())
        if exc.status_code == 405:
            return _fixed_error(MethodNotAllowed())
        return _fixed_error(InvalidRequest())

    @app.exception_handler(Exception)
    async def internal_error_handler(_request: Request, _exc: Exception) -> JSONResponse:
        return _fixed_error(VerifierUnavailable())

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/identity")
    async def identity() -> dict[str, object]:
        response = IdentityResponse(
            schema="dnai.attestation-qvl-identity.v1",
            verifier_address=runtime.verifier.signer.address,
            release_policy_hash=runtime.release.policy_hash,
            signer_custody="dstack_derived_separate_cvm",
            raw_secret_egress=False,
        )
        return response.model_dump(mode="json", by_alias=True)

    @app.post("/challenge")
    async def issue_challenge(
        request: Request,
        authorization: str = Header(default=""),
    ) -> dict[str, object]:
        _authenticate(authorization, runtime.auth_token)
        async with gate.slot():
            parsed = _parse_challenge_request(
                await _bounded_body(
                    request,
                    timeout_seconds=runtime.request_body_timeout_seconds,
                )
            )
            if parsed.chain_id != runtime.release.policy.chain_id:
                raise InvalidRequest
            challenge = await runtime.challenge_store.issue(parsed)
        return challenge.model_dump(mode="json", by_alias=True)

    @app.post("/attestation")
    async def identity_attestation(
        request: Request,
        authorization: str = Header(default=""),
    ) -> dict[str, object]:
        _authenticate(authorization, runtime.auth_token)
        if runtime.identity_attestor is None:
            raise NotEnabled
        async with gate.slot():
            parsed = _parse_identity_attestation_request(
                await _bounded_body(
                    request,
                    timeout_seconds=runtime.request_body_timeout_seconds,
                )
            )
            now = int(time.time())
            validate_activation_challenge(
                parsed,
                now=now,
                max_ttl_seconds=120,
            )
            if (
                parsed.chain_id != runtime.release.policy.chain_id
                or parsed.profile not in qvl_profiles(runtime.release.policy)
            ):
                raise InvalidRequest
            response = await asyncio.to_thread(
                runtime.identity_attestor.attest,
                request=parsed,
                verifier_address=runtime.verifier.signer.address,
                policy_hash=runtime.release.policy_hash,
            )
        return response.model_dump(mode="json", by_alias=True)

    @app.post("/verify")
    async def verify(request: Request, authorization: str = Header(default="")) -> dict[str, object]:
        _authenticate(authorization, runtime.auth_token)
        async with gate.slot():
            parsed = _parse_verification_request(
                await _bounded_body(
                    request,
                    timeout_seconds=runtime.request_body_timeout_seconds,
                )
            )
            async with runtime.challenge_store.reserve(parsed.challenge):
                try:
                    verdict = await asyncio.wait_for(
                        runtime.verifier.verify(parsed),
                        timeout=runtime.verification_timeout_seconds,
                    )
                except TimeoutError as exc:
                    raise VerifierUnavailable from exc
        return verdict.model_dump(mode="json", by_alias=True, exclude_none=True)

    return app


def create_production_app() -> FastAPI:
    """Uvicorn factory: only real dstack key derivation can construct production."""

    settings = Settings()  # type: ignore[call-arg]
    release = load_release_policy(settings.release_policy_path)
    signer = DstackVerdictSigner.from_policy_hash(release.policy_hash)
    verifier = IndependentQuoteVerifier(
        release=release,
        backend=DcapQvlBackend(settings.pccs_url),
        signer=signer,
    )
    attestor = DstackIdentityAttestor()
    challenge_store = OneTimeChallengeStore(
        profiles=qvl_profiles(release.policy),
        policy_hash=release.policy_hash,
        signer=signer,
        ttl_seconds=settings.challenge_ttl_seconds,
        maximum=settings.challenge_capacity,
    )
    return _create_app(Runtime(
        release=release,
        verifier=verifier,
        auth_token=settings.auth_token.get_secret_value(),
        identity_attestor=attestor,
        challenge_store=challenge_store,
        max_concurrency=settings.max_concurrency,
        rate_capacity=settings.rate_capacity,
        rate_refill_per_second=settings.rate_refill_per_second,
        request_body_timeout_seconds=settings.request_body_timeout_seconds,
        verification_timeout_seconds=settings.verification_timeout_seconds,
    ))
