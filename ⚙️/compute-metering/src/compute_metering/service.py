"""Bounded FastAPI surface for independent exact-asset metering."""

from __future__ import annotations

import asyncio
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import AsyncIterator

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from .chain import BaseSepoliaStateVerifier
from .config import Settings
from .errors import (
    CapacityExceeded,
    InvalidRequest,
    MethodNotAllowed,
    MeteringError,
    NotEnabled,
    NotFound,
    PolicyRejected,
    RequestTooLarge,
    Unauthorized,
)
from .identity_attestation import (
    DstackMeteringIdentityAttestor,
    HttpsComputeMeteringQvlClient,
    MeteringIdentityAttestor,
)
from .meter import ComputeMeter
from .models import MAX_BODY_BYTES, MeteringAssetIdentity, MeteringIdentity, MeteringRequest
from .policy import LoadedPolicySet, load_policy_set, parse_duplicate_free_json
from .replay import DurableReplayStore
from .rpc import StrictJsonRpcClient, rpc_origin_from_url
from .signing import DstackMeteringSigner, derive_dstack_replay_key


@dataclass(frozen=True)
class Runtime:
    release: LoadedPolicySet
    meter: ComputeMeter
    rpc: StrictJsonRpcClient
    replay: DurableReplayStore
    auth_token: str = field(repr=False)
    identity_attestor: MeteringIdentityAttestor | None
    identity_qvl_client: HttpsComputeMeteringQvlClient | None
    max_concurrency: int
    rate_capacity: int
    rate_refill_per_second: float
    request_body_timeout_seconds: float


class GlobalCapacityGate:
    """One-process fail-fast concurrency cap plus a global token bucket."""

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
    if not authorization.startswith("Bearer "):
        raise Unauthorized
    supplied = authorization[7:]
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


def _parse_request(raw: bytes) -> MeteringRequest:
    try:
        decoded = parse_duplicate_free_json(raw)
        return MeteringRequest.model_validate(decoded, strict=True)
    except (ValidationError, MeteringError, RecursionError) as exc:
        raise InvalidRequest from exc


def _fixed_error(error: MeteringError) -> JSONResponse:
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
    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await runtime.rpc.start()
        try:
            yield
        finally:
            await runtime.rpc.close()
            if runtime.identity_qvl_client is not None:
                runtime.identity_qvl_client.close()
            runtime.replay.close()

    app = FastAPI(
        title="DNAI Independent Compute Metering",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    gate = GlobalCapacityGate(
        maximum=runtime.max_concurrency,
        capacity=runtime.rate_capacity,
        refill_per_second=runtime.rate_refill_per_second,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    @app.exception_handler(MeteringError)
    async def metering_error_handler(_request: Request, exc: MeteringError) -> JSONResponse:
        return _fixed_error(exc)

    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(_request: Request, _exc: RequestValidationError) -> JSONResponse:
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
        return _fixed_error(MeteringError())

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/identity")
    async def identity() -> MeteringIdentity:
        policy = runtime.release.policy
        return MeteringIdentity(
            schema="dnai.compute-metering-identity.v1",
            classification="attested_dual_verified_metering",
            provider_authoritative_invoice=False,
            chain_id=policy.chain_id,
            vault_address=policy.vault_address,
            policy_set_hash=runtime.release.policy_set_hash,
            assets=tuple(
                MeteringAssetIdentity(
                    asset=entry.asset,
                    provider=entry.provider,
                    rate_policy_commitment=entry.rate_policy_commitment,
                )
                for entry in policy.asset_policies
            ),
            metering_verifier=runtime.meter.signer.address,
            metering_qvl_verifier=policy.metering_qvl_verifier,
            signer_custody=runtime.meter.signer.custody,
            raw_secret_egress=False,
        )

    @app.get("/attestation")
    async def identity_attestation(authorization: str = Header(default="")) -> dict[str, object]:
        _authenticate(authorization, runtime.auth_token)
        if runtime.identity_attestor is None or runtime.identity_qvl_client is None:
            raise NotEnabled
        policy = runtime.release.policy
        async with gate.slot():
            challenge = await asyncio.to_thread(
                runtime.identity_qvl_client.issue_challenge
            )
            packet = await asyncio.to_thread(
                runtime.identity_attestor.attest,
                metering_verifier=runtime.meter.signer.address,
                chain_id=policy.chain_id,
                vault_address=policy.vault_address,
                policy_set_hash=runtime.release.policy_set_hash,
                signer_custody=runtime.meter.signer.custody,
                challenge=challenge,
            )
            response = await asyncio.to_thread(
                runtime.identity_qvl_client.verify,
                packet,
            )
        return response.model_dump(mode="json", by_alias=True)

    @app.post("/meter")
    async def meter(request: Request, authorization: str = Header(default="")) -> Response:
        _authenticate(authorization, runtime.auth_token)
        async with gate.slot():
            raw = await _bounded_body(
                request,
                timeout_seconds=runtime.request_body_timeout_seconds,
            )
            parsed = _parse_request(raw)
            decision = await runtime.meter.meter(parsed)
        return Response(content=decision, status_code=200, media_type="application/json")

    return app


def create_production_app() -> FastAPI:
    settings = Settings()
    release = load_policy_set(settings.policy_set_path)
    if rpc_origin_from_url(settings.rpc_url.get_secret_value()) != release.policy.rpc_origin:
        raise PolicyRejected
    signer = DstackMeteringSigner.from_policy_set_hash(release.policy_set_hash)
    if settings.qvl_verifier_address != release.policy.metering_qvl_verifier:
        raise PolicyRejected
    replay_key = derive_dstack_replay_key(release.policy_set_hash)
    replay = DurableReplayStore(
        path=settings.state_path,
        policy_set_hash=release.policy_set_hash,
        _integrity_key=replay_key,
    )
    rpc = StrictJsonRpcClient(settings.rpc_url, timeout_seconds=settings.rpc_timeout_seconds)
    chain = BaseSepoliaStateVerifier(
        release=release,
        rpc=rpc,
        metering_verifier=signer.address,
        metering_qvl_verifier=release.policy.metering_qvl_verifier,
    )
    identity_attestor = DstackMeteringIdentityAttestor()
    identity_qvl_client = HttpsComputeMeteringQvlClient(
        verify_url=settings.qvl_url,
        auth_token=settings.qvl_auth_token.get_secret_value(),
        verifier_address=settings.qvl_verifier_address,
        release_policy_hash=settings.qvl_release_policy_hash,
        cvm_id=settings.cvm_id,
        deployment_intent_sha256=settings.deployment_intent_sha256,
        release_authority_sha256=settings.release_authority_sha256,
        ceremony_nonce=settings.ceremony_nonce,
        measurement_policy_sha256=settings.qvl_measurement_policy_sha256,
    )
    meter = ComputeMeter(
        release=release,
        signer=signer,
        chain=chain,
        replay=replay,
        identity_attestor=identity_attestor,
        qvl_client=identity_qvl_client,
    )
    runtime = Runtime(
        release=release,
        meter=meter,
        rpc=rpc,
        replay=replay,
        auth_token=settings.auth_token.get_secret_value(),
        identity_attestor=identity_attestor,
        identity_qvl_client=identity_qvl_client,
        max_concurrency=settings.max_concurrency,
        rate_capacity=settings.rate_capacity,
        rate_refill_per_second=settings.rate_refill_per_second,
        request_body_timeout_seconds=settings.request_body_timeout_seconds,
    )
    return _create_app(runtime)
