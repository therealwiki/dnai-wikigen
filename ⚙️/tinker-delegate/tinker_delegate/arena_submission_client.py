"""Version-pinned client for encrypted Arena safe-IR submissions.

This module is a *submission client*, not an execution prover.  It performs
three read-only checks before sending ciphertext:

* an exact, stable, ``finalized`` Base Sepolia ``ChallengeRegistry`` read;
* a recipient-key/report-data/quote-digest pin check; and
* a public worker-presence/release-binding check.

Those checks protect the caller from obvious release drift.  They do not
verify Intel TDX, establish an RPC quorum or consensus proof, authenticate the
delegate's heartbeat HMAC, or authorize worker execution.  The proxy and the
worker retain their independent authorization gates.

The only accepted credential source is ``WIKIGEN_ARENA_TOKEN``.  Candidate
plaintext, bearer tokens, ciphertext, and plaintext are never written to the
CLI output or included in exception messages.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Mapping, Protocol, Sequence, TextIO
from urllib.parse import quote, urlencode, urlparse

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_hash.auto import keccak

from tinker_delegate.arena_auth import (
    ARENA_AGENT_CREDENTIAL_AUDIENCE,
    ARENA_AGENT_CREDENTIAL_ISSUER,
    ARENA_AGENT_SCOPES,
)
from tinker_delegate.arena_ingress import (
    AES_GCM_NONCE_BYTES,
    GCM_TAG_BYTES,
    INGRESS_ALGORITHM,
    INGRESS_ATTESTATION_CONTEXT,
    INGRESS_CONTEXT,
    INGRESS_ENCODING,
    INGRESS_HKDF_INFO,
    INGRESS_SCHEMA_VERSION,
    MAX_AAD_BYTES,
    MAX_CIPHERTEXT_BYTES,
    ArenaCandidateBinding,
    ArenaCandidateEnvelope,
    arena_attestation_report_data,
    arena_candidate_aad,
    arena_idempotency_key_hash,
    arena_ingress_key_id,
    arena_submission_manifest_hash,
)
from tinker_delegate.arena_safe_ir import (
    SAFE_IR_CANDIDATE_KIND,
    SAFE_IR_ENTRYPOINT,
    SAFE_IR_MAX_CANDIDATE_BYTES,
    SAFE_IR_POLICY_COMMITMENT,
    SAFE_IR_RUNTIME,
    parse_safe_ir_program,
)
from tinker_delegate.arena_store import (
    DNASEQ_SAFE_IR_CHALLENGE_ID,
    DNASEQ_SAFE_IR_CHALLENGE_VERSION,
    EXECUTION_ASSURANCE,
    PRODUCT_STATUS,
    ChallengeManifest,
    QueueState,
    SubmissionIdentity,
    SubmissionManifest,
    SubmissionMode,
    default_challenge_catalog,
)
from tinker_delegate.arena_worker_cli import (
    BASE_SEPOLIA_CHAIN_ID,
    MAX_BLOCK_AGE_SECONDS,
    MAX_FUTURE_BLOCK_SKEW_SECONDS,
    ArenaRegistryChallengeState,
    ArenaRegistryReader,
    ArenaRegistryVersionState,
    ArenaWorkerBootstrapError,
    ArenaWorkerReleasePins,
    HttpsArenaRegistryReader,
    load_release_manifest,
)
from tinker_delegate.arena_worker_evidence import (
    EVIDENCE_CLASSIFICATION,
    ArenaWorkerReleaseBindings,
    arena_worker_heartbeat_binding_sha256,
    arena_worker_release_binding_sha256,
)


SUBMISSION_CLIENT_VERSION = "1.0.0"
SUBMISSION_CLIENT_CLASSIFICATION = "submission_client_not_execution_prover"
TOKEN_ENV = "WIKIGEN_ARENA_TOKEN"
MAX_TOKEN_BYTES = 4_096
MAX_PUBLIC_RESPONSE_BYTES = 512 * 1024
MAX_ERROR_RESPONSE_BYTES = 16 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 50_000
MAX_OWNER_PAGES = 8
MIN_TDX_QUOTE_BYTES = 632
MAX_TDX_QUOTE_BYTES = 16 * 1024
MAX_WORKER_HEARTBEAT_AGE_SECONDS = 300
REGISTRY_AUTHORIZATION_COMMITMENT_DOMAIN = (
    b"dnai-wikigen/arena-registry-authorization-snapshot/v1\0"
)

_AGENT_JWT_HEADER = {
    "alg": "HS256",
    "kid": "dstack-arena-agent-v1",
    "typ": "JWT",
}
_AGENT_JWT_FIELDS = frozenset(
    {
        "iss",
        "aud",
        "sub",
        "device_id",
        "owner_address",
        "challenge_id",
        "challenge_version",
        "generation",
        "scope",
        "daily_submission_cap",
        "iat",
        "nbf",
        "exp",
        "jti",
    }
)
_WORKER_CAPABILITY_FIELDS = frozenset(
    {
        "surface",
        "schema_version",
        "challenge_id",
        "challenge_version",
        "status",
        "backend",
        "isolation",
        "live_execution",
        "worker_connected",
        "safe_ir_execution_ready",
        "hostile_general_code_ready",
        "python_preview_live",
        "freshness",
        "evidence_authenticity",
        "evidence_classification",
        "gate_reason",
        "heartbeat_observed_at",
        "heartbeat_binding_sha256",
        "release_binding_sha256",
        "release_binding",
        "warning",
        "product_status",
        "exact_timing_egress",
        "internal_error_egress",
        "raw_candidate_egress",
        "tdx_attestation_egress",
    }
)
_ATTESTATION_FIELDS = frozenset(
    {
        "mode",
        "quote",
        "encryption_public_key",
        "report_context",
        "report_data",
        "quote_report_data",
        "app_id",
        "compose_hash",
        "os_image_hash",
        "verified",
    }
)
_CONTRACT_FIELDS = frozenset(
    {
        "surface",
        "schema_version",
        "product_status",
        "execution_assurance",
        "protocol",
        "encoding_rules",
        "aad",
        "recipient",
        "limits",
        "submission_gate",
        "envelope_exact_fields",
        "raw_secret_egress",
    }
)
_REGISTRY_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "verification_model",
        "chain_id",
        "block_number",
        "block_hash",
        "block_timestamp",
        "registry_address",
        "registry_runtime_code_hash",
        "approved_challenge_set_sha256",
        "catalog_challenge_id",
        "catalog_challenge_version",
        "catalog_manifest_hash",
        "registry_challenge_id",
        "registry_version",
        "controller_address",
        "pending_controller_address",
        "metadata_uri",
        "metadata_hash",
        "sealed_artifact_commitment",
        "evaluator_commitment",
        "release_policy_commitment",
        "registry_paused",
        "challenge_paused",
        "lifecycle",
        "configuration_frozen",
        "latest_version",
    }
)
_PUBLIC_SUBMISSION_FIELDS = frozenset(
    {
        "surface",
        "schema_version",
        "submission_id",
        "challenge_id",
        "challenge_version",
        "identity",
        "candidate_commitment",
        "manifest",
        "state",
        "queue_events",
        "ladder_release",
        "execution_capability",
        "execution_provenance",
        "product_status",
        "execution_assurance",
        "exact_timing_egress",
        "encrypted_reference_public",
        "raw_candidate_accepted",
        "raw_secret_egress",
    }
)
_OWNER_PAGE_FIELDS = frozenset(
    {
        "surface",
        "schema_version",
        "challenge_id",
        "challenge_version",
        "owner_identity",
        "page_count",
        "submissions",
        "has_more",
        "next_cursor",
        "scope",
        "product_status",
        "execution_assurance",
        "raw_candidate_egress",
        "encrypted_reference_egress",
        "exact_score_egress",
        "exact_reward_egress",
        "exact_timing_egress",
        "internal_error_egress",
    }
)
_OWNER_SUBMISSION_FIELDS = frozenset(
    {
        "surface",
        "schema_version",
        "submission_id",
        "challenge_id",
        "challenge_version",
        "identity",
        "candidate_commitment",
        "manifest",
        "state",
        "bounded_result",
        "execution_capability",
        "execution_provenance",
        "product_status",
        "execution_assurance",
        "raw_candidate_egress",
        "encrypted_reference_egress",
        "exact_score_egress",
        "exact_reward_egress",
        "exact_timing_egress",
        "internal_error_egress",
    }
)
_EXECUTION_PROVENANCE_FIELDS = frozenset(
    {
        "status",
        "outcome",
        "runtime",
        "runtime_policy_commitment",
        "challenge_manifest_hash",
        "compose_hash",
        "app_id",
        "os_image_hash",
        "quote_sha256",
        "verifier_address",
        "verdict_digest",
        "tee_signer_address",
        "chain_id",
        "challenge_registry_address",
        "evidence_classification",
        "independently_verified_by_client",
        "raw_tdx_quote_egress",
        "exact_score_egress",
        "exact_timing_egress",
    }
)
_ENVELOPE_FIELDS = [
    "schema_version",
    "algorithm",
    "encoding",
    "key_id",
    "attestation_report_data",
    "aad",
    "ephemeral_public_key",
    "nonce",
    "ciphertext",
]
_AAD_FIELDS = [
    "service",
    "context",
    "schema_version",
    "challenge_id",
    "challenge_version",
    "challenge_manifest_hash",
    "submission_manifest_hash",
    "candidate_commitment",
    "identity",
    "idempotency_key_hash",
    "key_id",
    "attestation_report_data_sha256",
    "registry_authorization_sha256",
]

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_RESOURCE_ID = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_JTI = re.compile(r"^[0-9a-f]{32}$")
_JWT_PART = re.compile(r"^[A-Za-z0-9_-]+$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SUBMISSION_ID = re.compile(r"^sub_[0-9a-f]{24}$")


class ArenaSubmissionClientError(RuntimeError):
    """Fail-closed client error with an allowlisted, non-sensitive reason."""

    _REASONS = frozenset(
        {
            "token_unavailable",
            "token_invalid",
            "release_pins_invalid",
            "transport_unavailable",
            "public_schema_invalid",
            "challenge_drift",
            "release_binding_unavailable",
            "registry_preflight_unavailable",
            "recipient_preflight_unavailable",
            "candidate_invalid",
            "submission_rejected",
            "submission_receipt_invalid",
            "owner_metadata_unavailable",
            "status_unavailable",
            "configuration_invalid",
        }
    )

    def __init__(self, reason: str):
        self.reason = reason if reason in self._REASONS else "transport_unavailable"
        super().__init__(self.reason)


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ArenaSubmissionClientError("public_schema_invalid") from exc


def _exact_mapping(
    value: Any,
    fields: frozenset[str] | set[str],
    *,
    reason: str = "public_schema_invalid",
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise ArenaSubmissionClientError(reason)
    return value


def _bounded_int(value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArenaSubmissionClientError("public_schema_invalid")
    if value < minimum or value > maximum:
        raise ArenaSubmissionClientError("public_schema_invalid")
    return value


def _bounded_ascii(value: Any, minimum: int, maximum: int) -> str:
    if not isinstance(value, str):
        raise ArenaSubmissionClientError("public_schema_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ArenaSubmissionClientError("public_schema_invalid") from exc
    if (
        not minimum <= len(encoded) <= maximum
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
    ):
        raise ArenaSubmissionClientError("public_schema_invalid")
    return value


def _decode_hex(value: Any, *, minimum: int, maximum: int) -> bytes:
    if not isinstance(value, str):
        raise ArenaSubmissionClientError("public_schema_invalid")
    raw = value.removeprefix("0x")
    if len(raw) % 2 or not re.fullmatch(r"[0-9a-f]+", raw or ""):
        raise ArenaSubmissionClientError("public_schema_invalid")
    try:
        decoded = bytes.fromhex(raw)
    except ValueError as exc:
        raise ArenaSubmissionClientError("public_schema_invalid") from exc
    if not minimum <= len(decoded) <= maximum:
        raise ArenaSubmissionClientError("public_schema_invalid")
    return decoded


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_base64url(value: Any, *, maximum: int) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > ((maximum * 8 + 5) // 6)
        or _JWT_PART.fullmatch(value) is None
        or "=" in value
    ):
        raise ArenaSubmissionClientError("token_invalid")
    try:
        decoded = base64.b64decode(
            value + "=" * ((-len(value)) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ArenaSubmissionClientError("token_invalid") from exc
    if len(decoded) > maximum or _base64url(decoded) != value:
        raise ArenaSubmissionClientError("token_invalid")
    return decoded


def _json_no_duplicates(raw: bytes, *, reason: str) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ArenaSubmissionClientError(reason)
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ArenaSubmissionClientError(reason)

    try:
        value = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except ArenaSubmissionClientError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ArenaSubmissionClientError(reason) from exc
    _bound_json_shape(value, reason=reason)
    return value


def _bound_json_shape(value: Any, *, reason: str) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ArenaSubmissionClientError(reason)
        if isinstance(item, Mapping):
            stack.extend((nested, depth + 1) for nested in item.values())
        elif isinstance(item, list):
            stack.extend((nested, depth + 1) for nested in item)


@dataclass(frozen=True, repr=False)
class ArenaAgentTokenClaims:
    owner_address: str
    credential_id: str
    device_id: str
    challenge_id: str
    challenge_version: str
    generation: int
    daily_submission_cap: int
    issued_at: int
    not_before: int
    expires_at: int

    def __repr__(self) -> str:
        return (
            "ArenaAgentTokenClaims("
            f"credential_id={self.credential_id!r}, "
            f"device_id={self.device_id!r}, "
            f"challenge={self.challenge_id!r}@{self.challenge_version!r})"
        )


def read_arena_agent_token(
    environment: Mapping[str, str] | None = None,
    *,
    now: int | None = None,
) -> tuple[str, ArenaAgentTokenClaims]:
    """Read and strictly project an agent bearer from its sole source.

    The local JWT projection is not signature verification.  It is used only
    to construct the candidate AAD identity proposal.  The proxy validates the
    HS256 signature, revocation state, generation, cap, scopes, and request
    commitment before accepting the request.
    """

    env = os.environ if environment is None else environment
    token = env.get(TOKEN_ENV, "")
    if not isinstance(token, str) or not token:
        raise ArenaSubmissionClientError("token_unavailable")
    if (
        not 80 <= len(token.encode("ascii", errors="ignore")) <= MAX_TOKEN_BYTES
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in token)
    ):
        raise ArenaSubmissionClientError("token_invalid")
    parts = token.split(".")
    if len(parts) != 3:
        raise ArenaSubmissionClientError("token_invalid")
    header_raw = _decode_base64url(parts[0], maximum=256)
    payload_raw = _decode_base64url(parts[1], maximum=2_048)
    signature = _decode_base64url(parts[2], maximum=32)
    if len(signature) != 32:
        raise ArenaSubmissionClientError("token_invalid")
    header = _json_no_duplicates(header_raw, reason="token_invalid")
    payload = _json_no_duplicates(payload_raw, reason="token_invalid")
    if header != _AGENT_JWT_HEADER:
        raise ArenaSubmissionClientError("token_invalid")
    claims = _exact_mapping(payload, _AGENT_JWT_FIELDS, reason="token_invalid")
    if (
        claims["iss"] != ARENA_AGENT_CREDENTIAL_ISSUER
        or claims["aud"] != ARENA_AGENT_CREDENTIAL_AUDIENCE
        or claims["challenge_id"] != DNASEQ_SAFE_IR_CHALLENGE_ID
        or claims["challenge_version"] != DNASEQ_SAFE_IR_CHALLENGE_VERSION
        or claims["scope"] != " ".join(ARENA_AGENT_SCOPES)
    ):
        raise ArenaSubmissionClientError("token_invalid")
    owner = claims["owner_address"]
    credential_id = claims["sub"]
    device_id = claims["device_id"]
    jti = claims["jti"]
    if (
        not isinstance(owner, str)
        or _ADDRESS.fullmatch(owner) is None
        or owner == "0x" + "0" * 40
        or not isinstance(credential_id, str)
        or _RESOURCE_ID.fullmatch(credential_id) is None
        or not isinstance(device_id, str)
        or _RESOURCE_ID.fullmatch(device_id) is None
        or not isinstance(jti, str)
        or _JTI.fullmatch(jti) is None
    ):
        raise ArenaSubmissionClientError("token_invalid")
    generation = _token_int(claims["generation"], 1, 1_000_000)
    cap = _token_int(claims["daily_submission_cap"], 1, 32)
    issued = _token_int(claims["iat"], 1, 4_102_444_800)
    not_before = _token_int(claims["nbf"], 1, 4_102_444_800)
    expires = _token_int(claims["exp"], 1, 4_102_444_800)
    checked_at = int(time.time() if now is None else now)
    if (
        isinstance(checked_at, bool)
        or checked_at < 1
        or not_before != issued
        or expires <= issued
        or expires - issued > 86_400
        or checked_at < not_before
        or checked_at >= expires
    ):
        raise ArenaSubmissionClientError("token_invalid")
    return token, ArenaAgentTokenClaims(
        owner_address=owner,
        credential_id=credential_id,
        device_id=device_id,
        challenge_id=DNASEQ_SAFE_IR_CHALLENGE_ID,
        challenge_version=DNASEQ_SAFE_IR_CHALLENGE_VERSION,
        generation=generation,
        daily_submission_cap=cap,
        issued_at=issued,
        not_before=not_before,
        expires_at=expires,
    )


def _token_int(value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArenaSubmissionClientError("token_invalid")
    if not minimum <= value <= maximum:
        raise ArenaSubmissionClientError("token_invalid")
    return value


@dataclass(frozen=True)
class TrustedArenaRelease:
    pins: ArenaWorkerReleasePins
    release_manifest_sha256: str
    release_sha: str
    image_digest: str
    verified_quote_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.pins, ArenaWorkerReleasePins):
            raise ArenaSubmissionClientError("release_pins_invalid")
        if (
            _SHA256.fullmatch(self.release_manifest_sha256) is None
            or _HEX_40.fullmatch(self.release_sha) is None
            or self.release_sha == "0" * 40
            or _SHA256.fullmatch(self.image_digest) is None
            or _SHA256.fullmatch(self.verified_quote_sha256) is None
        ):
            raise ArenaSubmissionClientError("release_pins_invalid")
        if any(
            value.endswith("0" * 64)
            for value in (
                self.release_manifest_sha256,
                self.image_digest,
                self.verified_quote_sha256,
            )
        ):
            raise ArenaSubmissionClientError("release_pins_invalid")

    @property
    def expected_worker_binding(self) -> ArenaWorkerReleaseBindings:
        binding = self.pins.challenge_binding
        tee = self.pins.tee_release
        return ArenaWorkerReleaseBindings(
            release_sha=self.release_sha,
            image_digest=self.image_digest,
            release_manifest_sha256=self.release_manifest_sha256,
            approved_challenge_set_sha256=self.pins.approved_challenge_set_sha256,
            approved_challenge_key=(
                f"{binding.catalog_challenge_id}@{binding.catalog_challenge_version}"
            ),
            release_policy_commitment=binding.release_policy_commitment,
            catalog_manifest_hash=binding.catalog_manifest_hash,
            runtime=binding.runtime,
            runtime_policy_commitment=binding.runtime_policy_commitment,
            compose_hash=tee.compose_hash,
            app_id=tee.app_id,
            os_image_hash=tee.os_image_hash,
        )


def load_trusted_arena_release(
    *,
    release_manifest_path: str,
    release_manifest_sha256: str,
    release_sha: str,
    image_digest: str,
    verified_quote_sha256: str,
) -> TrustedArenaRelease:
    """Load the exact existing ``safe-worker-release.v3`` format."""

    try:
        pins = load_release_manifest(
            SimpleNamespace(
                arena_worker_release_manifest_path=release_manifest_path,
                arena_worker_release_manifest_sha256=release_manifest_sha256,
            )
        )
        return TrustedArenaRelease(
            pins=pins,
            release_manifest_sha256=release_manifest_sha256,
            release_sha=release_sha,
            image_digest=image_digest,
            verified_quote_sha256=verified_quote_sha256,
        )
    except ArenaSubmissionClientError:
        raise
    except (ArenaWorkerBootstrapError, OSError, ValueError) as exc:
        raise ArenaSubmissionClientError("release_pins_invalid") from exc


class ArenaHttpTransport(Protocol):
    def get_json(self, path: str, *, authorized: bool = False) -> Any: ...

    def post_json(
        self,
        path: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> Any: ...

    def close(self) -> None: ...


class HttpsArenaSubmissionTransport:
    """Bounded no-redirect transport; its repr never contains the bearer."""

    def __init__(
        self,
        base_url: str,
        *,
        token: str,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = _https_origin(base_url, label="delegate")
        if not isinstance(token, str) or not token:
            raise ArenaSubmissionClientError("token_unavailable")
        self._token = token
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(20.0, connect=10.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None

    def __repr__(self) -> str:
        return f"HttpsArenaSubmissionTransport(base_url={self.base_url!r})"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def get_json(self, path: str, *, authorized: bool = False) -> Any:
        headers = {"Accept": "application/json", "Cache-Control": "no-store"}
        if authorized:
            headers["Authorization"] = f"Bearer {self._token}"
        return self._request("GET", path, headers=headers, body=None)

    def post_json(
        self,
        path: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> Any:
        body = _canonical_json(payload)
        if len(body) > 128 * 1024:
            raise ArenaSubmissionClientError("candidate_invalid")
        return self._request(
            "POST",
            path,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._token}",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
                "Idempotency-Key": idempotency_key,
            },
            body=body,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
    ) -> Any:
        if not path.startswith("/") or "#" in path:
            raise ArenaSubmissionClientError("configuration_invalid")
        try:
            request = self._client.build_request(
                method,
                f"{self.base_url}{path}",
                headers=dict(headers),
                content=body,
            )
            response = self._client.send(request, stream=True, follow_redirects=False)
            try:
                limit = (
                    MAX_PUBLIC_RESPONSE_BYTES
                    if 200 <= response.status_code < 300
                    else MAX_ERROR_RESPONSE_BYTES
                )
                raw = _bounded_response_body(response, limit)
                if response.history or not 200 <= response.status_code < 300:
                    raise ArenaSubmissionClientError(
                        "submission_rejected" if method == "POST" else "transport_unavailable"
                    )
            finally:
                response.close()
        except ArenaSubmissionClientError:
            raise
        except (httpx.HTTPError, OSError, ValueError) as exc:
            raise ArenaSubmissionClientError("transport_unavailable") from exc
        return _json_no_duplicates(raw, reason="public_schema_invalid")


def _bounded_response_body(response: httpx.Response, maximum: int) -> bytes:
    declared = response.headers.get("content-length", "").strip()
    if declared.isdigit() and int(declared) > maximum:
        raise ArenaSubmissionClientError("transport_unavailable")
    chunks: list[bytes] = []
    received = 0
    try:
        for chunk in response.iter_bytes():
            received += len(chunk)
            if received > maximum:
                raise ArenaSubmissionClientError("transport_unavailable")
            chunks.append(chunk)
    except ArenaSubmissionClientError:
        raise
    except (httpx.HTTPError, OSError) as exc:
        raise ArenaSubmissionClientError("transport_unavailable") from exc
    if received < 2:
        raise ArenaSubmissionClientError("transport_unavailable")
    return b"".join(chunks)


def _https_origin(value: str, *, label: str) -> str:
    try:
        parsed = urlparse(value)
    except ValueError as exc:
        raise ArenaSubmissionClientError("configuration_invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ArenaSubmissionClientError("configuration_invalid")
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"https://{parsed.hostname.lower()}{port}"


@dataclass(frozen=True)
class RecipientPreflight:
    public_key: bytes = field(repr=False)
    key_id: str
    report_data: bytes = field(repr=False)
    attestation_report_data_sha256: str
    quote_sha256: str

    def __repr__(self) -> str:
        return (
            "RecipientPreflight("
            f"key_id={self.key_id!r}, quote_sha256={self.quote_sha256!r}, "
            "tdx_verified=False)"
        )


@dataclass(frozen=True)
class ArenaSubmissionPreflight:
    challenge: ChallengeManifest
    registry_snapshot: Mapping[str, Any]
    registry_authorization_sha256: str
    recipient: RecipientPreflight
    worker_release_binding_sha256: str
    heartbeat_binding_sha256: str

    def public_summary(self) -> dict[str, Any]:
        return {
            "surface": "arena_submission_client_preflight",
            "schema_version": 1,
            "client_version": SUBMISSION_CLIENT_VERSION,
            "classification": SUBMISSION_CLIENT_CLASSIFICATION,
            "challenge_id": self.challenge.challenge_id,
            "challenge_version": self.challenge.version,
            "challenge_manifest_hash": self.challenge.manifest_hash,
            "registry_authorization_sha256": self.registry_authorization_sha256,
            "registry_verification_model": (
                "single_rpc_reported_finalized_pinned_block"
            ),
            "independent_rpc_quorum_verified": False,
            "consensus_proof_verified": False,
            "recipient_key_id": self.recipient.key_id,
            "quote_digest_pin_matched": True,
            "tdx_verified": False,
            "worker_release_binding_sha256": self.worker_release_binding_sha256,
            "worker_heartbeat_binding_sha256": self.heartbeat_binding_sha256,
            "worker_presence_classification": EVIDENCE_CLASSIFICATION,
            "worker_execution_authorized_by_client": False,
        }


@dataclass(frozen=True, repr=False)
class PreparedArenaSubmission:
    payload: Mapping[str, Any] = field(repr=False)
    candidate_commitment: str
    ciphertext_sha256: str
    idempotency_key: str = field(repr=False)
    key_id: str
    registry_authorization_sha256: str

    def __repr__(self) -> str:
        return (
            "PreparedArenaSubmission("
            f"candidate_commitment={self.candidate_commitment!r}, "
            f"ciphertext_sha256={self.ciphertext_sha256!r}, "
            f"key_id={self.key_id!r})"
        )


@dataclass(frozen=True)
class ArenaSubmissionStatus:
    submission_id: str
    state: str
    candidate_commitment: str
    product_status: str
    execution_assurance: str
    owner_metadata: Mapping[str, Any]
    terminal: bool

    def public_summary(self) -> dict[str, Any]:
        return {
            "surface": "arena_submission_client_status",
            "schema_version": 1,
            "client_version": SUBMISSION_CLIENT_VERSION,
            "classification": SUBMISSION_CLIENT_CLASSIFICATION,
            "submission_id": self.submission_id,
            "state": self.state,
            "candidate_commitment": self.candidate_commitment,
            "product_status": self.product_status,
            "execution_assurance": self.execution_assurance,
            "terminal": self.terminal,
            "owner_metadata": dict(self.owner_metadata),
            "execution_independently_verified_by_client": False,
            "tdx_verified": False,
        }


class ArenaSubmissionClient:
    """Exact DNASeq safe-IR v1 submission workflow."""

    def __init__(
        self,
        *,
        transport: ArenaHttpTransport,
        registry_reader: ArenaRegistryReader,
        trusted_release: TrustedArenaRelease,
        token_claims: ArenaAgentTokenClaims,
        clock: Callable[[], float] = time.time,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.transport = transport
        self.registry_reader = registry_reader
        self.trusted_release = trusted_release
        self.token_claims = token_claims
        self.clock = clock
        self.sleeper = sleeper
        if (
            token_claims.challenge_id != DNASEQ_SAFE_IR_CHALLENGE_ID
            or token_claims.challenge_version != DNASEQ_SAFE_IR_CHALLENGE_VERSION
        ):
            raise ArenaSubmissionClientError("token_invalid")

    def close(self) -> None:
        try:
            self.transport.close()
        finally:
            self.registry_reader.close()

    def preflight(self) -> ArenaSubmissionPreflight:
        challenge = self._fetch_challenge()
        snapshot = self._registry_preflight(challenge)
        registry_sha256 = _registry_snapshot_sha256(snapshot)
        release_sha256, heartbeat_sha256 = self._release_binding_preflight(
            challenge,
            snapshot,
        )
        recipient = self._recipient_preflight()
        return ArenaSubmissionPreflight(
            challenge=challenge,
            registry_snapshot=snapshot,
            registry_authorization_sha256=registry_sha256,
            recipient=recipient,
            worker_release_binding_sha256=release_sha256,
            heartbeat_binding_sha256=heartbeat_sha256,
        )

    def prepare_submission(
        self,
        source: bytes | bytearray,
        *,
        idempotency_key: str,
        preflight: ArenaSubmissionPreflight,
        ephemeral_private_key: bytes | None = None,
        nonce: bytes | None = None,
    ) -> PreparedArenaSubmission:
        if (
            not isinstance(idempotency_key, str)
            or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
            or len(idempotency_key.encode("ascii", errors="ignore")) > 128
        ):
            raise ArenaSubmissionClientError("candidate_invalid")
        try:
            program = parse_safe_ir_program(source)
        except Exception as exc:
            raise ArenaSubmissionClientError("candidate_invalid") from exc
        challenge = preflight.challenge
        if (
            challenge.challenge_id != DNASEQ_SAFE_IR_CHALLENGE_ID
            or challenge.version != DNASEQ_SAFE_IR_CHALLENGE_VERSION
            or challenge.candidate_kind != SAFE_IR_CANDIDATE_KIND
            or challenge.runtime != SAFE_IR_RUNTIME
            or challenge.entrypoint != SAFE_IR_ENTRYPOINT
            or program.source_bytes > challenge.max_source_bytes
        ):
            raise ArenaSubmissionClientError("challenge_drift")
        identity = _submission_identity(self.token_claims.owner_address)
        manifest = SubmissionManifest(
            challenge_manifest_hash=challenge.manifest_hash,
            candidate_kind=challenge.candidate_kind,
            runtime=challenge.runtime,
            entrypoint=challenge.entrypoint,
            source_bytes=program.source_bytes,
            mode=SubmissionMode.LEADERBOARD,
        )
        binding = ArenaCandidateBinding(
            challenge_id=challenge.challenge_id,
            challenge_version=challenge.version,
            challenge_manifest_hash=challenge.manifest_hash,
            submission_manifest_hash=arena_submission_manifest_hash(manifest),
            candidate_commitment=program.candidate_commitment,
            identity=identity.to_public_dict(),
            idempotency_key_hash=arena_idempotency_key_hash(
                challenge=challenge,
                identity=identity,
                idempotency_key=idempotency_key,
            ),
            key_id=preflight.recipient.key_id,
            attestation_report_data_sha256=(
                preflight.recipient.attestation_report_data_sha256
            ),
            registry_authorization_sha256=(
                preflight.registry_authorization_sha256
            ),
        )
        aad = arena_candidate_aad(binding)
        if len(aad) > MAX_AAD_BYTES:
            raise ArenaSubmissionClientError("candidate_invalid")
        try:
            encrypted = _encrypt_candidate(
                bytes(source),
                recipient_public_key=preflight.recipient.public_key,
                aad=aad,
                ephemeral_private_key=ephemeral_private_key,
                nonce=nonce,
            )
            envelope = ArenaCandidateEnvelope.from_mapping(
                {
                    "schema_version": INGRESS_SCHEMA_VERSION,
                    "algorithm": INGRESS_ALGORITHM,
                    "encoding": INGRESS_ENCODING,
                    "key_id": preflight.recipient.key_id,
                    "attestation_report_data": (
                        preflight.recipient.report_data.hex()
                    ),
                    "aad": _base64url(aad),
                    "ephemeral_public_key": _base64url(
                        encrypted["ephemeral_public_key"]
                    ),
                    "nonce": _base64url(encrypted["nonce"]),
                    "ciphertext": _base64url(encrypted["ciphertext"]),
                }
            )
            payload = {
                "candidate_commitment": program.candidate_commitment,
                "manifest": manifest.to_persisted_dict(),
                "registry_authorization": dict(preflight.registry_snapshot),
                "envelope": envelope.to_persisted_dict(),
            }
            return PreparedArenaSubmission(
                payload=payload,
                candidate_commitment=program.candidate_commitment,
                ciphertext_sha256=envelope.ciphertext_sha256,
                idempotency_key=idempotency_key,
                key_id=preflight.recipient.key_id,
                registry_authorization_sha256=(
                    preflight.registry_authorization_sha256
                ),
            )
        except ArenaSubmissionClientError:
            raise
        except Exception as exc:
            raise ArenaSubmissionClientError("candidate_invalid") from exc

    def submit(
        self,
        source: bytes | bytearray,
        *,
        idempotency_key: str,
        poll_attempts: int = 1,
        poll_interval_seconds: float = 2.0,
    ) -> ArenaSubmissionStatus:
        attempts = _bounded_int(poll_attempts, 1, 120)
        if (
            isinstance(poll_interval_seconds, bool)
            or not isinstance(poll_interval_seconds, (int, float))
            or not 0 <= float(poll_interval_seconds) <= 60
        ):
            raise ArenaSubmissionClientError("configuration_invalid")
        initial = self.preflight()
        prepared = self.prepare_submission(
            source,
            idempotency_key=idempotency_key,
            preflight=initial,
        )
        # Repeat every read-only gate after encryption.  A heartbeat timestamp
        # may advance, but the exact release, challenge, registry commitments,
        # recipient key, and independently supplied quote digest may not drift.
        current = self.preflight()
        if not _same_release_preflight(initial, current):
            raise ArenaSubmissionClientError("challenge_drift")
        path = _challenge_path() + "/submissions"
        try:
            raw = self.transport.post_json(
                path,
                prepared.payload,
                idempotency_key=prepared.idempotency_key,
            )
            receipt = _parse_submission_receipt(raw, prepared)
        except ArenaSubmissionClientError:
            raise
        except Exception as exc:
            raise ArenaSubmissionClientError("submission_rejected") from exc
        submission_id = receipt["submission"]["submission_id"]
        return self.poll_submission(
            submission_id,
            expected_commitment=prepared.candidate_commitment,
            attempts=attempts,
            interval_seconds=float(poll_interval_seconds),
        )

    def poll_submission(
        self,
        submission_id: str,
        *,
        expected_commitment: str | None = None,
        attempts: int = 1,
        interval_seconds: float = 2.0,
    ) -> ArenaSubmissionStatus:
        if _SUBMISSION_ID.fullmatch(submission_id) is None:
            raise ArenaSubmissionClientError("status_unavailable")
        last: ArenaSubmissionStatus | None = None
        for index in range(_bounded_int(attempts, 1, 120)):
            public = _parse_public_submission(
                self.transport.get_json(f"/arena/submissions/{submission_id}"),
                expected_challenge=(
                    DNASEQ_SAFE_IR_CHALLENGE_ID,
                    DNASEQ_SAFE_IR_CHALLENGE_VERSION,
                ),
            )
            if (
                expected_commitment is not None
                and not hmac.compare_digest(
                    str(public["candidate_commitment"]), expected_commitment
                )
            ):
                raise ArenaSubmissionClientError("submission_receipt_invalid")
            owner = self._find_owner_submission(submission_id)
            if (
                owner["candidate_commitment"] != public["candidate_commitment"]
                or owner["state"] != public["state"]
                or owner["manifest"] != public["manifest"]
                or owner["identity"] != public["identity"]
                or owner["execution_provenance"]
                != public["execution_provenance"]
                or owner["product_status"] != public["product_status"]
                or owner["execution_assurance"]
                != public["execution_assurance"]
            ):
                raise ArenaSubmissionClientError("owner_metadata_unavailable")
            self._validate_worker_reported_release(public)
            state = str(public["state"])
            terminal = state in {
                QueueState.COMPLETED.value,
                QueueState.FAILED.value,
                QueueState.WITHHELD.value,
                QueueState.CANCELLED.value,
                QueueState.EXPIRED.value,
                QueueState.DEAD_LETTER.value,
            }
            last = ArenaSubmissionStatus(
                submission_id=submission_id,
                state=state,
                candidate_commitment=str(public["candidate_commitment"]),
                product_status=str(public["product_status"]),
                execution_assurance=str(public["execution_assurance"]),
                owner_metadata=_owner_metadata_projection(owner),
                terminal=terminal,
            )
            if terminal or index + 1 >= attempts:
                return last
            self.sleeper(interval_seconds)
        if last is None:  # pragma: no cover - attempts are bounded to >=1.
            raise ArenaSubmissionClientError("status_unavailable")
        return last

    def _fetch_challenge(self) -> ChallengeManifest:
        try:
            raw = self.transport.get_json(_challenge_path())
            challenge = ChallengeManifest.from_public_dict(raw)
            expected = default_challenge_catalog().get(
                DNASEQ_SAFE_IR_CHALLENGE_ID,
                DNASEQ_SAFE_IR_CHALLENGE_VERSION,
            )
        except Exception as exc:
            if isinstance(exc, ArenaSubmissionClientError):
                raise
            raise ArenaSubmissionClientError("public_schema_invalid") from exc
        if challenge != expected:
            raise ArenaSubmissionClientError("challenge_drift")
        binding = self.trusted_release.pins.challenge_binding
        if (
            challenge.manifest_hash != binding.catalog_manifest_hash
            or binding.runtime != SAFE_IR_RUNTIME
            or binding.runtime_policy_commitment != SAFE_IR_POLICY_COMMITMENT
        ):
            raise ArenaSubmissionClientError("challenge_drift")
        return challenge

    def _release_binding_preflight(
        self,
        challenge: ChallengeManifest,
        registry_snapshot: Mapping[str, Any],
    ) -> tuple[str, str]:
        try:
            raw = self.transport.get_json(_challenge_path() + "/worker-capability")
            capability = _exact_mapping(
                raw,
                _WORKER_CAPABILITY_FIELDS,
                reason="release_binding_unavailable",
            )
            if (
                capability["surface"] != "arena_worker_capability"
                or capability["schema_version"] != 2
                or capability["challenge_id"] != challenge.challenge_id
                or capability["challenge_version"] != challenge.version
                or capability["status"] != "live"
                or capability["backend"] != "release_bound_safe_ir_worker"
                or capability["isolation"] != "independent_job_gate_required"
                or capability["live_execution"] is not True
                or capability["worker_connected"] is not True
                or capability["safe_ir_execution_ready"] is not True
                or capability["hostile_general_code_ready"] is not False
                or capability["python_preview_live"] is not False
                or capability["freshness"] != "fresh"
                or capability["evidence_authenticity"] != "hmac_verified"
                or capability["evidence_classification"] != EVIDENCE_CLASSIFICATION
                or capability["gate_reason"] != "ready"
                or capability["product_status"] != "live"
                or capability["exact_timing_egress"] is not False
                or capability["internal_error_egress"] is not False
                or capability["raw_candidate_egress"] is not False
                or capability["tdx_attestation_egress"] is not False
            ):
                raise ArenaSubmissionClientError("release_binding_unavailable")
            _bounded_ascii(capability["warning"], 1, 512)
            raw_binding = capability["release_binding"]
            if not isinstance(raw_binding, Mapping):
                raise ArenaSubmissionClientError("release_binding_unavailable")
            observed = ArenaWorkerReleaseBindings.from_mapping(raw_binding)
            expected = self.trusted_release.expected_worker_binding
            if observed != expected:
                raise ArenaSubmissionClientError("release_binding_unavailable")
            release_sha256 = arena_worker_release_binding_sha256(observed)
            if capability["release_binding_sha256"] != release_sha256:
                raise ArenaSubmissionClientError("release_binding_unavailable")
            observed_at = capability["heartbeat_observed_at"]
            if isinstance(observed_at, bool) or not isinstance(observed_at, int):
                raise ArenaSubmissionClientError("release_binding_unavailable")
            now = int(self.clock())
            if (
                observed_at < 1
                or observed_at > now + MAX_FUTURE_BLOCK_SKEW_SECONDS
                or now - observed_at > MAX_WORKER_HEARTBEAT_AGE_SECONDS
            ):
                raise ArenaSubmissionClientError("release_binding_unavailable")
            heartbeat_sha256 = arena_worker_heartbeat_binding_sha256(
                challenge_id=challenge.challenge_id,
                challenge_version=challenge.version,
                heartbeat_observed_at=observed_at,
                release_binding_sha256=release_sha256,
            )
            if capability["heartbeat_binding_sha256"] != heartbeat_sha256:
                raise ArenaSubmissionClientError("release_binding_unavailable")
            if (
                observed.approved_challenge_set_sha256
                != registry_snapshot["approved_challenge_set_sha256"]
                or observed.catalog_manifest_hash
                != registry_snapshot["catalog_manifest_hash"]
                or observed.release_policy_commitment
                != registry_snapshot["release_policy_commitment"]
            ):
                raise ArenaSubmissionClientError("release_binding_unavailable")
            return release_sha256, heartbeat_sha256
        except ArenaSubmissionClientError:
            raise
        except Exception as exc:
            raise ArenaSubmissionClientError("release_binding_unavailable") from exc

    def _registry_preflight(
        self,
        challenge: ChallengeManifest,
    ) -> Mapping[str, Any]:
        pins = self.trusted_release.pins
        binding = pins.challenge_binding
        reader = self.registry_reader
        try:
            if reader.chain_id() != BASE_SEPOLIA_CHAIN_ID:
                raise ValueError("wrong chain")
            finalized = reader.finalized_block()
            now = int(self.clock())
            if (
                finalized.timestamp > now + MAX_FUTURE_BLOCK_SKEW_SECONDS
                or now - finalized.timestamp > MAX_BLOCK_AGE_SECONDS
            ):
                raise ValueError("stale finalized block")
            before = reader.block(finalized.number)
            if before != finalized:
                raise ValueError("noncanonical finalized block")
            code = reader.bytecode(
                pins.challenge_registry_address,
                finalized.number,
            )
            if not code or "0x" + keccak(code).hex() != (
                pins.challenge_registry_runtime_code_hash
            ):
                raise ValueError("registry code drift")
            paused = reader.registry_paused(
                pins.challenge_registry_address,
                finalized.number,
            )
            exists = reader.challenge_exists(
                pins.challenge_registry_address,
                binding.registry_challenge_id,
                finalized.number,
            )
            registry_challenge = reader.challenge(
                pins.challenge_registry_address,
                binding.registry_challenge_id,
                finalized.number,
            )
            registry_version = reader.version(
                pins.challenge_registry_address,
                binding.registry_challenge_id,
                binding.registry_version,
                finalized.number,
            )
            after = reader.block(finalized.number)
            finalized_after = reader.finalized_block()
            if after != before or finalized_after != finalized:
                raise ValueError("registry read was not stable")
            if paused or not exists:
                raise ValueError("registry row unavailable")
            expected_challenge = ArenaRegistryChallengeState(
                controller=binding.controller_address,
                pending_controller=binding.pending_controller_address,
                lifecycle=1,
                latest_version=binding.registry_version,
                paused=False,
                configuration_frozen=True,
            )
            expected_version = ArenaRegistryVersionState(
                metadata_uri=binding.metadata_uri,
                metadata_hash=binding.metadata_hash,
                sealed_artifact_commitment=binding.sealed_artifact_commitment,
                evaluator_commitment=binding.evaluator_commitment,
                release_policy_commitment=binding.release_policy_commitment,
            )
            if registry_challenge != expected_challenge or registry_version != expected_version:
                raise ValueError("registry row drift")
            if (
                challenge.challenge_id != binding.catalog_challenge_id
                or challenge.version != binding.catalog_challenge_version
                or challenge.manifest_hash != binding.catalog_manifest_hash
            ):
                raise ValueError("catalog drift")
            snapshot = {
                "schema_version": 1,
                "verification_model": (
                    "single_rpc_reported_finalized_pinned_block"
                ),
                "chain_id": BASE_SEPOLIA_CHAIN_ID,
                "block_number": str(finalized.number),
                "block_hash": finalized.block_hash,
                "block_timestamp": str(finalized.timestamp),
                "registry_address": pins.challenge_registry_address,
                "registry_runtime_code_hash": (
                    pins.challenge_registry_runtime_code_hash
                ),
                "approved_challenge_set_sha256": (
                    pins.approved_challenge_set_sha256
                ),
                "catalog_challenge_id": challenge.challenge_id,
                "catalog_challenge_version": challenge.version,
                "catalog_manifest_hash": challenge.manifest_hash,
                "registry_challenge_id": str(binding.registry_challenge_id),
                "registry_version": binding.registry_version,
                "controller_address": binding.controller_address,
                "pending_controller_address": binding.pending_controller_address,
                "metadata_uri": binding.metadata_uri,
                "metadata_hash": binding.metadata_hash,
                "sealed_artifact_commitment": binding.sealed_artifact_commitment,
                "evaluator_commitment": binding.evaluator_commitment,
                "release_policy_commitment": binding.release_policy_commitment,
                "registry_paused": False,
                "challenge_paused": False,
                "lifecycle": 1,
                "configuration_frozen": True,
                "latest_version": binding.registry_version,
            }
            _exact_mapping(
                snapshot,
                _REGISTRY_SNAPSHOT_FIELDS,
                reason="registry_preflight_unavailable",
            )
            return snapshot
        except ArenaSubmissionClientError:
            raise
        except Exception as exc:
            raise ArenaSubmissionClientError("registry_preflight_unavailable") from exc

    def _recipient_preflight(self) -> RecipientPreflight:
        try:
            attestation = self.transport.get_json("/attestation?context=arena")
            contract = self.transport.get_json(
                "/arena/candidate-encryption-contract"
            )
            return _parse_recipient_preflight(
                attestation,
                contract,
                trusted_release=self.trusted_release,
            )
        except ArenaSubmissionClientError:
            raise
        except Exception as exc:
            raise ArenaSubmissionClientError("recipient_preflight_unavailable") from exc

    def _find_owner_submission(self, submission_id: str) -> Mapping[str, Any]:
        cursor: str | None = None
        expected_identity = _submission_identity(
            self.token_claims.owner_address
        ).to_public_dict()
        for _ in range(MAX_OWNER_PAGES):
            query = {"limit": "100"}
            if cursor is not None:
                query["cursor"] = cursor
            path = _challenge_path() + "/submissions/mine?" + urlencode(query)
            page = _parse_owner_page(
                self.transport.get_json(path, authorized=True)
            )
            if page["owner_identity"] != expected_identity["wallet_address_hash"]:
                raise ArenaSubmissionClientError("owner_metadata_unavailable")
            for item in page["submissions"]:
                if item["identity"] != expected_identity:
                    raise ArenaSubmissionClientError("owner_metadata_unavailable")
                if item["submission_id"] == submission_id:
                    return item
            if page["has_more"] is not True:
                break
            cursor = page["next_cursor"]
        raise ArenaSubmissionClientError("owner_metadata_unavailable")

    def _validate_worker_reported_release(
        self,
        submission: Mapping[str, Any],
    ) -> None:
        evidence = submission["execution_provenance"]
        if evidence["status"] == "not_executed":
            return
        pins = self.trusted_release.pins
        tee = pins.tee_release
        if (
            evidence["compose_hash"] != tee.compose_hash
            or evidence["app_id"] != tee.app_id
            or evidence["os_image_hash"] != tee.os_image_hash
            or evidence["tee_signer_address"] != tee.tee_signer_address
            or evidence["challenge_registry_address"]
            != pins.challenge_registry_address
            or evidence["verifier_address"]
            not in pins.trusted_qvl_verifier_addresses
        ):
            raise ArenaSubmissionClientError("status_unavailable")


def _challenge_path() -> str:
    return (
        "/arena/challenges/"
        + quote(DNASEQ_SAFE_IR_CHALLENGE_ID, safe="")
        + "/versions/"
        + quote(DNASEQ_SAFE_IR_CHALLENGE_VERSION, safe="")
    )


def _submission_identity(owner_address: str) -> SubmissionIdentity:
    project_id = "personal-" + hashlib.sha256(
        b"arena-personal-project:" + owner_address.encode("ascii")
    ).hexdigest()[:32]
    return SubmissionIdentity(wallet_address=owner_address, project_id=project_id)


def _registry_snapshot_sha256(snapshot: Mapping[str, Any]) -> str:
    _exact_mapping(
        snapshot,
        _REGISTRY_SNAPSHOT_FIELDS,
        reason="registry_preflight_unavailable",
    )
    return "sha256:" + hashlib.sha256(
        REGISTRY_AUTHORIZATION_COMMITMENT_DOMAIN + _canonical_json(snapshot)
    ).hexdigest()


def _same_release_preflight(
    left: ArenaSubmissionPreflight,
    right: ArenaSubmissionPreflight,
) -> bool:
    static_registry_fields = _REGISTRY_SNAPSHOT_FIELDS - {
        "block_number",
        "block_hash",
        "block_timestamp",
    }
    return (
        left.challenge == right.challenge
        and all(
            left.registry_snapshot[field] == right.registry_snapshot[field]
            for field in static_registry_fields
        )
        and hmac.compare_digest(
            left.recipient.key_id,
            right.recipient.key_id,
        )
        and hmac.compare_digest(
            left.recipient.attestation_report_data_sha256,
            right.recipient.attestation_report_data_sha256,
        )
        and hmac.compare_digest(
            left.recipient.quote_sha256,
            right.recipient.quote_sha256,
        )
        and hmac.compare_digest(
            left.worker_release_binding_sha256,
            right.worker_release_binding_sha256,
        )
    )


def _parse_recipient_preflight(
    attestation_value: Any,
    contract_value: Any,
    *,
    trusted_release: TrustedArenaRelease,
) -> RecipientPreflight:
    try:
        attestation = _exact_mapping(
            attestation_value,
            _ATTESTATION_FIELDS,
            reason="recipient_preflight_unavailable",
        )
        contract = _parse_encryption_contract(contract_value)
        if (
            attestation["mode"] != "tdx"
            or attestation["report_context"] != INGRESS_ATTESTATION_CONTEXT
            or attestation["verified"] is not False
        ):
            raise ArenaSubmissionClientError("recipient_preflight_unavailable")
        public_key = _decode_hex(
            attestation["encryption_public_key"], minimum=32, maximum=32
        )
        report_data = _decode_hex(attestation["report_data"], minimum=32, maximum=32)
        quote_bytes = _decode_hex(
            attestation["quote"],
            minimum=MIN_TDX_QUOTE_BYTES,
            maximum=MAX_TDX_QUOTE_BYTES,
        )
        quote_report_data = _decode_hex(
            attestation["quote_report_data"], minimum=32, maximum=64
        )
        expected_key_id = arena_ingress_key_id(public_key)
        expected_report_data = arena_attestation_report_data(public_key)
        expected_report_hash = "sha256:" + hashlib.sha256(report_data).hexdigest()
        quote_sha256 = "sha256:" + hashlib.sha256(quote_bytes).hexdigest()
        recipient = contract["recipient"]
        tee = trusted_release.pins.tee_release
        if (
            recipient["encryption_public_key"] != public_key.hex()
            or recipient["key_id"] != expected_key_id
            or recipient["report_context"] != INGRESS_ATTESTATION_CONTEXT
            or recipient["report_data"] != report_data.hex()
            or recipient["attestation_report_data_sha256"] != expected_report_hash
            or not hmac.compare_digest(report_data, expected_report_data)
            or not hmac.compare_digest(
                quote_sha256,
                trusted_release.verified_quote_sha256,
            )
            or quote_report_data[:32] != report_data
            or (
                len(quote_report_data) == 64
                and quote_report_data[32:] != b"\0" * 32
            )
            or attestation["compose_hash"] != tee.compose_hash
            or attestation["app_id"] != tee.app_id
            or attestation["os_image_hash"] != tee.os_image_hash
        ):
            raise ArenaSubmissionClientError("recipient_preflight_unavailable")
        try:
            X25519PublicKey.from_public_bytes(public_key)
        except ValueError as exc:
            raise ArenaSubmissionClientError("recipient_preflight_unavailable") from exc
        return RecipientPreflight(
            public_key=public_key,
            key_id=expected_key_id,
            report_data=report_data,
            attestation_report_data_sha256=expected_report_hash,
            quote_sha256=quote_sha256,
        )
    except ArenaSubmissionClientError:
        raise
    except Exception as exc:
        raise ArenaSubmissionClientError("recipient_preflight_unavailable") from exc


def _parse_encryption_contract(value: Any) -> Mapping[str, Any]:
    contract = _exact_mapping(
        value,
        _CONTRACT_FIELDS,
        reason="recipient_preflight_unavailable",
    )
    if (
        contract["surface"] != "arena_candidate_browser_encryption_contract"
        or contract["schema_version"] != INGRESS_SCHEMA_VERSION
        or contract["product_status"] != PRODUCT_STATUS
        or contract["execution_assurance"] != EXECUTION_ASSURANCE
        or contract["raw_secret_egress"] is not False
    ):
        raise ArenaSubmissionClientError("recipient_preflight_unavailable")
    protocol = _exact_mapping(
        contract["protocol"],
        {"algorithm", "encoding", "x25519_public_key_bytes", "hkdf", "aes_gcm"},
        reason="recipient_preflight_unavailable",
    )
    hkdf = _exact_mapping(
        protocol["hkdf"],
        {"hash", "length_bytes", "salt", "info_utf8"},
        reason="recipient_preflight_unavailable",
    )
    aes = _exact_mapping(
        protocol["aes_gcm"],
        {"key_bits", "nonce_bytes", "tag_bytes", "additional_authenticated_data"},
        reason="recipient_preflight_unavailable",
    )
    if (
        protocol["algorithm"] != INGRESS_ALGORITHM
        or protocol["encoding"] != INGRESS_ENCODING
        or protocol["x25519_public_key_bytes"] != 32
        or hkdf
        != {
            "hash": "SHA-256",
            "length_bytes": 32,
            "salt": "SHA-256(canonical_aad_bytes)",
            "info_utf8": INGRESS_HKDF_INFO.decode("ascii"),
        }
        or aes
        != {
            "key_bits": 256,
            "nonce_bytes": AES_GCM_NONCE_BYTES,
            "tag_bytes": GCM_TAG_BYTES,
            "additional_authenticated_data": "canonical_aad_bytes",
        }
    ):
        raise ArenaSubmissionClientError("recipient_preflight_unavailable")
    encoding = _exact_mapping(
        contract["encoding_rules"],
        {"binary_fields", "canonical_json"},
        reason="recipient_preflight_unavailable",
    )
    if encoding != {
        "binary_fields": "RFC4648 base64url without equals padding",
        "canonical_json": (
            "UTF-8 JSON; lexicographically sorted keys; comma and colon "
            "separators; ensure_ascii=true; allow_nan=false; no whitespace"
        ),
    }:
        raise ArenaSubmissionClientError("recipient_preflight_unavailable")
    aad = _exact_mapping(
        contract["aad"],
        {
            "service",
            "context",
            "schema_version",
            "exact_fields",
            "hash_formulas",
            "identity_derivation",
        },
        reason="recipient_preflight_unavailable",
    )
    if (
        aad["service"] != "dnai-wikigen"
        or aad["context"] != INGRESS_CONTEXT
        or aad["schema_version"] != INGRESS_SCHEMA_VERSION
        or aad["exact_fields"] != _AAD_FIELDS
    ):
        raise ArenaSubmissionClientError("recipient_preflight_unavailable")
    _exact_mapping(
        aad["hash_formulas"],
        {
            "challenge_manifest_hash",
            "submission_manifest_hash",
            "candidate_commitment",
            "identity.wallet_address_hash",
            "identity.project_id_hash",
            "idempotency_key_hash",
            "key_id",
            "attestation_report_data_sha256",
            "registry_authorization_sha256",
        },
        reason="recipient_preflight_unavailable",
    )
    _exact_mapping(
        aad["identity_derivation"],
        {"wallet_address", "project_id"},
        reason="recipient_preflight_unavailable",
    )
    recipient = _exact_mapping(
        contract["recipient"],
        {
            "encryption_public_key",
            "key_id",
            "report_context",
            "report_data",
            "attestation_report_data_sha256",
            "report_data_contract",
        },
        reason="recipient_preflight_unavailable",
    )
    report_contract = _exact_mapping(
        recipient["report_data_contract"],
        {"hash", "canonical_json"},
        reason="recipient_preflight_unavailable",
    )
    report_object = _exact_mapping(
        report_contract["canonical_json"],
        {"context", "encryption_public_key", "key_id", "protocol", "service"},
        reason="recipient_preflight_unavailable",
    )
    if (
        report_contract["hash"] != "SHA-256"
        or report_object
        != {
            "context": INGRESS_ATTESTATION_CONTEXT,
            "encryption_public_key": recipient["encryption_public_key"],
            "key_id": recipient["key_id"],
            "protocol": "arena_candidate_ingress_v1",
            "service": "dnai-wikigen",
        }
        or _SHA256.fullmatch(str(recipient["key_id"])) is None
        or _SHA256.fullmatch(
            str(recipient["attestation_report_data_sha256"])
        )
        is None
    ):
        raise ArenaSubmissionClientError("recipient_preflight_unavailable")
    limits = _exact_mapping(
        contract["limits"],
        {
            "max_aad_bytes",
            "max_ciphertext_bytes_including_gcm_tag",
            "max_plaintext_bytes_from_cipher_limit",
            "max_envelopes_per_store",
            "idempotency_key_max_bytes",
        },
        reason="recipient_preflight_unavailable",
    )
    if (
        limits["max_aad_bytes"] != MAX_AAD_BYTES
        or limits["max_ciphertext_bytes_including_gcm_tag"]
        != MAX_CIPHERTEXT_BYTES
        or limits["max_plaintext_bytes_from_cipher_limit"]
        != MAX_CIPHERTEXT_BYTES - GCM_TAG_BYTES
        or limits["idempotency_key_max_bytes"] != 128
    ):
        raise ArenaSubmissionClientError("recipient_preflight_unavailable")
    _bounded_int(limits["max_envelopes_per_store"], 1, 10_000)
    gate = _exact_mapping(
        contract["submission_gate"],
        {
            "fresh_cvm_attestation_required",
            "independent_quote_and_measurement_verification_required",
            "matching_current_recipient_key_required",
            "matching_report_data_binding_required",
            "api_verified_field_is_not_a_policy_verdict",
            "server_generated_sealed_reference",
            "plaintext_candidate_accepted",
            "hostile_code_execution_enabled",
        },
        reason="recipient_preflight_unavailable",
    )
    if gate != {
        "fresh_cvm_attestation_required": True,
        "independent_quote_and_measurement_verification_required": True,
        "matching_current_recipient_key_required": True,
        "matching_report_data_binding_required": True,
        "api_verified_field_is_not_a_policy_verdict": True,
        "server_generated_sealed_reference": True,
        "plaintext_candidate_accepted": False,
        "hostile_code_execution_enabled": False,
    }:
        raise ArenaSubmissionClientError("recipient_preflight_unavailable")
    if contract["envelope_exact_fields"] != _ENVELOPE_FIELDS:
        raise ArenaSubmissionClientError("recipient_preflight_unavailable")
    return contract


def _encrypt_candidate(
    source: bytes,
    *,
    recipient_public_key: bytes,
    aad: bytes,
    ephemeral_private_key: bytes | None,
    nonce: bytes | None,
) -> dict[str, bytes]:
    if not 1 <= len(source) <= SAFE_IR_MAX_CANDIDATE_BYTES:
        raise ArenaSubmissionClientError("candidate_invalid")
    if not 1 <= len(aad) <= MAX_AAD_BYTES:
        raise ArenaSubmissionClientError("candidate_invalid")
    try:
        private = (
            X25519PrivateKey.generate()
            if ephemeral_private_key is None
            else X25519PrivateKey.from_private_bytes(ephemeral_private_key)
        )
        recipient = X25519PublicKey.from_public_bytes(recipient_public_key)
        shared_secret = private.exchange(recipient)
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(aad).digest(),
            info=INGRESS_HKDF_INFO,
        ).derive(shared_secret)
        iv = os.urandom(AES_GCM_NONCE_BYTES) if nonce is None else bytes(nonce)
        if len(iv) != AES_GCM_NONCE_BYTES:
            raise ArenaSubmissionClientError("candidate_invalid")
        ciphertext = AESGCM(aes_key).encrypt(iv, source, aad)
        if (
            len(ciphertext) != len(source) + GCM_TAG_BYTES
            or len(ciphertext) > MAX_CIPHERTEXT_BYTES
        ):
            raise ArenaSubmissionClientError("candidate_invalid")
        return {
            "ephemeral_public_key": private.public_key().public_bytes_raw(),
            "nonce": iv,
            "ciphertext": ciphertext,
        }
    except ArenaSubmissionClientError:
        raise
    except (TypeError, ValueError) as exc:
        raise ArenaSubmissionClientError("candidate_invalid") from exc


def _assert_no_forbidden_fields(value: Any) -> None:
    forbidden = {
        "candidate_source",
        "encrypted_reference",
        "exact_score",
        "internal_score",
        "project_id",
        "raw_candidate",
        "source_code",
        "source_bytes",
        "ciphertext",
        "ciphertext_bytes",
        "wallet_address",
        "created_at",
        "updated_at",
        "occurred_at",
        "ladder_released_at",
    }
    stack = [value]
    nodes = 0
    while stack:
        item = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ArenaSubmissionClientError("public_schema_invalid")
        if isinstance(item, Mapping):
            if forbidden.intersection(item):
                raise ArenaSubmissionClientError("public_schema_invalid")
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _parse_execution_provenance(value: Any, *, runtime: str, manifest_hash: str) -> None:
    evidence = _exact_mapping(value, _EXECUTION_PROVENANCE_FIELDS)
    if (
        evidence["independently_verified_by_client"] is not False
        or evidence["raw_tdx_quote_egress"] is not False
        or evidence["exact_score_egress"] is not False
        or evidence["exact_timing_egress"] is not False
        or evidence["runtime"] != runtime
    ):
        raise ArenaSubmissionClientError("public_schema_invalid")
    if evidence["status"] == "not_executed":
        nullable = {
            "outcome",
            "runtime_policy_commitment",
            "challenge_manifest_hash",
            "compose_hash",
            "app_id",
            "os_image_hash",
            "quote_sha256",
            "verifier_address",
            "verdict_digest",
            "tee_signer_address",
            "chain_id",
            "challenge_registry_address",
        }
        if evidence["evidence_classification"] != "none" or any(
            evidence[field] is not None for field in nullable
        ):
            raise ArenaSubmissionClientError("public_schema_invalid")
        return
    if (
        evidence["status"] != "worker_reported"
        or evidence["outcome"] not in {"completed", "failed"}
        or evidence["runtime"] != SAFE_IR_RUNTIME
        or evidence["runtime_policy_commitment"] != SAFE_IR_POLICY_COMMITMENT
        or evidence["challenge_manifest_hash"] != manifest_hash
        or evidence["evidence_classification"]
        != "worker_reported_qvl_binding_not_independently_verified"
        or evidence["chain_id"] != BASE_SEPOLIA_CHAIN_ID
        or _SHA256.fullmatch(str(evidence["quote_sha256"])) is None
        or _HEX_64.fullmatch(str(evidence["compose_hash"])) is None
        or _HEX_64.fullmatch(str(evidence["os_image_hash"])) is None
        or _ADDRESS.fullmatch(str(evidence["verifier_address"])) is None
        or _ADDRESS.fullmatch(str(evidence["tee_signer_address"])) is None
        or evidence["verifier_address"] == evidence["tee_signer_address"]
        or _BYTES32.fullmatch(str(evidence["verdict_digest"])) is None
        or _ADDRESS.fullmatch(str(evidence["challenge_registry_address"])) is None
    ):
        raise ArenaSubmissionClientError("public_schema_invalid")
    _bounded_ascii(evidence["app_id"], 1, 128)


def _parse_modeled_execution_capability(value: Any) -> None:
    capability = _exact_mapping(
        value,
        {"status", "isolation", "backend", "warning", "hostile_code_ready", "live_execution", "worker_connected"},
    )
    if (
        capability["status"] != PRODUCT_STATUS
        or capability["isolation"] != "non_hardened"
        or capability["hostile_code_ready"] is not False
        or capability["live_execution"] is not False
        or capability["worker_connected"] is not False
    ):
        raise ArenaSubmissionClientError("public_schema_invalid")
    _bounded_ascii(capability["backend"], 1, 128)
    _bounded_ascii(capability["warning"], 1, 512)


def _parse_common_submission(
    value: Mapping[str, Any],
    *,
    expected_challenge: tuple[str, str],
) -> None:
    identity = _exact_mapping(value["identity"], {"wallet_address_hash", "project_id_hash"})
    manifest = _exact_mapping(
        value["manifest"],
        {
            "schema_version",
            "challenge_manifest_hash",
            "candidate_kind",
            "runtime",
            "entrypoint",
            "mode",
            "private_size_egress",
        },
    )
    if (
        value["surface"] not in {"arena_submission", "arena_owner_submission"}
        or value["schema_version"] != 2
        or _SUBMISSION_ID.fullmatch(str(value["submission_id"])) is None
        or (value["challenge_id"], value["challenge_version"])
        != expected_challenge
        or _SHA256.fullmatch(str(value["candidate_commitment"])) is None
        or not isinstance(value["state"], str)
        or value["state"] not in {state.value for state in QueueState}
        or _HEX_64.fullmatch(str(identity["wallet_address_hash"])) is None
        or _HEX_64.fullmatch(str(identity["project_id_hash"])) is None
        or manifest["schema_version"] != 1
        or _HEX_64.fullmatch(str(manifest["challenge_manifest_hash"])) is None
        or manifest["candidate_kind"] != SAFE_IR_CANDIDATE_KIND
        or manifest["runtime"] != SAFE_IR_RUNTIME
        or manifest["entrypoint"] != SAFE_IR_ENTRYPOINT
        or manifest["mode"] != "leaderboard"
        or manifest["private_size_egress"] is not False
    ):
        raise ArenaSubmissionClientError("public_schema_invalid")
    _parse_modeled_execution_capability(value["execution_capability"])
    _parse_execution_provenance(
        value["execution_provenance"],
        runtime=str(manifest["runtime"]),
        manifest_hash=str(manifest["challenge_manifest_hash"]),
    )
    evidence_status = value["execution_provenance"]["status"]
    if evidence_status == "worker_reported":
        if (
            value["product_status"] != "live"
            or value["execution_assurance"]
            != "worker_reported_qvl_binding_not_independently_verified"
        ):
            raise ArenaSubmissionClientError("public_schema_invalid")
    elif (
        value["product_status"] != PRODUCT_STATUS
        or value["execution_assurance"] != EXECUTION_ASSURANCE
    ):
        raise ArenaSubmissionClientError("public_schema_invalid")


def _parse_public_submission(
    value: Any,
    *,
    expected_challenge: tuple[str, str],
) -> Mapping[str, Any]:
    _assert_no_forbidden_fields(value)
    submission = _exact_mapping(value, _PUBLIC_SUBMISSION_FIELDS)
    _parse_common_submission(submission, expected_challenge=expected_challenge)
    if (
        submission["surface"] != "arena_submission"
        or submission["encrypted_reference_public"] is not False
        or submission["exact_timing_egress"] is not False
        or submission["raw_candidate_accepted"] is not False
        or submission["raw_secret_egress"] is not False
        or not isinstance(submission["queue_events"], list)
        or not 1 <= len(submission["queue_events"]) <= 32
    ):
        raise ArenaSubmissionClientError("public_schema_invalid")
    prior: str | None = None
    for index, raw in enumerate(submission["queue_events"], start=1):
        event = _exact_mapping(raw, {"sequence", "from_state", "to_state", "reason"})
        if (
            event["sequence"] != index
            or event["from_state"] != prior
            or event["to_state"] not in {state.value for state in QueueState}
            or not isinstance(event["reason"], str)
        ):
            raise ArenaSubmissionClientError("public_schema_invalid")
        prior = str(event["to_state"])
    if prior != submission["state"]:
        raise ArenaSubmissionClientError("public_schema_invalid")
    if submission["ladder_release"] is not None:
        release = _exact_mapping(
            submission["ladder_release"],
            {
                "submission_index",
                "accepted",
                "leaderboard_step_index",
                "step_denominator",
                "improvement_steps_so_far",
                "has_leaderboard_entry",
            },
        )
        _bounded_int(release["submission_index"], 1, 10_000)
        _bounded_int(release["leaderboard_step_index"], -1, 10_000)
        _bounded_int(release["step_denominator"], 1, 10_000)
        _bounded_int(release["improvement_steps_so_far"], 0, 10_000)
        if not isinstance(release["accepted"], bool) or not isinstance(
            release["has_leaderboard_entry"], bool
        ):
            raise ArenaSubmissionClientError("public_schema_invalid")
    return submission


def _parse_owner_page(value: Any) -> Mapping[str, Any]:
    _assert_no_forbidden_fields(value)
    page = _exact_mapping(value, _OWNER_PAGE_FIELDS)
    page_count = _bounded_int(page["page_count"], 0, 100)
    if (
        page["surface"] != "arena_owner_submissions"
        or page["schema_version"] != 2
        or page["challenge_id"] != DNASEQ_SAFE_IR_CHALLENGE_ID
        or page["challenge_version"] != DNASEQ_SAFE_IR_CHALLENGE_VERSION
        or _HEX_64.fullmatch(str(page["owner_identity"])) is None
        or page["scope"] != "authenticated_wallet_challenge_version"
        or page["product_status"] != "per_row"
        or page["execution_assurance"] != "per_submission_execution_provenance"
        or not isinstance(page["submissions"], list)
        or len(page["submissions"]) > 100
        or page_count != len(page["submissions"])
        or not isinstance(page["has_more"], bool)
        or page["raw_candidate_egress"] is not False
        or page["encrypted_reference_egress"] is not False
        or page["exact_score_egress"] is not False
        or page["exact_reward_egress"] is not False
        or page["exact_timing_egress"] is not False
        or page["internal_error_egress"] is not False
    ):
        raise ArenaSubmissionClientError("public_schema_invalid")
    cursor = page["next_cursor"]
    if (
        (page["has_more"] and _SUBMISSION_ID.fullmatch(str(cursor)) is None)
        or (not page["has_more"] and cursor is not None)
    ):
        raise ArenaSubmissionClientError("public_schema_invalid")
    for raw in page["submissions"]:
        item = _exact_mapping(raw, _OWNER_SUBMISSION_FIELDS)
        _parse_common_submission(
            item,
            expected_challenge=(
                DNASEQ_SAFE_IR_CHALLENGE_ID,
                DNASEQ_SAFE_IR_CHALLENGE_VERSION,
            ),
        )
        if (
            item["surface"] != "arena_owner_submission"
            or item["raw_candidate_egress"] is not False
            or item["encrypted_reference_egress"] is not False
            or item["exact_score_egress"] is not False
            or item["exact_reward_egress"] is not False
            or item["exact_timing_egress"] is not False
            or item["internal_error_egress"] is not False
        ):
            raise ArenaSubmissionClientError("public_schema_invalid")
        if item["bounded_result"] is not None:
            result = _exact_mapping(
                item["bounded_result"],
                {
                    "accepted",
                    "leaderboard_step_index",
                    "step_denominator",
                    "improvement_steps_so_far",
                },
            )
            if not isinstance(result["accepted"], bool):
                raise ArenaSubmissionClientError("public_schema_invalid")
            _bounded_int(result["leaderboard_step_index"], -1, 10_000)
            _bounded_int(result["step_denominator"], 1, 10_000)
            _bounded_int(result["improvement_steps_so_far"], 0, 10_000)
    return page


def _owner_metadata_projection(owner: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "submission_id": owner["submission_id"],
        "challenge_id": owner["challenge_id"],
        "challenge_version": owner["challenge_version"],
        "candidate_commitment": owner["candidate_commitment"],
        "manifest": dict(owner["manifest"]),
        "state": owner["state"],
        "bounded_result": (
            None
            if owner["bounded_result"] is None
            else dict(owner["bounded_result"])
        ),
        "product_status": owner["product_status"],
        "execution_assurance": owner["execution_assurance"],
        "raw_candidate_egress": False,
        "encrypted_reference_egress": False,
        "exact_score_egress": False,
        "exact_reward_egress": False,
        "exact_timing_egress": False,
    }


def _parse_submission_receipt(
    value: Any,
    prepared: PreparedArenaSubmission,
) -> Mapping[str, Any]:
    _assert_no_forbidden_fields(value)
    result = _exact_mapping(
        value,
        {
            "surface",
            "created",
            "idempotent_replay",
            "registry_ingress_boundary",
            "candidate_ingress",
            "submission",
            "raw_candidate_accepted",
            "encrypted_reference_egress",
            "raw_secret_egress",
        },
        reason="submission_receipt_invalid",
    )
    if (
        result["surface"] != "arena_submission_result"
        or not isinstance(result["created"], bool)
        or not isinstance(result["idempotent_replay"], bool)
        or result["idempotent_replay"] is result["created"]
        or result["raw_candidate_accepted"] is not False
        or result["encrypted_reference_egress"] is not False
        or result["raw_secret_egress"] is not False
    ):
        raise ArenaSubmissionClientError("submission_receipt_invalid")
    boundary = _exact_mapping(
        result["registry_ingress_boundary"],
        {
            "surface",
            "schema_version",
            "status",
            "verification_model",
            "browser_preflight_accepted_as_authority",
            "proxy_registry_authorized",
            "worker_registry_authorized",
            "registry_authorization_sha256",
            "chain_id",
            "block_number",
            "block_hash",
            "registry_address",
            "registry_challenge_id",
            "registry_version",
            "independent_rpc_quorum_verified",
            "consensus_proof_verified",
        },
        reason="submission_receipt_invalid",
    )
    snapshot = prepared.payload["registry_authorization"]
    if (
        boundary["surface"] != "arena_registry_ingress_boundary"
        or boundary["schema_version"] != 1
        or boundary["status"]
        != "proxy_independently_verified_at_finalized_block"
        or boundary["verification_model"]
        != "single_rpc_reported_finalized_pinned_block"
        or boundary["browser_preflight_accepted_as_authority"] is not False
        or boundary["proxy_registry_authorized"] is not True
        or boundary["worker_registry_authorized"] is not False
        or boundary["registry_authorization_sha256"]
        != prepared.registry_authorization_sha256
        or boundary["chain_id"] != BASE_SEPOLIA_CHAIN_ID
        or boundary["block_number"] != snapshot["block_number"]
        or boundary["block_hash"] != snapshot["block_hash"]
        or boundary["registry_address"] != snapshot["registry_address"]
        or boundary["registry_challenge_id"]
        != snapshot["registry_challenge_id"]
        or boundary["registry_version"] != snapshot["registry_version"]
        or boundary["independent_rpc_quorum_verified"] is not False
        or boundary["consensus_proof_verified"] is not False
    ):
        raise ArenaSubmissionClientError("submission_receipt_invalid")
    ingress = _exact_mapping(
        result["candidate_ingress"],
        {
            "surface",
            "schema_version",
            "blob_sha256",
            "ciphertext_sha256",
            "key_id",
            "created",
            "idempotent_replay",
            "sealed_reference_public",
            "plaintext_candidate_accepted",
            "product_status",
            "execution_assurance",
            "raw_secret_egress",
            "private_size_egress",
        },
        reason="submission_receipt_invalid",
    )
    if (
        ingress["surface"] != "arena_candidate_ingress_receipt"
        or ingress["schema_version"] != 1
        or _SHA256.fullmatch(str(ingress["blob_sha256"])) is None
        or ingress["ciphertext_sha256"] != prepared.ciphertext_sha256
        or ingress["key_id"] != prepared.key_id
        or not isinstance(ingress["created"], bool)
        or not isinstance(ingress["idempotent_replay"], bool)
        or ingress["idempotent_replay"] is ingress["created"]
        or ingress["sealed_reference_public"] is not False
        or ingress["plaintext_candidate_accepted"] is not False
        or ingress["product_status"] != PRODUCT_STATUS
        or ingress["execution_assurance"] != EXECUTION_ASSURANCE
        or ingress["raw_secret_egress"] is not False
        or ingress["private_size_egress"] is not False
    ):
        raise ArenaSubmissionClientError("submission_receipt_invalid")
    submission = _parse_public_submission(
        result["submission"],
        expected_challenge=(
            DNASEQ_SAFE_IR_CHALLENGE_ID,
            DNASEQ_SAFE_IR_CHALLENGE_VERSION,
        ),
    )
    if (
        submission["candidate_commitment"] != prepared.candidate_commitment
        or submission["product_status"] != PRODUCT_STATUS
        or submission["execution_assurance"] != EXECUTION_ASSURANCE
        or submission["execution_provenance"]["status"] != "not_executed"
    ):
        raise ArenaSubmissionClientError("submission_receipt_invalid")
    return result


def _secure_read_candidate(path: Path) -> bytearray:
    try:
        details = path.lstat()
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise ArenaSubmissionClientError("candidate_invalid")
        if not 1 <= details.st_size <= SAFE_IR_MAX_CANDIDATE_BYTES:
            raise ArenaSubmissionClientError("candidate_invalid")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino)
                != (details.st_dev, details.st_ino)
                or opened.st_size != details.st_size
            ):
                raise ArenaSubmissionClientError("candidate_invalid")
            raw = bytearray(os.read(descriptor, SAFE_IR_MAX_CANDIDATE_BYTES + 1))
            if len(raw) != opened.st_size:
                raise ArenaSubmissionClientError("candidate_invalid")
            return raw
        finally:
            os.close(descriptor)
    except ArenaSubmissionClientError:
        raise
    except OSError as exc:
        raise ArenaSubmissionClientError("candidate_invalid") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tinker-arena-submit",
        description=(
            "Version-pinned encrypted Arena submission client; not an execution prover"
        ),
    )
    parser.add_argument("--delegate-url", required=True)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--release-manifest", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--verified-quote-sha256", required=True)
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("preflight")
    submit = subcommands.add_parser("submit")
    submit.add_argument("candidate", type=Path)
    submit.add_argument("--idempotency-key", required=True)
    submit.add_argument("--poll-attempts", type=int, default=1)
    submit.add_argument("--poll-interval", type=float, default=2.0)
    status = subcommands.add_parser("status")
    status.add_argument("submission_id")
    status.add_argument("--poll-attempts", type=int, default=1)
    status.add_argument("--poll-interval", type=float, default=2.0)
    return parser


def _write_json(stream: TextIO, value: Mapping[str, Any]) -> None:
    stream.write(_canonical_json(value).decode("ascii") + "\n")


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    environment: Mapping[str, str] | None = None,
) -> int:
    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    client: ArenaSubmissionClient | None = None
    transport: HttpsArenaSubmissionTransport | None = None
    registry: HttpsArenaRegistryReader | None = None
    source: bytearray | None = None
    try:
        args = build_parser().parse_args(argv)
        token, claims = read_arena_agent_token(environment)
        release = load_trusted_arena_release(
            release_manifest_path=args.release_manifest,
            release_manifest_sha256=args.release_manifest_sha256,
            release_sha=args.release_sha,
            image_digest=args.image_digest,
            verified_quote_sha256=args.verified_quote_sha256,
        )
        transport = HttpsArenaSubmissionTransport(
            args.delegate_url,
            token=token,
        )
        registry = HttpsArenaRegistryReader(args.rpc_url)
        client = ArenaSubmissionClient(
            transport=transport,
            registry_reader=registry,
            trusted_release=release,
            token_claims=claims,
        )
        if args.command == "preflight":
            _write_json(output, client.preflight().public_summary())
        elif args.command == "submit":
            source = _secure_read_candidate(args.candidate)
            status_result = client.submit(
                source,
                idempotency_key=args.idempotency_key,
                poll_attempts=args.poll_attempts,
                poll_interval_seconds=args.poll_interval,
            )
            _write_json(output, status_result.public_summary())
        elif args.command == "status":
            status_result = client.poll_submission(
                args.submission_id,
                attempts=args.poll_attempts,
                interval_seconds=args.poll_interval,
            )
            _write_json(output, status_result.public_summary())
        else:  # pragma: no cover - argparse owns the closed command set.
            raise ArenaSubmissionClientError("configuration_invalid")
        return 0
    except ArenaSubmissionClientError as exc:
        _write_json(
            errors,
            {
                "surface": "arena_submission_client_failure",
                "schema_version": 1,
                "client_version": SUBMISSION_CLIENT_VERSION,
                "classification": SUBMISSION_CLIENT_CLASSIFICATION,
                "reason": exc.reason,
                "tdx_verified": False,
                "worker_execution_authorized_by_client": False,
            },
        )
        return 2
    finally:
        if source is not None:
            source[:] = b"\0" * len(source)
        if client is not None:
            client.close()
        else:
            if transport is not None:
                transport.close()
            if registry is not None:
                registry.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
