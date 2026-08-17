"""Authenticated HTTPS client for Diligence-QVL Royalty settlement appraisal.

The client keeps the bearer token and raw TDX quote inside the transport
boundary.  Its only durable/public output is an independently authenticated,
dual-EIP-712-signed settlement plan; it never broadcasts the plan.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Sequence

import httpx

from tinker_delegate import dstack_utils
from tinker_delegate.qvl_freshness import (
    QvlChallenge,
    authenticate_qvl_challenge,
    challenge_request,
    qvl_challenge_from_public_dict,
)
from tinker_delegate.result_verifier import (
    IndependentAttestationExpectation,
    ResultVerifierError,
    authenticate_independent_attestation_verdict,
    independent_attestation_verdict_from_public_dict,
)
from tinker_delegate.royalty_settlement_authorization import (
    AuthorizedRoyaltySettlementPlan,
    DstackRoyaltySettlementSigner,
    RoyaltySettlementAuthorizationError,
    RoyaltySettlementIntent,
    RoyaltySettlementReleaseBinding,
    RoyaltySettlementSignerUnavailable,
    build_royalty_settlement_authorization_packet,
    derive_royalty_settlement_anchor_evidence_commitment,
    derive_royalty_settlement_attestation_evidence_hash,
    derive_royalty_settlement_report_data,
    recover_raw_digest_address,
    royalty_settlement_qvl_authorization_digest,
)


ROYALTY_QVL_PROFILE = "royalty_settlement"
ROYALTY_QVL_DOMAIN = "main_runtime_cvm"
ROYALTY_QVL_AUTH_TOKEN_ENV = "TINKER_ROYALTY_SETTLEMENT_QVL_AUTH_TOKEN"
QVL_REQUEST_SCHEMA = "dnai.independent-tdx-verification-request.v2"
QVL_IDENTITY_SCHEMA = "dnai.attestation-qvl-identity.v1"
QVL_CAPABILITY_SCHEMA = "dnai.attestation-qvl-capabilities.v1"
ROYALTY_QVL_AUTHORIZATION_SCHEMA = (
    "dnai.royalty-settlement-qvl-authorization-request.v2"
)
ROYALTY_QVL_CAPABILITY_OBSERVATION_SCHEMA = (
    "dnai.collaboration.royalty-qvl-capability-observation.v1"
)
ROYALTY_QVL_SIGNER_CUSTODY = "dstack_derived_separate_cvm"
MAX_QVL_RESPONSE_BYTES = 96 * 1024
MIN_TDX_QUOTE_BYTES = 1024
MAX_TDX_QUOTE_BYTES = 16 * 1024

_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_APP_ID = re.compile(r"^(?!0{40}$)[0-9a-f]{40}$")
_BARE_SHA256 = re.compile(r"^(?!0{64}$)[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")

_CAPABILITY_OBSERVATION_DOMAIN = (
    b"dnai-wikigen/collaboration-royalty-qvl-capability-observation/v1\0"
)

_BASE_VERDICT_FIELDS = frozenset(
    {
        "schema",
        "verification_method",
        "verified",
        "chain_id",
        "domain",
        "profile",
        "cvm_id",
        "deployment_intent_sha256",
        "release_authority_sha256",
        "ceremony_nonce",
        "measurement_policy_sha256",
        "release_policy_hash",
        "challenge_id",
        "challenge_digest",
        "challenge_issued_at",
        "challenge_expires_at",
        "quote_hash",
        "report_data",
        "compose_hash",
        "app_id",
        "os_image_hash",
        "signer_address",
        "contract_address",
        "issued_at",
        "activation_evidence_lease_expires_at",
        "expires_at",
        "verifier_address",
        "verifier_signature",
    }
)
_ROYALTY_VERDICT_FIELDS = frozenset(
    {
        "qvl_royalty_verifier_address",
        "qvl_royalty_policy_commitment",
        "qvl_royalty_release_policy_commitment",
        "qvl_royalty_attestation_evidence_hash",
        "qvl_royalty_anchor_evidence_commitment",
        "qvl_royalty_authorization_expiry",
        "qvl_royalty_authorization_digest",
        "qvl_royalty_authorization_signature",
    }
)
ROYALTY_QVL_VERDICT_FIELDS = _BASE_VERDICT_FIELDS | _ROYALTY_VERDICT_FIELDS


class RoyaltyQvlClientError(RuntimeError):
    """Bounded failure that never embeds a bearer, quote, or provider value."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except Exception:
        raise RoyaltyQvlClientError("royalty_qvl_request_invalid") from None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError
        output[key] = value
    return output


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except Exception:
        raise RoyaltyQvlClientError("royalty_qvl_unavailable") from None
    if not isinstance(parsed, dict):
        raise RoyaltyQvlClientError("royalty_qvl_unavailable")
    return parsed


def _address(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise RoyaltyQvlClientError(f"{field_name}_invalid")
    result = value.strip().lower()
    if not _ADDRESS.fullmatch(result) or int(result[2:], 16) == 0:
        raise RoyaltyQvlClientError(f"{field_name}_invalid")
    return result


def _bytes32(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise RoyaltyQvlClientError(f"{field_name}_invalid")
    result = value.strip().lower()
    if not _BYTES32.fullmatch(result) or int(result[2:], 16) == 0:
        raise RoyaltyQvlClientError(f"{field_name}_invalid")
    return result


def _https_verify_url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2_048:
        raise RoyaltyQvlClientError("royalty_qvl_unavailable")
    try:
        parsed = httpx.URL(value)
    except Exception:
        raise RoyaltyQvlClientError("royalty_qvl_unavailable") from None
    if (
        parsed.scheme != "https"
        or not parsed.host
        or parsed.userinfo
        or parsed.query
        or parsed.fragment
        or parsed.path != "/verify"
        or parsed.host in {"localhost", "127.0.0.1", "::1"}
    ):
        raise RoyaltyQvlClientError("royalty_qvl_unavailable")
    return str(parsed)


def _auth_token(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 32 <= len(value.encode("utf-8")) <= 4_096
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise RoyaltyQvlClientError("royalty_qvl_unavailable")
    return value


def _bounded_response(response: httpx.Response) -> bytes:
    length = response.headers.get("content-length")
    if length is not None:
        try:
            parsed = int(length)
        except ValueError:
            raise RoyaltyQvlClientError("royalty_qvl_unavailable") from None
        if parsed < 1 or parsed > MAX_QVL_RESPONSE_BYTES:
            raise RoyaltyQvlClientError("royalty_qvl_unavailable")
    output = bytearray()
    for chunk in response.iter_bytes():
        if len(chunk) > MAX_QVL_RESPONSE_BYTES - len(output):
            raise RoyaltyQvlClientError("royalty_qvl_unavailable")
        output.extend(chunk)
    if not output:
        raise RoyaltyQvlClientError("royalty_qvl_unavailable")
    return bytes(output)


def _hex_bytes(value: Any, *, minimum: int, maximum: int) -> bytes:
    if not isinstance(value, str):
        raise RoyaltyQvlClientError("royalty_dstack_evidence_invalid")
    raw = value.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    try:
        decoded = bytes.fromhex(raw)
    except ValueError:
        raise RoyaltyQvlClientError("royalty_dstack_evidence_invalid") from None
    if not minimum <= len(decoded) <= maximum:
        raise RoyaltyQvlClientError("royalty_dstack_evidence_invalid")
    return decoded


def _revocations(values: Sequence[str]) -> frozenset[str]:
    normalized = tuple(_bytes32(value, field_name="revoked_quote_hash") for value in values)
    if normalized != tuple(sorted(set(normalized))):
        raise RoyaltyQvlClientError("royalty_qvl_revocation_policy_invalid")
    return frozenset(normalized)


@dataclass(frozen=True)
class PreparedRoyaltyAttestation:
    """Ephemeral quote packet; deliberately has no public serializer."""

    challenge: QvlChallenge
    quote: str = field(repr=False)
    expectation: Mapping[str, Any]
    attestation_evidence_hash: str


@dataclass(frozen=True)
class AuthenticatedRoyaltyQvlCapabilityObservation:
    """Fresh bounded reachability for one exact Royalty-QVL release.

    This observation combines exact HTTPS discovery fields with a fresh,
    authenticated and signed Royalty-profile challenge.  It proves endpoint
    reachability and release/configuration agreement only.  It is not a TDX
    quote, a per-job QVL verdict, or settlement authorization.
    """

    observed_at: int
    endpoint_sha256: str
    release_binding_sha256: str
    challenge: QvlChallenge
    qvl_verdict_verifier_address: str
    qvl_release_policy_hash: str
    royalty_qvl_verifier_address: str
    royalty_qvl_policy_commitment: str
    royalty_qvl_signer_key_id: str

    _FIELDS = frozenset(
        {
            "schema",
            "observed_at",
            "endpoint_sha256",
            "release_binding_sha256",
            "identity_schema",
            "capability_schema",
            "challenge",
            "qvl_verdict_verifier_address",
            "qvl_release_policy_hash",
            "qvl_signer_custody",
            "royalty_settlement_qvl_enabled",
            "royalty_authorization_schema",
            "royalty_qvl_verifier_address",
            "royalty_qvl_policy_commitment",
            "royalty_qvl_signer_key_id",
            "raw_secret_egress",
            "evidence_scope",
        }
    )

    def __post_init__(self) -> None:
        if (
            isinstance(self.observed_at, bool)
            or not isinstance(self.observed_at, int)
            or self.observed_at < 1
        ):
            raise RoyaltyQvlClientError("royalty_qvl_capability_invalid")
        if not _SHA256.fullmatch(self.endpoint_sha256) or not _SHA256.fullmatch(
            self.release_binding_sha256
        ):
            raise RoyaltyQvlClientError("royalty_qvl_capability_invalid")
        if not isinstance(self.challenge, QvlChallenge):
            raise RoyaltyQvlClientError("royalty_qvl_capability_invalid")
        try:
            verdict_verifier = _address(
                self.qvl_verdict_verifier_address,
                field_name="qvl_verdict_verifier",
            )
            release_policy = _bytes32(
                self.qvl_release_policy_hash,
                field_name="qvl_release_policy",
            )
            royalty_verifier = _address(
                self.royalty_qvl_verifier_address,
                field_name="royalty_qvl_verifier",
            )
            royalty_policy = _bytes32(
                self.royalty_qvl_policy_commitment,
                field_name="royalty_qvl_policy",
            )
            signer_key_id = _bytes32(
                self.royalty_qvl_signer_key_id,
                field_name="royalty_qvl_signer_key_id",
            )
            if (
                verdict_verifier != self.qvl_verdict_verifier_address
                or release_policy != self.qvl_release_policy_hash
                or royalty_verifier != self.royalty_qvl_verifier_address
                or royalty_policy != self.royalty_qvl_policy_commitment
                or signer_key_id != self.royalty_qvl_signer_key_id
                or self.challenge.chain_id != 84_532
            ):
                raise ValueError
            authenticate_qvl_challenge(
                self.challenge,
                expected_profile=ROYALTY_QVL_PROFILE,
                expected_chain_id=self.challenge.chain_id,
                expected_domain=ROYALTY_QVL_DOMAIN,
                expected_cvm_id=self.challenge.cvm_id,
                expected_deployment_intent_sha256=(
                    self.challenge.deployment_intent_sha256
                ),
                expected_release_authority_sha256=(
                    self.challenge.release_authority_sha256
                ),
                expected_ceremony_nonce=self.challenge.ceremony_nonce,
                expected_measurement_policy_sha256=(
                    self.challenge.measurement_policy_sha256
                ),
                trusted_verifier_addresses=(verdict_verifier,),
                expected_policy_hash=release_policy,
                now=self.observed_at,
            )
        except RoyaltyQvlClientError:
            raise
        except Exception:
            raise RoyaltyQvlClientError(
                "royalty_qvl_capability_invalid"
            ) from None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "schema": ROYALTY_QVL_CAPABILITY_OBSERVATION_SCHEMA,
            "observed_at": self.observed_at,
            "endpoint_sha256": self.endpoint_sha256,
            "release_binding_sha256": self.release_binding_sha256,
            "identity_schema": QVL_IDENTITY_SCHEMA,
            "capability_schema": QVL_CAPABILITY_SCHEMA,
            "challenge": self.challenge.to_public_dict(),
            "qvl_verdict_verifier_address": (
                self.qvl_verdict_verifier_address
            ),
            "qvl_release_policy_hash": self.qvl_release_policy_hash,
            "qvl_signer_custody": ROYALTY_QVL_SIGNER_CUSTODY,
            "royalty_settlement_qvl_enabled": True,
            "royalty_authorization_schema": ROYALTY_QVL_AUTHORIZATION_SCHEMA,
            "royalty_qvl_verifier_address": (
                self.royalty_qvl_verifier_address
            ),
            "royalty_qvl_policy_commitment": (
                self.royalty_qvl_policy_commitment
            ),
            "royalty_qvl_signer_key_id": self.royalty_qvl_signer_key_id,
            "raw_secret_egress": False,
            "evidence_scope": (
                "authenticated_endpoint_capability_not_job_attestation"
            ),
        }

    @classmethod
    def from_public_dict(
        cls,
        value: Mapping[str, Any],
    ) -> "AuthenticatedRoyaltyQvlCapabilityObservation":
        if not isinstance(value, Mapping) or set(value) != cls._FIELDS:
            raise RoyaltyQvlClientError("royalty_qvl_capability_invalid")
        if (
            value.get("schema") != ROYALTY_QVL_CAPABILITY_OBSERVATION_SCHEMA
            or value.get("identity_schema") != QVL_IDENTITY_SCHEMA
            or value.get("capability_schema") != QVL_CAPABILITY_SCHEMA
            or value.get("qvl_signer_custody")
            != ROYALTY_QVL_SIGNER_CUSTODY
            or value.get("royalty_settlement_qvl_enabled") is not True
            or value.get("royalty_authorization_schema")
            != ROYALTY_QVL_AUTHORIZATION_SCHEMA
            or value.get("raw_secret_egress") is not False
            or value.get("evidence_scope")
            != "authenticated_endpoint_capability_not_job_attestation"
            or not isinstance(value.get("challenge"), Mapping)
        ):
            raise RoyaltyQvlClientError("royalty_qvl_capability_invalid")
        try:
            challenge = qvl_challenge_from_public_dict(value["challenge"])
            return cls(
                observed_at=value["observed_at"],
                endpoint_sha256=value["endpoint_sha256"],
                release_binding_sha256=value["release_binding_sha256"],
                challenge=challenge,
                qvl_verdict_verifier_address=value[
                    "qvl_verdict_verifier_address"
                ],
                qvl_release_policy_hash=value["qvl_release_policy_hash"],
                royalty_qvl_verifier_address=value[
                    "royalty_qvl_verifier_address"
                ],
                royalty_qvl_policy_commitment=value[
                    "royalty_qvl_policy_commitment"
                ],
                royalty_qvl_signer_key_id=value[
                    "royalty_qvl_signer_key_id"
                ],
            )
        except RoyaltyQvlClientError:
            raise
        except Exception:
            raise RoyaltyQvlClientError(
                "royalty_qvl_capability_invalid"
            ) from None

    @property
    def commitment(self) -> str:
        return "sha256:" + hashlib.sha256(
            _CAPABILITY_OBSERVATION_DOMAIN
            + _canonical_json(self.to_public_dict())
        ).hexdigest()


class HttpsRoyaltySettlementQvlClient:
    """No-redirect authenticated client for one exact Diligence QVL release."""

    def __init__(
        self,
        *,
        qvl_url: str,
        auth_token: str,
        trusted_verdict_verifier_address: str,
        release: RoyaltySettlementReleaseBinding,
        max_verdict_age_seconds: int,
        revoked_quote_hashes: Sequence[str] = (),
        client: httpx.Client | None = None,
    ) -> None:
        if (
            isinstance(max_verdict_age_seconds, bool)
            or not isinstance(max_verdict_age_seconds, int)
            or not 1 <= max_verdict_age_seconds <= 300
        ):
            raise RoyaltyQvlClientError("royalty_qvl_policy_invalid")
        if not isinstance(release, RoyaltySettlementReleaseBinding):
            raise RoyaltyQvlClientError("royalty_qvl_policy_invalid")
        self.qvl_url = _https_verify_url(qvl_url)
        self.challenge_url = str(httpx.URL(self.qvl_url).copy_with(path="/challenge"))
        self.identity_url = str(httpx.URL(self.qvl_url).copy_with(path="/identity"))
        self.capabilities_url = str(
            httpx.URL(self.qvl_url).copy_with(path="/capabilities")
        )
        self._auth_token = _auth_token(auth_token)
        self.trusted_verdict_verifier_address = _address(
            trusted_verdict_verifier_address,
            field_name="qvl_verdict_verifier",
        )
        if self.trusted_verdict_verifier_address in {
            release.distributor_address,
            release.settlement_verifier_address,
            release.royalty_qvl_verifier_address,
            release.execution_policy_anchor_address,
        }:
            raise RoyaltyQvlClientError("royalty_qvl_role_separation_invalid")
        self.release = release
        self.max_verdict_age_seconds = max_verdict_age_seconds
        self.revoked_quote_hashes = _revocations(revoked_quote_hashes)
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None

    def __repr__(self) -> str:
        return "HttpsRoyaltySettlementQvlClient(authenticated=True)"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _post(self, url: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        request = self._client.build_request(
            "POST",
            url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._auth_token}",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
            content=_canonical_json(dict(payload)),
        )
        try:
            response = self._client.send(
                request,
                stream=True,
                follow_redirects=False,
            )
            try:
                content_type = (
                    response.headers.get("content-type", "")
                    .split(";", 1)[0]
                    .lower()
                )
                if (
                    response.status_code != 200
                    or response.history
                    or not (
                        content_type == "application/json"
                        or content_type.endswith("+json")
                    )
                ):
                    raise RoyaltyQvlClientError("royalty_qvl_unavailable")
                raw = _bounded_response(response)
            finally:
                response.close()
        except RoyaltyQvlClientError:
            raise
        except Exception:
            # Do not chain transport exceptions: request objects can retain the
            # Authorization header and the raw TDX quote body.
            raise RoyaltyQvlClientError("royalty_qvl_unavailable") from None
        return _json_object(raw)

    def _get(self, url: str) -> dict[str, Any]:
        request = self._client.build_request(
            "GET",
            url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._auth_token}",
                "Cache-Control": "no-store",
            },
        )
        try:
            response = self._client.send(
                request,
                stream=True,
                follow_redirects=False,
            )
            try:
                content_type = (
                    response.headers.get("content-type", "")
                    .split(";", 1)[0]
                    .lower()
                )
                if (
                    response.status_code != 200
                    or response.history
                    or not (
                        content_type == "application/json"
                        or content_type.endswith("+json")
                    )
                ):
                    raise RoyaltyQvlClientError("royalty_qvl_unavailable")
                raw = _bounded_response(response)
            finally:
                response.close()
        except RoyaltyQvlClientError:
            raise
        except Exception:
            # Do not chain transport exceptions: request objects retain the
            # direct worker-only bearer even for discovery endpoints.
            raise RoyaltyQvlClientError("royalty_qvl_unavailable") from None
        return _json_object(raw)

    def probe_capability(
        self,
        *,
        release_binding_sha256: str,
        now: int,
    ) -> AuthenticatedRoyaltyQvlCapabilityObservation:
        """Authenticate exact Royalty capability without collecting a quote.

        `/identity` and `/capabilities` remain discovery data.  They unlock
        funding only when the same no-redirect HTTPS endpoint also returns a
        fresh signed Royalty-profile challenge under the reviewed primary QVL
        verifier and release-policy hash.  Per-job TDX/QVL evidence remains a
        separate later operation.
        """

        if (
            isinstance(now, bool)
            or not isinstance(now, int)
            or now < 1
            or not isinstance(release_binding_sha256, str)
            or not _SHA256.fullmatch(release_binding_sha256)
        ):
            raise RoyaltyQvlClientError("royalty_qvl_capability_invalid")
        identity = self._get(self.identity_url)
        capabilities = self._get(self.capabilities_url)
        challenge = self.issue_challenge(now=now)
        try:
            if set(identity) != {
                "schema",
                "verifier_address",
                "release_policy_hash",
                "signer_custody",
                "raw_secret_egress",
            } or set(capabilities) != {
                "schema",
                "royalty_settlement_qvl_enabled",
                "royalty_authorization_schema",
                "royalty_qvl_verifier_address",
                "royalty_qvl_policy_commitment",
                "raw_secret_egress",
            }:
                raise ValueError
            identity_verifier = _address(
                identity["verifier_address"],
                field_name="qvl_verdict_verifier",
            )
            identity_policy = _bytes32(
                identity["release_policy_hash"],
                field_name="qvl_release_policy",
            )
            capability_verifier = _address(
                capabilities["royalty_qvl_verifier_address"],
                field_name="royalty_qvl_verifier",
            )
            capability_policy = _bytes32(
                capabilities["royalty_qvl_policy_commitment"],
                field_name="royalty_qvl_policy",
            )
            if (
                identity["schema"] != QVL_IDENTITY_SCHEMA
                or identity_verifier
                != self.trusted_verdict_verifier_address
                or identity_policy != self.release.qvl_release_policy_hash
                or identity["signer_custody"]
                != ROYALTY_QVL_SIGNER_CUSTODY
                or identity["raw_secret_egress"] is not False
                or capabilities["schema"] != QVL_CAPABILITY_SCHEMA
                or capabilities["royalty_settlement_qvl_enabled"] is not True
                or capabilities["royalty_authorization_schema"]
                != ROYALTY_QVL_AUTHORIZATION_SCHEMA
                or capability_verifier
                != self.release.royalty_qvl_verifier_address
                or capability_policy
                != self.release.royalty_qvl_policy_commitment
                or capabilities["raw_secret_egress"] is not False
                or challenge.verifier_address != identity_verifier
                or challenge.release_policy_hash != identity_policy
            ):
                raise ValueError
            endpoint_sha256 = "sha256:" + hashlib.sha256(
                b"dnai-wikigen/royalty-qvl-endpoint/v1\0"
                + self.qvl_url.encode("ascii")
            ).hexdigest()
            return AuthenticatedRoyaltyQvlCapabilityObservation(
                observed_at=now,
                endpoint_sha256=endpoint_sha256,
                release_binding_sha256=release_binding_sha256,
                challenge=challenge,
                qvl_verdict_verifier_address=identity_verifier,
                qvl_release_policy_hash=identity_policy,
                royalty_qvl_verifier_address=capability_verifier,
                royalty_qvl_policy_commitment=capability_policy,
                royalty_qvl_signer_key_id=(
                    self.release.royalty_qvl_signer_key_id
                ),
            )
        except RoyaltyQvlClientError:
            raise
        except Exception:
            raise RoyaltyQvlClientError(
                "royalty_qvl_capability_mismatch"
            ) from None

    def issue_challenge(self, *, now: int) -> QvlChallenge:
        request = challenge_request(
            ROYALTY_QVL_PROFILE,
            chain_id=self.release.chain_id,
            domain=ROYALTY_QVL_DOMAIN,
            cvm_id=self.release.main_runtime_cvm_id,
            deployment_intent_sha256=self.release.deployment_intent_sha256,
            release_authority_sha256=self.release.release_authority_sha256,
            ceremony_nonce=self.release.ceremony_nonce,
            measurement_policy_sha256=self.release.measurement_policy_sha256,
        )
        try:
            payload = self._post(self.challenge_url, request)
            return authenticate_qvl_challenge(
                qvl_challenge_from_public_dict(payload),
                expected_profile=ROYALTY_QVL_PROFILE,
                expected_chain_id=self.release.chain_id,
                expected_domain=ROYALTY_QVL_DOMAIN,
                expected_cvm_id=self.release.main_runtime_cvm_id,
                expected_deployment_intent_sha256=(
                    self.release.deployment_intent_sha256
                ),
                expected_release_authority_sha256=(
                    self.release.release_authority_sha256
                ),
                expected_ceremony_nonce=self.release.ceremony_nonce,
                expected_measurement_policy_sha256=(
                    self.release.measurement_policy_sha256
                ),
                trusted_verifier_addresses=(
                    self.trusted_verdict_verifier_address,
                ),
                expected_policy_hash=self.release.qvl_release_policy_hash,
                now=now,
            )
        except RoyaltyQvlClientError:
            raise
        except Exception:
            raise RoyaltyQvlClientError("royalty_qvl_challenge_invalid") from None

    def _collect_attestation(
        self,
        challenge: QvlChallenge,
    ) -> PreparedRoyaltyAttestation:
        if (
            not dstack_utils.is_dstack_enabled()
            or dstack_utils.is_dstack_simulator()
        ):
            raise RoyaltyQvlClientError("production_dstack_required")
        report_data = derive_royalty_settlement_report_data(self.release)
        quote_report_data = bytes.fromhex(report_data[2:]) + challenge.digest_bytes
        try:
            details = dstack_utils.get_attestation_details(quote_report_data)
        except Exception:
            raise RoyaltyQvlClientError("royalty_dstack_evidence_unavailable") from None
        quote = _hex_bytes(
            details.get("quote"),
            minimum=MIN_TDX_QUOTE_BYTES,
            maximum=MAX_TDX_QUOTE_BYTES,
        )
        returned_report_data = _hex_bytes(
            details.get("quote_report_data"),
            minimum=64,
            maximum=64,
        )
        if returned_report_data != quote_report_data:
            raise RoyaltyQvlClientError("royalty_dstack_evidence_invalid")
        compose_hash = _bytes32(details.get("compose_hash"), field_name="compose_hash")
        app_id = str(details.get("app_id") or "").strip().lower()
        os_image_hash = str(details.get("os_image_hash") or "").strip().lower()
        if (
            compose_hash != self.release.compose_hash
            or not _APP_ID.fullmatch(app_id)
            or app_id != self.release.app_id
            or not _BARE_SHA256.fullmatch(os_image_hash)
            or os_image_hash != self.release.os_image_hash
        ):
            raise RoyaltyQvlClientError("royalty_dstack_release_drift")
        quote_hash = "0x" + hashlib.sha256(quote).hexdigest()
        if quote_hash in self.revoked_quote_hashes:
            raise RoyaltyQvlClientError("royalty_dstack_quote_revoked")
        expectation: dict[str, Any] = {
            "mode": "tdx",
            "signer_address": self.release.settlement_verifier_address,
            "chain_id": self.release.chain_id,
            "contract_address": self.release.distributor_address,
            "report_data": report_data,
            "quote_report_data": "0x" + quote_report_data.hex(),
            "quote_hash": quote_hash,
            "quote_size": len(quote),
            "compose_hash": compose_hash,
            "app_id": app_id,
            "os_image_hash": os_image_hash,
            "raw_secret_egress": False,
        }
        evidence_hash = derive_royalty_settlement_attestation_evidence_hash(
            release=self.release,
            challenge=challenge.to_public_dict(),
            expectation=expectation,
        )
        return PreparedRoyaltyAttestation(
            challenge=challenge,
            quote="0x" + quote.hex(),
            expectation=MappingProxyType(expectation),
            attestation_evidence_hash=evidence_hash,
        )

    @staticmethod
    def _checked_at(now: int | None) -> int:
        checked_at = int(time.time()) if now is None else now
        if (
            isinstance(checked_at, bool)
            or not isinstance(checked_at, int)
            or checked_at < 1
        ):
            raise RoyaltyQvlClientError("royalty_settlement_intent_invalid")
        return checked_at

    def _validate_intent(
        self,
        intent: RoyaltySettlementIntent,
        *,
        checked_at: int,
    ) -> None:
        if not isinstance(intent, RoyaltySettlementIntent):
            raise RoyaltyQvlClientError("royalty_settlement_intent_invalid")
        if (
            intent.expiry <= checked_at
            or intent.expiry
            > checked_at + self.release.max_authorization_lifetime_seconds
        ):
            raise RoyaltyQvlClientError("royalty_settlement_expiry_invalid")

    def prepare_attestation(
        self,
        *,
        now: int | None = None,
    ) -> PreparedRoyaltyAttestation:
        """Collect one fresh challenge-bound quote without creating signatures.

        The orchestration worker deliberately performs this network-bound step
        before taking the global execution-policy journal lease.  The returned
        object has no serializer and still contains the raw quote, so it must
        remain ephemeral inside the main-runtime CVM.
        """

        checked_at = self._checked_at(now)
        challenge = self.issue_challenge(now=checked_at)
        return self._collect_attestation(challenge)

    def _authenticate_prepared(
        self,
        prepared: PreparedRoyaltyAttestation,
        *,
        checked_at: int,
    ) -> None:
        if not isinstance(prepared, PreparedRoyaltyAttestation):
            raise RoyaltyQvlClientError("royalty_dstack_evidence_invalid")
        try:
            challenge = authenticate_qvl_challenge(
                prepared.challenge,
                expected_profile=ROYALTY_QVL_PROFILE,
                expected_chain_id=self.release.chain_id,
                expected_domain=ROYALTY_QVL_DOMAIN,
                expected_cvm_id=self.release.main_runtime_cvm_id,
                expected_deployment_intent_sha256=(
                    self.release.deployment_intent_sha256
                ),
                expected_release_authority_sha256=(
                    self.release.release_authority_sha256
                ),
                expected_ceremony_nonce=self.release.ceremony_nonce,
                expected_measurement_policy_sha256=(
                    self.release.measurement_policy_sha256
                ),
                trusted_verifier_addresses=(
                    self.trusted_verdict_verifier_address,
                ),
                expected_policy_hash=self.release.qvl_release_policy_hash,
                now=checked_at,
            )
            quote = _hex_bytes(
                prepared.quote,
                minimum=MIN_TDX_QUOTE_BYTES,
                maximum=MAX_TDX_QUOTE_BYTES,
            )
            expectation = dict(prepared.expectation)
            expected_fields = {
                "mode",
                "signer_address",
                "chain_id",
                "contract_address",
                "report_data",
                "quote_report_data",
                "quote_hash",
                "quote_size",
                "compose_hash",
                "app_id",
                "os_image_hash",
                "raw_secret_egress",
            }
            if set(expectation) != expected_fields:
                raise ValueError
            report_data = derive_royalty_settlement_report_data(self.release)
            quote_report_data = "0x" + (
                bytes.fromhex(report_data[2:]) + challenge.digest_bytes
            ).hex()
            expected_quote_hash = "0x" + hashlib.sha256(quote).hexdigest()
            if (
                expectation["mode"] != "tdx"
                or expectation["signer_address"]
                != self.release.settlement_verifier_address
                or expectation["chain_id"] != self.release.chain_id
                or expectation["contract_address"]
                != self.release.distributor_address
                or expectation["report_data"] != report_data
                or expectation["quote_report_data"] != quote_report_data
                or expectation["quote_hash"] != expected_quote_hash
                or expectation["quote_size"] != len(quote)
                or expectation["compose_hash"] != self.release.compose_hash
                or expectation["app_id"] != self.release.app_id
                or expectation["os_image_hash"] != self.release.os_image_hash
                or expectation["raw_secret_egress"] is not False
                or expected_quote_hash in self.revoked_quote_hashes
                or prepared.attestation_evidence_hash
                != derive_royalty_settlement_attestation_evidence_hash(
                    release=self.release,
                    challenge=challenge.to_public_dict(),
                    expectation=expectation,
                )
            ):
                raise ValueError
        except RoyaltyQvlClientError:
            raise
        except Exception:
            raise RoyaltyQvlClientError(
                "royalty_dstack_evidence_invalid"
            ) from None

    def authorize_prepared(
        self,
        intent: RoyaltySettlementIntent,
        prepared: PreparedRoyaltyAttestation,
        *,
        now: int | None = None,
    ) -> AuthorizedRoyaltySettlementPlan:
        """Sign and independently verify one already-collected fresh quote."""

        checked_at = self._checked_at(now)
        return self._authorize_prepared(
            intent,
            prepared,
            checked_at=checked_at,
            signer=None,
        )

    def _authorize_prepared(
        self,
        intent: RoyaltySettlementIntent,
        prepared: PreparedRoyaltyAttestation,
        *,
        checked_at: int,
        signer: Any | None,
    ) -> AuthorizedRoyaltySettlementPlan:
        self._validate_intent(intent, checked_at=checked_at)
        self._authenticate_prepared(prepared, checked_at=checked_at)
        challenge = prepared.challenge
        if intent.expiry > challenge.expires_at:
            raise RoyaltyQvlClientError("royalty_settlement_expiry_invalid")
        if signer is None:
            signer = self._settlement_signer()
        if signer.address != self.release.settlement_verifier_address:
            raise RoyaltyQvlClientError("royalty_settlement_signer_drift")
        try:
            packet = build_royalty_settlement_authorization_packet(
                release=self.release,
                intent=intent,
                attestation_evidence_hash=prepared.attestation_evidence_hash,
                signer=signer,
            )
        except RoyaltySettlementSignerUnavailable:
            raise RoyaltyQvlClientError(
                "royalty_settlement_signer_unavailable"
            ) from None
        except Exception:
            raise RoyaltyQvlClientError(
                "royalty_settlement_packet_invalid"
            ) from None

        return self._verify_and_build_plan(
            packet=packet,
            prepared=prepared,
            checked_at=checked_at,
        )

    def _settlement_signer(self) -> Any:
        try:
            return DstackRoyaltySettlementSigner.from_dstack()
        except Exception:
            raise RoyaltyQvlClientError(
                "royalty_settlement_signer_unavailable"
            ) from None

    def authorize(
        self,
        intent: RoyaltySettlementIntent,
        *,
        now: int | None = None,
    ) -> AuthorizedRoyaltySettlementPlan:
        """Produce one fresh dual-authorized plan without broadcasting it."""

        checked_at = self._checked_at(now)
        self._validate_intent(intent, checked_at=checked_at)
        # Preserve the original all-in-one API's fail-before-network signer
        # check.  The orchestration path instead calls ``prepare_attestation``
        # before acquiring its global lease and ``authorize_prepared`` inside.
        signer = self._settlement_signer()
        prepared = self.prepare_attestation(now=checked_at)
        return self._authorize_prepared(
            intent,
            prepared,
            checked_at=checked_at,
            signer=signer,
        )

    def _verify_and_build_plan(
        self,
        *,
        packet: Any,
        prepared: PreparedRoyaltyAttestation,
        checked_at: int,
    ) -> AuthorizedRoyaltySettlementPlan:
        challenge = prepared.challenge

        verdict_payload = self._post(
            self.qvl_url,
            {
                "schema": QVL_REQUEST_SCHEMA,
                "challenge": challenge.to_public_dict(),
                "quote": prepared.quote,
                "expectation": dict(prepared.expectation),
                "royalty_authorization": packet.to_qvl_dict(),
            },
        )
        verified_at = checked_at
        try:
            if set(verdict_payload) != ROYALTY_QVL_VERDICT_FIELDS:
                raise ValueError
            verdict = independent_attestation_verdict_from_public_dict(
                verdict_payload
            )
            authenticated = authenticate_independent_attestation_verdict(
                verdict,
                expectation=IndependentAttestationExpectation(
                    trusted_verifier_addresses=(
                        self.trusted_verdict_verifier_address,
                    ),
                    chain_id=self.release.chain_id,
                    domain=ROYALTY_QVL_DOMAIN,
                    profile=ROYALTY_QVL_PROFILE,
                    cvm_id=self.release.main_runtime_cvm_id,
                    deployment_intent_sha256=(
                        self.release.deployment_intent_sha256
                    ),
                    release_authority_sha256=(
                        self.release.release_authority_sha256
                    ),
                    ceremony_nonce=self.release.ceremony_nonce,
                    measurement_policy_sha256=(
                        self.release.measurement_policy_sha256
                    ),
                    release_policy_hash=self.release.qvl_release_policy_hash,
                    challenge_id=challenge.challenge_id,
                    challenge_digest=challenge.challenge_digest,
                    challenge_issued_at=challenge.issued_at,
                    challenge_expires_at=challenge.expires_at,
                    quote_hash=str(prepared.expectation["quote_hash"]),
                    report_data=str(prepared.expectation["report_data"]),
                    compose_hash=str(prepared.expectation["compose_hash"]),
                    app_id=str(prepared.expectation["app_id"]),
                    os_image_hash=str(prepared.expectation["os_image_hash"]),
                    signer_address=self.release.settlement_verifier_address,
                    contract_address=self.release.distributor_address,
                    max_age_seconds=self.max_verdict_age_seconds,
                ),
                now=verified_at,
            )
            authorization = packet.authorization
            expected_qvl_digest = royalty_settlement_qvl_authorization_digest(
                chain_id=self.release.chain_id,
                distributor_address=self.release.distributor_address,
                authorization=authorization,
            )
            expected_anchor_commitment = (
                derive_royalty_settlement_anchor_evidence_commitment(
                    release=self.release,
                    authorization=authorization,
                )
            )
            qvl_signature = str(verdict.qvl_royalty_authorization_signature).lower()
            recovered_qvl = recover_raw_digest_address(
                digest=expected_qvl_digest,
                signature=qvl_signature,
            )
            if (
                verdict.qvl_royalty_verifier_address.lower()
                != self.release.royalty_qvl_verifier_address
                or recovered_qvl != self.release.royalty_qvl_verifier_address
                or verdict.qvl_royalty_policy_commitment.lower()
                != self.release.royalty_qvl_policy_commitment
                or verdict.qvl_royalty_release_policy_commitment.lower()
                != self.release.release_policy_commitment
                or verdict.qvl_royalty_attestation_evidence_hash.lower()
                != prepared.attestation_evidence_hash
                or verdict.qvl_royalty_anchor_evidence_commitment.lower()
                != expected_anchor_commitment
                or verdict.qvl_royalty_authorization_expiry != authorization.expiry
                or verdict.qvl_royalty_authorization_expiry <= verified_at
                or verdict.qvl_royalty_authorization_expiry
                > challenge.expires_at
                or verdict.qvl_royalty_authorization_expiry > verdict.expires_at
                or verdict.expires_at > challenge.expires_at
                or verdict.qvl_royalty_authorization_digest.lower()
                != expected_qvl_digest
            ):
                raise ValueError
        except (ResultVerifierError, RoyaltySettlementAuthorizationError, ValueError):
            raise RoyaltyQvlClientError("royalty_qvl_verdict_invalid") from None
        except Exception:
            raise RoyaltyQvlClientError("royalty_qvl_verdict_invalid") from None

        return AuthorizedRoyaltySettlementPlan(
            chain_id=self.release.chain_id,
            distributor_address=self.release.distributor_address,
            authorization=packet.authorization,
            settlement_verifier_address=packet.settlement_verifier_address,
            settlement_authorization_digest=(
                packet.settlement_authorization_digest
            ),
            settlement_authorization_signature=(
                packet.settlement_authorization_signature
            ),
            qvl_verifier_address=self.release.royalty_qvl_verifier_address,
            qvl_policy_commitment=self.release.royalty_qvl_policy_commitment,
            qvl_authorization_digest=expected_qvl_digest,
            qvl_authorization_signature=qvl_signature,
            qvl_anchor_evidence_commitment=expected_anchor_commitment,
            qvl_verdict_verifier_address=(
                self.trusted_verdict_verifier_address
            ),
            qvl_verdict_digest=authenticated.verdict_digest,
            qvl_release_policy_hash=self.release.qvl_release_policy_hash,
            quote_hash=str(prepared.expectation["quote_hash"]),
            report_data=str(prepared.expectation["report_data"]),
            compose_hash=str(prepared.expectation["compose_hash"]),
            app_id=str(prepared.expectation["app_id"]),
            os_image_hash=str(prepared.expectation["os_image_hash"]),
            authorization_expires_at=packet.authorization.expiry,
        )
