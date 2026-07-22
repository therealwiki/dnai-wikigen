"""Production independent-QVL activation for Compute workload recipients.

The main CVM derives both its X25519 recipient and a purpose-separated
secp256k1 activation identity from dstack.  For every activation it obtains an
authenticated, one-use challenge from the dedicated Compute-workload QVL,
collects a fresh TDX quote whose 64-byte report data binds the complete public
recipient context plus that challenge, and authenticates the returned EIP-191
verdict.  Raw quotes and bearer credentials never enter the public activation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Mapping, Sequence

import httpx
from eth_account import Account

from tinker_delegate import dstack_utils
from tinker_delegate.chain_submitter import derive_ethereum_private_key
from tinker_delegate.compute_workload_ingress import (
    ComputeWorkloadIngressUnavailable,
    ComputeWorkloadRecipient,
    ComputeWorkloadRecipientActivation,
    authenticate_compute_workload_recipient_activation,
    compute_workload_recipient_attestation_report_data,
    validate_compute_workload_recipient_attestation,
)
from tinker_delegate.qvl_freshness import (
    QvlChallenge,
    authenticate_qvl_challenge,
    challenge_request,
    qvl_challenge_from_public_dict,
)
from tinker_delegate.result_verifier import (
    IndependentAttestationExpectation,
    independent_attestation_verdict_from_public_dict,
)


ACTIVATION_SIGNER_KEY_PATH = "tinker/compute_workload_activation_signer"
ACTIVATION_SIGNER_CUSTODY = (
    "dstack_derived_compute_workload_activation_signer"
)
QVL_AUTH_TOKEN_ENV = "TINKER_COMPUTE_WORKLOAD_QVL_AUTH_TOKEN"
MAX_QVL_RESPONSE_BYTES = 96 * 1024
MIN_TDX_QUOTE_BYTES = 1024
MAX_TDX_QUOTE_BYTES = 16 * 1024

WORKLOAD_QVL_VERDICT_FIELDS = frozenset(
    {
        "schema",
        "verification_method",
        "verified",
        "domain",
        "cvm_id",
        "deployment_intent_sha256",
        "release_authority_sha256",
        "ceremony_nonce",
        "measurement_policy_sha256",
        "profile",
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
        "chain_id",
        "contract_address",
        "issued_at",
        "activation_evidence_lease_expires_at",
        "expires_at",
        "verifier_address",
        "verifier_signature",
    }
)

_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_APP_ID = re.compile(r"^(?!0{40}$)[0-9a-f]{40}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_CVM_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{7,127}$")
WORKLOAD_DOMAIN = "main_runtime_cvm"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except Exception:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload QVL is unavailable"
        ) from None
    if not isinstance(value, dict):
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload QVL is unavailable"
        )
    return value


def _bytes32(value: Any) -> str:
    if not isinstance(value, str):
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload release binding is invalid"
        )
    result = value.strip().lower()
    if not _BYTES32.fullmatch(result) or int(result[2:], 16) == 0:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload release binding is invalid"
        )
    return result


def _address(value: Any) -> str:
    if not isinstance(value, str):
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload release binding is invalid"
        )
    result = value.strip().lower()
    if not _ADDRESS.fullmatch(result) or int(result[2:], 16) == 0:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload release binding is invalid"
        )
    return result


def _sha256(value: Any) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload release binding is invalid"
        )
    return value


def _cvm_id(value: Any) -> str:
    if not isinstance(value, str) or not _CVM_ID.fullmatch(value):
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload release binding is invalid"
        )
    return value


def _https_verify_url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2_048:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload QVL is unavailable"
        )
    try:
        parsed = httpx.URL(value)
    except Exception:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload QVL is unavailable"
        ) from None
    if (
        parsed.scheme != "https"
        or not parsed.host
        or parsed.userinfo
        or parsed.query
        or parsed.fragment
        or parsed.path != "/verify"
        or parsed.host in {"localhost", "127.0.0.1", "::1"}
    ):
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload QVL is unavailable"
        )
    return str(parsed)


def _revoked_quote_hashes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 32_768:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload revocation policy is invalid"
        )
    try:
        parsed = json.loads(value, object_pairs_hook=_unique_object)
    except Exception:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload revocation policy is invalid"
        ) from None
    if not isinstance(parsed, list) or len(parsed) > 1_024:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload revocation policy is invalid"
        )
    normalized = tuple(_bytes32(item) for item in parsed)
    if normalized != tuple(sorted(set(normalized))):
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload revocation policy is invalid"
        )
    return normalized


def _hex_bytes(value: Any, *, minimum: int, maximum: int) -> bytes:
    if not isinstance(value, str):
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload dstack evidence is invalid"
        )
    raw = value.lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    try:
        decoded = bytes.fromhex(raw)
    except ValueError:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload dstack evidence is invalid"
        ) from None
    if not minimum <= len(decoded) <= maximum:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload dstack evidence is invalid"
        )
    return decoded


def _bounded_response(response: httpx.Response) -> bytes:
    length = response.headers.get("content-length")
    if length is not None:
        try:
            parsed = int(length)
        except ValueError:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload QVL is unavailable"
            ) from None
        if parsed < 1 or parsed > MAX_QVL_RESPONSE_BYTES:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload QVL is unavailable"
            )
    output = bytearray()
    for chunk in response.iter_bytes():
        if len(chunk) > MAX_QVL_RESPONSE_BYTES - len(output):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload QVL is unavailable"
            )
        output.extend(chunk)
    if not output:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload QVL is unavailable"
        )
    return bytes(output)


class HttpsComputeWorkloadActivationProvider:
    """Authenticated no-redirect transport to one dedicated QVL release."""

    def __init__(
        self,
        *,
        qvl_url: str,
        auth_token: str,
        trusted_verifier_address: str,
        release_policy_hash: str,
        max_verdict_age_seconds: int,
        revoked_quote_hashes: Sequence[str],
        chain_id: int,
        compute_vault_address: str,
        compute_vault_runtime_code_hash: str,
        fresh_contract_deployment_receipt_sha256: str,
        cvm_id: str,
        deployment_intent_sha256: str,
        release_authority_sha256: str,
        ceremony_nonce: str,
        measurement_policy_set_sha256: str,
        measurement_policy_sha256: str,
        main_runtime_evidence_sha256: str,
        client: httpx.Client | None = None,
    ) -> None:
        if (
            not dstack_utils.is_dstack_enabled()
            or dstack_utils.is_dstack_simulator()
            or not isinstance(max_verdict_age_seconds, int)
            or isinstance(max_verdict_age_seconds, bool)
            or not 1 <= max_verdict_age_seconds <= 300
            or chain_id != 84_532
            or not isinstance(auth_token, str)
            or not 32 <= len(auth_token.encode("utf-8")) <= 4_096
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in auth_token)
        ):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload activation provider is unavailable"
            )
        self.qvl_url = _https_verify_url(qvl_url)
        self.challenge_url = str(
            httpx.URL(self.qvl_url).copy_with(path="/challenge")
        )
        self._auth_token = auth_token
        self.trusted_verifier_address = _address(trusted_verifier_address)
        self.release_policy_hash = _bytes32(release_policy_hash)
        self.max_verdict_age_seconds = max_verdict_age_seconds
        normalized_revocations = tuple(_bytes32(value) for value in revoked_quote_hashes)
        if normalized_revocations != tuple(sorted(set(normalized_revocations))):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload revocation policy is invalid"
            )
        self.revoked_quote_hashes = frozenset(normalized_revocations)
        self.chain_id = chain_id
        self.compute_vault_address = _address(compute_vault_address)
        self.compute_vault_runtime_code_hash = _bytes32(
            compute_vault_runtime_code_hash
        )
        self.fresh_contract_deployment_receipt_sha256 = _bytes32(
            fresh_contract_deployment_receipt_sha256
        )
        self.domain = WORKLOAD_DOMAIN
        self.cvm_id = _cvm_id(cvm_id)
        self.deployment_intent_sha256 = _sha256(deployment_intent_sha256)
        self.release_authority_sha256 = _sha256(release_authority_sha256)
        self.ceremony_nonce = _bytes32(ceremony_nonce)
        self.measurement_policy_set_sha256 = _sha256(
            measurement_policy_set_sha256
        )
        self.measurement_policy_sha256 = _sha256(measurement_policy_sha256)
        self.main_runtime_evidence_sha256 = _sha256(
            main_runtime_evidence_sha256
        )
        try:
            material = dstack_utils.derive_storage_key(ACTIVATION_SIGNER_KEY_PATH)
            private_key = derive_ethereum_private_key(
                material,
                ACTIVATION_SIGNER_KEY_PATH,
            )
            self.activation_signer_address = Account.from_key(
                private_key
            ).address.lower()
        except Exception:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload activation signer is unavailable"
            ) from None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None

    @classmethod
    def from_settings(
        cls,
        settings: Any,
        *,
        client: httpx.Client | None = None,
    ) -> "HttpsComputeWorkloadActivationProvider":
        return cls(
            qvl_url=str(getattr(settings, "compute_workload_qvl_url", "") or ""),
            auth_token=os.environ.get(QVL_AUTH_TOKEN_ENV, ""),
            trusted_verifier_address=str(
                getattr(settings, "compute_workload_qvl_verifier_address", "") or ""
            ),
            release_policy_hash=str(
                getattr(settings, "compute_workload_qvl_release_policy_hash", "") or ""
            ),
            max_verdict_age_seconds=getattr(
                settings,
                "compute_workload_qvl_max_verdict_age_seconds",
                0,
            ),
            revoked_quote_hashes=_revoked_quote_hashes(
                str(
                    getattr(
                        settings,
                        "compute_workload_qvl_revoked_quote_hashes_json",
                        "",
                    )
                    or ""
                )
            ),
            chain_id=getattr(settings, "compute_workload_chain_id", 0),
            compute_vault_address=str(
                getattr(settings, "compute_vault_address", "") or ""
            ),
            compute_vault_runtime_code_hash=str(
                getattr(settings, "compute_vault_runtime_code_hash", "") or ""
            ),
            fresh_contract_deployment_receipt_sha256=str(
                getattr(
                    settings,
                    "compute_workload_fresh_deployment_receipt_sha256",
                    "",
                )
                or ""
            ),
            cvm_id=str(getattr(settings, "compute_workload_cvm_id", "") or ""),
            deployment_intent_sha256=str(
                getattr(settings, "compute_workload_deployment_intent_sha256", "")
                or ""
            ),
            release_authority_sha256=str(
                getattr(settings, "compute_workload_release_authority_sha256", "")
                or ""
            ),
            ceremony_nonce=str(
                getattr(settings, "compute_workload_ceremony_nonce", "") or ""
            ),
            measurement_policy_set_sha256=str(
                getattr(
                    settings,
                    "compute_workload_measurement_policy_set_sha256",
                    "",
                )
                or ""
            ),
            measurement_policy_sha256=str(
                getattr(
                    settings,
                    "compute_workload_qvl_measurement_policy_sha256",
                    "",
                )
                or ""
            ),
            main_runtime_evidence_sha256=str(
                getattr(
                    settings,
                    "compute_workload_main_runtime_evidence_sha256",
                    "",
                )
                or ""
            ),
            client=client,
        )

    def __repr__(self) -> str:
        return "HttpsComputeWorkloadActivationProvider(authenticated=True)"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def recipient_attestation(self, public_key: bytes) -> dict[str, Any]:
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload recipient is invalid"
            )
        payload = {
            "schema": "dnai.compute-workload-recipient-attestation.v1",
            "context": "compute_workload",
            "audience": "dnai-wikigen:compute-workload-recipient",
            "service": "dnai-wikigen",
            "protocol": "compute_workload_ingress_v1",
            "encryption_public_key": public_key.hex(),
            "key_id": "sha256:" + hashlib.sha256(public_key).hexdigest(),
            "activation_signer_address": self.activation_signer_address,
            "activation_signer_key_path": ACTIVATION_SIGNER_KEY_PATH,
            "activation_signer_custody": ACTIVATION_SIGNER_CUSTODY,
            "chain_id": self.chain_id,
            "compute_vault_address": self.compute_vault_address,
            "compute_vault_runtime_code_hash": self.compute_vault_runtime_code_hash,
            "fresh_contract_deployment_receipt_sha256": (
                self.fresh_contract_deployment_receipt_sha256
            ),
        }
        return validate_compute_workload_recipient_attestation(
            payload,
            expected_public_key=public_key,
        )

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
                    raise ComputeWorkloadIngressUnavailable(
                        "Compute workload QVL is unavailable"
                    )
                raw = _bounded_response(response)
            finally:
                response.close()
        except ComputeWorkloadIngressUnavailable:
            raise
        except Exception:
            # Transport errors may retain the bearer and raw quote; never
            # preserve them through an exception chain.
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload QVL is unavailable"
            ) from None
        return _json_object(raw)

    def _issue_challenge(self, *, now: int) -> QvlChallenge:
        payload = self._post(
            self.challenge_url,
            challenge_request(
                "compute_workload",
                chain_id=self.chain_id,
                domain=self.domain,
                cvm_id=self.cvm_id,
                deployment_intent_sha256=self.deployment_intent_sha256,
                release_authority_sha256=self.release_authority_sha256,
                ceremony_nonce=self.ceremony_nonce,
                measurement_policy_sha256=self.measurement_policy_sha256,
            ),
        )
        try:
            return authenticate_qvl_challenge(
                qvl_challenge_from_public_dict(payload),
                expected_profile="compute_workload",
                expected_chain_id=self.chain_id,
                expected_domain=self.domain,
                expected_cvm_id=self.cvm_id,
                expected_deployment_intent_sha256=self.deployment_intent_sha256,
                expected_release_authority_sha256=self.release_authority_sha256,
                expected_ceremony_nonce=self.ceremony_nonce,
                expected_measurement_policy_sha256=self.measurement_policy_sha256,
                trusted_verifier_addresses=(self.trusted_verifier_address,),
                expected_policy_hash=self.release_policy_hash,
                now=now,
            )
        except Exception:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload QVL challenge is invalid"
            ) from None

    def verified_activation(
        self,
        recipient: ComputeWorkloadRecipient,
        *,
        now: int,
    ) -> ComputeWorkloadRecipientActivation:
        if (
            not isinstance(recipient, ComputeWorkloadRecipient)
            or recipient.custody_mode != "dstack"
            or recipient.recipient_attestation is None
            or not dstack_utils.is_dstack_enabled()
            or dstack_utils.is_dstack_simulator()
        ):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload recipient activation is unavailable"
            )
        expected_attestation = self.recipient_attestation(recipient.public_key)
        if dict(recipient.recipient_attestation) != expected_attestation:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload recipient release binding is invalid"
            )
        challenge = self._issue_challenge(now=now)
        report_data = compute_workload_recipient_attestation_report_data(
            expected_attestation
        )
        quote_report_data = report_data + challenge.digest_bytes
        try:
            details = dstack_utils.get_attestation_details(quote_report_data)
        except Exception:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload dstack evidence is unavailable"
            ) from None
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
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload dstack evidence is invalid"
            )
        compose_hash = _bytes32(details.get("compose_hash"))
        app_id = str(details.get("app_id") or "").lower()
        os_image_hash = str(details.get("os_image_hash") or "").lower()
        if not _APP_ID.fullmatch(app_id) or not _HEX_64.fullmatch(os_image_hash):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload dstack identity is invalid"
            )
        quote_hash = "0x" + hashlib.sha256(quote).hexdigest()
        expectation_payload = {
            "mode": "tdx",
            "signer_address": self.activation_signer_address,
            "chain_id": self.chain_id,
            "contract_address": self.compute_vault_address,
            "report_data": "0x" + report_data.hex(),
            "quote_report_data": "0x" + quote_report_data.hex(),
            "quote_hash": quote_hash,
            "quote_size": len(quote),
            "compose_hash": compose_hash,
            "app_id": app_id,
            "os_image_hash": os_image_hash,
            "raw_secret_egress": False,
        }
        verdict_payload = self._post(
            self.qvl_url,
            {
                "schema": "dnai.independent-tdx-verification-request.v2",
                "challenge": challenge.to_public_dict(),
                "quote": "0x" + quote.hex(),
                "expectation": expectation_payload,
                "compute_workload_recipient": expected_attestation,
            },
        )
        try:
            if set(verdict_payload) != WORKLOAD_QVL_VERDICT_FIELDS:
                raise ValueError
            verdict = independent_attestation_verdict_from_public_dict(
                verdict_payload
            )
            if verdict.quote_hash.lower() in self.revoked_quote_hashes:
                raise ValueError
            expectation = IndependentAttestationExpectation(
                trusted_verifier_addresses=(self.trusted_verifier_address,),
                chain_id=self.chain_id,
                domain=self.domain,
                profile="compute_workload",
                cvm_id=self.cvm_id,
                deployment_intent_sha256=self.deployment_intent_sha256,
                release_authority_sha256=self.release_authority_sha256,
                ceremony_nonce=self.ceremony_nonce,
                measurement_policy_sha256=self.measurement_policy_sha256,
                release_policy_hash=self.release_policy_hash,
                challenge_id=challenge.challenge_id,
                challenge_digest=challenge.challenge_digest,
                challenge_issued_at=challenge.issued_at,
                challenge_expires_at=challenge.expires_at,
                quote_hash=quote_hash,
                report_data="0x" + report_data.hex(),
                compose_hash=compose_hash,
                app_id=app_id,
                os_image_hash=os_image_hash,
                signer_address=self.activation_signer_address,
                contract_address=self.compute_vault_address,
                max_age_seconds=self.max_verdict_age_seconds,
            )
            return authenticate_compute_workload_recipient_activation(
                recipient=recipient,
                verdict=verdict,
                expectation=expectation,
                measurement_policy_set_sha256=(
                    self.measurement_policy_set_sha256
                ),
                main_runtime_evidence_sha256=(
                    self.main_runtime_evidence_sha256
                ),
                now=now,
            )
        except ComputeWorkloadIngressUnavailable:
            raise
        except Exception:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload QVL verdict is invalid"
            ) from None
