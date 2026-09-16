"""Production-only dstack quote for the independent metering signer identity."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import Protocol

import dcap_qvl
import httpx
from dstack_sdk import DstackClient
from eth_account import Account
from eth_account.messages import encode_defunct

from .errors import SignerUnavailable
from .models import (
    MAX_QUOTE_BYTES,
    MIN_QUOTE_BYTES,
    ComputeMeteringQvlVerdict,
    ComputeMeteringAuthorizationRequest,
    ComputeQvlChallenge,
    MeteringIdentityAttestation,
)


REPORT_DATA_DOMAIN = b"dnai-wikigen/compute-metering-signer-attestation/v1\x00"
BASE_SEPOLIA_CHAIN_ID = 84_532
DSTACK_METERING_CUSTODY = "dstack_derived_independent_cvm"
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_BYTES32_RE = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")
_CVM_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{7,127}$")
_SHA256_RE = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
QVL_CHALLENGE_DOMAIN = b"dnai-wikigen/attestation-qvl/challenge/v2\x00"
QVL_VERDICT_DOMAIN = b"dnai-wikigen/independent-tdx-verdict/v4\x00"
COMPUTE_EVIDENCE_DOMAIN = b"dnai-wikigen/compute-metering-attestation-evidence/v1\x00"
MAX_QVL_JSON_BYTES = 64 * 1024


class MeteringIdentityAttestor(Protocol):
    def attest(
        self,
        *,
        metering_verifier: str,
        chain_id: int,
        vault_address: str,
        policy_set_hash: str,
        signer_custody: str,
        challenge: ComputeQvlChallenge,
    ) -> MeteringIdentityAttestation:
        """Return a quote that binds the exact independently derived meter identity."""


def _address(value: str) -> str:
    normalized = value.lower()
    if not _ADDRESS_RE.fullmatch(normalized) or int(normalized[2:], 16) == 0:
        raise SignerUnavailable
    return normalized


def _bytes32(value: str) -> str:
    normalized = value.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    if not _BYTES32_RE.fullmatch(normalized):
        raise SignerUnavailable
    return normalized


def _bare_sha256(value: object) -> str:
    normalized = str(value).lower().removeprefix("0x")
    if not re.fullmatch(r"(?!0{64}$)[0-9a-f]{64}", normalized):
        raise SignerUnavailable
    return normalized


def _app_id(value: object) -> str:
    normalized = str(value).lower().removeprefix("0x")
    if not re.fullmatch(r"(?!0{40}$)[0-9a-f]{40}", normalized):
        raise SignerUnavailable
    return normalized


def _release_sha256(value: str) -> str:
    if not _SHA256_RE.fullmatch(value):
        raise SignerUnavailable
    return value


def _cvm_id(value: str) -> str:
    if not _CVM_ID_RE.fullmatch(value):
        raise SignerUnavailable
    return value


def metering_identity_report_data(
    *,
    metering_verifier: str,
    chain_id: int,
    vault_address: str,
    policy_set_hash: str,
    signer_custody: str,
) -> bytes:
    """Derive the 32-byte report-data digest shared with the independent QVL."""

    if type(chain_id) is not int or chain_id != BASE_SEPOLIA_CHAIN_ID:
        raise SignerUnavailable
    if signer_custody != DSTACK_METERING_CUSTODY:
        raise SignerUnavailable
    payload = {
        "schema": "dnai.compute-metering-signer-attestation.v1",
        "chain_id": chain_id,
        "vault_address": _address(vault_address),
        "metering_verifier": _address(metering_verifier),
        "policy_set_hash": _bytes32(policy_set_hash),
        "signer_custody": signer_custody,
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(REPORT_DATA_DOMAIN + canonical).digest()


def compute_metering_attestation_evidence_hash(
    attestation: MeteringIdentityAttestation,
) -> str:
    """Hash the complete bounded quote packet that the QVL independently verifies."""

    payload = {
        "schema": "dnai.compute-metering-attestation-evidence.v1",
        "chain_id": attestation.challenge.chain_id,
        "domain": attestation.challenge.domain,
        "profile": attestation.challenge.profile,
        "cvm_id": attestation.challenge.cvm_id,
        "deployment_intent_sha256": (
            attestation.challenge.deployment_intent_sha256
        ),
        "release_authority_sha256": (
            attestation.challenge.release_authority_sha256
        ),
        "ceremony_nonce": attestation.challenge.ceremony_nonce,
        "measurement_policy_sha256": (
            attestation.challenge.measurement_policy_sha256
        ),
        "release_policy_hash": attestation.challenge.release_policy_hash,
        "challenge_id": attestation.challenge.challenge_id,
        "challenge_digest": attestation.challenge.challenge_digest,
        "quote_hash": attestation.quote_hash,
        "report_data": attestation.report_data,
        "quote_report_data": attestation.quote_report_data,
        "compose_hash": attestation.compose_hash,
        "app_id": attestation.app_id,
        "os_image_hash": attestation.os_image_hash,
        "signer_address": attestation.metering_verifier,
        "contract_address": attestation.vault_address,
        "policy_set_hash": attestation.policy_set_hash,
        "signer_custody": attestation.signer_custody,
    }
    return "0x" + hashlib.sha256(COMPUTE_EVIDENCE_DOMAIN + _canonical(payload)).hexdigest()


def independent_qvl_request(
    attestation: MeteringIdentityAttestation,
    authorization: ComputeMeteringAuthorizationRequest | None = None,
) -> dict[str, object]:
    """Map bounded public evidence to the QVL's generic verification request."""

    payload: dict[str, object] = {
        "schema": "dnai.independent-tdx-verification-request.v2",
        "challenge": attestation.challenge.model_dump(mode="json", by_alias=True),
        "quote": attestation.quote,
        "expectation": {
            "mode": attestation.mode,
            "signer_address": attestation.metering_verifier,
            "chain_id": attestation.chain_id,
            "contract_address": attestation.vault_address,
            "report_data": attestation.report_data,
            "quote_report_data": attestation.quote_report_data,
            "quote_hash": attestation.quote_hash,
            "quote_size": attestation.quote_size,
            "compose_hash": attestation.compose_hash,
            "app_id": attestation.app_id,
            "os_image_hash": attestation.os_image_hash,
            "raw_secret_egress": attestation.raw_secret_egress,
        },
    }
    if authorization is not None:
        payload["compute_authorization"] = authorization.model_dump(
            mode="json", by_alias=True
        )
    return payload


class DstackMeteringIdentityAttestor:
    """Real-dstack attestor; construction and quote parsing fail closed."""

    def __init__(self) -> None:
        if any(
            os.environ.get(name, "").strip()
            for name in ("DSTACK_SIMULATOR_ENDPOINT", "TAPPD_SIMULATOR_ENDPOINT")
        ):
            raise SignerUnavailable

    def attest(
        self,
        *,
        metering_verifier: str,
        chain_id: int,
        vault_address: str,
        policy_set_hash: str,
        signer_custody: str,
        challenge: ComputeQvlChallenge,
    ) -> MeteringIdentityAttestation:
        static_report_data = metering_identity_report_data(
            metering_verifier=metering_verifier,
            chain_id=chain_id,
            vault_address=vault_address,
            policy_set_hash=policy_set_hash,
            signer_custody=signer_custody,
        )
        if not isinstance(challenge, ComputeQvlChallenge):
            raise SignerUnavailable
        quote_report_data_request = static_report_data + bytes.fromhex(
            challenge.challenge_digest[2:]
        )
        try:
            client = DstackClient()
            if not client.is_reachable():
                raise SignerUnavailable
            info = client.info()
            quote_result = client.get_quote(quote_report_data_request)
            quote_hex = str(quote_result.quote).lower().removeprefix("0x")
            if not re.fullmatch(r"[0-9a-f]+", quote_hex) or len(quote_hex) % 2:
                raise SignerUnavailable
            raw_quote = bytes.fromhex(quote_hex)
            if len(raw_quote) < MIN_QUOTE_BYTES or len(raw_quote) > MAX_QUOTE_BYTES:
                raise SignerUnavailable
            parsed = dcap_qvl.parse_quote(raw_quote)
            if not parsed.is_tdx() or parsed.quote_type() != "TDX":
                raise SignerUnavailable
            quote_report_data = bytes(parsed.report.report_data)
            if quote_report_data != quote_report_data_request:
                raise SignerUnavailable
        except SignerUnavailable:
            raise
        except Exception as exc:
            raise SignerUnavailable from exc

        report_data_hex = "0x" + static_report_data.hex()
        return MeteringIdentityAttestation(
            schema="dnai.compute-metering-identity-attestation.v2",
            challenge=challenge,
            mode="tdx",
            metering_verifier=_address(metering_verifier),
            chain_id=BASE_SEPOLIA_CHAIN_ID,
            vault_address=_address(vault_address),
            policy_set_hash=_bytes32(policy_set_hash),
            signer_custody=DSTACK_METERING_CUSTODY,
            report_data=report_data_hex,
            quote_report_data="0x" + quote_report_data_request.hex(),
            quote="0x" + quote_hex,
            quote_hash="0x" + hashlib.sha256(raw_quote).hexdigest(),
            quote_size=len(raw_quote),
            app_id=_app_id(info.app_id),
            compose_hash=_bytes32(str(info.compose_hash)),
            os_image_hash=_bare_sha256(info.os_image_hash),
            raw_secret_egress=False,
        )


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def compute_qvl_challenge_digest(challenge: ComputeQvlChallenge) -> str:
    payload = challenge.model_dump(mode="json", by_alias=True)
    payload.pop("challenge_digest")
    payload.pop("verifier_signature")
    return "0x" + hashlib.sha256(QVL_CHALLENGE_DOMAIN + _canonical(payload)).hexdigest()


def compute_qvl_verdict_digest(verdict: ComputeMeteringQvlVerdict) -> str:
    # The independent QVL serializes absent optional authorization fields by
    # omission.  The consumer must hash that exact producer preimage rather
    # than reintroducing Pydantic ``null`` defaults after parsing.
    payload = verdict.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    payload.pop("verifier_signature")
    return "0x" + hashlib.sha256(QVL_VERDICT_DOMAIN + _canonical(payload)).hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError
        output[key] = value
    return output


def _strict_json(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_QVL_JSON_BYTES:
        raise ValueError
    value = json.loads(raw, object_pairs_hook=_unique_object)
    if not isinstance(value, dict):
        raise ValueError
    return value


class HttpsComputeMeteringQvlClient:
    """Challenge-first authenticated QVL transport; raw quotes never egress elsewhere."""

    def __init__(
        self,
        *,
        verify_url: str,
        auth_token: str,
        verifier_address: str,
        release_policy_hash: str,
        cvm_id: str,
        deployment_intent_sha256: str,
        release_authority_sha256: str,
        ceremony_nonce: str,
        measurement_policy_sha256: str,
        client: httpx.Client | None = None,
    ) -> None:
        try:
            parsed = httpx.URL(verify_url)
        except Exception:
            raise SignerUnavailable from None
        if (
            parsed.scheme != "https"
            or not parsed.host
            or parsed.userinfo
            or parsed.query
            or parsed.fragment
            or parsed.path != "/verify"
            or parsed.host in {"localhost", "127.0.0.1", "::1"}
            or not 32 <= len(auth_token.encode("utf-8")) <= 4096
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in auth_token)
        ):
            raise SignerUnavailable
        self.verify_url = str(parsed)
        self.challenge_url = self.verify_url.replace("/verify", "/challenge")
        self._auth_token = auth_token
        self.verifier_address = _address(verifier_address)
        self.release_policy_hash = _bytes32(release_policy_hash)
        self.cvm_id = _cvm_id(cvm_id)
        self.deployment_intent_sha256 = _release_sha256(
            deployment_intent_sha256
        )
        self.release_authority_sha256 = _release_sha256(
            release_authority_sha256
        )
        self.ceremony_nonce = _bytes32(ceremony_nonce)
        self.measurement_policy_sha256 = _release_sha256(
            measurement_policy_sha256
        )
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None

    def __repr__(self) -> str:
        return "HttpsComputeMeteringQvlClient(authenticated=True)"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _post(self, url: str, payload: dict[str, object]) -> dict[str, object]:
        request = self._client.build_request(
            "POST",
            url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._auth_token}",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
            content=_canonical(payload),
        )
        try:
            response = self._client.send(request, stream=True, follow_redirects=False)
            try:
                content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if (
                    response.status_code != 200
                    or response.history
                    or not (content_type == "application/json" or content_type.endswith("+json"))
                ):
                    raise SignerUnavailable
                raw = bytearray()
                for chunk in response.iter_bytes():
                    if len(chunk) > MAX_QVL_JSON_BYTES - len(raw):
                        raise SignerUnavailable
                    raw.extend(chunk)
            finally:
                response.close()
            return _strict_json(bytes(raw))
        except SignerUnavailable:
            raise
        except Exception:
            raise SignerUnavailable from None

    def issue_challenge(self, *, now: int | None = None) -> ComputeQvlChallenge:
        try:
            challenge = ComputeQvlChallenge.model_validate(
                self._post(
                    self.challenge_url,
                    {
                        "schema": "dnai.attestation-qvl-challenge-request.v2",
                        "chain_id": BASE_SEPOLIA_CHAIN_ID,
                        "domain": "independent_metering_cvm",
                        "profile": "compute_metering",
                        "cvm_id": self.cvm_id,
                        "deployment_intent_sha256": (
                            self.deployment_intent_sha256
                        ),
                        "release_authority_sha256": (
                            self.release_authority_sha256
                        ),
                        "ceremony_nonce": self.ceremony_nonce,
                        "measurement_policy_sha256": (
                            self.measurement_policy_sha256
                        ),
                    },
                ),
                strict=True,
            )
            # Freshness is evaluated when the response has arrived, not before
            # the network call. A delayed QVL response cannot revive an expired
            # challenge using a stale request-start timestamp.
            checked_at = int(time.time() if now is None else now)
            if (
                challenge.verifier_address != self.verifier_address
                or challenge.release_policy_hash != self.release_policy_hash
                or challenge.chain_id != BASE_SEPOLIA_CHAIN_ID
                or challenge.domain != "independent_metering_cvm"
                or challenge.profile != "compute_metering"
                or challenge.cvm_id != self.cvm_id
                or challenge.deployment_intent_sha256
                != self.deployment_intent_sha256
                or challenge.release_authority_sha256
                != self.release_authority_sha256
                or challenge.ceremony_nonce != self.ceremony_nonce
                or challenge.measurement_policy_sha256
                != self.measurement_policy_sha256
                or challenge.challenge_digest != compute_qvl_challenge_digest(challenge)
                or challenge.issued_at > checked_at + 5
                or challenge.expires_at <= checked_at
                or challenge.expires_at - challenge.issued_at > 120
            ):
                raise SignerUnavailable
            recovered = Account.recover_message(
                encode_defunct(hexstr=challenge.challenge_digest),
                signature=bytes.fromhex(challenge.verifier_signature[2:]),
            )
            if _address(recovered) != self.verifier_address:
                raise SignerUnavailable
            return challenge
        except SignerUnavailable:
            raise
        except Exception:
            raise SignerUnavailable from None

    def verify(
        self,
        attestation: MeteringIdentityAttestation,
        authorization: ComputeMeteringAuthorizationRequest | None = None,
    ) -> ComputeMeteringQvlVerdict:
        try:
            verdict = ComputeMeteringQvlVerdict.model_validate(
                self._post(
                    self.verify_url,
                    independent_qvl_request(attestation, authorization),
                ),
                strict=True,
            )
            challenge = attestation.challenge
            checked_at = int(time.time())
            if (
                verdict.verifier_address != self.verifier_address
                or verdict.release_policy_hash != self.release_policy_hash
                or verdict.chain_id != challenge.chain_id
                or verdict.domain != challenge.domain
                or verdict.profile != challenge.profile
                or verdict.cvm_id != challenge.cvm_id
                or verdict.deployment_intent_sha256
                != challenge.deployment_intent_sha256
                or verdict.release_authority_sha256
                != challenge.release_authority_sha256
                or verdict.ceremony_nonce != challenge.ceremony_nonce
                or verdict.measurement_policy_sha256
                != challenge.measurement_policy_sha256
                or verdict.challenge_id != challenge.challenge_id
                or verdict.challenge_digest != challenge.challenge_digest
                or verdict.challenge_issued_at != challenge.issued_at
                or verdict.challenge_expires_at != challenge.expires_at
                or verdict.quote_hash != attestation.quote_hash
                or verdict.report_data != attestation.report_data
                or verdict.compose_hash != attestation.compose_hash
                or verdict.app_id != attestation.app_id
                or verdict.os_image_hash != attestation.os_image_hash
                or verdict.signer_address != attestation.metering_verifier
                or verdict.chain_id != attestation.chain_id
                or verdict.contract_address != attestation.vault_address
                or verdict.issued_at < challenge.issued_at
                or verdict.issued_at >= challenge.expires_at
                or verdict.issued_at > checked_at + 5
                or verdict.expires_at <= checked_at
                or verdict.expires_at <= verdict.issued_at
            ):
                raise SignerUnavailable
            recovered = Account.recover_message(
                encode_defunct(hexstr=compute_qvl_verdict_digest(verdict)),
                signature=bytes.fromhex(verdict.verifier_signature[2:]),
            )
            if _address(recovered) != self.verifier_address:
                raise SignerUnavailable
            compute_fields = (
                verdict.qvl_compute_attestation_evidence_hash,
                verdict.qvl_compute_authorization_expiry,
                verdict.qvl_compute_authorization_digest,
                verdict.qvl_compute_authorization_signature,
            )
            if authorization is None:
                if any(value is not None for value in compute_fields):
                    raise SignerUnavailable
            else:
                from .evm import compute_metering_qvl_receipt_digest
                from .signing import validate_canonical_signature

                expected_evidence = compute_metering_attestation_evidence_hash(attestation)
                expected_digest = compute_metering_qvl_receipt_digest(
                    chain_id=attestation.chain_id,
                    vault_address=attestation.vault_address,
                    project_id=authorization.project_id,
                    job_id=authorization.job_id,
                    user=authorization.user,
                    asset=authorization.asset,
                    authorization_nonce=int(authorization.authorization_nonce),
                    max_asset_debit=int(authorization.max_asset_debit),
                    actual_asset_debit=int(authorization.actual_asset_debit),
                    authorization_expiry=authorization.authorization_expiry,
                    rate_policy_commitment=authorization.rate_policy_commitment,
                    workload_commitment=authorization.workload_commitment,
                    manifest_commitment=authorization.manifest_commitment,
                    dispatch_intent_commitment=authorization.dispatch_intent_commitment,
                    tee_identity=authorization.tee_identity,
                    compose_hash=authorization.compose_hash,
                    start_commitment=authorization.start_commitment,
                    billable_compute_units=int(authorization.billable_compute_units),
                    usage_started_at=authorization.usage_started_at,
                    usage_ended_at=authorization.usage_ended_at,
                    usage_commitment=authorization.usage_commitment,
                    metering_policy_set_hash=authorization.metering_policy_set_hash,
                    attestation_evidence_hash=authorization.attestation_evidence_hash,
                    receipt_expiry=authorization.receipt_expiry,
                )
                if (
                    authorization.attestation_evidence_hash != expected_evidence
                    or verdict.qvl_compute_attestation_evidence_hash != expected_evidence
                    or verdict.qvl_compute_authorization_expiry
                    != authorization.receipt_expiry
                    or verdict.qvl_compute_authorization_expiry
                    > challenge.expires_at
                    or verdict.qvl_compute_authorization_digest != expected_digest
                    or verdict.qvl_compute_authorization_signature is None
                ):
                    raise SignerUnavailable
                validate_canonical_signature(
                    verdict.qvl_compute_authorization_signature
                )
                raw_recovered = Account._recover_hash(
                    bytes.fromhex(expected_digest[2:]),
                    signature=bytes.fromhex(
                        verdict.qvl_compute_authorization_signature[2:]
                    ),
                )
                if _address(raw_recovered) != self.verifier_address:
                    raise SignerUnavailable
            return verdict
        except SignerUnavailable:
            raise
        except Exception:
            raise SignerUnavailable from None
