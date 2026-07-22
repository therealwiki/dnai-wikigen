"""Strict client-side authentication for one-time independent-QVL challenges."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from eth_account import Account
from eth_account.messages import encode_defunct


CHALLENGE_REQUEST_SCHEMA = "dnai.attestation-qvl-challenge-request.v2"
CHALLENGE_SCHEMA = "dnai.attestation-qvl-challenge.v2"
VERIFICATION_REQUEST_SCHEMA = "dnai.independent-tdx-verification-request.v2"
CHALLENGE_DOMAIN = b"dnai-wikigen/attestation-qvl/challenge/v2\x00"
QVL_PROFILES = frozenset(
    {
        "diligence",
        "arena",
        "execution_policy_anchor_writer",
        "compute_metering",
        "compute_workload",
        "email_oracle_kms_restart",
    }
)
MAX_CHALLENGE_TTL_SECONDS = 120
_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^0x[0-9a-f]{130}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_CVM_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{7,127}$")
CVM_DOMAINS = frozenset(
    {
        "main_runtime_cvm",
        "diligence_qvl_cvm",
        "arena_qvl_cvm",
        "anchor_writer_qvl_cvm",
        "compute_workload_qvl_cvm",
        "compute_metering_qvl_cvm",
        "independent_metering_cvm",
    }
)


class QvlFreshnessError(ValueError):
    """Fixed internal failure; callers map it to their bounded public code."""


def _address(value: Any) -> str:
    if not isinstance(value, str):
        raise QvlFreshnessError
    normalized = value.lower()
    if not _ADDRESS.fullmatch(normalized) or int(normalized[2:], 16) == 0:
        raise QvlFreshnessError
    return normalized


def _bytes32(value: Any) -> str:
    if not isinstance(value, str):
        raise QvlFreshnessError
    normalized = value.lower()
    if not _BYTES32.fullmatch(normalized) or int(normalized[2:], 16) == 0:
        raise QvlFreshnessError
    return normalized


def _int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise QvlFreshnessError
    return value


def _chain_id(value: Any) -> int:
    parsed = _int(value)
    if parsed < 1 or parsed > 2**63 - 1:
        raise QvlFreshnessError
    return parsed


def _sha256(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not _SHA256.fullmatch(value)
        or int(value[7:], 16) == 0
    ):
        raise QvlFreshnessError
    return value


def _cvm_id(value: Any) -> str:
    if not isinstance(value, str) or not _CVM_ID.fullmatch(value):
        raise QvlFreshnessError
    return value


def _domain(value: Any) -> str:
    if not isinstance(value, str) or value not in CVM_DOMAINS:
        raise QvlFreshnessError
    return value


@dataclass(frozen=True)
class QvlChallenge:
    schema: str
    chain_id: int
    domain: str
    profile: str
    cvm_id: str
    deployment_intent_sha256: str
    release_authority_sha256: str
    ceremony_nonce: str
    measurement_policy_sha256: str
    release_policy_hash: str
    challenge_id: str
    challenge_digest: str
    issued_at: int
    expires_at: int
    verifier_address: str
    verifier_signature: str

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "chain_id": self.chain_id,
            "domain": self.domain,
            "profile": self.profile,
            "cvm_id": self.cvm_id,
            "deployment_intent_sha256": self.deployment_intent_sha256,
            "release_authority_sha256": self.release_authority_sha256,
            "ceremony_nonce": self.ceremony_nonce,
            "measurement_policy_sha256": self.measurement_policy_sha256,
            "release_policy_hash": self.release_policy_hash,
            "challenge_id": self.challenge_id,
            "challenge_digest": self.challenge_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "verifier_address": self.verifier_address,
            "verifier_signature": self.verifier_signature,
        }

    @property
    def digest_bytes(self) -> bytes:
        return bytes.fromhex(self.challenge_digest[2:])


def qvl_challenge_from_public_dict(payload: Mapping[str, Any]) -> QvlChallenge:
    fields = {
        "schema",
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
        "issued_at",
        "expires_at",
        "verifier_address",
        "verifier_signature",
    }
    if not isinstance(payload, Mapping) or set(payload) != fields:
        raise QvlFreshnessError
    profile = payload["profile"]
    signature = payload["verifier_signature"]
    if (
        payload["schema"] != CHALLENGE_SCHEMA
        or not isinstance(profile, str)
        or profile not in QVL_PROFILES
        or not isinstance(signature, str)
        or not _SIGNATURE.fullmatch(signature)
    ):
        raise QvlFreshnessError
    challenge = QvlChallenge(
        schema=CHALLENGE_SCHEMA,
        chain_id=_chain_id(payload["chain_id"]),
        domain=_domain(payload["domain"]),
        profile=profile,
        cvm_id=_cvm_id(payload["cvm_id"]),
        deployment_intent_sha256=_sha256(payload["deployment_intent_sha256"]),
        release_authority_sha256=_sha256(payload["release_authority_sha256"]),
        ceremony_nonce=_bytes32(payload["ceremony_nonce"]),
        measurement_policy_sha256=_sha256(payload["measurement_policy_sha256"]),
        release_policy_hash=_bytes32(payload["release_policy_hash"]),
        challenge_id=_bytes32(payload["challenge_id"]),
        challenge_digest=_bytes32(payload["challenge_digest"]),
        issued_at=_int(payload["issued_at"]),
        expires_at=_int(payload["expires_at"]),
        verifier_address=_address(payload["verifier_address"]),
        verifier_signature=signature,
    )
    if challenge.expires_at <= challenge.issued_at:
        raise QvlFreshnessError
    return challenge


def qvl_challenge_digest(challenge: QvlChallenge) -> str:
    payload = challenge.to_public_dict()
    payload.pop("challenge_digest")
    payload.pop("verifier_signature")
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return "0x" + hashlib.sha256(CHALLENGE_DOMAIN + canonical).hexdigest()


def authenticate_qvl_challenge(
    challenge: QvlChallenge,
    *,
    expected_profile: str,
    expected_chain_id: int,
    expected_domain: str,
    expected_cvm_id: str,
    expected_deployment_intent_sha256: str,
    expected_release_authority_sha256: str,
    expected_ceremony_nonce: str,
    expected_measurement_policy_sha256: str,
    trusted_verifier_addresses: Sequence[str],
    expected_policy_hash: str = "",
    now: int | None = None,
) -> QvlChallenge:
    checked_at = int(time.time() if now is None else now)
    trusted = {_address(value) for value in trusted_verifier_addresses}
    if (
        expected_profile not in QVL_PROFILES
        or challenge.chain_id != _chain_id(expected_chain_id)
        or challenge.domain != _domain(expected_domain)
        or challenge.profile != expected_profile
        or challenge.cvm_id != _cvm_id(expected_cvm_id)
        or challenge.deployment_intent_sha256
        != _sha256(expected_deployment_intent_sha256)
        or challenge.release_authority_sha256
        != _sha256(expected_release_authority_sha256)
        or challenge.ceremony_nonce != _bytes32(expected_ceremony_nonce)
        or challenge.measurement_policy_sha256
        != _sha256(expected_measurement_policy_sha256)
        or not trusted
        or challenge.verifier_address not in trusted
        or challenge.challenge_digest != qvl_challenge_digest(challenge)
        or challenge.issued_at > checked_at + 5
        or challenge.expires_at <= checked_at
        or challenge.expires_at - challenge.issued_at > MAX_CHALLENGE_TTL_SECONDS
    ):
        raise QvlFreshnessError
    if expected_policy_hash and challenge.release_policy_hash != _bytes32(
        expected_policy_hash
    ):
        raise QvlFreshnessError
    try:
        recovered = Account.recover_message(
            encode_defunct(hexstr=challenge.challenge_digest),
            signature=bytes.fromhex(challenge.verifier_signature[2:]),
        )
    except Exception:
        raise QvlFreshnessError from None
    if _address(recovered) != challenge.verifier_address:
        raise QvlFreshnessError
    return challenge


def challenge_bound_report_data(static_report_data: str, challenge: QvlChallenge) -> str:
    return _bytes32(static_report_data) + challenge.challenge_digest[2:]


def challenge_request(
    profile: str,
    *,
    chain_id: int,
    domain: str,
    cvm_id: str,
    deployment_intent_sha256: str,
    release_authority_sha256: str,
    ceremony_nonce: str,
    measurement_policy_sha256: str,
) -> dict[str, str | int]:
    if profile not in QVL_PROFILES:
        raise QvlFreshnessError
    return {
        "schema": CHALLENGE_REQUEST_SCHEMA,
        "chain_id": _chain_id(chain_id),
        "domain": _domain(domain),
        "profile": profile,
        "cvm_id": _cvm_id(cvm_id),
        "deployment_intent_sha256": _sha256(deployment_intent_sha256),
        "release_authority_sha256": _sha256(release_authority_sha256),
        "ceremony_nonce": _bytes32(ceremony_nonce),
        "measurement_policy_sha256": _sha256(measurement_policy_sha256),
    }
