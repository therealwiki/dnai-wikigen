"""Optional self-attestation for the independent QVL identity."""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Protocol

import dcap_qvl
from dstack_sdk import DstackClient

from .errors import VerifierUnavailable
from .models import (
    IdentityAttestationRequest,
    IdentityAttestationResponse,
    MAX_QUOTE_BYTES,
    MIN_QUOTE_BYTES,
)


IDENTITY_REPORT_DATA_DOMAIN = b"dnai-wikigen/qvl-identity-report-data/v3\x00"


class IdentityAttestor(Protocol):
    def attest(
        self,
        *,
        request: IdentityAttestationRequest,
        verifier_address: str,
        policy_hash: str,
    ) -> IdentityAttestationResponse:
        """Bind the current QVL CVM quote to its signer and canonical policy hash."""


def identity_report_data(
    *,
    request: IdentityAttestationRequest,
    verifier_address: str,
    policy_hash: str,
) -> bytes:
    payload = {
        "schema": "dnai.qvl-identity-report-data.v3",
        "service": "dnai-attestation-qvl",
        "context": "qvl-verifier-identity",
        "chain_id": request.chain_id,
        "domain": request.domain,
        "profile": request.profile,
        "cvm_id": request.cvm_id,
        "deployment_intent_sha256": request.deployment_intent_sha256,
        "release_authority_sha256": request.release_authority_sha256,
        "ceremony_nonce": request.ceremony_nonce,
        "measurement_policy_sha256": request.measurement_policy_sha256,
        "app_id": request.app_id,
        "compose_hash": request.compose_hash,
        "os_image_hash": request.os_image_hash,
        "verifier_address": verifier_address,
        "release_policy_hash": policy_hash,
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(IDENTITY_REPORT_DATA_DOMAIN + canonical).digest()


def _bare_sha256(value: str) -> str:
    normalized = value.lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    if not re.fullmatch(r"(?!0{64}$)[0-9a-f]{64}", normalized):
        raise VerifierUnavailable
    return normalized


def _app_id(value: object) -> str:
    normalized = str(value).lower().removeprefix("0x")
    if not re.fullmatch(r"(?!0{40}$)[0-9a-f]{40}", normalized):
        raise VerifierUnavailable
    return normalized


class DstackIdentityAttestor:
    def __init__(self) -> None:
        if any(
            os.environ.get(name, "").strip()
            for name in ("DSTACK_SIMULATOR_ENDPOINT", "TAPPD_SIMULATOR_ENDPOINT")
        ):
            raise VerifierUnavailable

    def attest(
        self,
        *,
        request: IdentityAttestationRequest,
        verifier_address: str,
        policy_hash: str,
    ) -> IdentityAttestationResponse:
        try:
            freshness = bytes.fromhex(request.challenge_digest.removeprefix("0x"))
        except (TypeError, ValueError) as exc:
            raise VerifierUnavailable from exc
        if len(freshness) != 32 or not any(freshness):
            raise VerifierUnavailable
        try:
            client = DstackClient()
            if not client.is_reachable():
                raise VerifierUnavailable
            info = client.info()
            app_id = _app_id(info.app_id)
            compose_hash = _bare_sha256(str(info.compose_hash))
            os_image_hash = _bare_sha256(str(info.os_image_hash))
            if (
                app_id != request.app_id
                or compose_hash != request.compose_hash
                or os_image_hash != request.os_image_hash
            ):
                raise VerifierUnavailable
            static_report_data = identity_report_data(
                request=request,
                verifier_address=verifier_address,
                policy_hash=policy_hash,
            )
            quote_report_data_request = static_report_data + freshness
            quote_result = client.get_quote(quote_report_data_request)
            quote_hex = str(quote_result.quote).lower().removeprefix("0x")
            if not re.fullmatch(r"[0-9a-f]+", quote_hex) or len(quote_hex) % 2:
                raise VerifierUnavailable
            raw_quote = bytes.fromhex(quote_hex)
            if len(raw_quote) < MIN_QUOTE_BYTES or len(raw_quote) > MAX_QUOTE_BYTES:
                raise VerifierUnavailable
            parsed = dcap_qvl.parse_quote(raw_quote)
            if not parsed.is_tdx() or parsed.quote_type() != "TDX":
                raise VerifierUnavailable
            quote_report_data = bytes(parsed.report.report_data)
            if quote_report_data != quote_report_data_request:
                raise VerifierUnavailable
            quote_value = "0x" + quote_hex
        except VerifierUnavailable:
            raise
        except Exception as exc:
            raise VerifierUnavailable from exc
        return IdentityAttestationResponse(
            schema="dnai.qvl-identity-attestation-response.v3",
            chain_id=request.chain_id,
            domain=request.domain,
            profile=request.profile,
            cvm_id=request.cvm_id,
            deployment_intent_sha256=request.deployment_intent_sha256,
            release_authority_sha256=request.release_authority_sha256,
            ceremony_nonce=request.ceremony_nonce,
            measurement_policy_sha256=request.measurement_policy_sha256,
            verifier_address=verifier_address,
            release_policy_hash=policy_hash,
            report_data="0x" + static_report_data.hex(),
            quote_report_data="0x" + quote_report_data_request.hex(),
            challenge_id=request.challenge_id,
            challenge_digest=request.challenge_digest,
            challenge_issued_at=request.issued_at,
            challenge_expires_at=request.expires_at,
            quote=quote_value,
            quote_hash="0x" + hashlib.sha256(raw_quote).hexdigest(),
            quote_size=len(raw_quote),
            app_id=app_id,
            compose_hash=compose_hash,
            os_image_hash=os_image_hash,
            raw_secret_egress=False,
        )
