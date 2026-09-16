"""Bounded usage commitments and EIP-191 execution-TEE authentication."""

from __future__ import annotations

import hashlib

from eth_account import Account
from eth_account.messages import encode_defunct

from .errors import SignerUnavailable, UsageRejected
from .models import ComputeUsageEnvelope, MeteringRequest
from .policy import canonical_json_bytes
from .signing import normalize_address, validate_canonical_signature


USAGE_DOMAIN = b"dnai-wikigen/compute-usage/v1\x00"
REQUEST_DOMAIN = b"dnai-wikigen/compute-metering-request/v1\x00"


def canonical_usage_claims(usage: ComputeUsageEnvelope) -> dict[str, object]:
    payload = usage.model_dump(mode="json", by_alias=True)
    payload.pop("usage_commitment", None)
    payload.pop("tee_signature", None)
    return payload


def compute_usage_commitment(usage: ComputeUsageEnvelope) -> str:
    encoded = canonical_json_bytes(canonical_usage_claims(usage))
    return "0x" + hashlib.sha256(USAGE_DOMAIN + encoded).hexdigest()


def verify_usage_envelope(usage: ComputeUsageEnvelope, *, expected_tee_identity: str) -> None:
    if usage.tee_identity != expected_tee_identity:
        raise UsageRejected
    expected = compute_usage_commitment(usage)
    if expected != usage.usage_commitment:
        raise UsageRejected
    try:
        raw = validate_canonical_signature(usage.tee_signature)
        recovered = Account.recover_message(
            encode_defunct(hexstr=usage.usage_commitment),
            signature=raw,
        )
        if normalize_address(recovered) != expected_tee_identity:
            raise UsageRejected
    except UsageRejected:
        raise
    except Exception as exc:
        raise UsageRejected from exc


def semantic_request_hash(request: MeteringRequest) -> str:
    payload = request.model_dump(mode="json", by_alias=True)
    usage = dict(payload["usage"])
    usage.pop("tee_signature", None)
    payload["usage"] = usage
    return "0x" + hashlib.sha256(REQUEST_DOMAIN + canonical_json_bytes(payload)).hexdigest()
