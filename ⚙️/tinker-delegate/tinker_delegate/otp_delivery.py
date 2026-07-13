"""Off-chain commitment for the on-chain OTP-delivery audit trail.

`EmailOracleAuth.recordOtpDelivery(consumerAppId, deliveryHash)` writes a
dispute-resolution audit event whose `deliveryHash` is an off-chain commitment to
the delivery context — never the raw OTP. This module is the single place that
turns a delivery into that commitment: it hashes the OTP immediately and binds it
with the consumer app id and request id under a domain tag, so the value handed to
the chain (and everything this module returns) is a hash, never the code.

    deliveryHash = keccak256("dnai-otp-delivery:v1" ‖ consumerAppId ‖ requestId ‖ keccak256(otp))

The receipt is bounded: consumer/request are hashed, the OTP appears only as a
hash, and `raw_secret_egress` is false.
"""
from __future__ import annotations

import hashlib
from typing import Any

from eth_hash.auto import keccak

_DOMAIN = b"dnai-otp-delivery:v1"


class OtpDeliveryError(ValueError):
    """Raised when a delivery commitment cannot be built from the inputs."""


def _b(value: str) -> bytes:
    return value.encode("utf-8")


def compute_delivery_hash(consumer_app_id: str, request_id: str, otp: str) -> str:
    """Return the 0x keccak256 delivery commitment. The OTP is hashed immediately.

    The raw OTP is never returned or stored — only ``keccak256(otp)`` participates
    in the commitment, so the caller can hand the result straight to
    ``recordOtpDelivery`` without the code touching the chain.
    """

    if not consumer_app_id:
        raise OtpDeliveryError("consumer_app_id is required")
    if not request_id:
        raise OtpDeliveryError("request_id is required")
    if not otp:
        raise OtpDeliveryError("otp is required")

    otp_hash = keccak(_b(otp))
    # Length-prefix each field (not delimiter-join): the raw 32-byte otp_hash can
    # contain any byte, so a delimiter could otherwise collide two distinct
    # (consumer, request, otp) tuples onto one commitment.
    preimage = _DOMAIN + b"".join(
        len(part).to_bytes(4, "big") + part
        for part in (_b(consumer_app_id), _b(request_id), otp_hash)
    )
    return "0x" + keccak(preimage).hex()


def _sha256_hex(value: str, *, prefix: str) -> str:
    return "0x" + hashlib.sha256(f"{prefix}:{value}".encode("utf-8")).hexdigest()


def otp_delivery_receipt(consumer_app_id: str, request_id: str, otp: str) -> dict[str, Any]:
    """Bounded receipt for a single OTP delivery — hashes only, no raw OTP.

    ``delivery_hash`` is the value to pass to ``recordOtpDelivery``; the consumer
    and request identifiers are additionally hashed so the receipt itself can be
    logged without exposing them.
    """

    delivery_hash = compute_delivery_hash(consumer_app_id, request_id, otp)
    return {
        "kind": "otp_delivery_receipt",
        "consumer_app_id_hash": _sha256_hex(consumer_app_id, prefix="consumer_app_id"),
        "request_id_hash": _sha256_hex(request_id, prefix="request_id"),
        "delivery_hash": delivery_hash,
        "otp_returned": False,
        "raw_secret_egress": False,
    }
