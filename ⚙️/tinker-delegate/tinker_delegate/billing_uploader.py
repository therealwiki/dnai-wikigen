"""Client-side attestation-gated encrypted billing update helper."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any
from urllib.parse import urljoin

import httpx

from tinker_delegate.attestation_verifier import (
    AttestationPolicy,
    attestation_endpoint,
    verify_attestation_envelope,
)
from tinker_delegate.crypto import CARD_HKDF_INFO, encrypt_for_tee


@dataclass(frozen=True)
class BillingCardUploadPolicy:
    """Client-side policy for accepting a TEE billing-ingress key."""

    expected_compose_hash: str = ""
    expected_app_id: str = ""
    expected_os_image_hash: str = ""
    context: str = "billing"
    allow_local: bool = False
    max_age_seconds: float = 60.0
    auth_token: str = ""
    request_timeout_seconds: float = 180.0


@dataclass(frozen=True)
class BillingCardUploadResult:
    """Bounded result from an encrypted card update attempt."""

    status_code: int
    response: dict[str, Any]


def _endpoint(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def verify_billing_attestation(
    attestation: dict[str, Any],
    policy: BillingCardUploadPolicy,
) -> str:
    """Verify the billing attestation envelope before using its encryption key."""
    result = verify_attestation_envelope(
        attestation,
        AttestationPolicy(
            expected_compose_hash=policy.expected_compose_hash,
            expected_app_id=policy.expected_app_id,
            expected_os_image_hash=policy.expected_os_image_hash,
            context=policy.context,
            allow_local=policy.allow_local,
            max_age_seconds=policy.max_age_seconds,
        ),
    )
    return result.encryption_public_key


def encrypt_billing_card_payload(card_data: dict[str, Any], tee_public_key_hex: str) -> dict[str, str]:
    """Encrypt card JSON to a TEE billing key and wipe the local plaintext buffer."""
    plaintext = bytearray(
        json.dumps(
            card_data,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    try:
        tee_public_key = bytes.fromhex(tee_public_key_hex)
        encrypted = encrypt_for_tee(plaintext, tee_public_key, info=CARD_HKDF_INFO)
        return encrypted.to_hex()
    finally:
        for index in range(len(plaintext)):
            plaintext[index] = 0


def upload_billing_card_payload(
    base_url: str,
    card_data: dict[str, Any],
    policy: BillingCardUploadPolicy,
    *,
    client: httpx.Client | None = None,
) -> BillingCardUploadResult:
    """Fetch attestation, verify it, encrypt card data, and post to billing."""
    owns_client = client is None
    http = client or httpx.Client(timeout=policy.request_timeout_seconds)
    try:
        attestation_response = http.get(attestation_endpoint(base_url, policy.context))
        attestation_response.raise_for_status()
        tee_public_key = verify_billing_attestation(attestation_response.json(), policy)

        encrypted = encrypt_billing_card_payload(card_data, tee_public_key)
        headers = {"Authorization": f"Bearer {policy.auth_token}"} if policy.auth_token else None
        update_response = http.post(
            _endpoint(base_url, "/billing/card/encrypted"),
            json=encrypted,
            headers=headers,
        )
        update_response.raise_for_status()
        return BillingCardUploadResult(
            status_code=update_response.status_code,
            response=update_response.json(),
        )
    finally:
        if owns_client:
            http.close()
