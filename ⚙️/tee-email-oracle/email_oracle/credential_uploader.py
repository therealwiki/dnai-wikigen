"""Client-side attestation-gated email credential provisioning helper."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import time
from typing import Any
from urllib.parse import urlencode, urljoin

import httpx

from email_oracle.crypto import (
    ORACLE_CREDENTIALS_HKDF_INFO,
    attestation_report_data,
    encrypt_for_tee,
)


class CredentialUploadError(RuntimeError):
    """Raised when credential provisioning must fail closed."""


@dataclass(frozen=True)
class CredentialUploadPolicy:
    """Client-side policy for accepting a TEE credential-ingress key."""

    expected_compose_hash: str = ""
    expected_app_id: str = ""
    expected_os_image_hash: str = ""
    context: str = "oracle-credentials"
    allow_local: bool = False
    max_age_seconds: float = 60.0


@dataclass(frozen=True)
class CredentialUploadResult:
    """Bounded result from encrypted credential provisioning."""

    status_code: int
    response: dict[str, Any]


def _endpoint(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def attestation_endpoint(base_url: str, context: str) -> str:
    return _endpoint(base_url, "/attestation") + "?" + urlencode({"context": context})


def _hex_bytes(value: object, field: str, *, expected_len: int | None = None) -> bytes:
    if not isinstance(value, str) or not value:
        raise CredentialUploadError(f"{field} is missing")
    raw = value[2:] if value.startswith(("0x", "0X")) else value
    try:
        decoded = bytes.fromhex(raw)
    except ValueError as exc:
        raise CredentialUploadError(f"{field} must be hex") from exc
    if expected_len is not None and len(decoded) != expected_len:
        raise CredentialUploadError(f"{field} must be {expected_len} bytes")
    if expected_len is None and not decoded:
        raise CredentialUploadError(f"{field} must be non-empty")
    return decoded


def verify_credential_attestation(
    attestation: dict[str, Any],
    policy: CredentialUploadPolicy,
    *,
    fetched_at: float | None = None,
    now: float | None = None,
) -> str:
    """Verify the oracle credential attestation before using its public key."""
    checked_at = time.time() if now is None else now
    evidence_time = checked_at if fetched_at is None else fetched_at
    if policy.max_age_seconds >= 0 and checked_at - evidence_time > policy.max_age_seconds:
        raise CredentialUploadError("attestation evidence is stale")

    mode = attestation.get("mode")
    if mode == "local":
        if not policy.allow_local:
            raise CredentialUploadError("local attestation is not allowed")
    elif mode == "tdx":
        if attestation.get("verified") is False:
            raise CredentialUploadError("attestation endpoint reported verification failure")
        _hex_bytes(attestation.get("tdx_quote"), "tdx_quote")
        if not policy.expected_compose_hash:
            raise CredentialUploadError("expected compose hash is required for tdx mode")
        if attestation.get("compose_hash") != policy.expected_compose_hash:
            raise CredentialUploadError("compose hash mismatch")
        if policy.expected_app_id and attestation.get("app_id") != policy.expected_app_id:
            raise CredentialUploadError("app id mismatch")
        if (
            policy.expected_os_image_hash
            and attestation.get("os_image_hash") != policy.expected_os_image_hash
        ):
            raise CredentialUploadError("OS image hash mismatch")
    else:
        raise CredentialUploadError("attestation mode must be tdx")

    if attestation.get("report_context") != policy.context:
        raise CredentialUploadError("report context mismatch")

    public_key = _hex_bytes(
        attestation.get("encryption_public_key"),
        "encryption_public_key",
        expected_len=32,
    )
    report_data = _hex_bytes(attestation.get("report_data"), "report_data", expected_len=32)
    expected_report_data = attestation_report_data(
        "tee-email-oracle",
        policy.context,
        public_key,
    )
    if report_data != expected_report_data:
        raise CredentialUploadError("report data does not bind the encryption key")

    quote_report_data_value = attestation.get("quote_report_data")
    if quote_report_data_value:
        quote_report_data = _hex_bytes(quote_report_data_value, "quote_report_data")
        if len(quote_report_data) == 64:
            if quote_report_data[:32] != report_data or quote_report_data[32:] != b"\x00" * 32:
                raise CredentialUploadError("quote report data mismatch")
        elif len(quote_report_data) != 32:
            raise CredentialUploadError("quote_report_data must be 32 or 64 bytes")
        elif quote_report_data != report_data:
            raise CredentialUploadError("quote report data mismatch")

    return public_key.hex()


def encrypt_credentials_payload(credentials: dict[str, str], tee_public_key_hex: str) -> dict[str, str]:
    """Encrypt mailbox credentials to the oracle credential-ingress key."""
    plaintext = bytearray(
        json.dumps(credentials, sort_keys=True, separators=(",", ":")).encode()
    )
    try:
        encrypted = encrypt_for_tee(
            plaintext,
            bytes.fromhex(tee_public_key_hex),
            info=ORACLE_CREDENTIALS_HKDF_INFO,
            associated_data=b"tee-email-oracle:credentials:v1",
        )
        return encrypted.to_hex()
    finally:
        for index in range(len(plaintext)):
            plaintext[index] = 0


def upload_credentials_payload(
    base_url: str,
    credentials: dict[str, str],
    token: str,
    policy: CredentialUploadPolicy,
    *,
    client: httpx.Client | None = None,
) -> CredentialUploadResult:
    """Fetch attestation, verify it, encrypt credentials, and post to the oracle."""
    if not token:
        raise CredentialUploadError("credential provisioning token is required")
    owns_client = client is None
    http = client or httpx.Client(timeout=30.0)
    fetched_at = time.time()
    try:
        attestation_response = http.get(attestation_endpoint(base_url, policy.context))
        attestation_response.raise_for_status()
        tee_public_key = verify_credential_attestation(
            attestation_response.json(),
            policy,
            fetched_at=fetched_at,
        )
        encrypted = encrypt_credentials_payload(credentials, tee_public_key)
        response = http.post(
            _endpoint(base_url, "/credentials/encrypted"),
            headers={"Authorization": f"Bearer {token}"},
            json=encrypted,
        )
        response.raise_for_status()
        return CredentialUploadResult(
            status_code=response.status_code,
            response=response.json(),
        )
    finally:
        if owns_client:
            http.close()


def forbidden_credential_values(credentials: dict[str, str], token: str) -> tuple[str, ...]:
    """Return submitted secret values that must not appear in bounded output."""
    return tuple(
        value
        for value in (
            credentials.get("username", ""),
            credentials.get("domain", ""),
            credentials.get("password", ""),
            token,
        )
        if value
    )


def credential_hashes(credentials: dict[str, str]) -> dict[str, str]:
    """Bounded local hashes useful for operator-side audit without raw credentials."""
    email = f"{credentials.get('username', '')}@{credentials.get('domain', '')}"
    return {
        "credential_email_hash": hashlib.sha256(email.encode("utf-8")).hexdigest(),
        "credential_domain_hash": hashlib.sha256(
            credentials.get("domain", "").encode("utf-8")
        ).hexdigest(),
    }
