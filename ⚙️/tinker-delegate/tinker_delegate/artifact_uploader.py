"""Client-side attestation-gated artifact uploader.

The shared envelope checker is not an Intel DCAP/QVL implementation. Because
the service never self-asserts verification, deployed-TDX uploads remain blocked
until a separately authenticated independent verifier verdict is integrated.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

from tinker_delegate.artifacts import (
    ARTIFACT_ENVELOPE_SCHEME,
    ARTIFACT_PADDING_PROFILE,
    BASE_SEPOLIA_CHAIN_ID,
    ARTIFACT_COMMITMENT_SCHEME,
    encrypt_artifact_payload,
    normalize_artifact_commitment_secret,
    normalize_artifact_hash,
    verify_artifact_commitment,
    zero_buffer,
)
from tinker_delegate.attestation_verifier import (
    AttestationPolicy,
    AttestationVerificationError,
    attestation_endpoint,
    verify_attestation_envelope,
)


@dataclass(frozen=True)
class ArtifactUploadPolicy:
    """Client-side policy for accepting a TEE artifact-ingress key."""

    expected_compose_hash: str = ""
    expected_app_id: str = ""
    expected_os_image_hash: str = ""
    context: str = "artifact"
    allow_local: bool = False
    max_age_seconds: float = 60.0
    chain_id: int = BASE_SEPOLIA_CHAIN_ID
    diligence_room_address: str = ""
    evaluator_policy_commitment: str = ""


@dataclass(frozen=True)
class ArtifactUploadResult:
    """Bounded result from an encrypted artifact upload attempt."""

    deal_id: str
    artifact_hash: str
    ciphertext_sha256: str
    status_code: int
    response: dict[str, Any]


class ArtifactUploadAuthenticationError(ValueError):
    """Raised before reading/sending an artifact when seller auth is absent."""


@dataclass
class ArtifactCommitmentReceipt:
    """Private v2 recovery material; callers must zero ``commitment_secret``."""

    artifact_hash: str
    commitment_secret: bytearray


def load_artifact_commitment_receipt(path: str | Path) -> ArtifactCommitmentReceipt:
    """Load the exact private receipt emitted by the v2 commitment client."""
    receipt_path = Path(path)
    try:
        receipt_size = receipt_path.stat().st_size
    except OSError as exc:
        raise ValueError("artifact commitment receipt is not valid JSON") from exc
    if receipt_size > 2048:
        raise ValueError("artifact commitment receipt is too large")
    try:
        payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("artifact commitment receipt is not valid JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "scheme",
        "artifact_commitment",
        "commitment_secret",
    }:
        raise ValueError("artifact commitment receipt has an invalid shape")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != 2
        or not isinstance(payload["scheme"], str)
        or payload["scheme"] != ARTIFACT_COMMITMENT_SCHEME
    ):
        raise ValueError("artifact commitment receipt is not the required v2 scheme")
    lowercase_hex = set("0123456789abcdef")
    for field_name in ("artifact_commitment", "commitment_secret"):
        value = payload[field_name]
        if (
            not isinstance(value, str)
            or len(value) != 66
            or not value.startswith("0x")
            or any(char not in lowercase_hex for char in value[2:])
        ):
            raise ValueError(
                f"artifact commitment receipt {field_name} must be lowercase 0x bytes32 hex"
            )
    return ArtifactCommitmentReceipt(
        artifact_hash=normalize_artifact_hash(payload["artifact_commitment"]),
        commitment_secret=normalize_artifact_commitment_secret(payload["commitment_secret"]),
    )


def _endpoint(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _require_wallet_auth_token(wallet_auth_token: str) -> None:
    if not wallet_auth_token or any(char in wallet_auth_token for char in "\r\n"):
        raise ArtifactUploadAuthenticationError("seller wallet bearer token is required")


def verify_artifact_attestation(
    attestation: dict[str, Any],
    policy: ArtifactUploadPolicy,
) -> str:
    """Check the envelope before using a separately verified encryption key."""
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


def upload_artifact_bytes(
    base_url: str,
    deal_id: str,
    artifact: bytes | bytearray,
    policy: ArtifactUploadPolicy,
    *,
    artifact_hash: str,
    commitment_secret: bytes | bytearray | str,
    wallet_auth_token: str,
    client: httpx.Client | None = None,
) -> ArtifactUploadResult:
    """Verify v2 recovery material, attest, encrypt, and upload exact bytes."""
    _require_wallet_auth_token(wallet_auth_token)
    if not artifact:
        raise ValueError("artifact must not be empty")
    normalized_hash = normalize_artifact_hash(artifact_hash)
    verify_artifact_commitment(artifact, commitment_secret, normalized_hash)
    owns_client = client is None
    http = client or httpx.Client(timeout=30.0)
    try:
        attestation_response = http.get(attestation_endpoint(base_url, policy.context))
        attestation_response.raise_for_status()
        tee_public_key = verify_artifact_attestation(attestation_response.json(), policy)

        encrypted = encrypt_artifact_payload(
            artifact,
            tee_public_key,
            deal_id=deal_id,
            artifact_hash=normalized_hash,
            commitment_secret=commitment_secret,
            chain_id=policy.chain_id,
            diligence_room_address=policy.diligence_room_address,
            evaluator_policy_commitment=policy.evaluator_policy_commitment,
        )

        upload_response = http.post(
            _endpoint(base_url, f"/deal/{deal_id}/artifact/encrypted"),
            json=encrypted,
            headers={"Authorization": f"Bearer {wallet_auth_token}"},
        )
        upload_response.raise_for_status()
        response = upload_response.json()
        expected_fields = {
            "deal_id",
            "received",
            "ciphertext_sha256",
            "commitment_scheme",
            "envelope_scheme",
            "padding_profile",
            "exact_plaintext_size_egress",
        }
        if not isinstance(response, dict) or set(response) != expected_fields:
            raise ValueError("delegate returned a non-allowlisted artifact upload receipt")
        ciphertext_sha256 = "sha256:" + hashlib.sha256(
            bytes.fromhex(encrypted["ciphertext"])
        ).hexdigest()
        if (
            response.get("deal_id") != deal_id
            or response.get("received") is not True
            or response.get("ciphertext_sha256") != ciphertext_sha256
            or response.get("commitment_scheme") != ARTIFACT_COMMITMENT_SCHEME
            or response.get("envelope_scheme") != ARTIFACT_ENVELOPE_SCHEME
            or response.get("padding_profile") != ARTIFACT_PADDING_PROFILE
            or response.get("exact_plaintext_size_egress") is not False
        ):
            raise ValueError("delegate returned an invalid artifact upload receipt")
        return ArtifactUploadResult(
            deal_id=deal_id,
            artifact_hash=normalized_hash,
            ciphertext_sha256=ciphertext_sha256,
            status_code=upload_response.status_code,
            response=response,
        )
    finally:
        if owns_client:
            http.close()


def upload_artifact_file(
    base_url: str,
    deal_id: str,
    artifact_path: str | Path,
    commitment_receipt_path: str | Path,
    policy: ArtifactUploadPolicy,
    *,
    wallet_auth_token: str,
) -> ArtifactUploadResult:
    """Read artifact + private v2 receipt, upload, then zero mutable secrets."""
    # Authentication is checked before either private file is opened.
    _require_wallet_auth_token(wallet_auth_token)
    artifact = bytearray(Path(artifact_path).read_bytes())
    receipt: ArtifactCommitmentReceipt | None = None
    try:
        receipt = load_artifact_commitment_receipt(commitment_receipt_path)
        return upload_artifact_bytes(
            base_url,
            deal_id,
            artifact,
            policy,
            artifact_hash=receipt.artifact_hash,
            commitment_secret=receipt.commitment_secret,
            wallet_auth_token=wallet_auth_token,
        )
    finally:
        zero_buffer(artifact)
        if receipt is not None:
            zero_buffer(receipt.commitment_secret)
