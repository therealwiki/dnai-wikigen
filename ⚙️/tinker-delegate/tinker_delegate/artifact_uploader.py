"""Client-side attestation-gated artifact uploader."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

from tinker_delegate.artifacts import artifact_keccak256, encrypt_artifact_payload, zero_buffer
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


@dataclass(frozen=True)
class ArtifactUploadResult:
    """Bounded result from an encrypted artifact upload attempt."""

    deal_id: str
    artifact_hash: str
    size: int
    status_code: int
    response: dict[str, Any]


def _endpoint(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def verify_artifact_attestation(
    attestation: dict[str, Any],
    policy: ArtifactUploadPolicy,
) -> str:
    """Verify the attestation envelope before using its encryption key."""
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
    client: httpx.Client | None = None,
) -> ArtifactUploadResult:
    """Fetch attestation, verify it, encrypt artifact bytes, and upload."""
    owns_client = client is None
    http = client or httpx.Client(timeout=30.0)
    try:
        attestation_response = http.get(attestation_endpoint(base_url, policy.context))
        attestation_response.raise_for_status()
        tee_public_key = verify_artifact_attestation(attestation_response.json(), policy)

        artifact_hash = artifact_keccak256(artifact)
        encrypted = encrypt_artifact_payload(
            artifact,
            tee_public_key,
            deal_id=deal_id,
            artifact_hash=artifact_hash,
        )

        upload_response = http.post(
            _endpoint(base_url, f"/deal/{deal_id}/artifact/encrypted"),
            json=encrypted,
        )
        upload_response.raise_for_status()
        return ArtifactUploadResult(
            deal_id=deal_id,
            artifact_hash=artifact_hash,
            size=len(artifact),
            status_code=upload_response.status_code,
            response=upload_response.json(),
        )
    finally:
        if owns_client:
            http.close()


def upload_artifact_file(
    base_url: str,
    deal_id: str,
    artifact_path: str | Path,
    policy: ArtifactUploadPolicy,
) -> ArtifactUploadResult:
    """Read an artifact file into memory, upload it encrypted, then zero it."""
    artifact = bytearray(Path(artifact_path).read_bytes())
    try:
        return upload_artifact_bytes(base_url, deal_id, artifact, policy)
    finally:
        zero_buffer(artifact)
