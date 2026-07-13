"""Laptop-side verifier tying a CVM attestation to digest-pinned compose input."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from tinker_delegate.attestation_verifier import (
    AttestationPolicy,
    AttestationVerificationError,
    fetch_and_verify_attestation,
)
from tinker_delegate.compose_hash import (
    ComposeHashError,
    ImageDigest,
    verify_compose_hash,
)


class CvmAttestationError(RuntimeError):
    """Raised when a live CVM cannot be tied to the expected deployment inputs."""


@dataclass(frozen=True)
class CvmAttestationPolicy:
    """Expected local compose and live attestation identity."""

    api_url: str
    compose_path: Path
    env_files: tuple[Path, ...] = ()
    allowed_env_file: Path | None = None
    allowed_envs: tuple[str, ...] = ()
    context: str = "artifact"
    expected_compose_hash: str = ""
    expected_attested_compose_hash: str = ""
    expected_app_id: str = ""
    expected_os_image_hash: str = ""
    required_images: tuple[str, ...] = ()
    required_image_digests: tuple[str, ...] = ()
    allow_local: bool = False
    allow_tags: bool = False
    phala_raw_compose: bool = False
    max_age_seconds: float = 60.0


@dataclass(frozen=True)
class CvmAttestationBundle:
    """Bounded public verification bundle safe to persist in operator logs."""

    api_url: str
    context: str
    mode: str
    compose_hash: str
    attested_compose_hash: str
    rendered_compose_sha256: str
    images: tuple[ImageDigest, ...]
    app_id: str
    os_image_hash: str
    report_data: str
    encryption_public_key: str
    quote_size: int
    fetched_at: float
    quote_verification: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "api_url": self.api_url,
            "context": self.context,
            "mode": self.mode,
            "compose_hash": self.compose_hash,
            "attested_compose_hash": self.attested_compose_hash,
            "rendered_compose_sha256": self.rendered_compose_sha256,
            "images": [
                {"service": image.service, "image": image.image}
                for image in self.images
            ],
            "app_id": self.app_id,
            "os_image_hash": self.os_image_hash,
            "report_data": self.report_data,
            "encryption_public_key": self.encryption_public_key,
            "quote_size": self.quote_size,
            "fetched_at": self.fetched_at,
            "quote_verification": self.quote_verification,
        }


def _normalize_digest(value: str) -> str:
    digest = value.strip().lower()
    if digest.startswith("sha256:"):
        digest = digest[len("sha256:") :]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise CvmAttestationError(f"invalid sha256 digest requirement: {value}")
    return digest


def _image_digest(image: str) -> str | None:
    marker = "@sha256:"
    if marker not in image:
        return None
    return image.rsplit(marker, 1)[1].strip().lower()


def _require_images(
    images: tuple[ImageDigest, ...],
    *,
    required_images: tuple[str, ...],
    required_image_digests: tuple[str, ...],
) -> None:
    image_refs = {image.image for image in images}
    missing_refs = [image for image in required_images if image not in image_refs]
    if missing_refs:
        raise CvmAttestationError("missing required image reference: " + ", ".join(missing_refs))

    image_digests = {
        digest
        for image in images
        for digest in [_image_digest(image.image)]
        if digest is not None
    }
    missing_digests = [
        digest
        for digest in (_normalize_digest(value) for value in required_image_digests)
        if digest not in image_digests
    ]
    if missing_digests:
        raise CvmAttestationError(
            "missing required image digest: "
            + ", ".join("sha256:" + digest for digest in missing_digests)
        )


def verify_cvm_attestation(policy: CvmAttestationPolicy) -> CvmAttestationBundle:
    """Verify digest-pinned local compose input and a live CVM attestation."""
    try:
        compose = verify_compose_hash(
            policy.compose_path,
            env_files=list(policy.env_files),
            expected_hash=policy.expected_compose_hash,
            allowed_env_file=policy.allowed_env_file,
            allowed_envs=list(policy.allowed_envs),
            phala_raw_compose=policy.phala_raw_compose,
            allow_tags=policy.allow_tags,
        )
    except ComposeHashError as exc:
        raise CvmAttestationError(str(exc)) from exc

    _require_images(
        compose.images,
        required_images=policy.required_images,
        required_image_digests=policy.required_image_digests,
    )

    attestation_policy = AttestationPolicy(
        expected_compose_hash=policy.expected_attested_compose_hash or compose.compose_hash,
        expected_app_id=policy.expected_app_id,
        expected_os_image_hash=policy.expected_os_image_hash,
        context=policy.context,
        allow_local=policy.allow_local,
        max_age_seconds=policy.max_age_seconds,
    )
    try:
        attestation = fetch_and_verify_attestation(policy.api_url, attestation_policy)
    except AttestationVerificationError as exc:
        raise CvmAttestationError(str(exc)) from exc

    return CvmAttestationBundle(
        api_url=policy.api_url,
        context=policy.context,
        mode=attestation.mode,
        compose_hash=compose.compose_hash,
        attested_compose_hash=attestation.compose_hash,
        rendered_compose_sha256=compose.rendered_compose_sha256,
        images=compose.images,
        app_id=attestation.app_id,
        os_image_hash=attestation.os_image_hash,
        report_data=attestation.report_data,
        encryption_public_key=attestation.encryption_public_key,
        quote_size=attestation.quote_size,
        fetched_at=attestation.fetched_at,
        quote_verification="public-envelope-only; Intel TDX quote internals not parsed",
    )


def bundle_to_json(bundle: CvmAttestationBundle) -> str:
    """Serialize a bounded bundle deterministically for logs or STATUS evidence."""
    return json.dumps(bundle.to_public_dict(), indent=2, sort_keys=True)
