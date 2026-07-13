"""Deployment verifier tying GitHub image attestations to a live Phala CVM."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
from typing import Any

from tinker_delegate.cvm_attestation import (
    CvmAttestationBundle,
    CvmAttestationError,
    CvmAttestationPolicy,
    verify_cvm_attestation,
)


DEFAULT_REPO = "G-structure/dnai-wikigen"
DEFAULT_SIGNER_WORKFLOW = "G-structure/dnai-wikigen/.github/workflows/build-tee-images.yml"
PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"
SBOM_PREDICATE = "https://spdx.dev/Document/v2.3"


class DeploymentBundleError(RuntimeError):
    """Raised when a deployment bundle cannot be verified."""


@dataclass(frozen=True)
class GithubImagePolicy:
    """Expected GitHub attestation policy for one digest-pinned image."""

    image: str
    source_digest: str
    source_ref: str = ""
    repo: str = DEFAULT_REPO
    signer_workflow: str = DEFAULT_SIGNER_WORKFLOW


@dataclass(frozen=True)
class GithubImageAttestation:
    """Bounded public result for one verified image."""

    image: str
    repo: str
    signer_workflow: str
    source_digest: str
    source_ref: str
    provenance_attestation: str
    sbom_attestation: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "image": self.image,
            "repo": self.repo,
            "signer_workflow": self.signer_workflow,
            "source_digest": self.source_digest,
            "source_ref": self.source_ref,
            "provenance_attestation": self.provenance_attestation,
            "sbom_attestation": self.sbom_attestation,
        }


@dataclass(frozen=True)
class DeploymentBundlePolicy:
    """Expected source, image, compose, and live CVM identity."""

    api_url: str
    compose_path: Path
    images: tuple[GithubImagePolicy, ...]
    env_files: tuple[Path, ...] = ()
    allowed_env_file: Path | None = None
    allowed_envs: tuple[str, ...] = ()
    context: str = "artifact"
    expected_compose_hash: str = ""
    expected_attested_compose_hash: str = ""
    expected_app_id: str = ""
    expected_os_image_hash: str = ""
    extra_required_image_digests: tuple[str, ...] = ()
    allow_local: bool = False
    allow_tags: bool = False
    phala_raw_compose: bool = False
    max_age_seconds: float = 60.0


@dataclass(frozen=True)
class DeploymentVerificationBundle:
    """Single bounded certificate tying source attestations to live CVM evidence."""

    schema: str
    api_url: str
    context: str
    images: tuple[GithubImageAttestation, ...]
    cvm: CvmAttestationBundle

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "api_url": self.api_url,
            "context": self.context,
            "status": "verified",
            "images": [image.to_public_dict() for image in self.images],
            "cvm": self.cvm.to_public_dict(),
            "checks": {
                "github_provenance_attestations": "verified",
                "github_sbom_attestations": "verified",
                "digest_pinned_compose": "verified",
                "live_cvm_attestation": "verified",
                "raw_secret_egress": False,
            },
        }


def _normalize_digest(value: str) -> str:
    digest = value.strip().lower()
    if digest.startswith("sha256:"):
        digest = digest[len("sha256:") :]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise DeploymentBundleError(f"invalid sha256 digest: {value}")
    return digest


def image_digest(image: str) -> str:
    """Extract the sha256 digest from a digest-pinned image reference."""
    marker = "@sha256:"
    if marker not in image:
        raise DeploymentBundleError("image must be digest-pinned with @sha256: " + image)
    return _normalize_digest(image.rsplit(marker, 1)[1])


def _run_gh_attestation_verify(policy: GithubImagePolicy, predicate_type: str) -> None:
    args = [
        "gh",
        "attestation",
        "verify",
        "oci://" + policy.image,
        "--repo",
        policy.repo,
        "--bundle-from-oci",
        "--signer-workflow",
        policy.signer_workflow,
        "--source-digest",
        policy.source_digest,
        "--deny-self-hosted-runners",
        "--predicate-type",
        predicate_type,
    ]
    if policy.source_ref:
        args.extend(["--source-ref", policy.source_ref])
    try:
        subprocess.run(args, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise DeploymentBundleError("gh is required for GitHub attestation verification") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        if detail:
            detail = detail.splitlines()[-1]
        raise DeploymentBundleError(
            f"GitHub attestation verification failed for {policy.image}: {detail}"
        ) from exc


def verify_github_image(policy: GithubImagePolicy) -> GithubImageAttestation:
    """Verify one image has GitHub-signed SLSA provenance and SPDX SBOM attestations."""
    image_digest(policy.image)
    if not policy.source_digest.strip():
        raise DeploymentBundleError("--source-digest is required for every image")
    _run_gh_attestation_verify(policy, PROVENANCE_PREDICATE)
    _run_gh_attestation_verify(policy, SBOM_PREDICATE)
    return GithubImageAttestation(
        image=policy.image,
        repo=policy.repo,
        signer_workflow=policy.signer_workflow,
        source_digest=policy.source_digest,
        source_ref=policy.source_ref,
        provenance_attestation="verified",
        sbom_attestation="verified",
    )


def verify_deployment_bundle(policy: DeploymentBundlePolicy) -> DeploymentVerificationBundle:
    """Verify GitHub image provenance/SBOMs and the live CVM evidence in one pass."""
    if not policy.images:
        raise DeploymentBundleError("at least one --image is required")

    image_attestations = tuple(verify_github_image(image) for image in policy.images)
    required_digests = tuple(
        "sha256:" + image_digest(image.image) for image in policy.images
    ) + policy.extra_required_image_digests

    cvm_policy = CvmAttestationPolicy(
        api_url=policy.api_url,
        compose_path=policy.compose_path,
        env_files=policy.env_files,
        allowed_env_file=policy.allowed_env_file,
        allowed_envs=policy.allowed_envs,
        context=policy.context,
        expected_compose_hash=policy.expected_compose_hash,
        expected_attested_compose_hash=policy.expected_attested_compose_hash,
        expected_app_id=policy.expected_app_id,
        expected_os_image_hash=policy.expected_os_image_hash,
        required_images=tuple(image.image for image in policy.images),
        required_image_digests=required_digests,
        allow_local=policy.allow_local,
        allow_tags=policy.allow_tags,
        phala_raw_compose=policy.phala_raw_compose,
        max_age_seconds=policy.max_age_seconds,
    )
    try:
        cvm_bundle = verify_cvm_attestation(cvm_policy)
    except CvmAttestationError as exc:
        raise DeploymentBundleError(str(exc)) from exc

    return DeploymentVerificationBundle(
        schema="dnai.deployment.verification.v1",
        api_url=policy.api_url,
        context=policy.context,
        images=image_attestations,
        cvm=cvm_bundle,
    )


def bundle_to_json(bundle: DeploymentVerificationBundle) -> str:
    """Serialize a bounded deployment certificate deterministically."""
    return json.dumps(bundle.to_public_dict(), indent=2, sort_keys=True)
