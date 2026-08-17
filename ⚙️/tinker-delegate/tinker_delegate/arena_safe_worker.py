"""Fail-closed in-boundary worker for the DNASeq ``dnai-safe-ir-v1`` challenge.

This module is intentionally not exposed by FastAPI. ``arena_worker_service``
supplies the internal leased run loop; production compose can start it only
through the exact release inputs, while the public capability flag remains
fail-closed until activation evidence is available.

The worker:

* refuses local keys, the dstack simulator, and any job without a freshly
  authenticated independent-QVL verdict for the exact live quote;
* re-authorizes the frozen/open ChallengeRegistry state at one stable, fresh
  finalized block immediately before every durable claim or recovery resume;
* resumes the existing durable queue state machine after a process crash;
* loads only the server-generated sealed reference, re-verifies every queue,
  manifest, identity, key, AAD, length, and SHA-256 binding, and decrypts only
  after the CVM gate;
* interprets candidate bytes as the capability-free safe IR, never as Python;
* persists only the quantized Ladder release, terminal state, and bounded
  worker-reported QVL/release commitments;
* returns a small receipt with no controls, exact score, source, ciphertext,
  exception detail, timing, or resource trace.

Directly instantiating an activation object is not attestation verification.
Live wiring must use :class:`RefreshingArenaActivationProvider`, which collects
one recipient-bound quote per job and authenticates the verdict for that same
quote against external trust roots and stable release pins.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import threading
from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from tinker_delegate import dstack_utils
from tinker_delegate.arena_ingress import (
    GCM_TAG_BYTES,
    INGRESS_HKDF_INFO,
    ArenaCandidateIngressStore,
    ArenaIngressError,
    ArenaIngressMetadata,
    ArenaIngressRecipient,
    StoredArenaCandidateEnvelope,
    arena_attestation_report_data,
    arena_candidate_aad,
    arena_submission_manifest_hash,
)
from tinker_delegate.arena_safe_ir import (
    SAFE_IR_CANDIDATE_KIND,
    SAFE_IR_ENTRYPOINT,
    SAFE_IR_MAX_CANDIDATE_BYTES,
    SAFE_IR_POLICY_COMMITMENT,
    SAFE_IR_RUNTIME,
    SafeIrError,
    SafeIrProgram,
    execute_safe_ir_program,
    parse_safe_ir_program,
)
from tinker_delegate.arena_store import (
    DNASEQ_SAFE_IR_CHALLENGE_ID,
    DNASEQ_SAFE_IR_CHALLENGE_VERSION,
    ArenaStore,
    ArenaStoreError,
    ChallengeManifest,
    CiphertextEvidence,
    CiphertextState,
    ExecutionProvenance,
    QueueReason,
    QueueState,
    SubmissionMode,
    SubmissionRecord,
    default_challenge_catalog,
)
from tinker_delegate.bio_evaluators import BioValidationError, z_prime_factor
from tinker_delegate.chain_submitter import (
    SignerAttestationEvidence,
    normalize_address,
)
from tinker_delegate.qvl_freshness import QvlChallenge


WORKER_RECEIPT_SCHEMA_VERSION = 1
MIN_TDX_QUOTE_BYTES = 1_024
MAX_TDX_QUOTE_BYTES = 16_384
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


class ArenaSafeWorkerError(RuntimeError):
    """Fail-closed worker error whose text never contains private values."""


class ArenaSafeWorkerUnavailable(ArenaSafeWorkerError):
    """Raised before queue mutation when production authorization is absent."""


class ArenaSafeWorkerPolicyUnavailable(ArenaSafeWorkerUnavailable):
    """Raised before mutation when the persisted execution policy did not pass."""


class ArenaSafeWorkerRegistryUnavailable(ArenaSafeWorkerUnavailable):
    """Raised before a durable worker claim when registry authority is absent."""


class _CandidateExecutionFailed(ArenaSafeWorkerError):
    """Private bucket for candidate/decryption failures; detail never egresses."""


@dataclass(frozen=True)
class ArenaExecutionPolicyRequest:
    """Bounded context passed to the persisted execution-policy gate."""

    submission_id: str
    challenge_id: str
    challenge_version: str
    challenge_manifest_hash: str
    submission_manifest_hash: str
    candidate_commitment: str
    wallet_address: str
    project_id: str
    runtime: str
    runtime_policy_commitment: str


class ArenaExecutionPolicyGate(Protocol):
    """Adapter seam for the durable, fail-closed execution-policy store."""

    def authorize_arena_execution(
        self,
        request: ArenaExecutionPolicyRequest,
        *,
        occurred_at: int,
    ) -> bool:
        """Return exactly ``True`` only for a current persisted pass decision."""


@dataclass(frozen=True)
class ArenaRegistryClaimRequest:
    """Exact public ingress identity authorized immediately before a claim.

    ``ingress_binding_sha256`` commits to the canonical AEAD binding rather
    than ciphertext. It therefore binds the registry gate to the challenge,
    identity, candidate commitment, recipient, submission manifest, and the
    proxy's independently verified registry snapshot without exposing private
    candidate bytes.
    """

    submission_id: str
    encrypted_reference: str
    challenge_id: str
    challenge_version: str
    challenge_manifest_hash: str
    submission_manifest_hash: str
    candidate_commitment: str
    ingress_binding_sha256: str
    ingress_registry_authorization_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.submission_id, str)
            or re.fullmatch(r"sub_[0-9a-f]{24}", self.submission_id) is None
        ):
            raise ArenaSafeWorkerRegistryUnavailable(
                "Arena registry claim request is malformed"
            )
        if (
            not isinstance(self.encrypted_reference, str)
            or not 1 <= len(self.encrypted_reference.encode("utf-8")) <= 512
        ):
            raise ArenaSafeWorkerRegistryUnavailable(
                "Arena registry claim request is malformed"
            )
        for value in (self.challenge_id, self.challenge_version):
            if (
                not isinstance(value, str)
                or not 1 <= len(value.encode("utf-8")) <= 64
                or any(
                    ord(character) < 0x21 or ord(character) > 0x7E
                    for character in value
                )
            ):
                raise ArenaSafeWorkerRegistryUnavailable(
                    "Arena registry claim request is malformed"
                )
        if (
            not isinstance(self.challenge_manifest_hash, str)
            or _HEX_64.fullmatch(self.challenge_manifest_hash) is None
            or self.challenge_manifest_hash == "0" * 64
        ):
            raise ArenaSafeWorkerRegistryUnavailable(
                "Arena registry claim request is malformed"
            )
        for value in (
            self.submission_manifest_hash,
            self.candidate_commitment,
            self.ingress_binding_sha256,
            self.ingress_registry_authorization_sha256,
        ):
            if (
                not isinstance(value, str)
                or _SHA256.fullmatch(value) is None
                or value == "sha256:" + "0" * 64
            ):
                raise ArenaSafeWorkerRegistryUnavailable(
                    "Arena registry claim request is malformed"
                )

    def to_commitment_dict(self) -> dict[str, str]:
        return {
            "submission_id": self.submission_id,
            "encrypted_reference": self.encrypted_reference,
            "challenge_id": self.challenge_id,
            "challenge_version": self.challenge_version,
            "challenge_manifest_hash": self.challenge_manifest_hash,
            "submission_manifest_hash": self.submission_manifest_hash,
            "candidate_commitment": self.candidate_commitment,
            "ingress_binding_sha256": self.ingress_binding_sha256,
            "ingress_registry_authorization_sha256": (
                self.ingress_registry_authorization_sha256
            ),
        }

    @property
    def sha256(self) -> str:
        encoded = json.dumps(
            self.to_commitment_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return "sha256:" + hashlib.sha256(
            b"dnai-wikigen/arena-worker-registry-claim-request/v1\0" + encoded
        ).hexdigest()


@dataclass(frozen=True)
class ArenaWorkerRegistryAuthorization:
    """Bounded result of one finalized ChallengeRegistry claim-time read."""

    claim_request_sha256: str
    registry_snapshot_sha256: str
    chain_id: int
    block_number: int
    block_hash: str
    block_timestamp: int
    registry_address: str
    registry_challenge_id: int
    registry_version: int

    def __post_init__(self) -> None:
        for value in (self.claim_request_sha256, self.registry_snapshot_sha256):
            if (
                not isinstance(value, str)
                or _SHA256.fullmatch(value) is None
                or value == "sha256:" + "0" * 64
            ):
                raise ArenaSafeWorkerRegistryUnavailable(
                    "Arena registry claim authorization is malformed"
                )
        if isinstance(self.chain_id, bool) or self.chain_id != 84_532:
            raise ArenaSafeWorkerRegistryUnavailable(
                "Arena registry claim authorization is malformed"
            )
        for value in (self.block_number, self.block_timestamp):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ArenaSafeWorkerRegistryUnavailable(
                    "Arena registry claim authorization is malformed"
                )
        if (
            not isinstance(self.block_hash, str)
            or re.fullmatch(r"0x[0-9a-f]{64}", self.block_hash) is None
            or self.block_hash == "0x" + "0" * 64
        ):
            raise ArenaSafeWorkerRegistryUnavailable(
                "Arena registry claim authorization is malformed"
            )
        if (
            not isinstance(self.registry_address, str)
            or self.registry_address != self.registry_address.lower()
            or _ADDRESS.fullmatch(self.registry_address) is None
            or self.registry_address == "0x" + "0" * 40
        ):
            raise ArenaSafeWorkerRegistryUnavailable(
                "Arena registry claim authorization is malformed"
            )
        if (
            isinstance(self.registry_challenge_id, bool)
            or not isinstance(self.registry_challenge_id, int)
            or self.registry_challenge_id < 1
            or isinstance(self.registry_version, bool)
            or not isinstance(self.registry_version, int)
            or self.registry_version < 1
        ):
            raise ArenaSafeWorkerRegistryUnavailable(
                "Arena registry claim authorization is malformed"
            )


class ArenaRegistryClaimGate(Protocol):
    def authorize_arena_claim(
        self,
        request: ArenaRegistryClaimRequest,
        *,
        occurred_at: int,
    ) -> ArenaWorkerRegistryAuthorization:
        """Authorize one exact ingress binding at a current finalized block."""


@dataclass(frozen=True, repr=False)
class ArenaAttestationPacket:
    """One ephemeral quote and its bounded locally checked expectation.

    The raw quote exists only for the synchronous QVL request. ``repr`` never
    renders it and no serializer is provided.
    """

    evidence: SignerAttestationEvidence
    quote: str = field(repr=False)


class ArenaIndependentVerdictProvider(Protocol):
    def issue_challenge(self) -> QvlChallenge:
        """Authenticate one QVL-issued challenge before dstack quote work."""

    def verify(
        self,
        packet: ArenaAttestationPacket,
        challenge: QvlChallenge,
    ) -> Any:
        """Return the complete signed verdict for ``packet.quote``."""


class ArenaActivationProvider(Protocol):
    def refresh_activation(self, *, occurred_at: int) -> "ArenaSafeWorkerActivation":
        """Return a newly QVL-authenticated activation for one worker job."""


@dataclass(frozen=True)
class ArenaSafeWorkerActivation:
    """Exact output of the external deployment authorization gate.

    ``independent_tdx_verdict_verified`` is deliberately explicit: a dstack
    quote producer cannot set it merely because a quote exists.  The release
    process must obtain it from the independent verifier and bind the exact
    compose, challenge manifest, and runtime policy.
    """

    execution_enabled: bool
    independent_tdx_verdict_verified: bool
    compose_hash: str
    app_id: str
    os_image_hash: str
    quote_sha256: str
    verdict_expires_at: int
    challenge_manifest_hash: str
    runtime_policy_commitment: str
    verifier_address: str
    verdict_digest: str
    chain_id: int
    challenge_registry_address: str
    tee_signer_address: str

    def __post_init__(self) -> None:
        if not isinstance(self.execution_enabled, bool):
            raise ArenaSafeWorkerUnavailable("Arena worker activation is malformed")
        if not isinstance(self.independent_tdx_verdict_verified, bool):
            raise ArenaSafeWorkerUnavailable("Arena worker activation is malformed")
        if not isinstance(self.compose_hash, str) or not _HEX_64.fullmatch(
            self.compose_hash
        ) or self.compose_hash == "0" * 64:
            raise ArenaSafeWorkerUnavailable("Arena worker compose binding is malformed")
        if (
            not isinstance(self.app_id, str)
            or not 1 <= len(self.app_id.encode("utf-8")) <= 128
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in self.app_id)
        ):
            raise ArenaSafeWorkerUnavailable("Arena worker app binding is malformed")
        if not isinstance(self.os_image_hash, str) or not _HEX_64.fullmatch(
            self.os_image_hash
        ) or self.os_image_hash == "0" * 64:
            raise ArenaSafeWorkerUnavailable("Arena worker OS binding is malformed")
        if not isinstance(self.quote_sha256, str) or not _SHA256.fullmatch(
            self.quote_sha256
        ) or self.quote_sha256 == "sha256:" + "0" * 64:
            raise ArenaSafeWorkerUnavailable("Arena worker quote binding is malformed")
        if (
            isinstance(self.verdict_expires_at, bool)
            or not isinstance(self.verdict_expires_at, int)
            or self.verdict_expires_at < 1
        ):
            raise ArenaSafeWorkerUnavailable("Arena worker verdict expiry is malformed")
        if (
            not isinstance(self.challenge_manifest_hash, str)
            or not _HEX_64.fullmatch(self.challenge_manifest_hash)
        ):
            raise ArenaSafeWorkerUnavailable(
                "Arena worker challenge binding is malformed"
            )
        if (
            not isinstance(self.runtime_policy_commitment, str)
            or not _SHA256.fullmatch(self.runtime_policy_commitment)
        ):
            raise ArenaSafeWorkerUnavailable("Arena worker runtime binding is malformed")
        if not isinstance(self.verifier_address, str) or not _ADDRESS.fullmatch(
            self.verifier_address
        ) or int(self.verifier_address[2:], 16) == 0:
            raise ArenaSafeWorkerUnavailable("Arena worker verifier binding is malformed")
        if not isinstance(self.verdict_digest, str) or not re.fullmatch(
            r"^0x[0-9a-f]{64}$", self.verdict_digest
        ):
            raise ArenaSafeWorkerUnavailable("Arena worker verdict binding is malformed")
        if isinstance(self.chain_id, bool) or self.chain_id != 84_532:
            raise ArenaSafeWorkerUnavailable("Arena worker chain binding is unsupported")
        if not isinstance(self.challenge_registry_address, str) or not _ADDRESS.fullmatch(
            self.challenge_registry_address
        ) or int(self.challenge_registry_address[2:], 16) == 0:
            raise ArenaSafeWorkerUnavailable("Arena worker registry binding is malformed")
        if not isinstance(self.tee_signer_address, str) or not _ADDRESS.fullmatch(
            self.tee_signer_address
        ) or int(self.tee_signer_address[2:], 16) == 0:
            raise ArenaSafeWorkerUnavailable("Arena worker TEE binding is malformed")
        if self.verifier_address.lower() == self.tee_signer_address.lower():
            raise ArenaSafeWorkerUnavailable(
                "Arena worker verifier must be independent from the TEE"
            )


def activation_from_independent_verdict(
    verdict: Any,
    *,
    trusted_verifier_addresses: Sequence[str],
    recipient: ArenaIngressRecipient,
    expected_compose_hash: str,
    expected_app_id: str,
    expected_os_image_hash: str,
    expected_quote_sha256: str,
    expected_challenge: QvlChallenge,
    expected_tee_signer_address: str,
    chain_id: int,
    challenge_registry_address: str,
    now: int,
    max_verdict_age_seconds: int = 300,
) -> ArenaSafeWorkerActivation:
    """Authenticate a signed QVL verdict into the only live activation shape.

    Trust roots and every expected deployment binding are supplied outside the
    verdict. The challenge manifest and safe-IR policy commitments come from
    this reviewed worker image. Quote presence or a caller-provided boolean can
    never construct this activation.
    """

    from tinker_delegate.result_verifier import (
        IndependentAttestationExpectation,
        IndependentAttestationVerdict,
        ResultVerifierError,
        authenticate_independent_attestation_verdict,
    )

    if not isinstance(verdict, IndependentAttestationVerdict):
        raise ArenaSafeWorkerUnavailable("Arena worker QVL verdict is required")
    if not isinstance(recipient, ArenaIngressRecipient):
        raise ArenaSafeWorkerUnavailable("Arena worker recipient is required")
    if recipient.custody_mode != "dstack":
        raise ArenaSafeWorkerUnavailable(
            "Arena worker activation requires dstack key custody"
        )
    compose_hash = _raw_hex_32(expected_compose_hash, label="compose")
    os_image_hash = _raw_hex_32(expected_os_image_hash, label="OS image")
    quote_sha256 = _sha256_value(expected_quote_sha256, label="quote")
    if (
        not isinstance(expected_app_id, str)
        or not 1 <= len(expected_app_id.encode("utf-8")) <= 128
    ):
        raise ArenaSafeWorkerUnavailable("Arena worker app binding is malformed")
    if (
        isinstance(chain_id, bool)
        or chain_id != 84_532
        or expected_challenge.chain_id != chain_id
        or expected_challenge.domain != "main_runtime_cvm"
    ):
        raise ArenaSafeWorkerUnavailable("Arena worker chain binding is unsupported")
    challenge = default_challenge_catalog().get(
        DNASEQ_SAFE_IR_CHALLENGE_ID, DNASEQ_SAFE_IR_CHALLENGE_VERSION
    )
    expectation = IndependentAttestationExpectation(
        trusted_verifier_addresses=tuple(trusted_verifier_addresses),
        chain_id=expected_challenge.chain_id,
        domain=expected_challenge.domain,
        profile="arena",
        cvm_id=expected_challenge.cvm_id,
        deployment_intent_sha256=expected_challenge.deployment_intent_sha256,
        release_authority_sha256=expected_challenge.release_authority_sha256,
        ceremony_nonce=expected_challenge.ceremony_nonce,
        measurement_policy_sha256=expected_challenge.measurement_policy_sha256,
        release_policy_hash=expected_challenge.release_policy_hash,
        challenge_id=expected_challenge.challenge_id,
        challenge_digest=expected_challenge.challenge_digest,
        challenge_issued_at=expected_challenge.issued_at,
        challenge_expires_at=expected_challenge.expires_at,
        quote_hash="0x" + quote_sha256.removeprefix("sha256:"),
        report_data="0x" + recipient.report_data.hex(),
        compose_hash="0x" + compose_hash,
        app_id=expected_app_id,
        os_image_hash=os_image_hash,
        signer_address=expected_tee_signer_address,
        contract_address=challenge_registry_address,
        max_age_seconds=max_verdict_age_seconds,
    )
    try:
        authenticated = authenticate_independent_attestation_verdict(
            verdict,
            expectation=expectation,
            now=now,
        )
    except (ResultVerifierError, TypeError, ValueError) as exc:
        raise ArenaSafeWorkerUnavailable(
            "Arena worker QVL verdict authentication failed"
        ) from exc
    return ArenaSafeWorkerActivation(
        execution_enabled=True,
        independent_tdx_verdict_verified=True,
        compose_hash=compose_hash,
        app_id=expected_app_id,
        os_image_hash=os_image_hash,
        quote_sha256=quote_sha256,
        verdict_expires_at=verdict.expires_at,
        challenge_manifest_hash=challenge.manifest_hash,
        runtime_policy_commitment=SAFE_IR_POLICY_COMMITMENT,
        verifier_address=authenticated.verifier_address,
        verdict_digest=authenticated.verdict_digest,
        chain_id=chain_id,
        challenge_registry_address=challenge_registry_address,
        tee_signer_address=expected_tee_signer_address,
    )


class RefreshingArenaActivationProvider:
    """Collect and independently authorize one exact live quote per job.

    Only stable release measurements are retained on the provider. The raw
    quote, its dynamic hash, and the signed short-lived verdict remain local to
    :meth:`refresh_activation` and are discarded when it returns.
    """

    def __init__(
        self,
        *,
        recipient: ArenaIngressRecipient,
        verdict_provider: ArenaIndependentVerdictProvider,
        trusted_verifier_addresses: Sequence[str],
        expected_compose_hash: str,
        expected_app_id: str,
        expected_os_image_hash: str,
        expected_tee_signer_address: str,
        chain_id: int,
        challenge_registry_address: str,
        max_verdict_age_seconds: int = 300,
        attestation_collector: Any = None,
    ) -> None:
        if not isinstance(recipient, ArenaIngressRecipient):
            raise ArenaSafeWorkerUnavailable("Arena worker recipient is required")
        if recipient.custody_mode != "dstack":
            raise ArenaSafeWorkerUnavailable(
                "Arena worker activation requires dstack key custody"
            )
        if not hmac.compare_digest(
            recipient.report_data,
            arena_attestation_report_data(recipient.public_key),
        ):
            raise ArenaSafeWorkerUnavailable(
                "Arena worker recipient report binding is malformed"
            )
        if verdict_provider is None or not callable(
            getattr(verdict_provider, "verify", None)
        ):
            raise ArenaSafeWorkerUnavailable(
                "Arena independent QVL provider is required"
            )
        trusted = tuple(trusted_verifier_addresses)
        if not trusted:
            raise ArenaSafeWorkerUnavailable(
                "Arena trusted QVL verifier roots are required"
            )
        compose_hash = _raw_hex_32(expected_compose_hash, label="compose")
        os_image_hash = _raw_hex_32(expected_os_image_hash, label="OS image")
        if (
            not isinstance(expected_app_id, str)
            or not 1 <= len(expected_app_id.encode("utf-8")) <= 128
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E
                for character in expected_app_id
            )
        ):
            raise ArenaSafeWorkerUnavailable(
                "Arena worker app binding is malformed"
            )
        if isinstance(chain_id, bool) or chain_id != 84_532:
            raise ArenaSafeWorkerUnavailable(
                "Arena worker chain binding is unsupported"
            )
        try:
            tee_signer = normalize_address(expected_tee_signer_address)
            registry = normalize_address(challenge_registry_address)
            normalized_trusted = tuple(
                sorted({normalize_address(address) for address in trusted})
            )
        except Exception as exc:
            raise ArenaSafeWorkerUnavailable(
                "Arena worker address binding is malformed"
            ) from exc
        if len(normalized_trusted) != len(trusted) or tee_signer in normalized_trusted:
            raise ArenaSafeWorkerUnavailable(
                "Arena independent QVL roots are malformed"
            )
        if (
            isinstance(max_verdict_age_seconds, bool)
            or not isinstance(max_verdict_age_seconds, int)
            or not 1 <= max_verdict_age_seconds <= 300
        ):
            raise ArenaSafeWorkerUnavailable(
                "Arena QVL verdict age policy is malformed"
            )
        self._recipient = recipient
        self._verdict_provider = verdict_provider
        self._trusted_verifier_addresses = normalized_trusted
        self._expected_compose_hash = compose_hash
        self._expected_app_id = expected_app_id
        self._expected_os_image_hash = os_image_hash
        self._expected_tee_signer_address = tee_signer
        self._chain_id = chain_id
        self._challenge_registry_address = registry
        self._max_verdict_age_seconds = max_verdict_age_seconds
        self._attestation_collector = (
            attestation_collector or _collect_live_arena_attestation
        )

    def __repr__(self) -> str:
        return "RefreshingArenaActivationProvider(dstack_qvl_required=True)"

    def close(self) -> None:
        closer = getattr(self._verdict_provider, "close", None)
        if callable(closer):
            closer()

    def refresh_activation(self, *, occurred_at: int) -> ArenaSafeWorkerActivation:
        if isinstance(occurred_at, bool) or not isinstance(occurred_at, int):
            raise ArenaSafeWorkerUnavailable("Arena worker activation time is invalid")
        try:
            challenge = self._verdict_provider.issue_challenge()
            packet = self._attestation_collector(
                recipient=self._recipient,
                expected_compose_hash=self._expected_compose_hash,
                expected_app_id=self._expected_app_id,
                expected_os_image_hash=self._expected_os_image_hash,
                expected_tee_signer_address=self._expected_tee_signer_address,
                chain_id=self._chain_id,
                challenge_registry_address=self._challenge_registry_address,
                challenge_digest=challenge.digest_bytes,
            )
        except ArenaSafeWorkerUnavailable:
            raise
        except Exception as exc:
            raise ArenaSafeWorkerUnavailable(
                "Arena worker could not collect live dstack evidence"
            ) from exc
        if not isinstance(packet, ArenaAttestationPacket):
            raise ArenaSafeWorkerUnavailable(
                "Arena worker live attestation packet is malformed"
            )
        quote_sha256 = _validate_live_attestation_packet(
            packet,
            recipient=self._recipient,
            expected_compose_hash=self._expected_compose_hash,
            expected_app_id=self._expected_app_id,
            expected_os_image_hash=self._expected_os_image_hash,
            expected_tee_signer_address=self._expected_tee_signer_address,
            chain_id=self._chain_id,
            challenge_registry_address=self._challenge_registry_address,
        )
        try:
            verdict = self._verdict_provider.verify(packet, challenge)
        except Exception:
            raise ArenaSafeWorkerUnavailable(
                "Arena independent QVL verdict is unavailable"
            ) from None
        return activation_from_independent_verdict(
            verdict,
            trusted_verifier_addresses=self._trusted_verifier_addresses,
            recipient=self._recipient,
            expected_compose_hash=self._expected_compose_hash,
            expected_app_id=self._expected_app_id,
            expected_os_image_hash=self._expected_os_image_hash,
            expected_quote_sha256=quote_sha256,
            expected_challenge=challenge,
            expected_tee_signer_address=self._expected_tee_signer_address,
            chain_id=self._chain_id,
            challenge_registry_address=self._challenge_registry_address,
            now=occurred_at,
            max_verdict_age_seconds=self._max_verdict_age_seconds,
        )


@dataclass(frozen=True, repr=False)
class DnaseqVariantQcSafeIrEvaluator:
    """Trusted synthetic DNASeq evaluator with no exact-value serializer.

    ``positive_controls`` are sealed quality evidence for truth-supported
    synthetic calls. ``negative_controls`` are sealed quality evidence for
    simulated sequencing/calling artifacts. No bases, reads, alleles, loci,
    sample IDs, or labels are exposed to the candidate program.
    """

    positive_controls: tuple[float, ...] = field(repr=False)
    negative_controls: tuple[float, ...] = field(repr=False)

    def __init__(
        self,
        positive_controls: Sequence[float],
        negative_controls: Sequence[float],
    ) -> None:
        positive = _validate_evaluator_controls(positive_controls)
        negative = _validate_evaluator_controls(negative_controls)
        object.__setattr__(self, "positive_controls", positive)
        object.__setattr__(self, "negative_controls", negative)

    def __repr__(self) -> str:
        return (
            "DnaseqVariantQcSafeIrEvaluator("
            f"positive_count={len(self.positive_controls)}, "
            f"negative_count={len(self.negative_controls)})"
        )

    def run_public_conformance(self, program: SafeIrProgram) -> None:
        """Run a fixed public shape test; no result crosses the worker boundary."""

        execute_safe_ir_program(
            program,
            (100.0, 101.0, 99.0, 100.5, 140.0),
            (10.0, 11.0, 9.0, 10.5, 40.0),
        )

    def internal_score(self, program: SafeIrProgram) -> float:
        """Return a clamped internal score only to the in-process Ladder gate."""

        controls = execute_safe_ir_program(
            program,
            self.positive_controls,
            self.negative_controls,
        )
        raw_score = z_prime_factor(controls.positive, controls.negative)
        if not math.isfinite(raw_score) or raw_score <= 0.0:
            return 0.0
        return min(1.0, raw_score)


# Source compatibility for integrations that imported the pre-DNASeq class
# name. The canonical catalog and user-facing surfaces use the DNASeq name.
BioAssaySafeIrEvaluator = DnaseqVariantQcSafeIrEvaluator


@dataclass(frozen=True)
class ArenaSafeWorkerReceipt:
    submission_id: str
    candidate_commitment: str
    final_state: str
    failure_code: str
    ladder_release: dict[str, Any] | None
    idempotent_replay: bool

    def to_bounded_dict(self) -> dict[str, Any]:
        return {
            "surface": "arena_safe_worker_receipt",
            "schema_version": WORKER_RECEIPT_SCHEMA_VERSION,
            "submission_id": self.submission_id,
            "candidate_commitment": self.candidate_commitment,
            "final_state": self.final_state,
            "failure_code": self.failure_code,
            "ladder_release": self.ladder_release,
            "idempotent_replay": self.idempotent_replay,
            "runtime": SAFE_IR_RUNTIME,
            "runtime_policy_commitment": SAFE_IR_POLICY_COMMITMENT,
            "public_api_connected": False,
            "raw_candidate_egress": False,
            "selected_controls_egress": False,
            "exact_score_egress": False,
            "ciphertext_egress": False,
            "exception_detail_egress": False,
        }


class ArenaSafeIrWorker:
    """Crash-resumable safe-IR evaluator owned by one leased process.

    The in-process lock prevents duplicate calls within the leased process. The
    service entrypoint owns a lifetime filesystem lease, while the store's
    cross-process lock makes ``queued -> provisioning`` an atomic durable claim.
    A replacement process can resume from any nonterminal state after the old
    process releases its lease by exiting or crashing.
    """

    def __init__(
        self,
        *,
        arena_store: ArenaStore,
        ingress_store: ArenaCandidateIngressStore,
        recipient: ArenaIngressRecipient,
        evaluator: DnaseqVariantQcSafeIrEvaluator,
        activation_provider: ArenaActivationProvider,
        execution_policy_gate: ArenaExecutionPolicyGate,
        registry_claim_gate: ArenaRegistryClaimGate,
    ) -> None:
        if not isinstance(arena_store, ArenaStore):
            raise ArenaSafeWorkerUnavailable("Arena durable store is required")
        if not isinstance(ingress_store, ArenaCandidateIngressStore):
            raise ArenaSafeWorkerUnavailable("Arena ingress store is required")
        if not isinstance(recipient, ArenaIngressRecipient):
            raise ArenaSafeWorkerUnavailable("Arena recipient is required")
        if not isinstance(evaluator, DnaseqVariantQcSafeIrEvaluator):
            raise ArenaSafeWorkerUnavailable("Arena evaluator is required")
        if activation_provider is None or not callable(
            getattr(activation_provider, "refresh_activation", None)
        ):
            raise ArenaSafeWorkerUnavailable(
                "Arena refreshing activation provider is required"
            )
        if execution_policy_gate is None or not callable(
            getattr(execution_policy_gate, "authorize_arena_execution", None)
        ):
            raise ArenaSafeWorkerUnavailable(
                "Arena persisted execution-policy gate is required"
            )
        if registry_claim_gate is None or not callable(
            getattr(registry_claim_gate, "authorize_arena_claim", None)
        ):
            raise ArenaSafeWorkerUnavailable(
                "Arena finalized registry claim gate is required"
            )
        self._arena_store = arena_store
        self._ingress_store = ingress_store
        self._recipient = recipient
        self._evaluator = evaluator
        self._activation_provider = activation_provider
        self._execution_policy_gate = execution_policy_gate
        self._registry_claim_gate = registry_claim_gate
        self._lock = threading.RLock()

    def process_submission(
        self,
        submission_id: str,
        *,
        occurred_at: int,
    ) -> ArenaSafeWorkerReceipt:
        """Process or resume one submission without exposing private details."""

        with self._lock:
            record = self._arena_store.get_submission(submission_id)
            if record.state in {
                QueueState.COMPLETED,
                QueueState.FAILED,
                QueueState.WITHHELD,
                QueueState.CANCELLED,
                QueueState.EXPIRED,
                QueueState.DEAD_LETTER,
            }:
                record = self.cleanup_submission_ciphertext(
                    record.submission_id,
                    occurred_at=occurred_at,
                )
                if record.state in {QueueState.COMPLETED, QueueState.FAILED}:
                    return self._receipt(record, idempotent=True)
                raise ArenaSafeWorkerError("Arena submission is not executable")
            activation = self.verify_activation(occurred_at)
            challenge = self._challenge_for(record, activation)
            self._require_submission_policy(record, challenge)
            if record.state in {
                QueueState.REVIEW_HOLD,
            }:
                raise ArenaSafeWorkerError("Arena submission is not executable")
            policy_scope = ExitStack()
            try:
                self._require_execution_policy(
                    record,
                    challenge,
                    occurred_at,
                    policy_scope=policy_scope,
                )
            except Exception:
                policy_scope.close()
                raise

            plaintext: bytearray | None = None
            try:
                # Resolve only ciphertext-free index commitments before the
                # claim. The ingress constructor and describe call do not open
                # the envelope blob. Registry authorization then binds those
                # commitments immediately before the store's atomic
                # claim-vs-owner-cancel compare-and-swap.
                ingress = ArenaCandidateIngressStore(
                    self._ingress_store.root_dir,
                    max_envelopes=self._ingress_store.max_envelopes,
                )
                metadata = ingress.describe_envelope(record.encrypted_reference)
                self._require_registry_claim_authorization(
                    record=record,
                    challenge=challenge,
                    metadata=metadata,
                    activation=activation,
                    occurred_at=occurred_at,
                )
                record = self._arena_store.claim_safe_ir_submission(
                    record.submission_id,
                    occurred_at=occurred_at,
                ).submission

                if record.state == QueueState.SUBMITTED:
                    record = self._transition(
                        record,
                        QueueState.POLICY_SCREEN,
                        QueueReason.POLICY_CHECK_STARTED,
                        occurred_at,
                    )

                # This is the first ciphertext read. It occurs only after the
                # durable claim succeeds, so an owner cancellation that won the
                # same store lock cannot reach this line.
                stored = ingress.load_envelope(record.encrypted_reference)
                plaintext = self._decrypt_and_verify(
                    stored=stored,
                    record=record,
                    challenge=challenge,
                )
                program = parse_safe_ir_program(
                    plaintext,
                    expected_commitment=record.candidate_commitment,
                )

                if record.state == QueueState.POLICY_SCREEN:
                    record = self._transition(
                        record,
                        QueueState.QUEUED,
                        QueueReason.POLICY_PASSED,
                        occurred_at,
                    )
                if record.state in {
                    QueueState.QUEUED,
                    QueueState.PROVISIONING,
                    QueueState.PUBLIC_TESTS,
                    QueueState.SEALED_EVAL,
                }:
                    record = self._arena_store.claim_safe_ir_submission(
                        record.submission_id,
                        occurred_at=occurred_at,
                    ).submission
                if record.state == QueueState.PROVISIONING:
                    record = self._transition(
                        record,
                        QueueState.PUBLIC_TESTS,
                        QueueReason.PUBLIC_TESTS_STARTED,
                        occurred_at,
                    )
                if record.state == QueueState.PUBLIC_TESTS:
                    self._evaluator.run_public_conformance(program)
                    record = self._transition(
                        record,
                        QueueState.SEALED_EVAL,
                        QueueReason.SEALED_EVALUATION_STARTED,
                        occurred_at,
                    )
                if record.state != QueueState.SEALED_EVAL:
                    raise ArenaSafeWorkerError("Arena worker state is not resumable")
                if record.ladder_release is None:
                    internal_score = self._evaluator.internal_score(program)
                    self._arena_store.evaluate_ladder_submission(
                        record.submission_id,
                        internal_score,
                        occurred_at=occurred_at,
                    )
                    # Do not retain the exact score past the gate operation.
                    internal_score = 0.0
                    record = self._arena_store.get_submission(record.submission_id)
                record = self._arena_store.finalize_safe_ir_execution(
                    record.submission_id,
                    self._execution_provenance(activation, outcome="completed"),
                    occurred_at=occurred_at,
                )
                record = self.cleanup_submission_ciphertext(
                    record.submission_id,
                    occurred_at=occurred_at,
                )
                return self._receipt(record, idempotent=False)
            except (
                SafeIrError,
                InvalidTag,
                BioValidationError,
                _CandidateExecutionFailed,
            ) as exc:
                # Never interpolate or chain candidate/decryption details into a
                # public receipt.  Integrity/storage failures outside this bucket
                # propagate and do not convert compromised state into "failed".
                del exc
                current = self._arena_store.get_submission(record.submission_id)
                if current.state not in {
                    QueueState.COMPLETED,
                    QueueState.FAILED,
                    QueueState.WITHHELD,
                    QueueState.CANCELLED,
                    QueueState.EXPIRED,
                    QueueState.DEAD_LETTER,
                }:
                    current = self._arena_store.finalize_safe_ir_execution(
                        current.submission_id,
                        self._execution_provenance(activation, outcome="failed"),
                        occurred_at=occurred_at,
                    )
                if current.state in {QueueState.COMPLETED, QueueState.FAILED}:
                    current = self.cleanup_submission_ciphertext(
                        current.submission_id,
                        occurred_at=occurred_at,
                    )
                return self._receipt(current, idempotent=False)
            finally:
                if plaintext is not None:
                    for index in range(len(plaintext)):
                        plaintext[index] = 0
                policy_scope.close()

    def cleanup_submission_ciphertext(
        self,
        submission_id: str,
        *,
        occurred_at: int,
    ) -> SubmissionRecord:
        """Idempotently unlink terminal ciphertext and persist bounded evidence."""

        current = self._arena_store.get_submission(submission_id)
        if current.state not in {
            QueueState.COMPLETED,
            QueueState.FAILED,
            QueueState.WITHHELD,
            QueueState.CANCELLED,
            QueueState.EXPIRED,
            QueueState.DEAD_LETTER,
        }:
            raise ArenaSafeWorkerError(
                "Arena ciphertext cleanup requires a terminal submission"
            )
        if current.ciphertext_state == CiphertextState.UNLINKED:
            return current
        try:
            ingress = ArenaCandidateIngressStore(
                self._ingress_store.root_dir,
                max_envelopes=self._ingress_store.max_envelopes,
            )
            result = ingress.erase_envelope(current.encrypted_reference)
            evidence = CiphertextEvidence(result.evidence)
        except (ArenaIngressError, OSError):
            try:
                return self._arena_store.record_ciphertext_erasure(
                    submission_id,
                    evidence=CiphertextEvidence.UNLINK_FAILED,
                    occurred_at=occurred_at,
                )
            except ArenaStoreError:
                return self._arena_store.get_submission(submission_id)
        return self._arena_store.record_ciphertext_erasure(
            submission_id,
            evidence=evidence,
            occurred_at=occurred_at,
        )

    def cleanup_terminal_ciphertexts(
        self,
        *,
        occurred_at: int,
        limit: int = 32,
    ) -> int:
        """Retry a bounded oldest-first batch on every worker polling cycle."""

        cleaned = 0
        for record in self._arena_store.ciphertext_cleanup_candidates(limit=limit):
            updated = self.cleanup_submission_ciphertext(
                record.submission_id,
                occurred_at=occurred_at,
            )
            if updated.ciphertext_state == CiphertextState.UNLINKED:
                cleaned += 1
        return cleaned

    def close(self) -> None:
        closer = getattr(self._activation_provider, "close", None)
        if callable(closer):
            closer()
        policy_closer = getattr(self._execution_policy_gate, "close", None)
        if callable(policy_closer):
            policy_closer()
        registry_closer = getattr(self._registry_claim_gate, "close", None)
        if callable(registry_closer):
            registry_closer()

    def verify_activation(self, occurred_at: int) -> ArenaSafeWorkerActivation:
        """Obtain one new quote/verdict activation without queue mutation."""

        try:
            activation = self._activation_provider.refresh_activation(
                occurred_at=occurred_at
            )
        except ArenaSafeWorkerUnavailable:
            raise
        except Exception as exc:
            raise ArenaSafeWorkerUnavailable(
                "Arena worker activation refresh failed"
            ) from exc
        self._require_activation(activation, occurred_at)
        return activation

    def _require_activation(
        self,
        activation: ArenaSafeWorkerActivation,
        occurred_at: int,
    ) -> None:
        if not isinstance(activation, ArenaSafeWorkerActivation):
            raise ArenaSafeWorkerUnavailable(
                "Arena worker activation refresh returned an invalid value"
            )
        if not activation.execution_enabled:
            raise ArenaSafeWorkerUnavailable("Arena worker execution is disabled")
        if not activation.independent_tdx_verdict_verified:
            raise ArenaSafeWorkerUnavailable(
                "Arena worker lacks an independent TDX verdict"
            )
        if activation.runtime_policy_commitment != SAFE_IR_POLICY_COMMITMENT:
            raise ArenaSafeWorkerUnavailable("Arena worker runtime policy is not pinned")
        if (
            isinstance(occurred_at, bool)
            or not isinstance(occurred_at, int)
            or occurred_at < 0
            or occurred_at >= activation.verdict_expires_at
        ):
            raise ArenaSafeWorkerUnavailable("Arena worker TDX verdict is expired")
        if self._recipient.custody_mode != "dstack":
            raise ArenaSafeWorkerUnavailable("Arena worker requires dstack key custody")

    def _require_execution_policy(
        self,
        record: SubmissionRecord,
        challenge: ChallengeManifest,
        occurred_at: int,
        *,
        policy_scope: ExitStack,
    ) -> None:
        request = ArenaExecutionPolicyRequest(
            submission_id=record.submission_id,
            challenge_id=record.challenge_id,
            challenge_version=record.challenge_version,
            challenge_manifest_hash=challenge.manifest_hash,
            submission_manifest_hash=arena_submission_manifest_hash(record.manifest),
            candidate_commitment=record.candidate_commitment,
            wallet_address=record.identity.wallet_address,
            project_id=record.identity.project_id,
            runtime=SAFE_IR_RUNTIME,
            runtime_policy_commitment=SAFE_IR_POLICY_COMMITMENT,
        )
        try:
            lease_factory = getattr(
                self._execution_policy_gate,
                "authorized_arena_execution_lease",
                None,
            )
            if callable(lease_factory):
                authorized = policy_scope.enter_context(
                    lease_factory(request, occurred_at=occurred_at)
                )
            else:
                authorized = (
                    self._execution_policy_gate.authorize_arena_execution(
                        request,
                        occurred_at=occurred_at,
                    )
                )
        except Exception as exc:
            raise ArenaSafeWorkerPolicyUnavailable(
                "Arena persisted execution-policy decision is unavailable"
            ) from exc
        if authorized is not True:
            raise ArenaSafeWorkerPolicyUnavailable(
                "Arena persisted execution-policy decision did not pass"
            )

    def _challenge_for(
        self,
        record: SubmissionRecord,
        activation: ArenaSafeWorkerActivation,
    ) -> ChallengeManifest:
        try:
            challenge = default_challenge_catalog().get(
                record.challenge_id, record.challenge_version
            )
        except ArenaStoreError as exc:
            raise ArenaSafeWorkerUnavailable(
                "Arena worker challenge is not in the immutable catalog"
            ) from exc
        if challenge.manifest_hash != activation.challenge_manifest_hash:
            raise ArenaSafeWorkerUnavailable(
                "Arena worker challenge manifest is not deployment-pinned"
            )
        return challenge

    def _require_registry_claim_authorization(
        self,
        *,
        record: SubmissionRecord,
        challenge: ChallengeManifest,
        metadata: ArenaIngressMetadata,
        activation: ArenaSafeWorkerActivation,
        occurred_at: int,
    ) -> None:
        """Refresh finalized registry authority on the operation before claim."""

        request = ArenaRegistryClaimRequest(
            submission_id=record.submission_id,
            encrypted_reference=record.encrypted_reference,
            challenge_id=record.challenge_id,
            challenge_version=record.challenge_version,
            challenge_manifest_hash=challenge.manifest_hash,
            submission_manifest_hash=arena_submission_manifest_hash(record.manifest),
            candidate_commitment=record.candidate_commitment,
            ingress_binding_sha256=metadata.aad_sha256,
            ingress_registry_authorization_sha256=(
                metadata.registry_authorization_sha256
            ),
        )
        try:
            authorization = self._registry_claim_gate.authorize_arena_claim(
                request,
                occurred_at=occurred_at,
            )
        except ArenaSafeWorkerRegistryUnavailable:
            raise
        except Exception as exc:
            raise ArenaSafeWorkerRegistryUnavailable(
                "Arena finalized registry authorization is unavailable"
            ) from exc
        if (
            not isinstance(authorization, ArenaWorkerRegistryAuthorization)
            or not hmac.compare_digest(
                authorization.claim_request_sha256,
                request.sha256,
            )
            or authorization.chain_id != activation.chain_id
            or authorization.registry_address
            != activation.challenge_registry_address.lower()
        ):
            raise ArenaSafeWorkerRegistryUnavailable(
                "Arena finalized registry authorization did not bind the claim"
            )

    @staticmethod
    def _require_submission_policy(
        record: SubmissionRecord,
        challenge: ChallengeManifest,
    ) -> None:
        if (
            challenge.runtime != SAFE_IR_RUNTIME
            or challenge.candidate_kind != SAFE_IR_CANDIDATE_KIND
            or challenge.entrypoint != SAFE_IR_ENTRYPOINT
            or challenge.max_source_bytes != SAFE_IR_MAX_CANDIDATE_BYTES
        ):
            raise ArenaSafeWorkerUnavailable(
                "Arena worker refuses non-safe-IR challenge semantics"
            )
        if (
            record.manifest.runtime != SAFE_IR_RUNTIME
            or record.manifest.candidate_kind != SAFE_IR_CANDIDATE_KIND
            or record.manifest.entrypoint != SAFE_IR_ENTRYPOINT
            or record.manifest.mode != SubmissionMode.LEADERBOARD
        ):
            raise ArenaSafeWorkerUnavailable("Arena submission runtime is unsupported")

    def _decrypt_and_verify(
        self,
        *,
        stored: StoredArenaCandidateEnvelope,
        record: SubmissionRecord,
        challenge: ChallengeManifest,
    ) -> bytearray:
        binding = stored.binding
        envelope = stored.envelope
        expected_identity = record.identity.to_public_dict()
        checks = (
            binding.challenge_id == record.challenge_id,
            binding.challenge_version == record.challenge_version,
            binding.challenge_manifest_hash == challenge.manifest_hash,
            binding.submission_manifest_hash
            == arena_submission_manifest_hash(record.manifest),
            binding.candidate_commitment == record.candidate_commitment,
            dict(binding.identity) == expected_identity,
            binding.key_id == self._recipient.key_id,
            envelope.key_id == self._recipient.key_id,
            envelope.attestation_report_data == self._recipient.report_data.hex(),
            binding.attestation_report_data_sha256
            == "sha256:" + hashlib.sha256(self._recipient.report_data).hexdigest(),
            envelope.ciphertext_bytes == record.manifest.source_bytes + GCM_TAG_BYTES,
            record.manifest.source_bytes <= SAFE_IR_MAX_CANDIDATE_BYTES,
        )
        if not all(checks):
            raise _CandidateExecutionFailed("Arena candidate binding failed")
        aad = arena_candidate_aad(binding)
        if not hmac.compare_digest(_decode(envelope.aad), aad):
            raise _CandidateExecutionFailed("Arena candidate AAD failed")
        ephemeral = X25519PublicKey.from_public_bytes(
            _decode(envelope.ephemeral_public_key)
        )
        shared_secret = self._recipient.keypair._private.exchange(ephemeral)
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(aad).digest(),
            info=INGRESS_HKDF_INFO,
        ).derive(shared_secret)
        plaintext = AESGCM(aes_key).decrypt(
            _decode(envelope.nonce),
            _decode(envelope.ciphertext),
            aad,
        )
        if len(plaintext) != record.manifest.source_bytes:
            raise _CandidateExecutionFailed("Arena candidate length failed")
        commitment = "sha256:" + hashlib.sha256(plaintext).hexdigest()
        if not hmac.compare_digest(commitment, record.candidate_commitment):
            raise _CandidateExecutionFailed("Arena candidate commitment failed")
        return bytearray(plaintext)

    def _transition(
        self,
        record: SubmissionRecord,
        destination: QueueState,
        reason: QueueReason,
        occurred_at: int,
    ) -> SubmissionRecord:
        return self._arena_store.transition_submission(
            record.submission_id,
            destination,
            reason=reason,
            occurred_at=occurred_at,
        )

    @staticmethod
    def _execution_provenance(
        activation: ArenaSafeWorkerActivation,
        *,
        outcome: str,
    ) -> ExecutionProvenance:
        """Project only commitments; never the quote, signature, or exact score."""

        return ExecutionProvenance(
            outcome=outcome,
            runtime=SAFE_IR_RUNTIME,
            runtime_policy_commitment=activation.runtime_policy_commitment,
            challenge_manifest_hash=activation.challenge_manifest_hash,
            compose_hash=activation.compose_hash,
            app_id=activation.app_id,
            os_image_hash=activation.os_image_hash,
            quote_sha256=activation.quote_sha256,
            verifier_address=activation.verifier_address.lower(),
            verdict_digest=activation.verdict_digest,
            tee_signer_address=activation.tee_signer_address.lower(),
            chain_id=activation.chain_id,
            challenge_registry_address=activation.challenge_registry_address.lower(),
        )

    @staticmethod
    def _receipt(
        record: SubmissionRecord,
        *,
        idempotent: bool,
    ) -> ArenaSafeWorkerReceipt:
        release = (
            record.ladder_release.to_public_dict()
            if record.ladder_release is not None
            else None
        )
        return ArenaSafeWorkerReceipt(
            submission_id=record.submission_id,
            candidate_commitment=record.candidate_commitment,
            final_state=record.state.value,
            failure_code=(
                "execution_failed" if record.state == QueueState.FAILED else "none"
            ),
            ladder_release=release,
            idempotent_replay=idempotent,
        )


def _decode(value: str) -> bytes:
    # Envelope construction already enforces canonical base64url.  Re-encoding
    # here keeps the worker independently fail-closed if that assumption drifts.
    try:
        decoded = base64.b64decode(
            value + ("=" * ((-len(value)) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except Exception as exc:
        raise _CandidateExecutionFailed("Arena candidate encoding failed") from exc
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise _CandidateExecutionFailed("Arena candidate encoding failed")
    return decoded


def _validate_evaluator_controls(values: Sequence[float]) -> tuple[float, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise ArenaSafeWorkerUnavailable("Arena evaluator controls are malformed")
    try:
        output = tuple(float(value) for value in values)
    except (TypeError, ValueError) as exc:
        raise ArenaSafeWorkerUnavailable(
            "Arena evaluator controls are malformed"
        ) from exc
    if len(output) < 2 or len(output) > 512 or not all(
        math.isfinite(value) for value in output
    ):
        raise ArenaSafeWorkerUnavailable("Arena evaluator controls are malformed")
    return output


def _collect_live_arena_attestation(
    *,
    recipient: ArenaIngressRecipient,
    expected_compose_hash: str,
    expected_app_id: str,
    expected_os_image_hash: str,
    expected_tee_signer_address: str,
    chain_id: int,
    challenge_registry_address: str,
    challenge_digest: bytes,
) -> ArenaAttestationPacket:
    """Collect one quote and locally bind the exact packet sent to QVL."""

    if not dstack_utils.is_dstack_enabled():
        raise ArenaSafeWorkerUnavailable("Arena worker requires a dstack CVM")
    if dstack_utils.is_dstack_simulator() or os.environ.get(
        "DSTACK_SIMULATOR_ENDPOINT", ""
    ).strip():
        raise ArenaSafeWorkerUnavailable("Arena worker rejects the dstack simulator")
    try:
        if (
            not isinstance(challenge_digest, bytes)
            or len(challenge_digest) != 32
            or not any(challenge_digest)
        ):
            raise ArenaSafeWorkerUnavailable("Arena QVL challenge is malformed")
        details = dstack_utils.get_attestation_details(
            recipient.report_data + challenge_digest
        )
    except Exception as exc:
        raise ArenaSafeWorkerUnavailable(
            "Arena worker could not refresh dstack evidence"
        ) from exc
    if not isinstance(details, dict):
        raise ArenaSafeWorkerUnavailable("Arena worker live evidence is malformed")
    compose_hash = str(details.get("compose_hash") or "").lower().removeprefix("0x")
    os_image_hash = str(details.get("os_image_hash") or "").lower().removeprefix("0x")
    app_id = str(details.get("app_id") or "")
    quote_text = str(details.get("quote") or "").lower().removeprefix("0x")
    report_text = (
        str(details.get("quote_report_data") or "").lower().removeprefix("0x")
    )
    if (
        compose_hash != expected_compose_hash
        or app_id != expected_app_id
        or os_image_hash != expected_os_image_hash
    ):
        raise ArenaSafeWorkerUnavailable(
            "Arena worker live measurements do not match stable release pins"
        )
    try:
        if (
            not quote_text
            or not (
                MIN_TDX_QUOTE_BYTES * 2
                <= len(quote_text)
                <= MAX_TDX_QUOTE_BYTES * 2
            )
            or len(quote_text) % 2
            or not re.fullmatch(r"[0-9a-f]+", quote_text)
            or len(report_text) not in {64, 128}
            or not re.fullmatch(r"[0-9a-f]+", report_text)
        ):
            raise ValueError("malformed live evidence")
        quote_bytes = bytes.fromhex(quote_text)
        report_bytes = bytes.fromhex(report_text)
    except ValueError as exc:
        raise ArenaSafeWorkerUnavailable(
            "Arena worker received malformed live TDX evidence"
        ) from exc
    expected_report_data = recipient.report_data
    if (
        len(report_bytes) != 64
        or report_bytes[:32] != expected_report_data
        or report_bytes[32:] != challenge_digest
    ):
        raise ArenaSafeWorkerUnavailable(
            "Arena worker live report data does not bind the recipient"
        )
    quote_hash = hashlib.sha256(quote_bytes).hexdigest()
    evidence = SignerAttestationEvidence(
        mode="tdx",
        signer_address=expected_tee_signer_address,
        chain_id=chain_id,
        contract_address=challenge_registry_address,
        report_data="0x" + expected_report_data.hex(),
        quote_report_data="0x" + expected_report_data.hex(),
        quote_hash="0x" + quote_hash,
        quote_size=len(quote_bytes),
        compose_hash="0x" + expected_compose_hash,
        app_id=expected_app_id,
        os_image_hash=expected_os_image_hash,
    )
    return ArenaAttestationPacket(
        evidence=evidence,
        quote="0x" + quote_text,
    )


def _validate_live_attestation_packet(
    packet: ArenaAttestationPacket,
    *,
    recipient: ArenaIngressRecipient,
    expected_compose_hash: str,
    expected_app_id: str,
    expected_os_image_hash: str,
    expected_tee_signer_address: str,
    chain_id: int,
    challenge_registry_address: str,
) -> str:
    """Recompute the dynamic quote fields before sending the packet to QVL.

    The packet's expectation is never trusted as a declaration.  It must bind
    the exact stable Arena X25519 recipient and release pins retained by the
    provider, while the quote hash and byte count are recomputed from the raw
    quote that is about to be sent.
    """

    quote = packet.quote
    if (
        not isinstance(quote, str)
        or not quote.startswith("0x")
        or not (
            2 + MIN_TDX_QUOTE_BYTES * 2
            <= len(quote)
            <= 2 + MAX_TDX_QUOTE_BYTES * 2
        )
        or len(quote) % 2
        or not re.fullmatch(r"0x[0-9a-f]+", quote)
    ):
        raise ArenaSafeWorkerUnavailable(
            "Arena worker live attestation packet is malformed"
        )
    try:
        quote_bytes = bytes.fromhex(quote[2:])
        signer = normalize_address(packet.evidence.signer_address)
        registry = normalize_address(packet.evidence.contract_address)
    except Exception as exc:
        raise ArenaSafeWorkerUnavailable(
            "Arena worker live attestation packet is malformed"
        ) from exc
    quote_hash = hashlib.sha256(quote_bytes).hexdigest()
    report_data = "0x" + recipient.report_data.hex()
    evidence = packet.evidence
    if (
        not isinstance(evidence, SignerAttestationEvidence)
        or evidence.mode != "tdx"
        or signer != expected_tee_signer_address
        or isinstance(evidence.chain_id, bool)
        or evidence.chain_id != chain_id
        or registry != challenge_registry_address
        or evidence.report_data != report_data
        or evidence.quote_report_data != report_data
        or evidence.quote_hash != "0x" + quote_hash
        or isinstance(evidence.quote_size, bool)
        or evidence.quote_size != len(quote_bytes)
        or evidence.compose_hash != "0x" + expected_compose_hash
        or evidence.app_id != expected_app_id
        or evidence.os_image_hash != expected_os_image_hash
    ):
        raise ArenaSafeWorkerUnavailable(
            "Arena worker live attestation packet does not match release pins"
        )
    return "sha256:" + quote_hash


def _raw_hex_32(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise ArenaSafeWorkerUnavailable(f"Arena worker {label} binding is malformed")
    normalized = value.lower().removeprefix("0x")
    if not _HEX_64.fullmatch(normalized) or normalized == "0" * 64:
        raise ArenaSafeWorkerUnavailable(f"Arena worker {label} binding is malformed")
    return normalized


def _sha256_value(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise ArenaSafeWorkerUnavailable(f"Arena worker {label} binding is malformed")
    normalized = value.lower()
    if normalized.startswith("0x"):
        normalized = "sha256:" + normalized[2:]
    if not _SHA256.fullmatch(normalized) or normalized == "sha256:" + "0" * 64:
        raise ArenaSafeWorkerUnavailable(f"Arena worker {label} binding is malformed")
    return normalized
