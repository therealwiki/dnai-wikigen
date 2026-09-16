"""Signed, policy/profile-scoped, single-use QVL freshness challenges."""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Callable

from .errors import CapacityExceeded, VerificationRejected, VerifierUnavailable
from .models import (
    ArenaCandidateIngressBinding,
    ComputeMeteringSignerBinding,
    ComputeWorkloadRecipientBinding,
    DiligenceResultSignerBinding,
    ExecutionPolicyAnchorWriterBinding,
    IdentityAttestationRequest,
    QvlChallenge,
    QvlChallengeRequest,
    QvlProfile,
    ReportDataBinding,
    ReleasePolicy,
)
from .signing import VerdictSigner


CHALLENGE_DOMAIN = b"dnai-wikigen/attestation-qvl/challenge/v2\x00"
ACTIVATION_CHALLENGE_DOMAIN = (
    b"dnai-wikigen/qvl-identity-challenge/v3\x00"
)
MAX_CHALLENGE_TTL_SECONDS = 120
QVL_IDENTITY_DOMAIN_PROFILES: dict[str, tuple[QvlProfile, ...]] = {
    "diligence_qvl_cvm": (
        "diligence",
        "royalty_settlement",
        "email_oracle_kms_restart",
    ),
    "arena_qvl_cvm": ("arena",),
    "anchor_writer_qvl_cvm": ("execution_policy_anchor_writer",),
    "compute_workload_qvl_cvm": ("compute_workload",),
    "compute_metering_qvl_cvm": ("compute_metering",),
}
QVL_PROFILE_TARGET_DOMAIN: dict[QvlProfile, str] = {
    "diligence": "main_runtime_cvm",
    "royalty_settlement": "main_runtime_cvm",
    "arena": "main_runtime_cvm",
    "execution_policy_anchor_writer": "main_runtime_cvm",
    "compute_workload": "main_runtime_cvm",
    "compute_metering": "independent_metering_cvm",
    "email_oracle_kms_restart": "main_runtime_cvm",
}


def qvl_profile(binding: ReportDataBinding) -> QvlProfile:
    if isinstance(binding, DiligenceResultSignerBinding):
        return "diligence"
    if isinstance(binding, ArenaCandidateIngressBinding):
        return "arena"
    if isinstance(binding, ExecutionPolicyAnchorWriterBinding):
        return "execution_policy_anchor_writer"
    if isinstance(binding, ComputeWorkloadRecipientBinding):
        return "compute_workload"
    if isinstance(binding, ComputeMeteringSignerBinding):
        return "compute_metering"
    raise VerifierUnavailable


def qvl_profiles(policy: ReleasePolicy) -> tuple[QvlProfile, ...]:
    profiles: list[QvlProfile] = [qvl_profile(policy.report_data_binding)]
    if policy.royalty_settlement_binding is not None:
        profiles.append("royalty_settlement")
    if policy.email_oracle_kms_restart_binding is not None:
        profiles.append("email_oracle_kms_restart")
    return tuple(profiles)


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def challenge_digest(challenge: QvlChallenge | dict[str, object]) -> str:
    payload = (
        challenge.model_dump(mode="json", by_alias=True)
        if isinstance(challenge, QvlChallenge)
        else dict(challenge)
    )
    payload.pop("challenge_digest", None)
    payload.pop("verifier_signature", None)
    expected = {
        "schema",
        "chain_id",
        "domain",
        "profile",
        "cvm_id",
        "deployment_intent_sha256",
        "release_authority_sha256",
        "ceremony_nonce",
        "measurement_policy_sha256",
        "release_policy_hash",
        "challenge_id",
        "issued_at",
        "expires_at",
        "verifier_address",
    }
    if set(payload) != expected:
        raise VerifierUnavailable
    return "0x" + hashlib.sha256(CHALLENGE_DOMAIN + _canonical(payload)).hexdigest()


def activation_challenge_digest(request: IdentityAttestationRequest | dict[str, object]) -> str:
    payload = (
        request.model_dump(mode="json", by_alias=True)
        if isinstance(request, IdentityAttestationRequest)
        else dict(request)
    )
    payload.pop("challenge_digest", None)
    expected = {
        "schema",
        "chain_id",
        "domain",
        "profile",
        "cvm_id",
        "deployment_intent_sha256",
        "release_authority_sha256",
        "ceremony_nonce",
        "measurement_policy_sha256",
        "app_id",
        "compose_hash",
        "os_image_hash",
        "challenge_id",
        "issued_at",
        "expires_at",
    }
    if set(payload) != expected:
        raise VerificationRejected
    return "0x" + hashlib.sha256(
        ACTIVATION_CHALLENGE_DOMAIN + _canonical(payload)
    ).hexdigest()


def validate_activation_challenge(
    request: IdentityAttestationRequest,
    *,
    now: int,
    max_ttl_seconds: int,
) -> None:
    if (
        max_ttl_seconds < 1
        or max_ttl_seconds > MAX_CHALLENGE_TTL_SECONDS
        or request.profile not in QVL_IDENTITY_DOMAIN_PROFILES.get(
            request.domain, ()
        )
        or request.challenge_digest != activation_challenge_digest(request)
        or request.issued_at > now + 5
        or request.expires_at <= now
        or request.expires_at - request.issued_at > max_ttl_seconds
    ):
        raise VerificationRejected


@dataclass
class _StoredChallenge:
    challenge: QvlChallenge
    state: str = "fresh"


class OneTimeChallengeStore:
    """Bounded one-process store with atomic fresh -> reserved -> consumed states."""

    def __init__(
        self,
        *,
        profiles: tuple[QvlProfile, ...],
        policy_hash: str,
        signer: VerdictSigner,
        ttl_seconds: int,
        maximum: int,
        clock: Callable[[], int] | None = None,
        random_bytes: Callable[[int], bytes] | None = None,
    ) -> None:
        if not 1 <= ttl_seconds <= MAX_CHALLENGE_TTL_SECONDS:
            raise VerifierUnavailable
        if not 1 <= maximum <= 65_536:
            raise VerifierUnavailable
        if not profiles or len(set(profiles)) != len(profiles):
            raise VerifierUnavailable
        self.profiles = profiles
        self.policy_hash = policy_hash
        self.signer = signer
        self.ttl_seconds = ttl_seconds
        self.maximum = maximum
        self._clock = clock or (lambda: int(time.time()))
        self._random_bytes = random_bytes or secrets.token_bytes
        self._entries: OrderedDict[str, _StoredChallenge] = OrderedDict()
        self._lock = asyncio.Lock()

    def _prune(self, now: int) -> None:
        expired = [
            key
            for key, entry in self._entries.items()
            if entry.challenge.expires_at <= now
        ]
        for key in expired:
            self._entries.pop(key, None)

    async def issue(self, request: "QvlChallengeRequest") -> QvlChallenge:
        now = int(self._clock())
        async with self._lock:
            self._prune(now)
            if (
                request.profile not in self.profiles
                or QVL_PROFILE_TARGET_DOMAIN.get(request.profile)
                != request.domain
            ):
                raise VerificationRejected
            if len(self._entries) >= self.maximum:
                raise CapacityExceeded
            challenge_id = ""
            for _ in range(8):
                candidate = "0x" + self._random_bytes(32).hex()
                if int(candidate[2:], 16) != 0 and candidate not in self._entries:
                    challenge_id = candidate
                    break
            if not challenge_id:
                raise VerifierUnavailable
            unsigned: dict[str, object] = {
                "schema": "dnai.attestation-qvl-challenge.v2",
                "chain_id": request.chain_id,
                "domain": request.domain,
                "profile": request.profile,
                "cvm_id": request.cvm_id,
                "deployment_intent_sha256": request.deployment_intent_sha256,
                "release_authority_sha256": request.release_authority_sha256,
                "ceremony_nonce": request.ceremony_nonce,
                "measurement_policy_sha256": request.measurement_policy_sha256,
                "release_policy_hash": self.policy_hash,
                "challenge_id": challenge_id,
                "issued_at": now,
                "expires_at": now + self.ttl_seconds,
                "verifier_address": self.signer.address,
            }
            digest = challenge_digest(unsigned)
            challenge = QvlChallenge.model_validate(
                {
                    **unsigned,
                    "challenge_digest": digest,
                    "verifier_signature": self.signer.sign_digest(digest),
                },
                strict=True,
            )
            self._entries[challenge_id] = _StoredChallenge(challenge=challenge)
            return challenge

    @asynccontextmanager
    async def reserve(self, challenge: QvlChallenge) -> AsyncIterator[None]:
        now = int(self._clock())
        async with self._lock:
            self._prune(now)
            stored = self._entries.get(challenge.challenge_id)
            if (
                stored is None
                or stored.state != "fresh"
                or stored.challenge != challenge
                or challenge.profile not in self.profiles
                or QVL_PROFILE_TARGET_DOMAIN.get(challenge.profile)
                != challenge.domain
                or challenge.release_policy_hash != self.policy_hash
                or challenge.verifier_address != self.signer.address
                or challenge.challenge_digest != challenge_digest(challenge)
                or challenge.issued_at > now + 5
                or challenge.expires_at <= now
                or challenge.expires_at - challenge.issued_at != self.ttl_seconds
            ):
                raise VerificationRejected
            stored.state = "reserved"
        try:
            yield
        finally:
            async with self._lock:
                stored = self._entries.get(challenge.challenge_id)
                if stored is not None:
                    stored.state = "consumed"

    async def state(self, challenge_id: str) -> str | None:
        """Test/diagnostic seam; never exposed over HTTP."""

        async with self._lock:
            entry = self._entries.get(challenge_id)
            return entry.state if entry else None
