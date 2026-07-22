"""Durable, bounded domain state for the public sealed-challenge Arena.

This module intentionally has no HTTP, wallet-authentication, queue-worker, or
candidate-execution integration.  The caller must authenticate the wallet and
project before supplying :class:`SubmissionIdentity`.  Candidate plaintext is
not an accepted field: only a SHA-256 commitment and an opaque encrypted-object
reference may be persisted.

The initial catalog contains a Python assay-QC preview and a capability-free
DNASeq variant-QC safe-IR challenge. The generic Python execution capability is
deliberately fixed to ``modeled`` and ``non_hardened``. Safe-IR rows carry their
own bounded execution provenance; a catalog capability or worker heartbeat
alone can never upgrade a row into verified execution evidence.

Exact rewards are also outside this module's input surface.  A leaderboard
release must arrive as the bounded :class:`~tinker_delegate.ladder_release.LadderRelease`
produced inside the evaluator boundary.  The public ranking includes accepted
Ladder improvements only, never the re-released running best attached to a
rejected candidate.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from tinker_delegate.arena_safe_ir import (
    SAFE_IR_CANDIDATE_KIND,
    SAFE_IR_ENTRYPOINT,
    SAFE_IR_MAX_CANDIDATE_BYTES,
    SAFE_IR_RUNTIME,
)
from tinker_delegate.ladder_release import LadderLeaderboard, LadderPolicy, LadderRelease


STORE_SCHEMA_VERSION = 2
CATALOG_SCHEMA_VERSION = 1
CHALLENGE_SCHEMA_VERSION = 1
SUBMISSION_SCHEMA_VERSION = 1
PUBLIC_SUBMISSION_SCHEMA_VERSION = 2
PUBLIC_QUEUE_SCHEMA_VERSION = 2
PUBLIC_LEADERBOARD_SCHEMA_VERSION = 2
PUBLIC_OWNER_SUBMISSIONS_SCHEMA_VERSION = 2

MAX_STORE_BYTES = 8 * 1024 * 1024
MAX_CHALLENGES = 32
MAX_SUBMISSIONS = 10_000
MAX_QUEUE_EVENTS = 32
MAX_PUBLIC_LEADERBOARD_ROWS = 100
MAX_OWNER_SUBMISSION_ROWS = 100
MAX_ENCRYPTED_REFERENCE_BYTES = 512
MAX_IDEMPOTENCY_KEY_BYTES = 128
MAX_PROJECT_ID_BYTES = 64
MAX_TIMESTAMP = 4_102_444_800  # 2100-01-01 UTC; bounds caller-controlled integers.

BIO_CHALLENGE_ID = "synthetic-bio-assay-qc"
BIO_CHALLENGE_VERSION = "1.0.0"
BIO_CHALLENGE_SLUG = "synthetic-assay-qc-season-01"
BIO_CANDIDATE_KIND = "python_assay_qc_program"
BIO_RUNTIME = "python3.11"
BIO_ENTRYPOINT = "process"
BIO_MAX_SOURCE_BYTES = 8_192
BIO_LADDER_STEP_DENOMINATOR = 20
BIO_MAX_LADDER_SUBMISSIONS = 32

DNASEQ_SAFE_IR_CHALLENGE_ID = "dnaseq-variant-qc-safe-ir"
DNASEQ_SAFE_IR_CHALLENGE_VERSION = "1.0.0"
DNASEQ_SAFE_IR_CHALLENGE_SLUG = "dnaseq-variant-qc-safe-ir-season-01"

# Compatibility aliases for older source integrations. They intentionally point
# at the new canonical challenge; the previous assay-QC safe-IR identifier is no
# longer present in the immutable default catalog.
BIO_SAFE_IR_CHALLENGE_ID = DNASEQ_SAFE_IR_CHALLENGE_ID
BIO_SAFE_IR_CHALLENGE_VERSION = DNASEQ_SAFE_IR_CHALLENGE_VERSION
BIO_SAFE_IR_CHALLENGE_SLUG = DNASEQ_SAFE_IR_CHALLENGE_SLUG

MODELED_EXECUTION_WARNING = (
    "Modeled queue only. The current local AST/subprocess sandbox is non-hardened "
    "and must not execute hostile public code."
)
SAFE_IR_EXECUTION_WARNING = (
    "Capability-free DNASeq safe-IR runtime implemented and adversarially tested, but "
    "the dedicated attested worker, independent deployment authorization, and "
    "on-chain evaluator binding are not connected. Execution remains disabled."
)
SAFE_IR_PREVIEW_BACKEND = "dnai_safe_ir_v1_preview"
PRODUCT_STATUS = "modeled"
EXECUTION_ASSURANCE = "projection_only_no_hardened_executor"
PER_ROW_PRODUCT_STATUS = "per_row"
PER_ROW_EXECUTION_ASSURANCE = "per_submission_execution_provenance"
WORKER_REPORTED_EVIDENCE_CLASSIFICATION = (
    "worker_reported_qvl_binding_not_independently_verified"
)

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_WALLET_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_PROJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ENCRYPTED_REFERENCE = re.compile(
    r"^(?:sealed|r2)://[A-Za-z0-9][A-Za-z0-9._/-]{2,500}$"
)
_REFERENCE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SUBMISSION_ID = re.compile(r"^sub_[0-9a-f]{24}$")


class ArenaStoreError(ValueError):
    """Raised when Arena state or an operation fails closed."""


class ArenaStoreCorruptError(ArenaStoreError):
    """Raised when persisted state is malformed, inconsistent, or oversized."""


class ArenaIdempotencyConflict(ArenaStoreError):
    """Raised when an idempotency key is reused for a different request."""


class SubmissionMode(str, Enum):
    TEST = "test"
    BENCHMARK = "benchmark"
    LEADERBOARD = "leaderboard"


class QueueState(str, Enum):
    SUBMITTED = "submitted"
    POLICY_SCREEN = "policy_screen"
    QUEUED = "queued"
    PROVISIONING = "provisioning"
    PUBLIC_TESTS = "public_tests"
    SEALED_EVAL = "sealed_eval"
    REVIEW_HOLD = "review_hold"
    COMPLETED = "completed"
    FAILED = "failed"
    WITHHELD = "withheld"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    DEAD_LETTER = "dead_letter"


class QueueReason(str, Enum):
    CALLER_SUBMITTED = "caller_submitted"
    POLICY_CHECK_STARTED = "policy_check_started"
    POLICY_PASSED = "policy_passed"
    WORKER_CLAIMED = "worker_claimed"
    PUBLIC_TESTS_STARTED = "public_tests_started"
    SEALED_EVALUATION_STARTED = "sealed_evaluation_started"
    HUMAN_REVIEW_REQUIRED = "human_review_required"
    EVALUATION_COMPLETED = "evaluation_completed"
    EXECUTION_FAILED = "execution_failed"
    POLICY_WITHHELD = "policy_withheld"
    CALLER_CANCELLED = "caller_cancelled"
    QUEUE_EXPIRED = "queue_expired"
    RETRY_EXHAUSTED = "retry_exhausted"


_ALLOWED_TRANSITIONS: dict[QueueState, frozenset[QueueState]] = {
    QueueState.SUBMITTED: frozenset(
        {QueueState.POLICY_SCREEN, QueueState.CANCELLED, QueueState.FAILED}
    ),
    QueueState.POLICY_SCREEN: frozenset(
        {
            QueueState.QUEUED,
            QueueState.REVIEW_HOLD,
            QueueState.WITHHELD,
            QueueState.CANCELLED,
            QueueState.FAILED,
        }
    ),
    QueueState.QUEUED: frozenset(
        {
            QueueState.PROVISIONING,
            QueueState.CANCELLED,
            QueueState.EXPIRED,
            QueueState.DEAD_LETTER,
            QueueState.FAILED,
        }
    ),
    QueueState.PROVISIONING: frozenset(
        {
            QueueState.PUBLIC_TESTS,
            QueueState.CANCELLED,
            QueueState.DEAD_LETTER,
            QueueState.FAILED,
        }
    ),
    QueueState.PUBLIC_TESTS: frozenset(
        {
            QueueState.SEALED_EVAL,
            QueueState.REVIEW_HOLD,
            QueueState.WITHHELD,
            QueueState.FAILED,
        }
    ),
    QueueState.SEALED_EVAL: frozenset(
        {
            QueueState.REVIEW_HOLD,
            QueueState.COMPLETED,
            QueueState.WITHHELD,
            QueueState.FAILED,
        }
    ),
    QueueState.REVIEW_HOLD: frozenset(
        {
            QueueState.QUEUED,
            QueueState.SEALED_EVAL,
            QueueState.COMPLETED,
            QueueState.WITHHELD,
            QueueState.CANCELLED,
            QueueState.EXPIRED,
        }
    ),
    QueueState.COMPLETED: frozenset(),
    QueueState.FAILED: frozenset(),
    QueueState.WITHHELD: frozenset(),
    QueueState.CANCELLED: frozenset(),
    QueueState.EXPIRED: frozenset(),
    QueueState.DEAD_LETTER: frozenset(),
}

_EXPECTED_REASON_FOR_STATE: dict[QueueState, frozenset[QueueReason]] = {
    QueueState.POLICY_SCREEN: frozenset({QueueReason.POLICY_CHECK_STARTED}),
    QueueState.QUEUED: frozenset({QueueReason.POLICY_PASSED}),
    QueueState.PROVISIONING: frozenset({QueueReason.WORKER_CLAIMED}),
    QueueState.PUBLIC_TESTS: frozenset({QueueReason.PUBLIC_TESTS_STARTED}),
    QueueState.SEALED_EVAL: frozenset({QueueReason.SEALED_EVALUATION_STARTED}),
    QueueState.REVIEW_HOLD: frozenset({QueueReason.HUMAN_REVIEW_REQUIRED}),
    QueueState.COMPLETED: frozenset({QueueReason.EVALUATION_COMPLETED}),
    QueueState.FAILED: frozenset({QueueReason.EXECUTION_FAILED}),
    QueueState.WITHHELD: frozenset({QueueReason.POLICY_WITHHELD}),
    QueueState.CANCELLED: frozenset({QueueReason.CALLER_CANCELLED}),
    QueueState.EXPIRED: frozenset({QueueReason.QUEUE_EXPIRED}),
    QueueState.DEAD_LETTER: frozenset({QueueReason.RETRY_EXHAUSTED}),
}


def _require_exact_keys(
    payload: Mapping[str, Any], expected: frozenset[str], *, label: str
) -> None:
    if not isinstance(payload, Mapping):
        raise ArenaStoreError(f"{label} must be an object")
    actual = set(payload)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ArenaStoreError(
            f"{label} fields are not allowlisted (missing={missing}, unknown={unknown})"
        )


def _require_int(value: Any, *, label: str, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArenaStoreError(f"{label} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        suffix = f" and <= {maximum}" if maximum is not None else ""
        raise ArenaStoreError(f"{label} must be >= {minimum}{suffix}")
    return value


def _require_bool(value: Any, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise ArenaStoreError(f"{label} must be a boolean")
    return value


def _require_bounded_string(
    value: Any, *, label: str, minimum_bytes: int = 1, maximum_bytes: int
) -> str:
    if not isinstance(value, str):
        raise ArenaStoreError(f"{label} must be a string")
    size = len(value.encode("utf-8"))
    if size < minimum_bytes or size > maximum_bytes:
        raise ArenaStoreError(
            f"{label} must be between {minimum_bytes} and {maximum_bytes} UTF-8 bytes"
        )
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ArenaStoreError(f"{label} contains control characters")
    return value


def _canonical_json(payload: Any) -> bytes:
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ArenaStoreError("Arena value is not canonical JSON") from exc


def _sha256_json(payload: Any, *, prefix: str) -> str:
    digest = hashlib.sha256()
    digest.update(prefix.encode("ascii"))
    digest.update(b"\0")
    digest.update(_canonical_json(payload))
    return digest.hexdigest()


@dataclass(frozen=True)
class ExecutionCapability:
    """A capability record that can represent only the current safe truth."""

    status: str = "modeled"
    isolation: str = "non_hardened"
    backend: str = "local_ast_subprocess_demo"
    hostile_code_ready: bool = False
    live_execution: bool = False
    worker_connected: bool = False
    warning: str = MODELED_EXECUTION_WARNING

    _FIELDS = frozenset(
        {
            "status",
            "isolation",
            "backend",
            "hostile_code_ready",
            "live_execution",
            "worker_connected",
            "warning",
        }
    )

    def __post_init__(self) -> None:
        actual = (
            self.status,
            self.isolation,
            self.backend,
            self.hostile_code_ready,
            self.live_execution,
            self.worker_connected,
            self.warning,
        )
        allowed = {
            (
                "modeled",
                "non_hardened",
                "local_ast_subprocess_demo",
                False,
                False,
                False,
                MODELED_EXECUTION_WARNING,
            ),
            (
                "modeled",
                "non_hardened",
                SAFE_IR_PREVIEW_BACKEND,
                False,
                False,
                False,
                SAFE_IR_EXECUTION_WARNING,
            ),
        }
        if actual not in allowed:
            raise ArenaStoreError(
                "Arena execution capability must remain modeled, non-hardened, "
                "disconnected, and unsafe for hostile code"
            )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "isolation": self.isolation,
            "backend": self.backend,
            "hostile_code_ready": self.hostile_code_ready,
            "live_execution": self.live_execution,
            "worker_connected": self.worker_connected,
            "warning": self.warning,
        }

    @classmethod
    def from_public_dict(cls, payload: Mapping[str, Any]) -> "ExecutionCapability":
        _require_exact_keys(payload, cls._FIELDS, label="execution capability")
        return cls(
            status=str(payload["status"]),
            isolation=str(payload["isolation"]),
            backend=str(payload["backend"]),
            hostile_code_ready=_require_bool(
                payload["hostile_code_ready"], label="hostile_code_ready"
            ),
            live_execution=_require_bool(payload["live_execution"], label="live_execution"),
            worker_connected=_require_bool(
                payload["worker_connected"], label="worker_connected"
            ),
            warning=str(payload["warning"]),
        )


@dataclass(frozen=True)
class ChallengeManifest:
    challenge_id: str
    version: str
    slug: str
    title: str
    summary: str
    environment: str
    candidate_kind: str
    runtime: str
    entrypoint: str
    max_source_bytes: int
    metric: str
    ladder_policy: LadderPolicy
    execution_capability: ExecutionCapability = ExecutionCapability()
    schema_version: int = CHALLENGE_SCHEMA_VERSION
    synthetic_only: bool = True
    raw_data_egress: bool = False
    exact_reward_egress: bool = False

    _FIELDS = frozenset(
        {
            "surface",
            "schema_version",
            "challenge_id",
            "version",
            "slug",
            "title",
            "summary",
            "environment",
            "candidate",
            "data_policy",
            "evaluation",
            "execution_capability",
            "product_status",
            "execution_assurance",
            "manifest_hash",
            "raw_secret_egress",
        }
    )
    _CANDIDATE_FIELDS = frozenset(
        {"kind", "runtime", "entrypoint", "max_source_bytes"}
    )
    _DATA_POLICY_FIELDS = frozenset({"synthetic_only", "raw_data_egress"})
    _EVALUATION_FIELDS = frozenset(
        {
            "metric",
            "direction",
            "release_mechanism",
            "ladder_policy",
            "exact_reward_egress",
        }
    )
    _LADDER_FIELDS = frozenset(
        {"step_denominator", "max_improvement_steps", "max_submissions"}
    )

    def __post_init__(self) -> None:
        _require_int(self.schema_version, label="challenge schema_version", minimum=1, maximum=1)
        if not _IDENTIFIER.fullmatch(self.challenge_id):
            raise ArenaStoreError("challenge_id is malformed")
        if not _SEMVER.fullmatch(self.version):
            raise ArenaStoreError("challenge version must be strict semver")
        if not _SLUG.fullmatch(self.slug):
            raise ArenaStoreError("challenge slug is malformed")
        _require_bounded_string(self.title, label="challenge title", maximum_bytes=96)
        _require_bounded_string(self.summary, label="challenge summary", maximum_bytes=512)
        for label, value in (
            ("environment", self.environment),
            ("candidate_kind", self.candidate_kind),
            ("runtime", self.runtime),
            ("entrypoint", self.entrypoint),
            ("metric", self.metric),
        ):
            _require_bounded_string(value, label=label, maximum_bytes=64)
        _require_int(
            self.max_source_bytes,
            label="max_source_bytes",
            minimum=1,
            maximum=65_536,
        )
        if not isinstance(self.ladder_policy, LadderPolicy):
            raise ArenaStoreError("ladder_policy must be a LadderPolicy")
        if self.ladder_policy.max_submissions is None:
            raise ArenaStoreError("public Arena Ladder must have a bounded submission budget")
        if not isinstance(self.execution_capability, ExecutionCapability):
            raise ArenaStoreError("execution_capability is malformed")
        if self.synthetic_only is not True:
            raise ArenaStoreError("the initial BIO Arena challenge must be synthetic-only")
        if self.raw_data_egress is not False or self.exact_reward_egress is not False:
            raise ArenaStoreError("raw data and exact reward egress must remain disabled")

    def _unsigned_public_dict(self) -> dict[str, Any]:
        return {
            "surface": "arena_challenge_manifest",
            "schema_version": self.schema_version,
            "challenge_id": self.challenge_id,
            "version": self.version,
            "slug": self.slug,
            "title": self.title,
            "summary": self.summary,
            "environment": self.environment,
            "candidate": {
                "kind": self.candidate_kind,
                "runtime": self.runtime,
                "entrypoint": self.entrypoint,
                "max_source_bytes": self.max_source_bytes,
            },
            "data_policy": {
                "synthetic_only": self.synthetic_only,
                "raw_data_egress": self.raw_data_egress,
            },
            "evaluation": {
                "metric": self.metric,
                "direction": "higher_is_better",
                "release_mechanism": "fixed_eta_ladder",
                "ladder_policy": self.ladder_policy.to_public_dict(),
                "exact_reward_egress": self.exact_reward_egress,
            },
            "execution_capability": self.execution_capability.to_public_dict(),
            "product_status": PRODUCT_STATUS,
            "execution_assurance": EXECUTION_ASSURANCE,
            "raw_secret_egress": False,
        }

    @property
    def manifest_hash(self) -> str:
        return _sha256_json(self._unsigned_public_dict(), prefix="arena_challenge_manifest")

    def to_public_dict(self) -> dict[str, Any]:
        payload = self._unsigned_public_dict()
        payload["manifest_hash"] = self.manifest_hash
        return payload

    @classmethod
    def from_public_dict(cls, payload: Mapping[str, Any]) -> "ChallengeManifest":
        _require_exact_keys(payload, cls._FIELDS, label="challenge manifest")
        if payload["surface"] != "arena_challenge_manifest":
            raise ArenaStoreError("unsupported challenge manifest surface")
        if (
            payload["product_status"] != PRODUCT_STATUS
            or payload["execution_assurance"] != EXECUTION_ASSURANCE
        ):
            raise ArenaStoreError("challenge execution status must remain modeled")
        if payload["raw_secret_egress"] is not False:
            raise ArenaStoreError("challenge manifest must report raw_secret_egress=false")
        candidate = payload["candidate"]
        data_policy = payload["data_policy"]
        evaluation = payload["evaluation"]
        if (
            not isinstance(candidate, Mapping)
            or not isinstance(data_policy, Mapping)
            or not isinstance(evaluation, Mapping)
        ):
            raise ArenaStoreError("challenge manifest contains malformed nested objects")
        _require_exact_keys(candidate, cls._CANDIDATE_FIELDS, label="candidate schema")
        _require_exact_keys(data_policy, cls._DATA_POLICY_FIELDS, label="data policy")
        _require_exact_keys(evaluation, cls._EVALUATION_FIELDS, label="evaluation policy")
        if evaluation["direction"] != "higher_is_better":
            raise ArenaStoreError("unsupported challenge metric direction")
        if evaluation["release_mechanism"] != "fixed_eta_ladder":
            raise ArenaStoreError("unsupported leaderboard release mechanism")
        ladder = evaluation["ladder_policy"]
        if not isinstance(ladder, Mapping):
            raise ArenaStoreError("ladder policy must be an object")
        _require_exact_keys(ladder, cls._LADDER_FIELDS, label="ladder policy")
        denominator = _require_int(
            ladder["step_denominator"],
            label="step_denominator",
            minimum=1,
            maximum=10_000,
        )
        if ladder["max_improvement_steps"] != denominator:
            raise ArenaStoreError("max_improvement_steps must equal step_denominator")
        max_submissions = _require_int(
            ladder["max_submissions"],
            label="max_submissions",
            minimum=1,
            maximum=MAX_SUBMISSIONS,
        )
        capability = payload["execution_capability"]
        if not isinstance(capability, Mapping):
            raise ArenaStoreError("execution capability must be an object")
        manifest = cls(
            challenge_id=_require_bounded_string(
                payload["challenge_id"], label="challenge_id", maximum_bytes=64
            ),
            version=_require_bounded_string(
                payload["version"], label="challenge version", maximum_bytes=32
            ),
            slug=_require_bounded_string(
                payload["slug"], label="challenge slug", maximum_bytes=96
            ),
            title=_require_bounded_string(
                payload["title"], label="challenge title", maximum_bytes=96
            ),
            summary=_require_bounded_string(
                payload["summary"], label="challenge summary", maximum_bytes=512
            ),
            environment=_require_bounded_string(
                payload["environment"], label="environment", maximum_bytes=64
            ),
            candidate_kind=_require_bounded_string(
                candidate["kind"], label="candidate kind", maximum_bytes=64
            ),
            runtime=_require_bounded_string(
                candidate["runtime"], label="runtime", maximum_bytes=64
            ),
            entrypoint=_require_bounded_string(
                candidate["entrypoint"], label="entrypoint", maximum_bytes=64
            ),
            max_source_bytes=_require_int(
                candidate["max_source_bytes"],
                label="max_source_bytes",
                minimum=1,
                maximum=65_536,
            ),
            metric=_require_bounded_string(
                evaluation["metric"], label="metric", maximum_bytes=64
            ),
            ladder_policy=LadderPolicy(
                step_denominator=denominator,
                max_submissions=max_submissions,
            ),
            execution_capability=ExecutionCapability.from_public_dict(capability),
            schema_version=_require_int(
                payload["schema_version"],
                label="challenge schema_version",
                minimum=1,
                maximum=1,
            ),
            synthetic_only=_require_bool(
                data_policy["synthetic_only"], label="synthetic_only"
            ),
            raw_data_egress=_require_bool(
                data_policy["raw_data_egress"], label="raw_data_egress"
            ),
            exact_reward_egress=_require_bool(
                evaluation["exact_reward_egress"], label="exact_reward_egress"
            ),
        )
        stored_hash = _require_bounded_string(
            payload["manifest_hash"], label="manifest_hash", maximum_bytes=64
        )
        if not _HEX_64.fullmatch(stored_hash) or stored_hash != manifest.manifest_hash:
            raise ArenaStoreError("challenge manifest hash mismatch")
        return manifest


@dataclass(frozen=True)
class ChallengeCatalog:
    challenges: tuple[ChallengeManifest, ...]
    schema_version: int = CATALOG_SCHEMA_VERSION

    _FIELDS = frozenset(
        {
            "surface",
            "schema_version",
            "challenge_count",
            "challenges",
            "product_status",
            "execution_assurance",
            "raw_secret_egress",
        }
    )

    def __post_init__(self) -> None:
        _require_int(self.schema_version, label="catalog schema_version", minimum=1, maximum=1)
        if not isinstance(self.challenges, tuple):
            raise ArenaStoreError("catalog challenges must be a tuple")
        if not self.challenges or len(self.challenges) > MAX_CHALLENGES:
            raise ArenaStoreError(f"catalog must contain 1..{MAX_CHALLENGES} challenges")
        keys: set[tuple[str, str]] = set()
        slugs: set[str] = set()
        for challenge in self.challenges:
            if not isinstance(challenge, ChallengeManifest):
                raise ArenaStoreError("catalog contains malformed challenge")
            key = (challenge.challenge_id, challenge.version)
            if key in keys or challenge.slug in slugs:
                raise ArenaStoreError("catalog challenge versions and slugs must be unique")
            keys.add(key)
            slugs.add(challenge.slug)

    def get(self, challenge_id: str, version: str) -> ChallengeManifest:
        for challenge in self.challenges:
            if challenge.challenge_id == challenge_id and challenge.version == version:
                return challenge
        raise ArenaStoreError("unknown challenge id/version")

    def to_public_dict(self) -> dict[str, Any]:
        challenges = sorted(
            self.challenges, key=lambda item: (item.challenge_id, item.version)
        )
        return {
            "surface": "arena_challenge_catalog",
            "schema_version": self.schema_version,
            "challenge_count": len(challenges),
            "challenges": [challenge.to_public_dict() for challenge in challenges],
            "product_status": PRODUCT_STATUS,
            "execution_assurance": EXECUTION_ASSURANCE,
            "raw_secret_egress": False,
        }

    @classmethod
    def from_public_dict(cls, payload: Mapping[str, Any]) -> "ChallengeCatalog":
        _require_exact_keys(payload, cls._FIELDS, label="challenge catalog")
        if payload["surface"] != "arena_challenge_catalog":
            raise ArenaStoreError("unsupported challenge catalog surface")
        if (
            payload["product_status"] != PRODUCT_STATUS
            or payload["execution_assurance"] != EXECUTION_ASSURANCE
        ):
            raise ArenaStoreError("catalog execution status must remain modeled")
        if payload["raw_secret_egress"] is not False:
            raise ArenaStoreError("challenge catalog must report raw_secret_egress=false")
        raw_challenges = payload["challenges"]
        if not isinstance(raw_challenges, list):
            raise ArenaStoreError("catalog challenges must be an array")
        if len(raw_challenges) > MAX_CHALLENGES:
            raise ArenaStoreError("catalog challenge count exceeds limit")
        challenges = tuple(
            ChallengeManifest.from_public_dict(item)
            if isinstance(item, Mapping)
            else _raise("catalog challenge must be an object")
            for item in raw_challenges
        )
        if payload["challenge_count"] != len(challenges):
            raise ArenaStoreError("catalog challenge_count mismatch")
        return cls(
            challenges=challenges,
            schema_version=_require_int(
                payload["schema_version"],
                label="catalog schema_version",
                minimum=1,
                maximum=1,
            ),
        )


def default_challenge_catalog() -> ChallengeCatalog:
    """Return immutable Python-demo and safe-IR synthetic BIO challenges."""

    return ChallengeCatalog(
        challenges=(
            ChallengeManifest(
                challenge_id=BIO_CHALLENGE_ID,
                version=BIO_CHALLENGE_VERSION,
                slug=BIO_CHALLENGE_SLUG,
                title="Synthetic Assay QC",
                summary=(
                    "Write a bounded Python control-selection program for a sealed, "
                    "synthetic assay plate. Only Ladder-quantized improvement state "
                    "may enter the public ranking."
                ),
                environment="bio_assay_program_qc",
                candidate_kind=BIO_CANDIDATE_KIND,
                runtime=BIO_RUNTIME,
                entrypoint=BIO_ENTRYPOINT,
                max_source_bytes=BIO_MAX_SOURCE_BYTES,
                metric="z_prime_factor",
                ladder_policy=LadderPolicy(
                    step_denominator=BIO_LADDER_STEP_DENOMINATOR,
                    max_submissions=BIO_MAX_LADDER_SUBMISSIONS,
                ),
            ),
            ChallengeManifest(
                challenge_id=DNASEQ_SAFE_IR_CHALLENGE_ID,
                version=DNASEQ_SAFE_IR_CHALLENGE_VERSION,
                slug=DNASEQ_SAFE_IR_CHALLENGE_SLUG,
                title="DNASeq Variant QC · Safe IR",
                summary=(
                    "Select robust subsets from sealed synthetic per-variant quality "
                    "lanes: truth-supported calls and simulated sequencing artifacts. "
                    "Maximize their Z-prime separation without receiving bases, reads, "
                    "alleles, loci, sample IDs, or exact labels. Only a quantized "
                    "Ladder release and bounded execution provenance may leave."
                ),
                environment="synthetic_dnaseq_variant_qc",
                candidate_kind=SAFE_IR_CANDIDATE_KIND,
                runtime=SAFE_IR_RUNTIME,
                entrypoint=SAFE_IR_ENTRYPOINT,
                max_source_bytes=SAFE_IR_MAX_CANDIDATE_BYTES,
                metric="variant_quality_z_prime",
                ladder_policy=LadderPolicy(
                    step_denominator=BIO_LADDER_STEP_DENOMINATOR,
                    max_submissions=BIO_MAX_LADDER_SUBMISSIONS,
                ),
                execution_capability=ExecutionCapability(
                    backend=SAFE_IR_PREVIEW_BACKEND,
                    warning=SAFE_IR_EXECUTION_WARNING,
                ),
            ),
        )
    )


@dataclass(frozen=True)
class SubmissionIdentity:
    """Identity metadata authenticated and supplied by the caller."""

    wallet_address: str
    project_id: str

    _FIELDS = frozenset({"wallet_address", "project_id"})

    def __post_init__(self) -> None:
        if not isinstance(self.wallet_address, str) or not _WALLET_ADDRESS.fullmatch(
            self.wallet_address
        ):
            raise ArenaStoreError("wallet_address must be a 20-byte EVM address")
        if self.wallet_address != self.wallet_address.lower():
            object.__setattr__(self, "wallet_address", self.wallet_address.lower())
        _require_bounded_string(
            self.project_id,
            label="project_id",
            maximum_bytes=MAX_PROJECT_ID_BYTES,
        )
        if not _PROJECT_ID.fullmatch(self.project_id):
            raise ArenaStoreError("project_id is malformed")

    def to_public_dict(self) -> dict[str, str]:
        """Return a stable public pseudonym, never the raw wallet address."""

        return {
            "wallet_address_hash": _sha256_json(
                self.wallet_address, prefix="arena_public_wallet"
            ),
            "project_id_hash": _sha256_json(
                self.project_id, prefix="arena_public_project"
            ),
        }

    def to_persisted_dict(self) -> dict[str, str]:
        return {
            "wallet_address": self.wallet_address,
            "project_id": self.project_id,
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "SubmissionIdentity":
        _require_exact_keys(payload, cls._FIELDS, label="submission identity")
        return cls(
            wallet_address=_require_bounded_string(
                payload["wallet_address"], label="wallet_address", maximum_bytes=42
            ),
            project_id=_require_bounded_string(
                payload["project_id"],
                label="project_id",
                maximum_bytes=MAX_PROJECT_ID_BYTES,
            ),
        )


@dataclass(frozen=True)
class SubmissionManifest:
    """Bounded candidate metadata; source text is structurally impossible here."""

    challenge_manifest_hash: str
    candidate_kind: str
    runtime: str
    entrypoint: str
    source_bytes: int
    mode: SubmissionMode
    schema_version: int = SUBMISSION_SCHEMA_VERSION

    _FIELDS = frozenset(
        {
            "schema_version",
            "challenge_manifest_hash",
            "candidate_kind",
            "runtime",
            "entrypoint",
            "source_bytes",
            "mode",
        }
    )

    def __post_init__(self) -> None:
        _require_int(
            self.schema_version,
            label="submission manifest schema_version",
            minimum=1,
            maximum=1,
        )
        if not isinstance(self.challenge_manifest_hash, str) or not _HEX_64.fullmatch(
            self.challenge_manifest_hash
        ):
            raise ArenaStoreError("challenge_manifest_hash must be lowercase SHA-256")
        for label, value in (
            ("candidate_kind", self.candidate_kind),
            ("runtime", self.runtime),
            ("entrypoint", self.entrypoint),
        ):
            _require_bounded_string(value, label=label, maximum_bytes=64)
        _require_int(self.source_bytes, label="source_bytes", minimum=1, maximum=65_536)
        if not isinstance(self.mode, SubmissionMode):
            raise ArenaStoreError("submission mode is unsupported")

    def validate_for(self, challenge: ChallengeManifest) -> None:
        expected = (
            challenge.manifest_hash,
            challenge.candidate_kind,
            challenge.runtime,
            challenge.entrypoint,
        )
        actual = (
            self.challenge_manifest_hash,
            self.candidate_kind,
            self.runtime,
            self.entrypoint,
        )
        if actual != expected:
            raise ArenaStoreError("submission manifest does not match challenge version")
        if self.source_bytes > challenge.max_source_bytes:
            raise ArenaStoreError("submission source_bytes exceeds challenge maximum")

    def to_public_dict(self) -> dict[str, Any]:
        """Return candidate metadata without its exact private byte length."""

        return {
            "schema_version": self.schema_version,
            "challenge_manifest_hash": self.challenge_manifest_hash,
            "candidate_kind": self.candidate_kind,
            "runtime": self.runtime,
            "entrypoint": self.entrypoint,
            "mode": self.mode.value,
            "private_size_egress": False,
        }

    def to_persisted_dict(self) -> dict[str, Any]:
        """Return the internal manifest used for caps and sealed persistence."""

        return {
            "schema_version": self.schema_version,
            "challenge_manifest_hash": self.challenge_manifest_hash,
            "candidate_kind": self.candidate_kind,
            "runtime": self.runtime,
            "entrypoint": self.entrypoint,
            "source_bytes": self.source_bytes,
            "mode": self.mode.value,
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "SubmissionManifest":
        _require_exact_keys(payload, cls._FIELDS, label="submission manifest")
        try:
            mode = SubmissionMode(str(payload["mode"]))
        except ValueError as exc:
            raise ArenaStoreError("submission mode is unsupported") from exc
        return cls(
            schema_version=_require_int(
                payload["schema_version"],
                label="submission manifest schema_version",
                minimum=1,
                maximum=1,
            ),
            challenge_manifest_hash=_require_bounded_string(
                payload["challenge_manifest_hash"],
                label="challenge_manifest_hash",
                maximum_bytes=64,
            ),
            candidate_kind=_require_bounded_string(
                payload["candidate_kind"], label="candidate_kind", maximum_bytes=64
            ),
            runtime=_require_bounded_string(
                payload["runtime"], label="runtime", maximum_bytes=64
            ),
            entrypoint=_require_bounded_string(
                payload["entrypoint"], label="entrypoint", maximum_bytes=64
            ),
            source_bytes=_require_int(
                payload["source_bytes"],
                label="source_bytes",
                minimum=1,
                maximum=65_536,
            ),
            mode=mode,
        )


@dataclass(frozen=True)
class QueueEvent:
    sequence: int
    from_state: QueueState | None
    to_state: QueueState
    occurred_at: int
    reason: QueueReason

    _FIELDS = frozenset(
        {"sequence", "from_state", "to_state", "occurred_at", "reason"}
    )

    def __post_init__(self) -> None:
        _require_int(
            self.sequence,
            label="queue event sequence",
            minimum=1,
            maximum=MAX_QUEUE_EVENTS,
        )
        _require_int(
            self.occurred_at,
            label="queue event occurred_at",
            minimum=0,
            maximum=MAX_TIMESTAMP,
        )
        if self.from_state is not None and not isinstance(self.from_state, QueueState):
            raise ArenaStoreError("queue event from_state is invalid")
        if not isinstance(self.to_state, QueueState) or not isinstance(self.reason, QueueReason):
            raise ArenaStoreError("queue event state or reason is invalid")
        if self.sequence == 1:
            if (
                self.from_state is not None
                or self.to_state != QueueState.SUBMITTED
                or self.reason != QueueReason.CALLER_SUBMITTED
            ):
                raise ArenaStoreError("first queue event must be caller submission")
        else:
            if self.from_state is None:
                raise ArenaStoreError("non-initial queue event needs from_state")
            if self.to_state not in _ALLOWED_TRANSITIONS[self.from_state]:
                raise ArenaStoreError("queue event contains an illegal transition")
            if self.reason not in _EXPECTED_REASON_FOR_STATE[self.to_state]:
                raise ArenaStoreError("queue event reason does not match destination state")

    def to_public_dict(self) -> dict[str, Any]:
        """Return the public state transition without an execution timestamp.

        Exact transition times are retained in the sealed durable record for
        ordering and crash recovery.  Once a confidential evaluator is
        connected, their deltas can reveal candidate-dependent execution
        latency, so they are not part of the public queue protocol.
        """
        return {
            "sequence": self.sequence,
            "from_state": self.from_state.value if self.from_state else None,
            "to_state": self.to_state.value,
            "reason": self.reason.value,
        }

    def to_persisted_dict(self) -> dict[str, Any]:
        """Return the exact internal representation needed for recovery."""

        return {
            "sequence": self.sequence,
            "from_state": self.from_state.value if self.from_state else None,
            "to_state": self.to_state.value,
            "occurred_at": self.occurred_at,
            "reason": self.reason.value,
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "QueueEvent":
        _require_exact_keys(payload, cls._FIELDS, label="queue event")
        try:
            from_state = (
                None
                if payload["from_state"] is None
                else QueueState(str(payload["from_state"]))
            )
            to_state = QueueState(str(payload["to_state"]))
            reason = QueueReason(str(payload["reason"]))
        except ValueError as exc:
            raise ArenaStoreError("queue event contains unsupported enum value") from exc
        return cls(
            sequence=_require_int(
                payload["sequence"],
                label="queue event sequence",
                minimum=1,
                maximum=MAX_QUEUE_EVENTS,
            ),
            from_state=from_state,
            to_state=to_state,
            occurred_at=_require_int(
                payload["occurred_at"],
                label="queue event occurred_at",
                minimum=0,
                maximum=MAX_TIMESTAMP,
            ),
            reason=reason,
        )


def _validate_candidate_commitment(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ArenaStoreError("candidate_commitment must use sha256:<lowercase hex>")
    digest = value.removeprefix("sha256:")
    if not _HEX_64.fullmatch(digest):
        raise ArenaStoreError("candidate_commitment must use sha256:<lowercase hex>")
    return value


def _validate_encrypted_reference(value: Any) -> str:
    reference = _require_bounded_string(
        value,
        label="encrypted_reference",
        maximum_bytes=MAX_ENCRYPTED_REFERENCE_BYTES,
    )
    if not _ENCRYPTED_REFERENCE.fullmatch(reference):
        raise ArenaStoreError(
            "encrypted_reference must be an allowlisted sealed:// or r2:// reference"
        )
    path = reference.split("://", 1)[1]
    segments = path.split("/")
    if (
        len(segments) < 2
        or len(segments) > 16
        or any(
            segment in {".", ".."} or not _REFERENCE_SEGMENT.fullmatch(segment)
            for segment in segments
        )
    ):
        raise ArenaStoreError(
            "encrypted_reference must contain bounded namespace/key path segments"
        )
    return reference


def _ladder_release_to_dict(release: LadderRelease) -> dict[str, Any]:
    return release.to_public_dict()


def _ladder_release_from_mapping(payload: Mapping[str, Any]) -> LadderRelease:
    expected = frozenset(
        {
            "submission_index",
            "accepted",
            "leaderboard_step_index",
            "step_denominator",
            "improvement_steps_so_far",
            "has_leaderboard_entry",
        }
    )
    _require_exact_keys(payload, expected, label="Ladder release")
    release = LadderRelease(
        submission_index=_require_int(
            payload["submission_index"], label="Ladder submission_index", minimum=1
        ),
        accepted=_require_bool(payload["accepted"], label="Ladder accepted"),
        leaderboard_step_index=_require_int(
            payload["leaderboard_step_index"],
            label="Ladder leaderboard_step_index",
            minimum=-1,
        ),
        step_denominator=_require_int(
            payload["step_denominator"], label="Ladder step_denominator", minimum=1
        ),
        improvement_steps_so_far=_require_int(
            payload["improvement_steps_so_far"],
            label="Ladder improvement_steps_so_far",
            minimum=0,
        ),
    )
    if payload["has_leaderboard_entry"] is not (release.leaderboard_step_index >= 0):
        raise ArenaStoreError("Ladder has_leaderboard_entry mismatch")
    return release


@dataclass(frozen=True)
class ExecutionProvenance:
    """Bounded worker claim attached to exactly one terminal submission.

    This record is intentionally *not* an independent TDX verification result.
    It records the public commitments that the in-boundary worker used after its
    QVL and execution-policy gates passed. A browser or auditor must still obtain
    and authenticate the corresponding signed QVL verdict before upgrading the
    row to independently verified evidence.
    """

    outcome: str
    runtime: str
    runtime_policy_commitment: str
    challenge_manifest_hash: str
    compose_hash: str
    app_id: str
    os_image_hash: str
    quote_sha256: str
    verifier_address: str
    verdict_digest: str
    tee_signer_address: str
    chain_id: int
    challenge_registry_address: str

    _FIELDS = frozenset(
        {
            "outcome",
            "runtime",
            "runtime_policy_commitment",
            "challenge_manifest_hash",
            "compose_hash",
            "app_id",
            "os_image_hash",
            "quote_sha256",
            "verifier_address",
            "verdict_digest",
            "tee_signer_address",
            "chain_id",
            "challenge_registry_address",
        }
    )

    def __post_init__(self) -> None:
        if self.outcome not in {"completed", "failed"}:
            raise ArenaStoreError("execution provenance outcome is unsupported")
        if self.runtime != SAFE_IR_RUNTIME:
            raise ArenaStoreError("execution provenance runtime is unsupported")
        for label, value in (
            ("runtime policy", self.runtime_policy_commitment),
            ("quote", self.quote_sha256),
        ):
            if (
                not isinstance(value, str)
                or not value.startswith("sha256:")
                or not _HEX_64.fullmatch(value.removeprefix("sha256:"))
                or value == "sha256:" + "0" * 64
            ):
                raise ArenaStoreError(f"execution provenance {label} is malformed")
        for label, value in (
            ("challenge manifest", self.challenge_manifest_hash),
            ("compose", self.compose_hash),
            ("OS image", self.os_image_hash),
        ):
            if (
                not isinstance(value, str)
                or not _HEX_64.fullmatch(value)
                or value == "0" * 64
            ):
                raise ArenaStoreError(f"execution provenance {label} is malformed")
        if (
            not isinstance(self.verdict_digest, str)
            or not self.verdict_digest.startswith("0x")
            or not _HEX_64.fullmatch(self.verdict_digest[2:])
            or self.verdict_digest == "0x" + "0" * 64
        ):
            raise ArenaStoreError("execution provenance verdict digest is malformed")
        for label, value in (
            ("verifier", self.verifier_address),
            ("TEE signer", self.tee_signer_address),
            ("challenge registry", self.challenge_registry_address),
        ):
            if (
                not isinstance(value, str)
                or value != value.lower()
                or not _WALLET_ADDRESS.fullmatch(value)
                or value == "0x" + "0" * 40
            ):
                raise ArenaStoreError(f"execution provenance {label} is malformed")
        if len({self.verifier_address, self.tee_signer_address}) != 2:
            raise ArenaStoreError("execution provenance verifier is not independent")
        _require_bounded_string(
            self.app_id,
            label="execution provenance app_id",
            maximum_bytes=128,
        )
        _require_int(
            self.chain_id,
            label="execution provenance chain_id",
            minimum=84_532,
            maximum=84_532,
        )

    def to_persisted_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "runtime": self.runtime,
            "runtime_policy_commitment": self.runtime_policy_commitment,
            "challenge_manifest_hash": self.challenge_manifest_hash,
            "compose_hash": self.compose_hash,
            "app_id": self.app_id,
            "os_image_hash": self.os_image_hash,
            "quote_sha256": self.quote_sha256,
            "verifier_address": self.verifier_address,
            "verdict_digest": self.verdict_digest,
            "tee_signer_address": self.tee_signer_address,
            "chain_id": self.chain_id,
            "challenge_registry_address": self.challenge_registry_address,
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "ExecutionProvenance":
        _require_exact_keys(payload, cls._FIELDS, label="execution provenance")
        return cls(
            outcome=str(payload["outcome"]),
            runtime=str(payload["runtime"]),
            runtime_policy_commitment=str(payload["runtime_policy_commitment"]),
            challenge_manifest_hash=str(payload["challenge_manifest_hash"]),
            compose_hash=str(payload["compose_hash"]),
            app_id=str(payload["app_id"]),
            os_image_hash=str(payload["os_image_hash"]),
            quote_sha256=str(payload["quote_sha256"]),
            verifier_address=str(payload["verifier_address"]),
            verdict_digest=str(payload["verdict_digest"]),
            tee_signer_address=str(payload["tee_signer_address"]),
            chain_id=_require_int(
                payload["chain_id"],
                label="execution provenance chain_id",
                minimum=84_532,
                maximum=84_532,
            ),
            challenge_registry_address=str(payload["challenge_registry_address"]),
        )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "status": "worker_reported",
            **self.to_persisted_dict(),
            "evidence_classification": WORKER_REPORTED_EVIDENCE_CLASSIFICATION,
            "independently_verified_by_client": False,
            "raw_tdx_quote_egress": False,
            "exact_score_egress": False,
            "exact_timing_egress": False,
        }


def _unobserved_execution_provenance(runtime: str) -> dict[str, Any]:
    return {
        "status": "not_executed",
        "outcome": None,
        "runtime": runtime,
        "runtime_policy_commitment": None,
        "challenge_manifest_hash": None,
        "compose_hash": None,
        "app_id": None,
        "os_image_hash": None,
        "quote_sha256": None,
        "verifier_address": None,
        "verdict_digest": None,
        "tee_signer_address": None,
        "chain_id": None,
        "challenge_registry_address": None,
        "evidence_classification": "none",
        "independently_verified_by_client": False,
        "raw_tdx_quote_egress": False,
        "exact_score_egress": False,
        "exact_timing_egress": False,
    }


@dataclass(frozen=True)
class SubmissionRecord:
    submission_id: str
    challenge_id: str
    challenge_version: str
    identity: SubmissionIdentity
    candidate_commitment: str
    encrypted_reference: str
    manifest: SubmissionManifest
    state: QueueState
    created_at: int
    updated_at: int
    events: tuple[QueueEvent, ...]
    ladder_release: LadderRelease | None = None
    ladder_released_at: int | None = None
    execution_provenance: ExecutionProvenance | None = None

    _PERSISTED_FIELDS = frozenset(
        {
            "submission_id",
            "challenge_id",
            "challenge_version",
            "identity",
            "candidate_commitment",
            "encrypted_reference",
            "manifest",
            "state",
            "created_at",
            "updated_at",
            "events",
            "ladder_release",
            "ladder_released_at",
            "execution_provenance",
            "raw_candidate_persisted",
        }
    )

    def __post_init__(self) -> None:
        if not isinstance(self.submission_id, str) or not _SUBMISSION_ID.fullmatch(
            self.submission_id
        ):
            raise ArenaStoreError("submission_id is malformed")
        if not _IDENTIFIER.fullmatch(self.challenge_id) or not _SEMVER.fullmatch(
            self.challenge_version
        ):
            raise ArenaStoreError("submission challenge reference is malformed")
        if not isinstance(self.identity, SubmissionIdentity):
            raise ArenaStoreError("submission identity is malformed")
        _validate_candidate_commitment(self.candidate_commitment)
        _validate_encrypted_reference(self.encrypted_reference)
        if not isinstance(self.manifest, SubmissionManifest):
            raise ArenaStoreError("submission manifest is malformed")
        if not isinstance(self.state, QueueState):
            raise ArenaStoreError("submission queue state is malformed")
        _require_int(
            self.created_at, label="created_at", minimum=0, maximum=MAX_TIMESTAMP
        )
        _require_int(
            self.updated_at,
            label="updated_at",
            minimum=self.created_at,
            maximum=MAX_TIMESTAMP,
        )
        if (
            not isinstance(self.events, tuple)
            or not self.events
            or len(self.events) > MAX_QUEUE_EVENTS
        ):
            raise ArenaStoreError("submission queue history is malformed or oversized")
        previous: QueueEvent | None = None
        for position, event in enumerate(self.events, start=1):
            if not isinstance(event, QueueEvent) or event.sequence != position:
                raise ArenaStoreError("submission queue history sequence is malformed")
            if previous is not None:
                if event.from_state != previous.to_state:
                    raise ArenaStoreError("submission queue history is discontinuous")
                if event.occurred_at < previous.occurred_at:
                    raise ArenaStoreError("submission queue event time regressed")
            previous = event
        if self.events[0].occurred_at != self.created_at:
            raise ArenaStoreError("submission created_at does not match first queue event")
        if self.events[-1].to_state != self.state or self.events[-1].occurred_at > self.updated_at:
            raise ArenaStoreError("submission queue state or updated_at does not match history")
        if (self.ladder_release is None) != (self.ladder_released_at is None):
            raise ArenaStoreError("Ladder release and timestamp must be present together")
        if self.ladder_release is not None:
            if not isinstance(self.ladder_release, LadderRelease):
                raise ArenaStoreError("submission Ladder release is malformed")
            _require_int(
                self.ladder_released_at,
                label="ladder_released_at",
                minimum=self.created_at,
                maximum=MAX_TIMESTAMP,
            )
            if self.ladder_released_at > self.updated_at:
                raise ArenaStoreError("Ladder release timestamp cannot exceed updated_at")
        if self.execution_provenance is not None:
            if not isinstance(self.execution_provenance, ExecutionProvenance):
                raise ArenaStoreError("submission execution provenance is malformed")
            if self.state not in {QueueState.COMPLETED, QueueState.FAILED}:
                raise ArenaStoreError("execution provenance requires a terminal worker state")
            if self.execution_provenance.outcome != self.state.value:
                raise ArenaStoreError("execution provenance outcome does not match queue state")

    def to_public_dict(self, capability: ExecutionCapability) -> dict[str, Any]:
        """Return an allowlisted public projection; encrypted storage ref omitted."""

        provenance = (
            self.execution_provenance.to_public_dict()
            if self.execution_provenance is not None
            else _unobserved_execution_provenance(self.manifest.runtime)
        )
        return {
            "surface": "arena_submission",
            "schema_version": PUBLIC_SUBMISSION_SCHEMA_VERSION,
            "submission_id": self.submission_id,
            "challenge_id": self.challenge_id,
            "challenge_version": self.challenge_version,
            "identity": self.identity.to_public_dict(),
            "candidate_commitment": self.candidate_commitment,
            "manifest": self.manifest.to_public_dict(),
            "state": self.state.value,
            "queue_events": [event.to_public_dict() for event in self.events],
            "ladder_release": (
                _ladder_release_to_dict(self.ladder_release)
                if self.ladder_release is not None
                else None
            ),
            "execution_capability": capability.to_public_dict(),
            "execution_provenance": provenance,
            "product_status": (
                "live" if self.execution_provenance is not None else PRODUCT_STATUS
            ),
            "execution_assurance": (
                WORKER_REPORTED_EVIDENCE_CLASSIFICATION
                if self.execution_provenance is not None
                else EXECUTION_ASSURANCE
            ),
            "exact_timing_egress": False,
            "encrypted_reference_public": False,
            "raw_candidate_accepted": False,
            "raw_secret_egress": False,
        }

    def to_owner_dict(self, capability: ExecutionCapability) -> dict[str, Any]:
        """Return the authenticated-wallet projection.

        Ownership grants visibility into the caller's bounded workflow state,
        not into evaluator internals or storage capabilities.  In particular,
        the opaque encrypted reference remains an in-boundary worker secret.
        """

        bounded_release = None
        if self.ladder_release is not None:
            bounded_release = {
                "accepted": self.ladder_release.accepted,
                "leaderboard_step_index": self.ladder_release.leaderboard_step_index,
                "step_denominator": self.ladder_release.step_denominator,
                "improvement_steps_so_far": self.ladder_release.improvement_steps_so_far,
            }
        provenance = (
            self.execution_provenance.to_public_dict()
            if self.execution_provenance is not None
            else _unobserved_execution_provenance(self.manifest.runtime)
        )
        return {
            "surface": "arena_owner_submission",
            "schema_version": PUBLIC_SUBMISSION_SCHEMA_VERSION,
            "submission_id": self.submission_id,
            "challenge_id": self.challenge_id,
            "challenge_version": self.challenge_version,
            "identity": self.identity.to_public_dict(),
            "candidate_commitment": self.candidate_commitment,
            "manifest": self.manifest.to_public_dict(),
            "state": self.state.value,
            "bounded_result": bounded_release,
            "execution_capability": capability.to_public_dict(),
            "execution_provenance": provenance,
            "product_status": (
                "live" if self.execution_provenance is not None else PRODUCT_STATUS
            ),
            "execution_assurance": (
                WORKER_REPORTED_EVIDENCE_CLASSIFICATION
                if self.execution_provenance is not None
                else EXECUTION_ASSURANCE
            ),
            "raw_candidate_egress": False,
            "encrypted_reference_egress": False,
            "exact_score_egress": False,
            "exact_reward_egress": False,
            "exact_timing_egress": False,
            "internal_error_egress": False,
        }

    def to_worker_dict(self, capability: ExecutionCapability) -> dict[str, Any]:
        """Return the sealed reference only to an in-boundary runtime caller."""

        public = self.to_public_dict(capability)
        public["surface"] = "arena_submission_worker"
        public["encrypted_reference"] = self.encrypted_reference
        return public

    def to_persisted_dict(self) -> dict[str, Any]:
        return {
            "submission_id": self.submission_id,
            "challenge_id": self.challenge_id,
            "challenge_version": self.challenge_version,
            "identity": self.identity.to_persisted_dict(),
            "candidate_commitment": self.candidate_commitment,
            "encrypted_reference": self.encrypted_reference,
            "manifest": self.manifest.to_persisted_dict(),
            "state": self.state.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "events": [event.to_persisted_dict() for event in self.events],
            "ladder_release": (
                _ladder_release_to_dict(self.ladder_release)
                if self.ladder_release is not None
                else None
            ),
            "ladder_released_at": self.ladder_released_at,
            "execution_provenance": (
                self.execution_provenance.to_persisted_dict()
                if self.execution_provenance is not None
                else None
            ),
            "raw_candidate_persisted": False,
        }

    @classmethod
    def from_persisted_dict(cls, payload: Mapping[str, Any]) -> "SubmissionRecord":
        _require_exact_keys(payload, cls._PERSISTED_FIELDS, label="persisted submission")
        if payload["raw_candidate_persisted"] is not False:
            raise ArenaStoreError("Arena must never persist a raw candidate")
        identity = payload["identity"]
        manifest = payload["manifest"]
        events = payload["events"]
        if not isinstance(identity, Mapping) or not isinstance(manifest, Mapping):
            raise ArenaStoreError("persisted submission has malformed identity or manifest")
        if not isinstance(events, list) or len(events) > MAX_QUEUE_EVENTS:
            raise ArenaStoreError("persisted queue history is malformed or oversized")
        ladder_payload = payload["ladder_release"]
        if ladder_payload is not None and not isinstance(ladder_payload, Mapping):
            raise ArenaStoreError("persisted Ladder release is malformed")
        provenance_payload = payload["execution_provenance"]
        if provenance_payload is not None and not isinstance(provenance_payload, Mapping):
            raise ArenaStoreError("persisted execution provenance is malformed")
        try:
            state = QueueState(str(payload["state"]))
        except ValueError as exc:
            raise ArenaStoreError("persisted submission state is unsupported") from exc
        return cls(
            submission_id=_require_bounded_string(
                payload["submission_id"], label="submission_id", maximum_bytes=28
            ),
            challenge_id=_require_bounded_string(
                payload["challenge_id"], label="challenge_id", maximum_bytes=64
            ),
            challenge_version=_require_bounded_string(
                payload["challenge_version"],
                label="challenge_version",
                maximum_bytes=32,
            ),
            identity=SubmissionIdentity.from_mapping(identity),
            candidate_commitment=_require_bounded_string(
                payload["candidate_commitment"],
                label="candidate_commitment",
                maximum_bytes=71,
            ),
            encrypted_reference=_require_bounded_string(
                payload["encrypted_reference"],
                label="encrypted_reference",
                maximum_bytes=MAX_ENCRYPTED_REFERENCE_BYTES,
            ),
            manifest=SubmissionManifest.from_mapping(manifest),
            state=state,
            created_at=_require_int(
                payload["created_at"],
                label="created_at",
                minimum=0,
                maximum=MAX_TIMESTAMP,
            ),
            updated_at=_require_int(
                payload["updated_at"],
                label="updated_at",
                minimum=0,
                maximum=MAX_TIMESTAMP,
            ),
            events=tuple(
                QueueEvent.from_mapping(event)
                if isinstance(event, Mapping)
                else _raise("persisted queue event must be an object")
                for event in events
            ),
            ladder_release=(
                _ladder_release_from_mapping(ladder_payload)
                if ladder_payload is not None
                else None
            ),
            ladder_released_at=(
                None
                if payload["ladder_released_at"] is None
                else _require_int(
                    payload["ladder_released_at"],
                    label="ladder_released_at",
                    minimum=0,
                    maximum=MAX_TIMESTAMP,
                )
            ),
            execution_provenance=(
                ExecutionProvenance.from_mapping(provenance_payload)
                if provenance_payload is not None
                else None
            ),
        )


@dataclass(frozen=True)
class SubmissionResult:
    submission: SubmissionRecord
    created: bool


@dataclass(frozen=True)
class ArenaWorkerClaim:
    """Durable safe-IR claim result used only inside the worker boundary."""

    submission: SubmissionRecord
    recovered: bool


@dataclass(frozen=True)
class _IdempotencyRecord:
    key_hash: str
    request_hash: str
    submission_id: str

    _FIELDS = frozenset({"key_hash", "request_hash", "submission_id"})

    def __post_init__(self) -> None:
        if not _HEX_64.fullmatch(self.key_hash) or not _HEX_64.fullmatch(self.request_hash):
            raise ArenaStoreError("idempotency hashes are malformed")
        if not _SUBMISSION_ID.fullmatch(self.submission_id):
            raise ArenaStoreError("idempotency submission_id is malformed")

    def to_dict(self) -> dict[str, str]:
        return {
            "key_hash": self.key_hash,
            "request_hash": self.request_hash,
            "submission_id": self.submission_id,
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "_IdempotencyRecord":
        _require_exact_keys(payload, cls._FIELDS, label="idempotency record")
        return cls(
            key_hash=_require_bounded_string(
                payload["key_hash"], label="idempotency key_hash", maximum_bytes=64
            ),
            request_hash=_require_bounded_string(
                payload["request_hash"],
                label="idempotency request_hash",
                maximum_bytes=64,
            ),
            submission_id=_require_bounded_string(
                payload["submission_id"],
                label="idempotency submission_id",
                maximum_bytes=28,
            ),
        )


@dataclass(frozen=True)
class _ArenaState:
    catalog: ChallengeCatalog
    submissions: dict[str, SubmissionRecord]
    idempotency: dict[str, _IdempotencyRecord]


class ArenaStore:
    """Thread- and process-safe, copy-on-write Arena JSON store.

    Writes use a same-directory temporary file, ``fsync``, and ``os.replace``.
    Every operation also holds a same-directory ``flock`` and reloads the
    durable state before inspecting it. Separate API and worker processes can
    therefore share this file without stale snapshots or lost updates. The
    worker uses a distinct lifetime lease for single-worker election; this
    lock protects state consistency rather than evaluator ownership.
    """

    _ROOT_FIELDS = frozenset(
        {
            "surface",
            "schema_version",
            "catalog",
            "submissions",
            "idempotency",
            "raw_candidate_persisted",
        }
    )

    def __init__(
        self,
        path: str | Path,
        *,
        catalog: ChallengeCatalog | None = None,
        max_submissions: int = MAX_SUBMISSIONS,
    ) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._operation_depth = 0
        self._operation_fd: int | None = None
        self._lock_path = self.path.with_name(f".{self.path.name}.lock")
        self._initialized = False
        self._max_submissions = _require_int(
            max_submissions,
            label="max_submissions",
            minimum=1,
            maximum=MAX_SUBMISSIONS,
        )
        expected_catalog = catalog or default_challenge_catalog()
        if not isinstance(expected_catalog, ChallengeCatalog):
            raise ArenaStoreError("catalog must be a ChallengeCatalog")
        self._expected_catalog = expected_catalog
        self._state = _ArenaState(
            catalog=expected_catalog,
            submissions={},
            idempotency={},
        )
        with self._operation(refresh=False):
            if self.path.is_symlink():
                raise ArenaStoreCorruptError("Arena persistence cannot be a symlink")
            if self.path.exists():
                loaded = self._load()
                self._require_expected_catalog(loaded)
                self._state = loaded
            else:
                self._persist(self._state)
        self._initialized = True

    def public_catalog(self) -> dict[str, Any]:
        with self._operation():
            return self._state.catalog.to_public_dict()

    def get_submission(self, submission_id: str) -> SubmissionRecord:
        with self._operation():
            return self._get_submission(submission_id)

    def public_submission(self, submission_id: str) -> dict[str, Any]:
        with self._operation():
            record = self._get_submission(submission_id)
            challenge = self._state.catalog.get(
                record.challenge_id, record.challenge_version
            )
            return record.to_public_dict(challenge.execution_capability)

    def owner_submission(self, submission_id: str) -> dict[str, Any]:
        """Bounded projection for an already-authenticated wallet owner."""

        with self._operation():
            record = self._get_submission(submission_id)
            challenge = self._state.catalog.get(
                record.challenge_id, record.challenge_version
            )
            return record.to_owner_dict(challenge.execution_capability)

    def worker_submission(self, submission_id: str) -> dict[str, Any]:
        """Sealed projection for a separately authenticated in-boundary worker."""

        with self._operation():
            record = self._get_submission(submission_id)
            challenge = self._state.catalog.get(
                record.challenge_id, record.challenge_version
            )
            return record.to_worker_dict(challenge.execution_capability)

    def owner_submissions(
        self,
        *,
        wallet_address: str,
        challenge_id: str,
        challenge_version: str,
        limit: int = 25,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Return one bounded page filtered by the authenticated wallet.

        ``wallet_address`` must come from verified token claims.  There is no
        project or owner query parameter, preventing a caller from selecting a
        different principal.  The cursor is a public submission identifier and
        is accepted only when it belongs to the same wallet and challenge page.
        """

        if not isinstance(wallet_address, str) or not _WALLET_ADDRESS.fullmatch(
            wallet_address
        ):
            raise ArenaStoreError("owner wallet address is malformed")
        identity_address = wallet_address.lower()
        page_limit = _require_int(
            limit,
            label="owner submissions limit",
            minimum=1,
            maximum=MAX_OWNER_SUBMISSION_ROWS,
        )
        if cursor is not None and (
            not isinstance(cursor, str) or not _SUBMISSION_ID.fullmatch(cursor)
        ):
            raise ArenaStoreError("owner submissions cursor is malformed")

        with self._operation():
            challenge = self._state.catalog.get(challenge_id, challenge_version)
            matching = sorted(
                (
                    record
                    for record in self._state.submissions.values()
                    if record.challenge_id == challenge_id
                    and record.challenge_version == challenge_version
                    and hmac.compare_digest(
                        record.identity.wallet_address,
                        identity_address,
                    )
                ),
                key=lambda item: (-item.created_at, item.submission_id),
            )
            start = 0
            if cursor is not None:
                try:
                    start = next(
                        index + 1
                        for index, record in enumerate(matching)
                        if hmac.compare_digest(record.submission_id, cursor)
                    )
                except StopIteration as exc:
                    raise ArenaStoreError(
                        "owner submissions cursor is outside this authenticated page"
                    ) from exc
            page = matching[start : start + page_limit]
            has_more = start + len(page) < len(matching)
            next_cursor = page[-1].submission_id if has_more and page else None
            return {
                "surface": "arena_owner_submissions",
                "schema_version": PUBLIC_OWNER_SUBMISSIONS_SCHEMA_VERSION,
                "challenge_id": challenge_id,
                "challenge_version": challenge_version,
                "owner_identity": _sha256_json(
                    identity_address,
                    prefix="arena_public_wallet",
                ),
                "page_count": len(page),
                "submissions": [
                    record.to_owner_dict(challenge.execution_capability)
                    for record in page
                ],
                "has_more": has_more,
                "next_cursor": next_cursor,
                "scope": "authenticated_wallet_challenge_version",
                "product_status": PER_ROW_PRODUCT_STATUS,
                "execution_assurance": PER_ROW_EXECUTION_ASSURANCE,
                "raw_candidate_egress": False,
                "encrypted_reference_egress": False,
                "exact_score_egress": False,
                "exact_reward_egress": False,
                "exact_timing_egress": False,
                "internal_error_egress": False,
            }

    def submit(
        self,
        *,
        challenge_id: str,
        challenge_version: str,
        identity: SubmissionIdentity | Mapping[str, Any],
        candidate_commitment: str,
        encrypted_reference: str,
        manifest: SubmissionManifest | Mapping[str, Any],
        idempotency_key: str,
        submitted_at: int,
    ) -> SubmissionResult:
        caller_identity = (
            identity
            if isinstance(identity, SubmissionIdentity)
            else SubmissionIdentity.from_mapping(identity)
        )
        candidate_manifest = (
            manifest
            if isinstance(manifest, SubmissionManifest)
            else SubmissionManifest.from_mapping(manifest)
        )
        commitment = _validate_candidate_commitment(candidate_commitment)
        encrypted_ref = _validate_encrypted_reference(encrypted_reference)
        timestamp = _require_int(
            submitted_at,
            label="submitted_at",
            minimum=0,
            maximum=MAX_TIMESTAMP,
        )
        key = _require_bounded_string(
            idempotency_key,
            label="idempotency_key",
            maximum_bytes=MAX_IDEMPOTENCY_KEY_BYTES,
        )
        if not _IDEMPOTENCY_KEY.fullmatch(key):
            raise ArenaStoreError("idempotency_key is malformed")

        with self._operation():
            challenge = self._state.catalog.get(challenge_id, challenge_version)
            candidate_manifest.validate_for(challenge)
            key_hash = _sha256_json(
                {
                    "wallet_address": caller_identity.wallet_address,
                    "project_id": caller_identity.project_id,
                    "challenge_id": challenge_id,
                    "challenge_version": challenge_version,
                    "idempotency_key": key,
                },
                prefix="arena_idempotency_key",
            )
            request_payload = {
                "challenge_id": challenge_id,
                "challenge_version": challenge_version,
                "identity": caller_identity.to_persisted_dict(),
                "candidate_commitment": commitment,
                "encrypted_reference": encrypted_ref,
                "manifest": candidate_manifest.to_persisted_dict(),
            }
            request_hash = _sha256_json(
                request_payload, prefix="arena_submission_request"
            )
            existing = self._state.idempotency.get(key_hash)
            if existing is not None:
                if existing.request_hash != request_hash:
                    raise ArenaIdempotencyConflict(
                        "idempotency key was already used for a different submission"
                    )
                return SubmissionResult(
                    submission=self._state.submissions[existing.submission_id],
                    created=False,
                )
            if len(self._state.submissions) >= self._max_submissions:
                raise ArenaStoreError("Arena submission store is full")

            submission_id = f"sub_{key_hash[:24]}"
            if submission_id in self._state.submissions:
                raise ArenaStoreError("submission id collision")
            initial_event = QueueEvent(
                sequence=1,
                from_state=None,
                to_state=QueueState.SUBMITTED,
                occurred_at=timestamp,
                reason=QueueReason.CALLER_SUBMITTED,
            )
            record = SubmissionRecord(
                submission_id=submission_id,
                challenge_id=challenge_id,
                challenge_version=challenge_version,
                identity=caller_identity,
                candidate_commitment=commitment,
                encrypted_reference=encrypted_ref,
                manifest=candidate_manifest,
                state=QueueState.SUBMITTED,
                created_at=timestamp,
                updated_at=timestamp,
                events=(initial_event,),
            )
            idem_record = _IdempotencyRecord(
                key_hash=key_hash,
                request_hash=request_hash,
                submission_id=submission_id,
            )
            submissions = dict(self._state.submissions)
            submissions[submission_id] = record
            idempotency = dict(self._state.idempotency)
            idempotency[key_hash] = idem_record
            candidate_state = _ArenaState(
                catalog=self._state.catalog,
                submissions=submissions,
                idempotency=idempotency,
            )
            self._persist(candidate_state)
            self._state = candidate_state
            return SubmissionResult(submission=record, created=True)

    def transition_submission(
        self,
        submission_id: str,
        to_state: QueueState | str,
        *,
        reason: QueueReason | str,
        occurred_at: int,
    ) -> SubmissionRecord:
        try:
            destination = to_state if isinstance(to_state, QueueState) else QueueState(to_state)
            transition_reason = reason if isinstance(reason, QueueReason) else QueueReason(reason)
        except ValueError as exc:
            raise ArenaStoreError("unsupported queue state or reason") from exc
        timestamp = _require_int(
            occurred_at, label="occurred_at", minimum=0, maximum=MAX_TIMESTAMP
        )
        with self._operation():
            current = self._get_submission(submission_id)
            if destination not in _ALLOWED_TRANSITIONS[current.state]:
                raise ArenaStoreError(
                    f"illegal Arena queue transition {current.state.value}->{destination.value}"
                )
            if transition_reason not in _EXPECTED_REASON_FOR_STATE[destination]:
                raise ArenaStoreError("queue reason does not match destination state")
            if timestamp < current.updated_at:
                raise ArenaStoreError("queue transition timestamp regressed")
            if len(current.events) >= MAX_QUEUE_EVENTS:
                raise ArenaStoreError("queue event history is full")
            if (
                destination == QueueState.COMPLETED
                and current.manifest.mode == SubmissionMode.LEADERBOARD
            ):
                if current.ladder_release is None:
                    raise ArenaStoreError(
                        "leaderboard submission cannot complete without a bounded Ladder release"
                    )
            event = QueueEvent(
                sequence=len(current.events) + 1,
                from_state=current.state,
                to_state=destination,
                occurred_at=timestamp,
                reason=transition_reason,
            )
            updated = replace(
                current,
                state=destination,
                updated_at=timestamp,
                events=current.events + (event,),
            )
            self._replace_submission(updated)
            return updated

    def finalize_safe_ir_execution(
        self,
        submission_id: str,
        provenance: ExecutionProvenance,
        *,
        occurred_at: int,
    ) -> SubmissionRecord:
        """Atomically attach bounded worker provenance and a terminal state.

        The generic transition API cannot attach this object. That keeps a
        manually advanced or modeled row distinct from a row emitted by the
        gated safe-IR worker. The public object remains a worker-reported claim,
        not an independently browser-verified QVL or TDX verdict.
        """

        if not isinstance(provenance, ExecutionProvenance):
            raise ArenaStoreError("safe-IR execution provenance is required")
        timestamp = _require_int(
            occurred_at, label="occurred_at", minimum=0, maximum=MAX_TIMESTAMP
        )
        destination = (
            QueueState.COMPLETED
            if provenance.outcome == "completed"
            else QueueState.FAILED
        )
        reason = (
            QueueReason.EVALUATION_COMPLETED
            if destination == QueueState.COMPLETED
            else QueueReason.EXECUTION_FAILED
        )
        with self._operation():
            current = self._get_submission(submission_id)
            challenge = self._state.catalog.get(
                current.challenge_id, current.challenge_version
            )
            if (
                current.challenge_id != DNASEQ_SAFE_IR_CHALLENGE_ID
                or current.challenge_version != DNASEQ_SAFE_IR_CHALLENGE_VERSION
                or current.manifest.runtime != SAFE_IR_RUNTIME
                or current.manifest.candidate_kind != SAFE_IR_CANDIDATE_KIND
                or current.manifest.entrypoint != SAFE_IR_ENTRYPOINT
                or current.manifest.mode != SubmissionMode.LEADERBOARD
            ):
                raise ArenaStoreError(
                    "worker finalization requires the pinned DNASeq safe-IR challenge"
                )
            if (
                provenance.runtime != current.manifest.runtime
                or provenance.challenge_manifest_hash != challenge.manifest_hash
            ):
                raise ArenaStoreError(
                    "execution provenance does not bind the submission challenge"
                )
            if destination not in _ALLOWED_TRANSITIONS[current.state]:
                raise ArenaStoreError(
                    f"illegal Arena queue transition {current.state.value}->{destination.value}"
                )
            if destination == QueueState.COMPLETED and (
                current.state != QueueState.SEALED_EVAL
                or current.ladder_release is None
            ):
                raise ArenaStoreError(
                    "completed worker execution requires sealed evaluation and a Ladder release"
                )
            if timestamp < current.updated_at:
                raise ArenaStoreError("worker finalization timestamp regressed")
            if len(current.events) >= MAX_QUEUE_EVENTS:
                raise ArenaStoreError("queue event history is full")
            event = QueueEvent(
                sequence=len(current.events) + 1,
                from_state=current.state,
                to_state=destination,
                occurred_at=timestamp,
                reason=reason,
            )
            updated = replace(
                current,
                state=destination,
                updated_at=timestamp,
                events=current.events + (event,),
                execution_provenance=provenance,
            )
            self._replace_submission(updated)
            return updated

    def record_ladder_release(
        self,
        submission_id: str,
        release: LadderRelease,
        *,
        occurred_at: int,
    ) -> SubmissionRecord:
        """Attach a bounded release; an exact score is not an accepted input."""

        if not isinstance(release, LadderRelease):
            raise ArenaStoreError("leaderboard update must be an existing LadderRelease")
        timestamp = _require_int(
            occurred_at, label="occurred_at", minimum=0, maximum=MAX_TIMESTAMP
        )
        with self._operation():
            current = self._get_submission(submission_id)
            if current.manifest.mode != SubmissionMode.LEADERBOARD:
                raise ArenaStoreError("only leaderboard-mode submissions accept Ladder releases")
            if current.ladder_release is not None:
                if (
                    current.ladder_release == release
                    and current.ladder_released_at == timestamp
                ):
                    return current
                raise ArenaStoreError("submission already has a different Ladder release")
            if current.state != QueueState.SEALED_EVAL:
                raise ArenaStoreError("Ladder release requires sealed_eval queue state")
            if timestamp < current.updated_at:
                raise ArenaStoreError("Ladder release timestamp regressed")
            challenge = self._state.catalog.get(
                current.challenge_id, current.challenge_version
            )
            previous = self._challenge_releases(current.challenge_id, current.challenge_version)
            self._validate_ladder_release(release, previous, challenge)
            updated = replace(
                current,
                updated_at=timestamp,
                ladder_release=release,
                ladder_released_at=timestamp,
            )
            self._replace_submission(updated)
            return updated

    def evaluate_ladder_submission(
        self,
        submission_id: str,
        internal_score: float,
        *,
        occurred_at: int,
    ) -> dict[str, Any]:
        """Runtime-only score reduction that persists only a bounded release.

        The exact score is handed directly to the existing ``LadderLeaderboard``
        implementation. It is never inserted into an event, exception message,
        request hash, or persistence payload. Callers must invoke this only
        inside the evaluator boundary; the future public HTTP API must not expose
        this method.
        """

        timestamp = _require_int(
            occurred_at, label="occurred_at", minimum=0, maximum=MAX_TIMESTAMP
        )
        with self._operation():
            current = self._get_submission(submission_id)
            if current.manifest.mode != SubmissionMode.LEADERBOARD:
                raise ArenaStoreError("only leaderboard-mode submissions accept Ladder scores")
            if current.ladder_release is not None:
                raise ArenaStoreError("submission already has a Ladder release")
            if current.state != QueueState.SEALED_EVAL:
                raise ArenaStoreError("Ladder evaluation requires sealed_eval queue state")
            challenge = self._state.catalog.get(
                current.challenge_id, current.challenge_version
            )
            previous = self._challenge_releases(
                current.challenge_id, current.challenge_version
            )
            board = self._rebuild_ladder(previous, challenge)
            # LadderLeaderboard performs the exact type/range checks. Only its
            # bounded result crosses into durable state.
            release = board.submit(internal_score)
            self.record_ladder_release(
                submission_id, release, occurred_at=timestamp
            )
            return release.to_public_dict()

    def public_leaderboard(
        self,
        challenge_id: str,
        challenge_version: str,
        *,
        limit: int = MAX_PUBLIC_LEADERBOARD_ROWS,
    ) -> dict[str, Any]:
        row_limit = _require_int(
            limit,
            label="leaderboard limit",
            minimum=1,
            maximum=MAX_PUBLIC_LEADERBOARD_ROWS,
        )
        with self._operation():
            challenge = self._state.catalog.get(challenge_id, challenge_version)
            best_by_identity: dict[tuple[str, str], SubmissionRecord] = {}
            for record in self._state.submissions.values():
                if (
                    record.challenge_id != challenge_id
                    or record.challenge_version != challenge_version
                    or record.state != QueueState.COMPLETED
                    or record.ladder_release is None
                    or not record.ladder_release.accepted
                ):
                    continue
                identity_key = (
                    record.identity.wallet_address,
                    record.identity.project_id,
                )
                prior = best_by_identity.get(identity_key)
                if (
                    prior is None
                    or prior.ladder_release is None
                    or record.ladder_release.leaderboard_step_index
                    > prior.ladder_release.leaderboard_step_index
                ):
                    best_by_identity[identity_key] = record
            ranked = sorted(
                best_by_identity.values(),
                key=lambda item: (
                    -item.ladder_release.leaderboard_step_index,  # type: ignore[union-attr]
                    item.ladder_released_at,
                    item.submission_id,
                ),
            )[:row_limit]
            rows: list[dict[str, Any]] = []
            for rank, record in enumerate(ranked, start=1):
                release = record.ladder_release
                assert release is not None
                rows.append(
                    {
                        "rank": rank,
                        "submission_id": record.submission_id,
                        "identity": record.identity.to_public_dict(),
                        "candidate_commitment": record.candidate_commitment,
                        "leaderboard_step_index": release.leaderboard_step_index,
                        "step_denominator": release.step_denominator,
                        "improvement_steps_so_far": release.improvement_steps_so_far,
                        "ladder_submission_index": release.submission_index,
                        "execution_provenance": (
                            record.execution_provenance.to_public_dict()
                            if record.execution_provenance is not None
                            else _unobserved_execution_provenance(
                                record.manifest.runtime
                            )
                        ),
                        "product_status": (
                            "live"
                            if record.execution_provenance is not None
                            else PRODUCT_STATUS
                        ),
                        "execution_assurance": (
                            WORKER_REPORTED_EVIDENCE_CLASSIFICATION
                            if record.execution_provenance is not None
                            else EXECUTION_ASSURANCE
                        ),
                    }
                )
            return {
                "surface": "arena_public_leaderboard",
                "schema_version": PUBLIC_LEADERBOARD_SCHEMA_VERSION,
                "challenge_id": challenge_id,
                "challenge_version": challenge_version,
                "challenge_manifest_hash": challenge.manifest_hash,
                "release_mechanism": "fixed_eta_ladder_accepted_improvements_only",
                "step_denominator": challenge.ladder_policy.step_denominator,
                "row_count": len(rows),
                "rows": rows,
                "execution_capability": challenge.execution_capability.to_public_dict(),
                "product_status": PER_ROW_PRODUCT_STATUS,
                "execution_assurance": PER_ROW_EXECUTION_ASSURANCE,
                "exact_reward_egress": False,
                "exact_timing_egress": False,
                "encrypted_reference_egress": False,
                "raw_candidate_egress": False,
            }

    def public_queue(
        self,
        challenge_id: str,
        challenge_version: str,
        *,
        limit: int = 100,
    ) -> dict[str, Any]:
        queue_limit = _require_int(limit, label="queue limit", minimum=1, maximum=100)
        with self._operation():
            challenge = self._state.catalog.get(challenge_id, challenge_version)
            matching = sorted(
                (
                    record
                    for record in self._state.submissions.values()
                    if record.challenge_id == challenge_id
                    and record.challenge_version == challenge_version
                ),
                key=lambda item: (-item.created_at, item.submission_id),
            )[:queue_limit]
            return {
                "surface": "arena_public_queue",
                "schema_version": PUBLIC_QUEUE_SCHEMA_VERSION,
                "challenge_id": challenge_id,
                "challenge_version": challenge_version,
                "submission_count": len(matching),
                "submissions": [
                    record.to_public_dict(challenge.execution_capability)
                    for record in matching
                ],
                "execution_capability": challenge.execution_capability.to_public_dict(),
                "product_status": PER_ROW_PRODUCT_STATUS,
                "execution_assurance": PER_ROW_EXECUTION_ASSURANCE,
                "exact_timing_egress": False,
                "raw_candidate_egress": False,
            }

    def next_safe_ir_work_item(self) -> SubmissionRecord | None:
        """Return the next safe-IR work item from a fresh durable snapshot.

        In-progress records are resumed before new submissions. This internal
        method returns the sealed record, so callers must hold the separate
        single-worker process lease before using it.
        """

        priorities = {
            QueueState.SEALED_EVAL: 0,
            QueueState.PUBLIC_TESTS: 1,
            QueueState.PROVISIONING: 2,
            QueueState.QUEUED: 3,
            QueueState.POLICY_SCREEN: 4,
            QueueState.SUBMITTED: 5,
        }
        with self._operation():
            candidates = [
                record
                for record in self._state.submissions.values()
                if record.challenge_id == DNASEQ_SAFE_IR_CHALLENGE_ID
                and record.challenge_version == DNASEQ_SAFE_IR_CHALLENGE_VERSION
                and record.manifest.runtime == SAFE_IR_RUNTIME
                and record.manifest.candidate_kind == SAFE_IR_CANDIDATE_KIND
                and record.manifest.entrypoint == SAFE_IR_ENTRYPOINT
                and record.manifest.mode == SubmissionMode.LEADERBOARD
                and record.state in priorities
            ]
            if not candidates:
                return None
            return min(
                candidates,
                key=lambda record: (
                    priorities[record.state],
                    record.updated_at,
                    record.created_at,
                    record.submission_id,
                ),
            )

    def claim_safe_ir_submission(
        self,
        submission_id: str,
        *,
        occurred_at: int,
    ) -> ArenaWorkerClaim:
        """Atomically claim a queued safe-IR record or resume a durable claim.

        ``queued -> provisioning`` is the durable claim boundary. A record
        already in ``provisioning``, ``public_tests``, or ``sealed_eval`` is a
        crash-recovery claim and is returned without another queue event.
        """

        timestamp = _require_int(
            occurred_at, label="occurred_at", minimum=0, maximum=MAX_TIMESTAMP
        )
        with self._operation():
            current = self._get_submission(submission_id)
            if (
                current.challenge_id != DNASEQ_SAFE_IR_CHALLENGE_ID
                or current.challenge_version != DNASEQ_SAFE_IR_CHALLENGE_VERSION
                or current.manifest.runtime != SAFE_IR_RUNTIME
                or current.manifest.candidate_kind != SAFE_IR_CANDIDATE_KIND
                or current.manifest.entrypoint != SAFE_IR_ENTRYPOINT
                or current.manifest.mode != SubmissionMode.LEADERBOARD
            ):
                raise ArenaStoreError(
                    "worker claim requires the pinned DNASeq safe-IR challenge"
                )
            if current.state == QueueState.QUEUED:
                claimed = self.transition_submission(
                    submission_id,
                    QueueState.PROVISIONING,
                    reason=QueueReason.WORKER_CLAIMED,
                    occurred_at=timestamp,
                )
                return ArenaWorkerClaim(submission=claimed, recovered=False)
            if current.state in {
                QueueState.PROVISIONING,
                QueueState.PUBLIC_TESTS,
                QueueState.SEALED_EVAL,
            }:
                return ArenaWorkerClaim(submission=current, recovered=True)
            raise ArenaStoreError("Arena submission is not ready for a worker claim")

    def _get_submission(self, submission_id: str) -> SubmissionRecord:
        if not isinstance(submission_id, str) or not _SUBMISSION_ID.fullmatch(submission_id):
            raise ArenaStoreError("submission_id is malformed")
        try:
            return self._state.submissions[submission_id]
        except KeyError as exc:
            raise ArenaStoreError("unknown Arena submission") from exc

    @contextmanager
    def _operation(self, *, refresh: bool = True):
        """Serialize one state operation across threads and processes."""

        with self._lock:
            outermost = self._operation_depth == 0
            if outermost:
                fd = self._acquire_file_lock()
                self._operation_fd = fd
                try:
                    if refresh:
                        if self.path.is_symlink():
                            raise ArenaStoreCorruptError(
                                "Arena persistence cannot be a symlink"
                            )
                        if not self.path.exists():
                            if self._initialized:
                                raise ArenaStoreCorruptError(
                                    "Arena persistence disappeared after initialization"
                                )
                        else:
                            loaded = self._load()
                            self._require_expected_catalog(loaded)
                            self._state = loaded
                except Exception:
                    self._release_file_lock(fd)
                    self._operation_fd = None
                    raise
            self._operation_depth += 1
            try:
                yield
            finally:
                self._operation_depth -= 1
                if outermost:
                    fd = self._operation_fd
                    self._operation_fd = None
                    if fd is not None:
                        self._release_file_lock(fd)

    def _acquire_file_lock(self) -> int:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd: int | None = None
        try:
            fd = os.open(self._lock_path, flags, 0o600)
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            return fd
        except OSError as exc:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise ArenaStoreError("Arena durable store lock is unavailable") from exc

    @staticmethod
    def _release_file_lock(fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _require_expected_catalog(self, state: _ArenaState) -> None:
        if state.catalog.to_public_dict() != self._expected_catalog.to_public_dict():
            raise ArenaStoreCorruptError(
                "persisted challenge catalog differs from configured versioned catalog"
            )

    def _replace_submission(self, updated: SubmissionRecord) -> None:
        submissions = dict(self._state.submissions)
        submissions[updated.submission_id] = updated
        candidate_state = _ArenaState(
            catalog=self._state.catalog,
            submissions=submissions,
            idempotency=dict(self._state.idempotency),
        )
        self._persist(candidate_state)
        self._state = candidate_state

    def _challenge_releases(
        self, challenge_id: str, challenge_version: str
    ) -> list[LadderRelease]:
        releases = [
            record.ladder_release
            for record in self._state.submissions.values()
            if record.challenge_id == challenge_id
            and record.challenge_version == challenge_version
            and record.ladder_release is not None
        ]
        return sorted(releases, key=lambda item: item.submission_index)

    @staticmethod
    def _rebuild_ladder(
        releases: list[LadderRelease], challenge: ChallengeManifest
    ) -> LadderLeaderboard:
        """Reconstruct Ladder counters from bounded releases, without raw scores."""

        board = LadderLeaderboard(challenge.ladder_policy)
        denominator = challenge.ladder_policy.step_denominator
        replayed: list[LadderRelease] = []
        for expected in releases:
            ArenaStore._validate_ladder_release(expected, replayed, challenge)
            if expected.accepted:
                # A point one tenth of a grid cell above the released integer
                # reproduces both the strict improvement test and nearest-grid
                # rounding. At the top of the grid, 1.0 is the only valid point.
                synthetic_score = (
                    1.0
                    if expected.leaderboard_step_index == denominator
                    else (expected.leaderboard_step_index + 0.1) / denominator
                )
            else:
                # Re-submit the released best; it cannot clear best + one step.
                synthetic_score = max(0.0, expected.leaderboard_step_index / denominator)
            actual = board.submit(synthetic_score)
            if actual != expected:
                raise ArenaStoreError("bounded Ladder history cannot be reconstructed")
            replayed.append(expected)
        return board

    @staticmethod
    def _validate_ladder_release(
        release: LadderRelease,
        previous: list[LadderRelease],
        challenge: ChallengeManifest,
    ) -> None:
        denominator = challenge.ladder_policy.step_denominator
        max_submissions = challenge.ladder_policy.max_submissions
        assert max_submissions is not None
        for label, value, minimum, maximum in (
            ("submission_index", release.submission_index, 1, max_submissions),
            ("leaderboard_step_index", release.leaderboard_step_index, -1, denominator),
            ("step_denominator", release.step_denominator, 1, denominator),
            ("improvement_steps_so_far", release.improvement_steps_so_far, 0, denominator),
        ):
            _require_int(value, label=f"Ladder {label}", minimum=minimum, maximum=maximum)
        if not isinstance(release.accepted, bool):
            raise ArenaStoreError("Ladder accepted must be a boolean")
        if release.step_denominator != denominator:
            raise ArenaStoreError("Ladder denominator does not match challenge manifest")
        if release.submission_index != len(previous) + 1:
            raise ArenaStoreError("Ladder submission_index is not the next release")
        previous_best = previous[-1].leaderboard_step_index if previous else -1
        previous_improvements = previous[-1].improvement_steps_so_far if previous else 0
        if release.accepted:
            if previous_best >= denominator - 1:
                raise ArenaStoreError(
                    "accepted Ladder release cannot clear a full step above the grid ceiling"
                )
            if (
                release.leaderboard_step_index <= previous_best
                or release.improvement_steps_so_far != previous_improvements + 1
            ):
                raise ArenaStoreError("accepted Ladder release is not a bounded improvement")
        elif (
            release.leaderboard_step_index != previous_best
            or release.improvement_steps_so_far != previous_improvements
        ):
            raise ArenaStoreError("rejected Ladder release must re-release the prior best")
        if release.improvement_steps_so_far > release.submission_index:
            raise ArenaStoreError("Ladder improvement count exceeds submission count")

    def _persist(self, state: _ArenaState) -> None:
        payload = {
            "surface": "arena_store",
            "schema_version": STORE_SCHEMA_VERSION,
            "catalog": state.catalog.to_public_dict(),
            "submissions": [
                record.to_persisted_dict()
                for record in sorted(
                    state.submissions.values(), key=lambda item: item.submission_id
                )
            ],
            "idempotency": [
                record.to_dict()
                for record in sorted(
                    state.idempotency.values(), key=lambda item: item.key_hash
                )
            ],
            "raw_candidate_persisted": False,
        }
        encoded = _canonical_json(payload) + b"\n"
        if len(encoded) > MAX_STORE_BYTES:
            raise ArenaStoreError("Arena persistence exceeds maximum store size")
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=str(parent)
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            _fsync_directory(parent)
        except Exception:
            if fd >= 0:
                os.close(fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise

    def _load(self) -> _ArenaState:
        try:
            size = self.path.stat().st_size
            if size <= 0 or size > MAX_STORE_BYTES:
                raise ArenaStoreCorruptError("Arena persistence is empty or oversized")
            raw = self.path.read_bytes()
            payload = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
            if not isinstance(payload, Mapping):
                raise ArenaStoreError("Arena persistence root must be an object")
            _require_exact_keys(payload, self._ROOT_FIELDS, label="Arena persistence root")
            if payload["surface"] != "arena_store":
                raise ArenaStoreError("unsupported Arena persistence surface")
            if payload["raw_candidate_persisted"] is not False:
                raise ArenaStoreError("Arena persistence claims raw candidate data")
            _require_int(
                payload["schema_version"],
                label="Arena store schema_version",
                minimum=STORE_SCHEMA_VERSION,
                maximum=STORE_SCHEMA_VERSION,
            )
            raw_catalog = payload["catalog"]
            raw_submissions = payload["submissions"]
            raw_idempotency = payload["idempotency"]
            if not isinstance(raw_catalog, Mapping):
                raise ArenaStoreError("persisted catalog must be an object")
            if not isinstance(raw_submissions, list) or not isinstance(raw_idempotency, list):
                raise ArenaStoreError("persisted submissions/idempotency must be arrays")
            if (
                len(raw_submissions) > self._max_submissions
                or len(raw_idempotency) > self._max_submissions
            ):
                raise ArenaStoreError("persisted Arena record count exceeds configured limit")
            catalog = ChallengeCatalog.from_public_dict(raw_catalog)
            submissions: dict[str, SubmissionRecord] = {}
            for item in raw_submissions:
                if not isinstance(item, Mapping):
                    raise ArenaStoreError("persisted submission must be an object")
                record = SubmissionRecord.from_persisted_dict(item)
                if record.submission_id in submissions:
                    raise ArenaStoreError("duplicate persisted submission_id")
                challenge = catalog.get(record.challenge_id, record.challenge_version)
                record.manifest.validate_for(challenge)
                submissions[record.submission_id] = record
            idempotency: dict[str, _IdempotencyRecord] = {}
            referenced_submission_ids: set[str] = set()
            for item in raw_idempotency:
                if not isinstance(item, Mapping):
                    raise ArenaStoreError("persisted idempotency record must be an object")
                record = _IdempotencyRecord.from_mapping(item)
                if record.key_hash in idempotency:
                    raise ArenaStoreError("duplicate persisted idempotency key hash")
                if record.submission_id not in submissions:
                    raise ArenaStoreError("idempotency record references unknown submission")
                if record.submission_id != f"sub_{record.key_hash[:24]}":
                    raise ArenaStoreError("idempotency key hash does not bind submission_id")
                if record.submission_id in referenced_submission_ids:
                    raise ArenaStoreError("multiple idempotency records reference one submission")
                submission = submissions[record.submission_id]
                expected_request_hash = _sha256_json(
                    {
                        "challenge_id": submission.challenge_id,
                        "challenge_version": submission.challenge_version,
                        "identity": submission.identity.to_persisted_dict(),
                        "candidate_commitment": submission.candidate_commitment,
                        "encrypted_reference": submission.encrypted_reference,
                        "manifest": submission.manifest.to_persisted_dict(),
                    },
                    prefix="arena_submission_request",
                )
                if record.request_hash != expected_request_hash:
                    raise ArenaStoreError("persisted idempotency request hash mismatch")
                idempotency[record.key_hash] = record
                referenced_submission_ids.add(record.submission_id)
            if len(idempotency) != len(submissions):
                raise ArenaStoreError("every persisted submission needs one idempotency record")
            state = _ArenaState(
                catalog=catalog,
                submissions=submissions,
                idempotency=idempotency,
            )
            self._validate_all_ladder_histories(state)
            return state
        except ArenaStoreCorruptError:
            raise
        except (
            ArenaStoreError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            OSError,
            RecursionError,
        ) as exc:
            raise ArenaStoreCorruptError(
                f"Arena persistence failed closed: {type(exc).__name__}"
            ) from exc

    @staticmethod
    def _validate_all_ladder_histories(state: _ArenaState) -> None:
        for challenge in state.catalog.challenges:
            releases = sorted(
                (
                    record.ladder_release
                    for record in state.submissions.values()
                    if record.challenge_id == challenge.challenge_id
                    and record.challenge_version == challenge.version
                    and record.ladder_release is not None
                ),
                key=lambda item: item.submission_index,
            )
            previous: list[LadderRelease] = []
            for release in releases:
                ArenaStore._validate_ladder_release(release, previous, challenge)
                previous.append(release)


def _raise(message: str) -> Any:
    raise ArenaStoreError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArenaStoreError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ArenaStoreError(f"non-finite JSON constant is forbidden: {value}")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        directory_fd = os.open(path, flags)
    except OSError:
        return
    try:
        try:
            os.fsync(directory_fd)
        except OSError:
            # The atomic replacement already succeeded. Directory fsync is a
            # durability hardening step that is unsupported on some filesystems;
            # reporting failure now would leave memory behind the replaced file.
            pass
    finally:
        os.close(directory_fd)
