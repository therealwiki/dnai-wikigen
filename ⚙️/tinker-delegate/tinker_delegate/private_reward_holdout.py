"""Hidden-holdout split and query accounting for private reward environments."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class HoldoutPartition(str, Enum):
    TRAIN = "train"
    REWARD = "reward"
    FINAL_VALIDATION = "final_validation"


@dataclass(frozen=True)
class HoldoutRecord:
    record_id: str
    payload: bytes
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def record_hash(self) -> str:
        return _sha256_hex(self.payload)


@dataclass(frozen=True)
class HoldoutSplitPolicy:
    train_fraction: float = 0.6
    reward_fraction: float = 0.2
    final_validation_fraction: float = 0.2
    min_train_records: int = 1
    min_reward_records: int = 1
    min_final_validation_records: int = 1
    max_reward_queries: int = 32
    max_reward_queries_per_candidate: int = 3
    min_unique_reward_candidates_before_final: int = 1
    max_final_validations: int = 1
    split_seed: str = "dnai-hidden-holdout-v1"

    def __post_init__(self) -> None:
        fractions = (
            self.train_fraction,
            self.reward_fraction,
            self.final_validation_fraction,
        )
        if any(fraction <= 0 for fraction in fractions):
            raise ValueError("holdout split fractions must be positive")
        if abs(sum(fractions) - 1.0) > 1e-9:
            raise ValueError("holdout split fractions must sum to 1")
        if self.min_train_records < 0:
            raise ValueError("min_train_records must be non-negative")
        if self.min_reward_records < 0:
            raise ValueError("min_reward_records must be non-negative")
        if self.min_final_validation_records < 0:
            raise ValueError("min_final_validation_records must be non-negative")
        if self.max_reward_queries < 0:
            raise ValueError("max_reward_queries must be non-negative")
        if self.max_reward_queries_per_candidate < 1:
            raise ValueError("max_reward_queries_per_candidate must be positive")
        if self.min_unique_reward_candidates_before_final < 0:
            raise ValueError("min_unique_reward_candidates_before_final must be non-negative")
        if self.max_final_validations < 1:
            raise ValueError("max_final_validations must be positive")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "train_fraction": self.train_fraction,
            "reward_fraction": self.reward_fraction,
            "final_validation_fraction": self.final_validation_fraction,
            "min_train_records": self.min_train_records,
            "min_reward_records": self.min_reward_records,
            "min_final_validation_records": self.min_final_validation_records,
            "max_reward_queries": self.max_reward_queries,
            "max_reward_queries_per_candidate": self.max_reward_queries_per_candidate,
            "min_unique_reward_candidates_before_final": self.min_unique_reward_candidates_before_final,
            "max_final_validations": self.max_final_validations,
            "split_seed_hash": _sha256_hex(self.split_seed.encode("utf-8")),
        }


@dataclass(frozen=True)
class HoldoutPublicManifest:
    split_commitment: str
    policy: dict[str, Any]
    # Compatibility name retained for environment metadata consumers. Values
    # are fixed disclosure bands, never exact private cardinalities.
    partition_counts: dict[str, str]
    reward_query_count: int
    unique_reward_candidates: int
    max_reward_queries_for_single_candidate: int
    final_validation_count: int
    closed_to_reward_queries: bool

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "split_commitment": self.split_commitment,
            "policy": _stable_public(self.policy),
            "partition_counts": _stable_public(self.partition_counts),
            "partition_count_disclosure": "banded_v1",
            "reward_query_count": self.reward_query_count,
            "unique_reward_candidates": self.unique_reward_candidates,
            "max_reward_queries_for_single_candidate": self.max_reward_queries_for_single_candidate,
            "final_validation_count": self.final_validation_count,
            "closed_to_reward_queries": self.closed_to_reward_queries,
        }


class HiddenHoldoutSet:
    """TEE-internal train/reward/final split with bounded public accounting."""

    def __init__(
        self,
        records: Mapping[str, bytes | HoldoutRecord],
        policy: HoldoutSplitPolicy | None = None,
    ) -> None:
        self.policy = policy or HoldoutSplitPolicy()
        self._records = _normalize_records(records)
        self._partitions = self._build_partitions()
        self._reward_candidate_hashes: list[str] = []
        self._final_candidate_hashes: list[str] = []
        self._final_validation_started = False
        self._validate_minimums()

    def records_for(self, partition: HoldoutPartition) -> tuple[HoldoutRecord, ...]:
        return tuple(self._partitions[partition])

    def record_ids_for(self, partition: HoldoutPartition) -> tuple[str, ...]:
        return tuple(record.record_id for record in self._partitions[partition])

    @property
    def partition_counts(self) -> dict[str, int]:
        return {
            partition.value: len(records)
            for partition, records in self._partitions.items()
        }

    @property
    def split_commitment(self) -> str:
        partitions = {
            partition.value: [
                {
                    "record_hash": record.record_hash,
                    "partition_record_hash": _partition_record_hash(
                        self.policy.split_seed,
                        partition,
                        record,
                    ),
                }
                for record in records
            ]
            for partition, records in self._partitions.items()
        }
        # Bind the exact private assignment and the explicitly declared public
        # policy in one commitment. Policy values are safe to disclose because
        # they are selected before evaluation, not inferred from private rows.
        return _sha256_json({
            "policy": self.policy.to_public_dict(),
            "partitions": partitions,
        })

    @property
    def reward_query_count(self) -> int:
        return len(self._reward_candidate_hashes)

    @property
    def unique_reward_candidates(self) -> int:
        return len(set(self._reward_candidate_hashes))

    @property
    def max_reward_queries_for_single_candidate(self) -> int:
        if not self._reward_candidate_hashes:
            return 0
        return max(
            self._reward_candidate_hashes.count(candidate_hash)
            for candidate_hash in set(self._reward_candidate_hashes)
        )

    @property
    def final_validation_count(self) -> int:
        return len(self._final_candidate_hashes)

    @property
    def closed_to_reward_queries(self) -> bool:
        return self._final_validation_started

    def record_reward_query(self, candidate_hash: str) -> None:
        if self._final_validation_started:
            raise RuntimeError("reward queries are closed after final validation starts")
        if self.reward_query_count >= self.policy.max_reward_queries:
            raise RuntimeError("reward query budget exhausted for hidden holdout")
        if self._reward_candidate_hashes.count(candidate_hash) >= self.policy.max_reward_queries_per_candidate:
            raise RuntimeError("candidate repeat limit exhausted for hidden holdout")
        self._reward_candidate_hashes.append(candidate_hash)

    def record_final_validation(self, candidate_hash: str) -> None:
        if self.final_validation_count >= self.policy.max_final_validations:
            raise RuntimeError("final validation budget exhausted for hidden holdout")
        if self.unique_reward_candidates < self.policy.min_unique_reward_candidates_before_final:
            raise RuntimeError("not enough unique reward candidates for final validation")
        self._final_validation_started = True
        self._final_candidate_hashes.append(candidate_hash)

    def public_manifest(self) -> HoldoutPublicManifest:
        return HoldoutPublicManifest(
            split_commitment=self.split_commitment,
            policy=self.policy.to_public_dict(),
            partition_counts={
                partition: _private_partition_count_band(count)
                for partition, count in self.partition_counts.items()
            },
            reward_query_count=self.reward_query_count,
            unique_reward_candidates=self.unique_reward_candidates,
            max_reward_queries_for_single_candidate=self.max_reward_queries_for_single_candidate,
            final_validation_count=self.final_validation_count,
            closed_to_reward_queries=self.closed_to_reward_queries,
        )

    def _build_partitions(self) -> dict[HoldoutPartition, list[HoldoutRecord]]:
        ordered = sorted(
            self._records,
            key=lambda record: _partition_sort_key(self.policy.split_seed, record),
        )
        total = len(ordered)
        train_count = int(total * self.policy.train_fraction)
        reward_count = int(total * self.policy.reward_fraction)
        final_count = total - train_count - reward_count

        train_count = max(train_count, self.policy.min_train_records)
        reward_count = max(reward_count, self.policy.min_reward_records)
        final_count = max(final_count, self.policy.min_final_validation_records)
        minimum_total = train_count + reward_count + final_count
        if minimum_total > total:
            raise ValueError("not enough records to satisfy holdout minimums")

        remaining = total - minimum_total
        train_count += remaining
        reward_start = train_count
        final_start = train_count + reward_count
        return {
            HoldoutPartition.TRAIN: ordered[:reward_start],
            HoldoutPartition.REWARD: ordered[reward_start:final_start],
            HoldoutPartition.FINAL_VALIDATION: ordered[final_start:],
        }

    def _validate_minimums(self) -> None:
        counts = self.partition_counts
        if counts[HoldoutPartition.TRAIN.value] < self.policy.min_train_records:
            raise ValueError("train holdout partition is too small")
        if counts[HoldoutPartition.REWARD.value] < self.policy.min_reward_records:
            raise ValueError("reward holdout partition is too small")
        if counts[HoldoutPartition.FINAL_VALIDATION.value] < self.policy.min_final_validation_records:
            raise ValueError("final validation holdout partition is too small")


def _normalize_records(records: Mapping[str, bytes | HoldoutRecord]) -> list[HoldoutRecord]:
    normalized: list[HoldoutRecord] = []
    seen_ids: set[str] = set()
    for record_id, value in records.items():
        if record_id in seen_ids:
            raise ValueError("record IDs must be unique")
        seen_ids.add(record_id)
        if isinstance(value, HoldoutRecord):
            if value.record_id != record_id:
                raise ValueError("mapping key must match HoldoutRecord.record_id")
            normalized.append(value)
        else:
            normalized.append(HoldoutRecord(record_id=record_id, payload=bytes(value)))
    if not normalized:
        raise ValueError("hidden holdout set requires at least one record")
    return normalized


def _partition_sort_key(seed: str, record: HoldoutRecord) -> str:
    return _sha256_json({
        "seed": seed,
        "record_id": record.record_id,
        "record_hash": record.record_hash,
    })


def _partition_record_hash(
    seed: str,
    partition: HoldoutPartition,
    record: HoldoutRecord,
) -> str:
    return _sha256_json({
        "seed": seed,
        "partition": partition.value,
        "record_hash": record.record_hash,
    })


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_hex(json.dumps(_stable_public(value), sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _private_partition_count_band(count: int) -> str:
    """Coarse public band for a TEE-internal partition cardinality."""

    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("partition count must be a non-negative int")
    if count == 0:
        return "none"
    if count <= 8:
        return "small_1_to_8"
    if count <= 64:
        return "medium_9_to_64"
    if count <= 512:
        return "large_65_to_512"
    return "very_large_gt_512"


def _stable_public(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _stable_public(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_stable_public(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
