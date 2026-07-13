"""Deterministic data-quality checks for bio-validation datasets.

A bio-validation result is only as trustworthy as the dataset it was computed
over. This module turns dataset *metadata* into a bounded, deterministic quality
assessment that plugs into the fail-closed release gate: a result computed on an
insufficient sample or a train/test-contaminated split is held for review rather
than released, because such a result is misleading, not merely low-quality.

Pure policy: no network, no Tinker, no raw data. The caller supplies only counts
and booleans (a `DatasetProfile`), never records; the assessment returns only a
quality band, bounded flags, a `blocks_release` boolean, and a profile hash.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class DataQualityBand(str, Enum):
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    WITHHELD = "withheld"


class DataQualityError(ValueError):
    """Raised when a data-quality assessment cannot be performed."""


@dataclass(frozen=True)
class DataQualityPolicy:
    min_samples: int = 30
    max_missing_fraction: float = 0.2
    max_duplicate_fraction: float = 0.1
    min_class_count: int = 5
    max_class_imbalance_ratio: float = 10.0
    forbid_train_test_contamination: bool = True

    def __post_init__(self) -> None:
        if self.min_samples < 1:
            raise DataQualityError("min_samples must be >= 1")
        for name in ("max_missing_fraction", "max_duplicate_fraction"):
            value = getattr(self, name)
            if not (0.0 <= value <= 1.0):
                raise DataQualityError(f"{name} must be in [0, 1]")
        if self.min_class_count < 1:
            raise DataQualityError("min_class_count must be >= 1")
        if self.max_class_imbalance_ratio < 1.0:
            raise DataQualityError("max_class_imbalance_ratio must be >= 1")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "min_samples": self.min_samples,
            "max_missing_fraction": self.max_missing_fraction,
            "max_duplicate_fraction": self.max_duplicate_fraction,
            "min_class_count": self.min_class_count,
            "max_class_imbalance_ratio": self.max_class_imbalance_ratio,
            "forbid_train_test_contamination": self.forbid_train_test_contamination,
        }


@dataclass(frozen=True)
class DatasetProfile:
    """Bounded metadata about a (synthetic/toy) dataset. Counts only, no records.

    - `n_samples` / `n_features`: shape.
    - `n_missing_cells`: total missing cells across the sample x feature grid.
    - `n_duplicate_rows`: rows that duplicate an earlier row.
    - `class_counts`: label -> count (empty for non-classification tasks).
    - `train_test_overlap`: number of rows shared between train and test splits.
    - `expected_features`: declared schema width; a mismatch is a schema error.
    """

    n_samples: int
    n_features: int
    n_missing_cells: int = 0
    n_duplicate_rows: int = 0
    class_counts: Mapping[str, int] = field(default_factory=dict)
    train_test_overlap: int = 0
    expected_features: int | None = None

    def __post_init__(self) -> None:
        if self.n_samples < 1:
            raise DataQualityError("n_samples must be >= 1")
        if self.n_features < 1:
            raise DataQualityError("n_features must be >= 1")
        for name in ("n_missing_cells", "n_duplicate_rows", "train_test_overlap"):
            if getattr(self, name) < 0:
                raise DataQualityError(f"{name} must be >= 0")
        if self.n_missing_cells > self.n_samples * self.n_features:
            raise DataQualityError("n_missing_cells exceeds the sample x feature grid")
        if self.n_duplicate_rows >= self.n_samples:
            raise DataQualityError("n_duplicate_rows must be < n_samples")
        for label, count in self.class_counts.items():
            if not isinstance(label, str) or not isinstance(count, int) or count < 0:
                raise DataQualityError("class_counts must be str->non-negative int")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "n_samples": self.n_samples,
            "n_features": self.n_features,
            "n_missing_cells": self.n_missing_cells,
            "n_duplicate_rows": self.n_duplicate_rows,
            "class_count": len(self.class_counts),
            "train_test_overlap": self.train_test_overlap,
            "expected_features": self.expected_features,
        }


@dataclass(frozen=True)
class DataQualityReport:
    """Bounded data-quality assessment. Only band/flags/booleans/hash egress."""

    quality_band: DataQualityBand
    blocks_release: bool
    flags: tuple[str, ...]
    profile_hash: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "quality_band": self.quality_band.value,
            "blocks_release": self.blocks_release,
            "flags": list(self.flags),
            "profile_hash": self.profile_hash,
            "raw_secret_egress": False,
        }


# Flags that invalidate a result outright (a computed metric would be
# misleading), versus flags that only degrade the quality band.
_BLOCKING_FLAGS = frozenset({"insufficient_samples", "train_test_contamination", "schema_mismatch"})


def _profile_hash(profile: DatasetProfile, policy: DataQualityPolicy) -> str:
    payload = {"profile": profile.to_public_dict(), "policy": policy.to_public_dict()}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    return f"dq_{digest[:48]}"


def assess_data_quality(
    profile: DatasetProfile,
    policy: DataQualityPolicy | None = None,
) -> DataQualityReport:
    """Deterministically assess dataset quality from bounded metadata.

    Blocking flags (`insufficient_samples`, `train_test_contamination`,
    `schema_mismatch`) force `blocks_release=true` and a POOR band. Non-blocking
    flags (`excessive_missingness`, `excessive_duplicates`, `class_imbalance`,
    `underpopulated_class`) degrade the band: FAIR for one, POOR for two or more.
    """

    policy = policy or DataQualityPolicy()
    flags: list[str] = []

    if profile.expected_features is not None and profile.n_features != profile.expected_features:
        flags.append("schema_mismatch")
    if profile.n_samples < policy.min_samples:
        flags.append("insufficient_samples")
    if policy.forbid_train_test_contamination and profile.train_test_overlap > 0:
        flags.append("train_test_contamination")

    grid = profile.n_samples * profile.n_features
    if grid > 0 and profile.n_missing_cells / grid > policy.max_missing_fraction:
        flags.append("excessive_missingness")
    if profile.n_duplicate_rows / profile.n_samples > policy.max_duplicate_fraction:
        flags.append("excessive_duplicates")

    counts = [c for c in profile.class_counts.values()]
    if counts:
        if min(counts) < policy.min_class_count:
            flags.append("underpopulated_class")
        if min(counts) > 0 and max(counts) / min(counts) > policy.max_class_imbalance_ratio:
            flags.append("class_imbalance")

    flags_sorted = tuple(sorted(set(flags)))
    blocking = bool(_BLOCKING_FLAGS.intersection(flags_sorted))
    non_blocking = [f for f in flags_sorted if f not in _BLOCKING_FLAGS]

    if blocking or len(non_blocking) >= 2:
        band = DataQualityBand.POOR
    elif non_blocking:
        band = DataQualityBand.FAIR
    else:
        band = DataQualityBand.GOOD

    return DataQualityReport(
        quality_band=band,
        blocks_release=blocking,
        flags=flags_sorted,
        profile_hash=_profile_hash(profile, policy),
    )
