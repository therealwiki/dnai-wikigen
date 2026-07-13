"""Deterministic re-identification risk checks for bio-validation outputs.

Even when a bio result is an *aggregate* (never an individual-level record), it
can still re-identify people if it is computed over a tiny cohort or reports
small-cell breakdowns (the classic small-cell / k-anonymity problem). This module
turns that risk into a bounded, deterministic assessment that plugs into the
fail-closed release gate in `bio_validation.py`.

It is pure policy: no network, no Tinker, no raw data. The caller supplies only
cohort *metadata* (counts and booleans), never records; the assessment returns
only a coarse risk band and a `blocks_release` boolean plus a bounded hash.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


class ReidRiskBand(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    WITHHELD = "withheld"


class ReidError(ValueError):
    """Raised when a re-identification assessment cannot be performed."""


@dataclass(frozen=True)
class ReidPolicy:
    """Thresholds for small-cohort / small-cell re-identification risk.

    `min_cohort_size` is the k-anonymity threshold: reported subgroups smaller
    than k are considered directly re-identifying unless suppressed. Below
    `2*k` is flagged as elevated (medium) but not blocking on its own.
    """

    min_cohort_size: int = 11  # common small-cell suppression threshold
    medium_multiple: int = 2

    def __post_init__(self) -> None:
        if self.min_cohort_size < 1:
            raise ReidError("min_cohort_size must be >= 1")
        if self.medium_multiple < 1:
            raise ReidError("medium_multiple must be >= 1")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "min_cohort_size": self.min_cohort_size,
            "medium_multiple": self.medium_multiple,
        }


@dataclass(frozen=True)
class CohortReport:
    """Bounded metadata about the cohort an aggregate result was computed over.

    - `n_records`: total records in the cohort.
    - `min_subgroup_size`: smallest subgroup size across any reported breakdown
      (equals `n_records` when no breakdown is reported).
    - `aggregates_only`: the output is aggregate statistics, not per-record rows.
    - `small_cells_suppressed`: subgroups below the k threshold were suppressed
      / merged before any release.
    """

    n_records: int
    min_subgroup_size: int
    aggregates_only: bool = True
    small_cells_suppressed: bool = False

    def __post_init__(self) -> None:
        if self.n_records < 1:
            raise ReidError("n_records must be >= 1")
        if self.min_subgroup_size < 1:
            raise ReidError("min_subgroup_size must be >= 1")
        if self.min_subgroup_size > self.n_records:
            raise ReidError("min_subgroup_size cannot exceed n_records")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "n_records": self.n_records,
            "min_subgroup_size": self.min_subgroup_size,
            "aggregates_only": self.aggregates_only,
            "small_cells_suppressed": self.small_cells_suppressed,
        }


@dataclass(frozen=True)
class ReidAssessment:
    """Bounded re-identification assessment. Only bands/booleans/hashes egress."""

    risk_band: ReidRiskBand
    blocks_release: bool
    reason_code: str
    report_hash: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "risk_band": self.risk_band.value,
            "blocks_release": self.blocks_release,
            "reason_code": self.reason_code,
            "report_hash": self.report_hash,
            "raw_secret_egress": False,
        }


def _report_hash(report: CohortReport, policy: ReidPolicy) -> str:
    payload = {"report": report.to_public_dict(), "policy": policy.to_public_dict()}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    return f"reid_{digest[:48]}"


def assess_reidentification(
    report: CohortReport,
    policy: ReidPolicy | None = None,
) -> ReidAssessment:
    """Deterministically assess small-cohort / small-cell re-identification risk.

    Blocking (fail-closed) conditions:
      - a reported subgroup smaller than k that was NOT suppressed;
      - non-aggregate (per-record) output with any subgroup below k.
    Elevated-but-not-blocking (medium): smallest subgroup in [k, medium_multiple*k).
    Otherwise low.
    """

    policy = policy or ReidPolicy()
    report_hash = _report_hash(report, policy)
    k = policy.min_cohort_size

    if not report.aggregates_only and report.min_subgroup_size < k:
        return ReidAssessment(
            ReidRiskBand.HIGH, True, "individual_level_small_subgroup", report_hash
        )
    if report.min_subgroup_size < k and not report.small_cells_suppressed:
        return ReidAssessment(
            ReidRiskBand.HIGH, True, "unsuppressed_small_cell", report_hash
        )
    if report.min_subgroup_size < k * policy.medium_multiple:
        return ReidAssessment(
            ReidRiskBand.MEDIUM, False, "elevated_small_cohort", report_hash
        )
    return ReidAssessment(ReidRiskBand.LOW, False, "cohort_above_threshold", report_hash)
