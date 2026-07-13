"""Deterministic dual-use / biosecurity risk classifier.

The forbidden-output screen in `bio_validation.py` scans free *text* for
dangerous content. This module is the complementary axis: a deterministic
classifier over *structured* declared signals about what a bio-validation task
does (does it touch a pathogen? does it emit sequences or wetlab protocols? is
it gain-of-function?). It assigns a dual-use risk tier from an explicit policy —
not an LLM judgment — so the decision is auditable and reproducible.

Pure policy: no network, no model, no raw data. The caller declares bounded
feature booleans; the classifier returns only a risk tier, a gate decision hint,
bounded matched-signal reasons, and a hash. This is deliberately conservative:
ambiguous or unknown cases escalate, they do not clear.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


class DualUseTier(str, Enum):
    CLEARED = "cleared"
    REVIEW = "review"
    PROHIBITED = "prohibited"


class DualUseError(ValueError):
    """Raised when a dual-use classification cannot be performed."""


@dataclass(frozen=True)
class DualUseFeatures:
    """Declared structured signals about a bio-validation task. Booleans only.

    All fields are caller-asserted metadata, never raw data. Defaults are the
    lower-risk value EXCEPT `synthetic_or_public_data_only`, which defaults True
    only because the first supported use cases are synthetic; a caller working
    with real data must set it False so the classifier escalates.
    """

    involves_pathogen: bool = False
    involves_toxin: bool = False
    involves_gain_of_function: bool = False
    de_novo_agent_design: bool = False
    produces_sequences: bool = False       # emits nucleotide/protein sequences
    produces_wetlab_protocol: bool = False  # emits actionable wetlab steps
    involves_human_subjects: bool = False
    human_subjects_irb_approved: bool = False
    synthetic_or_public_data_only: bool = True

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "involves_pathogen": self.involves_pathogen,
            "involves_toxin": self.involves_toxin,
            "involves_gain_of_function": self.involves_gain_of_function,
            "de_novo_agent_design": self.de_novo_agent_design,
            "produces_sequences": self.produces_sequences,
            "produces_wetlab_protocol": self.produces_wetlab_protocol,
            "involves_human_subjects": self.involves_human_subjects,
            "human_subjects_irb_approved": self.human_subjects_irb_approved,
            "synthetic_or_public_data_only": self.synthetic_or_public_data_only,
        }


@dataclass(frozen=True)
class DualUseAssessment:
    """Bounded dual-use assessment. Only tier/decision/reasons/hash egress."""

    tier: DualUseTier
    reasons: tuple[str, ...]
    features_hash: str

    @property
    def blocks_release(self) -> bool:
        return self.tier in (DualUseTier.REVIEW, DualUseTier.PROHIBITED)

    @property
    def denies_release(self) -> bool:
        return self.tier == DualUseTier.PROHIBITED

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value,
            "blocks_release": self.blocks_release,
            "denies_release": self.denies_release,
            "reasons": list(self.reasons),
            "features_hash": self.features_hash,
            "raw_secret_egress": False,
        }


def _features_hash(features: DualUseFeatures) -> str:
    digest = hashlib.sha256(
        json.dumps(features.to_public_dict(), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return f"dualuse_{digest[:48]}"


def classify_dual_use(features: DualUseFeatures) -> DualUseAssessment:
    """Deterministically classify a task's dual-use risk tier.

    PROHIBITED (deny): gain-of-function, de novo agent design, or emitting
    sequences/wetlab protocols in a pathogen/toxin context.
    REVIEW (hold): pathogen/toxin context, sequence/protocol emission, human
    subjects without IRB approval, or non-synthetic/public data.
    CLEARED: none of the above.
    """

    reasons: list[str] = []
    features_hash = _features_hash(features)

    actionable_output = features.produces_sequences or features.produces_wetlab_protocol
    dangerous_context = features.involves_pathogen or features.involves_toxin

    # Prohibited signals (each independently sufficient).
    if features.involves_gain_of_function:
        reasons.append("gain_of_function")
    if features.de_novo_agent_design:
        reasons.append("de_novo_agent_design")
    if dangerous_context and actionable_output:
        reasons.append("actionable_output_in_dangerous_context")

    if reasons:
        return DualUseAssessment(DualUseTier.PROHIBITED, tuple(sorted(set(reasons))), features_hash)

    # Review signals.
    if features.involves_pathogen:
        reasons.append("pathogen_context")
    if features.involves_toxin:
        reasons.append("toxin_context")
    if features.produces_sequences:
        reasons.append("emits_sequences")
    if features.produces_wetlab_protocol:
        reasons.append("emits_wetlab_protocol")
    if features.involves_human_subjects and not features.human_subjects_irb_approved:
        reasons.append("human_subjects_without_irb")
    if not features.synthetic_or_public_data_only:
        reasons.append("non_synthetic_data")

    if reasons:
        return DualUseAssessment(DualUseTier.REVIEW, tuple(sorted(set(reasons))), features_hash)

    return DualUseAssessment(DualUseTier.CLEARED, (), features_hash)
