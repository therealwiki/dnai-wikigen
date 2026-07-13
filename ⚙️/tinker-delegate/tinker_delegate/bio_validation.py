"""Bio-validation target: fail-closed bounded release gate for bio/dual-use output.

This module is the code-level counterpart of the bio-validation target defined
in `docs/BIO_VALIDATION.md`. It exists to make one non-negotiable invariant real
instead of aspirational:

    Bio/dual-use outputs must fail closed until the risk screen, reviewer queue,
    and bounded result schema are real.

The gate never releases raw bio data, raw candidate text, raw evaluator traces,
or exact continuous rewards. A caller submits a candidate bio-validation result;
the gate returns only a bounded decision (`release` / `hold` / `deny`), a bounded
result schema (bands and hashes), a forbidden-output screen summary, and a review
route when held. Until every readiness capability is explicitly enabled, the gate
holds for human review rather than releasing.

Nothing here calls Tinker, touches the network, or reads sealed data. It is a
deterministic policy kernel over an already-computed bounded result.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "bio-validation-target-v1"


class BioReleaseDecision(str, Enum):
    """Bounded release decision for a bio-validation result."""

    RELEASE = "release"
    HOLD = "hold"
    DENY = "deny"


class BioBand(str, Enum):
    """Coarse band shared by score / confidence / utility fields."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    WITHHELD = "withheld"


class BioSafetyBand(str, Enum):
    """Safety posture of the result, independent of utility."""

    CLEARED = "cleared"
    REVIEW = "review"
    BLOCKED = "blocked"


class BioReviewRoute(str, Enum):
    """Where a held result is routed for human review."""

    EXPERT_IN_THE_LOOP = "expert-in-the-loop"
    BIOSECURITY_REVIEW = "biosecurity-review"
    ACCESS_REVIEW_OFFICER = "access-review-officer"


class BioValidationError(ValueError):
    """Raised when a bio-validation request cannot be handled safely."""


# Forbidden output categories for bio/dual-use results. These are matched against
# any operator-supplied free-text so that raw, dual-use, or reconstruction-prone
# material never rides out through the "methodology" or "notes" channel. The
# patterns are intentionally broad: on any match the gate denies or blocks.
# Separator between tokens of a compound dangerous term. A safety screen must
# not be evadable by swapping the word separator: `gain-of-function`,
# `gain_of_function` (ubiquitous in code-derived identifiers), `gain.of.function`,
# `gain of function`, and even the concatenated `gainoffunction` are all the same
# term and must all be caught. `*` (zero-or-more) covers the concatenated form as
# defense-in-depth; false positives are near-impossible because the ordered token
# sequence is itself the dangerous term.
_SEP = r"[-_.\s]*"

_FORBIDDEN_PATTERNS: dict[str, tuple[str, ...]] = {
    "wetlab_protocol": (
        rf"\bwet{_SEP}lab\b",
        r"\bprotocol\s+step",
        r"\breagent",
        r"\bpcr\s+cycle",
        r"\bculture\s+condition",
        r"\bsynthesi[sz]e\b",
    ),
    "pathogen_enhancement": (
        rf"\bgain{_SEP}of{_SEP}function\b",
        r"\benhance\w*\s+(?:virulence|transmissib|pathogen)",
        r"\bincrease\w*\s+(?:lethality|transmissib)",
        r"\bpathogen\s+enhanc",
    ),
    "de_novo_harmful_design": (
        rf"\bde{_SEP}novo\b",
        r"\bdesign\w*\s+(?:toxin|pathogen|virus|bioweapon)",
        r"\bnovel\s+(?:toxin|pathogen|agent)",
    ),
    "patient_level_output": (
        r"\bpatient\s+id\b",
        r"\bmrn\b",
        r"\bmedical\s+record\s+number",
        r"\bindividual[- ]level\s+(?:record|label|outcome)",
    ),
    "raw_records": (
        r"\braw\s+(?:record|sample|read|sequence|genotype)",
        r"\bfastq\b",
        r"\bvcf\s+row",
    ),
    "model_weights": (
        r"\bmodel\s+weight",
        r"\bcheckpoint\s+(?:bytes|blob|path)",
        r"\bstate[_ ]dict\b",
    ),
    "reconstruction_prone_stats": (
        r"\bper[- ]record\b",
        r"\bexact\s+(?:count|value|reward|loss)\b",
        r"\bfull\s+confusion\s+matrix",
        r"\bmembership\s+inference",
    ),
}


@dataclass(frozen=True)
class BioReadiness:
    """Explicit capability flags. Every flag must be true before any release.

    Defaults are all false so that a fresh/misconfigured deployment fails closed.
    """

    risk_screen_enabled: bool = False
    reviewer_queue_enabled: bool = False
    bounded_schema_enabled: bool = False
    synthetic_or_approved_data_only: bool = False

    def missing(self) -> tuple[str, ...]:
        missing: list[str] = []
        if not self.risk_screen_enabled:
            missing.append("risk_screen")
        if not self.reviewer_queue_enabled:
            missing.append("reviewer_queue")
        if not self.bounded_schema_enabled:
            missing.append("bounded_schema")
        if not self.synthetic_or_approved_data_only:
            missing.append("data_policy")
        return tuple(missing)

    def all_ready(self) -> bool:
        return not self.missing()


@dataclass(frozen=True)
class BioResultCandidate:
    """A bounded bio-validation result proposed for release.

    Bands are already coarse. Free-text fields are screened, never released
    verbatim; only their hash and screen verdict leave the gate.
    """

    use_case_id: str
    methodology_class: str
    score_band: BioBand = BioBand.WITHHELD
    confidence_band: BioBand = BioBand.WITHHELD
    utility_band: BioBand = BioBand.WITHHELD
    data_quality_flags: tuple[str, ...] = ()
    compute_cost_band: str = "unknown"
    # Free-text the caller wants to attach (methodology notes, failure notes).
    # Screened for forbidden content; only a hash and verdict are emitted.
    free_text_fields: dict[str, str] = field(default_factory=dict)
    # Whether the caller asserts the result derives from an individual-level
    # dataset. Individual-level data forces a fail-closed hold absent DP marking.
    individual_level_data: bool = False
    differential_privacy_marked: bool = False

    def __post_init__(self) -> None:
        if not self.use_case_id or not isinstance(self.use_case_id, str):
            raise BioValidationError("use_case_id is required")
        if not self.methodology_class or not isinstance(self.methodology_class, str):
            raise BioValidationError("methodology_class is required")
        if not isinstance(self.free_text_fields, dict):
            raise BioValidationError("free_text_fields must be a mapping")
        for key, value in self.free_text_fields.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise BioValidationError("free_text_fields must be string->string")


def _stable_hash(value: str, *, prefix: str) -> str:
    digest = hashlib.sha256(f"{prefix}:{value}".encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:48]}"


def screen_forbidden_output(text: str) -> tuple[str, ...]:
    """Return the sorted set of forbidden categories matched in `text`."""

    lowered = text.lower()
    matched: set[str] = set()
    for category, patterns in _FORBIDDEN_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, lowered):
                matched.add(category)
                break
    return tuple(sorted(matched))


def _screen_candidate(candidate: BioResultCandidate) -> tuple[tuple[str, ...], dict[str, Any]]:
    """Screen every free-text field; return matched categories and a bounded map."""

    all_matched: set[str] = set()
    field_summaries: dict[str, Any] = {}
    for key, value in sorted(candidate.free_text_fields.items()):
        matched = screen_forbidden_output(value)
        all_matched.update(matched)
        field_summaries[key] = {
            "text_hash": _stable_hash(value, prefix="bio_text"),
            "matched_category_count": len(matched),
            "clean": not matched,
        }
    return tuple(sorted(all_matched)), field_summaries


@dataclass(frozen=True)
class BioReleaseReceipt:
    """Bounded, egress-safe receipt of a release decision."""

    decision: BioReleaseDecision
    safety_band: BioSafetyBand
    review_route: BioReviewRoute | None
    reason_code: str
    readiness_missing: tuple[str, ...]
    forbidden_categories: tuple[str, ...]
    result_schema: dict[str, Any]
    result_hash: str

    def to_public_dict(self) -> dict[str, Any]:
        from tinker_delegate.decision_explainer import explain_decision

        return {
            "schema_version": SCHEMA_VERSION,
            "decision": self.decision.value,
            "safety_band": self.safety_band.value,
            "review_route": self.review_route.value if self.review_route else None,
            "reason_code": self.reason_code,
            # Self-explaining receipt: a bounded, leak-free policy explanation of
            # the reason code (its ":suffix" is stripped, so no detail leaks).
            "explanation": explain_decision(self.reason_code).to_public_dict(),
            "readiness_missing": list(self.readiness_missing),
            "forbidden_categories": list(self.forbidden_categories),
            "result_schema": self.result_schema,
            "result_hash": self.result_hash,
            "raw_secret_egress": False,
        }


def _bounded_result_schema(
    candidate: BioResultCandidate,
    *,
    safety_band: BioSafetyBand,
    field_summaries: dict[str, Any],
    released: bool,
) -> dict[str, Any]:
    """Assemble the bounded result schema. Bands are withheld unless released."""

    def band(value: BioBand) -> str:
        return value.value if released else BioBand.WITHHELD.value

    return {
        "use_case_id": candidate.use_case_id,
        "methodology_class": candidate.methodology_class,
        "score_band": band(candidate.score_band),
        "confidence_band": band(candidate.confidence_band),
        "safety_band": safety_band.value,
        "utility_band": band(candidate.utility_band),
        "compute_cost_band": candidate.compute_cost_band if released else "withheld",
        "data_quality_flags": sorted(candidate.data_quality_flags) if released else [],
        "free_text_screen": field_summaries,
        "released": released,
    }


def _result_hash(candidate: BioResultCandidate, safety_band: BioSafetyBand) -> str:
    payload = {
        "use_case_id": candidate.use_case_id,
        "methodology_class": candidate.methodology_class,
        "score_band": candidate.score_band.value,
        "confidence_band": candidate.confidence_band.value,
        "utility_band": candidate.utility_band.value,
        "safety_band": safety_band.value,
        "data_quality_flags": sorted(candidate.data_quality_flags),
        "individual_level_data": candidate.individual_level_data,
    }
    return _stable_hash(json.dumps(payload, sort_keys=True), prefix="bio_result")


def evaluate_bio_release(
    candidate: BioResultCandidate,
    readiness: BioReadiness,
    *,
    dual_use: "DualUseAssessment | None" = None,
    reid: "ReidAssessment | None" = None,
    data_quality: "DataQualityReport | None" = None,
    dp_charge: "DpChargeResult | None" = None,
    require_dual_use_screen: bool = False,
) -> BioReleaseReceipt:
    """Fail-closed release gate for a bounded bio-validation result.

    Order of checks (most protective first):
      1. Forbidden output content -> DENY / BLOCKED (never releasable).
      2. Dual-use tier PROHIBITED -> DENY; REVIEW -> HOLD / BIOSECURITY_REVIEW.
      3. Re-identification risk that blocks -> HOLD / BIOSECURITY_REVIEW.
      4. Individual-level data without a satisfied DP budget -> HOLD /
         BIOSECURITY_REVIEW.
      5. Data-quality validity failure that blocks -> HOLD / EXPERT_IN_THE_LOOP.
      6. Any missing readiness capability -> HOLD / EXPERT_IN_THE_LOOP.
      7. All clear -> RELEASE / CLEARED with bounded bands.

    `dual_use`, `reid`, and `data_quality` are optional bounded assessments (see
    `bio_dual_use.classify_dual_use`, `bio_reid.assess_reidentification`, and
    `bio_data_quality.assess_data_quality`); when any blocks, release is held (or
    denied for a prohibited dual-use tier) even if every readiness capability is
    enabled.

    The forbidden-output *text* screen always runs. The *structured* dual-use
    classifier is caller-supplied because the danger signals (pathogen, toxin,
    gain-of-function) are declared metadata the candidate does not carry. A
    caller handling a potentially dual-use domain should set
    `require_dual_use_screen=True`: then a missing `dual_use` assessment fails
    closed to HOLD (a structurally-dangerous task, e.g. gain-of-function, whose
    text fields look benign cannot silently RELEASE by omitting the screen).
    """

    forbidden_categories, field_summaries = _screen_candidate(candidate)

    if forbidden_categories:
        safety_band = BioSafetyBand.BLOCKED
        schema = _bounded_result_schema(
            candidate, safety_band=safety_band, field_summaries=field_summaries, released=False
        )
        return BioReleaseReceipt(
            decision=BioReleaseDecision.DENY,
            safety_band=safety_band,
            review_route=BioReviewRoute.BIOSECURITY_REVIEW,
            reason_code="forbidden_output_detected",
            readiness_missing=readiness.missing(),
            forbidden_categories=forbidden_categories,
            result_schema=schema,
            result_hash=_result_hash(candidate, safety_band),
        )

    if require_dual_use_screen and dual_use is None:
        # A caller in a dual-use domain required the structured screen, but none
        # was supplied: fail closed to human review rather than silently clearing
        # the structured axis (the text screen alone can't see declared danger).
        safety_band = BioSafetyBand.REVIEW
        schema = _bounded_result_schema(
            candidate, safety_band=safety_band, field_summaries=field_summaries, released=False
        )
        return BioReleaseReceipt(
            decision=BioReleaseDecision.HOLD,
            safety_band=safety_band,
            review_route=BioReviewRoute.BIOSECURITY_REVIEW,
            reason_code="dual_use_screen_required",
            readiness_missing=readiness.missing(),
            forbidden_categories=(),
            result_schema=schema,
            result_hash=_result_hash(candidate, safety_band),
        )

    if dual_use is not None and dual_use.blocks_release:
        deny = dual_use.denies_release
        safety_band = BioSafetyBand.BLOCKED if deny else BioSafetyBand.REVIEW
        schema = _bounded_result_schema(
            candidate, safety_band=safety_band, field_summaries=field_summaries, released=False
        )
        schema["dual_use"] = dual_use.to_public_dict()
        return BioReleaseReceipt(
            decision=BioReleaseDecision.DENY if deny else BioReleaseDecision.HOLD,
            safety_band=safety_band,
            review_route=BioReviewRoute.BIOSECURITY_REVIEW,
            reason_code=f"dual_use_{dual_use.tier.value}:{','.join(dual_use.reasons)}",
            readiness_missing=readiness.missing(),
            forbidden_categories=(),
            result_schema=schema,
            result_hash=_result_hash(candidate, safety_band),
        )

    if reid is not None and reid.blocks_release:
        safety_band = BioSafetyBand.REVIEW
        schema = _bounded_result_schema(
            candidate, safety_band=safety_band, field_summaries=field_summaries, released=False
        )
        schema["reid_assessment"] = reid.to_public_dict()
        return BioReleaseReceipt(
            decision=BioReleaseDecision.HOLD,
            safety_band=safety_band,
            review_route=BioReviewRoute.BIOSECURITY_REVIEW,
            reason_code=f"reidentification_risk:{reid.reason_code}",
            readiness_missing=readiness.missing(),
            forbidden_categories=(),
            result_schema=schema,
            result_hash=_result_hash(candidate, safety_band),
        )

    if candidate.individual_level_data:
        # A live DP charge, when supplied, takes precedence over the asserted
        # boolean: it must be an admitted, PHI-safe (DP-mode) release. Otherwise
        # fall back to the legacy caller-asserted `differential_privacy_marked`.
        if dp_charge is not None:
            dp_satisfied = bool(dp_charge.allowed and dp_charge.phi_safe)
            dp_reason = f"individual_level_data_dp_{dp_charge.reason_code}"
        else:
            dp_satisfied = candidate.differential_privacy_marked
            dp_reason = "individual_level_data_not_dp_marked"
        if not dp_satisfied:
            safety_band = BioSafetyBand.REVIEW
            schema = _bounded_result_schema(
                candidate, safety_band=safety_band, field_summaries=field_summaries, released=False
            )
            if dp_charge is not None:
                schema["dp_accounting"] = dp_charge.to_public_dict()
            return BioReleaseReceipt(
                decision=BioReleaseDecision.HOLD,
                safety_band=safety_band,
                review_route=BioReviewRoute.BIOSECURITY_REVIEW,
                reason_code=dp_reason,
                readiness_missing=readiness.missing(),
                forbidden_categories=(),
                result_schema=schema,
                result_hash=_result_hash(candidate, safety_band),
            )

    if data_quality is not None and data_quality.blocks_release:
        safety_band = BioSafetyBand.REVIEW
        schema = _bounded_result_schema(
            candidate, safety_band=safety_band, field_summaries=field_summaries, released=False
        )
        schema["data_quality"] = data_quality.to_public_dict()
        return BioReleaseReceipt(
            decision=BioReleaseDecision.HOLD,
            safety_band=safety_band,
            review_route=BioReviewRoute.EXPERT_IN_THE_LOOP,
            reason_code=f"data_quality_invalid:{','.join(data_quality.flags)}",
            readiness_missing=readiness.missing(),
            forbidden_categories=(),
            result_schema=schema,
            result_hash=_result_hash(candidate, safety_band),
        )

    missing = readiness.missing()
    if missing:
        safety_band = BioSafetyBand.REVIEW
        schema = _bounded_result_schema(
            candidate, safety_band=safety_band, field_summaries=field_summaries, released=False
        )
        return BioReleaseReceipt(
            decision=BioReleaseDecision.HOLD,
            safety_band=safety_band,
            review_route=BioReviewRoute.EXPERT_IN_THE_LOOP,
            reason_code="readiness_incomplete",
            readiness_missing=missing,
            forbidden_categories=(),
            result_schema=schema,
            result_hash=_result_hash(candidate, safety_band),
        )

    safety_band = BioSafetyBand.CLEARED
    schema = _bounded_result_schema(
        candidate, safety_band=safety_band, field_summaries=field_summaries, released=True
    )
    if dp_charge is not None and candidate.individual_level_data:
        schema["dp_accounting"] = dp_charge.to_public_dict()
    return BioReleaseReceipt(
        decision=BioReleaseDecision.RELEASE,
        safety_band=safety_band,
        review_route=None,
        reason_code="cleared_bounded_release",
        readiness_missing=(),
        forbidden_categories=(),
        result_schema=schema,
        result_hash=_result_hash(candidate, safety_band),
    )
