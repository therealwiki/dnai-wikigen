"""Deterministic stub bio evaluator over synthetic assay-QC data.

This is the first concrete bio-validation evaluator (see `docs/BIO_VALIDATION.md`
first use case: synthetic assay QC). It computes bounded quality *bands* from
synthetic/public toy assay measurements and hands them to the fail-closed release
gate in `bio_validation.py`. It is deliberately:

- Deterministic: same input -> same bands (no RNG, no network, no Tinker).
- Synthetic-only: operates on caller-supplied toy numbers, never real bio data.
- Bounded: only coarse bands and public data-quality flags leave the evaluator;
  the exact Z'-factor / signal statistics stay internal, mirroring the private-
  reward "no exact reward egress" rule.
- Fail-closed downstream: the evaluator never releases anything itself; its
  `BioResultCandidate` still passes through `evaluate_bio_release`, which holds
  unless every readiness capability is enabled.

The QC metric is the standard Z'-factor
(Zhang, Chung & Oldenburg, 1999): `Z' = 1 - 3*(sigma_p + sigma_n)/|mu_p - mu_n|`,
a well-known screening-assay quality score. Using a real, published metric keeps
the stub honest while carrying no dual-use content.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any, Sequence

from tinker_delegate.bio_validation import (
    BioBand,
    BioReadiness,
    BioReleaseReceipt,
    BioResultCandidate,
    BioValidationError,
    evaluate_bio_release,
)

USE_CASE_ID = "synthetic_assay_qc"
METHODOLOGY_CLASS = "synthetic_assay_qc_zprime"


@dataclass(frozen=True)
class SyntheticAssay:
    """Synthetic assay-QC measurements. Toy numbers only — never real bio data.

    `positive_controls` and `negative_controls` are replicate signal readings for
    the high and low controls of a screening plate; `replicates` is the per-point
    replicate count the caller ran. Values are unitless synthetic intensities.
    """

    positive_controls: Sequence[float]
    negative_controls: Sequence[float]
    replicates: int = 1
    free_text_fields: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        pos = [float(v) for v in self.positive_controls]
        neg = [float(v) for v in self.negative_controls]
        if len(pos) < 2 or len(neg) < 2:
            raise BioValidationError("assay QC requires at least 2 positive and 2 negative controls")
        if any(not _finite(v) for v in pos + neg):
            raise BioValidationError("assay measurements must be finite")
        if self.replicates < 1:
            raise BioValidationError("replicates must be >= 1")
        if not isinstance(self.free_text_fields, dict):
            raise BioValidationError("free_text_fields must be a mapping")


def _finite(value: float) -> bool:
    return value == value and value not in (float("inf"), float("-inf"))


def z_prime_factor(positive: Sequence[float], negative: Sequence[float]) -> float:
    """Standard Z'-factor screening-assay quality score (internal, not egress).

    Returns a value in (-inf, 1]. Z' >= 0.5 is an excellent assay, 0 <= Z' < 0.5
    is marginal, Z' < 0 is unacceptable (control distributions overlap). When the
    signal window is zero the assay has no dynamic range; we return -inf.
    """

    # Defense in depth: SyntheticAssay already requires >= 2 controls, but this is
    # a public function — fail with the module's error, not a raw StatisticsError,
    # if a direct caller passes empty controls.
    if not positive or not negative:
        raise BioValidationError("z_prime_factor requires non-empty positive and negative controls")

    mu_p = statistics.fmean(positive)
    mu_n = statistics.fmean(negative)
    window = abs(mu_p - mu_n)
    if window == 0:
        return float("-inf")
    sigma_p = statistics.pstdev(positive)
    sigma_n = statistics.pstdev(negative)
    return 1.0 - 3.0 * (sigma_p + sigma_n) / window


def _score_band(z_prime: float) -> BioBand:
    if z_prime >= 0.5:
        return BioBand.HIGH
    if z_prime >= 0.0:
        return BioBand.MEDIUM
    return BioBand.LOW


def _confidence_band(replicates: int) -> BioBand:
    if replicates >= 3:
        return BioBand.HIGH
    if replicates == 2:
        return BioBand.MEDIUM
    return BioBand.LOW


def _utility_band(positive: Sequence[float], negative: Sequence[float]) -> BioBand:
    """Separation of the control distributions relative to their spread."""

    mu_p = statistics.fmean(positive)
    mu_n = statistics.fmean(negative)
    spread = statistics.pstdev(positive) + statistics.pstdev(negative)
    window = abs(mu_p - mu_n)
    if spread == 0:
        return BioBand.HIGH if window > 0 else BioBand.WITHHELD
    ratio = window / spread
    if ratio >= 10.0:
        return BioBand.HIGH
    if ratio >= 5.0:
        return BioBand.MEDIUM
    return BioBand.LOW


def _data_quality_flags(assay: SyntheticAssay) -> tuple[str, ...]:
    pos = [float(v) for v in assay.positive_controls]
    neg = [float(v) for v in assay.negative_controls]
    flags: list[str] = []
    if assay.replicates < 3:
        flags.append("low_replicates")
    mu_n = statistics.fmean(neg)
    if mu_n != 0 and statistics.pstdev(neg) / abs(mu_n) > 0.2:
        flags.append("high_background_cv")
    # Control overlap: the lowest positive control dips to/below the highest
    # negative control — the plate cannot cleanly separate hits from background.
    if min(pos) <= max(neg):
        flags.append("control_overlap")
    if len(pos) < 3 or len(neg) < 3:
        flags.append("few_control_wells")
    return tuple(sorted(flags))


def evaluate_synthetic_assay_qc(assay: SyntheticAssay) -> BioResultCandidate:
    """Compute bounded QC bands for a synthetic assay. Only bands/flags leave.

    The exact Z'-factor and control statistics are computed here and discarded;
    they are never placed on the returned candidate.
    """

    pos = [float(v) for v in assay.positive_controls]
    neg = [float(v) for v in assay.negative_controls]
    z_prime = z_prime_factor(pos, neg)
    return BioResultCandidate(
        use_case_id=USE_CASE_ID,
        methodology_class=METHODOLOGY_CLASS,
        score_band=_score_band(z_prime),
        confidence_band=_confidence_band(assay.replicates),
        utility_band=_utility_band(pos, neg),
        data_quality_flags=_data_quality_flags(assay),
        compute_cost_band="negligible",
        free_text_fields=dict(assay.free_text_fields),
        individual_level_data=False,
        differential_privacy_marked=False,
    )


def run_synthetic_assay_qc(
    assay: SyntheticAssay,
    readiness: BioReadiness | None = None,
    *,
    dual_use: "DualUseAssessment | None" = None,
    reid: "ReidAssessment | None" = None,
    data_quality: "DataQualityReport | None" = None,
) -> BioReleaseReceipt:
    """Evaluate a synthetic assay and pass the result through the release gate.

    With no readiness passed (the default), the gate holds fail-closed — the
    evaluator cannot self-release. Callers enable readiness capabilities only
    once the corresponding real controls exist. Optional `reid` (from
    `bio_reid.assess_reidentification`) and `data_quality` (from
    `bio_data_quality.assess_data_quality`) assessments hold release when either
    blocks.
    """

    candidate = evaluate_synthetic_assay_qc(assay)
    return evaluate_bio_release(
        candidate,
        readiness or BioReadiness(),
        dual_use=dual_use,
        reid=reid,
        data_quality=data_quality,
    )


def demo_synthetic_assay_qc() -> dict[str, Any]:
    """Deterministic bounded demo: a clean assay held fail-closed by default."""

    assay = SyntheticAssay(
        positive_controls=(100.0, 102.0, 98.0, 101.0),
        negative_controls=(10.0, 9.0, 11.0, 10.5),
        replicates=3,
    )
    receipt = run_synthetic_assay_qc(assay)
    return {
        "demo": "synthetic_assay_qc",
        "receipt": receipt.to_public_dict(),
        "raw_secret_egress": False,
    }
