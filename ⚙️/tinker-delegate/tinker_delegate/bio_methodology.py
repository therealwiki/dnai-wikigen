"""Bounded methodology summaries that cannot reconstruct raw data.

A buyer/reviewer wants to know *how* a bio-validation result was produced, but a
free-text "methodology" field is a leak channel: it can smuggle raw values,
per-record notes, or dual-use detail. This module makes the summary safe by
construction: it is composed only from a CLOSED controlled vocabulary of method
tokens plus COARSE magnitude bands. No raw values, no exact hyperparameters, and
no per-record content can appear, because anything outside the allowlist is
rejected and any caller free-text is screened and reduced to a hash.

Pure, deterministic, offline. The output is a bounded summary dict with
`raw_secret_egress=false` and `reconstruction_safe=true`.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from tinker_delegate.bio_validation import screen_forbidden_output


class MethodFamily(str, Enum):
    SUPERVISED_CLASSIFIER = "supervised_classifier"
    REGRESSION = "regression"
    DENOISING = "denoising"
    QC_SCORING = "qc_scoring"
    CLUSTERING = "clustering"
    METHOD_VALIDATION = "method_validation"


class MagnitudeBand(str, Enum):
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"
    UNKNOWN = "unknown"


class MethodologyError(ValueError):
    """Raised when a methodology profile contains out-of-vocabulary tokens."""


# Closed vocabularies. Anything outside these is rejected (fail closed) so the
# summary cannot become a free-text leak channel.
ALLOWED_PREPROCESSING: frozenset[str] = frozenset(
    {
        "log_normalize",
        "library_size_normalize",
        "scale",
        "impute_missing",
        "filter_low_count",
        "batch_correct",
        "train_test_split",
        "deduplicate",
        "feature_select",
    }
)
ALLOWED_MODEL_CLASSES: frozenset[str] = frozenset(
    {
        "baseline_mean",
        "linear",
        "logistic_regression",
        "random_forest",
        "gradient_boosting",
        "mlp",
        "cnn",
        "transformer",
        "knn",
        "zprime_qc",
        "denoiser_pooling",
    }
)
ALLOWED_PROTOCOLS: frozenset[str] = frozenset(
    {"holdout", "k_fold_cv", "nested_cv", "hidden_holdout", "bootstrap"}
)
_ALLOWED_HYPERPARAMS: frozenset[str] = frozenset(
    {"model_size", "learning_rate", "regularization", "n_estimators", "depth", "epochs"}
)


@dataclass(frozen=True)
class MethodologyProfile:
    """Structured, controlled-vocabulary description of a method. No raw data."""

    method_family: MethodFamily
    model_class: str
    evaluation_protocol: str
    preprocessing: Sequence[str] = ()
    sample_size_band: MagnitudeBand = MagnitudeBand.UNKNOWN
    feature_count_band: MagnitudeBand = MagnitudeBand.UNKNOWN
    hyperparameter_bands: Mapping[str, MagnitudeBand] = field(default_factory=dict)
    # Optional caller free-text: screened, never emitted verbatim.
    notes: str = ""

    def __post_init__(self) -> None:
        if self.model_class not in ALLOWED_MODEL_CLASSES:
            raise MethodologyError(f"model_class '{self.model_class}' is out of vocabulary")
        if self.evaluation_protocol not in ALLOWED_PROTOCOLS:
            raise MethodologyError(f"evaluation_protocol '{self.evaluation_protocol}' is out of vocabulary")
        for step in self.preprocessing:
            if step not in ALLOWED_PREPROCESSING:
                raise MethodologyError(f"preprocessing step '{step}' is out of vocabulary")
        for name, band in self.hyperparameter_bands.items():
            if name not in _ALLOWED_HYPERPARAMS:
                raise MethodologyError(f"hyperparameter '{name}' is out of vocabulary")
            if not isinstance(band, MagnitudeBand):
                raise MethodologyError("hyperparameter values must be MagnitudeBand")


def _compose_summary(profile: MethodologyProfile) -> str:
    """Build a human-readable summary from controlled tokens only."""

    steps = ", ".join(sorted(profile.preprocessing)) or "none"
    hyper = (
        ", ".join(f"{k}={profile.hyperparameter_bands[k].value}" for k in sorted(profile.hyperparameter_bands))
        or "unspecified"
    )
    return (
        f"A {profile.method_family.value} approach using a {profile.model_class} model, "
        f"preprocessing: [{steps}], evaluated by {profile.evaluation_protocol} on a "
        f"{profile.sample_size_band.value}-sample / {profile.feature_count_band.value}-feature "
        f"dataset (hyperparameter bands: {hyper})."
    )


def _methodology_hash(profile: MethodologyProfile) -> str:
    payload = {
        "method_family": profile.method_family.value,
        "model_class": profile.model_class,
        "evaluation_protocol": profile.evaluation_protocol,
        "preprocessing": sorted(profile.preprocessing),
        "sample_size_band": profile.sample_size_band.value,
        "feature_count_band": profile.feature_count_band.value,
        "hyperparameter_bands": {k: v.value for k, v in profile.hyperparameter_bands.items()},
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    return f"methodology_{digest[:48]}"


def summarize_methodology(profile: MethodologyProfile) -> dict[str, Any]:
    """Return a bounded, reconstruction-safe methodology summary.

    The composed summary is defensively re-screened through the forbidden-output
    screen; because every token is from a closed vocabulary this should always be
    clean, and a non-empty screen result is surfaced as `summary_clean=false`
    rather than released.
    """

    summary_text = _compose_summary(profile)
    summary_matches = screen_forbidden_output(summary_text)
    notes_matches = screen_forbidden_output(profile.notes) if profile.notes else ()
    return {
        "schema": "bio-methodology-summary-v1",
        "method_family": profile.method_family.value,
        "model_class": profile.model_class,
        "evaluation_protocol": profile.evaluation_protocol,
        "preprocessing": sorted(profile.preprocessing),
        "sample_size_band": profile.sample_size_band.value,
        "feature_count_band": profile.feature_count_band.value,
        "hyperparameter_bands": {k: v.value for k, v in sorted(profile.hyperparameter_bands.items())},
        "summary_text": summary_text if not summary_matches else "",
        "summary_clean": not summary_matches,
        "notes_hash": hashlib.sha256(profile.notes.encode("utf-8")).hexdigest()[:48] if profile.notes else "",
        "notes_clean": not notes_matches,
        "methodology_hash": _methodology_hash(profile),
        "reconstruction_safe": True,
        "raw_secret_egress": False,
    }
