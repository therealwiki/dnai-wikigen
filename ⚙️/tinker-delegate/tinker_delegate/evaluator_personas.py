"""Multiple bounded evaluator personas composed fail-closed by intersection.

Realizes the PROJECT.md claim that buyers, sponsors, reviewers, and agents
interact with sealed data only through bounded interfaces — here as distinct
*reviewer lenses*, each judging an evaluation from one concern:

* ``buyer_utility``     — is the result useful enough to the buyer?
* ``seller_protection`` — is the seller's private data protected (leakage bound,
  offer within cap)?
* ``biosecurity``       — does the bio dual-use / re-identification screen clear?
* ``data_quality``      — is the underlying data trustworthy?
* ``economics``         — does the spend fit the budget/fee policy?

Each persona reads only *already-bounded* signals (bands, tiers, booleans — never
raw data) and returns a bounded ``PersonaVerdict``. The panel composes them by
strict intersection: any ``DENY`` denies, any ``HOLD`` holds, and only an
all-``PASS`` panel proceeds — the same fail-closed rule as the coordination
reducer. Unknown/missing signals fail closed (DENY), never open.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping


class PersonaDecision(str, Enum):
    PASS = "pass"
    HOLD = "hold"
    DENY = "deny"


class Persona(str, Enum):
    BUYER_UTILITY = "buyer_utility"
    SELLER_PROTECTION = "seller_protection"
    BIOSECURITY = "biosecurity"
    DATA_QUALITY = "data_quality"
    ECONOMICS = "economics"


# Ordering for intersection: worst (most restrictive) wins.
_SEVERITY = {PersonaDecision.PASS: 0, PersonaDecision.HOLD: 1, PersonaDecision.DENY: 2}

_QUALITY_BANDS = ("exceptional", "high", "medium", "low", "negligible", "withheld")
_RISK_BANDS = ("low", "medium", "high")
_DUAL_USE_TIERS = ("cleared", "review", "prohibited")


@dataclass(frozen=True)
class EvaluationSummary:
    """Bounded, already-reduced signals a persona panel judges. No raw data."""

    utility_band: str = ""
    data_quality_band: str = ""
    reidentification_risk: str = ""
    dual_use_tier: str = ""
    leakage_within_bounds: bool | None = None
    offer_within_cap: bool | None = None
    cost_within_budget: bool | None = None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "utility_band": self.utility_band,
            "data_quality_band": self.data_quality_band,
            "reidentification_risk": self.reidentification_risk,
            "dual_use_tier": self.dual_use_tier,
            "leakage_within_bounds": self.leakage_within_bounds,
            "offer_within_cap": self.offer_within_cap,
            "cost_within_budget": self.cost_within_budget,
        }


@dataclass(frozen=True)
class PersonaVerdict:
    persona: Persona
    decision: PersonaDecision
    reason_code: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "persona": self.persona.value,
            "decision": self.decision.value,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class PanelDecision:
    decision: PersonaDecision
    verdicts: tuple[PersonaVerdict, ...]
    panel_hash: str
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "evaluator_persona_panel",
            "decision": self.decision.value,
            "verdicts": [v.to_public_dict() for v in self.verdicts],
            "panel_hash": self.panel_hash,
            "raw_secret_egress": self.raw_secret_egress,
        }


def _norm(value: str) -> str:
    return (value or "").strip().lower()


def _rank(band: str, order: tuple[str, ...]) -> int:
    """Index of a band in an ordered vocabulary, or -1 if unknown."""
    b = _norm(band)
    return order.index(b) if b in order else -1


def evaluate_buyer_utility(summary: EvaluationSummary) -> PersonaVerdict:
    rank = _rank(summary.utility_band, _QUALITY_BANDS)
    if rank < 0 or _norm(summary.utility_band) == "withheld":
        decision, reason = PersonaDecision.DENY, "utility_unknown_or_withheld"
    elif rank <= _rank("medium", _QUALITY_BANDS):  # exceptional/high/medium
        decision, reason = PersonaDecision.PASS, "utility_sufficient"
    elif _norm(summary.utility_band) == "low":
        decision, reason = PersonaDecision.HOLD, "utility_marginal"
    else:  # negligible
        decision, reason = PersonaDecision.DENY, "utility_insufficient"
    return PersonaVerdict(Persona.BUYER_UTILITY, decision, reason)


def evaluate_seller_protection(summary: EvaluationSummary) -> PersonaVerdict:
    if summary.leakage_within_bounds is not True:
        return PersonaVerdict(Persona.SELLER_PROTECTION, PersonaDecision.DENY, "leakage_bound_unverified")
    if summary.offer_within_cap is not True:
        return PersonaVerdict(Persona.SELLER_PROTECTION, PersonaDecision.HOLD, "offer_above_cap")
    return PersonaVerdict(Persona.SELLER_PROTECTION, PersonaDecision.PASS, "seller_protected")


def evaluate_biosecurity(summary: EvaluationSummary) -> PersonaVerdict:
    tier = _norm(summary.dual_use_tier)
    risk = _norm(summary.reidentification_risk)
    if tier not in _DUAL_USE_TIERS or risk not in _RISK_BANDS:
        return PersonaVerdict(Persona.BIOSECURITY, PersonaDecision.DENY, "bio_screen_unverified")
    if tier == "prohibited" or risk == "high":
        return PersonaVerdict(Persona.BIOSECURITY, PersonaDecision.DENY, "bio_dual_use_or_reid_blocked")
    if tier == "review" or risk == "medium":
        return PersonaVerdict(Persona.BIOSECURITY, PersonaDecision.HOLD, "bio_needs_reviewer")
    return PersonaVerdict(Persona.BIOSECURITY, PersonaDecision.PASS, "bio_cleared")


def evaluate_data_quality(summary: EvaluationSummary) -> PersonaVerdict:
    rank = _rank(summary.data_quality_band, _QUALITY_BANDS)
    if rank < 0 or _norm(summary.data_quality_band) == "withheld":
        decision, reason = PersonaDecision.DENY, "data_quality_unknown"
    elif rank <= _rank("medium", _QUALITY_BANDS):
        decision, reason = PersonaDecision.PASS, "data_quality_ok"
    elif _norm(summary.data_quality_band) == "low":
        decision, reason = PersonaDecision.HOLD, "data_quality_marginal"
    else:  # negligible
        decision, reason = PersonaDecision.DENY, "data_quality_poor"
    return PersonaVerdict(Persona.DATA_QUALITY, decision, reason)


def evaluate_economics(summary: EvaluationSummary) -> PersonaVerdict:
    if summary.cost_within_budget is not True:
        return PersonaVerdict(Persona.ECONOMICS, PersonaDecision.DENY, "cost_exceeds_budget")
    return PersonaVerdict(Persona.ECONOMICS, PersonaDecision.PASS, "economics_ok")


_PERSONA_EVALUATORS: dict[Persona, Callable[[EvaluationSummary], PersonaVerdict]] = {
    Persona.BUYER_UTILITY: evaluate_buyer_utility,
    Persona.SELLER_PROTECTION: evaluate_seller_protection,
    Persona.BIOSECURITY: evaluate_biosecurity,
    Persona.DATA_QUALITY: evaluate_data_quality,
    Persona.ECONOMICS: evaluate_economics,
}

DEFAULT_PERSONAS: tuple[Persona, ...] = tuple(_PERSONA_EVALUATORS.keys())


def evaluate_personas(
    summary: EvaluationSummary,
    personas: tuple[Persona, ...] = DEFAULT_PERSONAS,
) -> PanelDecision:
    """Run each persona lens and compose the panel by strict intersection.

    Any DENY denies, any HOLD holds, only all-PASS proceeds. The panel must cover
    at least one persona; unknown/missing signals fail closed inside each lens.
    """
    if not personas:
        raise ValueError("persona panel must include at least one persona")
    verdicts = tuple(_PERSONA_EVALUATORS[p](summary) for p in personas)
    worst = max(verdicts, key=lambda v: _SEVERITY[v.decision]).decision
    panel_hash = _sha256_json(
        {
            "summary": summary.to_public_dict(),
            "verdicts": [v.to_public_dict() for v in verdicts],
            "decision": worst.value,
        }
    )
    return PanelDecision(decision=worst, verdicts=verdicts, panel_hash=panel_hash)


# Data-quality bands (good/fair/poor/withheld) map into the persona quality
# vocabulary so the data-quality lens gives good->PASS, fair->HOLD, poor->DENY.
_DATA_QUALITY_MAP = {
    "good": "medium",
    "fair": "low",
    "poor": "negligible",
    "withheld": "withheld",
}


def _enum_value(value: Any) -> str:
    if value is None:
        return ""
    return value.value if hasattr(value, "value") else str(value)


def summary_from_bio_evidence(
    *,
    result_candidate: Any = None,
    data_quality: Any = None,
    reid: Any = None,
    dual_use: Any = None,
    leakage_within_bounds: bool | None = None,
    offer_within_cap: bool | None = None,
    cost_within_budget: bool | None = None,
) -> EvaluationSummary:
    """Bridge already-bounded bio assessments into an EvaluationSummary.

    Duck-typed on the bounded fields the bio modules expose
    (`utility_band`, `quality_band`, `risk_band`, `tier`) so this stays free of
    bio imports. Unknown/absent bands map to empty strings, which the persona
    lenses treat as fail-closed DENY.
    """
    utility = _norm(_enum_value(getattr(result_candidate, "utility_band", "")))
    dq_raw = _norm(_enum_value(getattr(data_quality, "quality_band", "")))
    data_quality_band = _DATA_QUALITY_MAP.get(dq_raw, dq_raw if dq_raw else "")
    if data_quality is not None and dq_raw not in _DATA_QUALITY_MAP:
        data_quality_band = ""  # unknown quality band -> fail closed
    reid_risk = _norm(_enum_value(getattr(reid, "risk_band", "")))
    tier = _norm(_enum_value(getattr(dual_use, "tier", "")))
    return EvaluationSummary(
        utility_band=utility,
        data_quality_band=data_quality_band,
        reidentification_risk=reid_risk,
        dual_use_tier=tier,
        leakage_within_bounds=leakage_within_bounds,
        offer_within_cap=offer_within_cap,
        cost_within_budget=cost_within_budget,
    )


def evaluate_bio_personas(
    *,
    result_candidate: Any = None,
    data_quality: Any = None,
    reid: Any = None,
    dual_use: Any = None,
    leakage_within_bounds: bool | None = None,
    offer_within_cap: bool | None = None,
    cost_within_budget: bool | None = None,
    personas: tuple[Persona, ...] = DEFAULT_PERSONAS,
) -> PanelDecision:
    """Build an EvaluationSummary from bio evidence and run the persona panel."""
    summary = summary_from_bio_evidence(
        result_candidate=result_candidate,
        data_quality=data_quality,
        reid=reid,
        dual_use=dual_use,
        leakage_within_bounds=leakage_within_bounds,
        offer_within_cap=offer_within_cap,
        cost_within_budget=cost_within_budget,
    )
    return evaluate_personas(summary, personas=personas)


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(_stable(value), sort_keys=True, separators=(",", ":"))
    return "0x" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _stable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(k): _stable(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_stable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
