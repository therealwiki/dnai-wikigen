"""Bounded cost reconciliation across the metered / chain / budget views.

The delegate meters Tinker work as an *estimate* (`session.CostMeter`, priced
from token counts). Three other numbers describe the same spend from different
vantage points:

* ``chain_compute_cost_wei`` — what the delegate submits on-chain and the buyer
  is actually charged at settlement.
* ``budget_cap_wei`` — the ceiling the buyer authorized.
* ``reported_cost_wei`` — the cost Tinker itself reports, when a real backend is
  wired (``None`` in the source-modeled path today).

``reconcile_costs`` ties them together and returns a bounded, fail-closed verdict
so settlement can refuse to pay a charge that (a) exceeds the buyer's budget, (b)
exceeds what the delegate itself metered (overcharge protection), or (c) diverges
from Tinker's own reported cost beyond tolerance. Only a fully ``RECONCILED``
verdict is ``settlement_safe``.

The public dict bands every wei amount through ``value_band`` — no raw amount is
required to leave the boundary to make the integrity decision.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from tinker_delegate.run_metadata_store import value_band


class CostReconciliationStatus(str, Enum):
    RECONCILED = "reconciled"
    OVER_BUDGET = "over_budget"
    CHAIN_EXCEEDS_ESTIMATE = "chain_exceeds_estimate"
    REPORTED_MISMATCH = "reported_mismatch"
    INVALID = "invalid"


def _safe_label(model: str) -> str:
    text = str(model).strip().lower()
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789_.:/-"
    clipped = "".join(char for char in text[:64] if char in allowed)
    return clipped or "unknown"


@dataclass(frozen=True)
class CostReconciliation:
    """Bounded, fail-closed reconciliation of the four cost views for one deal."""

    model: str
    estimated_cost_wei: int
    chain_compute_cost_wei: int
    budget_cap_wei: int
    fee_wei: int
    status: CostReconciliationStatus
    reported_cost_wei: int | None = None
    tolerance_bps: int = 0

    @property
    def budget_remaining_wei(self) -> int:
        """Budget left after the on-chain charge, floored at zero."""

        return max(0, self.budget_cap_wei - self.chain_compute_cost_wei)

    @property
    def over_budget(self) -> bool:
        return self.chain_compute_cost_wei > self.budget_cap_wei

    @property
    def settlement_safe(self) -> bool:
        """Only a fully reconciled verdict may proceed to settlement."""

        return self.status == CostReconciliationStatus.RECONCILED

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "surface": "cost_reconciliation",
            "model": self.model,
            "status": self.status.value,
            "settlement_safe": self.settlement_safe,
            "over_budget": self.over_budget,
            "tolerance_bps": self.tolerance_bps,
            "estimated_cost_band": value_band(self.estimated_cost_wei),
            "chain_compute_cost_band": value_band(self.chain_compute_cost_wei),
            "budget_cap_band": value_band(self.budget_cap_wei),
            "budget_remaining_band": value_band(self.budget_remaining_wei),
            "fee_band": value_band(self.fee_wei),
            "reported_cost_band": value_band(self.reported_cost_wei),
            "reported_present": self.reported_cost_wei is not None,
            "raw_secret_egress": False,
        }


def _within_tolerance(a: int, b: int, tolerance_bps: int) -> bool:
    """True if ``a`` and ``b`` agree within ``tolerance_bps`` of the larger."""

    slack = (max(a, b) * tolerance_bps) // 10_000
    return abs(a - b) <= slack


def reconcile_costs(
    *,
    model: str,
    estimated_cost_wei: int,
    chain_compute_cost_wei: int,
    budget_cap_wei: int,
    fee_wei: int = 0,
    reported_cost_wei: int | None = None,
    tolerance_bps: int = 0,
) -> CostReconciliation:
    """Reconcile the four cost views into a bounded, fail-closed verdict.

    Calling contract: ``chain_compute_cost_wei`` is the TOTAL developer charge the
    delegate will submit (compute + fee), and ``budget_cap_wei`` is the headroom
    the buyer authorized for that charge (e.g. the deal budget cap minus any seller
    offer). ``fee_wei`` is the informational fee component already included in
    ``chain_compute_cost_wei`` — it is surfaced as a band but is NOT added again to
    the budget comparison (doing so would double-count it). The OVER_BUDGET
    boundary is strict (`charge > cap`), matching the on-chain
    ``DiligenceRoom.submitResult`` rule ``offer + computeCost + fee > budgetCap``
    exactly: a charge equal to the cap is in-budget on both sides.

    Status is assigned by severity, buyer-harm first:

    1. ``INVALID``  — any negative input, or a nonsensical tolerance.
    2. ``OVER_BUDGET`` — the on-chain charge exceeds the authorized budget.
    3. ``CHAIN_EXCEEDS_ESTIMATE`` — the on-chain charge exceeds what the delegate
       itself metered (beyond tolerance): the delegate must never submit more
       than it can account for. A charge *below* the estimate is fine (the buyer
       simply pays less).
    4. ``REPORTED_MISMATCH`` — Tinker's own reported cost diverges from the
       metered estimate beyond tolerance (only checked when reported is present).
    5. ``RECONCILED`` — all views agree; settlement may proceed.
    """

    safe_model = _safe_label(model)
    negatives = [
        estimated_cost_wei,
        chain_compute_cost_wei,
        budget_cap_wei,
        fee_wei,
    ]
    if reported_cost_wei is not None:
        negatives.append(reported_cost_wei)
    if tolerance_bps < 0 or any(value < 0 for value in negatives):
        status = CostReconciliationStatus.INVALID
    elif chain_compute_cost_wei > budget_cap_wei:
        status = CostReconciliationStatus.OVER_BUDGET
    elif chain_compute_cost_wei > estimated_cost_wei and not _within_tolerance(
        chain_compute_cost_wei, estimated_cost_wei, tolerance_bps
    ):
        status = CostReconciliationStatus.CHAIN_EXCEEDS_ESTIMATE
    elif reported_cost_wei is not None and not _within_tolerance(
        reported_cost_wei, estimated_cost_wei, tolerance_bps
    ):
        status = CostReconciliationStatus.REPORTED_MISMATCH
    else:
        status = CostReconciliationStatus.RECONCILED

    return CostReconciliation(
        model=safe_model,
        estimated_cost_wei=estimated_cost_wei,
        chain_compute_cost_wei=chain_compute_cost_wei,
        budget_cap_wei=budget_cap_wei,
        fee_wei=fee_wei,
        status=status,
        reported_cost_wei=reported_cost_wei,
        tolerance_bps=tolerance_bps,
    )


def reconcile_from_meter(
    meter: Any,
    *,
    chain_compute_cost_wei: int,
    budget_cap_wei: int,
    reported_cost_wei: int | None = None,
    tolerance_bps: int = 0,
) -> CostReconciliation:
    """Reconcile using a ``session.CostMeter``'s metered estimate as the anchor.

    Duck-typed (reads ``model``/``total_cost_wei``/``fee_wei``) so this module
    stays free of the heavy ``session`` import and its Tinker SDK dependency.
    """

    return reconcile_costs(
        model=getattr(meter, "model", "") or "unknown",
        estimated_cost_wei=int(meter.total_cost_wei),
        chain_compute_cost_wei=chain_compute_cost_wei,
        budget_cap_wei=budget_cap_wei,
        fee_wei=int(getattr(meter, "fee_wei", 0)),
        reported_cost_wei=reported_cost_wei,
        tolerance_bps=tolerance_bps,
    )
