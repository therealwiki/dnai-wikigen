"""Fail-closed top-up (auto-reload) policy for a Tinker (or metered) balance.

Decides whether — and by how much — to top up a balance when it runs low, from an
explicit, bounded policy rather than an ad-hoc rule. Auto-reload charges a card,
so this is a high-privilege action: it is OFF by default and gated by an
`emergency_disabled` kill switch that always wins.

Pure policy: the caller supplies the current balance and the policy; the decision
is deterministic. The returned `TopUpDecision` carries the exact top-up amount so
the caller can execute it (an economic action), but `to_public_dict` bands every
wei amount. A produced top-up amount is still a SPEND — the caller should gate it
through `spend_budget.SpendLedger.authorize` before charging, so caps still bind.

Decision order (most protective first):
  1. emergency_disabled -> no top-up (kill switch).
  2. auto_reload disabled -> no top-up (default posture).
  3. invalid (negative) balance -> no top-up (fail closed).
  4. balance >= min_balance -> no top-up (sufficient).
  5. otherwise -> top up toward `target_balance`, capped at `max_topup`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tinker_delegate.run_metadata_store import value_band


class TopUpPolicyError(ValueError):
    """Raised when a top-up policy is misconfigured."""


@dataclass(frozen=True)
class TopUpPolicy:
    """Bounded auto-reload policy. Amounts are wei."""

    min_balance_wei: int          # reload when the balance drops below this
    target_balance_wei: int       # reload up toward this
    max_topup_wei: int            # never reload more than this in one top-up
    auto_reload_enabled: bool = False   # default OFF: auto-charging a card is opt-in
    emergency_disabled: bool = False    # kill switch: always wins

    def __post_init__(self) -> None:
        for name in ("min_balance_wei", "target_balance_wei", "max_topup_wei"):
            if getattr(self, name) < 0:
                raise TopUpPolicyError(f"{name} must be >= 0")
        if self.target_balance_wei < self.min_balance_wei:
            raise TopUpPolicyError("target_balance_wei must be >= min_balance_wei")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "min_balance_band": value_band(self.min_balance_wei),
            "target_balance_band": value_band(self.target_balance_wei),
            "max_topup_band": value_band(self.max_topup_wei),
            "auto_reload_enabled": self.auto_reload_enabled,
            "emergency_disabled": self.emergency_disabled,
        }


@dataclass(frozen=True)
class TopUpDecision:
    """Bounded top-up decision. The exact `topup_amount_wei` is the action amount
    for the caller (an economic entitlement); `to_public_dict` bands it."""

    should_topup: bool
    topup_amount_wei: int
    reason_code: str
    reaches_target: bool

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "topup_decision",
            "should_topup": self.should_topup,
            "topup_amount_band": value_band(self.topup_amount_wei),
            "reason_code": self.reason_code,
            "reaches_target": self.reaches_target,
            "raw_secret_egress": False,
        }


def decide_topup(current_balance_wei: int, policy: TopUpPolicy) -> TopUpDecision:
    """Decide whether/how much to top up, fail-closed. See module docstring."""

    def _no(reason: str) -> TopUpDecision:
        return TopUpDecision(
            should_topup=False, topup_amount_wei=0, reason_code=reason, reaches_target=False
        )

    # Kill switch and default-off posture win before anything else.
    if policy.emergency_disabled:
        return _no("emergency_disabled")
    if not policy.auto_reload_enabled:
        return _no("auto_reload_off")
    if current_balance_wei < 0:
        return _no("invalid_balance")
    if current_balance_wei >= policy.min_balance_wei:
        return _no("balance_sufficient")

    desired = policy.target_balance_wei - current_balance_wei
    amount = min(desired, policy.max_topup_wei)
    if amount <= 0:
        # max_topup is zero (or target == current): nothing to reload.
        return _no("no_topup_available")
    reaches_target = current_balance_wei + amount >= policy.target_balance_wei
    return TopUpDecision(
        should_topup=True,
        topup_amount_wei=amount,
        reason_code="topup_authorized" if reaches_target else "partial_topup",
        reaches_target=reaches_target,
    )
