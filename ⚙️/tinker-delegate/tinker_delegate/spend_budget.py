"""Fail-closed multi-cap budget enforcement for Tinker (or any metered) spend.

A proposed spend must fit under EVERY active cap — buyer, room, daily, and
operator — before it is authorized; the tightest cap binds (strict intersection,
most restrictive wins, like the coordination reducer). The buyer/room/operator
caps apply to spend-to-date (cumulative); the daily cap applies per calendar-day
bucket. A day bucket is caller-supplied (e.g. "2026-07-12") so the ledger stays
pure and deterministic — no wall clock.

Fail-closed: a proposed spend that would exceed any active cap is denied WITHOUT
mutating the ledger (no budget is consumed by a rejected charge). The boundary is
strict (`spend > cap` denies; a spend that lands exactly on a cap is allowed),
matching the on-chain / cost-reconciliation convention.

Output is bounded: an `allowed` flag, the binding cap name, a reason code, and
coarse remaining bands per active cap — never a raw wei amount.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tinker_delegate.run_metadata_store import value_band

_CUMULATIVE = ("buyer", "room", "operator")


class SpendBudgetError(ValueError):
    """Raised when a spend budget is misconfigured."""


@dataclass(frozen=True)
class SpendCaps:
    """Per-scope spend ceilings in wei. `None` means that scope is uncapped."""

    buyer_cap_wei: int | None = None
    room_cap_wei: int | None = None
    daily_cap_wei: int | None = None
    operator_cap_wei: int | None = None

    def __post_init__(self) -> None:
        for name in ("buyer_cap_wei", "room_cap_wei", "daily_cap_wei", "operator_cap_wei"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise SpendBudgetError(f"{name} must be >= 0 or None")

    def cap_for(self, scope: str) -> int | None:
        return getattr(self, f"{scope}_cap_wei")

    def active_scopes(self) -> tuple[str, ...]:
        return tuple(
            s for s in ("buyer", "room", "operator", "daily") if self.cap_for(s) is not None
        )


@dataclass(frozen=True)
class SpendAuthorization:
    """Bounded verdict for one proposed spend. Only bands/booleans/names egress."""

    allowed: bool
    binding_cap: str
    reason_code: str
    remaining_bands: dict[str, str]
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "spend_authorization",
            "allowed": self.allowed,
            "binding_cap": self.binding_cap,
            "reason_code": self.reason_code,
            "remaining_bands": dict(self.remaining_bands),
            "raw_secret_egress": self.raw_secret_egress,
        }


class SpendLedger:
    """Tracks cumulative and per-day spend and authorizes charges against caps."""

    def __init__(self, caps: SpendCaps) -> None:
        self._caps = caps
        self._spent_total = 0
        self._daily_spent: dict[str, int] = {}

    @property
    def spent_total(self) -> int:
        return self._spent_total

    def daily_spent(self, day_bucket: str) -> int:
        return self._daily_spent.get(day_bucket, 0)

    def _spent_before(self, scope: str, day_bucket: str) -> int:
        return self._daily_spent.get(day_bucket, 0) if scope == "daily" else self._spent_total

    def _remaining_bands(self, day_bucket: str) -> dict[str, str]:
        bands: dict[str, str] = {}
        for scope in self._caps.active_scopes():
            cap = self._caps.cap_for(scope)
            remaining = max(0, cap - self._spent_before(scope, day_bucket))
            bands[scope] = value_band(remaining)
        return bands

    def authorize(self, amount_wei: int, *, day_bucket: str) -> SpendAuthorization:
        """Authorize a proposed spend against every active cap; fail closed."""
        if not isinstance(day_bucket, str) or not day_bucket:
            raise SpendBudgetError("day_bucket must be a non-empty string")
        if amount_wei < 0:
            return SpendAuthorization(
                allowed=False,
                binding_cap="none",
                reason_code="negative_amount",
                remaining_bands=self._remaining_bands(day_bucket),
            )

        # Find every cap the charge would exceed (strict >), and bind to the one
        # with the LEAST remaining headroom (the tightest — most responsible).
        violated: list[tuple[str, int]] = []  # (scope, remaining_before)
        for scope in self._caps.active_scopes():
            cap = self._caps.cap_for(scope)
            spent_before = self._spent_before(scope, day_bucket)
            if spent_before + amount_wei > cap:
                violated.append((scope, cap - spent_before))

        if violated:
            binding = min(violated, key=lambda item: (item[1], item[0]))[0]
            return SpendAuthorization(
                allowed=False,
                binding_cap=binding,
                reason_code=f"exceeds_{binding}_cap",
                remaining_bands=self._remaining_bands(day_bucket),
            )

        # Admit: consume budget on BOTH the cumulative and the daily ledgers.
        self._spent_total += amount_wei
        self._daily_spent[day_bucket] = self._daily_spent.get(day_bucket, 0) + amount_wei

        # Report the tightest remaining cap after the charge (informational).
        remaining_bands = self._remaining_bands(day_bucket)
        tightest = "none"
        best: int | None = None
        for scope in self._caps.active_scopes():
            cap = self._caps.cap_for(scope)
            remaining_after = cap - self._spent_before(scope, day_bucket)
            if best is None or remaining_after < best:
                best, tightest = remaining_after, scope
        return SpendAuthorization(
            allowed=True,
            binding_cap=tightest,
            reason_code="within_budget",
            remaining_bands=remaining_bands,
        )
