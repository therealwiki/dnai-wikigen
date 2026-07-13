"""Per-query royalty settlement for multiple corpus owners.

A surfaced turn meters a per-query royalty for each corpus. A corpus may be
co-owned, so the royalty must split among several owners by weight and accrue as
pull-payment balances the owners can later withdraw. This module is the pure,
fail-closed settlement primitive for that:

* ``split_royalty`` divides a total among ``OwnerShare`` weights (basis points
  summing to 10000) using the largest-remainder method, so the payouts always sum
  to *exactly* the total — no wei created or lost, deterministic tie-break.
* ``RoyaltyLedger`` accrues each per-query split into per-owner claimable
  balances and preserves the conservation invariant that every accrued wei is
  either still claimable or already claimed — ``claimable + claimed == accrued``
  — so nothing is created or lost across accruals and withdrawals.

Exact settlement amounts are economic entitlements (a bounded settlement event,
not sealed data); the public summary additionally exposes coarse amount bands.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Sequence

_BPS_TOTAL = 10_000


class RoyaltyError(ValueError):
    """Raised on a malformed royalty split."""


@dataclass(frozen=True)
class OwnerShare:
    owner_ref: str
    weight_bps: int


@dataclass(frozen=True)
class Payout:
    owner_ref: str
    amount: int

    def to_public_dict(self) -> dict[str, Any]:
        return {"owner_ref": self.owner_ref, "amount": self.amount, "amount_band": _amount_band(self.amount)}


def split_royalty(total_amount: int, shares: Sequence[OwnerShare]) -> tuple[Payout, ...]:
    """Split ``total_amount`` among owners by weight; payouts sum to the total."""
    if total_amount < 0:
        raise RoyaltyError("total amount must be non-negative")
    if not shares:
        raise RoyaltyError("at least one owner share is required")
    owners = [s.owner_ref for s in shares]
    if len(set(owners)) != len(owners):
        raise RoyaltyError("owner refs must be unique")
    if any(s.weight_bps < 0 for s in shares):
        raise RoyaltyError("weights must be non-negative")
    if sum(s.weight_bps for s in shares) != _BPS_TOTAL:
        raise RoyaltyError("weights must sum to 10000 basis points")

    # Floor each share, then distribute the leftover wei to the largest
    # fractional remainders (deterministic tie-break by owner_ref).
    floors: list[int] = []
    remainders: list[tuple[int, str, int]] = []  # (remainder, owner_ref, index)
    for index, share in enumerate(shares):
        numerator = total_amount * share.weight_bps
        floors.append(numerator // _BPS_TOTAL)
        remainders.append((numerator % _BPS_TOTAL, share.owner_ref, index))

    leftover = total_amount - sum(floors)
    # Largest remainder first; ties broken by owner_ref for determinism.
    order = sorted(remainders, key=lambda r: (-r[0], r[1]))
    for i in range(leftover):
        _, _, idx = order[i]
        floors[idx] += 1

    return tuple(Payout(owner_ref=share.owner_ref, amount=floors[i]) for i, share in enumerate(shares))


@dataclass(frozen=True)
class RoyaltyAccrual:
    query_ref: str
    total_amount: int
    payouts: tuple[Payout, ...]

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "query_ref": self.query_ref,
            "total_band": _amount_band(self.total_amount),
            "payouts": [p.to_public_dict() for p in self.payouts],
        }


class RoyaltyLedger:
    """Accrues per-query royalty splits into per-owner claimable balances."""

    def __init__(self) -> None:
        self._claimable: dict[str, int] = {}
        self._accruals: list[RoyaltyAccrual] = []
        # Total already withdrawn via claim(). Conservation is a three-way ledger:
        # every accrued wei is either still claimable or has been claimed.
        self._claimed_total: int = 0

    def accrue(self, query_ref: str, total_amount: int, shares: Sequence[OwnerShare]) -> RoyaltyAccrual:
        payouts = split_royalty(total_amount, shares)
        for payout in payouts:
            self._claimable[payout.owner_ref] = self._claimable.get(payout.owner_ref, 0) + payout.amount
        accrual = RoyaltyAccrual(query_ref=query_ref, total_amount=total_amount, payouts=payouts)
        self._accruals.append(accrual)
        return accrual

    def claimable(self, owner_ref: str) -> int:
        return self._claimable.get(owner_ref, 0)

    def total_accrued(self) -> int:
        return sum(a.total_amount for a in self._accruals)

    def total_claimable(self) -> int:
        return sum(self._claimable.values())

    def total_claimed(self) -> int:
        return self._claimed_total

    def owners(self) -> tuple[str, ...]:
        return tuple(sorted(self._claimable))

    def claim(self, owner_ref: str) -> int:
        """Withdraw an owner's full claimable balance (pull payment). Returns it."""
        amount = self._claimable.get(owner_ref, 0)
        if amount <= 0:
            raise RoyaltyError("nothing to claim")
        self._claimable[owner_ref] = 0
        self._claimed_total += amount
        return amount

    def public_summary(self) -> dict[str, Any]:
        claimable = {owner: self._claimable[owner] for owner in sorted(self._claimable)}
        return {
            "kind": "royalty_ledger_summary",
            "accrual_count": len(self._accruals),
            "owner_count": len(self._claimable),
            "total_accrued_band": _amount_band(self.total_accrued()),
            "total_claimed_band": _amount_band(self.total_claimed()),
            "claimable_bands": {owner: _amount_band(amount) for owner, amount in claimable.items()},
            # True conservation: nothing created or lost — every accrued wei is
            # either still claimable or already claimed. (The previous
            # claimable == accrued check falsely reported not-conserved after any
            # withdrawal, since claimed funds legitimately leave the pool.)
            "conserved": self.total_claimable() + self.total_claimed() == self.total_accrued(),
            "settlement_hash": _sha256_json(
                {"accruals": [a.to_public_dict() for a in self._accruals]}
            ),
            "raw_secret_egress": False,
        }


def _amount_band(amount: int) -> str:
    if amount <= 0:
        return "zero"
    if amount < 10**15:
        return "sub_milli"
    if amount < 10**16:
        return "milli"
    if amount < 10**17:
        return "centi"
    if amount < 10**18:
        return "deci"
    return "whole_or_more"


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "0x" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
