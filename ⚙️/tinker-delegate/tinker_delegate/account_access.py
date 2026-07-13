"""Bounded classifier for the Tinker account access / billing-activation gate.

The account itself is TEE-owned (email-oracle OTP login), so "unblocking" is not a
login problem — it is the provider's server-side access/billing state. This module
turns the account/billing page text into a *bounded* verdict so the automation can
detect the gate, decide whether it is self-serve or needs provider approval, and
notice when the gate text changes across runs — all without egressing raw page
text, card material, or any secret.

It is the deterministic core that a live browser step (navigate to the billing
page, read its text) calls; the classification and receipt are pure and testable
without the live CVM.

Design fact grounded in evidence: the observed gate "Access is blocked due to
billing status. Please add payment." persisted after a card was on file and the
balance was topped to ~$20, so ``access_blocked_billing`` is treated as a
provider-side activation gate (``actionable=False``), NOT a self-serve
add-payment step.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

# Bounded state vocabulary (closed set).
ACTIVE = "active"
ACCESS_BLOCKED_BILLING = "access_blocked_billing"
PAYMENT_REQUIRED = "payment_required"
WAITLIST_OR_GATED = "waitlist_or_gated"
UNKNOWN = "unknown"

_OPERATOR_ACTION = {
    ACTIVE: "none_account_active",
    ACCESS_BLOCKED_BILLING: "contact_provider_for_account_activation",
    PAYMENT_REQUIRED: "add_payment_method",
    WAITLIST_OR_GATED: "request_or_await_provider_access",
    UNKNOWN: "inspect_gate_manually",
}

# Whether the state is resolvable by the TEE's own automation (self-serve) vs an
# out-of-band provider action. access_blocked_billing is NOT self-serve: adding
# payment did not clear it (see module docstring).
_ACTIONABLE = {
    ACTIVE: False,          # nothing to do
    ACCESS_BLOCKED_BILLING: False,
    PAYMENT_REQUIRED: True,
    WAITLIST_OR_GATED: False,
    UNKNOWN: False,
}


def classify_account_access(text: str) -> str:
    """Map billing/account page text to a bounded access state (never the text)."""
    normalized = re.sub(r"\s+", " ", text or "").strip().lower()
    if not normalized:
        return UNKNOWN

    blocked_billing = (
        ("access" in normalized and "blocked" in normalized and "billing" in normalized)
        or "blocked due to billing" in normalized
        or ("account" in normalized and "suspended" in normalized)
    )
    if blocked_billing:
        return ACCESS_BLOCKED_BILLING

    gated = any(
        hint in normalized
        for hint in (
            "waitlist",
            "request access",
            "not yet available",
            "invite only",
            "invitation",
            "join the waitlist",
            "access is limited",
        )
    )
    if gated:
        return WAITLIST_OR_GATED

    payment_required = any(
        hint in normalized
        for hint in (
            "please add payment",
            "add a payment method",
            "no payment method",
            "add a card",
            "payment method required",
            "add payment method to continue",
        )
    )
    if payment_required:
        return PAYMENT_REQUIRED

    active = any(
        hint in normalized
        for hint in (
            "api access enabled",
            "training enabled",
            "your account is active",
            "billing active",
            "account in good standing",
        )
    )
    if active:
        return ACTIVE

    return UNKNOWN


def account_access_receipt(text: str) -> dict[str, Any]:
    """Bounded receipt: state, action, page-text hash — no raw text or secrets.

    The ``page_text_hash`` lets callers detect that the gate changed between runs
    (e.g. after the operator resolves activation) without storing the page.
    """
    state = classify_account_access(text)
    normalized = re.sub(r"\s+", " ", text or "").strip().lower()
    page_text_hash = "0x" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return {
        "kind": "account_access_status",
        "state": state,
        "actionable_by_automation": _ACTIONABLE[state],
        "operator_action": _OPERATOR_ACTION[state],
        "bounded_message": f"account_access:{state}",
        "page_text_hash": page_text_hash,
        "raw_secret_egress": False,
    }
