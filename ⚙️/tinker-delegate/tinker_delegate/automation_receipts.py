"""Bounded automation receipts for Tinker browser operations.

Receipts are the public audit surface for browser-mediated account operations.
They intentionally do not contain raw page text, API keys, OTPs, card data, or
account credentials.  Callers get stable status classes, bands, and hashes that
prove what the automation saw without turning the browser into a data exfil path.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from tinker_delegate.redaction import redact_text


class AutomationSurface(StrEnum):
    TINKER_AUTH = "tinker_auth"
    API_KEY_PROVISIONING = "api_key_provisioning"
    API_KEY_MANAGEMENT = "api_key_management"
    PAYMENT_METHOD = "payment_method"
    PAYMENT_METHOD_STATUS = "payment_method_status"
    PAYMENT_METHOD_REMOVAL = "payment_method_removal"
    ADD_BALANCE = "add_balance"


class AutomationStage(StrEnum):
    NOT_STARTED = "not_started"
    BROWSER_CONNECTED = "browser_connected"
    BROWSER_CONTEXT_READY = "browser_context_ready"
    AUTH_PAGE_LOADED = "auth_page_loaded"
    AUTH_EMAIL_SUBMITTED = "auth_email_submitted"
    AUTH_OTP_PAGE_REACHED = "auth_otp_page_reached"
    AUTHENTICATED = "authenticated"
    ONBOARDING_COMPLETE = "onboarding_complete"
    API_KEYS_PAGE_LOADED = "api_keys_page_loaded"
    API_KEY_CREATE_CLICKED = "api_key_create_clicked"
    API_KEY_GENERATE_CLICKED = "api_key_generate_clicked"
    API_KEY_CAPTURED = "api_key_captured"
    API_KEY_STORED = "api_key_stored"
    API_KEY_NAME_ENTERED = "api_key_name_entered"
    API_KEY_LIST_READ = "api_key_list_read"
    API_KEY_DELETE_CLICKED = "api_key_delete_clicked"
    API_KEY_DELETE_CONFIRMED = "api_key_delete_confirmed"
    API_KEY_DELETED = "api_key_deleted"
    BILLING_PAGE_LOADED = "billing_page_loaded"
    PAYMENT_MODAL_OPENED = "payment_modal_opened"
    STRIPE_IFRAME_FOUND = "stripe_iframe_found"
    PAYMENT_FORM_FILLED = "payment_form_filled"
    PAYMENT_SUBMITTED = "payment_submitted"
    ADD_BALANCE_MODAL_OPENED = "add_balance_modal_opened"
    ADD_BALANCE_AMOUNT_FILLED = "add_balance_amount_filled"
    ADD_BALANCE_SUBMITTED = "add_balance_submitted"


class AutomationOutcome(StrEnum):
    SUCCESS = "success"
    CARD_DECLINED = "card_declined"
    PAYMENT_METHOD_REQUIRED = "payment_method_required"
    SELECTOR_MISSING = "selector_missing"
    KEY_NOT_FOUND = "key_not_found"
    AUTH_REQUIRED = "auth_required"
    AUTH_ACCESS_BLOCKED = "auth_access_blocked"
    STORE_FAILED = "store_failed"
    POLICY_DENIED = "policy_denied"
    BOT_OR_RATE_LIMIT = "bot_or_rate_limit"
    TRANSIENT_BROWSER_FAILURE = "transient_browser_failure"
    UNKNOWN_FAILURE = "unknown_failure"


@dataclass(frozen=True)
class AutomationReceipt:
    """Bounded public record for a Tinker automation attempt."""

    surface: AutomationSurface
    outcome: AutomationOutcome
    furthest_stage: AutomationStage
    evidence_hash: str
    bounded_message: str = ""
    account_hash: str = ""
    amount_band: str = ""
    balance_band: str = ""
    tdx_quote_hash: str = ""
    card_payload_destroyed: bool = False
    raw_secret_egress: bool = False
    issued_at: int = field(default_factory=lambda: int(time.time()))

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "surface": self.surface.value,
            "outcome": self.outcome.value,
            "furthest_stage": self.furthest_stage.value,
            "bounded_message": self.bounded_message,
            "evidence_hash": self.evidence_hash,
            "account_hash": self.account_hash,
            "amount_band": self.amount_band,
            "balance_band": self.balance_band,
            "tdx_quote_hash": self.tdx_quote_hash,
            "card_payload_destroyed": self.card_payload_destroyed,
            "raw_secret_egress": self.raw_secret_egress,
            "issued_at": self.issued_at,
        }


def hash_bounded_evidence(*parts: object) -> str:
    """Hash redacted evidence into a stable audit value."""
    payload = json.dumps(
        [redact_text(part) for part in parts],
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def account_hash(identifier: str) -> str:
    if not identifier:
        return ""
    return hashlib.sha256(identifier.strip().lower().encode()).hexdigest()


def quote_hash(quote: str | None) -> str:
    if not quote:
        return ""
    return hashlib.sha256(quote.encode()).hexdigest()


def amount_band(amount_dollars: float | int | None) -> str:
    if amount_dollars is None:
        return "unknown"
    amount = float(amount_dollars)
    if not math.isfinite(amount):
        return "invalid_amount"
    if amount <= 0:
        return "zero_or_negative"
    if amount < 5:
        return "lt_5_usd"
    if amount < 25:
        return "5_25_usd"
    if amount < 100:
        return "25_100_usd"
    return "gte_100_usd"


def balance_band(balance: str | None) -> str:
    if not balance or balance == "unknown":
        return "unknown"
    digits = "".join(ch for ch in balance if ch.isdigit() or ch == ".")
    if not digits:
        return "unknown"
    value = float(digits)
    if value == 0:
        return "zero_usd"
    if value < 10:
        return "lt_10_usd"
    if value < 100:
        return "10_100_usd"
    return "gte_100_usd"


def classify_automation_error(error: str | None) -> AutomationOutcome:
    text = (error or "").lower()
    if not text:
        return AutomationOutcome.UNKNOWN_FAILURE
    if "declined" in text or "your card" in text or "the card" in text:
        return AutomationOutcome.CARD_DECLINED
    if "payment method required" in text:
        return AutomationOutcome.PAYMENT_METHOD_REQUIRED
    if "selector" in text or "not found" in text or "iframe" in text or "button" in text:
        return AutomationOutcome.SELECTOR_MISSING
    if "auth required" in text or "sign in required" in text:
        return AutomationOutcome.AUTH_REQUIRED
    if "access blocked" in text or ("auth" in text and "blocked" in text):
        return AutomationOutcome.AUTH_ACCESS_BLOCKED
    if (
        "exceeds approved cap" in text
        or "must be finite and positive" in text
        or "must be positive" in text
        or "below tinker minimum" in text
        or "whole-dollar" in text
        or "policy" in text
    ):
        return AutomationOutcome.POLICY_DENIED
    if "rate limit" in text or "too many" in text or "bot" in text:
        return AutomationOutcome.BOT_OR_RATE_LIMIT
    if (
        "timeout" in text
        or "browser" in text
        or "navigation" in text
        or "page.goto" in text
        or "err_aborted" in text
        or "cdp" in text
        or "did not become ready" in text
    ):
        return AutomationOutcome.TRANSIENT_BROWSER_FAILURE
    return AutomationOutcome.UNKNOWN_FAILURE


def make_receipt(
    *,
    surface: AutomationSurface,
    outcome: AutomationOutcome,
    furthest_stage: AutomationStage,
    evidence: object = "",
    bounded_message: str = "",
    account_identifier: str = "",
    amount_dollars: float | int | None = None,
    balance: str | None = None,
    tdx_quote: str | None = None,
    card_payload_destroyed: bool = False,
) -> AutomationReceipt:
    return AutomationReceipt(
        surface=surface,
        outcome=outcome,
        furthest_stage=furthest_stage,
        bounded_message=bounded_message,
        evidence_hash=hash_bounded_evidence(surface.value, outcome.value, furthest_stage.value, evidence),
        account_hash=account_hash(account_identifier),
        amount_band=amount_band(amount_dollars) if amount_dollars is not None else "",
        balance_band=balance_band(balance) if balance is not None else "",
        tdx_quote_hash=quote_hash(tdx_quote),
        card_payload_destroyed=card_payload_destroyed,
        raw_secret_egress=False,
    )
