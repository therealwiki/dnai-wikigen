"""Secure card update channel — encrypted card delivery from developer to TEE.

Trust model:
  1. Developer requests TDX attestation from CVM via GET /attestation?context=billing
  2. Developer verifies: code measurements match git SHA → docker digest → compose hash
     and report_data binds the returned encryption_public_key
  3. Developer encrypts CardPayload to TEE's ephemeral public key (X25519 + AES-256-GCM)
  4. Developer sends encrypted payload to POST /billing/card
  5. TEE decrypts inside enclave, fills Stripe form via browser, submits
  6. TEE zeroes card details from memory — never persisted to disk
  7. Returns success + TDX quote attesting the billing operation

What the developer CAN do:
  - Add/update payment method (card details encrypted to TEE)
  - Add balance (amount only, no card details needed if card on file)
  - Read balance (no sensitive data)

What the developer CANNOT do:
  - Access the Tinker API key
  - Read training data or model weights
  - View training run results (only bounded scores via the deal flow)
  - Extract the email/password (sealed in TEE)

Why this doesn't break the trust model:
  - Card details are ephemeral — exist only in TEE memory for ~10 seconds
  - The developer already trusts the TEE code (verified via attestation)
  - Stripe tokenizes the card on their servers — TEE doesn't persist it
  - The billing session uses the same Tinker auth session that's already in the TEE
  - No new attack surface: the card goes developer → TEE → Stripe, same as
    developer → browser → Stripe, except the browser is inside the TEE

The key insight: the developer is NOT giving the TEE access to their card.
They're using the TEE as a secure intermediary to add a card to the Tinker
account that the TEE controls. The developer trusts the TEE because its code
is attested. The card is delivered to Stripe, not stored by the TEE.
"""
import asyncio
import hashlib
import json
from typing import Optional

from pydantic import BaseModel

from tinker_delegate.automation_receipts import (
    AutomationOutcome,
    AutomationStage,
    AutomationSurface,
    classify_automation_error,
    make_receipt,
    quote_hash,
)
from tinker_delegate.billing import (
    CardDetails,
    add_payment_method,
    add_balance,
    get_account_access_status,
    get_balance,
    get_payment_method_status,
    remove_payment_method,
)
from tinker_delegate.config import Settings
from tinker_delegate.crypto import TEEKeyPair, EncryptedPayload
from tinker_delegate.dstack_utils import get_attestation_details, is_dstack_enabled
from tinker_delegate.funding_receipt_store import build_funding_receipt_store
from tinker_delegate.funding_policy import (
    FundingPolicyError,
    funding_policy_receipt,
    require_add_balance_allowed,
    require_card_automation_allowed,
)
from tinker_delegate.redaction import redact_text
from tinker_delegate.tinker_encumbrance import (
    TinkerEncumbranceError,
    TinkerOperationKind,
    preflight_tinker_operation,
)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class CardPayload(BaseModel):
    """Card details submitted by developer. Normally encrypted in transit."""
    card_number: str
    exp_month: str  # "01"-"12"
    exp_year: str   # "26" or "2026"
    cvc: str
    cardholder_name: str
    address_line1: str = ""
    address_city: str = ""
    address_state: str = ""
    address_postal: str = ""
    address_country: str = "US"

    def zero(self) -> None:
        self.card_number = ""
        self.exp_month = ""
        self.exp_year = ""
        self.cvc = ""
        self.cardholder_name = ""
        self.address_line1 = ""
        self.address_city = ""
        self.address_state = ""
        self.address_postal = ""
        self.address_country = ""


class EncryptedCardPayload(BaseModel):
    """Encrypted card payload — production format.

    Developer encrypts CardPayload JSON to the TEE's X25519 public key
    (obtained from GET /attestation?context=billing after verifying the TDX quote).
    """
    ephemeral_public_key: str  # hex
    nonce: str                 # hex
    ciphertext: str            # hex


class BalancePayload(BaseModel):
    """Add balance request."""
    amount_dollars: float


class BillingResponse(BaseModel):
    success: bool
    error: Optional[str] = None
    balance: Optional[str] = None
    card_on_file: Optional[bool] = None
    payment_method_count_band: Optional[str] = None
    tdx_quote: Optional[str] = None  # hex-encoded TDX quote in production
    attempt_record: Optional[dict] = None
    proxy_auth_context: Optional[dict] = None


# ---------------------------------------------------------------------------
# TEE keypair — singleton, generated on boot
# ---------------------------------------------------------------------------

_tee_keypair: TEEKeyPair | None = None


def get_tee_keypair() -> TEEKeyPair:
    """Get or create the TEE's X25519 keypair."""
    global _tee_keypair
    if _tee_keypair is None:
        _tee_keypair = TEEKeyPair()
    return _tee_keypair


def attestation_report_data(context: str, public_key: bytes) -> bytes:
    """Report data binding an operation context to the TEE encryption key."""
    payload = json.dumps(
        {
            "service": "tinker-delegate",
            "context": context,
            "encryption_public_key": public_key.hex(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).digest()


# ---------------------------------------------------------------------------
# TEE attestation (stub for local, real in dstack)
# ---------------------------------------------------------------------------

def get_attestation(context: str = "ingress") -> dict:
    """Get TDX attestation quote + TEE's encryption public key.

    In production (dstack CVM): returns real TDX quote binding the
    enclave identity + code measurements + encryption public key.

    Locally: returns a stub with the encryption public key (for testing).
    """
    keypair = get_tee_keypair()
    report_data = attestation_report_data(context, keypair.public_key_bytes)
    if is_dstack_enabled():
        try:
            details = get_attestation_details(report_data)
            return {
                "mode": "tdx",
                "quote": details["quote"],
                "encryption_public_key": keypair.public_key_bytes.hex(),
                "report_context": context,
                "report_data": report_data.hex(),
                "quote_report_data": details.get("quote_report_data", ""),
                "event_log": details.get("event_log", ""),
                "vm_config": details.get("vm_config", ""),
                "app_id": details["app_id"],
                "instance_id": details.get("instance_id", ""),
                "app_name": details.get("app_name", ""),
                "device_id": details.get("device_id", ""),
                "mr_aggregated": details.get("mr_aggregated", ""),
                "os_image_hash": details.get("os_image_hash", ""),
                "compose_hash": details["compose_hash"],
                "tcb_info": details.get("tcb_info", {}),
                "verified": True,
            }
        except Exception as e:
            return {"mode": "tdx", "error": redact_text(e), "verified": False}
    else:
        return {
            "mode": "local",
            "note": "Running locally without TDX. In production, this returns a real attestation quote.",
            "encryption_public_key": keypair.public_key_bytes.hex(),
            "report_context": context,
            "report_data": report_data.hex(),
            "verified": False,
        }


# ---------------------------------------------------------------------------
# Card update operations (called by the API server)
# ---------------------------------------------------------------------------

async def handle_card_update(payload: CardPayload, settings: Settings) -> BillingResponse:
    """Process a plaintext card payload: fill form, zero memory.

    For local dev only. In production, use handle_encrypted_card_update.
    """
    try:
        require_card_automation_allowed(settings)
        _require_tinker_encumbrance_allowed(
            settings,
            surface=AutomationSurface.PAYMENT_METHOD,
            operation_kind=TinkerOperationKind.ADD_PAYMENT_METHOD,
        )
    except FundingPolicyError as exc:
        error = redact_text(exc)
        payload.zero()
        return _billing_response_with_persisted_receipt(
            settings,
            success=False,
            error=error,
            attempt_record=funding_policy_receipt(
                surface=AutomationSurface.PAYMENT_METHOD,
                error=error,
                card_payload_destroyed=True,
            ),
        )
    except TinkerEncumbranceError as exc:
        error = redact_text(exc)
        payload.zero()
        return _billing_response_with_persisted_receipt(
            settings,
            success=False,
            error=error,
            attempt_record=funding_policy_receipt(
                surface=AutomationSurface.PAYMENT_METHOD,
                error=error,
                card_payload_destroyed=True,
            ),
        )

    card = CardDetails(
        number=payload.card_number,
        exp_month=payload.exp_month,
        exp_year=payload.exp_year,
        cvc=payload.cvc,
        name=payload.cardholder_name,
        address_line1=payload.address_line1,
        address_city=payload.address_city,
        address_state=payload.address_state,
        address_postal=payload.address_postal,
        address_country=payload.address_country,
    )

    try:
        result = await add_payment_method(card, settings)

        attestation = get_attestation("billing")

        return _billing_response_with_persisted_receipt(
            settings,
            success=result.get("success", False),
            error=result.get("error"),
            tdx_quote=attestation.get("quote"),
            attempt_record=_with_quote_hash(
                _attempt_record_or_fallback(
                    result,
                    AutomationSurface.PAYMENT_METHOD,
                    card_payload_destroyed=True,
                ),
                attestation.get("quote"),
            ),
        )
    except Exception as e:
        error = redact_text(e)
        return _billing_response_with_persisted_receipt(
            settings,
            success=False,
            error=error,
            attempt_record=_exception_receipt(
                AutomationSurface.PAYMENT_METHOD,
                error,
                card_payload_destroyed=True,
            ),
        )
    finally:
        card.zero()
        payload.zero()


async def handle_encrypted_card_update(
    payload: EncryptedCardPayload, settings: Settings
) -> BillingResponse:
    """Process an encrypted card payload: decrypt inside TEE, fill form, zero memory.

    Production path. Card details are encrypted to the TEE's X25519 public key.
    """
    plaintext_bytes = None
    card = None
    try:
        require_card_automation_allowed(settings)
        _require_tinker_encumbrance_allowed(
            settings,
            surface=AutomationSurface.PAYMENT_METHOD,
            operation_kind=TinkerOperationKind.ADD_PAYMENT_METHOD,
        )
    except FundingPolicyError as exc:
        error = redact_text(exc)
        return _billing_response_with_persisted_receipt(
            settings,
            success=False,
            error=error,
            attempt_record=funding_policy_receipt(
                surface=AutomationSurface.PAYMENT_METHOD,
                error=error,
                card_payload_destroyed=True,
            ),
        )
    except TinkerEncumbranceError as exc:
        error = redact_text(exc)
        return _billing_response_with_persisted_receipt(
            settings,
            success=False,
            error=error,
            attempt_record=funding_policy_receipt(
                surface=AutomationSurface.PAYMENT_METHOD,
                error=error,
                card_payload_destroyed=True,
            ),
        )

    keypair = get_tee_keypair()
    try:
        encrypted = EncryptedPayload.from_hex({
            "ephemeral_public_key": payload.ephemeral_public_key,
            "nonce": payload.nonce,
            "ciphertext": payload.ciphertext,
        })
        plaintext_bytes = bytearray(keypair.decrypt(encrypted))
        card_data = json.loads(plaintext_bytes.decode())

        card = CardDetails(
            number=card_data["card_number"],
            exp_month=card_data["exp_month"],
            exp_year=card_data["exp_year"],
            cvc=card_data["cvc"],
            name=card_data["cardholder_name"],
            address_line1=card_data.get("address_line1", ""),
            address_city=card_data.get("address_city", ""),
            address_state=card_data.get("address_state", ""),
            address_postal=card_data.get("address_postal", ""),
            address_country=card_data.get("address_country", "US"),
        )

        # Zero plaintext immediately after parsing.
        for i in range(len(plaintext_bytes)):
            plaintext_bytes[i] = 0
        plaintext_bytes = None

        result = await add_payment_method(card, settings)
        attestation = get_attestation("billing")

        return _billing_response_with_persisted_receipt(
            settings,
            success=result.get("success", False),
            error=result.get("error"),
            tdx_quote=attestation.get("quote"),
            attempt_record=_with_quote_hash(
                _attempt_record_or_fallback(
                    result,
                    AutomationSurface.PAYMENT_METHOD,
                    card_payload_destroyed=True,
                ),
                attestation.get("quote"),
            ),
        )
    except Exception as e:
        error = redact_text(e)
        return _billing_response_with_persisted_receipt(
            settings,
            success=False,
            error=error,
            attempt_record=_exception_receipt(
                AutomationSurface.PAYMENT_METHOD,
                error,
                card_payload_destroyed=True,
            ),
        )
    finally:
        if plaintext_bytes is not None:
            for i in range(len(plaintext_bytes)):
                plaintext_bytes[i] = 0
        if card:
            card.zero()


async def handle_add_balance(payload: BalancePayload, settings: Settings) -> BillingResponse:
    """Add credit balance. No card details needed (uses card on file)."""
    try:
        require_add_balance_allowed(settings)
        _require_tinker_encumbrance_allowed(
            settings,
            surface=AutomationSurface.ADD_BALANCE,
            operation_kind=TinkerOperationKind.ADD_BALANCE,
            amount_dollars=payload.amount_dollars,
        )
    except FundingPolicyError as exc:
        error = redact_text(exc)
        return _billing_response_with_persisted_receipt(
            settings,
            success=False,
            error=error,
            attempt_record=funding_policy_receipt(
                surface=AutomationSurface.ADD_BALANCE,
                error=error,
                amount_dollars=payload.amount_dollars,
            ),
        )
    except TinkerEncumbranceError as exc:
        error = redact_text(exc)
        return _billing_response_with_persisted_receipt(
            settings,
            success=False,
            error=error,
            attempt_record=funding_policy_receipt(
                surface=AutomationSurface.ADD_BALANCE,
                error=error,
                amount_dollars=payload.amount_dollars,
            ),
        )

    try:
        result = await add_balance(payload.amount_dollars, settings)
        return _billing_response_with_persisted_receipt(
            settings,
            success=result.get("success", False),
            error=result.get("error"),
            attempt_record=_attempt_record_or_fallback(
                result,
                AutomationSurface.ADD_BALANCE,
            ),
        )
    except Exception as e:
        error = redact_text(e)
        return _billing_response_with_persisted_receipt(
            settings,
            success=False,
            error=error,
            attempt_record=_exception_receipt(AutomationSurface.ADD_BALANCE, error),
        )


async def handle_get_balance(settings: Settings) -> BillingResponse:
    """Get current balance."""
    try:
        result = await get_balance(settings)
        return BillingResponse(
            success=True,
            balance=result.get("balance"),
        )
    except Exception as e:
        return BillingResponse(success=False, error=_bounded_error_label(e))


async def handle_payment_method_status(settings: Settings) -> BillingResponse:
    """Return bounded payment-method presence without card details."""
    try:
        result = await get_payment_method_status(settings)
        return BillingResponse(
            success=result.get("success", False),
            error=result.get("error"),
            card_on_file=result.get("card_on_file"),
            payment_method_count_band=result.get("payment_method_count_band"),
            attempt_record=result.get("attempt_record"),
        )
    except Exception as e:
        error = _bounded_error_label(e)
        return BillingResponse(
            success=False,
            error=error,
            attempt_record=_exception_receipt(AutomationSurface.PAYMENT_METHOD_STATUS, redact_text(e)),
        )


async def handle_account_access_status(settings: Settings) -> dict:
    """Return the bounded account access/billing-gate receipt (no card/secret)."""
    try:
        return await get_account_access_status(settings)
    except Exception as e:
        return {
            "kind": "account_access_status",
            "success": False,
            "state": "unknown",
            "actionable_by_automation": False,
            "operator_action": "inspect_gate_manually",
            "bounded_message": _bounded_error_label(e),
            "raw_secret_egress": False,
        }


async def handle_remove_payment_method(settings: Settings) -> BillingResponse:
    """Remove payment method through the authenticated Tinker billing UI."""
    try:
        result = await remove_payment_method(settings)
        return _billing_response_with_persisted_receipt(
            settings,
            success=result.get("success", False),
            error=result.get("error"),
            attempt_record=_attempt_record_or_fallback(
                result,
                AutomationSurface.PAYMENT_METHOD_REMOVAL,
            ),
        )
    except Exception as e:
        error = redact_text(e)
        return _billing_response_with_persisted_receipt(
            settings,
            success=False,
            error=error,
            attempt_record=_exception_receipt(AutomationSurface.PAYMENT_METHOD_REMOVAL, error),
        )


def _with_quote_hash(attempt_record: Optional[dict], quote: Optional[str]) -> Optional[dict]:
    if not attempt_record:
        return None
    bounded = dict(attempt_record)
    bounded["tdx_quote_hash"] = quote_hash(quote)
    return bounded


def _require_tinker_encumbrance_allowed(
    settings: Settings,
    *,
    surface: AutomationSurface,
    operation_kind: TinkerOperationKind,
    amount_dollars: float | None = None,
) -> None:
    result = preflight_tinker_operation(
        settings,
        operation_kind=operation_kind,
        amount_dollars=amount_dollars,
    )
    if result.allowed:
        return
    label = surface.value.replace("_", "-")
    raise TinkerEncumbranceError(f"Tinker encumbrance policy denied {label}: {result.reason}")


def _attempt_record_or_fallback(
    result: dict,
    surface: AutomationSurface,
    *,
    card_payload_destroyed: bool = False,
) -> dict:
    attempt_record = result.get("attempt_record")
    if attempt_record:
        return attempt_record
    success = bool(result.get("success"))
    error = result.get("error")
    outcome = AutomationOutcome.SUCCESS if success else classify_automation_error(error)
    return make_receipt(
        surface=surface,
        outcome=outcome,
        furthest_stage=AutomationStage.NOT_STARTED,
        evidence=error or success,
        bounded_message="success" if success else outcome.value,
        card_payload_destroyed=card_payload_destroyed,
    ).to_public_dict()


def _persist_attempt_record(settings: Settings, attempt_record: Optional[dict]) -> Optional[dict]:
    if not attempt_record:
        return None
    store = build_funding_receipt_store(settings)
    return store.append(attempt_record)


def _billing_response_with_persisted_receipt(
    settings: Settings,
    *,
    success: bool,
    error: Optional[str],
    attempt_record: Optional[dict],
    tdx_quote: Optional[str] = None,
) -> BillingResponse:
    try:
        persisted_record = _persist_attempt_record(settings, attempt_record)
    except Exception as exc:
        return BillingResponse(
            success=False,
            error=f"funding receipt persistence failed: {redact_text(exc)}",
            tdx_quote=tdx_quote,
            attempt_record=None,
        )
    return BillingResponse(
        success=success,
        error=error,
        tdx_quote=tdx_quote,
        attempt_record=persisted_record,
    )


def _exception_receipt(
    surface: AutomationSurface,
    error: str,
    *,
    card_payload_destroyed: bool = False,
) -> dict:
    outcome = classify_automation_error(error)
    return make_receipt(
        surface=surface,
        outcome=outcome,
        furthest_stage=AutomationStage.NOT_STARTED,
        evidence=error,
        bounded_message=outcome.value,
        card_payload_destroyed=card_payload_destroyed,
    ).to_public_dict()


def _bounded_error_label(error: object) -> str:
    """Return a public error label without browser URLs, selectors, or page text."""

    return classify_automation_error(redact_text(error)).value
