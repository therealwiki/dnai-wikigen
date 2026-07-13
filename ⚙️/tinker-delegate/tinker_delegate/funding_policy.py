"""Funding-mode policy for Tinker account balance operations."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from tinker_delegate.automation_receipts import (
    AutomationOutcome,
    AutomationStage,
    AutomationSurface,
    make_receipt,
)
from tinker_delegate.funding_receipt_store import build_funding_receipt_store
from tinker_delegate.redaction import redact_text
from tinker_delegate.tinker_encumbrance import (
    TinkerEncumbranceError,
    TinkerOperationKind,
    preflight_tinker_operation,
)


class FundingMode(StrEnum):
    MANUAL_PREFUND = "manual_prefund"
    OPERATOR_CAPPED_VALIDATION = "operator_capped_validation"
    OFFICIAL_TOKENIZED = "official_tokenized"


class FundingPolicyError(PermissionError):
    """Raised when a funding operation is denied by the configured mode."""


@dataclass(frozen=True)
class FundingPolicyStatus:
    mode: FundingMode
    production_model: str
    card_automation_allowed: bool
    add_balance_automation_allowed: bool
    min_add_balance_usd: float
    max_add_balance_usd: float
    plaintext_card_endpoint_allowed: bool
    add_balance_endpoint_allowed: bool
    raw_card_scope: str
    next_required_evidence: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "production_model": self.production_model,
            "card_automation_allowed": self.card_automation_allowed,
            "add_balance_automation_allowed": self.add_balance_automation_allowed,
            "min_add_balance_usd": self.min_add_balance_usd,
            "max_add_balance_usd": self.max_add_balance_usd,
            "plaintext_card_endpoint_allowed": self.plaintext_card_endpoint_allowed,
            "add_balance_endpoint_allowed": self.add_balance_endpoint_allowed,
            "raw_card_scope": self.raw_card_scope,
            "next_required_evidence": self.next_required_evidence,
        }


@dataclass(frozen=True)
class FundingPreflightCheck:
    name: str
    ok: bool
    status: str
    detail: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class FundingValidationPreflight:
    ready: bool
    policy: FundingPolicyStatus
    checks: tuple[FundingPreflightCheck, ...]

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "policy": self.policy.to_public_dict(),
            "checks": [check.to_public_dict() for check in self.checks],
        }


def resolve_funding_mode(settings) -> FundingMode:
    try:
        return FundingMode(settings.funding_mode)
    except ValueError as exc:
        allowed = ", ".join(mode.value for mode in FundingMode)
        raise FundingPolicyError(f"Unsupported TINKER_FUNDING_MODE; expected one of: {allowed}") from exc


def funding_policy_status(settings) -> FundingPolicyStatus:
    mode = resolve_funding_mode(settings)
    operator_validation = mode == FundingMode.OPERATOR_CAPPED_VALIDATION
    tokenized = mode == FundingMode.OFFICIAL_TOKENIZED
    return FundingPolicyStatus(
        mode=mode,
        production_model=(
            "manual/developer prefund"
            if mode == FundingMode.MANUAL_PREFUND
            else "one-off operator-owned capped validation"
            if operator_validation
            else "official/tokenized funding route"
        ),
        card_automation_allowed=operator_validation,
        add_balance_automation_allowed=operator_validation,
        min_add_balance_usd=settings.min_add_balance_usd,
        max_add_balance_usd=settings.max_add_balance_usd,
        plaintext_card_endpoint_allowed=bool(settings.allow_plaintext_card_endpoint and operator_validation),
        add_balance_endpoint_allowed=bool(settings.allow_add_balance_endpoint and operator_validation),
        raw_card_scope=(
            "denied"
            if not operator_validation
            else "operator-owned capped validation only; not production or repeated funding"
        ),
        next_required_evidence=(
            "capped real-card validation with operator approval"
            if operator_validation
            else "official tokenized route or manual prefund evidence"
            if tokenized
            else "manual prefund balance evidence or approved tokenized funding design"
        ),
    )


def require_card_automation_allowed(settings) -> FundingMode:
    mode = resolve_funding_mode(settings)
    if mode != FundingMode.OPERATOR_CAPPED_VALIDATION:
        raise FundingPolicyError(
            "Card automation is disabled by TINKER_FUNDING_MODE; "
            "set operator_capped_validation only for an approved one-off operator-owned test"
        )
    return mode


def require_add_balance_allowed(settings) -> FundingMode:
    mode = resolve_funding_mode(settings)
    if mode != FundingMode.OPERATOR_CAPPED_VALIDATION:
        raise FundingPolicyError(
            "Add-balance automation is disabled by TINKER_FUNDING_MODE; "
            "production funding is manual/developer prefund until an approved tokenized route exists"
        )
    return mode


def funding_policy_receipt(
    *,
    surface: AutomationSurface,
    error: str,
    amount_dollars: float | None = None,
    card_payload_destroyed: bool = False,
) -> dict[str, Any]:
    return make_receipt(
        surface=surface,
        outcome=AutomationOutcome.POLICY_DENIED,
        furthest_stage=AutomationStage.NOT_STARTED,
        evidence=error,
        bounded_message=error,
        amount_dollars=amount_dollars,
        card_payload_destroyed=card_payload_destroyed,
    ).to_public_dict()


def funding_validation_preflight(
    settings,
    *,
    amount_dollars: float | None = None,
    require_add_balance_endpoint: bool = False,
    api_url: str = "",
    expected_compose_hash: str = "",
    expected_app_id: str = "",
    expected_os_image_hash: str = "",
    allow_local_attestation: bool = False,
    fetch_attestation: bool = False,
) -> FundingValidationPreflight:
    """Check operator funding readiness without card material or browser launch."""
    policy = funding_policy_status(settings)
    checks: list[FundingPreflightCheck] = []

    checks.append(
        FundingPreflightCheck(
            name="funding_mode",
            ok=policy.mode == FundingMode.OPERATOR_CAPPED_VALIDATION,
            status=policy.mode.value,
            detail=(
                "operator capped validation enabled"
                if policy.mode == FundingMode.OPERATOR_CAPPED_VALIDATION
                else "set TINKER_FUNDING_MODE=operator_capped_validation for a one-off operator validation"
            ),
        )
    )

    min_amount = float(settings.min_add_balance_usd)
    max_amount = float(settings.max_add_balance_usd)
    cap_ok = math.isfinite(min_amount) and math.isfinite(max_amount) and 0 < min_amount <= max_amount
    checks.append(
        FundingPreflightCheck(
            name="max_add_balance_cap",
            ok=cap_ok,
            status=f"{settings.min_add_balance_usd}..{settings.max_add_balance_usd}",
            detail="configured min/cap must be finite, positive, and min must not exceed cap",
        )
    )

    if amount_dollars is not None:
        amount = float(amount_dollars)
        amount_ok = (
            math.isfinite(amount)
            and min_amount <= amount <= max_amount
            and amount.is_integer()
        )
        if not math.isfinite(amount) or amount <= 0:
            amount_status = "invalid_amount"
        elif amount < min_amount:
            amount_status = "below_minimum"
        elif not amount.is_integer():
            amount_status = "not_whole_dollar"
        elif amount > max_amount:
            amount_status = "outside_cap"
        else:
            amount_status = "within_cap"
        checks.append(
            FundingPreflightCheck(
                name="requested_amount",
                ok=amount_ok,
                status=amount_status,
                detail=(
                    "requested amount must be a whole-dollar value no smaller than "
                    "TINKER_MIN_ADD_BALANCE_USD and no larger than TINKER_MAX_ADD_BALANCE_USD"
                ),
            )
        )

    if getattr(settings, "encumbrance_required", False) or getattr(
        settings, "encumbrance_contract_address", ""
    ):
        checks.append(_tinker_encumbrance_check(settings, amount_dollars=amount_dollars))

    if require_add_balance_endpoint:
        endpoint_ok = bool(settings.allow_add_balance_endpoint)
        checks.append(
            FundingPreflightCheck(
                name="add_balance_endpoint",
                ok=endpoint_ok,
                status="enabled" if endpoint_ok else "disabled",
                detail="set TINKER_ALLOW_ADD_BALANCE_ENDPOINT=true only for a deliberate capped validation",
            )
        )

    checks.append(_receipt_store_check(settings))
    checks.extend(
        _attestation_preflight_checks(
            api_url=api_url,
            expected_compose_hash=expected_compose_hash,
            expected_app_id=expected_app_id,
            expected_os_image_hash=expected_os_image_hash,
            allow_local_attestation=allow_local_attestation,
            fetch_attestation=fetch_attestation,
        )
    )

    return FundingValidationPreflight(
        ready=all(check.ok for check in checks),
        policy=policy,
        checks=tuple(checks),
    )


def _receipt_store_check(settings) -> FundingPreflightCheck:
    try:
        build_funding_receipt_store(settings).load()
    except Exception as exc:
        return FundingPreflightCheck(
            name="funding_receipt_store",
            ok=False,
            status="unavailable",
            detail=redact_text(exc),
        )
    return FundingPreflightCheck(
        name="funding_receipt_store",
        ok=True,
        status="loadable",
        detail="bounded encrypted receipt store can be opened",
    )


def _tinker_encumbrance_check(settings, *, amount_dollars: float | None) -> FundingPreflightCheck:
    try:
        result = preflight_tinker_operation(
            settings,
            operation_kind=TinkerOperationKind.ADD_BALANCE,
            amount_dollars=amount_dollars or 0,
        )
    except TinkerEncumbranceError as exc:
        return FundingPreflightCheck(
            name="tinker_encumbrance",
            ok=False,
            status="error",
            detail=redact_text(exc),
        )
    return FundingPreflightCheck(
        name="tinker_encumbrance",
        ok=bool(result.allowed),
        status=result.reason,
        detail=(
            "contract policy checked for add-balance"
            if result.checked
            else "contract policy not checked"
        ),
    )


def _attestation_preflight_checks(
    *,
    api_url: str,
    expected_compose_hash: str,
    expected_app_id: str,
    expected_os_image_hash: str,
    allow_local_attestation: bool,
    fetch_attestation: bool,
) -> list[FundingPreflightCheck]:
    if not api_url:
        return [
            FundingPreflightCheck(
                name="billing_attestation_policy",
                ok=False,
                status="missing_api_url",
                detail="provide the delegate API URL to preflight encrypted-card attestation",
            )
        ]

    has_expected_identity = bool(expected_compose_hash or expected_app_id or expected_os_image_hash)
    if not allow_local_attestation and not has_expected_identity:
        return [
            FundingPreflightCheck(
                name="billing_attestation_policy",
                ok=False,
                status="missing_expected_measurement",
                detail="provide expected compose/app/OS image hash or explicitly allow local attestation",
            )
        ]

    checks = [
        FundingPreflightCheck(
            name="billing_attestation_policy",
            ok=True,
            status="configured",
            detail="billing attestation policy has bounded expected evidence",
        )
    ]
    if not fetch_attestation:
        checks.append(
            FundingPreflightCheck(
                name="billing_attestation_fetch",
                ok=True,
                status="skipped",
                detail="pass --fetch-attestation to live-fetch and verify /attestation?context=billing",
            )
        )
        return checks

    from tinker_delegate.attestation_verifier import (
        AttestationPolicy,
        AttestationVerificationError,
        fetch_and_verify_attestation,
    )

    policy = AttestationPolicy(
        expected_compose_hash=expected_compose_hash,
        expected_app_id=expected_app_id,
        expected_os_image_hash=expected_os_image_hash,
        context="billing",
        allow_local=allow_local_attestation,
    )
    try:
        result = fetch_and_verify_attestation(api_url, policy)
    except AttestationVerificationError as exc:
        checks.append(
            FundingPreflightCheck(
                name="billing_attestation_fetch",
                ok=False,
                status="rejected",
                detail=redact_text(exc),
            )
        )
        return checks
    except Exception as exc:
        checks.append(
            FundingPreflightCheck(
                name="billing_attestation_fetch",
                ok=False,
                status="unavailable",
                detail=redact_text(exc),
            )
        )
        return checks

    checks.append(
        FundingPreflightCheck(
            name="billing_attestation_fetch",
            ok=True,
            status=result.mode,
            detail="billing attestation evidence verified",
        )
    )
    return checks
