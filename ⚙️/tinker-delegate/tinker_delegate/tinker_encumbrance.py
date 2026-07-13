"""Bounded runtime reads for ``TinkerAccountEncumbrance`` policy.

The helper reads public contract state only. It does not send transactions,
hold card material, or expose Tinker credentials.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Protocol

from eth_hash.auto import keccak

from tinker_delegate.chain_submitter import (
    ChainSubmitterError,
    JsonRpcClient,
    encode_uint256,
    normalize_address,
)
from tinker_delegate.redaction import redact_text


class TinkerEncumbranceError(ValueError):
    """Raised when Tinker account policy cannot be checked safely."""


class TinkerOperationKind(IntEnum):
    ADD_PAYMENT_METHOD = 0
    ADD_BALANCE = 1
    SPEND_TINKER_COMPUTE = 2
    MANUAL_PREFUND = 3


class EthCallClient(Protocol):
    def eth_call(self, tx: dict[str, Any]) -> str:
        """Return hex-encoded ABI data for an ``eth_call``."""


MAX_ADD_BALANCE_SELECTOR = keccak(b"maxAddBalanceWei()")[:4]
MAX_SPEND_SELECTOR = keccak(b"maxSpendWei()")[:4]
EMERGENCY_HALTED_SELECTOR = keccak(b"emergencyHalted()")[:4]
APPROVED_COMPOSE_SELECTOR = keccak(b"approvedComposeHashes(bytes32)")[:4]


@dataclass(frozen=True)
class TinkerEncumbrancePolicyResult:
    checked: bool
    allowed: bool
    reason: str
    operation: str
    operation_kind: int
    contract_address: str = ""
    compose_hash: str = ""
    compose_approved: bool = False
    emergency_halted: bool = False
    amount_wei: int = 0
    max_amount_wei: int = 0
    limit_kind: str = ""
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "allowed": self.allowed,
            "reason": self.reason,
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "contract_address": self.contract_address,
            "compose_hash": self.compose_hash,
            "compose_approved": self.compose_approved,
            "emergency_halted": self.emergency_halted,
            "amount_wei": str(self.amount_wei),
            "max_amount_wei": str(self.max_amount_wei),
            "limit_kind": self.limit_kind,
            "raw_secret_egress": self.raw_secret_egress,
        }


class TinkerEncumbranceChecker:
    """Read-only checker for a deployed ``TinkerAccountEncumbrance``."""

    def __init__(self, rpc: EthCallClient, contract_address: str):
        self.rpc = rpc
        self.contract_address = _normalize_contract_address(contract_address)

    def check_operation(
        self,
        *,
        operation_kind: TinkerOperationKind,
        compose_hash: str,
        amount_wei: int = 0,
    ) -> TinkerEncumbrancePolicyResult:
        compose_hash = normalize_policy_bytes32(compose_hash, field="compose hash")
        amount_wei = _normalize_uint256(amount_wei, field="amountWei")

        try:
            emergency_halted = self._read_bool(EMERGENCY_HALTED_SELECTOR)
            compose_approved = self._read_bool(
                APPROVED_COMPOSE_SELECTOR + bytes.fromhex(compose_hash[2:])
            )
            max_amount_wei, limit_kind = self._limit_for(operation_kind)
        except (ChainSubmitterError, TinkerEncumbranceError) as exc:
            raise TinkerEncumbranceError(redact_text(exc)) from exc

        allowed = True
        reason = "allowed"
        if emergency_halted:
            allowed = False
            reason = "emergency_halted"
        elif not compose_approved:
            allowed = False
            reason = "compose_hash_not_approved"
        elif limit_kind and amount_wei > max_amount_wei:
            allowed = False
            reason = f"{limit_kind}_cap_exceeded"

        return TinkerEncumbrancePolicyResult(
            checked=True,
            allowed=allowed,
            reason=reason,
            operation=operation_kind.name.lower(),
            operation_kind=int(operation_kind),
            contract_address=self.contract_address,
            compose_hash=compose_hash,
            compose_approved=compose_approved,
            emergency_halted=emergency_halted,
            amount_wei=amount_wei,
            max_amount_wei=max_amount_wei,
            limit_kind=limit_kind,
        )

    def _limit_for(self, operation_kind: TinkerOperationKind) -> tuple[int, str]:
        if operation_kind == TinkerOperationKind.ADD_BALANCE:
            return self._read_uint256(MAX_ADD_BALANCE_SELECTOR), "add_balance"
        if operation_kind == TinkerOperationKind.SPEND_TINKER_COMPUTE:
            return self._read_uint256(MAX_SPEND_SELECTOR), "spend"
        return 0, ""

    def _read_uint256(self, selector_and_args: bytes) -> int:
        raw = self._eth_call(selector_and_args)
        decoded = _decode_word(raw)
        return int.from_bytes(decoded, "big")

    def _read_bool(self, selector_and_args: bytes) -> bool:
        value = self._read_uint256(selector_and_args)
        if value not in (0, 1):
            raise TinkerEncumbranceError("boolean contract read returned non-bool value")
        return bool(value)

    def _eth_call(self, selector_and_args: bytes) -> str:
        return self.rpc.eth_call(
            {
                "to": self.contract_address,
                "data": "0x" + selector_and_args.hex(),
            }
        )


def preflight_tinker_operation(
    settings,
    *,
    operation_kind: TinkerOperationKind,
    amount_dollars: float | None = None,
    amount_wei: int | None = None,
    compose_hash: str = "",
    contract_address: str = "",
    rpc_url: str = "",
    required: bool | None = None,
    rpc: EthCallClient | None = None,
) -> TinkerEncumbrancePolicyResult:
    """Check Tinker account policy when an encumbrance contract is configured.

    If no contract is configured and the policy is not required, this returns an
    explicit unchecked/allowed result so local manual-prefund development keeps
    working. If an address is configured or required is true, failures deny the
    operation before browser automation.
    """

    operation_kind = TinkerOperationKind(operation_kind)
    configured_contract = contract_address or getattr(settings, "encumbrance_contract_address", "")
    policy_required = bool(getattr(settings, "encumbrance_required", False))
    if required is not None:
        policy_required = bool(required)
    if not configured_contract:
        return TinkerEncumbrancePolicyResult(
            checked=False,
            allowed=not policy_required,
            reason="missing_contract" if policy_required else "not_configured",
            operation=operation_kind.name.lower(),
            operation_kind=int(operation_kind),
        )

    resolved_compose_hash = compose_hash or getattr(settings, "encumbrance_compose_hash", "")
    if not resolved_compose_hash:
        return TinkerEncumbrancePolicyResult(
            checked=False,
            allowed=False,
            reason="missing_compose_hash",
            operation=operation_kind.name.lower(),
            operation_kind=int(operation_kind),
            contract_address=_normalize_contract_address(configured_contract),
        )

    resolved_amount_wei = amount_wei
    if resolved_amount_wei is None:
        resolved_amount_wei = amount_dollars_to_policy_wei(
            amount_dollars or 0,
            units_per_usd=int(getattr(settings, "encumbrance_policy_units_per_usd_wei", 10**18)),
        )

    client: EthCallClient | None = rpc
    close_client = False
    try:
        if client is None:
            resolved_rpc_url = rpc_url or getattr(settings, "encumbrance_rpc_url", "") or getattr(
                settings, "chain_rpc_url", ""
            )
            if not resolved_rpc_url:
                return TinkerEncumbrancePolicyResult(
                    checked=False,
                    allowed=False,
                    reason="missing_rpc_url",
                    operation=operation_kind.name.lower(),
                    operation_kind=int(operation_kind),
                    contract_address=_normalize_contract_address(configured_contract),
                )
            client = JsonRpcClient(resolved_rpc_url)
            close_client = True
        return TinkerEncumbranceChecker(client, configured_contract).check_operation(
            operation_kind=operation_kind,
            compose_hash=resolved_compose_hash,
            amount_wei=resolved_amount_wei,
        )
    finally:
        if close_client and hasattr(client, "close"):
            client.close()  # type: ignore[attr-defined]


def amount_dollars_to_policy_wei(amount_dollars: float, *, units_per_usd: int = 10**18) -> int:
    amount = float(amount_dollars)
    if not math.isfinite(amount) or amount < 0:
        raise TinkerEncumbranceError("amount must be finite and non-negative")
    units = _normalize_uint256(units_per_usd, field="unitsPerUsdWei")
    return int(round(amount * units))


def normalize_policy_bytes32(value: str, *, field: str = "bytes32") -> str:
    raw = str(value).strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    try:
        decoded = bytes.fromhex(raw)
    except ValueError as exc:
        raise TinkerEncumbranceError(f"{field} must be hex") from exc
    if len(decoded) != 32:
        raise TinkerEncumbranceError(f"{field} must be bytes32")
    if decoded == b"\x00" * 32:
        raise TinkerEncumbranceError(f"{field} must be non-zero")
    return "0x" + decoded.hex()


def _normalize_uint256(value: int, *, field: str) -> int:
    normalized = int(value)
    if normalized < 0 or normalized >= 2**256:
        raise TinkerEncumbranceError(f"{field} must be uint256")
    return normalized


def _normalize_contract_address(address: str) -> str:
    try:
        return normalize_address(address)
    except ChainSubmitterError as exc:
        raise TinkerEncumbranceError(redact_text(exc)) from exc


def _decode_word(raw: str) -> bytes:
    text = str(raw).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    try:
        decoded = bytes.fromhex(text)
    except ValueError as exc:
        raise TinkerEncumbranceError("contract read returned non-hex data") from exc
    if len(decoded) != 32:
        raise TinkerEncumbranceError("contract read returned non-word data")
    return decoded


def encode_bool(value: bool) -> str:
    return "0x" + encode_uint256(1 if value else 0).hex()


def encode_uint(value: int) -> str:
    return "0x" + encode_uint256(value).hex()
