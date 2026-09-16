"""Bounded calldata plan for an already-authorized RoyaltyDistributor v3 settlement.

This module is an encoder, not an entitlement authority or signer. It accepts
the exact release-CVM and independent-QVL signatures plus the complete anchored
authorization, recomputes the EIP-712 owner/amount array commitment, and emits
raw calldata for a funder to broadcast with a Foundry keystore account. The old
unsigned ``query_ref + caller supplied split`` path no longer exists.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from eth_hash.auto import keccak

from tinker_delegate.chain_submitter import encode_address_word, encode_uint256, normalize_address

_ZERO_ADDRESS = "0x" + "00" * 20
_MAX_RECIPIENTS = 16
_OWNER_AMOUNTS_TYPEHASH = keccak(b"RoyaltyOwnerAmounts(address[] owners,uint256[] amounts)")
_AUTHORIZATION_TUPLE = (
    "(bytes32,uint256,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,"
    "address,uint256,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint256)"
)
_DISTRIBUTE_ARGUMENTS = f"{_AUTHORIZATION_TUPLE},address[],uint256[],bytes,bytes"
DISTRIBUTE_NATIVE_FUNCTION = f"distributeNative({_DISTRIBUTE_ARGUMENTS})"
DISTRIBUTE_ERC20_FUNCTION = f"distributeERC20({_DISTRIBUTE_ARGUMENTS})"
SETTLE_RESERVED_FUNCTION = f"settleReserved(bytes32,{_DISTRIBUTE_ARGUMENTS})"
DISTRIBUTE_NATIVE_SELECTOR = keccak(DISTRIBUTE_NATIVE_FUNCTION.encode())[:4]
DISTRIBUTE_ERC20_SELECTOR = keccak(DISTRIBUTE_ERC20_FUNCTION.encode())[:4]
SETTLE_RESERVED_SELECTOR = keccak(SETTLE_RESERVED_FUNCTION.encode())[:4]


class RoyaltyDistributionError(ValueError):
    """Raised when an authorized distribution plan is malformed."""


@dataclass(frozen=True)
class DistributionRecipient:
    owner_address: str
    amount: int


@dataclass(frozen=True)
class SettlementAuthorization:
    settlement_id: str
    settlement_nonce: int
    funding_reservation_id: str
    release_policy_commitment: str
    room_commitment: str
    room_state_commitment: str
    query_commitment: str
    grant_set_commitment: str
    allocation_commitment: str
    owners_amounts_hash: str
    asset_address: str
    total: int
    execution_commitment: str
    result_commitment: str
    usage_commitment: str
    attestation_evidence_hash: str
    anchor_resource_hash: str
    anchor_decision_hash: str
    anchor_sequence: int
    expiry: int


@dataclass(frozen=True)
class RoyaltyDistributionPlan:
    contract_address: str
    asset_address: str
    native: bool
    settlement_id: str
    settlement_nonce: int
    funding_reservation_id: str
    prefunded: bool
    total_amount: int
    recipient_count: int
    owners_amounts_hash: str
    authorization_fields_hash: str
    function: str
    calldata: str
    cast_command: str
    requires_release_signatures: bool = True
    requires_funder_broadcast: bool = True
    raw_secret_egress: bool = False

    @property
    def token_address(self) -> str:
        """Compatibility alias for callers that display the exact asset."""
        return self.asset_address

    @property
    def query_ref(self) -> str:
        """Compatibility alias; v2 semantics are globally unique settlement ID."""
        return self.settlement_id

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "authorized_royalty_distribution_plan_v3",
            "contract_address": self.contract_address,
            "asset_address": self.asset_address,
            "native": self.native,
            "settlement_id": self.settlement_id,
            "settlement_nonce": self.settlement_nonce,
            "funding_reservation_id": self.funding_reservation_id,
            "prefunded": self.prefunded,
            "total_amount": self.total_amount,
            "recipient_count": self.recipient_count,
            "owners_amounts_hash": self.owners_amounts_hash,
            "authorization_fields_hash": self.authorization_fields_hash,
            "function": self.function,
            "calldata": self.calldata,
            "cast_command": self.cast_command,
            "requires_release_signatures": self.requires_release_signatures,
            "requires_funder_broadcast": self.requires_funder_broadcast,
            "raw_secret_egress": self.raw_secret_egress,
        }


def compute_owner_amounts_hash(recipients: Sequence[DistributionRecipient]) -> str:
    """Reproduce the contract's EIP-712 dynamic-array commitment."""
    normalized = _normalize_recipients(recipients)
    owners_encoded = b"".join(encode_address_word(owner) for owner, _ in normalized)
    amounts_encoded = b"".join(encode_uint256(amount) for _, amount in normalized)
    return "0x" + keccak(_OWNER_AMOUNTS_TYPEHASH + keccak(owners_encoded) + keccak(amounts_encoded)).hex()


def build_royalty_distribution_plan(
    *,
    contract_address: str,
    authorization: SettlementAuthorization,
    recipients: Sequence[DistributionRecipient],
    settlement_signature: str,
    qvl_signature: str,
    keystore_account: str = "dev",
    rpc_url_placeholder: str = "$BASE_SEPOLIA_RPC_URL",
) -> RoyaltyDistributionPlan:
    """Encode one exact dual-signed, anchor-bound settlement for broadcast."""
    contract = normalize_address(contract_address)
    normalized_recipients = _normalize_recipients(recipients)
    owners = [owner for owner, _ in normalized_recipients]
    amounts = [amount for _, amount in normalized_recipients]
    total = sum(amounts)
    if total != _positive_uint(authorization.total, field="authorization total"):
        raise RoyaltyDistributionError("recipient sum does not match authorization total")

    computed_owner_amounts_hash = compute_owner_amounts_hash(recipients)
    supplied_owner_amounts_hash = _bytes32_hex(
        authorization.owners_amounts_hash, field="owners_amounts_hash"
    )
    if computed_owner_amounts_hash.lower() != supplied_owner_amounts_hash.lower():
        raise RoyaltyDistributionError("recipients do not match the signed owners_amounts_hash")

    authorization_words = _encode_authorization(authorization)
    asset = normalize_address(authorization.asset_address)
    native = asset == _ZERO_ADDRESS
    settlement_signature_bytes = _hex_bytes(
        settlement_signature, field="settlement_signature", allow_empty=False
    )
    qvl_signature_bytes = _hex_bytes(qvl_signature, field="qvl_signature", allow_empty=False)

    owners_tail = _encode_address_array(owners)
    amounts_tail = _encode_uint_array(amounts)
    settlement_signature_tail = _encode_bytes(settlement_signature_bytes)
    qvl_signature_tail = _encode_bytes(qvl_signature_bytes)
    reservation_id = _bytes32_allow_zero(
        authorization.funding_reservation_id,
        field="funding_reservation_id",
    )
    prefunded = reservation_id != b"\x00" * 32
    head_length = (20 + 4 + (1 if prefunded else 0)) * 32
    owners_offset = head_length
    amounts_offset = owners_offset + len(owners_tail)
    settlement_signature_offset = amounts_offset + len(amounts_tail)
    qvl_signature_offset = settlement_signature_offset + len(settlement_signature_tail)
    body = (
        (reservation_id if prefunded else b"")
        + authorization_words
        + encode_uint256(owners_offset)
        + encode_uint256(amounts_offset)
        + encode_uint256(settlement_signature_offset)
        + encode_uint256(qvl_signature_offset)
        + owners_tail
        + amounts_tail
        + settlement_signature_tail
        + qvl_signature_tail
    )
    function = (
        SETTLE_RESERVED_FUNCTION
        if prefunded
        else DISTRIBUTE_NATIVE_FUNCTION if native else DISTRIBUTE_ERC20_FUNCTION
    )
    selector = (
        SETTLE_RESERVED_SELECTOR
        if prefunded
        else DISTRIBUTE_NATIVE_SELECTOR if native else DISTRIBUTE_ERC20_SELECTOR
    )
    calldata = "0x" + (selector + body).hex()
    value_flag = f" --value {total}" if native and not prefunded else ""
    cast_command = (
        f"cast send {contract} {calldata}{value_flag} "
        f"--rpc-url {rpc_url_placeholder} --account {keystore_account}"
    )
    return RoyaltyDistributionPlan(
        contract_address=contract,
        asset_address=asset,
        native=native,
        settlement_id=_bytes32_hex(authorization.settlement_id, field="settlement_id"),
        settlement_nonce=_positive_uint(authorization.settlement_nonce, field="settlement_nonce"),
        funding_reservation_id="0x" + reservation_id.hex(),
        prefunded=prefunded,
        total_amount=total,
        recipient_count=len(normalized_recipients),
        owners_amounts_hash=computed_owner_amounts_hash,
        authorization_fields_hash="0x" + keccak(authorization_words).hex(),
        function=function,
        calldata=calldata,
        cast_command=cast_command,
    )


def _encode_authorization(authorization: SettlementAuthorization) -> bytes:
    return b"".join(
        (
            _bytes32(authorization.settlement_id, field="settlement_id"),
            encode_uint256(_positive_uint(authorization.settlement_nonce, field="settlement_nonce")),
            _bytes32_allow_zero(
                authorization.funding_reservation_id,
                field="funding_reservation_id",
            ),
            _bytes32(authorization.release_policy_commitment, field="release_policy_commitment"),
            _bytes32(authorization.room_commitment, field="room_commitment"),
            _bytes32(authorization.room_state_commitment, field="room_state_commitment"),
            _bytes32(authorization.query_commitment, field="query_commitment"),
            _bytes32(authorization.grant_set_commitment, field="grant_set_commitment"),
            _bytes32(authorization.allocation_commitment, field="allocation_commitment"),
            _bytes32(authorization.owners_amounts_hash, field="owners_amounts_hash"),
            encode_address_word(normalize_address(authorization.asset_address)),
            encode_uint256(_positive_uint(authorization.total, field="total")),
            _bytes32(authorization.execution_commitment, field="execution_commitment"),
            _bytes32(authorization.result_commitment, field="result_commitment"),
            _bytes32(authorization.usage_commitment, field="usage_commitment"),
            _bytes32(authorization.attestation_evidence_hash, field="attestation_evidence_hash"),
            _bytes32(authorization.anchor_resource_hash, field="anchor_resource_hash"),
            _bytes32(authorization.anchor_decision_hash, field="anchor_decision_hash"),
            encode_uint256(_positive_uint(authorization.anchor_sequence, field="anchor_sequence")),
            encode_uint256(_positive_uint(authorization.expiry, field="expiry")),
        )
    )


def _normalize_recipients(recipients: Sequence[DistributionRecipient]) -> list[tuple[str, int]]:
    if not recipients:
        raise RoyaltyDistributionError("at least one recipient is required")
    if len(recipients) > _MAX_RECIPIENTS:
        raise RoyaltyDistributionError("recipient count exceeds contract maximum")
    normalized: list[tuple[str, int]] = []
    for recipient in recipients:
        owner = normalize_address(recipient.owner_address)
        if owner == _ZERO_ADDRESS:
            raise RoyaltyDistributionError("recipient owner cannot be the zero address")
        amount = _positive_uint(recipient.amount, field="recipient amount")
        normalized.append((owner, amount))
    normalized.sort(key=lambda item: int(item[0][2:], 16))
    if len({owner for owner, _ in normalized}) != len(normalized):
        raise RoyaltyDistributionError("recipient owners must be unique")
    return normalized


def _encode_address_array(addresses: Sequence[str]) -> bytes:
    return encode_uint256(len(addresses)) + b"".join(encode_address_word(address) for address in addresses)


def _encode_uint_array(values: Sequence[int]) -> bytes:
    return encode_uint256(len(values)) + b"".join(encode_uint256(value) for value in values)


def _encode_bytes(value: bytes) -> bytes:
    padding = (-len(value)) % 32
    return encode_uint256(len(value)) + value + (b"\x00" * padding)


def _bytes32(value: str, *, field: str) -> bytes:
    decoded = _hex_bytes(value, field=field, allow_empty=False)
    if len(decoded) != 32 or decoded == b"\x00" * 32:
        raise RoyaltyDistributionError(f"{field} must be a nonzero bytes32 value")
    return decoded


def _bytes32_allow_zero(value: str, *, field: str) -> bytes:
    decoded = _hex_bytes(value, field=field, allow_empty=False)
    if len(decoded) != 32:
        raise RoyaltyDistributionError(f"{field} must be a bytes32 value")
    return decoded


def _bytes32_hex(value: str, *, field: str) -> str:
    return "0x" + _bytes32(value, field=field).hex()


def _hex_bytes(value: str, *, field: str, allow_empty: bool) -> bytes:
    if not isinstance(value, str):
        raise RoyaltyDistributionError(f"{field} must be hex")
    body = value[2:] if value.startswith(("0x", "0X")) else value
    if len(body) % 2 != 0 or any(char not in "0123456789abcdefABCDEF" for char in body):
        raise RoyaltyDistributionError(f"{field} must be even-length hex")
    decoded = bytes.fromhex(body)
    if not allow_empty and not decoded:
        raise RoyaltyDistributionError(f"{field} must be nonempty")
    if len(decoded) > 4096:
        raise RoyaltyDistributionError(f"{field} exceeds the bounded signature size")
    return decoded


def _positive_uint(value: int, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value >= 2**256:
        raise RoyaltyDistributionError(f"{field} must be a positive uint256")
    return value
