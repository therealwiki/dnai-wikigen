"""Bounded on-chain distribution plan for the RoyaltyDistributor rail.

Given the resolved per-owner payouts of a settled diligence flow / royalty
ledger, this builds the exact `RoyaltyDistributor.distributeNative` /
`distributeERC20` call the operator broadcasts to credit each co-owner's
claimable balance. Like the governance plan, it does NOT execute — it emits
bounded calldata plus a keystore `cast` command template (`--account`, never a
raw key), so the developer/operator sends it. Exact settlement amounts are
economic entitlements (a bounded settlement event), so they appear; no raw data
or secrets do.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from eth_hash.auto import keccak

from tinker_delegate.chain_submitter import encode_address_word, encode_uint256, normalize_address

_ZERO_ADDRESS = "0x" + "00" * 20
DISTRIBUTE_NATIVE_SELECTOR = keccak(b"distributeNative(bytes32,address[],uint256[])")[:4]
DISTRIBUTE_ERC20_SELECTOR = keccak(b"distributeERC20(bytes32,address,address[],uint256[])")[:4]


class RoyaltyDistributionError(ValueError):
    """Raised on a malformed distribution plan."""


@dataclass(frozen=True)
class DistributionRecipient:
    owner_address: str
    amount: int


@dataclass(frozen=True)
class RoyaltyDistributionPlan:
    contract_address: str
    token_address: str
    native: bool
    query_ref: str
    total_amount: int
    recipient_count: int
    function: str
    calldata: str
    cast_command: str
    requires_operator_broadcast: bool = True
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "royalty_distribution_plan",
            "contract_address": self.contract_address,
            "token_address": self.token_address,
            "native": self.native,
            "query_ref": self.query_ref,
            "total_amount": self.total_amount,
            "recipient_count": self.recipient_count,
            "function": self.function,
            "calldata": self.calldata,
            "cast_command": self.cast_command,
            "requires_operator_broadcast": self.requires_operator_broadcast,
            "raw_secret_egress": self.raw_secret_egress,
        }


def _bytes32(value: str) -> bytes:
    body = value[2:] if value.startswith(("0x", "0X")) else value
    if len(body) != 64 or any(c not in "0123456789abcdefABCDEF" for c in body):
        raise RoyaltyDistributionError("query_ref must be a 32-byte hex value")
    return bytes.fromhex(body)


def _encode_address_array(addresses: Sequence[str]) -> bytes:
    out = encode_uint256(len(addresses))
    for addr in addresses:
        out += encode_address_word(addr)
    return out


def _encode_uint_array(values: Sequence[int]) -> bytes:
    out = encode_uint256(len(values))
    for value in values:
        out += encode_uint256(value)
    return out


def build_royalty_distribution_plan(
    *,
    contract_address: str,
    query_ref: str,
    recipients: Sequence[DistributionRecipient],
    token_address: str = _ZERO_ADDRESS,
    keystore_account: str = "dev",
    rpc_url_placeholder: str = "$BASE_SEPOLIA_RPC_URL",
) -> RoyaltyDistributionPlan:
    """Build the bounded distribute call for a settled royalty split."""
    if not recipients:
        raise RoyaltyDistributionError("at least one recipient is required")
    contract = normalize_address(contract_address)
    token = normalize_address(token_address)
    native = token == _ZERO_ADDRESS
    query_word = _bytes32(query_ref)

    owners: list[str] = []
    amounts: list[int] = []
    for r in recipients:
        owner = normalize_address(r.owner_address)
        if owner == _ZERO_ADDRESS:
            raise RoyaltyDistributionError("recipient owner cannot be the zero address")
        if r.amount <= 0:
            raise RoyaltyDistributionError("recipient amount must be positive")
        owners.append(owner)
        amounts.append(int(r.amount))
    total = sum(amounts)

    owners_join = ",".join(owners)
    amounts_join = ",".join(str(a) for a in amounts)

    if native:
        # head: bytes32, offset(owners), offset(amounts)
        head_len = 3 * 32
        off_owners = head_len
        owners_tail = _encode_address_array(owners)
        off_amounts = head_len + len(owners_tail)
        body = (
            query_word
            + encode_uint256(off_owners)
            + encode_uint256(off_amounts)
            + owners_tail
            + _encode_uint_array(amounts)
        )
        calldata = "0x" + (DISTRIBUTE_NATIVE_SELECTOR + body).hex()
        function = "distributeNative(bytes32,address[],uint256[])"
        cast_command = (
            f"cast send {contract} '{function}' "
            f'"{query_ref}" "[{owners_join}]" "[{amounts_join}]" '
            f"--value {total} --rpc-url {rpc_url_placeholder} --account {keystore_account}"
        )
    else:
        # head: bytes32, address, offset(owners), offset(amounts)
        head_len = 4 * 32
        off_owners = head_len
        owners_tail = _encode_address_array(owners)
        off_amounts = head_len + len(owners_tail)
        body = (
            query_word
            + encode_address_word(token)
            + encode_uint256(off_owners)
            + encode_uint256(off_amounts)
            + owners_tail
            + _encode_uint_array(amounts)
        )
        calldata = "0x" + (DISTRIBUTE_ERC20_SELECTOR + body).hex()
        function = "distributeERC20(bytes32,address,address[],uint256[])"
        cast_command = (
            f"cast send {contract} '{function}' "
            f'"{query_ref}" "{token}" "[{owners_join}]" "[{amounts_join}]" '
            f"--rpc-url {rpc_url_placeholder} --account {keystore_account}"
        )

    return RoyaltyDistributionPlan(
        contract_address=contract,
        token_address=token,
        native=native,
        query_ref=query_ref,
        total_amount=total,
        recipient_count=len(recipients),
        function=function,
        calldata=calldata,
        cast_command=cast_command,
    )
