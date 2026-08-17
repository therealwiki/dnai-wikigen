"""Independent dstack-derived raw EIP-712 signing and replay-key custody."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Protocol

from dstack_sdk import DstackClient
from dstack_sdk.ethereum import to_account_secure
from eth_account.signers.local import LocalAccount

from .errors import SignerUnavailable


SIGNER_PATH_PREFIX = "dnai-wikigen/compute-metering/policy-set-eip712-signer/v1"
REPLAY_PATH_PREFIX = "dnai-wikigen/compute-metering/policy-set-replay-integrity/v1"
REPLAY_DERIVATION_DOMAIN = b"dnai-wikigen/compute-metering/replay-integrity-key/v1\x00"
BYTES32_RE = re.compile(r"^0x[0-9a-f]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
SIGNATURE_RE = re.compile(r"^0x[0-9a-f]{130}$")
SECP256K1_HALF_ORDER = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0


class MeteringSigner(Protocol):
    address: str
    custody: str

    def sign_digest(self, digest: str) -> str:
        """Raw-sign one already-computed EIP-712 digest."""


def _reject_simulator() -> None:
    if any(
        os.environ.get(name, "").strip()
        for name in ("DSTACK_SIMULATOR_ENDPOINT", "TAPPD_SIMULATOR_ENDPOINT")
    ):
        raise SignerUnavailable


def normalize_address(value: str) -> str:
    lowered = value.lower()
    if not ADDRESS_RE.fullmatch(lowered):
        raise SignerUnavailable
    return lowered


def validate_canonical_signature(signature: str) -> bytes:
    if not SIGNATURE_RE.fullmatch(signature):
        raise SignerUnavailable
    raw = bytes.fromhex(signature[2:])
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:64], "big")
    v = raw[64]
    if r == 0 or s == 0 or s > SECP256K1_HALF_ORDER or v not in (27, 28):
        raise SignerUnavailable
    return raw


@dataclass(frozen=True)
class DstackMeteringSigner:
    _account: LocalAccount = field(repr=False)
    key_path: str

    custody = "dstack_derived_independent_cvm"

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", normalize_address(self._account.address))

    @classmethod
    def from_policy_set_hash(cls, policy_set_hash: str) -> "DstackMeteringSigner":
        _reject_simulator()
        if not BYTES32_RE.fullmatch(policy_set_hash) or int(policy_set_hash[2:], 16) == 0:
            raise SignerUnavailable
        key_path = f"{SIGNER_PATH_PREFIX}/{policy_set_hash[2:]}"
        try:
            client = DstackClient()
            if not client.is_reachable():
                raise SignerUnavailable
            response = client.get_key(key_path, "ethereum-signing")
            account = to_account_secure(response)
        except SignerUnavailable:
            raise
        except Exception as exc:
            raise SignerUnavailable from exc
        return cls(_account=account, key_path=key_path)

    def sign_digest(self, digest: str) -> str:
        if not BYTES32_RE.fullmatch(digest):
            raise SignerUnavailable
        try:
            signed = self._account.unsafe_sign_hash(bytes.fromhex(digest[2:]))
            signature = "0x" + bytes(signed.signature).hex()
            validate_canonical_signature(signature)
        except SignerUnavailable:
            raise
        except Exception as exc:
            raise SignerUnavailable from exc
        return signature


def derive_dstack_replay_key(policy_set_hash: str) -> bytes:
    _reject_simulator()
    if not BYTES32_RE.fullmatch(policy_set_hash) or int(policy_set_hash[2:], 16) == 0:
        raise SignerUnavailable
    key_path = f"{REPLAY_PATH_PREFIX}/{policy_set_hash[2:]}"
    try:
        client = DstackClient()
        if not client.is_reachable():
            raise SignerUnavailable
        raw = client.get_key(key_path, "hmac-sha256").decode_key()
        if len(raw) < 32 or len(raw) > 4096:
            raise SignerUnavailable
        return hashlib.sha256(REPLAY_DERIVATION_DOMAIN + bytes.fromhex(policy_set_hash[2:]) + raw).digest()
    except SignerUnavailable:
        raise
    except Exception as exc:
        raise SignerUnavailable from exc
