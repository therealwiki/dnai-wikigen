"""Opaque account-binding commitment for the TEE-owned Tinker account.

The commitment deliberately contains no email address, provider account id,
API key, project id, release SHA, or contract address. A measured provisioner
must later associate the private root with the real provider account and issue
bounded attested evidence. This module only standardizes the cryptographic
derivation shared with Solidity and the release operator tooling.
"""

from __future__ import annotations

import hashlib
import hmac

from eth_hash.auto import keccak


TINKER_ACCOUNT_BINDING_SCHEMA = "dnai.tinker-account-binding.v1"
TINKER_ACCOUNT_BINDING_TYPE = (
    "DnaiTinkerAccountBindingV1(uint256 chainId,bytes32 providerNamespace,bytes32 bindingRoot)"
)
TINKER_PROVIDER_NAMESPACE_LABEL = "thinking-machines/tinker"
TINKER_ACCOUNT_BINDING_CHAIN_ID = 84_532
TINKER_ACCOUNT_BINDING_ROOT_HKDF_SALT = b"dnai-wikigen/tinker-account-binding/v1"
TINKER_ACCOUNT_BINDING_TYPEHASH = keccak(TINKER_ACCOUNT_BINDING_TYPE.encode("utf-8"))
TINKER_PROVIDER_NAMESPACE = keccak(TINKER_PROVIDER_NAMESPACE_LABEL.encode("utf-8"))


def _binding_root(value: bytes | str) -> bytes:
    if isinstance(value, str):
        if not value.startswith("0x") or len(value) != 66 or value != value.lower():
            raise ValueError(
                "Tinker account binding root must be a nonzero lowercase 0x-prefixed bytes32"
            )
        try:
            value = bytes.fromhex(value[2:])
        except ValueError as exc:
            raise ValueError(
                "Tinker account binding root must be a nonzero lowercase 0x-prefixed bytes32"
            ) from exc
    if not isinstance(value, bytes) or len(value) != 32 or value == b"\x00" * 32:
        raise ValueError("Tinker account binding root must be exactly 32 nonzero private bytes")
    return value


def _private_share(value: bytes, label: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32 or value == b"\x00" * 32:
        raise ValueError(f"{label} must be exactly 32 nonzero private bytes")
    return value


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes((counter,)), hashlib.sha256).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def derive_tinker_account_binding_root(
    shares: tuple[bytes, bytes] | list[bytes],
    *,
    chain_id: int = TINKER_ACCOUNT_BINDING_CHAIN_ID,
) -> bytes:
    """Reconstruct one opaque root from two distinct private shares."""

    if not isinstance(shares, (tuple, list)) or len(shares) != 2:
        raise ValueError("Tinker account binding requires exactly two private shares")
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or not 1 <= chain_id < 2**256:
        raise ValueError("Tinker account binding chain id must be a nonzero uint256")
    ordered = sorted(
        _private_share(share, f"Tinker account binding share[{index}]")
        for index, share in enumerate(shares)
    )
    if ordered[0] == ordered[1]:
        raise ValueError("Tinker account binding shares must be distinct")
    info = chain_id.to_bytes(32, "big") + TINKER_PROVIDER_NAMESPACE
    return _hkdf_sha256(
        b"".join(ordered),
        TINKER_ACCOUNT_BINDING_ROOT_HKDF_SALT,
        info,
        32,
    )


def derive_tinker_account_commitment(
    binding_root: bytes | str,
    *,
    chain_id: int = TINKER_ACCOUNT_BINDING_CHAIN_ID,
) -> str:
    """Return the exact public EVM bytes32 commitment for ``binding_root``."""

    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or not 1 <= chain_id < 2**256:
        raise ValueError("Tinker account binding chain id must be a nonzero uint256")
    encoded = b"".join(
        (
            TINKER_ACCOUNT_BINDING_TYPEHASH,
            chain_id.to_bytes(32, "big"),
            TINKER_PROVIDER_NAMESPACE,
            _binding_root(binding_root),
        )
    )
    return "0x" + keccak(encoded).hex()
