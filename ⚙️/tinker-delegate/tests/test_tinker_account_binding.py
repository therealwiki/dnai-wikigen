from __future__ import annotations

import pytest

from tinker_delegate.tinker_account_binding import (
    TINKER_ACCOUNT_BINDING_CHAIN_ID,
    TINKER_ACCOUNT_BINDING_SCHEMA,
    TINKER_ACCOUNT_BINDING_TYPE,
    TINKER_ACCOUNT_BINDING_TYPEHASH,
    TINKER_ACCOUNT_BINDING_ROOT_HKDF_SALT,
    TINKER_PROVIDER_NAMESPACE,
    TINKER_PROVIDER_NAMESPACE_LABEL,
    derive_tinker_account_binding_root,
    derive_tinker_account_commitment,
)


ROOT_ONE = "0x" + "00" * 31 + "01"


def test_tinker_account_binding_constants_freeze_the_exact_provider_domain() -> None:
    assert TINKER_ACCOUNT_BINDING_SCHEMA == "dnai.tinker-account-binding.v1"
    assert TINKER_ACCOUNT_BINDING_TYPE == (
        "DnaiTinkerAccountBindingV1(uint256 chainId,bytes32 providerNamespace,bytes32 bindingRoot)"
    )
    assert TINKER_PROVIDER_NAMESPACE_LABEL == "thinking-machines/tinker"
    assert TINKER_ACCOUNT_BINDING_CHAIN_ID == 84_532
    assert TINKER_ACCOUNT_BINDING_ROOT_HKDF_SALT == b"dnai-wikigen/tinker-account-binding/v1"
    assert len(TINKER_ACCOUNT_BINDING_TYPEHASH) == 32
    assert len(TINKER_PROVIDER_NAMESPACE) == 32


def test_tinker_account_binding_has_one_frozen_cross_language_known_answer() -> None:
    assert derive_tinker_account_commitment(ROOT_ONE) == (
        "0xa5c3b464917302dc58881695681975aea0bfbac6d3ebc3c7aab27854c64130d9"
    )


def test_tinker_account_binding_root_requires_two_shares_and_ignores_order() -> None:
    first = b"\x11" * 32
    second = b"\x22" * 32
    root = derive_tinker_account_binding_root([first, second])
    assert len(root) == 32
    assert root != b"\x00" * 32
    assert root == derive_tinker_account_binding_root([second, first])
    assert derive_tinker_account_commitment(root) == (
        "0x30f8a29b35be70acdb3eb4f513dc60f3f1bdc3c62aa5dbd3d53738a824eb04c8"
    )


def test_tinker_account_binding_is_separated_by_root_and_chain() -> None:
    root_two = "0x" + "00" * 31 + "02"
    assert derive_tinker_account_commitment(ROOT_ONE) != derive_tinker_account_commitment(root_two)
    assert derive_tinker_account_commitment(ROOT_ONE) != derive_tinker_account_commitment(
        ROOT_ONE, chain_id=1
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "0x" + "00" * 32,
        "0X" + "11" * 32,
        "0x" + "AA" * 32,
        "0x" + "11" * 31,
        b"\x01" * 31,
        b"\x00" * 32,
    ],
)
def test_tinker_account_binding_rejects_invalid_roots(value: bytes | str) -> None:
    with pytest.raises(ValueError, match="binding root"):
        derive_tinker_account_commitment(value)


@pytest.mark.parametrize("chain_id", [0, -1, True, 2**256])
def test_tinker_account_binding_rejects_invalid_chain_ids(chain_id: int) -> None:
    with pytest.raises(ValueError, match="chain id"):
        derive_tinker_account_commitment(ROOT_ONE, chain_id=chain_id)


def test_tinker_account_binding_root_rejects_invalid_share_sets() -> None:
    with pytest.raises(ValueError, match="exactly two"):
        derive_tinker_account_binding_root([])
    with pytest.raises(ValueError, match="distinct"):
        derive_tinker_account_binding_root([b"\x01" * 32, b"\x01" * 32])
    with pytest.raises(ValueError, match=r"share\[0\]"):
        derive_tinker_account_binding_root([b"\x01" * 31, b"\x02" * 32])
    with pytest.raises(ValueError, match=r"share\[0\]"):
        derive_tinker_account_binding_root(["0x" + "11" * 32, b"\x22" * 32])  # type: ignore[list-item]
