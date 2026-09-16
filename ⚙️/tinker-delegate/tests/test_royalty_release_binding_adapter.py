from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tinker_delegate.collaboration_execution_service import (
    royalty_release_binding_commitment,
)
from tinker_delegate.royalty_release_binding_adapter import (
    RoyaltyReleaseBindingAdapterError,
    royalty_release_binding_from_adapter_receipt,
    runtime_binding_commitment,
    source_binding_sha256,
)
from tinker_delegate.royalty_settlement_authorization import (
    derive_royalty_qvl_policy_commitment,
)


VECTOR_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "royalty_release_binding_adapter_v1.json"
)
VECTOR = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def test_frozen_js_to_python_royalty_runtime_binding_kat() -> None:
    assert VECTOR["schema"] == (
        "dnai.royalty-settlement-runtime-binding-adapter-known-answer.v1"
    )
    assert VECTOR["truth_status"] == (
        "synthetic_cross_language_known_answer_never_live_release_authority"
    )
    receipt = VECTOR["adapter_receipt"]
    binding = royalty_release_binding_from_adapter_receipt(receipt)
    assert source_binding_sha256(receipt["source_binding"]) == (
        "sha256:ac2afcc6e72d81cb9dd107ed683e7ee65d380bbc5cccb89b852338a26933748b"
    )
    assert runtime_binding_commitment(receipt["runtime_binding"]) == (
        "sha256:1963adbf72508148a6c0e8795b398b8195b5ee62cc638f67509f4ad4c0c53f63"
    )
    assert royalty_release_binding_commitment(binding) == (
        receipt["runtime_binding_commitment"]
    )
    assert derive_royalty_qvl_policy_commitment(binding) == (
        "0xac84767f084ec979b282d1ccf07fd3e1807a3d20d373852f24df474bf1273797"
    )
    assert binding.release_authority_sha256 == (
        receipt["source_binding"]["final_release_authority_v4_sha256"]
    )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value.update(
                source_binding_sha256="sha256:" + "ef" * 32
            ),
            "source-binding digest",
        ),
        (
            lambda value: value["reconciliation_receipt"].update(
                royalty_release_history_receipt_sha256="sha256:" + "ed" * 32
            ),
            "does not bind the JavaScript source",
        ),
        (
            lambda value: value["runtime_binding"].update(
                owner_address="0x" + "fe" * 20
            ),
            "owner_address differs",
        ),
        (
            lambda value: value["runtime_binding"].update(
                royalty_qvl_policy_commitment="0x" + "ec" * 32
            ),
            "runtime binding is invalid",
        ),
        (
            lambda value: value.update(unreviewed=True),
            "fields do not match",
        ),
    ],
)
def test_adapter_fails_closed_on_cross_language_drift(mutate, message: str) -> None:
    value = copy.deepcopy(VECTOR["adapter_receipt"])
    mutate(value)
    with pytest.raises(RoyaltyReleaseBindingAdapterError, match=message):
        royalty_release_binding_from_adapter_receipt(value)
