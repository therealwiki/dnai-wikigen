from __future__ import annotations

from copy import deepcopy

import pytest
from eth_account import Account

from compute_metering.errors import UsageRejected
from compute_metering.models import ComputeUsageEnvelope, MeteringRequest
from compute_metering.usage import (
    compute_usage_commitment,
    semantic_request_hash,
    verify_usage_envelope,
)
from tests.support import (
    PINNED_HASH,
    TEE,
    make_context,
    sign_usage_payload,
    unsigned_usage_payload,
)


def test_usage_commitment_and_eip191_signature_authenticate_exact_tee(tmp_path):
    context = make_context(tmp_path)
    try:
        usage = context.request.usage
        assert compute_usage_commitment(usage) == usage.usage_commitment
        verify_usage_envelope(usage, expected_tee_identity=TEE)
    finally:
        context.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("prefill_tokens", "999999"),
        ("sample_tokens", "499999"),
        ("training_tokens", "1"),
        ("usage_observed_at", 1_799_999_969),
        ("model", "other-model"),
        ("recipe", "training.v1"),
        ("outcome", "failed"),
        ("authorization_nonce", "8"),
        ("max_asset_debit", "999"),
        ("raw_secret_egress", False),
    ],
)
def test_any_signed_claim_mutation_without_resigning_is_rejected(tmp_path, field, value):
    context = make_context(tmp_path)
    try:
        payload = context.request.usage.model_dump(mode="json", by_alias=True)
        if field == "raw_secret_egress":
            payload["project_id"] = "0x" + "98" * 32
        else:
            payload[field] = value
        mutated = ComputeUsageEnvelope.model_validate(payload, strict=True)
        with pytest.raises(UsageRejected):
            verify_usage_envelope(mutated, expected_tee_identity=TEE)
    finally:
        context.close()


def test_wrong_signer_wrong_expected_identity_and_noncanonical_signature_fail(tmp_path):
    context = make_context(tmp_path)
    try:
        base = unsigned_usage_payload(context.release)
        wrong = sign_usage_payload(base, account=Account.from_key(bytes.fromhex("99" * 32)))
        with pytest.raises(UsageRejected):
            verify_usage_envelope(
                ComputeUsageEnvelope.model_validate(wrong, strict=True),
                expected_tee_identity=TEE,
            )

        with pytest.raises(UsageRejected):
            verify_usage_envelope(context.request.usage, expected_tee_identity="0x" + "88" * 20)

        bad_v = context.request.usage.model_copy(update={"tee_signature": context.request.usage.tee_signature[:-2] + "00"})
        with pytest.raises(UsageRejected):
            verify_usage_envelope(bad_v, expected_tee_identity=TEE)

        raw = bytearray(bytes.fromhex(context.request.usage.tee_signature[2:]))
        raw[32:64] = (2**256 - 1).to_bytes(32, "big")
        high_s = context.request.usage.model_copy(update={"tee_signature": "0x" + raw.hex()})
        with pytest.raises(UsageRejected):
            verify_usage_envelope(high_s, expected_tee_identity=TEE)
    finally:
        context.close()


def test_zero_usage_failure_is_valid_but_zero_usage_success_is_not(tmp_path):
    context = make_context(tmp_path)
    try:
        failed = sign_usage_payload(
            unsigned_usage_payload(
                context.release,
                outcome="failed",
                prefill_tokens="0",
                sample_tokens="0",
                training_tokens="0",
            )
        )
        usage = ComputeUsageEnvelope.model_validate(failed, strict=True)
        verify_usage_envelope(usage, expected_tee_identity=TEE)

        success = dict(failed)
        success["outcome"] = "succeeded"
        with pytest.raises(Exception):
            ComputeUsageEnvelope.model_validate(success, strict=True)
    finally:
        context.close()


def test_semantic_request_hash_excludes_only_signature(tmp_path):
    context = make_context(tmp_path)
    try:
        original = context.request
        alternate_signature = original.usage.tee_signature[:-2] + ("1c" if original.usage.tee_signature[-2:] == "1b" else "1b")
        changed_signature = original.model_copy(
            update={"usage": original.usage.model_copy(update={"tee_signature": alternate_signature})}
        )
        assert semantic_request_hash(original) == semantic_request_hash(changed_signature)

        changed_block = original.model_copy(
            update={"block": original.block.model_copy(update={"hash": "0x" + "99" * 32})}
        )
        assert semantic_request_hash(original) != semantic_request_hash(changed_block)

        changed_commitment = original.model_copy(
            update={"usage": original.usage.model_copy(update={"usage_commitment": "0x" + "77" * 32})}
        )
        assert semantic_request_hash(original) != semantic_request_hash(changed_commitment)
    finally:
        context.close()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update({"unexpected": True}),
        lambda p: p.update({"prefill_tokens": 1}),
        lambda p: p.update({"prefill_tokens": "01"}),
        lambda p: p.update({"tee_identity": str(p["tee_identity"]).upper()}),
        lambda p: p.update({"usage_commitment": "0x" + "00" * 32}),
        lambda p: p.update({"raw_secret_egress": True}),
    ],
)
def test_usage_wire_schema_is_strict(tmp_path, mutation):
    context = make_context(tmp_path)
    try:
        payload = deepcopy(context.request.usage.model_dump(mode="json", by_alias=True))
        mutation(payload)
        with pytest.raises(Exception):
            ComputeUsageEnvelope.model_validate(payload, strict=True)
    finally:
        context.close()
