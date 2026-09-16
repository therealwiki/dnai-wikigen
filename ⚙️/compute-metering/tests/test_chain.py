from __future__ import annotations

from dataclasses import replace

import pytest

from compute_metering.chain import compute_exact_debit
from compute_metering.errors import ChainStateRejected, PolicyRejected
from compute_metering.models import ComputeUsageEnvelope, UINT256_MAX
from compute_metering.rpc import BlockSnapshot
from tests.support import (
    ATTESTATION_EVIDENCE_HASH,
    COMPOSE_HASH,
    METER,
    NOW,
    PINNED_HASH,
    PINNED_NUMBER,
    PROVIDER,
    USDC,
    FakeRpc,
    FakeMeteringSigner,
    make_context,
    request_payload,
    sign_usage_payload,
    unsigned_usage_payload,
)


async def _verify(context, *, usage=None, receipt_expiry_cap=NOW + 120):
    return await context.chain.verify(
        block=context.request.block,
        usage=usage or context.request.usage,
        attestation_evidence_hash=ATTESTATION_EVIDENCE_HASH,
        receipt_expiry_cap=receipt_expiry_cap,
    )


@pytest.mark.asyncio
async def test_valid_snapshot_recomputes_debit_and_compares_onchain_digest(tmp_path):
    context = make_context(tmp_path)
    try:
        result = await _verify(context)
        assert result.actual_asset_debit == 750
        assert result.receipt_expiry == NOW + 120
        assert result.metering_receipt_digest.startswith("0x")
        assert context.rpc.code_blocks == [PINNED_HASH]
        assert set(context.rpc.eth_call_blocks) == {PINNED_HASH}
        assert context.rpc.number_calls == 2
    finally:
        context.close()


@pytest.mark.parametrize(
    ("prefill", "sample", "training", "expected"),
    [
        ("0", "0", "0", 0),
        ("1", "0", "0", 1),
        ("4000", "0", "0", 1),
        ("4001", "0", "0", 2),
        ("1000000", "500000", "0", 750),
        ("0", "0", "100000", 500),
    ],
)
def test_exact_debit_uses_checked_integer_ceiling(tmp_path, prefill, sample, training, expected):
    context = make_context(tmp_path)
    try:
        payload = unsigned_usage_payload(
            context.release,
            outcome="failed" if (prefill, sample, training) == ("0", "0", "0") else "succeeded",
            prefill_tokens=prefill,
            sample_tokens=sample,
            training_tokens=training,
        )
        usage = ComputeUsageEnvelope.model_validate(sign_usage_payload(payload), strict=True)
        assert compute_exact_debit(context.release.policy.asset_policies[0], usage) == expected
    finally:
        context.close()


def test_debit_enforces_counter_policy_and_total_cap(tmp_path):
    context = make_context(tmp_path)
    try:
        too_many = ComputeUsageEnvelope.model_validate(
            sign_usage_payload(unsigned_usage_payload(context.release, prefill_tokens="10000001")),
            strict=True,
        )
        with pytest.raises(ChainStateRejected):
            compute_exact_debit(context.release.policy.asset_policies[0], too_many)

        over_total = ComputeUsageEnvelope.model_validate(
            sign_usage_payload(unsigned_usage_payload(context.release, training_tokens="1000000")),
            strict=True,
        )
        with pytest.raises(ChainStateRejected):
            compute_exact_debit(context.release.policy.asset_policies[0], over_total)

        unknown = ComputeUsageEnvelope.model_validate(
            sign_usage_payload(unsigned_usage_payload(context.release, model="unknown-model")),
            strict=True,
        )
        with pytest.raises(ChainStateRejected):
            compute_exact_debit(context.release.policy.asset_policies[0], unknown)
    finally:
        context.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("code", b"\x60\x00"),
        ("owner", "0x" + "91" * 20),
        ("developer", "0x" + "92" * 20),
        ("metering", "0x" + "93" * 20),
        ("metering_qvl", "0x" + "94" * 20),
        ("metering_policy_set_hash", "0x" + "93" * 32),
        ("metering_binding_frozen", False),
        ("pending_metering_verifier", "0x" + "93" * 20),
        ("pending_metering_qvl_verifier", "0x" + "94" * 20),
        ("pending_metering_policy_set_hash", "0x" + "93" * 32),
        ("pending_metering_binding_activates_at", 1),
        ("paused", True),
        ("fee", 501),
        ("fee_frozen", False),
        ("rate_frozen", False),
        ("asset_frozen", False),
        ("compose_frozen", False),
        ("tee_identity_additions_frozen", False),
        ("allowed_asset_count", 2),
        ("active_rate_policy_count", 3),
        ("approved_compose_count", 2),
        ("approved_tee_identity_count", 2),
        ("pending_asset_count", 1),
        ("pending_rate_policy_count", 1),
        ("pending_compose_count", 1),
        ("pending_tee_identity_count", 1),
        ("pending_developer_fee_activates_at", 1),
        ("compose_approved", False),
        ("tee_compose", "0x" + "94" * 32),
        ("rate", ("0x" + "95" * 20, PROVIDER, 500, True)),
        ("rate", ("0x" + "00" * 20, "0x" + "96" * 20, 500, True)),
        ("rate", ("0x" + "00" * 20, PROVIDER, 501, True)),
        ("rate", ("0x" + "00" * 20, PROVIDER, 500, False)),
        ("digest", "0x" + "97" * 32),
        ("qvl_digest", "0x" + "96" * 32),
        ("usage_digest", "0x" + "95" * 32),
    ],
)
async def test_any_release_root_or_digest_mismatch_fails_closed(tmp_path, key, value):
    context = make_context(tmp_path)
    try:
        context.rpc.state[key] = value
        with pytest.raises(ChainStateRejected):
            await _verify(context)
    finally:
        context.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("index", list(range(21)))
async def test_every_job_field_is_bound(index, tmp_path):
    context = make_context(tmp_path)
    try:
        job = list(context.rpc._job_values())
        replacements: list[object] = [
            bytes.fromhex("98" * 32),
            "0x" + "98" * 20,
            "0x" + "98" * 20,
            8,
            999,
            1,
            NOW + 601,
            NOW - 61,
            1,
            1,
            bytes.fromhex("98" * 32),
            bytes.fromhex("98" * 32),
            bytes.fromhex("98" * 32),
            bytes.fromhex("98" * 32),
            bytes.fromhex("98" * 32),
            bytes.fromhex("98" * 32),
            bytes.fromhex("98" * 32),
            bytes.fromhex("98" * 32),
            1,
            "0x" + "98" * 20,
            3,
        ]
        job[index] = replacements[index]
        context.rpc.state["job"] = tuple(job)
        with pytest.raises(ChainStateRejected):
            await _verify(context)
    finally:
        context.close()


@pytest.mark.asyncio
async def test_chain_id_block_hash_confirmations_and_freshness_are_pinned(tmp_path):
    context = make_context(tmp_path)
    try:
        context.rpc.chain_id_value = 8453
        with pytest.raises(ChainStateRejected):
            await _verify(context)

        context.rpc.chain_id_value = 84532
        context.rpc.pinned = replace(context.rpc.pinned, hash="0x" + "99" * 32)
        with pytest.raises(ChainStateRejected):
            await _verify(context)

        context.rpc.pinned = BlockSnapshot(PINNED_NUMBER, PINNED_HASH, NOW - 20)
        context.rpc.latest = BlockSnapshot(PINNED_NUMBER + 1, "0x" + "88" * 32, NOW)
        with pytest.raises(ChainStateRejected):
            await _verify(context)

        context.rpc.latest = BlockSnapshot(PINNED_NUMBER + 2, "0x" + "88" * 32, NOW)
        context.rpc.pinned = BlockSnapshot(PINNED_NUMBER, PINNED_HASH, NOW - 301)
        with pytest.raises(ChainStateRejected):
            await _verify(context)
    finally:
        context.close()


@pytest.mark.asyncio
async def test_policy_time_usage_time_submission_window_and_reorg_rechecks_fail_closed(tmp_path):
    context = make_context(tmp_path)
    try:
        context.chain.clock = lambda: NOW + 4000
        with pytest.raises(PolicyRejected):
            await _verify(context, receipt_expiry_cap=NOW + 4100)

        context.chain.clock = lambda: NOW
        future_usage = context.request.usage.model_copy(update={"usage_observed_at": NOW + 31})
        with pytest.raises(ChainStateRejected):
            await _verify(context, usage=future_usage)

        context.rpc.final_number_block = BlockSnapshot(PINNED_NUMBER, "0x" + "77" * 32, NOW - 20)
        with pytest.raises(ChainStateRejected):
            await _verify(context)

        context.rpc.final_number_block = None
        context.rpc.final_hash_block = BlockSnapshot(PINNED_NUMBER + 1, PINNED_HASH, NOW - 20)
        with pytest.raises(ChainStateRejected):
            await _verify(context)
    finally:
        context.close()


@pytest.mark.asyncio
async def test_same_immutable_signer_strictly_selects_native_or_usdc_from_onchain_job(tmp_path):
    context = make_context(tmp_path)
    try:
        from compute_metering.models import MeteringRequest
        from compute_metering.chain import BaseSepoliaStateVerifier

        usdc_request = MeteringRequest.model_validate(
            request_payload(context.release, asset=USDC), strict=True
        )
        rpc = FakeRpc(context.release, usdc_request.usage)
        signer = FakeMeteringSigner()
        verifier = BaseSepoliaStateVerifier(
            release=context.release,
            rpc=rpc,
            metering_verifier=signer.address,
            metering_qvl_verifier=context.release.policy.metering_qvl_verifier,
            clock=lambda: NOW,
        )
        result = await verifier.verify(
            block=usdc_request.block,
            usage=usdc_request.usage,
            attestation_evidence_hash=ATTESTATION_EVIDENCE_HASH,
            receipt_expiry_cap=NOW + 120,
        )
        assert result.asset == USDC
        assert result.rate_policy_commitment == usdc_request.usage.rate_policy_commitment
        assert signer.address == METER

        job = list(rpc._job_values())
        job[2] = "0x" + "99" * 20
        job[10] = bytes.fromhex("99" * 32)
        rpc.state["job"] = tuple(job)
        with pytest.raises(ChainStateRejected):
            await verifier.verify(
                block=usdc_request.block,
                usage=usdc_request.usage,
                attestation_evidence_hash=ATTESTATION_EVIDENCE_HASH,
                receipt_expiry_cap=NOW + 120,
            )
    finally:
        context.close()
