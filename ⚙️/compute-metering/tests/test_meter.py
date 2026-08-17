from __future__ import annotations

import json

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from compute_metering.errors import (
    ChainStateRejected,
    PolicyRejected,
    ReplayConflict,
    UsageRejected,
)
from compute_metering.models import MeteringDecision
from compute_metering.chain import BaseSepoliaStateVerifier
from compute_metering.meter import ComputeMeter
from compute_metering.models import MeteringRequest
from tests.support import (
    FakeIdentityAttestor,
    FakeQvlClient,
    FakeRpc,
    METER,
    NOW,
    QVL,
    USDC,
    make_context,
    request_payload,
)
from compute_metering.usage import semantic_request_hash


@pytest.mark.asyncio
async def test_meter_commits_bounded_decision_then_exact_replay_skips_chain(tmp_path):
    context = make_context(tmp_path)
    try:
        first = await context.meter.meter(context.request)
        calls_after_first = context.rpc.chain_id_calls
        signatures_after_first = len(context.signer.digests)
        second = await context.meter.meter(context.request)
        assert second == first
        assert context.rpc.chain_id_calls == calls_after_first == 1
        assert len(context.signer.digests) == signatures_after_first == 1

        payload = json.loads(first)
        decision = MeteringDecision.model_validate(payload, strict=True)
        assert decision.classification == "attested_dual_verified_metering"
        assert decision.provider_authoritative_invoice is False
        assert decision.raw_secret_egress is False
        assert decision.actual_asset_debit == "750"
        assert not ({"prompt", "dataset", "output", "provider_secret"} & set(payload))
    finally:
        context.close()


@pytest.mark.asyncio
async def test_metering_signature_is_raw_eip712_not_eip191(tmp_path):
    context = make_context(tmp_path)
    try:
        encoded = await context.meter.meter(context.request)
        decision = MeteringDecision.model_validate(json.loads(encoded), strict=True)
        recovered_raw = Account._recover_hash(
            bytes.fromhex(decision.metering_receipt_digest[2:]),
            signature=bytes.fromhex(decision.verifier_signature[2:]),
        ).lower()
        recovered_prefixed = Account.recover_message(
            encode_defunct(hexstr=decision.metering_receipt_digest),
            signature=bytes.fromhex(decision.verifier_signature[2:]),
        ).lower()
        assert recovered_raw == METER
        assert recovered_prefixed != METER
    finally:
        context.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("boundary", "error_type"),
    [
        ("submission_window", ChainStateRejected),
        ("policy", PolicyRejected),
    ],
)
async def test_rpc_completion_crossing_freshness_boundary_is_not_signed_or_recorded(
    tmp_path,
    boundary,
    error_type,
):
    context = make_context(tmp_path)
    try:
        clock = [NOW]
        context.chain.clock = lambda: clock[0]
        original_block_by_hash = context.rpc.block_by_hash

        async def delayed_final_block(block_hash):
            result = await original_block_by_hash(block_hash)
            if boundary == "submission_window":
                receipt_expiry = min(
                    result.timestamp + context.release.policy.receipt_ttl_seconds,
                    context.request.usage.authorization_expiry,
                )
                clock[0] = (
                    receipt_expiry
                    - context.release.policy.min_submission_window_seconds
                    + 1
                )
            else:
                clock[0] = context.release.policy.valid_until + 1
            return result

        context.rpc.block_by_hash = delayed_final_block
        with pytest.raises(error_type):
            await context.meter.meter(context.request)
        assert context.signer.digests == []
        assert context.replay.lookup(
            job_id=context.request.usage.job_id,
            usage_commitment=context.request.usage.usage_commitment,
            request_hash=semantic_request_hash(context.request),
        ) is None
    finally:
        context.close()


@pytest.mark.asyncio
async def test_execution_signature_is_authenticated_before_replay_lookup(tmp_path):
    context = make_context(tmp_path)
    try:
        await context.meter.meter(context.request)
        bad = context.request.model_copy(
            update={
                "usage": context.request.usage.model_copy(
                    update={"tee_signature": context.request.usage.tee_signature[:-2] + "00"}
                )
            }
        )
        with pytest.raises(UsageRejected):
            await context.meter.meter(bad)
        assert context.rpc.chain_id_calls == 1
    finally:
        context.close()


@pytest.mark.asyncio
async def test_same_job_with_new_valid_usage_context_is_replay_conflict(tmp_path):
    context = make_context(tmp_path)
    try:
        await context.meter.meter(context.request)
        from tests.support import sign_usage_payload

        changed_payload = context.request.usage.model_dump(mode="json", by_alias=True)
        changed_payload["prefill_tokens"] = "999999"
        changed = context.request.model_copy(
            update={
                "usage": context.request.usage.model_validate(
                    sign_usage_payload(changed_payload), strict=True
                )
            }
        )
        with pytest.raises(ReplayConflict):
            await context.meter.meter(changed)
    finally:
        context.close()


@pytest.mark.asyncio
async def test_one_policy_set_and_one_signer_meter_both_native_and_usdc(tmp_path):
    context = make_context(tmp_path)
    try:
        usdc_request = MeteringRequest.model_validate(
            request_payload(context.release, asset=USDC), strict=True
        )
        usdc_rpc = FakeRpc(context.release, usdc_request.usage)
        usdc_chain = BaseSepoliaStateVerifier(
            release=context.release,
            rpc=usdc_rpc,
            metering_verifier=context.signer.address,
            metering_qvl_verifier=QVL,
            clock=lambda: NOW,
        )
        meter = ComputeMeter(
            release=context.release,
            signer=context.signer,
            chain=usdc_chain,
            replay=context.replay,
            identity_attestor=FakeIdentityAttestor(),
            qvl_client=FakeQvlClient(),  # type: ignore[arg-type]
        )
        decision = MeteringDecision.model_validate(
            json.loads(await meter.meter(usdc_request)), strict=True
        )
        assert decision.asset == USDC
        assert decision.metering_verifier == METER
        assert decision.policy_set_hash == context.release.policy_set_hash
        assert decision.rate_policy_commitment == usdc_request.usage.rate_policy_commitment
    finally:
        context.close()
