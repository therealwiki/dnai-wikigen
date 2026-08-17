from __future__ import annotations

import asyncio

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from attestation_qvl.challenge import (
    OneTimeChallengeStore,
    challenge_digest,
    qvl_profiles,
)
from attestation_qvl.errors import CapacityExceeded, VerificationRejected
from tests.support import NOW, make_context


@pytest.mark.asyncio
async def test_issued_challenge_is_signed_policy_and_profile_scoped(tmp_path):
    context = make_context(tmp_path)

    challenge = await context.challenge_store.issue(context.challenge_request)

    assert challenge.profile == "diligence"
    assert challenge.release_policy_hash == context.release.policy_hash
    assert challenge.issued_at == NOW
    assert challenge.expires_at == NOW + 60
    assert challenge.challenge_digest == challenge_digest(challenge)
    recovered = Account.recover_message(
        encode_defunct(hexstr=challenge.challenge_digest),
        signature=challenge.verifier_signature,
    )
    assert recovered.lower() == context.signer.address


@pytest.mark.parametrize("compute_metering", [False, True])
@pytest.mark.asyncio
async def test_challenge_issue_enforces_profile_target_domain(
    tmp_path,
    compute_metering,
):
    context = make_context(tmp_path, compute_metering=compute_metering)
    wrong_domain = (
        "main_runtime_cvm"
        if compute_metering
        else "independent_metering_cvm"
    )
    with pytest.raises(VerificationRejected):
        await context.challenge_store.issue(
            context.challenge_request.model_copy(
                update={"domain": wrong_domain}
            )
        )
    issued = await context.challenge_store.issue(context.challenge_request)
    assert issued.domain == context.challenge_request.domain


@pytest.mark.asyncio
async def test_reservation_is_atomic_single_use_under_concurrency(tmp_path):
    context = make_context(tmp_path)
    challenge = await context.challenge_store.issue(context.challenge_request)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def first_user() -> None:
        async with context.challenge_store.reserve(challenge):
            entered.set()
            await release.wait()

    task = asyncio.create_task(first_user())
    await entered.wait()
    with pytest.raises(VerificationRejected):
        async with context.challenge_store.reserve(challenge):
            pass
    release.set()
    await task

    assert await context.challenge_store.state(challenge.challenge_id) == "consumed"
    with pytest.raises(VerificationRejected):
        async with context.challenge_store.reserve(challenge):
            pass


@pytest.mark.asyncio
async def test_expired_challenge_is_pruned_and_cannot_be_reserved(tmp_path):
    context = make_context(tmp_path)
    clock = [NOW]
    context.challenge_store._clock = lambda: clock[0]
    challenge = await context.challenge_store.issue(context.challenge_request)
    clock[0] = challenge.expires_at

    with pytest.raises(VerificationRejected):
        async with context.challenge_store.reserve(challenge):
            pass
    assert await context.challenge_store.state(challenge.challenge_id) is None


@pytest.mark.asyncio
async def test_wrong_profile_policy_digest_or_signature_never_reserves(tmp_path):
    context = make_context(tmp_path)
    challenge = await context.challenge_store.issue(context.challenge_request)
    variants = (
        challenge.model_copy(update={"profile": "arena"}),
        challenge.model_copy(update={"release_policy_hash": "0x" + "12" * 32}),
        challenge.model_copy(update={"challenge_digest": "0x" + "34" * 32}),
        challenge.model_copy(update={"verifier_signature": "0x" + "56" * 65}),
        challenge.model_copy(update={"domain": "independent_metering_cvm"}),
        challenge.model_copy(update={"cvm_id": "cvm-cross-domain-0001"}),
        challenge.model_copy(update={"release_authority_sha256": "sha256:" + "57" * 32}),
    )

    for variant in variants:
        with pytest.raises(VerificationRejected):
            async with context.challenge_store.reserve(variant):
                pass
        assert await context.challenge_store.state(challenge.challenge_id) == "fresh"

    async with context.challenge_store.reserve(challenge):
        pass
    assert await context.challenge_store.state(challenge.challenge_id) == "consumed"


@pytest.mark.asyncio
async def test_profile_admission_and_store_capacity_are_bounded(tmp_path):
    context = make_context(tmp_path)
    store = OneTimeChallengeStore(
        profiles=qvl_profiles(context.release.policy),
        policy_hash=context.release.policy_hash,
        signer=context.signer,
        ttl_seconds=60,
        maximum=1,
        clock=lambda: NOW,
        random_bytes=lambda size: bytes.fromhex("ef" * size),
    )

    with pytest.raises(VerificationRejected):
        await store.issue(context.challenge_request.model_copy(update={"profile": "arena"}))
    await store.issue(context.challenge_request)
    with pytest.raises(CapacityExceeded):
        await store.issue(context.challenge_request)
