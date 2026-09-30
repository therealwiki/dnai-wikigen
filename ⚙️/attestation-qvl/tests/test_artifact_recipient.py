from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from attestation_qvl.challenge import qvl_profiles
from attestation_qvl.errors import VerificationRejected, VerifierUnavailable
from attestation_qvl.qvl import VerifiedQuote, derive_artifact_recipient_report_data
from attestation_qvl.signing import independent_verdict_digest
from tests.support import NOW, make_context, policy_payload, write_policy


def test_secondary_binding_preserves_primary_and_absent_policy_hash(tmp_path):
    original = write_policy(tmp_path / "original.json")
    assert "artifact_recipient_binding" not in json.loads(original.canonical_bytes)
    explicit_absence = policy_payload()
    explicit_absence["artifact_recipient_binding"] = None
    assert write_policy(tmp_path / "absent.json", explicit_absence).policy_hash == original.policy_hash
    enabled = write_policy(tmp_path / "enabled.json", policy_payload(artifact_recipient=True))
    assert enabled.policy_hash != original.policy_hash
    assert enabled.policy.report_data_binding.kind == "diligence_result_signer_v1"
    assert qvl_profiles(enabled.policy) == ("diligence", "artifact_recipient")


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(chain_id=1),
    lambda value: value.update(allowed_signer_addresses=[]),
    lambda value: value.update(allowed_signer_addresses=["0x" + "22" * 20, "0x" + "23" * 20]),
    lambda value: value.update(report_data_binding=policy_payload(arena=True)["report_data_binding"]),
    lambda value: value["artifact_recipient_binding"].update(kind="arena_candidate_ingress_v1"),
    lambda value: value["artifact_recipient_binding"].update(encryption_public_key="33" * 31),
    lambda value: value["artifact_recipient_binding"].update(key_id="sha256:" + "00" * 32),
    lambda value: value["artifact_recipient_binding"].update(
        encryption_public_key="00" * 32,
        key_id="sha256:" + hashlib.sha256(bytes(32)).hexdigest(),
    ),
    lambda value: value["artifact_recipient_binding"].update(unreviewed=True),
])
def test_artifact_policy_is_exact_diligence_only_and_key_bound(tmp_path, mutation):
    payload = policy_payload(artifact_recipient=True)
    mutation(payload)
    with pytest.raises(VerifierUnavailable):
        write_policy(tmp_path / "policy.json", payload)


@pytest.mark.asyncio
async def test_artifact_recipient_quote_produces_purpose_bound_v4_lease(tmp_path):
    context = make_context(tmp_path, artifact_recipient=True, max_verdict_ttl_seconds=900)
    binding = context.release.policy.artifact_recipient_binding
    expected = hashlib.sha256(json.dumps({
        "service": "tinker-delegate",
        "context": "artifact",
        "encryption_public_key": binding.encryption_public_key,
    }, sort_keys=True, separators=(",", ":")).encode()).digest()
    assert derive_artifact_recipient_report_data(binding) == expected
    assert context.backend.result.report_data == expected + bytes.fromhex(context.challenge.challenge_digest[2:])
    verdict = await context.verifier.verify(context.request())
    assert verdict.profile == "artifact_recipient"
    assert verdict.quote_hash == "0x" + hashlib.sha256(context.raw_quote).hexdigest()
    assert verdict.report_data == "0x" + expected.hex()
    assert verdict.expires_at == NOW + 900
    assert verdict.activation_evidence_lease_expires_at == verdict.expires_at
    assert Account.recover_message(
        encode_defunct(hexstr=independent_verdict_digest(verdict)),
        signature=verdict.verifier_signature,
    ).lower() == context.signer.address
    public = verdict.model_dump(mode="json", by_alias=True, exclude_none=True)
    assert not any(field.startswith("qvl_") for field in public)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", [
    "result_authorization", "compute_authorization",
    "royalty_authorization", "compute_workload_recipient",
])
async def test_artifact_profile_never_authorizes_other_operations(tmp_path, field):
    context = make_context(tmp_path, artifact_recipient=True)
    request = context.request().model_copy(update={field: object()})
    with pytest.raises(VerificationRejected):
        await context.verifier.verify(request)
    assert context.backend.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", ["diligence", "arena", "email_oracle_kms_restart"])
async def test_artifact_quote_cannot_be_relabelled_for_another_purpose(tmp_path, profile):
    context = make_context(tmp_path, artifact_recipient=True)
    payload = deepcopy(context.request_payload)
    payload["challenge"]["profile"] = profile
    with pytest.raises(VerificationRejected):
        await context.verifier.verify(context.request(payload))
    assert context.backend.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("suffix", [b"", bytes(32), bytes.fromhex("cd" * 32), bytes(33)])
async def test_artifact_quote_requires_exact_static_digest_and_challenge(tmp_path, suffix):
    context = make_context(tmp_path, artifact_recipient=True)
    context.backend.result = VerifiedQuote(
        quote_type="TDX", status="OK",
        report_data=context.report_data + suffix,
        measurements=context.backend.result.measurements,
    )
    with pytest.raises(VerificationRejected):
        await context.verifier.verify(context.request())


@pytest.mark.asyncio
async def test_artifact_recipient_challenge_requires_explicit_policy_and_main_domain(tmp_path):
    context = make_context(tmp_path)
    with pytest.raises(VerificationRejected):
        await context.challenge_store.issue(context.challenge_request.model_copy(update={"profile": "artifact_recipient"}))
    context = make_context(tmp_path, artifact_recipient=True)
    with pytest.raises(VerificationRejected):
        await context.challenge_store.issue(context.challenge_request.model_copy(update={"domain": "independent_metering_cvm"}))
    challenge = await context.challenge_store.issue(context.challenge_request)
    assert challenge.profile == "artifact_recipient"
    assert challenge.expires_at - challenge.issued_at <= 120
