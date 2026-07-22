from __future__ import annotations

from copy import deepcopy

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from attestation_qvl.errors import VerificationRejected
from attestation_qvl.qvl import (
    VerifiedQuote,
    derive_compute_metering_attestation_evidence_hash,
    derive_compute_metering_report_data,
    derive_compute_workload_recipient_report_data,
    derive_email_oracle_kms_restart_report_data,
    derive_signer_report_data,
)
from attestation_qvl.signing import (
    compute_metering_qvl_authorization_digest,
    diligence_qvl_result_authorization_digest,
    independent_verdict_digest,
)
from tests.support import (
    APP_ID,
    COMPOSE_HASH,
    CONTRACT,
    NOW,
    OS_IMAGE_HASH,
    SIGNER_ADDRESS,
    WORKLOAD_RECIPIENT_KEY_ID,
    make_context,
    measurement_bytes,
    policy_payload,
    write_policy,
)


@pytest.mark.asyncio
async def test_valid_quote_produces_exact_bounded_eip191_verdict(tmp_path):
    context = make_context(tmp_path)

    verdict = await context.verifier.verify(context.request())
    public = verdict.model_dump(mode="json", by_alias=True, exclude_none=True)

    assert set(public) == {
        "schema", "verification_method", "verified", "quote_hash", "report_data",
        "compose_hash", "app_id", "os_image_hash", "signer_address", "chain_id",
        "contract_address", "issued_at",
        "activation_evidence_lease_expires_at", "expires_at", "verifier_address",
        "verifier_signature", "profile", "release_policy_hash", "challenge_id",
        "challenge_digest", "challenge_issued_at", "challenge_expires_at",
        "domain", "cvm_id", "deployment_intent_sha256",
        "release_authority_sha256", "ceremony_nonce", "measurement_policy_sha256",
    }
    assert public["schema"] == "dnai.independent-tdx-verdict.v4"
    assert public["verification_method"] == "intel_tdx_dcap_qvl"
    assert public["verified"] is True
    assert public["compose_hash"] == COMPOSE_HASH
    assert public["app_id"] == APP_ID
    assert public["os_image_hash"] == OS_IMAGE_HASH
    assert public["signer_address"] == SIGNER_ADDRESS
    assert public["chain_id"] == 84_532
    assert public["contract_address"] == CONTRACT
    assert public["domain"] == context.challenge.domain
    assert public["cvm_id"] == context.challenge.cvm_id
    assert public["release_authority_sha256"] == context.challenge.release_authority_sha256
    assert public["issued_at"] == NOW
    assert public["expires_at"] == NOW + 300
    assert public["activation_evidence_lease_expires_at"] == public["expires_at"]
    assert public["expires_at"] > context.challenge.expires_at
    assert context.backend.calls == [context.raw_quote]
    assert len(context.signer.digests) == 2
    digest = independent_verdict_digest(verdict)
    assert context.signer.digests[-1] == digest
    recovered = Account.recover_message(
        encode_defunct(hexstr=digest),
        signature=public["verifier_signature"],
    )
    assert recovered.lower() == context.signer.address
    rendered = str(public)
    assert context.request_payload["quote"] not in rendered
    assert "raw_secret_egress" not in public


@pytest.mark.asyncio
async def test_diligence_qvl_signs_exact_bounded_settlement_context(tmp_path):
    context = make_context(tmp_path)
    payload = deepcopy(context.request_payload)
    payload["result_authorization"] = {
        "schema": "dnai.diligence-qvl-result-authorization-request.v1",
        "deal_id": 17,
        "evaluator_policy_commitment": "0x" + "bb" * 32,
        "result_hash": "0x" + "cc" * 32,
        "authorization_expiry": NOW + 30,
    }

    verdict = await context.verifier.verify(context.request(payload))
    public = verdict.model_dump(mode="json", by_alias=True, exclude_none=True)
    expected_digest = diligence_qvl_result_authorization_digest(
        chain_id=84_532,
        contract_address=CONTRACT,
        deal_id=17,
        tee_identity=SIGNER_ADDRESS,
        compose_hash=COMPOSE_HASH,
        evaluator_policy_commitment="0x" + "bb" * 32,
        result_hash="0x" + "cc" * 32,
        attestation_release_policy_hash=context.release.policy_hash,
        attestation_evidence_hash=public["quote_hash"],
        authorization_expiry=NOW + 30,
    )

    assert public["qvl_deal_id"] == 17
    assert public["qvl_attestation_evidence_hash"] == public["quote_hash"]
    assert public["qvl_authorization_digest"] == expected_digest
    assert context.signer.digests[-2:] == [
        expected_digest,
        independent_verdict_digest(verdict),
    ]
    assert (
        Account.recover_message(
            encode_defunct(hexstr=expected_digest),
            signature=public["qvl_authorization_signature"],
        ).lower()
        == context.signer.address
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("authorization_expiry", [NOW, NOW + 61, NOW + 601])
async def test_diligence_qvl_rejects_stale_or_overbroad_settlement_expiry(
    tmp_path,
    authorization_expiry,
):
    context = make_context(tmp_path)
    payload = deepcopy(context.request_payload)
    payload["result_authorization"] = {
        "schema": "dnai.diligence-qvl-result-authorization-request.v1",
        "deal_id": 17,
        "evaluator_policy_commitment": "0x" + "bb" * 32,
        "result_hash": "0x" + "cc" * 32,
        "authorization_expiry": authorization_expiry,
    }

    with pytest.raises(VerificationRejected):
        await context.verifier.verify(context.request(payload))


@pytest.mark.asyncio
async def test_non_diligence_profile_cannot_request_settlement_signature(tmp_path):
    context = make_context(tmp_path, arena=True)
    payload = deepcopy(context.request_payload)
    payload["result_authorization"] = {
        "schema": "dnai.diligence-qvl-result-authorization-request.v1",
        "deal_id": 17,
        "evaluator_policy_commitment": "0x" + "bb" * 32,
        "result_hash": "0x" + "cc" * 32,
        "authorization_expiry": NOW + 30,
    }

    with pytest.raises(VerificationRejected):
        await context.verifier.verify(context.request(payload))
    assert context.backend.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("chain_id", 1),
        ("contract_address", "0x3333333333333333333333333333333333333333"),
        ("compose_hash", "0x" + "bb" * 32),
        ("app_id", "dd" * 20),
        ("os_image_hash", "ee" * 32),
        ("signer_address", "0x4444444444444444444444444444444444444444"),
        ("report_data", "0x" + "55" * 32),
        ("quote_report_data", "0x" + "66" * 64),
    ],
)
async def test_request_release_assertions_never_become_authority(tmp_path, field, value):
    context = make_context(tmp_path)
    payload = deepcopy(context.request_payload)
    payload["expectation"][field] = value

    with pytest.raises(VerificationRejected):
        await context.verifier.verify(context.request(payload))
    assert context.backend.calls == []
    assert context.signer.digests == [context.challenge.challenge_digest]


@pytest.mark.asyncio
async def test_quote_hash_and_size_are_recomputed_before_qvl(tmp_path):
    context = make_context(tmp_path)
    for field, value in (("quote_hash", "0x" + "77" * 32), ("quote_size", 2049)):
        payload = deepcopy(context.request_payload)
        payload["expectation"][field] = value
        with pytest.raises(VerificationRejected):
            await context.verifier.verify(context.request(payload))
    assert context.backend.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "report_data",
    [
        b"short",
        bytes.fromhex("11" * 32) + bytes(32),
        None,
    ],
)
async def test_report_data_requires_exact_digest_and_zero_padding(tmp_path, report_data):
    context = make_context(tmp_path)
    if report_data is None:
        report_data = context.report_data + bytes.fromhex("01" * 32)
    context.backend.result = VerifiedQuote(
        quote_type="TDX",
        status="OK",
        report_data=report_data,
        measurements=measurement_bytes(),
    )
    with pytest.raises(VerificationRejected):
        await context.verifier.verify(context.request())


@pytest.mark.asyncio
async def test_exact_measurement_map_rejects_mismatch_missing_and_extra(tmp_path):
    context = make_context(tmp_path)
    variants = []
    mismatched = measurement_bytes()
    mismatched["mr_td"] = bytes.fromhex("99" * 48)
    variants.append(mismatched)
    missing = measurement_bytes()
    missing.pop("rt_mr3")
    variants.append(missing)
    extra = measurement_bytes()
    extra["mr_service_td"] = bytes.fromhex("10" * 48)
    variants.append(extra)
    for measurements in variants:
        context.backend.result = VerifiedQuote(
            quote_type="TDX",
            status="OK",
            report_data=context.report_data + bytes(32),
            measurements=measurements,
        )
        with pytest.raises(VerificationRejected):
            await context.verifier.verify(context.request())


@pytest.mark.asyncio
async def test_debug_td_is_rejected_even_if_other_measurements_match(tmp_path):
    context = make_context(tmp_path)
    debug = measurement_bytes()
    debug["td_attributes"] = (1).to_bytes(8, "little")
    context.backend.result = VerifiedQuote(
        quote_type="TDX",
        status="OK",
        report_data=context.report_data + bytes(32),
        measurements=debug,
    )
    context.release.policy.measurements  # policy remains the independently pinned non-debug value
    with pytest.raises(VerificationRejected):
        await context.verifier.verify(context.request())


@pytest.mark.asyncio
@pytest.mark.parametrize(("quote_type", "status"), [("SGX", "OK"), ("TDX", "OUT_OF_DATE"), ("TDX", "TcbStatus.OK")])
async def test_only_tdx_and_exact_policy_tcb_status_are_accepted(tmp_path, quote_type, status):
    context = make_context(tmp_path)
    context.backend.result = VerifiedQuote(
        quote_type=quote_type,
        status=status,
        report_data=context.report_data + bytes(32),
        measurements=measurement_bytes(),
    )
    with pytest.raises(VerificationRejected):
        await context.verifier.verify(context.request())


@pytest.mark.asyncio
async def test_policy_validity_is_checked_before_backend_or_signer(tmp_path):
    context = make_context(tmp_path)
    context.verifier._clock = lambda: NOW + 10_000
    with pytest.raises(VerificationRejected):
        await context.verifier.verify(context.request())
    assert context.backend.calls == []
    assert context.signer.digests == [context.challenge.challenge_digest]


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["challenge", "policy"])
async def test_verification_finishing_at_freshness_boundary_cannot_issue_verdict(
    tmp_path,
    boundary,
):
    context = make_context(
        tmp_path,
        policy_valid_until=NOW + 30 if boundary == "policy" else None,
    )
    clock = [NOW]
    context.verifier._clock = lambda: clock[0]
    original_verify = context.backend.verify

    async def delayed_verify(raw_quote):
        verified = await original_verify(raw_quote)
        clock[0] = (
            context.challenge.expires_at
            if boundary == "challenge"
            else context.release.policy.valid_until
        )
        return verified

    context.backend.verify = delayed_verify
    with pytest.raises(VerificationRejected):
        await context.verifier.verify(context.request())
    assert context.backend.calls == [context.raw_quote]
    assert context.signer.digests == [context.challenge.challenge_digest]


@pytest.mark.asyncio
async def test_verdict_timestamp_and_ttl_start_when_dcap_verification_completes(tmp_path):
    context = make_context(tmp_path)
    clock = [NOW]
    context.verifier._clock = lambda: clock[0]
    original_verify = context.backend.verify

    async def delayed_verify(raw_quote):
        verified = await original_verify(raw_quote)
        clock[0] = NOW + 5
        return verified

    context.backend.verify = delayed_verify
    verdict = await context.verifier.verify(context.request())
    assert verdict.issued_at == NOW + 5
    assert verdict.expires_at == NOW + 305
    assert verdict.activation_evidence_lease_expires_at == verdict.expires_at


@pytest.mark.asyncio
async def test_exact_900_second_activation_evidence_lease_outlives_challenge(tmp_path):
    context = make_context(tmp_path, max_verdict_ttl_seconds=900)

    verdict = await context.verifier.verify(context.request())

    assert verdict.issued_at == NOW
    assert verdict.activation_evidence_lease_expires_at == NOW + 900
    assert verdict.expires_at == NOW + 900
    assert verdict.challenge_expires_at == NOW + 60


@pytest.mark.asyncio
async def test_activation_evidence_lease_is_truncated_by_policy_valid_until(tmp_path):
    context = make_context(
        tmp_path,
        max_verdict_ttl_seconds=900,
        policy_valid_until=NOW + 300,
    )

    verdict = await context.verifier.verify(context.request())

    assert verdict.activation_evidence_lease_expires_at == NOW + 300
    assert verdict.expires_at == NOW + 300


@pytest.mark.asyncio
async def test_tdx_v15_pair_is_required_and_verified_exactly(tmp_path):
    context = make_context(tmp_path, v15=True)
    verdict = await context.verifier.verify(context.request())
    assert verdict.verified is True
    assert set(context.backend.result.measurements) >= {"tee_tcb_svn2", "mr_service_td"}


@pytest.mark.asyncio
async def test_arena_candidate_ingress_binding_is_independently_derived(tmp_path):
    context = make_context(tmp_path, arena=True)
    verdict = await context.verifier.verify(context.request())
    assert verdict.report_data == "0x" + context.report_data.hex()
    assert verdict.signer_address == SIGNER_ADDRESS


@pytest.mark.asyncio
async def test_execution_policy_anchor_writer_binding_commits_release_and_key_path(
    tmp_path,
):
    context = make_context(tmp_path, anchor_writer=True)
    verdict = await context.verifier.verify(context.request())
    assert verdict.report_data == "0x" + context.report_data.hex()
    assert verdict.signer_address == SIGNER_ADDRESS
    assert verdict.contract_address == CONTRACT

    for field, value in (
        ("writer_release_commitment", "0x" + "66" * 32),
        ("writer_key_path", "tinker/shared"),
        ("writer_custody", "operator_key"),
    ):
        payload = policy_payload(anchor_writer=True)
        payload["report_data_binding"][field] = value
        with pytest.raises(Exception):
            # The policy either rejects the noncanonical literal or derives a
            # different digest which cannot authorize the already collected quote.
            drifted = write_policy(tmp_path / f"drifted-{field}.json", payload)
            context.verifier.release = drifted
            await context.verifier.verify(context.request())


@pytest.mark.asyncio
async def test_compute_metering_binding_commits_policy_set_custody_vault_and_signer(tmp_path):
    context = make_context(tmp_path, compute_metering=True)
    verdict = await context.verifier.verify(context.request())
    binding = context.release.policy.report_data_binding
    assert verdict.report_data == "0x" + context.report_data.hex()
    assert verdict.signer_address == SIGNER_ADDRESS
    assert verdict.contract_address == CONTRACT
    assert context.report_data == derive_compute_metering_report_data(
        metering_verifier=SIGNER_ADDRESS,
        chain_id=84_532,
        vault_address=CONTRACT,
        policy_set_hash=binding.policy_set_hash,
        signer_custody=binding.signer_custody,
    )

    payload = policy_payload(compute_metering=True)
    payload["report_data_binding"]["policy_set_hash"] = "0x" + "66" * 32
    drifted = write_policy(tmp_path / "drifted-compute-policy.json", payload)
    context.verifier.release = drifted
    with pytest.raises(VerificationRejected):
        await context.verifier.verify(context.request())


@pytest.mark.asyncio
async def test_compute_workload_recipient_is_dynamic_but_semantically_quote_bound(tmp_path):
    context = make_context(tmp_path, compute_workload=True)
    request = context.request()
    verdict = await context.verifier.verify(request)
    attestation = request.compute_workload_recipient

    assert context.release.policy.allowed_signer_addresses == ()
    assert verdict.profile == "compute_workload"
    assert verdict.signer_address == SIGNER_ADDRESS
    assert verdict.contract_address == CONTRACT
    assert attestation.key_id == WORKLOAD_RECIPIENT_KEY_ID
    assert context.report_data == derive_compute_workload_recipient_report_data(
        attestation
    )
    assert verdict.report_data == "0x" + context.report_data.hex()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("encryption_public_key", "44" * 32),
        ("activation_signer_address", "0x" + "44" * 20),
        ("compute_vault_address", "0x" + "55" * 20),
        ("compute_vault_runtime_code_hash", "0x" + "66" * 32),
        ("fresh_contract_deployment_receipt_sha256", "0x" + "77" * 32),
    ],
)
async def test_compute_workload_recipient_dynamic_context_cannot_be_substituted(
    tmp_path, field, value
):
    context = make_context(tmp_path, compute_workload=True)
    payload = deepcopy(context.request_payload)
    payload["compute_workload_recipient"][field] = value
    if field == "encryption_public_key":
        import hashlib

        payload["compute_workload_recipient"]["key_id"] = (
            "sha256:" + hashlib.sha256(bytes.fromhex(value)).hexdigest()
        )

    with pytest.raises(VerificationRejected):
        await context.verifier.verify(context.request(payload))


def test_compute_workload_release_rejects_pre_live_signer_pinning(tmp_path):
    payload = policy_payload(compute_workload=True)
    payload["allowed_signer_addresses"] = [SIGNER_ADDRESS]
    with pytest.raises(Exception):
        write_policy(tmp_path / "unsafe-workload-policy.json", payload)


@pytest.mark.asyncio
async def test_compute_metering_qvl_raw_signature_binds_exact_v2_receipt(tmp_path):
    context = make_context(tmp_path, compute_metering=True)
    request = context.request()
    binding = context.release.policy.report_data_binding
    evidence_hash = derive_compute_metering_attestation_evidence_hash(request, binding)
    authorization = {
        "schema": "dnai.compute-metering-qvl-authorization-request.v1",
        "project_id": "0x" + "10" * 32,
        "job_id": "0x" + "20" * 32,
        "user": "0x" + "33" * 20,
        "asset": "0x" + "00" * 20,
        "authorization_nonce": "7",
        "max_asset_debit": "1000",
        "actual_asset_debit": "750",
        "authorization_expiry": NOW + 100,
        "rate_policy_commitment": "0x" + "41" * 32,
        "workload_commitment": "0x" + "42" * 32,
        "manifest_commitment": "0x" + "43" * 32,
        "dispatch_intent_commitment": "0x" + "44" * 32,
        "tee_identity": SIGNER_ADDRESS,
        "compose_hash": COMPOSE_HASH,
        "start_commitment": "0x" + "45" * 32,
        "billable_compute_units": "1500000",
        "usage_started_at": NOW - 60,
        "usage_ended_at": NOW,
        "usage_commitment": "0x" + "46" * 32,
        "metering_policy_set_hash": binding.policy_set_hash,
        "attestation_evidence_hash": evidence_hash,
        "receipt_expiry": NOW + 30,
    }
    payload = deepcopy(context.request_payload)
    payload["compute_authorization"] = authorization

    verdict = await context.verifier.verify(context.request(payload))
    expected = compute_metering_qvl_authorization_digest(
        chain_id=84_532,
        contract_address=CONTRACT,
        project_id=authorization["project_id"],
        job_id=authorization["job_id"],
        user=authorization["user"],
        asset=authorization["asset"],
        authorization_nonce=7,
        max_asset_debit=1000,
        actual_asset_debit=750,
        authorization_expiry=NOW + 100,
        rate_policy_commitment=authorization["rate_policy_commitment"],
        workload_commitment=authorization["workload_commitment"],
        manifest_commitment=authorization["manifest_commitment"],
        dispatch_intent_commitment=authorization["dispatch_intent_commitment"],
        tee_identity=SIGNER_ADDRESS,
        compose_hash=COMPOSE_HASH,
        start_commitment=authorization["start_commitment"],
        billable_compute_units=1_500_000,
        usage_started_at=NOW - 60,
        usage_ended_at=NOW,
        usage_commitment=authorization["usage_commitment"],
        metering_policy_set_hash=binding.policy_set_hash,
        attestation_evidence_hash=evidence_hash,
        receipt_expiry=NOW + 30,
    )
    assert verdict.qvl_compute_authorization_digest == expected
    assert verdict.qvl_compute_attestation_evidence_hash == evidence_hash
    assert verdict.qvl_compute_authorization_expiry == NOW + 30
    assert Account._recover_hash(
        bytes.fromhex(expected[2:]),
        signature=verdict.qvl_compute_authorization_signature,
    ).lower() == context.signer.address
    assert Account.recover_message(
        encode_defunct(hexstr=expected),
        signature=verdict.qvl_compute_authorization_signature,
    ).lower() != context.signer.address


@pytest.mark.asyncio
async def test_email_kms_restart_uses_secondary_profile_on_same_diligence_root(tmp_path):
    context = make_context(tmp_path, email_restart=True)
    verdict = await context.verifier.verify(context.request())
    binding = context.release.policy.email_oracle_kms_restart_binding

    assert verdict.profile == "email_oracle_kms_restart"
    assert verdict.release_policy_hash == context.release.policy_hash
    assert verdict.verifier_address == context.signer.address
    assert verdict.signer_address == SIGNER_ADDRESS
    assert verdict.chain_id == 84_532
    assert verdict.report_data == "0x" + context.report_data.hex()
    assert context.report_data == derive_email_oracle_kms_restart_report_data(
        signer_address=SIGNER_ADDRESS,
        chain_id=84_532,
        binding=binding,
    )


@pytest.mark.asyncio
async def test_email_kms_restart_profile_cannot_cross_authorize_diligence_quote(tmp_path):
    context = make_context(tmp_path, email_restart=True)
    payload = deepcopy(context.request_payload)
    payload["challenge"]["profile"] = "diligence"

    with pytest.raises(VerificationRejected):
        await context.verifier.verify(context.request(payload))
    assert context.backend.calls == []

    diligence_path = tmp_path / "diligence-only"
    diligence_path.mkdir()
    diligence_only = make_context(diligence_path)
    payload = deepcopy(diligence_only.request_payload)
    payload["challenge"]["profile"] = "email_oracle_kms_restart"
    with pytest.raises(VerificationRejected):
        await diligence_only.verifier.verify(diligence_only.request(payload))
    assert diligence_only.backend.calls == []


def test_report_data_derivation_is_canonical_and_case_normalized():
    first = derive_signer_report_data(
        signer_address=SIGNER_ADDRESS,
        chain_id=84_532,
        contract_address=CONTRACT,
    )
    second = derive_signer_report_data(
        signer_address=SIGNER_ADDRESS.upper().replace("0X", "0x"),
        chain_id=84_532,
        contract_address=CONTRACT.upper().replace("0X", "0x"),
    )
    assert first == second
    assert len(first) == 32
