from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path

from fastapi.testclient import TestClient

DELEGATE_PROJECT = Path(__file__).resolve().parents[2] / "tinker-delegate"
sys.path.insert(0, str(DELEGATE_PROJECT))
COMPUTE_METERING_SRC = Path(__file__).resolve().parents[2] / "compute-metering" / "src"
sys.path.insert(0, str(COMPUTE_METERING_SRC))

from compute_metering.identity_attestation import (  # noqa: E402
    DSTACK_METERING_CUSTODY,
    metering_identity_report_data,
)

from tinker_delegate.arena_ingress import (  # noqa: E402
    arena_attestation_report_data,
    arena_ingress_key_id,
)
from tinker_delegate.arena_safe_worker import ArenaAttestationPacket  # noqa: E402
from tinker_delegate.arena_worker_cli import (  # noqa: E402
    HttpsArenaQvlClient,
    QVL_REQUEST_SCHEMA as ARENA_QVL_REQUEST_SCHEMA,
)
from tinker_delegate.chain_submitter import (  # noqa: E402
    SignerAttestationEvidence,
    signer_attestation_report_data,
)
from tinker_delegate.deal_runtime import (  # noqa: E402
    HttpsIndependentQvlClient,
    QVL_REQUEST_SCHEMA as DEAL_QVL_REQUEST_SCHEMA,
    SignerAttestationPacket,
)
from tinker_delegate.execution_policy_anchor_cli import (  # noqa: E402
    AnchorWriterAttestationPacket,
    AnchorWriterEvidence,
    HttpsAnchorWriterQvlClient,
    writer_evidence_report_data,
)
from tinker_delegate.result_verifier import (  # noqa: E402
    IndependentAttestationExpectation,
    authenticate_independent_attestation_verdict,
    independent_attestation_verdict_digest,
)

from attestation_qvl.qvl import (  # noqa: E402
    derive_arena_report_data,
    derive_compute_metering_report_data,
    derive_execution_policy_anchor_writer_report_data,
    derive_signer_report_data,
)
from attestation_qvl.service import Runtime, _create_app  # noqa: E402
from attestation_qvl.signing import independent_verdict_digest  # noqa: E402
from tests.support import NOW, TOKEN, make_context  # noqa: E402


def _evidence(context) -> SignerAttestationEvidence:
    public = context.request_payload["expectation"]
    return SignerAttestationEvidence(
        mode=public["mode"],
        signer_address=public["signer_address"],
        chain_id=public["chain_id"],
        contract_address=public["contract_address"],
        report_data=public["report_data"],
        quote_report_data=public["report_data"],
        quote_hash=public["quote_hash"],
        quote_size=public["quote_size"],
        compose_hash=public["compose_hash"],
        app_id=public["app_id"],
        os_image_hash=public["os_image_hash"],
    )


def _app(context):
    return _create_app(Runtime(
        release=context.release,
        verifier=context.verifier,
        auth_token=TOKEN,
        identity_attestor=None,
        challenge_store=context.challenge_store,
        max_concurrency=4,
        rate_capacity=30,
        rate_refill_per_second=1.0,
        request_body_timeout_seconds=5.0,
        verification_timeout_seconds=5.0,
    ))


def _authenticate(context, verdict):
    public = context.request_payload["expectation"]
    expectation = IndependentAttestationExpectation(
        trusted_verifier_addresses=(context.signer.address,),
        chain_id=verdict.chain_id,
        domain=verdict.domain,
        profile=verdict.profile,
        cvm_id=verdict.cvm_id,
        deployment_intent_sha256=verdict.deployment_intent_sha256,
        release_authority_sha256=verdict.release_authority_sha256,
        ceremony_nonce=verdict.ceremony_nonce,
        measurement_policy_sha256=verdict.measurement_policy_sha256,
        release_policy_hash=context.release.policy_hash,
        challenge_id=verdict.challenge_id,
        challenge_digest=verdict.challenge_digest,
        challenge_issued_at=verdict.challenge_issued_at,
        challenge_expires_at=verdict.challenge_expires_at,
        quote_hash=public["quote_hash"],
        report_data=public["report_data"],
        compose_hash=public["compose_hash"],
        app_id=public["app_id"],
        os_image_hash=public["os_image_hash"],
        signer_address=public["signer_address"],
        contract_address=public["contract_address"],
        max_age_seconds=300,
    )
    return authenticate_independent_attestation_verdict(
        verdict,
        expectation=expectation,
        now=NOW,
    )


def test_report_data_algorithms_match_both_delegate_consumers_exactly():
    signer = "0x" + "22" * 20
    contract = "0x" + "11" * 20
    assert derive_signer_report_data(
        signer_address=signer,
        chain_id=84_532,
        contract_address=contract,
    ) == signer_attestation_report_data(
        signer_address=signer,
        chain_id=84_532,
        contract_address=contract,
    )

    public_key = bytes.fromhex("33" * 32)
    assert derive_arena_report_data(
        encryption_public_key=public_key.hex(),
        key_id=arena_ingress_key_id(public_key),
    ) == arena_attestation_report_data(public_key)
    assert DEAL_QVL_REQUEST_SCHEMA == ARENA_QVL_REQUEST_SCHEMA == "dnai.independent-tdx-verification-request.v2"

    release = "0x" + "55" * 32
    assert derive_execution_policy_anchor_writer_report_data(
        writer_address=signer,
        chain_id=84_532,
        anchor_address=contract,
        writer_release_commitment=release,
        writer_key_path="tinker/execution_policy_anchor_writer",
        writer_custody="dstack_derived_execution_policy_anchor_writer",
    ) == writer_evidence_report_data(
        writer_address=signer,
        anchor_address=contract,
        writer_release_commitment=release,
    )

    policy_set_hash = "0x" + "44" * 32
    assert derive_compute_metering_report_data(
        metering_verifier=signer,
        chain_id=84_532,
        vault_address=contract,
        policy_set_hash=policy_set_hash,
        signer_custody=DSTACK_METERING_CUSTODY,
    ) == metering_identity_report_data(
        metering_verifier=signer,
        chain_id=84_532,
        vault_address=contract,
        policy_set_hash=policy_set_hash,
        signer_custody=DSTACK_METERING_CUSTODY,
    )


def test_deal_https_qvl_client_round_trips_exact_request_verdict_and_signature(tmp_path, monkeypatch):
    monkeypatch.setattr("tinker_delegate.qvl_freshness.time.time", lambda: NOW)
    context = make_context(tmp_path)
    packet = SignerAttestationPacket(
        evidence=_evidence(context),
        quote=context.request_payload["quote"],
    )
    with TestClient(_app(context), raise_server_exceptions=False) as transport:
        client = HttpsIndependentQvlClient(
            "http://testserver/verify",
            auth_token=TOKEN,
            client=transport,
            allow_plain_http_for_local_test=True,
            trusted_verifier_addresses=(context.signer.address,),
            expected_policy_hash=context.release.policy_hash,
            chain_id=context.challenge.chain_id,
            cvm_id=context.challenge.cvm_id,
            deployment_intent_sha256=context.challenge.deployment_intent_sha256,
            release_authority_sha256=context.challenge.release_authority_sha256,
            ceremony_nonce=context.challenge.ceremony_nonce,
            measurement_policy_sha256=context.challenge.measurement_policy_sha256,
        )
        challenge = client.issue_challenge()
        verdict = client.verify(packet, challenge)

    assert independent_attestation_verdict_digest(verdict) == independent_verdict_digest(verdict.to_public_dict())
    authenticated = _authenticate(context, verdict)
    assert authenticated.verifier_address == context.signer.address


def test_arena_https_qvl_client_uses_same_schema_with_arena_policy_instance(tmp_path, monkeypatch):
    monkeypatch.setattr("tinker_delegate.qvl_freshness.time.time", lambda: NOW)
    context = make_context(tmp_path, arena=True)
    packet = ArenaAttestationPacket(
        evidence=_evidence(context),
        quote=context.request_payload["quote"],
    )
    with TestClient(_app(context), raise_server_exceptions=False) as transport:
        client = HttpsArenaQvlClient(
            "https://testserver/verify",
            auth_token=TOKEN,
            client=transport,
            trusted_verifier_addresses=(context.signer.address,),
            expected_policy_hash=context.release.policy_hash,
            chain_id=context.challenge.chain_id,
            cvm_id=context.challenge.cvm_id,
            deployment_intent_sha256=context.challenge.deployment_intent_sha256,
            release_authority_sha256=context.challenge.release_authority_sha256,
            ceremony_nonce=context.challenge.ceremony_nonce,
            measurement_policy_sha256=context.challenge.measurement_policy_sha256,
        )
        challenge = client.issue_challenge()
        verdict = client.verify(packet, challenge)

    assert verdict.report_data == "0x" + context.report_data.hex()
    assert independent_attestation_verdict_digest(verdict) == independent_verdict_digest(verdict.to_public_dict())
    authenticated = _authenticate(context, verdict)
    assert authenticated.verifier_address == context.signer.address


def test_anchor_writer_https_qvl_client_round_trips_the_release_bound_profile(tmp_path, monkeypatch):
    monkeypatch.setattr("tinker_delegate.qvl_freshness.time.time", lambda: NOW)
    context = make_context(tmp_path, anchor_writer=True)
    public = context.request_payload["expectation"]
    evidence = AnchorWriterEvidence(
        writer_address=public["signer_address"],
        anchor_address=public["contract_address"],
        writer_release_commitment="0x" + "55" * 32,
        app_id=public["app_id"],
        compose_hash=public["compose_hash"],
        os_image_hash=public["os_image_hash"],
        report_data=public["report_data"],
        quote_report_data=public["report_data"],
        quote_sha256=public["quote_hash"],
        quote_size=public["quote_size"],
    )
    packet = AnchorWriterAttestationPacket(
        evidence=evidence,
        quote=context.request_payload["quote"],
    )
    with TestClient(_app(context), raise_server_exceptions=False) as transport:
        client = HttpsAnchorWriterQvlClient(
            "https://testserver/verify",
            auth_token=TOKEN,
            client=transport,
            trusted_verifier_addresses=(context.signer.address,),
            expected_policy_hash=context.release.policy_hash,
            chain_id=context.challenge.chain_id,
            cvm_id=context.challenge.cvm_id,
            deployment_intent_sha256=context.challenge.deployment_intent_sha256,
            release_authority_sha256=context.challenge.release_authority_sha256,
            ceremony_nonce=context.challenge.ceremony_nonce,
            measurement_policy_sha256=context.challenge.measurement_policy_sha256,
        )
        challenge = client.issue_challenge()
        verdict = client.verify(packet, challenge)

    assert verdict.report_data == "0x" + context.report_data.hex()
    assert independent_attestation_verdict_digest(verdict) == independent_verdict_digest(verdict.to_public_dict())
    authenticated = _authenticate(context, verdict)
    assert authenticated.verifier_address == context.signer.address


def test_compute_metering_endpoint_packet_maps_to_exact_qvl_request_and_verdict(tmp_path):
    context = make_context(tmp_path, compute_metering=True)
    binding = context.release.policy.report_data_binding
    report_data = "0x" + context.report_data.hex()
    with TestClient(_app(context), raise_server_exceptions=False) as transport:
        challenge_response = transport.post(
            "/challenge",
            headers={"Authorization": f"Bearer {TOKEN}"},
            json=context.challenge_request.model_dump(mode="json", by_alias=True),
        )
        assert challenge_response.status_code == 200
        challenge = challenge_response.json()
        request = deepcopy(context.request_payload)
        request["challenge"] = challenge
        request["expectation"]["quote_report_data"] = (
            report_data + challenge["challenge_digest"][2:]
        )
        response = transport.post(
            "/verify",
            headers={"Authorization": f"Bearer {TOKEN}"},
            json=request,
        )
    assert response.status_code == 200
    verdict = response.json()
    assert verdict["verified"] is True
    assert verdict["report_data"] == report_data
    assert verdict["signer_address"] == context.request_payload["expectation"]["signer_address"]
    assert verdict["contract_address"] == context.release.policy.contract_address
    assert verdict["domain"] == "independent_metering_cvm"
    assert binding.policy_set_hash == context.release.policy.report_data_binding.policy_set_hash
