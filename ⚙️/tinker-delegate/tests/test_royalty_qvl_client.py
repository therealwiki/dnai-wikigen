from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, Callable
from unittest.mock import patch

import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.qvl_freshness import QvlChallenge, qvl_challenge_digest
from tinker_delegate.result_verifier import (
    independent_attestation_verdict_digest,
    independent_attestation_verdict_from_public_dict,
)
from tinker_delegate.royalty_qvl_client import (
    AuthenticatedRoyaltyQvlCapabilityObservation,
    HttpsRoyaltySettlementQvlClient,
    RoyaltyQvlClientError,
)
from tinker_delegate.royalty_settlement_authorization import (
    ROYALTY_SETTLEMENT_SIGNER_CUSTODY,
    ROYALTY_SETTLEMENT_SIGNER_KEY_PATH,
    derive_royalty_settlement_anchor_evidence_commitment,
    royalty_settlement_qvl_authorization_digest,
)
from tests.test_royalty_settlement_authorization import (
    MAIN,
    NOW,
    ROYALTY_QVL,
    VERDICT_QVL,
    RawSigner,
    make_intent,
    make_release,
)


QUOTE = bytes.fromhex("ab" * 1024)
TOKEN = "royalty-qvl-token-" + "x" * 48


def signed_challenge(*, profile: str = "royalty_settlement") -> QvlChallenge:
    release = make_release()
    unsigned = QvlChallenge(
        schema="dnai.attestation-qvl-challenge.v2",
        chain_id=release.chain_id,
        domain="main_runtime_cvm",
        profile=profile,
        cvm_id=release.main_runtime_cvm_id,
        deployment_intent_sha256=release.deployment_intent_sha256,
        release_authority_sha256=release.release_authority_sha256,
        ceremony_nonce=release.ceremony_nonce,
        measurement_policy_sha256=release.measurement_policy_sha256,
        release_policy_hash=release.qvl_release_policy_hash,
        challenge_id="0x" + "a1" * 32,
        challenge_digest="0x" + "a2" * 32,
        issued_at=NOW - 1,
        expires_at=NOW + 60,
        verifier_address=VERDICT_QVL.address.lower(),
        verifier_signature="0x" + "01" * 64 + "1b",
    )
    digest = qvl_challenge_digest(unsigned)
    signature = VERDICT_QVL.sign_message(encode_defunct(hexstr=digest))
    return replace(
        unsigned,
        challenge_digest=digest,
        verifier_signature="0x" + bytes(signature.signature).hex(),
    )


def _authorization_from_qvl_payload(payload: dict[str, Any]):
    from tinker_delegate.royalty_distribution_plan import SettlementAuthorization

    return SettlementAuthorization(
        settlement_id=payload["settlement_id"],
        settlement_nonce=int(payload["settlement_nonce"]),
        funding_reservation_id=payload["funding_reservation_id"],
        release_policy_commitment=payload["release_policy_commitment"],
        room_commitment=payload["room_commitment"],
        room_state_commitment=payload["room_state_commitment"],
        query_commitment=payload["query_commitment"],
        grant_set_commitment=payload["grant_set_commitment"],
        allocation_commitment=payload["allocation_commitment"],
        owners_amounts_hash=payload["owners_amounts_hash"],
        asset_address=payload["asset"],
        total=int(payload["total"]),
        execution_commitment=payload["execution_commitment"],
        result_commitment=payload["result_commitment"],
        usage_commitment=payload["usage_commitment"],
        attestation_evidence_hash=payload["attestation_evidence_hash"],
        anchor_resource_hash=payload["anchor_resource_hash"],
        anchor_decision_hash=payload["anchor_decision_hash"],
        anchor_sequence=int(payload["anchor_sequence"]),
        expiry=payload["expiry"],
    )


VerdictMutation = Callable[[dict[str, Any], dict[str, Any]], None]


def transport(
    *,
    challenge: QvlChallenge | None = None,
    mutate_verdict: VerdictMutation | None = None,
    paths: list[str] | None = None,
) -> httpx.MockTransport:
    release = make_release()
    issued_challenge = challenge or signed_challenge()

    def handler(request: httpx.Request) -> httpx.Response:
        if paths is not None:
            paths.append(request.url.path)
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        request_payload = json.loads(request.content)
        if request.url.path == "/challenge":
            assert request_payload == {
                "schema": "dnai.attestation-qvl-challenge-request.v2",
                "chain_id": release.chain_id,
                "domain": "main_runtime_cvm",
                "profile": "royalty_settlement",
                "cvm_id": release.main_runtime_cvm_id,
                "deployment_intent_sha256": release.deployment_intent_sha256,
                "release_authority_sha256": release.release_authority_sha256,
                "ceremony_nonce": release.ceremony_nonce,
                "measurement_policy_sha256": release.measurement_policy_sha256,
            }
            return httpx.Response(
                200,
                json=issued_challenge.to_public_dict(),
                headers={"content-type": "application/json"},
            )
        assert request.url.path == "/verify"
        assert request_payload["schema"] == (
            "dnai.independent-tdx-verification-request.v2"
        )
        assert request_payload["quote"] == "0x" + QUOTE.hex()
        authorization_payload = request_payload["royalty_authorization"]
        authorization = _authorization_from_qvl_payload(authorization_payload)
        assert authorization_payload["settlement_authorization_signature"]
        qvl_digest = royalty_settlement_qvl_authorization_digest(
            chain_id=release.chain_id,
            distributor_address=release.distributor_address,
            authorization=authorization,
        )
        qvl_signature = ROYALTY_QVL.unsafe_sign_hash(bytes.fromhex(qvl_digest[2:]))
        qvl_anchor_commitment = derive_royalty_settlement_anchor_evidence_commitment(
            release=release,
            authorization=authorization,
        )
        expectation = request_payload["expectation"]
        verdict: dict[str, Any] = {
            "schema": "dnai.independent-tdx-verdict.v4",
            "verification_method": "intel_tdx_dcap_qvl",
            "verified": True,
            "chain_id": release.chain_id,
            "domain": "main_runtime_cvm",
            "profile": "royalty_settlement",
            "cvm_id": release.main_runtime_cvm_id,
            "deployment_intent_sha256": release.deployment_intent_sha256,
            "release_authority_sha256": release.release_authority_sha256,
            "ceremony_nonce": release.ceremony_nonce,
            "measurement_policy_sha256": release.measurement_policy_sha256,
            "release_policy_hash": release.qvl_release_policy_hash,
            "challenge_id": issued_challenge.challenge_id,
            "challenge_digest": issued_challenge.challenge_digest,
            "challenge_issued_at": issued_challenge.issued_at,
            "challenge_expires_at": issued_challenge.expires_at,
            "quote_hash": expectation["quote_hash"],
            "report_data": expectation["report_data"],
            "compose_hash": expectation["compose_hash"],
            "app_id": expectation["app_id"],
            "os_image_hash": expectation["os_image_hash"],
            "signer_address": release.settlement_verifier_address,
            "contract_address": release.distributor_address,
            "issued_at": NOW,
            "activation_evidence_lease_expires_at": NOW + 50,
            "expires_at": NOW + 50,
            "verifier_address": VERDICT_QVL.address.lower(),
            "verifier_signature": "0x" + "01" * 64 + "1b",
            "qvl_royalty_verifier_address": (
                release.royalty_qvl_verifier_address
            ),
            "qvl_royalty_policy_commitment": (
                release.royalty_qvl_policy_commitment
            ),
            "qvl_royalty_release_policy_commitment": (
                release.release_policy_commitment
            ),
            "qvl_royalty_attestation_evidence_hash": (
                authorization.attestation_evidence_hash
            ),
            "qvl_royalty_anchor_evidence_commitment": qvl_anchor_commitment,
            "qvl_royalty_authorization_expiry": authorization.expiry,
            "qvl_royalty_authorization_digest": qvl_digest,
            "qvl_royalty_authorization_signature": (
                "0x" + bytes(qvl_signature.signature).hex()
            ),
        }
        if mutate_verdict is not None:
            mutate_verdict(verdict, request_payload)
        parsed = independent_attestation_verdict_from_public_dict(verdict)
        verdict_digest = independent_attestation_verdict_digest(parsed)
        signed = VERDICT_QVL.sign_message(encode_defunct(hexstr=verdict_digest))
        verdict["verifier_signature"] = "0x" + bytes(signed.signature).hex()
        return httpx.Response(
            200,
            json=verdict,
            headers={"content-type": "application/json"},
        )

    return httpx.MockTransport(handler)


def client_for(
    *,
    mutate_verdict: VerdictMutation | None = None,
    challenge: QvlChallenge | None = None,
    paths: list[str] | None = None,
) -> HttpsRoyaltySettlementQvlClient:
    return HttpsRoyaltySettlementQvlClient(
        qvl_url="https://diligence-qvl.example.test/verify",
        auth_token=TOKEN,
        trusted_verdict_verifier_address=VERDICT_QVL.address.lower(),
        release=make_release(),
        max_verdict_age_seconds=120,
        client=httpx.Client(
            transport=transport(
                challenge=challenge,
                mutate_verdict=mutate_verdict,
                paths=paths,
            ),
            follow_redirects=False,
        ),
    )


def capability_transport(
    *,
    challenge: QvlChallenge | None = None,
    mutate_identity: Callable[[dict[str, Any]], None] | None = None,
    mutate_capability: Callable[[dict[str, Any]], None] | None = None,
    paths: list[str] | None = None,
) -> httpx.MockTransport:
    release = make_release()
    issued_challenge = challenge or signed_challenge()

    def handler(request: httpx.Request) -> httpx.Response:
        if paths is not None:
            paths.append(request.url.path)
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        if request.url.path == "/identity":
            payload: dict[str, Any] = {
                "schema": "dnai.attestation-qvl-identity.v1",
                "verifier_address": VERDICT_QVL.address.lower(),
                "release_policy_hash": release.qvl_release_policy_hash,
                "signer_custody": "dstack_derived_separate_cvm",
                "raw_secret_egress": False,
            }
            if mutate_identity is not None:
                mutate_identity(payload)
            return httpx.Response(
                200,
                json=payload,
                headers={"content-type": "application/json"},
            )
        if request.url.path == "/capabilities":
            payload = {
                "schema": "dnai.attestation-qvl-capabilities.v1",
                "royalty_settlement_qvl_enabled": True,
                "royalty_authorization_schema": (
                    "dnai.royalty-settlement-qvl-authorization-request.v2"
                ),
                "royalty_qvl_verifier_address": (
                    release.royalty_qvl_verifier_address
                ),
                "royalty_qvl_policy_commitment": (
                    release.royalty_qvl_policy_commitment
                ),
                "raw_secret_egress": False,
            }
            if mutate_capability is not None:
                mutate_capability(payload)
            return httpx.Response(
                200,
                json=payload,
                headers={"content-type": "application/json"},
            )
        assert request.url.path == "/challenge"
        request_payload = json.loads(request.content)
        assert request_payload["profile"] == "royalty_settlement"
        return httpx.Response(
            200,
            json=issued_challenge.to_public_dict(),
            headers={"content-type": "application/json"},
        )

    return httpx.MockTransport(handler)


def capability_client(**transport_kwargs: Any) -> HttpsRoyaltySettlementQvlClient:
    return HttpsRoyaltySettlementQvlClient(
        qvl_url="https://diligence-qvl.example.test/verify",
        auth_token=TOKEN,
        trusted_verdict_verifier_address=VERDICT_QVL.address.lower(),
        release=make_release(),
        max_verdict_age_seconds=120,
        client=httpx.Client(
            transport=capability_transport(**transport_kwargs),
            follow_redirects=False,
        ),
    )


def test_authenticated_exact_capability_probe_is_bounded_and_round_trips():
    paths: list[str] = []
    client = capability_client(paths=paths)
    observation = client.probe_capability(
        release_binding_sha256="sha256:" + "ab" * 32,
        now=NOW,
    )
    assert paths == ["/identity", "/capabilities", "/challenge"]
    assert observation.challenge.profile == "royalty_settlement"
    assert observation.challenge.release_policy_hash == (
        make_release().qvl_release_policy_hash
    )
    assert observation.royalty_qvl_verifier_address == (
        make_release().royalty_qvl_verifier_address
    )
    assert observation.royalty_qvl_policy_commitment == (
        make_release().royalty_qvl_policy_commitment
    )
    assert observation.royalty_qvl_signer_key_id == (
        make_release().royalty_qvl_signer_key_id
    )
    assert observation.commitment.startswith("sha256:")
    assert AuthenticatedRoyaltyQvlCapabilityObservation.from_public_dict(
        observation.to_public_dict()
    ) == observation
    serialized = json.dumps(observation.to_public_dict(), sort_keys=True)
    assert TOKEN not in serialized
    assert "quote" not in serialized


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update(
            royalty_settlement_qvl_enabled=False
        ),
        lambda payload: payload.update(
            royalty_authorization_schema="dnai.legacy.v1"
        ),
        lambda payload: payload.update(
            royalty_qvl_verifier_address="0x" + "aa" * 20
        ),
        lambda payload: payload.update(
            royalty_qvl_policy_commitment="0x" + "bb" * 32
        ),
    ],
)
def test_capability_probe_rejects_exact_capability_mismatch(mutation):
    client = capability_client(mutate_capability=mutation)
    with pytest.raises(RoyaltyQvlClientError, match="capability_mismatch"):
        client.probe_capability(
            release_binding_sha256="sha256:" + "ab" * 32,
            now=NOW,
        )


def test_capability_probe_rejects_stale_signed_challenge():
    client = capability_client(challenge=signed_challenge())
    with pytest.raises(RoyaltyQvlClientError, match="challenge_invalid"):
        client.probe_capability(
            release_binding_sha256="sha256:" + "ab" * 32,
            now=NOW + 61,
        )


def test_capability_probe_fails_closed_when_endpoint_is_unreachable():
    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    client = HttpsRoyaltySettlementQvlClient(
        qvl_url="https://diligence-qvl.example.test/verify",
        auth_token=TOKEN,
        trusted_verdict_verifier_address=VERDICT_QVL.address.lower(),
        release=make_release(),
        max_verdict_age_seconds=120,
        client=httpx.Client(
            transport=httpx.MockTransport(unavailable),
            follow_redirects=False,
        ),
    )
    with pytest.raises(RoyaltyQvlClientError, match="royalty_qvl_unavailable"):
        client.probe_capability(
            release_binding_sha256="sha256:" + "ab" * 32,
            now=NOW,
        )


def attestation_details(report_data: bytes) -> dict[str, Any]:
    release = make_release()
    assert len(report_data) == 64
    return {
        "quote": "0x" + QUOTE.hex(),
        "quote_report_data": "0x" + report_data.hex(),
        "compose_hash": release.compose_hash,
        "app_id": release.app_id,
        "os_image_hash": release.os_image_hash,
    }


def authorize(client: HttpsRoyaltySettlementQvlClient):
    with (
        patch(
            "tinker_delegate.royalty_qvl_client.dstack_utils.is_dstack_enabled",
            return_value=True,
        ),
        patch(
            "tinker_delegate.royalty_qvl_client.dstack_utils.is_dstack_simulator",
            return_value=False,
        ),
        patch(
            "tinker_delegate.royalty_qvl_client.dstack_utils.get_attestation_details",
            side_effect=attestation_details,
        ),
        patch(
            "tinker_delegate.royalty_qvl_client.DstackRoyaltySettlementSigner.from_dstack",
            return_value=RawSigner(),
        ),
    ):
        return client.authorize(make_intent(), now=NOW)


def test_fresh_quote_main_signature_and_diligence_qvl_authorization_round_trip():
    paths: list[str] = []
    client = client_for(paths=paths)
    plan = authorize(client)
    assert paths == ["/challenge", "/verify"]
    assert plan.settlement_verifier_address == MAIN.address.lower()
    assert plan.qvl_verifier_address == ROYALTY_QVL.address.lower()
    assert plan.qvl_verdict_verifier_address == VERDICT_QVL.address.lower()
    assert plan.authorization.attestation_evidence_hash
    assert plan.authorization.anchor_resource_hash
    assert plan.authorization.anchor_decision_hash
    assert plan.authorization_expires_at == NOW + 30
    assert plan.settlement_authorization_digest != plan.qvl_authorization_digest

    public = plan.to_public_dict()
    rendered = json.dumps(public, sort_keys=True)
    assert ("0x" + QUOTE.hex()) not in rendered
    assert TOKEN not in rendered
    assert "artifact" not in rendered.lower() or public["raw_artifact_egress"] is False
    assert public["status"] == "dual_authorized_not_broadcast"
    assert public["independent_qvl_tdx_verified"] is True
    assert public["funding_evidence_supplied"] is False
    assert public["finalized_chain_receipt_supplied"] is False
    assert public["withdrawal_performed"] is False
    assert repr(client) == "HttpsRoyaltySettlementQvlClient(authenticated=True)"
    assert TOKEN not in repr(client)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda verdict, _request: verdict.update(
            {"qvl_royalty_policy_commitment": "0x" + "b1" * 32}
        ),
        lambda verdict, _request: verdict.update(
            {"qvl_royalty_verifier_address": VERDICT_QVL.address.lower()}
        ),
        lambda verdict, _request: verdict.update(
            {"qvl_royalty_authorization_expiry": NOW - 1}
        ),
        lambda verdict, _request: verdict.update(
            {"qvl_royalty_release_policy_commitment": "0x" + "b2" * 32}
        ),
        lambda verdict, _request: verdict.update(
            {"qvl_royalty_attestation_evidence_hash": "0x" + "b3" * 32}
        ),
        lambda verdict, _request: verdict.update(
            {"qvl_royalty_anchor_evidence_commitment": "0x" + "b4" * 32}
        ),
        lambda verdict, _request: verdict.update(
            {"qvl_royalty_authorization_digest": "0x" + "b5" * 32}
        ),
        lambda verdict, _request: verdict.update({"profile": "diligence"}),
    ],
)
def test_authenticated_but_policy_role_expiry_or_context_drifted_verdict_fails(
    mutation,
):
    with pytest.raises(RoyaltyQvlClientError, match="royalty_qvl_verdict_invalid"):
        authorize(client_for(mutate_verdict=mutation))


def test_wrong_challenge_domain_fails_before_quote_or_signature():
    challenge = replace(signed_challenge(), domain="diligence_qvl_cvm")
    # Re-sign the altered challenge so this exercises external context binding,
    # not merely a forged signature.
    unsigned = replace(
        challenge,
        challenge_digest="0x" + "c1" * 32,
        verifier_signature="0x" + "01" * 64 + "1b",
    )
    digest = qvl_challenge_digest(unsigned)
    signed = VERDICT_QVL.sign_message(encode_defunct(hexstr=digest))
    challenge = replace(
        unsigned,
        challenge_digest=digest,
        verifier_signature="0x" + bytes(signed.signature).hex(),
    )
    paths: list[str] = []
    with pytest.raises(RoyaltyQvlClientError, match="challenge_invalid"):
        authorize(client_for(challenge=challenge, paths=paths))
    assert paths == ["/challenge"]


def test_main_release_identity_drift_fails_before_qvl_verify():
    paths: list[str] = []
    client = client_for(paths=paths)

    def drifted_details(report_data: bytes) -> dict[str, Any]:
        details = attestation_details(report_data)
        details["compose_hash"] = "0x" + "d1" * 32
        return details

    with (
        patch(
            "tinker_delegate.royalty_qvl_client.dstack_utils.is_dstack_enabled",
            return_value=True,
        ),
        patch(
            "tinker_delegate.royalty_qvl_client.dstack_utils.is_dstack_simulator",
            return_value=False,
        ),
        patch(
            "tinker_delegate.royalty_qvl_client.dstack_utils.get_attestation_details",
            side_effect=drifted_details,
        ),
        patch(
            "tinker_delegate.royalty_qvl_client.DstackRoyaltySettlementSigner.from_dstack",
            return_value=RawSigner(),
        ),
    ):
        with pytest.raises(RoyaltyQvlClientError, match="release_drift"):
            client.authorize(make_intent(), now=NOW)
    assert paths == ["/challenge"]


def test_expired_intent_and_non_dstack_signer_are_rejected_before_network():
    paths: list[str] = []
    client = client_for(paths=paths)
    with pytest.raises(RoyaltyQvlClientError, match="expiry_invalid"):
        client.authorize(make_intent(expiry=NOW), now=NOW)
    assert paths == []

    with (
        patch(
            "tinker_delegate.royalty_qvl_client.DstackRoyaltySettlementSigner.from_dstack",
            side_effect=Exception("must not escape"),
        ),
    ):
        with pytest.raises(
            RoyaltyQvlClientError,
            match="royalty_settlement_signer_unavailable",
        ) as error:
            client.authorize(make_intent(), now=NOW)
        assert "must not escape" not in str(error.value)


def test_https_exact_verify_endpoint_and_role_separation_are_required():
    release = make_release()
    with pytest.raises(RoyaltyQvlClientError, match="unavailable"):
        HttpsRoyaltySettlementQvlClient(
            qvl_url="http://diligence-qvl.example.test/verify",
            auth_token=TOKEN,
            trusted_verdict_verifier_address=VERDICT_QVL.address.lower(),
            release=release,
            max_verdict_age_seconds=120,
        )
    with pytest.raises(RoyaltyQvlClientError, match="role_separation"):
        HttpsRoyaltySettlementQvlClient(
            qvl_url="https://diligence-qvl.example.test/verify",
            auth_token=TOKEN,
            trusted_verdict_verifier_address=ROYALTY_QVL.address.lower(),
            release=release,
            max_verdict_age_seconds=120,
        )


def test_key_path_and_custody_literals_match_qvl_release_policy():
    assert ROYALTY_SETTLEMENT_SIGNER_KEY_PATH == (
        "tinker/collaboration_royalty_settlement_signer"
    )
    assert ROYALTY_SETTLEMENT_SIGNER_CUSTODY == (
        "dstack_derived_main_runtime_royalty_settlement_signer"
    )
