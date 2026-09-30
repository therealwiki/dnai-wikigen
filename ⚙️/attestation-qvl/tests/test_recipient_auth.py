from __future__ import annotations

from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from attestation_qvl.errors import Unauthorized, VerifierUnavailable
from attestation_qvl.service import Runtime, _create_app, _require_recipient_scope
from attestation_qvl.qvl import VerifiedQuote
from tests.support import TOKEN, make_context
from tests.test_service import FakeIdentityAttestor


ARTIFACT_TOKEN = "artifact-recipient-only-token-0123456789abcdef"
ARENA_TOKEN = "arena-recipient-only-token-0123456789abcdef"


def runtime_for(context, **tokens):
    return Runtime(
        release=context.release, verifier=context.verifier, auth_token=TOKEN,
        identity_attestor=FakeIdentityAttestor(), challenge_store=context.challenge_store,
        max_concurrency=4, rate_capacity=100, rate_refill_per_second=1,
        request_body_timeout_seconds=5, verification_timeout_seconds=5,
        **tokens,
    )


def fresh_payload(client, context, token):
    response = client.post("/challenge", headers={"Authorization": f"Bearer {token}"},
        json=context.challenge_request.model_dump(mode="json", by_alias=True))
    assert response.status_code == 200
    payload = deepcopy(context.request_payload)
    payload["challenge"] = response.json()
    digest = response.json()["challenge_digest"]
    payload["expectation"]["quote_report_data"] = payload["expectation"]["report_data"] + digest[2:]
    context.backend.result = VerifiedQuote(
        quote_type="TDX", status="OK", report_data=context.report_data + bytes.fromhex(digest[2:]),
        measurements=context.backend.result.measurements,
    )
    return payload


@pytest.mark.parametrize("kind,token", [("artifact_recipient", ARTIFACT_TOKEN), ("arena", ARENA_TOKEN)])
def test_recipient_bearer_only_challenges_and_verifies_its_exact_profile(tmp_path, kind, token):
    context = make_context(tmp_path, **{kind: True})
    setting = "artifact_recipient_auth_token" if kind == "artifact_recipient" else "arena_recipient_auth_token"
    runtime = runtime_for(context, **{setting: token})
    assert token not in repr(runtime)
    with TestClient(_create_app(runtime)) as client:
        payload = fresh_payload(client, context, token)
        response = client.post("/verify", headers={"Authorization": f"Bearer {token}"}, json=payload)
        assert response.status_code == 200
        assert response.json()["profile"] == kind
        replay = client.post("/verify", headers={"Authorization": f"Bearer {token}"}, json=payload)
        assert replay.status_code != 200
        denied = client.post("/attestation", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, content=b"not-json")
        assert denied.status_code == 401


@pytest.mark.parametrize("kind,token", [("artifact_recipient", ARTIFACT_TOKEN), ("arena", ARENA_TOKEN)])
def test_recipient_bearer_cannot_cross_profile_before_quote_work_or_challenge_consumption(tmp_path, kind, token):
    context = make_context(tmp_path, **{kind: True})
    setting = "artifact_recipient_auth_token" if kind == "artifact_recipient" else "arena_recipient_auth_token"
    with TestClient(_create_app(runtime_for(context, **{setting: token}))) as client:
        payload = fresh_payload(client, context, token)
        wrong = deepcopy(payload)
        wrong["challenge"]["profile"] = "diligence"
        response = client.post("/verify", headers={"Authorization": f"Bearer {token}"}, json=wrong)
        assert response.status_code == 401
        challenge = context.challenge_request.model_dump(mode="json", by_alias=True)
        challenge["profile"] = "diligence"
        response = client.post("/challenge", headers={"Authorization": f"Bearer {token}"}, json=challenge)
        assert response.status_code == 401
        assert context.backend.calls == []
        response = client.post("/verify", headers={"Authorization": f"Bearer {token}"}, json=payload)
        assert response.status_code == 200


@pytest.mark.parametrize("kind,token", [("artifact_recipient", ARTIFACT_TOKEN), ("arena", ARENA_TOKEN)])
def test_recipient_bearer_cannot_request_diligence_signature(tmp_path, kind, token):
    context = make_context(tmp_path, **{kind: True})
    setting = "artifact_recipient_auth_token" if kind == "artifact_recipient" else "arena_recipient_auth_token"
    with TestClient(_create_app(runtime_for(context, **{setting: token}))) as client:
        payload = fresh_payload(client, context, token)
        modified = deepcopy(payload)
        modified["result_authorization"] = {
            "schema": "dnai.diligence-qvl-result-authorization-request.v1", "deal_id": 17,
            "evaluator_policy_commitment": "0x" + "bb" * 32,
            "result_hash": "0x" + "cc" * 32,
            "authorization_expiry": context.challenge.expires_at - 1,
        }
        response = client.post("/verify", headers={"Authorization": f"Bearer {token}"}, json=modified)
        assert response.status_code == 401
        assert context.backend.calls == []
        assert client.post("/verify", headers={"Authorization": f"Bearer {token}"}, json=payload).status_code == 200


@pytest.mark.parametrize("field", ["result_authorization", "compute_authorization", "royalty_authorization", "compute_workload_recipient"])
@pytest.mark.parametrize("kind", ["artifact_recipient", "arena"])
def test_recipient_scope_rejects_every_extra_authority_payload(tmp_path, field, kind):
    context = make_context(tmp_path, **{kind: True})
    with pytest.raises(Unauthorized):
        _require_recipient_scope(kind, context.request().model_copy(update={field: object()}))


@pytest.mark.parametrize("tokens", [
    {"artifact_recipient_auth_token": ARTIFACT_TOKEN},
    {"arena_recipient_auth_token": ARENA_TOKEN},
    {"artifact_recipient_auth_token": TOKEN},
    {"artifact_recipient_auth_token": "short"},
])
def test_runtime_rejects_unbound_duplicate_or_malformed_recipient_credentials(tmp_path, tokens):
    context = make_context(tmp_path)
    with pytest.raises(VerifierUnavailable):
        _create_app(runtime_for(context, **tokens))


def test_recipient_credentials_are_not_interchangeable_between_qvl_roots(tmp_path):
    context = make_context(tmp_path, artifact_recipient=True)
    with TestClient(_create_app(runtime_for(context, artifact_recipient_auth_token=ARTIFACT_TOKEN))) as client:
        response = client.post("/challenge", headers={"Authorization": f"Bearer {ARENA_TOKEN}", "Content-Type": "application/json"}, content=b"not-json")
        assert response.status_code == 401
