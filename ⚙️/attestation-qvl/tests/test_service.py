from __future__ import annotations

import asyncio
import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from attestation_qvl.errors import (
    CapacityExceeded,
    InvalidRequest,
    RequestTooLarge,
    Unauthorized,
    VerifierUnavailable,
)
from attestation_qvl.models import IdentityAttestationResponse, MAX_BODY_BYTES
from attestation_qvl.service import (
    GlobalCapacityGate,
    Runtime,
    _authenticate,
    _bounded_body,
    _create_app,
    _parse_challenge_request,
    _parse_identity_attestation_request,
    _parse_verification_request,
)
from tests.support import (
    CEREMONY_NONCE,
    DEPLOYMENT_INTENT_SHA256,
    MEASUREMENT_POLICY_SHA256,
    RELEASE_AUTHORITY_SHA256,
    TOKEN,
    make_context,
)
from attestation_qvl.challenge import activation_challenge_digest
from attestation_qvl.models import IdentityAttestationRequest
from attestation_qvl.qvl import VerifiedQuote


class FakeIdentityAttestor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def attest(self, **values: object) -> IdentityAttestationResponse:
        self.calls.append((values["verifier_address"], values["policy_hash"]))
        request = values["request"]
        assert isinstance(request, IdentityAttestationRequest)
        quote = bytes.fromhex("45" * 1024)
        return IdentityAttestationResponse(
            schema="dnai.qvl-identity-attestation-response.v3",
            chain_id=request.chain_id,
            domain=request.domain,
            profile=request.profile,
            cvm_id=request.cvm_id,
            deployment_intent_sha256=request.deployment_intent_sha256,
            release_authority_sha256=request.release_authority_sha256,
            ceremony_nonce=request.ceremony_nonce,
            measurement_policy_sha256=request.measurement_policy_sha256,
            verifier_address=values["verifier_address"],
            release_policy_hash=values["policy_hash"],
            report_data="0x" + "12" * 32,
            quote_report_data="0x" + "12" * 32 + request.challenge_digest[2:],
            challenge_id=request.challenge_id,
            challenge_digest=request.challenge_digest,
            challenge_issued_at=request.issued_at,
            challenge_expires_at=request.expires_at,
            quote="0x" + quote.hex(),
            quote_hash="0x" + hashlib.sha256(quote).hexdigest(),
            quote_size=len(quote),
            app_id=request.app_id,
            compose_hash=request.compose_hash,
            os_image_hash=request.os_image_hash,
            raw_secret_egress=False,
        )


def _client(
    context,
    *,
    attestor=None,
    maximum=4,
    capacity=30,
    request_body_timeout_seconds=5.0,
    verification_timeout_seconds=5.0,
) -> TestClient:
    runtime = Runtime(
        release=context.release,
        verifier=context.verifier,
        auth_token=TOKEN,
        identity_attestor=attestor,
        challenge_store=context.challenge_store,
        max_concurrency=maximum,
        rate_capacity=capacity,
        rate_refill_per_second=0.5,
        request_body_timeout_seconds=request_body_timeout_seconds,
        verification_timeout_seconds=verification_timeout_seconds,
    )
    assert TOKEN not in repr(runtime)
    return TestClient(_create_app(runtime), raise_server_exceptions=False)


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}"}


def _fresh_request(client: TestClient, context) -> dict[str, object]:
    challenge_response = client.post(
        "/challenge",
        headers=_auth(),
        json=context.challenge_request.model_dump(mode="json", by_alias=True),
    )
    assert challenge_response.status_code == 200
    challenge = challenge_response.json()
    payload = deepcopy(context.request_payload)
    payload["challenge"] = challenge
    payload["expectation"]["quote_report_data"] = (
        payload["expectation"]["report_data"] + challenge["challenge_digest"][2:]
    )
    context.backend.result = VerifiedQuote(
        quote_type=context.backend.result.quote_type,
        status=context.backend.result.status,
        report_data=context.report_data + bytes.fromhex(challenge["challenge_digest"][2:]),
        measurements=context.backend.result.measurements,
    )
    return payload


def _activation_request() -> dict[str, object]:
    unsigned = {
        "schema": "dnai.qvl-identity-attestation-request.v3",
        "chain_id": 84_532,
        "domain": "diligence_qvl_cvm",
        "profile": "diligence",
        "cvm_id": "cvm-diligence-qvl-0001",
        "deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
        "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
        "ceremony_nonce": CEREMONY_NONCE,
        "measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
        "app_id": "51" * 20,
        "compose_hash": "52" * 32,
        "os_image_hash": "53" * 32,
        "challenge_id": "0x" + "78" * 32,
        "issued_at": int(__import__("time").time()) - 1,
        "expires_at": int(__import__("time").time()) + 60,
    }
    model = IdentityAttestationRequest.model_validate(
        {**unsigned, "challenge_digest": "0x" + "01" * 32}, strict=True
    )
    return {**unsigned, "challenge_digest": activation_challenge_digest(model)}


def test_live_http_surface_returns_bounded_identity_and_exact_verdict(tmp_path):
    context = make_context(tmp_path)
    with _client(context) as client:
        health = client.get("/health")
        identity = client.get("/identity")
        response = client.post("/verify", headers=_auth(), json=_fresh_request(client, context))

    assert health.json() == {"status": "ok"}
    assert identity.json() == {
        "schema": "dnai.attestation-qvl-identity.v1",
        "verifier_address": context.signer.address,
        "release_policy_hash": context.release.policy_hash,
        "signer_custody": "dstack_derived_separate_cvm",
        "raw_secret_egress": False,
    }
    assert response.status_code == 200
    assert response.json()["schema"] == "dnai.independent-tdx-verdict.v4"
    assert "quote" not in response.json()
    for result in (health, identity, response):
        assert result.headers["cache-control"] == "no-store"
        assert result.headers["x-content-type-options"] == "nosniff"
        assert result.headers["x-frame-options"] == "DENY"
        assert result.headers["referrer-policy"] == "no-referrer"


def test_one_diligence_qvl_root_issues_both_diligence_and_email_restart_profiles(tmp_path):
    context = make_context(tmp_path, email_restart=True)
    with _client(context) as client:
        diligence = client.post(
            "/challenge",
            headers=_auth(),
            json={
                **context.challenge_request.model_dump(mode="json", by_alias=True),
                "profile": "diligence",
            },
        )
        email_payload = _fresh_request(client, context)
        email_verdict = client.post("/verify", headers=_auth(), json=email_payload)

    assert diligence.status_code == 200
    assert diligence.json()["profile"] == "diligence"
    assert diligence.json()["verifier_address"] == context.signer.address
    assert diligence.json()["release_policy_hash"] == context.release.policy_hash
    assert email_verdict.status_code == 200
    assert email_verdict.json()["profile"] == "email_oracle_kms_restart"
    assert email_verdict.json()["verifier_address"] == context.signer.address
    assert email_verdict.json()["release_policy_hash"] == context.release.policy_hash


@pytest.mark.parametrize("authorization", [None, "", "Basic abc", "Bearer wrong"])
def test_authentication_fails_before_body_or_qvl_work(tmp_path, authorization):
    context = make_context(tmp_path)
    headers = {} if authorization is None else {"Authorization": authorization}
    with _client(context) as client:
        response = client.post("/verify", headers=headers, content=b"not even json")
    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}
    assert response.headers["www-authenticate"] == "Bearer"
    assert context.backend.calls == []


@pytest.mark.parametrize("path", ["/challenge", "/verify", "/attestation"])
def test_every_sensitive_route_authenticates_before_parsing_body(tmp_path, path):
    context = make_context(tmp_path)
    with _client(context, attestor=FakeIdentityAttestor()) as client:
        response = client.post(
            path,
            headers={"Content-Type": "application/json"},
            content=b"not-json-and-must-not-be-parsed",
        )
    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}
    assert context.backend.calls == []


def test_non_ascii_bearer_is_a_fixed_unauthorized_failure():
    with pytest.raises(Unauthorized):
        _authenticate("Bearer " + "é" * 32, TOKEN)


@pytest.mark.parametrize(
    ("headers", "content", "status", "code"),
    [
        ({}, b"{}", 400, "invalid_request"),
        ({"Content-Type": "text/plain"}, b"{}", 400, "invalid_request"),
        ({"Content-Type": "application/json", "Content-Encoding": "gzip"}, b"{}", 400, "invalid_request"),
        ({"Content-Type": "application/json"}, b"", 400, "invalid_request"),
        ({"Content-Type": "application/json"}, b"x" * (MAX_BODY_BYTES + 1), 413, "request_too_large"),
    ],
)
def test_body_boundary_is_strict_and_bounded(tmp_path, headers, content, status, code):
    context = make_context(tmp_path)
    request_headers = {**_auth(), **headers}
    with _client(context) as client:
        response = client.post("/verify", headers=request_headers, content=content)
    assert response.status_code == status
    assert response.json() == {"error": code}
    assert context.backend.calls == []


def test_duplicate_json_and_strict_wire_types_are_fixed_invalid_requests(tmp_path):
    context = make_context(tmp_path)
    raw = json.dumps(context.request_payload, separators=(",", ":"))
    duplicate = raw.replace(
        '{"schema":',
        '{"schema":"dnai.independent-tdx-verification-request.v1","schema":',
        1,
    )
    wrong_type = deepcopy(context.request_payload)
    wrong_type["expectation"]["chain_id"] = "84532"
    with _client(context) as client:
        duplicate_response = client.post(
            "/verify",
            headers={**_auth(), "Content-Type": "application/json"},
            content=duplicate,
        )
        type_response = client.post("/verify", headers=_auth(), json=wrong_type)
    assert duplicate_response.json() == {"error": "invalid_request"}
    assert type_response.json() == {"error": "invalid_request"}
    assert context.backend.calls == []


@pytest.mark.asyncio
async def test_body_reader_times_out_and_prechecks_chunk_before_extend():
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/verify",
        "headers": [(b"content-type", b"application/json")],
    }

    async def delayed_receive():
        await asyncio.sleep(1)
        return {"type": "http.request", "body": b"{}", "more_body": False}

    with pytest.raises(InvalidRequest):
        await _bounded_body(Request(scope, delayed_receive), timeout_seconds=0.01)

    class OversizedRequest:
        headers = {"content-type": "application/json"}

        async def stream(self):
            yield b"{" + b"x" * MAX_BODY_BYTES

    with pytest.raises(RequestTooLarge):
        await _bounded_body(OversizedRequest(), timeout_seconds=1)


def test_recursive_json_failures_map_to_fixed_invalid_request(monkeypatch):
    def recurse(_raw):
        raise RecursionError

    monkeypatch.setattr("attestation_qvl.service.parse_duplicate_free_json", recurse)
    for parser in (
        _parse_verification_request,
        _parse_challenge_request,
        _parse_identity_attestation_request,
    ):
        with pytest.raises(InvalidRequest):
            parser(b"{}")


def test_verification_and_backend_failures_never_echo_details(tmp_path):
    context = make_context(tmp_path)
    mismatch = deepcopy(context.request_payload)
    mismatch["expectation"]["compose_hash"] = "0x" + "99" * 32
    with _client(context) as client:
        fresh = _fresh_request(client, context)
        fresh["expectation"]["compose_hash"] = mismatch["expectation"]["compose_hash"]
        rejected = client.post("/verify", headers=_auth(), json=fresh)
        context.backend.error = VerifierUnavailable("do not expose PCCS detail")
        unavailable = client.post("/verify", headers=_auth(), json=_fresh_request(client, context))
    assert rejected.status_code == 400
    assert rejected.json() == {"error": "verification_rejected"}
    assert unavailable.status_code == 503
    assert unavailable.json() == {"error": "verifier_unavailable"}
    assert "PCCS" not in unavailable.text
    assert context.request_payload["quote"] not in unavailable.text


def test_challenge_replay_is_rejected_before_second_backend_call(tmp_path):
    context = make_context(tmp_path)
    with _client(context) as client:
        payload = _fresh_request(client, context)
        accepted = client.post("/verify", headers=_auth(), json=payload)
        replayed = client.post("/verify", headers=_auth(), json=payload)

    assert accepted.status_code == 200
    assert replayed.status_code == 400
    assert replayed.json() == {"error": "verification_rejected"}
    assert context.backend.calls == [context.raw_quote]


def test_wrong_challenge_profile_policy_digest_and_signature_fail_before_qvl(tmp_path):
    context = make_context(tmp_path)
    with _client(context) as client:
        payload = _fresh_request(client, context)
        challenge = payload["challenge"]
        mutations = (
            ("profile", "arena"),
            ("release_policy_hash", "0x" + "12" * 32),
            ("challenge_digest", "0x" + "34" * 32),
            ("verifier_signature", "0x" + "56" * 65),
            ("domain", "independent_metering_cvm"),
            ("cvm_id", "cvm-cross-domain-0001"),
            ("release_authority_sha256", "sha256:" + "57" * 32),
        )
        for field, value in mutations:
            hostile = deepcopy(payload)
            hostile["challenge"][field] = value
            rejected = client.post("/verify", headers=_auth(), json=hostile)
            assert rejected.status_code == 400
            assert rejected.json() == {"error": "verification_rejected"}
        accepted = client.post("/verify", headers=_auth(), json=payload)

    assert accepted.status_code == 200
    assert context.backend.calls == [context.raw_quote]


def test_expired_challenge_is_rejected_before_qvl(tmp_path):
    context = make_context(tmp_path)
    clock = [1_800_000_000]
    context.challenge_store._clock = lambda: clock[0]
    with _client(context) as client:
        payload = _fresh_request(client, context)
        clock[0] = payload["challenge"]["expires_at"]
        response = client.post("/verify", headers=_auth(), json=payload)

    assert response.status_code == 400
    assert response.json() == {"error": "verification_rejected"}
    assert context.backend.calls == []


def test_verification_timeout_consumes_challenge_and_replay_stays_closed(tmp_path):
    context = make_context(tmp_path)

    async def stalled_verification(_request):
        await asyncio.sleep(1)
        raise AssertionError("timeout did not cancel verification")

    context.verifier.verify = stalled_verification
    with _client(context, verification_timeout_seconds=0.01) as client:
        payload = _fresh_request(client, context)
        timed_out = client.post("/verify", headers=_auth(), json=payload)
        replayed = client.post("/verify", headers=_auth(), json=payload)

    assert timed_out.status_code == 503
    assert timed_out.json() == {"error": "verifier_unavailable"}
    assert replayed.status_code == 400
    assert replayed.json() == {"error": "verification_rejected"}
    assert context.backend.calls == []


def test_optional_identity_attestation_and_fixed_route_errors(tmp_path):
    context = make_context(tmp_path)
    attestor = FakeIdentityAttestor()
    with _client(context, attestor=attestor) as client:
        response = client.post("/attestation", headers=_auth(), json=_activation_request())
        missing = client.get("/missing")
        wrong_method = client.put("/health")
    assert response.status_code == 200
    assert response.json()["schema"] == "dnai.qvl-identity-attestation-response.v3"
    assert attestor.calls == [(context.signer.address, context.release.policy_hash)]
    assert missing.status_code == 404 and missing.json() == {"error": "not_found"}
    assert wrong_method.status_code == 405 and wrong_method.json() == {"error": "method_not_allowed"}

    with _client(context) as disabled:
        disabled_response = disabled.post("/attestation", headers=_auth(), json=_activation_request())
        openapi = disabled.get("/openapi.json")
    assert disabled_response.status_code == 404
    assert disabled_response.json() == {"error": "not_enabled"}
    assert openapi.json() == {"error": "not_found"}


def test_identity_attestation_requires_external_fresh_challenge_binding(tmp_path):
    context = make_context(tmp_path)
    attestor = FakeIdentityAttestor()
    wrong_digest = _activation_request()
    wrong_digest["challenge_digest"] = "0x" + "12" * 32
    expired = {
        **_activation_request(),
        "challenge_id": "0x" + "34" * 32,
        "challenge_digest": "0x" + "01" * 32,
        "issued_at": 1_700_000_000,
        "expires_at": 1_700_000_060,
    }
    expired_model = IdentityAttestationRequest.model_validate(expired, strict=True)
    expired["challenge_digest"] = activation_challenge_digest(expired_model)

    with _client(context, attestor=attestor) as client:
        wrong_response = client.post(
            "/attestation", headers=_auth(), json=wrong_digest
        )
        expired_response = client.post(
            "/attestation", headers=_auth(), json=expired
        )

    assert wrong_response.status_code == 400
    assert wrong_response.json() == {"error": "verification_rejected"}
    assert expired_response.status_code == 400
    assert expired_response.json() == {"error": "verification_rejected"}
    assert attestor.calls == []


def test_identity_attestation_rejects_non_exact_or_cross_domain_lineage(tmp_path):
    context = make_context(tmp_path)
    attestor = FakeIdentityAttestor()
    missing = _activation_request()
    missing.pop("release_authority_sha256")
    unexpected = {**_activation_request(), "legacy_cvm_name": "qvl"}
    cross_domain = {
        **_activation_request(),
        "domain": "arena_qvl_cvm",
    }
    cross_model = IdentityAttestationRequest.model_validate(
        cross_domain, strict=True
    )
    cross_domain["challenge_digest"] = activation_challenge_digest(cross_model)
    wrong_chain = {**_activation_request(), "chain_id": 1}
    chain_model = IdentityAttestationRequest.model_validate(wrong_chain, strict=True)
    wrong_chain["challenge_digest"] = activation_challenge_digest(chain_model)

    with _client(context, attestor=attestor) as client:
        responses = {
            "missing": client.post("/attestation", headers=_auth(), json=missing),
            "unexpected": client.post(
                "/attestation", headers=_auth(), json=unexpected
            ),
            "cross_domain": client.post(
                "/attestation", headers=_auth(), json=cross_domain
            ),
            "wrong_chain": client.post(
                "/attestation", headers=_auth(), json=wrong_chain
            ),
        }

    assert responses["missing"].json() == {"error": "invalid_request"}
    assert responses["unexpected"].json() == {"error": "invalid_request"}
    assert responses["cross_domain"].json() == {
        "error": "verification_rejected"
    }
    assert responses["wrong_chain"].json() == {"error": "invalid_request"}
    assert attestor.calls == []


@pytest.mark.asyncio
async def test_global_gate_fails_fast_for_concurrency_and_rate(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("attestation_qvl.service.time.monotonic", lambda: now[0])
    gate = GlobalCapacityGate(maximum=1, capacity=2, refill_per_second=1.0)

    await gate.enter()
    with pytest.raises(CapacityExceeded):
        await gate.enter()
    await gate.exit()
    await gate.enter()
    await gate.exit()
    with pytest.raises(CapacityExceeded):
        await gate.enter()
    now[0] += 1.0
    await gate.enter()
    await gate.exit()


def test_production_has_no_quote_logging_sink_and_access_logs_stay_disabled():
    project = Path(__file__).resolve().parents[1]
    production_sources = list((project / "src" / "attestation_qvl").glob("*.py"))
    for source in production_sources:
        text = source.read_text(encoding="utf-8")
        assert "logging." not in text
        assert "logger." not in text
        assert "print(" not in text
    assert "access_log=False" in (project / "src" / "attestation_qvl" / "main.py").read_text()
    assert "--no-access-log" in (project / "Dockerfile").read_text()
