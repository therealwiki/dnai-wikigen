from __future__ import annotations

import json
import hashlib
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from compute_metering.errors import CapacityExceeded, SignerUnavailable, Unauthorized
from compute_metering.models import (
    MAX_BODY_BYTES,
    ComputeMeteringQvlVerdict,
    ComputeQvlChallenge,
    MeteringIdentityAttestation,
)
from compute_metering.service import GlobalCapacityGate, Runtime, _authenticate, _create_app
from tests.support import (
    CEREMONY_NONCE,
    DEPLOYMENT_INTENT_SHA256,
    MEASUREMENT_POLICY_SHA256,
    METER,
    METERING_APP_ID,
    METERING_CVM_ID,
    METERING_OS_IMAGE_HASH,
    RELEASE_AUTHORITY_SHA256,
    TOKEN,
    VAULT,
    make_context,
)


class FakeIdentityAttestor:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def attest(self, **values: object) -> MeteringIdentityAttestation:
        self.calls.append(values)
        raw_quote = bytes.fromhex("45" * 1024)
        report_data = "0x" + "67" * 32
        return MeteringIdentityAttestation(
            schema="dnai.compute-metering-identity-attestation.v2",
            challenge=values["challenge"],
            mode="tdx",
            metering_verifier=values["metering_verifier"],
            chain_id=values["chain_id"],
            vault_address=values["vault_address"],
            policy_set_hash=values["policy_set_hash"],
            signer_custody=values["signer_custody"],
            report_data=report_data,
            quote_report_data=report_data + values["challenge"].challenge_digest[2:],
            quote="0x" + raw_quote.hex(),
            quote_hash="0x" + hashlib.sha256(raw_quote).hexdigest(),
            quote_size=len(raw_quote),
            app_id=METERING_APP_ID,
            compose_hash="0x" + "89" * 32,
            os_image_hash=METERING_OS_IMAGE_HASH,
            raw_secret_egress=False,
        )


class FakeIdentityQvlClient:
    def __init__(self) -> None:
        now = int(time.time())
        self.challenge = ComputeQvlChallenge(
            schema="dnai.attestation-qvl-challenge.v2",
            chain_id=84_532,
            domain="independent_metering_cvm",
            profile="compute_metering",
            cvm_id=METERING_CVM_ID,
            deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
            release_authority_sha256=RELEASE_AUTHORITY_SHA256,
            ceremony_nonce=CEREMONY_NONCE,
            measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
            release_policy_hash="0x" + "56" * 32,
            challenge_id="0x" + "67" * 32,
            challenge_digest="0x" + "78" * 32,
            issued_at=now - 1,
            expires_at=now + 60,
            verifier_address="0x" + "89" * 20,
            verifier_signature="0x" + "9a" * 65,
        )
        self.closed = False

    def issue_challenge(self):
        return self.challenge

    def verify(self, packet: MeteringIdentityAttestation):
        return ComputeMeteringQvlVerdict(
            schema="dnai.independent-tdx-verdict.v4",
            verification_method="intel_tdx_dcap_qvl",
            verified=True,
            chain_id=self.challenge.chain_id,
            domain=self.challenge.domain,
            profile="compute_metering",
            cvm_id=self.challenge.cvm_id,
            deployment_intent_sha256=(
                self.challenge.deployment_intent_sha256
            ),
            release_authority_sha256=(
                self.challenge.release_authority_sha256
            ),
            ceremony_nonce=self.challenge.ceremony_nonce,
            measurement_policy_sha256=(
                self.challenge.measurement_policy_sha256
            ),
            release_policy_hash=self.challenge.release_policy_hash,
            challenge_id=self.challenge.challenge_id,
            challenge_digest=self.challenge.challenge_digest,
            challenge_issued_at=self.challenge.issued_at,
            challenge_expires_at=self.challenge.expires_at,
            quote_hash=packet.quote_hash,
            report_data=packet.report_data,
            compose_hash=packet.compose_hash,
            app_id=packet.app_id,
            os_image_hash=packet.os_image_hash,
            signer_address=packet.metering_verifier,
            contract_address=packet.vault_address,
            issued_at=self.challenge.issued_at,
            activation_evidence_lease_expires_at=self.challenge.expires_at,
            expires_at=self.challenge.expires_at,
            verifier_address=self.challenge.verifier_address,
            verifier_signature="0x" + "ab" * 65,
        )

    def close(self):
        self.closed = True


def _runtime(context, *, attestor=None, qvl=None, maximum=4, capacity=30):
    return Runtime(
        release=context.release,
        meter=context.meter,
        rpc=context.rpc,
        replay=context.replay,
        auth_token=TOKEN,
        identity_attestor=attestor,
        identity_qvl_client=(qvl if qvl is not None else (FakeIdentityQvlClient() if attestor else None)),
        max_concurrency=maximum,
        rate_capacity=capacity,
        rate_refill_per_second=0.5,
        request_body_timeout_seconds=5.0,
    )


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}"}


def test_live_surface_returns_two_asset_identity_and_canonical_decision(tmp_path):
    context = make_context(tmp_path)
    runtime = _runtime(context)
    assert TOKEN not in repr(runtime)
    with TestClient(_create_app(runtime), raise_server_exceptions=False) as client:
        health = client.get("/health")
        identity = client.get("/identity")
        first = client.post("/meter", headers=_auth(), json=context.request_payload)
        second = client.post("/meter", headers=_auth(), json=context.request_payload)

    assert health.json() == {"status": "ok"}
    assert identity.status_code == 200
    identity_payload = identity.json()
    assert identity_payload["schema"] == "dnai.compute-metering-identity.v1"
    assert identity_payload["policy_set_hash"] == context.release.policy_set_hash
    assert identity_payload["signer_custody"] == "dstack_derived_independent_cvm"
    assert len(identity_payload["assets"]) == 2
    assert all(entry["provider"] for entry in identity_payload["assets"])
    assert first.status_code == 200 and first.content == second.content
    assert first.content == json.dumps(first.json(), sort_keys=True, separators=(",", ":")).encode()
    assert first.json()["classification"] == "attested_dual_verified_metering"
    assert first.json()["provider_authoritative_invoice"] is False
    assert context.rpc.started and context.rpc.closed
    for response in (health, identity, first, second):
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"


def test_bearer_authenticated_attestation_binds_exact_runtime_identity(tmp_path):
    context = make_context(tmp_path)
    attestor = FakeIdentityAttestor()
    with TestClient(
        _create_app(_runtime(context, attestor=attestor)),
        raise_server_exceptions=False,
    ) as client:
        unauthorized = client.get("/attestation")
        response = client.get("/attestation", headers=_auth())

    assert unauthorized.status_code == 401
    assert unauthorized.json() == {"error": "unauthorized"}
    assert len(attestor.calls) == 1
    assert attestor.calls[0] == {
        "metering_verifier": METER,
        "chain_id": 84_532,
        "vault_address": VAULT,
        "policy_set_hash": context.release.policy_set_hash,
        "signer_custody": "dstack_derived_independent_cvm",
        "challenge": attestor.calls[0]["challenge"],
    }
    assert response.status_code == 200
    assert response.json()["schema"] == "dnai.independent-tdx-verdict.v4"
    assert response.json()["signer_address"] == METER
    assert response.headers["cache-control"] == "no-store"


def test_nonproduction_runtime_cannot_emit_attestation(tmp_path):
    context = make_context(tmp_path)
    with TestClient(_create_app(_runtime(context)), raise_server_exceptions=False) as client:
        unauthorized = client.get("/attestation")
        disabled = client.get("/attestation", headers=_auth())
    assert unauthorized.json() == {"error": "unauthorized"}
    assert disabled.status_code == 404
    assert disabled.json() == {"error": "not_enabled"}


def test_attestation_failure_is_fixed_and_does_not_leak_detail(tmp_path):
    context = make_context(tmp_path)

    class UnavailableAttestor:
        def attest(self, **_values):
            raise SignerUnavailable("private dstack socket detail")

    with TestClient(
        _create_app(_runtime(context, attestor=UnavailableAttestor())),
        raise_server_exceptions=False,
    ) as client:
        response = client.get("/attestation", headers=_auth())
    assert response.status_code == 503
    assert response.json() == {"error": "signer_unavailable"}
    assert "private" not in response.text


@pytest.mark.parametrize("authorization", [None, "", "Basic abc", "Bearer wrong"])
def test_authentication_precedes_body_and_chain_work(tmp_path, authorization):
    context = make_context(tmp_path)
    headers = {} if authorization is None else {"Authorization": authorization}
    with TestClient(_create_app(_runtime(context)), raise_server_exceptions=False) as client:
        response = client.post("/meter", headers=headers, content=b"not json")
    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}
    assert response.headers["www-authenticate"] == "Bearer"
    assert context.rpc.chain_id_calls == 0


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
def test_request_body_boundary_is_strict_and_fixed(tmp_path, headers, content, status, code):
    context = make_context(tmp_path)
    with TestClient(_create_app(_runtime(context)), raise_server_exceptions=False) as client:
        response = client.post("/meter", headers={**_auth(), **headers}, content=content)
    assert response.status_code == status
    assert response.json() == {"error": code}
    assert context.rpc.chain_id_calls == 0


def test_duplicate_json_strict_types_and_route_errors_are_bounded(tmp_path):
    context = make_context(tmp_path)
    raw = json.dumps(context.request_payload, separators=(",", ":"))
    duplicate = raw.replace(
        '{"schema":',
        '{"schema":"dnai.compute-metering-request.v1","schema":',
        1,
    )
    wrong = json.loads(raw)
    wrong["block"]["number"] = str(wrong["block"]["number"])
    with TestClient(_create_app(_runtime(context)), raise_server_exceptions=False) as client:
        duplicate_response = client.post(
            "/meter",
            headers={**_auth(), "Content-Type": "application/json"},
            content=duplicate,
        )
        wrong_response = client.post("/meter", headers=_auth(), json=wrong)
        missing = client.get("/missing")
        method = client.put("/health")
        docs = client.get("/openapi.json")
    assert duplicate_response.json() == {"error": "invalid_request"}
    assert wrong_response.json() == {"error": "invalid_request"}
    assert missing.json() == docs.json() == {"error": "not_found"}
    assert method.json() == {"error": "method_not_allowed"}


@pytest.mark.asyncio
async def test_global_gate_fails_fast_for_concurrency_and_rate(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("compute_metering.service.time.monotonic", lambda: now[0])
    gate = GlobalCapacityGate(maximum=1, capacity=2, refill_per_second=1.0)
    await gate.enter()
    with pytest.raises(CapacityExceeded):
        await gate.enter()
    await gate.exit()
    await gate.enter()
    await gate.exit()
    with pytest.raises(CapacityExceeded):
        await gate.enter()
    now[0] += 1
    await gate.enter()
    await gate.exit()


def test_nonascii_bearer_is_fixed_unauthorized():
    with pytest.raises(Unauthorized):
        _authenticate("Bearer " + "é" * 32, TOKEN)


def test_production_sources_have_no_request_logging_or_access_logs():
    project = Path(__file__).resolve().parents[1]
    for source in (project / "src" / "compute_metering").glob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert "logging." not in text
        assert "logger." not in text
        assert "print(" not in text
    assert "access_log=False" in (project / "src" / "compute_metering" / "main.py").read_text()
    assert "--no-access-log" in (project / "Dockerfile").read_text()
    service = (project / "src" / "compute_metering" / "service.py").read_text()
    assert "identity_attestor = DstackMeteringIdentityAttestor()" in service
    assert "identity_attestor=identity_attestor" in service
    assert "qvl_client=identity_qvl_client" in service
