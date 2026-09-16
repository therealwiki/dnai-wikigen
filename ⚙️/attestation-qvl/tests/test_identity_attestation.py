from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from attestation_qvl.errors import VerifierUnavailable
from attestation_qvl.identity_attestation import DstackIdentityAttestor, identity_report_data
from attestation_qvl.models import IdentityAttestationRequest


VERIFIER = "0x" + "12" * 20
POLICY_HASH = "0x" + "34" * 32
CHALLENGE_ID = "0x" + "56" * 32
CHALLENGE_DIGEST = "0x" + "78" * 32
REQUEST = IdentityAttestationRequest.model_validate({
    "schema": "dnai.qvl-identity-attestation-request.v3",
    "chain_id": 84_532,
    "domain": "diligence_qvl_cvm",
    "profile": "diligence",
    "cvm_id": "cvm-diligence-qvl-0001",
    "deployment_intent_sha256": "sha256:" + "41" * 32,
    "release_authority_sha256": "sha256:" + "42" * 32,
    "ceremony_nonce": "0x" + "43" * 32,
    "measurement_policy_sha256": "sha256:" + "44" * 32,
    "app_id": "12" * 20,
    "compose_hash": "67" * 32,
    "os_image_hash": "89" * 32,
    "challenge_id": CHALLENGE_ID,
    "challenge_digest": CHALLENGE_DIGEST,
    "issued_at": 1_800_000_000,
    "expires_at": 1_800_000_060,
}, strict=True)
IDENTITY_ARGS = {
    "request": REQUEST,
    "verifier_address": VERIFIER,
    "policy_hash": POLICY_HASH,
}


def test_identity_attestor_accepts_native_dstack_unprefixed_quote_and_checks_binding(monkeypatch):
    report_data = identity_report_data(**IDENTITY_ARGS)
    raw_quote = bytes.fromhex("45" * 2048)
    calls: list[bytes] = []

    class Client:
        def is_reachable(self) -> bool:
            return True

        def info(self) -> object:
            return SimpleNamespace(
                app_id="12" * 20,
                compose_hash="67" * 32,
                os_image_hash="89" * 32,
            )

        def get_quote(self, value: bytes) -> object:
            calls.append(value)
            return SimpleNamespace(quote=raw_quote.hex())

    parsed = SimpleNamespace(
        is_tdx=lambda: True,
        quote_type=lambda: "TDX",
        report=SimpleNamespace(report_data=report_data + bytes.fromhex(CHALLENGE_DIGEST[2:])),
    )
    monkeypatch.setattr("attestation_qvl.identity_attestation.DstackClient", Client)
    monkeypatch.setattr("attestation_qvl.identity_attestation.dcap_qvl.parse_quote", lambda value: parsed)

    response = DstackIdentityAttestor().attest(
        verifier_address=VERIFIER,
        policy_hash=POLICY_HASH,
        request=REQUEST,
    )
    public = response.model_dump(mode="json", by_alias=True)
    assert calls == [report_data + bytes.fromhex(CHALLENGE_DIGEST[2:])]
    assert public["quote"] == "0x" + raw_quote.hex()
    assert public["quote_hash"] == "0x" + hashlib.sha256(raw_quote).hexdigest()
    assert public["quote_size"] == len(raw_quote)
    assert public["report_data"] == "0x" + report_data.hex()
    assert public["quote_report_data"] == "0x" + report_data.hex() + CHALLENGE_DIGEST[2:]
    assert public["compose_hash"] == "67" * 32
    assert public["release_authority_sha256"] == REQUEST.release_authority_sha256
    assert public["measurement_policy_sha256"] == REQUEST.measurement_policy_sha256


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("chain_id", 1),
        ("domain", "arena_qvl_cvm"),
        ("profile", "arena"),
        ("cvm_id", "cvm-diligence-qvl-0002"),
        ("deployment_intent_sha256", "sha256:" + "51" * 32),
        ("release_authority_sha256", "sha256:" + "52" * 32),
        ("ceremony_nonce", "0x" + "53" * 32),
        ("measurement_policy_sha256", "sha256:" + "54" * 32),
        ("app_id", "55" * 20),
        ("compose_hash", "56" * 32),
        ("os_image_hash", "57" * 32),
    ],
)
def test_identity_report_data_commits_every_release_and_runtime_binding(field, value):
    baseline = identity_report_data(**IDENTITY_ARGS)
    mutated = REQUEST.model_copy(update={field: value})
    assert identity_report_data(
        request=mutated,
        verifier_address=VERIFIER,
        policy_hash=POLICY_HASH,
    ) != baseline


@pytest.mark.parametrize(
    ("verifier_address", "policy_hash"),
    [
        ("0x" + "13" * 20, POLICY_HASH),
        (VERIFIER, "0x" + "35" * 32),
    ],
)
def test_identity_report_data_commits_verifier_and_release_policy(
    verifier_address, policy_hash
):
    assert identity_report_data(
        request=REQUEST,
        verifier_address=verifier_address,
        policy_hash=policy_hash,
    ) != identity_report_data(**IDENTITY_ARGS)


@pytest.mark.parametrize("name", ["DSTACK_SIMULATOR_ENDPOINT", "TAPPD_SIMULATOR_ENDPOINT"])
def test_identity_attestor_rejects_simulator(monkeypatch, name):
    monkeypatch.setenv(name, "http://127.0.0.1:8090")
    with pytest.raises(VerifierUnavailable):
        DstackIdentityAttestor()


@pytest.mark.parametrize(
    ("is_tdx", "quote_type", "padding"),
    [
        (False, "SGX", bytes(32)),
        (True, "TDX", bytes.fromhex("01" * 32)),
    ],
)
def test_identity_attestor_rejects_non_tdx_or_wrong_report_binding(monkeypatch, is_tdx, quote_type, padding):
    report_data = identity_report_data(**IDENTITY_ARGS)
    raw_quote = bytes.fromhex("45" * 2048)

    class Client:
        def is_reachable(self) -> bool:
            return True

        def info(self) -> object:
            return SimpleNamespace(app_id="12" * 20, compose_hash="67" * 32, os_image_hash="89" * 32)

        def get_quote(self, _value: bytes) -> object:
            return SimpleNamespace(quote=raw_quote.hex())

    parsed = SimpleNamespace(
        is_tdx=lambda: is_tdx,
        quote_type=lambda: quote_type,
        report=SimpleNamespace(report_data=report_data + padding),
    )
    monkeypatch.setattr("attestation_qvl.identity_attestation.DstackClient", Client)
    monkeypatch.setattr("attestation_qvl.identity_attestation.dcap_qvl.parse_quote", lambda _value: parsed)
    with pytest.raises(VerifierUnavailable):
        DstackIdentityAttestor().attest(
            verifier_address=VERIFIER,
            policy_hash=POLICY_HASH,
            request=REQUEST,
        )
