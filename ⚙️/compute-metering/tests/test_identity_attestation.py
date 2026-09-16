from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from compute_metering.errors import SignerUnavailable
from compute_metering.identity_attestation import (
    DSTACK_METERING_CUSTODY,
    DstackMeteringIdentityAttestor,
    HttpsComputeMeteringQvlClient,
    compute_qvl_challenge_digest,
    compute_qvl_verdict_digest,
    independent_qvl_request,
    metering_identity_report_data,
)
from compute_metering.models import ComputeMeteringQvlVerdict, ComputeQvlChallenge
from tests.support import METER, VAULT


POLICY_SET_HASH = "0x" + "34" * 32
NOW = 1_800_000_000
QVL = Account.from_key(bytes.fromhex("ab" * 32))
QVL_POLICY_HASH = "0x" + "56" * 32
METERING_CVM_ID = "cvm-independent-metering-0001"
DEPLOYMENT_INTENT_SHA256 = "sha256:" + "41" * 32
RELEASE_AUTHORITY_SHA256 = "sha256:" + "42" * 32
CEREMONY_NONCE = "0x" + "43" * 32
MEASUREMENT_POLICY_SHA256 = "sha256:" + "44" * 32
APP_ID = "45" * 20
OS_IMAGE_HASH = "46" * 32
CHALLENGE = ComputeQvlChallenge(
    schema="dnai.attestation-qvl-challenge.v2",
    chain_id=84_532,
    domain="independent_metering_cvm",
    profile="compute_metering",
    cvm_id=METERING_CVM_ID,
    deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
    release_authority_sha256=RELEASE_AUTHORITY_SHA256,
    ceremony_nonce=CEREMONY_NONCE,
    measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
    release_policy_hash=QVL_POLICY_HASH,
    challenge_id="0x" + "67" * 32,
    challenge_digest="0x" + "78" * 32,
    issued_at=NOW,
    expires_at=NOW + 60,
    verifier_address="0x" + "89" * 20,
    verifier_signature="0x" + "9a" * 65,
)


def _report_data() -> bytes:
    return metering_identity_report_data(
        metering_verifier=METER,
        chain_id=84_532,
        vault_address=VAULT,
        policy_set_hash=POLICY_SET_HASH,
        signer_custody=DSTACK_METERING_CUSTODY,
    )


def _signed_challenge(**overrides) -> ComputeQvlChallenge:
    values = {
        "schema": "dnai.attestation-qvl-challenge.v2",
        "chain_id": 84_532,
        "domain": "independent_metering_cvm",
        "profile": "compute_metering",
        "cvm_id": METERING_CVM_ID,
        "deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
        "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
        "ceremony_nonce": CEREMONY_NONCE,
        "measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
        "release_policy_hash": QVL_POLICY_HASH,
        "challenge_id": "0x" + "67" * 32,
        "challenge_digest": "0x" + "01" * 32,
        "issued_at": NOW,
        "expires_at": NOW + 120,
        "verifier_address": QVL.address.lower(),
        "verifier_signature": "0x" + "00" * 65,
    }
    values.update(overrides)
    unsigned = ComputeQvlChallenge.model_validate(values, strict=True)
    digest = compute_qvl_challenge_digest(unsigned)
    signature = QVL.sign_message(encode_defunct(hexstr=digest)).signature
    return unsigned.model_copy(
        update={
            "challenge_digest": digest,
            "verifier_signature": "0x" + bytes(signature).hex(),
        }
    )


def _signed_verdict(attestation, challenge, **overrides) -> ComputeMeteringQvlVerdict:
    values = {
        "schema": "dnai.independent-tdx-verdict.v4",
        "verification_method": "intel_tdx_dcap_qvl",
        "verified": True,
        "chain_id": challenge.chain_id,
        "domain": challenge.domain,
        "profile": "compute_metering",
        "cvm_id": challenge.cvm_id,
        "deployment_intent_sha256": challenge.deployment_intent_sha256,
        "release_authority_sha256": challenge.release_authority_sha256,
        "ceremony_nonce": challenge.ceremony_nonce,
        "measurement_policy_sha256": challenge.measurement_policy_sha256,
        "release_policy_hash": challenge.release_policy_hash,
        "challenge_id": challenge.challenge_id,
        "challenge_digest": challenge.challenge_digest,
        "challenge_issued_at": challenge.issued_at,
        "challenge_expires_at": challenge.expires_at,
        "quote_hash": attestation.quote_hash,
        "report_data": attestation.report_data,
        "compose_hash": attestation.compose_hash,
        "app_id": attestation.app_id,
        "os_image_hash": attestation.os_image_hash,
        "signer_address": attestation.metering_verifier,
        "contract_address": attestation.vault_address,
        "issued_at": NOW,
        "expires_at": NOW + 900,
        "verifier_address": QVL.address.lower(),
        "verifier_signature": "0x" + "00" * 65,
    }
    values.update(overrides)
    values.setdefault(
        "activation_evidence_lease_expires_at", values["expires_at"]
    )
    unsigned = ComputeMeteringQvlVerdict.model_validate(values, strict=True)
    signature = QVL.sign_message(
        encode_defunct(hexstr=compute_qvl_verdict_digest(unsigned))
    ).signature
    return unsigned.model_copy(
        update={"verifier_signature": "0x" + bytes(signature).hex()}
    )


def _install_dstack(
    monkeypatch,
    *,
    reachable=True,
    quote=None,
    parsed=None,
    info=None,
    challenge=CHALLENGE,
):
    raw_quote = bytes.fromhex("45" * 2048) if quote is None else quote
    report_data = _report_data()
    calls: list[bytes] = []

    class Client:
        def is_reachable(self) -> bool:
            return reachable

        def info(self) -> object:
            return info or SimpleNamespace(
                app_id=APP_ID,
                compose_hash="67" * 32,
                os_image_hash=OS_IMAGE_HASH,
            )

        def get_quote(self, value: bytes) -> object:
            calls.append(value)
            if isinstance(raw_quote, bytes):
                return SimpleNamespace(quote=raw_quote.hex())
            return SimpleNamespace(quote=raw_quote)

    parsed_quote = parsed or SimpleNamespace(
        is_tdx=lambda: True,
        quote_type=lambda: "TDX",
        report=SimpleNamespace(
            report_data=report_data + bytes.fromhex(challenge.challenge_digest[2:])
        ),
    )
    monkeypatch.setattr("compute_metering.identity_attestation.DstackClient", Client)
    monkeypatch.setattr(
        "compute_metering.identity_attestation.dcap_qvl.parse_quote",
        lambda _raw: parsed_quote,
    )
    return raw_quote, calls


def test_real_dstack_quote_packet_binds_every_metering_authority(monkeypatch):
    raw_quote, calls = _install_dstack(monkeypatch)
    response = DstackMeteringIdentityAttestor().attest(
        metering_verifier=METER,
        chain_id=84_532,
        vault_address=VAULT,
        policy_set_hash=POLICY_SET_HASH,
        signer_custody=DSTACK_METERING_CUSTODY,
        challenge=CHALLENGE,
    )
    public = response.model_dump(mode="json", by_alias=True)
    expected = _report_data()
    assert calls == [expected + bytes.fromhex(CHALLENGE.challenge_digest[2:])]
    assert public["mode"] == "tdx"
    assert public["metering_verifier"] == METER
    assert public["chain_id"] == 84_532
    assert public["vault_address"] == VAULT
    assert public["policy_set_hash"] == POLICY_SET_HASH
    assert public["signer_custody"] == DSTACK_METERING_CUSTODY
    assert public["report_data"] == "0x" + expected.hex()
    assert public["quote_report_data"] == "0x" + expected.hex() + CHALLENGE.challenge_digest[2:]
    assert public["quote_hash"] == "0x" + hashlib.sha256(raw_quote).hexdigest()
    assert public["quote_size"] == len(raw_quote)
    assert public["raw_secret_egress"] is False

    request = independent_qvl_request(response)
    assert request["schema"] == "dnai.independent-tdx-verification-request.v2"
    assert request["quote"] == public["quote"]
    assert request["expectation"]["signer_address"] == METER
    assert request["expectation"]["contract_address"] == VAULT


def test_report_data_has_stable_vector_and_normalizes_hex_case():
    first = _report_data()
    second = metering_identity_report_data(
        metering_verifier=METER.upper().replace("0X", "0x"),
        chain_id=84_532,
        vault_address=VAULT.upper().replace("0X", "0x"),
        policy_set_hash=POLICY_SET_HASH.upper().replace("0X", "0x"),
        signer_custody=DSTACK_METERING_CUSTODY,
    )
    assert first == second
    assert first.hex() == "7c92fea52fac7020aa21bbfbffa4d18dea5f3bfdedde8e5de51a938e5047d291"


@pytest.mark.parametrize("name", ["DSTACK_SIMULATOR_ENDPOINT", "TAPPD_SIMULATOR_ENDPOINT"])
def test_production_attestor_rejects_simulator(monkeypatch, name):
    monkeypatch.setenv(name, "http://127.0.0.1:8090")
    with pytest.raises(SignerUnavailable):
        DstackMeteringIdentityAttestor()


@pytest.mark.parametrize(
    "overrides",
    [
        {"chain_id": 1},
        {"chain_id": True},
        {"vault_address": "0x" + "00" * 20},
        {"metering_verifier": "0x" + "00" * 20},
        {"policy_set_hash": "0x" + "00" * 32},
        {"signer_custody": "operator_key"},
    ],
)
def test_report_data_rejects_wrong_chain_zero_authority_or_custody(overrides):
    values = {
        "metering_verifier": METER,
        "chain_id": 84_532,
        "vault_address": VAULT,
        "policy_set_hash": POLICY_SET_HASH,
        "signer_custody": DSTACK_METERING_CUSTODY,
    }
    values.update(overrides)
    with pytest.raises(SignerUnavailable):
        metering_identity_report_data(**values)


def test_attestor_rejects_unreachable_dstack(monkeypatch):
    _install_dstack(monkeypatch, reachable=False)
    with pytest.raises(SignerUnavailable):
        DstackMeteringIdentityAttestor().attest(
            metering_verifier=METER,
            chain_id=84_532,
            vault_address=VAULT,
            policy_set_hash=POLICY_SET_HASH,
            signer_custody=DSTACK_METERING_CUSTODY,
            challenge=CHALLENGE,
        )


@pytest.mark.parametrize("quote", ["xyz", "0", bytes(1023), bytes(16 * 1024 + 1)])
def test_attestor_rejects_malformed_or_bounded_quote(monkeypatch, quote):
    _install_dstack(monkeypatch, quote=quote)
    with pytest.raises(SignerUnavailable):
        DstackMeteringIdentityAttestor().attest(
            metering_verifier=METER,
            chain_id=84_532,
            vault_address=VAULT,
            policy_set_hash=POLICY_SET_HASH,
            signer_custody=DSTACK_METERING_CUSTODY,
            challenge=CHALLENGE,
        )


def test_attestor_rejects_quote_parser_failure(monkeypatch):
    _install_dstack(monkeypatch)

    def reject(_raw):
        raise ValueError("malformed quote")

    monkeypatch.setattr(
        "compute_metering.identity_attestation.dcap_qvl.parse_quote",
        reject,
    )
    with pytest.raises(SignerUnavailable):
        DstackMeteringIdentityAttestor().attest(
            metering_verifier=METER,
            chain_id=84_532,
            vault_address=VAULT,
            policy_set_hash=POLICY_SET_HASH,
            signer_custody=DSTACK_METERING_CUSTODY,
            challenge=CHALLENGE,
        )


@pytest.mark.parametrize(
    "info",
    [
        SimpleNamespace(
            app_id="bad app id",
            compose_hash="67" * 32,
            os_image_hash=OS_IMAGE_HASH,
        ),
        SimpleNamespace(
            app_id=APP_ID,
            compose_hash="00" * 32,
            os_image_hash=OS_IMAGE_HASH,
        ),
        SimpleNamespace(
            app_id=APP_ID,
            compose_hash="67" * 32,
            os_image_hash="",
        ),
    ],
)
def test_attestor_rejects_invalid_dstack_release_labels(monkeypatch, info):
    _install_dstack(monkeypatch, info=info)
    with pytest.raises(SignerUnavailable):
        DstackMeteringIdentityAttestor().attest(
            metering_verifier=METER,
            chain_id=84_532,
            vault_address=VAULT,
            policy_set_hash=POLICY_SET_HASH,
            signer_custody=DSTACK_METERING_CUSTODY,
            challenge=CHALLENGE,
        )


@pytest.mark.parametrize(
    ("is_tdx", "quote_type", "report_data"),
    [
        (False, "SGX", _report_data() + bytes(32)),
        (True, "SGX", _report_data() + bytes(32)),
        (True, "TDX", b"short"),
        (True, "TDX", _report_data() + bytes.fromhex("01" * 32)),
    ],
)
def test_attestor_rejects_non_tdx_and_wrong_report_data(
    monkeypatch,
    is_tdx,
    quote_type,
    report_data,
):
    parsed = SimpleNamespace(
        is_tdx=lambda: is_tdx,
        quote_type=lambda: quote_type,
        report=SimpleNamespace(report_data=report_data),
    )
    _install_dstack(monkeypatch, parsed=parsed)
    with pytest.raises(SignerUnavailable):
        DstackMeteringIdentityAttestor().attest(
            metering_verifier=METER,
            chain_id=84_532,
            vault_address=VAULT,
            policy_set_hash=POLICY_SET_HASH,
            signer_custody=DSTACK_METERING_CUSTODY,
            challenge=CHALLENGE,
        )


def test_https_qvl_client_challenge_quote_and_verdict_happy_path(monkeypatch):
    challenge = _signed_challenge()
    _install_dstack(monkeypatch, challenge=challenge)
    attestation = DstackMeteringIdentityAttestor().attest(
        metering_verifier=METER,
        chain_id=84_532,
        vault_address=VAULT,
        policy_set_hash=POLICY_SET_HASH,
        signer_custody=DSTACK_METERING_CUSTODY,
        challenge=challenge,
    )
    verdict = _signed_verdict(attestation, challenge)
    verdict_preimage = verdict.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    verdict_preimage.pop("verifier_signature")
    assert not any(key.startswith("qvl_compute_") for key in verdict_preimage)
    assert compute_qvl_verdict_digest(verdict) == (
        "0x"
        + hashlib.sha256(
            b"dnai-wikigen/independent-tdx-verdict/v4\x00"
            + json.dumps(
                verdict_preimage,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        ).hexdigest()
    )
    requests = []

    def handler(request):
        requests.append((request.url.path, json.loads(request.content)))
        payload = (
            challenge.model_dump(mode="json", by_alias=True)
            if request.url.path == "/challenge"
            else verdict.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        )
        return httpx.Response(200, json=payload)

    transport = httpx.Client(transport=httpx.MockTransport(handler))
    client = HttpsComputeMeteringQvlClient(
        verify_url="https://qvl.example.test/verify",
        auth_token="compute-qvl-test-token-" + "x" * 32,
        verifier_address=QVL.address,
        release_policy_hash=QVL_POLICY_HASH,
        cvm_id=METERING_CVM_ID,
        deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
        release_authority_sha256=RELEASE_AUTHORITY_SHA256,
        ceremony_nonce=CEREMONY_NONCE,
        measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        client=transport,
    )
    issued = client.issue_challenge(now=NOW)
    monkeypatch.setattr("compute_metering.identity_attestation.time.time", lambda: NOW)
    authenticated = client.verify(attestation)

    assert issued == challenge
    assert authenticated == verdict
    assert requests[0] == (
        "/challenge",
        {
            "schema": "dnai.attestation-qvl-challenge-request.v2",
            "chain_id": 84_532,
            "domain": "independent_metering_cvm",
            "profile": "compute_metering",
            "cvm_id": METERING_CVM_ID,
            "deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
            "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
            "ceremony_nonce": CEREMONY_NONCE,
            "measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
        },
    )
    assert requests[1][0] == "/verify"
    assert requests[1][1]["schema"] == "dnai.independent-tdx-verification-request.v2"
    assert requests[1][1]["challenge"] == challenge.model_dump(
        mode="json", by_alias=True
    )
    assert requests[1][1]["quote"] == attestation.quote
    assert requests[1][1]["expectation"]["quote_report_data"] == (
        attestation.report_data + challenge.challenge_digest[2:]
    )
    assert attestation.quote not in json.dumps(requests[0][1])
    transport.close()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update(
            {"schema": "dnai.attestation-qvl-challenge.v1"}
        ),
        lambda payload: payload.pop("cvm_id"),
        lambda payload: payload.update({"chain_id": 1}),
        lambda payload: payload.update({"domain": "main_runtime_cvm"}),
        lambda payload: payload.update({"profile": "arena"}),
        lambda payload: payload.update({"cvm_id": "cvm-cross-domain-0001"}),
        lambda payload: payload.update(
            {"deployment_intent_sha256": "sha256:" + "51" * 32}
        ),
        lambda payload: payload.update(
            {"release_authority_sha256": "sha256:" + "52" * 32}
        ),
        lambda payload: payload.update({"ceremony_nonce": "0x" + "53" * 32}),
        lambda payload: payload.update(
            {"measurement_policy_sha256": "sha256:" + "54" * 32}
        ),
        lambda payload: payload.update({"release_policy_hash": "0x" + "12" * 32}),
        lambda payload: payload.update({"verifier_signature": "0x" + "34" * 65}),
        lambda payload: payload.update({"expires_at": NOW}),
        lambda payload: payload.update({"unexpected": True}),
    ],
)
def test_https_qvl_client_rejects_wrong_challenge_context(mutation):
    payload = _signed_challenge().model_dump(mode="json", by_alias=True)
    mutation(payload)
    transport = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    client = HttpsComputeMeteringQvlClient(
        verify_url="https://qvl.example.test/verify",
        auth_token="compute-qvl-test-token-" + "x" * 32,
        verifier_address=QVL.address,
        release_policy_hash=QVL_POLICY_HASH,
        cvm_id=METERING_CVM_ID,
        deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
        release_authority_sha256=RELEASE_AUTHORITY_SHA256,
        ceremony_nonce=CEREMONY_NONCE,
        measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        client=transport,
    )
    with pytest.raises(SignerUnavailable):
        client.issue_challenge(now=NOW)
    transport.close()


def test_https_qvl_client_checks_challenge_freshness_after_response(monkeypatch):
    challenge = _signed_challenge()
    clock = [NOW]

    def handler(_request):
        clock[0] = challenge.expires_at
        return httpx.Response(
            200,
            json=challenge.model_dump(mode="json", by_alias=True),
        )

    monkeypatch.setattr(
        "compute_metering.identity_attestation.time.time",
        lambda: clock[0],
    )
    transport = httpx.Client(transport=httpx.MockTransport(handler))
    client = HttpsComputeMeteringQvlClient(
        verify_url="https://qvl.example.test/verify",
        auth_token="compute-qvl-test-token-" + "x" * 32,
        verifier_address=QVL.address,
        release_policy_hash=QVL_POLICY_HASH,
        cvm_id=METERING_CVM_ID,
        deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
        release_authority_sha256=RELEASE_AUTHORITY_SHA256,
        ceremony_nonce=CEREMONY_NONCE,
        measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        client=transport,
    )
    with pytest.raises(SignerUnavailable):
        client.issue_challenge()
    transport.close()


@pytest.mark.parametrize(
    "variant",
    [
        "legacy_v2",
        "missing_lineage",
        "wrong_chain",
        "wrong_domain",
        "wrong_cvm_id",
        "wrong_deployment_intent",
        "wrong_release_authority",
        "wrong_ceremony_nonce",
        "wrong_measurement_policy",
        "wrong_challenge",
        "wrong_policy",
        "wrong_signature",
        "expired",
        "future_issued",
        "extra_field",
    ],
)
def test_https_qvl_client_rejects_replayed_or_context_drifted_verdict(
    monkeypatch, variant
):
    challenge = _signed_challenge()
    _install_dstack(monkeypatch, challenge=challenge)
    attestation = DstackMeteringIdentityAttestor().attest(
        metering_verifier=METER,
        chain_id=84_532,
        vault_address=VAULT,
        policy_set_hash=POLICY_SET_HASH,
        signer_custody=DSTACK_METERING_CUSTODY,
        challenge=challenge,
    )
    if variant == "future_issued":
        verdict = _signed_verdict(
            attestation,
            challenge,
            issued_at=NOW + 10,
            expires_at=NOW + 120,
        )
        payload = verdict.model_dump(mode="json", by_alias=True)
    else:
        payload = _signed_verdict(attestation, challenge).model_dump(
            mode="json", by_alias=True
        )
        if variant == "wrong_challenge":
            payload["challenge_id"] = "0x" + "12" * 32
        elif variant == "legacy_v2":
            payload["schema"] = "dnai.independent-tdx-verdict.v2"
        elif variant == "missing_lineage":
            payload.pop("release_authority_sha256")
        elif variant == "wrong_chain":
            payload["chain_id"] = 1
        elif variant == "wrong_domain":
            payload["domain"] = "main_runtime_cvm"
        elif variant == "wrong_cvm_id":
            payload["cvm_id"] = "cvm-cross-domain-0001"
        elif variant == "wrong_deployment_intent":
            payload["deployment_intent_sha256"] = "sha256:" + "51" * 32
        elif variant == "wrong_release_authority":
            payload["release_authority_sha256"] = "sha256:" + "52" * 32
        elif variant == "wrong_ceremony_nonce":
            payload["ceremony_nonce"] = "0x" + "53" * 32
        elif variant == "wrong_measurement_policy":
            payload["measurement_policy_sha256"] = "sha256:" + "54" * 32
        elif variant == "wrong_policy":
            payload["release_policy_hash"] = "0x" + "23" * 32
        elif variant == "wrong_signature":
            payload["verifier_signature"] = "0x" + "34" * 65
        elif variant == "expired":
            payload["expires_at"] = NOW
        elif variant == "extra_field":
            payload["unexpected"] = True
    transport = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))
    )
    client = HttpsComputeMeteringQvlClient(
        verify_url="https://qvl.example.test/verify",
        auth_token="compute-qvl-test-token-" + "x" * 32,
        verifier_address=QVL.address,
        release_policy_hash=QVL_POLICY_HASH,
        cvm_id=METERING_CVM_ID,
        deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
        release_authority_sha256=RELEASE_AUTHORITY_SHA256,
        ceremony_nonce=CEREMONY_NONCE,
        measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        client=transport,
    )
    monkeypatch.setattr("compute_metering.identity_attestation.time.time", lambda: NOW)
    with pytest.raises(SignerUnavailable):
        client.verify(attestation)
    transport.close()
