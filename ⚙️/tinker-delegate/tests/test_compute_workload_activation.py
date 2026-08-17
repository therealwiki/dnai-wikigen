from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate import dstack_utils
from tinker_delegate.compute_workload_activation import (
    ACTIVATION_SIGNER_CUSTODY,
    ACTIVATION_SIGNER_KEY_PATH,
    MAX_QVL_RESPONSE_BYTES,
    HttpsComputeWorkloadActivationProvider,
)
from tinker_delegate.compute_workload_ingress import (
    ComputeWorkloadIngressUnavailable,
    ComputeWorkloadRecipient,
)
from tinker_delegate.crypto import TEEKeyPair
from tinker_delegate.qvl_freshness import (
    CHALLENGE_SCHEMA,
    QvlChallenge,
    qvl_challenge_digest,
)
from tinker_delegate.result_verifier import (
    INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
    INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
    IndependentAttestationVerdict,
    independent_attestation_verdict_digest,
)


NOW = 1_800_000_000
AUTH_TOKEN = "compute-workload-qvl-test-token-" + "x" * 32
RELEASE_POLICY_HASH = "0x" + "11" * 32
COMPUTE_VAULT = "0x" + "22" * 20
VAULT_RUNTIME_CODE_HASH = "0x" + "33" * 32
FRESH_DEPLOYMENT_RECEIPT_SHA256 = "0x" + "44" * 32
COMPOSE_HASH = "0x" + "55" * 32
APP_ID = "66" * 20
OS_IMAGE_HASH = "77" * 32
QUOTE = b"q" * 1_024
CVM_ID = "cvm-main-runtime-0001"
DEPLOYMENT_INTENT_SHA256 = "sha256:" + "41" * 32
RELEASE_AUTHORITY_SHA256 = "sha256:" + "42" * 32
CEREMONY_NONCE = "0x" + "43" * 32
MEASUREMENT_POLICY_SHA256 = "sha256:" + "44" * 32
MEASUREMENT_POLICY_SET_SHA256 = "sha256:" + "45" * 32
MAIN_RUNTIME_EVIDENCE_SHA256 = "sha256:" + "46" * 32


def _signed_challenge(qvl: Account) -> QvlChallenge:
    unsigned = QvlChallenge(
        schema=CHALLENGE_SCHEMA,
        chain_id=84_532,
        domain="main_runtime_cvm",
        profile="compute_workload",
        cvm_id=CVM_ID,
        deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
        release_authority_sha256=RELEASE_AUTHORITY_SHA256,
        ceremony_nonce=CEREMONY_NONCE,
        measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        release_policy_hash=RELEASE_POLICY_HASH,
        challenge_id="0x" + "88" * 32,
        challenge_digest="0x" + "01" * 32,
        issued_at=NOW - 10,
        expires_at=NOW + 90,
        verifier_address=qvl.address.lower(),
        verifier_signature="0x" + "00" * 65,
    )
    digest = qvl_challenge_digest(unsigned)
    signature = qvl.sign_message(encode_defunct(hexstr=digest)).signature
    return replace(
        unsigned,
        challenge_digest=digest,
        verifier_signature="0x" + bytes(signature).hex(),
    )


def _signed_verdict(
    qvl: Account,
    challenge: QvlChallenge,
    expectation: dict[str, object],
    *,
    include_diligence_authorization: bool = False,
) -> IndependentAttestationVerdict:
    unsigned = IndependentAttestationVerdict(
        schema=INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
        verification_method=INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
        verified=True,
        chain_id=challenge.chain_id,
        domain=challenge.domain,
        profile="compute_workload",
        cvm_id=challenge.cvm_id,
        deployment_intent_sha256=challenge.deployment_intent_sha256,
        release_authority_sha256=challenge.release_authority_sha256,
        ceremony_nonce=challenge.ceremony_nonce,
        measurement_policy_sha256=challenge.measurement_policy_sha256,
        release_policy_hash=RELEASE_POLICY_HASH,
        challenge_id=challenge.challenge_id,
        challenge_digest=challenge.challenge_digest,
        challenge_issued_at=challenge.issued_at,
        challenge_expires_at=challenge.expires_at,
        quote_hash=str(expectation["quote_hash"]),
        report_data=str(expectation["report_data"]),
        compose_hash=str(expectation["compose_hash"]),
        app_id=str(expectation["app_id"]),
        os_image_hash=str(expectation["os_image_hash"]),
        signer_address=str(expectation["signer_address"]),
        contract_address=str(expectation["contract_address"]),
        issued_at=NOW - 2,
        activation_evidence_lease_expires_at=NOW + 60,
        expires_at=NOW + 60,
        verifier_address=qvl.address.lower(),
        verifier_signature="0x" + "00" * 65,
    )
    if include_diligence_authorization:
        unsigned = replace(
            unsigned,
            qvl_deal_id=1,
            qvl_evaluator_policy_commitment="0x" + "91" * 32,
            qvl_result_hash="0x" + "92" * 32,
            qvl_attestation_evidence_hash=str(expectation["quote_hash"]),
            qvl_authorization_expiry=NOW + 30,
            qvl_authorization_digest="0x" + "93" * 32,
            qvl_authorization_signature="0x" + "94" * 65,
        )
    signature = qvl.sign_message(
        encode_defunct(hexstr=independent_attestation_verdict_digest(unsigned))
    ).signature
    return replace(
        unsigned,
        verifier_signature="0x" + bytes(signature).hex(),
    )


def _provider(
    monkeypatch: pytest.MonkeyPatch,
    handler,
    *,
    qvl_url: str = "https://verify.example/verify",
    revoked_quote_hashes: tuple[str, ...] = (),
) -> HttpsComputeWorkloadActivationProvider:
    monkeypatch.setattr(dstack_utils, "is_dstack_enabled", lambda: True)
    monkeypatch.setattr(dstack_utils, "is_dstack_simulator", lambda: False)
    monkeypatch.setattr(
        dstack_utils,
        "derive_storage_key",
        lambda path: hashlib.sha256(("test:" + path).encode()).digest(),
    )
    return HttpsComputeWorkloadActivationProvider(
        qvl_url=qvl_url,
        auth_token=AUTH_TOKEN,
        trusted_verifier_address=QVL.address,
        release_policy_hash=RELEASE_POLICY_HASH,
        max_verdict_age_seconds=120,
        revoked_quote_hashes=revoked_quote_hashes,
        chain_id=84_532,
        compute_vault_address=COMPUTE_VAULT,
        compute_vault_runtime_code_hash=VAULT_RUNTIME_CODE_HASH,
        fresh_contract_deployment_receipt_sha256=(
            FRESH_DEPLOYMENT_RECEIPT_SHA256
        ),
        cvm_id=CVM_ID,
        deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
        release_authority_sha256=RELEASE_AUTHORITY_SHA256,
        ceremony_nonce=CEREMONY_NONCE,
        measurement_policy_set_sha256=MEASUREMENT_POLICY_SET_SHA256,
        measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        main_runtime_evidence_sha256=MAIN_RUNTIME_EVIDENCE_SHA256,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


QVL = Account.from_key(bytes.fromhex("81" * 32))


@pytest.mark.parametrize("include_diligence_authorization", [False, True])
def test_signed_challenge_quote_and_exact_workload_verdict_boundary(
    monkeypatch: pytest.MonkeyPatch,
    include_diligence_authorization: bool,
) -> None:
    challenge = _signed_challenge(QVL)
    requests: list[tuple[str, dict[str, object]]] = []
    quote_report_data: list[bytes] = []

    def get_attestation_details(report_data: bytes) -> dict[str, str]:
        quote_report_data.append(report_data)
        return {
            "quote": "0x" + QUOTE.hex(),
            "quote_report_data": "0x" + report_data.hex(),
            "compose_hash": COMPOSE_HASH,
            "app_id": APP_ID,
            "os_image_hash": OS_IMAGE_HASH,
        }

    monkeypatch.setattr(
        dstack_utils,
        "get_attestation_details",
        get_attestation_details,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {AUTH_TOKEN}"
        assert request.headers["cache-control"] == "no-store"
        payload = json.loads(request.content)
        requests.append((request.url.path, payload))
        if request.url.path == "/challenge":
            return httpx.Response(200, json=challenge.to_public_dict())
        assert request.url.path == "/verify"
        verdict = _signed_verdict(
            QVL,
            challenge,
            payload["expectation"],
            include_diligence_authorization=include_diligence_authorization,
        )
        return httpx.Response(200, json=verdict.to_public_dict())

    provider = _provider(monkeypatch, handler)
    keypair = TEEKeyPair.from_private_key_hex("21" * 32)
    attestation = provider.recipient_attestation(keypair.public_key_bytes)
    recipient = ComputeWorkloadRecipient.from_keypair(
        keypair,
        custody_mode="dstack",
        recipient_attestation=attestation,
    )

    if include_diligence_authorization:
        with pytest.raises(
            ComputeWorkloadIngressUnavailable,
            match="Compute workload QVL verdict is invalid",
        ):
            provider.verified_activation(recipient, now=NOW)
        return

    activation = provider.verified_activation(recipient, now=NOW)

    assert provider.challenge_url == "https://verify.example/challenge"
    assert repr(provider) == (
        "HttpsComputeWorkloadActivationProvider(authenticated=True)"
    )
    assert activation.recipient_key_id == recipient.key_id
    assert activation.to_dict()["schema"] == (
        "dnai.compute.workload-recipient-activation.v3"
    )
    assert activation.recipient_evidence_lease_expires_at == activation.expires_at
    assert activation.measurement_policy_set_sha256 == (
        MEASUREMENT_POLICY_SET_SHA256
    )
    assert activation.main_runtime_evidence_sha256 == (
        MAIN_RUNTIME_EVIDENCE_SHA256
    )
    assert dict(activation.recipient_attestation) == attestation
    assert attestation["activation_signer_address"] == (
        provider.activation_signer_address
    )
    assert attestation["activation_signer_key_path"] == ACTIVATION_SIGNER_KEY_PATH
    assert attestation["activation_signer_custody"] == ACTIVATION_SIGNER_CUSTODY
    assert quote_report_data == [
        recipient.report_data + challenge.digest_bytes
    ]
    assert len(quote_report_data[0]) == 64
    assert requests[0] == (
        "/challenge",
        {
            "ceremony_nonce": CEREMONY_NONCE,
            "chain_id": 84_532,
            "cvm_id": CVM_ID,
            "deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
            "domain": "main_runtime_cvm",
            "measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
            "profile": "compute_workload",
            "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
            "schema": "dnai.attestation-qvl-challenge-request.v2",
        },
    )
    verify_request = requests[1][1]
    assert set(verify_request) == {
        "schema",
        "challenge",
        "quote",
        "expectation",
        "compute_workload_recipient",
    }
    assert verify_request["schema"] == (
        "dnai.independent-tdx-verification-request.v2"
    )
    assert verify_request["challenge"] == challenge.to_public_dict()
    assert verify_request["quote"] == "0x" + QUOTE.hex()
    assert verify_request["compute_workload_recipient"] == attestation
    expectation = verify_request["expectation"]
    assert expectation["report_data"] == "0x" + recipient.report_data.hex()
    assert expectation["quote_report_data"] == (
        "0x" + quote_report_data[0].hex()
    )
    assert expectation["quote_hash"] == (
        "0x" + hashlib.sha256(QUOTE).hexdigest()
    )
    assert expectation["raw_secret_egress"] is False
    public_activation = activation.to_dict()
    encoded_activation = json.dumps(public_activation)
    assert "0x" + QUOTE.hex() not in encoded_activation
    assert "quote_report_data" not in encoded_activation
    assert AUTH_TOKEN not in encoded_activation


def test_dstack_report_data_substitution_fails_before_verdict_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge = _signed_challenge(QVL)
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(200, json=challenge.to_public_dict())

    provider = _provider(monkeypatch, handler)
    keypair = TEEKeyPair.from_private_key_hex("21" * 32)
    recipient = ComputeWorkloadRecipient.from_keypair(
        keypair,
        custody_mode="dstack",
        recipient_attestation=provider.recipient_attestation(
            keypair.public_key_bytes
        ),
    )
    monkeypatch.setattr(
        dstack_utils,
        "get_attestation_details",
        lambda _report_data: {
            "quote": "0x" + QUOTE.hex(),
            "quote_report_data": "0x" + "aa" * 64,
            "compose_hash": COMPOSE_HASH,
            "app_id": APP_ID,
            "os_image_hash": OS_IMAGE_HASH,
        },
    )

    with pytest.raises(
        ComputeWorkloadIngressUnavailable,
        match="Compute workload dstack evidence is invalid",
    ):
        provider.verified_activation(recipient, now=NOW)
    assert paths == ["/challenge"]


def test_locally_revoked_quote_is_rejected_after_signed_qvl_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge = _signed_challenge(QVL)

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        if request.url.path == "/challenge":
            return httpx.Response(200, json=challenge.to_public_dict())
        verdict = _signed_verdict(QVL, challenge, payload["expectation"])
        return httpx.Response(200, json=verdict.to_public_dict())

    quote_hash = "0x" + hashlib.sha256(QUOTE).hexdigest()
    provider = _provider(
        monkeypatch,
        handler,
        revoked_quote_hashes=(quote_hash,),
    )
    keypair = TEEKeyPair.from_private_key_hex("21" * 32)
    recipient = ComputeWorkloadRecipient.from_keypair(
        keypair,
        custody_mode="dstack",
        recipient_attestation=provider.recipient_attestation(
            keypair.public_key_bytes
        ),
    )

    def get_attestation_details(report_data: bytes) -> dict[str, str]:
        return {
            "quote": "0x" + QUOTE.hex(),
            "quote_report_data": "0x" + report_data.hex(),
            "compose_hash": COMPOSE_HASH,
            "app_id": APP_ID,
            "os_image_hash": OS_IMAGE_HASH,
        }

    monkeypatch.setattr(
        dstack_utils,
        "get_attestation_details",
        get_attestation_details,
    )
    with pytest.raises(
        ComputeWorkloadIngressUnavailable,
        match="Compute workload QVL verdict is invalid",
    ):
        provider.verified_activation(recipient, now=NOW)


def test_transport_errors_discard_bearer_and_request_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            f"transport retained {AUTH_TOKEN}",
            request=request,
        )

    provider = _provider(monkeypatch, handler)
    with pytest.raises(ComputeWorkloadIngressUnavailable) as captured:
        provider._issue_challenge(now=NOW)

    assert str(captured.value) == "Compute workload QVL is unavailable"
    assert captured.value.__cause__ is None
    assert AUTH_TOKEN not in repr(captured.value)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(
            200,
            content=b'{"schema":"one","schema":"two"}',
            headers={"content-type": "application/json"},
        ),
        httpx.Response(
            200,
            content=b"x" * (MAX_QVL_RESPONSE_BYTES + 1),
            headers={"content-type": "application/json"},
        ),
        httpx.Response(
            302,
            headers={
                "content-type": "application/json",
                "location": "https://attacker.invalid/challenge",
            },
        ),
    ],
    ids=["duplicate-json", "oversize", "redirect"],
)
def test_noncanonical_oversize_and_redirect_responses_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    response: httpx.Response,
) -> None:
    provider = _provider(monkeypatch, lambda _request: response)

    with pytest.raises(
        ComputeWorkloadIngressUnavailable,
        match="Compute workload QVL is unavailable",
    ):
        provider._issue_challenge(now=NOW)
