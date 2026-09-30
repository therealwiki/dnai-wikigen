"""Synthetic protocol tests: no hardware quote, network, or release authority."""
from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate import dstack_utils
from tinker_delegate.crypto import TEEKeyPair
from tinker_delegate.qvl_freshness import CHALLENGE_SCHEMA, QvlChallenge, qvl_challenge_digest
from tinker_delegate.recipient_evidence import (
    AUTH_TOKEN_ENV, EVIDENCE_SCHEMA, MAX_QVL_RESPONSE_BYTES, TRUST_SCHEMA,
    HttpsRecipientEvidenceProvider, RecipientEvidenceUnavailable, RecipientQuoteCollector,
    RecipientQuoteRateLimited,
    parse_recipient_trust_policy, recipient_binding,
)
from tinker_delegate.result_verifier import (
    INDEPENDENT_ATTESTATION_VERDICT_SCHEMA, INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
    IndependentAttestationVerdict, independent_attestation_verdict_digest,
)

NOW = 1_800_000_000
# Published deterministic test-only material; never deployed or authorizing.
QVL = Account.from_key(bytes.fromhex("81" * 32))
KEYPAIR = TEEKeyPair.from_private_key_hex("21" * 32)
TOKEN = "recipient-only-test-bearer-" + "x" * 32


def trust_policy(context="artifact"):
    binding = recipient_binding(context, KEYPAIR.public_key_bytes)
    return {
        "schema": TRUST_SCHEMA, "context": context,
        "profile": "artifact_recipient" if context == "artifact" else "arena",
        "domain": "main_runtime_cvm", "chain_id": 84532,
        "cvm_id": "cvm-main-runtime-0001",
        "deployment_intent_sha256": "sha256:" + "41" * 32,
        "release_authority_sha256": "sha256:" + "42" * 32,
        "ceremony_nonce": "0x" + "43" * 32,
        "measurement_policy_sha256": "sha256:" + "44" * 32,
        "release_policy_hash": "0x" + "11" * 32,
        "verifier_address": QVL.address.lower(), "signer_address": "0x" + "22" * 20,
        "contract_address": "0x" + "33" * 20, "compose_hash": "0x" + "55" * 32,
        "app_id": "66" * 20, "os_image_hash": "77" * 32,
        "encryption_public_key": binding["encryption_public_key"],
        "key_id": binding["key_id"], "report_data": "0x" + binding["report_data"],
        "max_verdict_age_seconds": 120,
    }


def sign_challenge(policy, now, index):
    value = QvlChallenge(
        schema=CHALLENGE_SCHEMA, profile=policy["profile"],
        **{key: policy[key] for key in (
            "chain_id", "domain", "cvm_id", "deployment_intent_sha256",
            "release_authority_sha256", "ceremony_nonce", "measurement_policy_sha256",
            "release_policy_hash", "verifier_address",
        )},
        challenge_id="0x" + hashlib.sha256(f"synthetic-{policy['context']}-{index}".encode()).hexdigest(),
        challenge_digest="0x" + "01" * 32, issued_at=now, expires_at=now + 90,
        verifier_signature="0x" + "00" * 65,
    )
    digest = qvl_challenge_digest(value)
    return replace(value, challenge_digest=digest,
                   verifier_signature="0x" + bytes(QVL.sign_message(encode_defunct(hexstr=digest)).signature).hex())


def sign_verdict(policy, challenge, expectation, now, updates=None):
    value = IndependentAttestationVerdict(
        schema=INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
        verification_method=INDEPENDENT_ATTESTATION_VERIFICATION_METHOD, verified=True,
        **{key: policy[key] for key in (
            "chain_id", "domain", "profile", "cvm_id", "deployment_intent_sha256",
            "release_authority_sha256", "ceremony_nonce", "measurement_policy_sha256",
            "release_policy_hash", "verifier_address",
        )},
        **{key: expectation[key] for key in (
            "quote_hash", "report_data", "compose_hash", "app_id", "os_image_hash",
            "signer_address", "contract_address",
        )},
        challenge_id=challenge["challenge_id"], challenge_digest=challenge["challenge_digest"],
        challenge_issued_at=challenge["issued_at"], challenge_expires_at=challenge["expires_at"],
        issued_at=now, activation_evidence_lease_expires_at=now + 60, expires_at=now + 60,
        verifier_signature="0x" + "00" * 65,
    )
    if updates:
        value = replace(value, **updates)
    digest = independent_attestation_verdict_digest(value)
    return replace(value, verifier_signature="0x" + bytes(QVL.sign_message(encode_defunct(hexstr=digest)).signature).hex())


class Harness:
    def __init__(self, monkeypatch, context="artifact"):
        self.policy = trust_policy(context)
        self.now = NOW
        self.requests = []
        self.challenges = []
        self.quote_requests = []
        self.modify_challenge = lambda value: value
        self.modify_verdict = lambda value: value
        self.verdict_updates = {}
        self.modify_quote = lambda value: value
        self.after_challenge = lambda: None
        self.after_quote = lambda: None
        self.after_verdict = lambda: None
        monkeypatch.setattr(dstack_utils, "is_dstack_enabled", lambda: True)
        monkeypatch.setattr(dstack_utils, "is_dstack_simulator", lambda: False)
        monkeypatch.setattr(dstack_utils, "get_attestation_details", self.quote)
        self.client = httpx.Client(transport=httpx.MockTransport(self.handler))
        self.provider = HttpsRecipientEvidenceProvider(
            trust_policy=self.policy, qvl_url="https://recipient-qvl.example/verify",
            auth_token=TOKEN, client=self.client, clock=lambda: self.now,
        )
        self.recipient = recipient_binding(context, KEYPAIR.public_key_bytes)

    def quote(self, report_data):
        self.quote_requests.append(report_data)
        raw = bytearray(b"\x51" * 1024)
        raw[0:2] = (4).to_bytes(2, "little")
        raw[4:8] = (0x81).to_bytes(4, "little")
        raw[568:632] = report_data
        details = {
            "quote": "0x" + bytes(raw).hex(), "quote_report_data": "0x" + report_data.hex(),
            "compose_hash": self.policy["compose_hash"], "app_id": self.policy["app_id"],
            "os_image_hash": self.policy["os_image_hash"],
        }
        self.after_quote()
        return self.modify_quote(details)

    def handler(self, request):
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        assert request.headers["cache-control"] == "no-store"
        payload = json.loads(request.content)
        self.requests.append((request.url.path, payload))
        if request.url.path == "/challenge":
            challenge = sign_challenge(self.policy, self.now, len(self.challenges))
            self.challenges.append(challenge)
            self.after_challenge()
            return httpx.Response(200, json=self.modify_challenge(challenge.to_public_dict()))
        assert request.url.path == "/verify"
        assert set(payload) == {"schema", "challenge", "quote", "expectation"}
        assert hashlib.sha256(bytes.fromhex(payload["quote"][2:])).hexdigest() == payload["expectation"]["quote_hash"][2:]
        verdict = sign_verdict(self.policy, payload["challenge"], payload["expectation"], self.now,
                               self.verdict_updates)
        self.after_verdict()
        return httpx.Response(200, json=self.modify_verdict(verdict.to_public_dict()))

    def evidence(self):
        return self.provider.evidence(self.recipient, custody_mode="dstack")


def public_fixture(monkeypatch, context):
    harness = Harness(monkeypatch, context)
    first = harness.evidence()
    harness.now = first["verdict"]["expires_at"] + 1
    renewed = harness.evidence()
    assert first["recipient"] == renewed["recipient"]
    assert first["challenge"]["challenge_id"] != renewed["challenge"]["challenge_id"]
    assert first["quote"] != renewed["quote"]
    assert len(harness.requests) == 4
    return {
        "synthetic_non_authorizing": True, "now": NOW,
        "trust": harness.policy, "evidence": first,
        "renewed": {"now": harness.now, "evidence": renewed},
    }


@pytest.mark.parametrize("context", ["artifact", "arena"])
def test_exact_context_binding_and_independent_signed_evidence(monkeypatch, context):
    harness = Harness(monkeypatch, context)
    evidence = harness.evidence()
    assert set(evidence) == {"schema", "context", "recipient", "quote", "quote_report_data", "challenge", "verdict"}
    assert evidence["schema"] == EVIDENCE_SCHEMA
    assert evidence["context"] == context
    assert evidence["recipient"] == harness.recipient
    assert evidence["quote_report_data"] == harness.policy["report_data"] + evidence["challenge"]["challenge_digest"][2:]
    assert bytes.fromhex(evidence["quote"][2:])[568:632].hex() == evidence["quote_report_data"][2:]
    assert [path for path, _ in harness.requests] == ["/challenge", "/verify"]
    assert TOKEN not in json.dumps(evidence)


@pytest.mark.parametrize("context", ["artifact", "arena"])
def test_cross_language_fixture_is_actual_public_producer_output(monkeypatch, context):
    path = Path(__file__).resolve().parents[3] / "web/src/lib/fixtures" / f"recipient-evidence-{context}.json"
    fixture = json.loads(path.read_text())
    assert fixture == public_fixture(monkeypatch, context)


def test_cache_copies_do_not_mutate_pins_or_extend_lease_and_renew_after_expiry(monkeypatch):
    harness = Harness(monkeypatch)
    first = harness.evidence()
    first["recipient"]["encryption_public_key"] = "ab" * 32
    first["verdict"]["expires_at"] += 999
    harness.policy["max_verdict_age_seconds"] = 900
    harness.now += 30
    cached = harness.evidence()
    assert cached["verdict"]["expires_at"] == NOW + 60
    assert cached["recipient"] == harness.recipient
    assert len(harness.requests) == 2
    harness.now = NOW + 60
    renewed = harness.evidence()
    assert renewed["verdict"]["expires_at"] == NOW + 120
    assert renewed["challenge"]["challenge_id"] != cached["challenge"]["challenge_id"]
    assert renewed["quote"] != cached["quote"]
    assert len(harness.requests) == 4


def test_singleflight_releases_state_lock_and_publishes_one_observation(monkeypatch):
    harness = Harness(monkeypatch)
    entered, release = threading.Event(), threading.Event()
    def block():
        entered.set()
        assert release.wait(5)
    harness.after_challenge = block
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(harness.evidence) for _ in range(4)]
        assert entered.wait(5)
        assert harness.provider._condition.acquire(blocking=False)
        harness.provider._condition.release()
        release.set()
        results = [future.result(timeout=5) for future in futures]
    assert all(result == results[0] for result in results)
    assert len(harness.requests) == 2
    assert len(harness.quote_requests) == 1


@pytest.mark.parametrize("phase", ["after_challenge", "after_quote", "after_verdict"])
def test_clock_is_checked_after_each_io_phase(monkeypatch, phase):
    harness = Harness(monkeypatch)
    setattr(harness, phase, lambda: setattr(harness, "now", harness.now + 121))
    with pytest.raises(RecipientEvidenceUnavailable, match="^Recipient evidence is unavailable$"):
        harness.evidence()
    assert harness.provider._cache is None


def test_expired_cache_never_returned_when_renewal_fails(monkeypatch):
    harness = Harness(monkeypatch)
    harness.evidence()
    harness.now += 60
    harness.modify_challenge = lambda _: {"secret": TOKEN}
    with pytest.raises(RecipientEvidenceUnavailable) as failure:
        harness.evidence()
    assert TOKEN not in str(failure.value)
    assert failure.value.__cause__ is None
    assert harness.provider._cache is None


@pytest.mark.parametrize("change", ["quote_hash", "report_data", "profile", "signer_address", "contract_address", "compose_hash", "measurement_policy_sha256"])
def test_authenticated_but_wrong_verdict_binding_is_rejected(monkeypatch, change):
    harness = Harness(monkeypatch)
    if change == "profile":
        value = "arena"
    elif change in {"signer_address", "contract_address"}:
        value = "0x" + "99" * 20
    elif change.endswith("sha256"):
        value = "sha256:" + "99" * 32
    else:
        value = "0x" + "99" * 32
    harness.verdict_updates = {change: value}
    with pytest.raises(RecipientEvidenceUnavailable):
        harness.evidence()


@pytest.mark.parametrize("field", ["verifier_signature", "profile"])
def test_wrong_challenge_signature_or_profile_is_rejected_before_quote(monkeypatch, field):
    harness = Harness(monkeypatch)
    harness.modify_challenge = lambda value: {**value, field: "arena" if field == "profile" else "0x" + "00" * 65}
    with pytest.raises(RecipientEvidenceUnavailable):
        harness.evidence()
    assert not harness.quote_requests


def test_wrong_verdict_signature_or_extra_fields_rejected(monkeypatch):
    for update in ({"verifier_signature": "0x" + "00" * 65}, {"raw_secret": TOKEN}):
        harness = Harness(monkeypatch)
        harness.modify_verdict = lambda value: {**value, **update}
        with pytest.raises(RecipientEvidenceUnavailable):
            harness.evidence()


@pytest.mark.parametrize("mode", ["static_zero_half", "claimed_report", "version", "tee_type"])
def test_actual_raw_quote_report_and_version_are_checked(monkeypatch, mode):
    harness = Harness(monkeypatch)
    def modify(value):
        raw = bytearray.fromhex(value["quote"][2:])
        if mode == "static_zero_half":
            raw[600:632] = bytes(32)
        elif mode == "claimed_report":
            value["quote_report_data"] = "0x" + "00" * 64
        elif mode == "version":
            raw[0:2] = (5).to_bytes(2, "little")
        else:
            raw[4:8] = bytes(4)
        value["quote"] = "0x" + raw.hex()
        return value
    harness.modify_quote = modify
    with pytest.raises(RecipientEvidenceUnavailable):
        harness.evidence()
    assert len(harness.requests) == 1


def test_recipient_key_change_after_restart_cannot_reuse_trust_or_cache(monkeypatch):
    harness = Harness(monkeypatch)
    harness.evidence()
    changed = recipient_binding("artifact", TEEKeyPair.from_private_key_hex("31" * 32).public_key_bytes)
    with pytest.raises(RecipientEvidenceUnavailable):
        harness.provider.evidence(changed, custody_mode="dstack")
    assert len(harness.requests) == 2


@pytest.mark.parametrize("change,value", [
    ("report_data", "0x" + "ff" * 32),  # Old result-signer digest is not the recipient digest.
    ("key_id", "sha256:" + "ff" * 32), ("profile", "diligence"),
    ("max_verdict_age_seconds", 901), ("max_verdict_age_seconds", True),
    ("chain_id", 1), ("unexpected", "rejected"),
])
def test_trust_requires_exact_canonical_recipient_policy(change, value):
    with pytest.raises(RecipientEvidenceUnavailable):
        parse_recipient_trust_policy({**trust_policy(), change: value})


def test_duplicate_trust_fields_are_not_normalized_away():
    raw = json.dumps(trust_policy())
    with pytest.raises(RecipientEvidenceUnavailable):
        parse_recipient_trust_policy(raw[:-1] + ',"context":"artifact"}')


@pytest.mark.parametrize("local,simulator,custody", [(True, False, "dstack"), (False, True, "dstack"), (False, False, "local")])
def test_local_simulated_or_non_dstack_recipient_never_reuses_cached_evidence(monkeypatch, local, simulator, custody):
    harness = Harness(monkeypatch)
    harness.evidence()
    monkeypatch.setattr(dstack_utils, "is_dstack_enabled", lambda: not local)
    monkeypatch.setattr(dstack_utils, "is_dstack_simulator", lambda: simulator)
    with pytest.raises(RecipientEvidenceUnavailable):
        harness.provider.evidence(harness.recipient, custody_mode=custody)


@pytest.mark.parametrize("url", ["http://example/verify", "https://a:b@example/verify", "https://example/wrong", "https://example/verify?q=1", "https://localhost/verify"])
def test_transport_endpoint_is_fixed_https_verify(monkeypatch, url):
    harness = Harness(monkeypatch)
    with pytest.raises(RecipientEvidenceUnavailable):
        HttpsRecipientEvidenceProvider(trust_policy=harness.policy, qvl_url=url, auth_token=TOKEN, client=harness.client)


@pytest.mark.parametrize("response", [
    httpx.Response(302, headers={"location": "https://other.example/verify"}),
    httpx.Response(200, text="not JSON"),
    httpx.Response(200, content=b"x" * (MAX_QVL_RESPONSE_BYTES + 1), headers={"content-type": "application/json"}),
    httpx.Response(200, content=b'{"field":1,"field":2}', headers={"content-type": "application/json"}),
])
def test_bounded_transport_rejects_redirect_nonjson_oversize_and_duplicate_fields(monkeypatch, response):
    harness = Harness(monkeypatch)
    harness.provider._client = httpx.Client(transport=httpx.MockTransport(lambda _: response))
    with pytest.raises(RecipientEvidenceUnavailable):
        harness.evidence()


def test_api_context_binding_no_store_and_fixed_failure(monkeypatch):
    from fastapi.testclient import TestClient
    from tinker_delegate import api
    from tinker_delegate.arena_ingress import ArenaIngressRecipient
    import tinker_delegate.card_channel as card_channel
    harness = Harness(monkeypatch)
    monkeypatch.setattr(card_channel, "get_artifact_keypair", lambda **_: KEYPAIR)
    monkeypatch.setattr(api, "_get_recipient_evidence_provider", lambda _: harness.provider)
    with TestClient(api.app) as client:
        response = client.get("/attestation/recipient?context=artifact")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["recipient"] == harness.recipient
        assert client.get("/attestation/recipient?context=billing").status_code == 400
        monkeypatch.setattr(api, "_get_arena_ingress", lambda: SimpleNamespace(
            recipient=ArenaIngressRecipient.from_keypair(KEYPAIR, custody_mode="dstack")))
        wrong_context = client.get("/attestation/recipient?context=arena")
        assert wrong_context.status_code == 503
        assert wrong_context.headers["cache-control"] == "no-store"
        assert wrong_context.json() == {"detail": "Recipient evidence is unavailable"}


def test_factory_reads_only_dedicated_context_token_and_keys_all_pins(monkeypatch):
    from tinker_delegate import api
    harness = Harness(monkeypatch)
    values = SimpleNamespace(artifact_recipient_trust_json=json.dumps(harness.policy),
                             artifact_recipient_qvl_url="https://recipient-qvl.example/verify")
    monkeypatch.setattr(api, "settings", values)
    monkeypatch.setattr(api, "_recipient_evidence_providers", {})
    monkeypatch.delenv(AUTH_TOKEN_ENV["artifact"], raising=False)
    monkeypatch.setenv("TINKER_DILIGENCE_QVL_AUTH_TOKEN", TOKEN)
    with pytest.raises(RecipientEvidenceUnavailable):
        api._get_recipient_evidence_provider("artifact")
    monkeypatch.setenv(AUTH_TOKEN_ENV["artifact"], TOKEN)
    first = api._get_recipient_evidence_provider("artifact")
    assert first is api._get_recipient_evidence_provider("artifact")
    values.artifact_recipient_trust_json = json.dumps({**harness.policy, "ceremony_nonce": "0x" + "88" * 32})
    second = api._get_recipient_evidence_provider("artifact")
    assert second is not first
    assert TOKEN not in repr(first)
    first.close()
    second.close()


def test_original_result_signer_digest_is_not_an_artifact_recipient_binding():
    from tinker_delegate.chain_submitter import signer_attestation_report_data
    policy = trust_policy()
    original_digest = signer_attestation_report_data(
        signer_address=policy["signer_address"], chain_id=policy["chain_id"],
        contract_address=policy["contract_address"],
    )
    assert "0x" + original_digest.hex() != policy["report_data"]
    with pytest.raises(RecipientEvidenceUnavailable):
        parse_recipient_trust_policy({**policy, "report_data": "0x" + original_digest.hex()})


def test_fresh_provider_retains_derived_artifact_pin_but_changed_kms_material_fails(monkeypatch):
    from tinker_delegate import api, card_channel
    harness = Harness(monkeypatch)
    material = [b"\x21" * 32]
    paths = []

    def derive(path):
        paths.append(path)
        return material[0]

    monkeypatch.setattr(card_channel, "is_dstack_enabled", lambda: True)
    monkeypatch.setattr(card_channel, "is_dstack_simulator", lambda: False)
    monkeypatch.setattr(dstack_utils, "derive_storage_key", derive)
    first_binding, custody = api._actual_recipient_binding("artifact")
    first = harness.provider.evidence(first_binding, custody_mode=custody)
    restarted = HttpsRecipientEvidenceProvider(
        trust_policy=harness.policy, qvl_url="https://recipient-qvl.example/verify",
        auth_token=TOKEN, client=harness.client, clock=lambda: harness.now,
    )
    restarted_binding, custody = api._actual_recipient_binding("artifact")
    second = restarted.evidence(restarted_binding, custody_mode=custody)
    assert second["recipient"] == first["recipient"] == harness.recipient
    assert second["challenge"]["challenge_id"] != first["challenge"]["challenge_id"]
    material[0] = b"\x22" * 32
    changed_binding, custody = api._actual_recipient_binding("artifact")
    assert changed_binding["encryption_public_key"] != first_binding["encryption_public_key"]
    for provider in (harness.provider, restarted):
        with pytest.raises(RecipientEvidenceUnavailable):
            provider.evidence(changed_binding, custody_mode=custody)
    assert len(harness.requests) == 4
    assert paths == ["tinker/artifact_ingress"] * 3


def test_discovery_external_qvl_review_bootstrap_restart_and_renewal(monkeypatch):
    """Mock external QVL setup explicitly; it is not an automatic driver step."""
    from fastapi.testclient import TestClient
    from tinker_delegate import api, card_channel, recipient_evidence
    from tinker_delegate.qvl_freshness import (
        authenticate_qvl_challenge, challenge_request, qvl_challenge_from_public_dict,
    )
    from tinker_delegate.result_verifier import (
        IndependentAttestationExpectation, authenticate_independent_attestation_verdict,
        independent_attestation_verdict_from_public_dict,
    )

    harness = Harness(monkeypatch)
    paths, providers, consumed_challenges = [], [], set()
    operator_reviewed_binding = None
    settings = SimpleNamespace(artifact_recipient_trust_json="", artifact_recipient_qvl_url="")
    monkeypatch.setattr(api, "settings", settings)
    monkeypatch.setattr(api, "_recipient_evidence_providers", {})
    monkeypatch.setattr(api, "_recipient_quote_collector", None)
    monkeypatch.delenv(AUTH_TOKEN_ENV["artifact"], raising=False)
    monkeypatch.setattr(card_channel, "is_dstack_enabled", lambda: True)
    monkeypatch.setattr(card_channel, "is_dstack_simulator", lambda: False)

    def derive(path):
        paths.append(path)
        # Public synthetic material, deliberately different from Harness's key.
        return b"\x24" * 32

    monkeypatch.setattr(dstack_utils, "derive_storage_key", derive)
    monkeypatch.setattr(card_channel, "get_attestation_details", lambda report: harness.quote(report.ljust(64, b"\x00")))

    def reviewed_qvl(request):
        # This is the mocked, externally deployed QVL policy boundary, not a
        # delegate API that can approve its own freshly discovered recipient.
        assert operator_reviewed_binding is not None
        payload = json.loads(request.content)
        if request.url.path == "/verify":
            challenge = payload["challenge"]
            assert challenge in [value.to_public_dict() for value in harness.challenges]
            assert challenge["challenge_id"] not in consumed_challenges
            consumed_challenges.add(challenge["challenge_id"])
            binding = recipient_binding("artifact", bytes.fromhex(operator_reviewed_binding["encryption_public_key"]))
            assert operator_reviewed_binding["key_id"] == binding["key_id"]
            assert payload["expectation"]["report_data"] == "0x" + binding["report_data"]
            assert bytes.fromhex(payload["quote"][2:])[568:632].hex() == binding["report_data"] + challenge["challenge_digest"][2:]
        return harness.handler(request)

    def check_appraisal(verdict_payload, challenge, quote):
        policy = harness.policy
        expectation = IndependentAttestationExpectation(
            trusted_verifier_addresses=(policy["verifier_address"],),
            **{key: policy[key] for key in (
                "chain_id", "domain", "profile", "cvm_id", "deployment_intent_sha256",
                "release_authority_sha256", "ceremony_nonce", "measurement_policy_sha256",
                "release_policy_hash", "report_data", "compose_hash", "app_id",
                "os_image_hash", "signer_address", "contract_address",
            )},
            challenge_id=challenge["challenge_id"], challenge_digest=challenge["challenge_digest"],
            challenge_issued_at=challenge["issued_at"], challenge_expires_at=challenge["expires_at"],
            quote_hash="0x" + hashlib.sha256(bytes.fromhex(quote[2:])).hexdigest(),
            max_age_seconds=policy["max_verdict_age_seconds"],
        )
        return authenticate_independent_attestation_verdict(
            independent_attestation_verdict_from_public_dict(verdict_payload),
            expectation=expectation, now=harness.now,
        )

    with httpx.Client(transport=httpx.MockTransport(reviewed_qvl), headers={
        "Authorization": f"Bearer {TOKEN}", "Cache-Control": "no-store",
    }) as qvl, TestClient(api.app) as client:
        # 1. Discover the real resolver's unappraised public key without runtime
        # trust settings or a recipient-QVL bearer. It differs from the test seed.
        discovered_response = client.get("/attestation?context=artifact")
        assert discovered_response.status_code == 200
        discovered = discovered_response.json()
        assert discovered["verified"] is False
        assert discovered["encryption_public_key"] != harness.recipient["encryption_public_key"]
        assert client.get("/attestation/recipient?context=artifact").status_code == 503
        assert not harness.requests

        # 2. Simulate the EXTERNAL operator review and QVL policy deployment.
        # Nothing above automatically promotes the discovery into trusted pins.
        binding = recipient_binding("artifact", bytes.fromhex(discovered["encryption_public_key"]))
        assert discovered["report_data"] == binding["report_data"]
        operator_reviewed_binding = {
            "kind": "artifact_recipient_v1", "encryption_public_key": binding["encryption_public_key"],
            "key_id": binding["key_id"],
        }
        harness.policy.update(encryption_public_key=binding["encryption_public_key"],
                              key_id=binding["key_id"], report_data="0x" + binding["report_data"])
        reviewed_policy_json = json.dumps(harness.policy, sort_keys=True)
        fields = {key: harness.policy[key] for key in (
            "chain_id", "domain", "cvm_id", "deployment_intent_sha256",
            "release_authority_sha256", "ceremony_nonce", "measurement_policy_sha256",
        )}
        challenge_payload = qvl.post("https://recipient-qvl.example/challenge", json=
            challenge_request("artifact_recipient", **fields)).json()
        challenge = qvl_challenge_from_public_dict(challenge_payload)
        authenticate_qvl_challenge(
            challenge, expected_profile="artifact_recipient",
            **{f"expected_{key}": value for key, value in fields.items()},
            trusted_verifier_addresses=(harness.policy["verifier_address"],),
            expected_policy_hash=harness.policy["release_policy_hash"], now=harness.now,
        )

        # 3. The constrained bootstrap route works before final trust is installed.
        bootstrap_response = client.post("/attestation/recipient-quote", json={
            "context": "artifact", "challenge_digest": challenge.challenge_digest,
        })
        assert bootstrap_response.status_code == 200
        bootstrap = bootstrap_response.json()
        assert bootstrap["verified"] is False and bootstrap["recipient"] == binding
        assert settings.artifact_recipient_trust_json == ""
        expectation = {
            "mode": "tdx", "raw_secret_egress": False,
            **{key: harness.policy[key] for key in (
                "signer_address", "chain_id", "contract_address", "report_data",
                "compose_hash", "app_id", "os_image_hash",
            )},
            "quote_hash": bootstrap["quote_hash"], "quote_report_data": bootstrap["quote_report_data"],
            "quote_size": len(bytes.fromhex(bootstrap["quote"][2:])),
        }
        bootstrap_verdict = qvl.post("https://recipient-qvl.example/verify", json={
            "schema": "dnai.independent-tdx-verification-request.v2", "challenge": challenge_payload,
            "quote": bootstrap["quote"], "expectation": expectation,
        }).json()
        check_appraisal(bootstrap_verdict, challenge_payload, bootstrap["quote"])

        # 4. Model final configuration delivery and a fresh process: no inherited
        # provider cache/collector/boot key. Only the reviewed pins and KMS remain.
        settings.artifact_recipient_trust_json = reviewed_policy_json
        settings.artifact_recipient_qvl_url = "https://recipient-qvl.example/verify"
        monkeypatch.setenv(AUTH_TOKEN_ENV["artifact"], TOKEN)
        monkeypatch.setattr(api, "_recipient_evidence_providers", {})
        monkeypatch.setattr(api, "_recipient_quote_collector", None)
        monkeypatch.setattr(card_channel, "_tee_keypair", None)

        def provider_with_mock_io(**kwargs):
            provider = HttpsRecipientEvidenceProvider(**kwargs, client=qvl, clock=lambda: harness.now)
            providers.append(provider)
            return provider

        monkeypatch.setattr(recipient_evidence, "HttpsRecipientEvidenceProvider", provider_with_mock_io)
        harness.now = bootstrap_verdict["expires_at"] + 1
        final_response = client.get("/attestation/recipient?context=artifact")
        assert final_response.status_code == 200
        final = final_response.json()
        check_appraisal(final["verdict"], final["challenge"], final["quote"])
        assert final["recipient"] == bootstrap["recipient"]
        assert final["challenge"]["challenge_id"] != challenge.challenge_id

        # 5. A second lease renewal requires new signed evidence, not a rebuild,
        # new operator pin, or resurrection of the bootstrap/previous verdict.
        harness.now = final["verdict"]["expires_at"] + 1
        renewed_response = client.get("/attestation/recipient?context=artifact")
        assert renewed_response.status_code == 200
        renewed = renewed_response.json()
        check_appraisal(renewed["verdict"], renewed["challenge"], renewed["quote"])
        assert renewed["recipient"] == binding
        assert renewed["challenge"]["challenge_id"] != final["challenge"]["challenge_id"]
        assert renewed["quote"] != final["quote"]
        assert settings.artifact_recipient_trust_json == reviewed_policy_json
        assert len(providers) == 1
    harness.client.close()
    assert paths == ["tinker/artifact_ingress"] * 4
    assert len(consumed_challenges) == 3
    assert [path for path, _ in harness.requests] == ["/challenge", "/verify"] * 3


@pytest.mark.parametrize("field", ["compose_hash", "app_id", "os_image_hash"])
def test_changed_quote_identity_does_not_silently_repin_release_trust(monkeypatch, field):
    harness = Harness(monkeypatch)
    original = harness.evidence()
    harness.now = original["verdict"]["expires_at"] + 1
    changed = "88" * (20 if field == "app_id" else 32)
    if field == "compose_hash":
        changed = "0x" + changed
    harness.modify_quote = lambda value: {**value, field: changed}
    with pytest.raises(RecipientEvidenceUnavailable):
        harness.evidence()
    assert harness.provider._cache is None
    assert [path for path, _ in harness.requests] == ["/challenge", "/verify", "/challenge"]


def test_reused_unexpired_one_use_challenge_is_rejected_on_renewal(monkeypatch):
    harness = Harness(monkeypatch)
    first = harness.evidence()
    harness.now += 60
    harness.modify_challenge = lambda _: first["challenge"]
    with pytest.raises(RecipientEvidenceUnavailable):
        harness.evidence()
    assert len(harness.quote_requests) == 1


@pytest.mark.parametrize("context", ["artifact", "arena"])
def test_bootstrap_collector_works_without_trust_or_qvl_credentials(monkeypatch, context):
    from fastapi.testclient import TestClient
    from tinker_delegate import api
    from tinker_delegate.arena_ingress import ArenaIngressRecipient
    import tinker_delegate.card_channel as card_channel
    harness = Harness(monkeypatch, context)
    monkeypatch.setattr(api, "settings", SimpleNamespace())
    monkeypatch.setattr(api, "_recipient_quote_collector", RecipientQuoteCollector())
    monkeypatch.setattr(api, "_get_recipient_evidence_provider", lambda _: pytest.fail("bootstrap must not require trust or QVL transport"))
    monkeypatch.setattr(card_channel, "get_artifact_keypair", lambda **_: KEYPAIR)
    monkeypatch.setattr(api, "_get_arena_ingress", lambda: SimpleNamespace(
        recipient=ArenaIngressRecipient.from_keypair(KEYPAIR, custody_mode="dstack")))
    for key in AUTH_TOKEN_ENV.values():
        monkeypatch.delenv(key, raising=False)
    with TestClient(api.app) as client:
        response = client.post("/attestation/recipient-quote", json={"context": context, "challenge_digest": "0x" + "99" * 32})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    value = response.json()
    assert set(value) == {"schema", "context", "recipient", "quote", "quote_hash", "quote_report_data", "compose_hash", "app_id", "os_image_hash", "verified"}
    assert value["schema"] == "dnai.recipient-quote.v1"
    assert value["context"] == context
    assert value["recipient"] == harness.recipient
    assert value["verified"] is False
    assert value["quote_report_data"] == harness.policy["report_data"] + "99" * 32
    assert value["quote_hash"] == "0x" + hashlib.sha256(bytes.fromhex(value["quote"][2:])).hexdigest()
    assert not harness.requests


@pytest.mark.parametrize("body", [
    {"context": "billing", "challenge_digest": "0x" + "99" * 32},
    {"context": "artifact", "challenge_digest": "0x" + "00" * 32},
    {"context": "artifact", "challenge_digest": "0x" + "99" * 32, "encryption_public_key": "ff" * 32},
    {"context": "artifact", "challenge_digest": "0x" + "99" * 32, "report_data": "ff" * 32},
    {"context": "artifact", "challenge_digest": "0x" + "99" * 33},
])
def test_bootstrap_body_rejects_context_key_override_extra_and_invalid_challenge(monkeypatch, body):
    from fastapi.testclient import TestClient
    from tinker_delegate import api
    monkeypatch.setattr(api, "_actual_recipient_binding", lambda _: pytest.fail("invalid request must not collect recipient"))
    with TestClient(api.app) as client:
        assert client.post("/attestation/recipient-quote", json=body).status_code == 422


def test_bootstrap_route_returns_bounded_fixed_rate_limit_response(monkeypatch):
    from fastapi.testclient import TestClient
    from tinker_delegate import api
    harness = Harness(monkeypatch)
    monkeypatch.setattr(api, "_recipient_quote_collector", RecipientQuoteCollector(clock=lambda: 100.0))
    monkeypatch.setattr(api, "_actual_recipient_binding", lambda _: (harness.recipient, "dstack"))
    body = {"context": "artifact", "challenge_digest": "0x" + "99" * 32}
    with TestClient(api.app) as client:
        assert client.post("/attestation/recipient-quote", json=body).status_code == 200
        response = client.post("/attestation/recipient-quote", json=body)
    assert response.status_code == 429
    assert response.headers["retry-after"] == "2"
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {"detail": "Recipient quote collection is rate limited"}
    assert len(harness.quote_requests) == 1


def test_bootstrap_route_enforces_512_byte_prebuffer_cap(monkeypatch):
    from fastapi.testclient import TestClient
    from tinker_delegate import api
    from tinker_delegate.request_body_limits import RECIPIENT_QUOTE_REQUEST_MAX_BYTES
    harness = Harness(monkeypatch)
    monkeypatch.setattr(api, "_recipient_quote_collector", RecipientQuoteCollector())
    monkeypatch.setattr(api, "_actual_recipient_binding", lambda _: (harness.recipient, "dstack"))
    assert RECIPIENT_QUOTE_REQUEST_MAX_BYTES == 512
    body = json.dumps({"context": "artifact", "challenge_digest": "0x" + "99" * 32}).encode().ljust(512, b" ")
    with TestClient(api.app) as client:
        accepted = client.post("/attestation/recipient-quote", content=body, headers={"Content-Type": "application/json"})
        rejected = client.post("/attestation/recipient-quote", content=body + b" ", headers={"Content-Type": "application/json"})
    assert accepted.status_code == 200
    assert rejected.status_code == 413
    assert rejected.json() == {"detail": "request body exceeds route limit"}
    assert len(harness.quote_requests) == 1


@pytest.mark.parametrize("declared", [True, False])
def test_bootstrap_body_limit_rejects_before_oversize_bytes_reach_app(declared):
    from tinker_delegate.request_body_limits import RouteBodyLimitMiddleware
    received, sent = [], []
    messages = [
        {"type": "http.request", "body": b" " * 512, "more_body": True},
        {"type": "http.request", "body": b"not-reflected", "more_body": False},
    ]

    async def downstream(_scope, receive, _send):
        while True:
            message = await receive()
            received.append(message["body"])
            if not message.get("more_body"):
                break

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "method": "POST", "path": "/attestation/recipient-quote",
        "headers": [(b"content-length", b"525")] if declared else [],
    }
    asyncio.run(RouteBodyLimitMiddleware(downstream)(scope, receive, send))
    assert sent[0]["status"] == 413
    assert received == ([] if declared else [b" " * 512])
    assert b"not-reflected" not in sent[1]["body"]


def test_bootstrap_rate_bound_is_per_context_and_lock_is_not_held_during_io(monkeypatch):
    harness = Harness(monkeypatch)
    now = [100.0]
    collector = RecipientQuoteCollector(clock=lambda: now[0])
    entered, release = threading.Event(), threading.Event()
    def block():
        entered.set()
        assert release.wait(5)
    harness.after_quote = block
    args = {"challenge_digest": "0x" + "99" * 32, "custody_mode": "dstack"}
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(collector.collect, "artifact", harness.recipient, **args)
        assert entered.wait(5)
        assert collector._lock.acquire(blocking=False)
        collector._lock.release()
        now[0] += 3
        with pytest.raises(RecipientQuoteRateLimited):
            collector.collect("artifact", harness.recipient, **args)
        release.set()
        first.result(timeout=5)
    harness.after_quote = lambda: None
    collector.collect("artifact", harness.recipient, **args)
    with pytest.raises(RecipientQuoteRateLimited):
        collector.collect("artifact", harness.recipient, **args)
    arena = recipient_binding("arena", KEYPAIR.public_key_bytes)
    assert collector.collect("arena", arena, **args)["context"] == "arena"


def test_bootstrap_false_raw_report_local_and_simulator_are_rejected(monkeypatch):
    harness = Harness(monkeypatch)
    harness.modify_quote = lambda value: {**value, "quote_report_data": "0x" + "00" * 64}
    with pytest.raises(RecipientEvidenceUnavailable):
        RecipientQuoteCollector().collect("artifact", harness.recipient, challenge_digest="0x" + "99" * 32, custody_mode="dstack")
    harness.modify_quote = lambda value: value
    monkeypatch.setattr(dstack_utils, "is_dstack_simulator", lambda: True)
    with pytest.raises(RecipientEvidenceUnavailable):
        RecipientQuoteCollector().collect("artifact", harness.recipient, challenge_digest="0x" + "99" * 32, custody_mode="dstack")
    monkeypatch.setattr(dstack_utils, "is_dstack_simulator", lambda: False)
    monkeypatch.setattr(dstack_utils, "is_dstack_enabled", lambda: False)
    with pytest.raises(RecipientEvidenceUnavailable):
        RecipientQuoteCollector().collect("artifact", harness.recipient, challenge_digest="0x" + "99" * 32, custody_mode="dstack")
