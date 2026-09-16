from __future__ import annotations

import re

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from attestation_qvl.errors import VerifierUnavailable
from attestation_qvl.qvl import IndependentQuoteVerifier
from attestation_qvl.signing import (
    DstackRoyaltySettlementSigner,
    DstackVerdictSigner,
    ROYALTY_SIGNER_PATH_PREFIX,
    SIGNER_PATH_PREFIX,
)
from tests.support import FakeBackend, FakeVerdictSigner, measurement_bytes, policy_payload, write_policy


def test_dstack_signer_path_includes_exact_canonical_policy_hash(monkeypatch):
    calls: list[tuple[str, str]] = []
    account = Account.from_key(bytes.fromhex("42" * 32))

    class Client:
        def is_reachable(self) -> bool:
            return True

        def get_key(self, path: str, purpose: str) -> object:
            calls.append((path, purpose))
            return object()

    monkeypatch.setattr("attestation_qvl.signing.DstackClient", Client)
    monkeypatch.setattr("attestation_qvl.signing.to_account_secure", lambda _result: account)
    policy_hash = "0x" + "ab" * 32
    signer = DstackVerdictSigner.from_policy_hash(policy_hash)

    assert calls == [(f"{SIGNER_PATH_PREFIX}/{policy_hash[2:]}", "ethereum-signing")]
    assert signer.address == account.address.lower()
    assert signer.custody == "dstack_derived_separate_cvm"
    digest = "0x" + "cd" * 32
    signature = signer.sign_digest(digest)
    assert re.fullmatch(r"0x[0-9a-f]{130}", signature)
    assert Account.recover_message(encode_defunct(hexstr=digest), signature=signature).lower() == signer.address


def test_dstack_royalty_signer_uses_distinct_key_path_and_raw_domain(monkeypatch):
    calls: list[tuple[str, str]] = []
    account = Account.from_key(bytes.fromhex("43" * 32))

    class Client:
        def is_reachable(self) -> bool:
            return True

        def get_key(self, path: str, purpose: str) -> object:
            calls.append((path, purpose))
            return object()

    monkeypatch.setattr("attestation_qvl.signing.DstackClient", Client)
    monkeypatch.setattr(
        "attestation_qvl.signing.to_account_secure", lambda _result: account
    )
    key_id = "0x" + "bc" * 32
    signer = DstackRoyaltySettlementSigner.from_key_id(key_id)

    assert calls == [
        (f"{ROYALTY_SIGNER_PATH_PREFIX}/{key_id[2:]}", "ethereum-signing")
    ]
    assert not signer.key_path.startswith(SIGNER_PATH_PREFIX)
    assert signer.custody == (
        "dstack_derived_diligence_qvl_royalty_settlement_signer"
    )
    digest = "0x" + "de" * 32
    signature = signer.sign_raw_digest(digest)
    assert Account._recover_hash(
        bytes.fromhex(digest[2:]), signature=signature
    ).lower() == signer.address
    assert Account.recover_message(
        encode_defunct(hexstr=digest), signature=signature
    ).lower() != signer.address


@pytest.mark.parametrize("key_id", ["bc" * 32, "0x" + "00" * 32, "0x1234"])
def test_royalty_signer_rejects_noncanonical_or_zero_key_id(monkeypatch, key_id):
    monkeypatch.setattr(
        "attestation_qvl.signing.DstackClient",
        lambda: pytest.fail("invalid key IDs must fail before dstack construction"),
    )
    with pytest.raises(VerifierUnavailable):
        DstackRoyaltySettlementSigner.from_key_id(key_id)


@pytest.mark.parametrize("name", ["DSTACK_SIMULATOR_ENDPOINT", "TAPPD_SIMULATOR_ENDPOINT"])
def test_production_signer_rejects_simulator_before_client_construction(monkeypatch, name):
    monkeypatch.setenv(name, "http://127.0.0.1:8090")
    monkeypatch.setattr(
        "attestation_qvl.signing.DstackClient",
        lambda: pytest.fail("simulator rejection must happen before dstack client construction"),
    )
    with pytest.raises(VerifierUnavailable):
        DstackVerdictSigner.from_policy_hash("0x" + "ab" * 32)
    with pytest.raises(VerifierUnavailable):
        DstackRoyaltySettlementSigner.from_key_id("0x" + "bc" * 32)


@pytest.mark.parametrize("policy_hash", ["ab" * 32, "0x" + "00" * 32, "0x1234"])
def test_signer_rejects_noncanonical_or_zero_policy_hash(monkeypatch, policy_hash):
    monkeypatch.setattr(
        "attestation_qvl.signing.DstackClient",
        lambda: pytest.fail("invalid hashes must fail before dstack client construction"),
    )
    with pytest.raises(VerifierUnavailable):
        DstackVerdictSigner.from_policy_hash(policy_hash)


def test_signer_rejects_unreachable_dstack_and_invalid_digest(monkeypatch):
    class Client:
        def is_reachable(self) -> bool:
            return False

    monkeypatch.setattr("attestation_qvl.signing.DstackClient", Client)
    with pytest.raises(VerifierUnavailable):
        DstackVerdictSigner.from_policy_hash("0x" + "ab" * 32)

    signer = DstackVerdictSigner(
        _account=Account.from_key(bytes.fromhex("42" * 32)),
        key_path="test-only",
    )
    with pytest.raises(VerifierUnavailable):
        signer.sign_digest("not-a-digest")


def test_qvl_refuses_a_verifier_identity_in_the_evaluated_signer_allowlist(tmp_path):
    signer = FakeVerdictSigner()
    payload = policy_payload()
    payload["allowed_signer_addresses"] = [signer.address]
    release = write_policy(tmp_path / "policy.json", payload)
    backend = FakeBackend(
        result=__import__("attestation_qvl.qvl", fromlist=["VerifiedQuote"]).VerifiedQuote(
            quote_type="TDX",
            status="OK",
            report_data=bytes(64),
            measurements=measurement_bytes(),
        )
    )
    with pytest.raises(VerifierUnavailable):
        IndependentQuoteVerifier(release=release, backend=backend, signer=signer)
