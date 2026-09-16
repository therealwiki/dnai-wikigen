from __future__ import annotations

import hashlib

import pytest
from eth_account import Account

from compute_metering.errors import SignerUnavailable
from compute_metering.signing import (
    DstackMeteringSigner,
    REPLAY_DERIVATION_DOMAIN,
    derive_dstack_replay_key,
    validate_canonical_signature,
)
from tests.support import METER, METER_ACCOUNT


def test_injected_signer_raw_signs_digest_with_low_s_signature():
    signer = DstackMeteringSigner(_account=METER_ACCOUNT, key_path="test/path")
    digest = "0x" + "12" * 32
    signature = signer.sign_digest(digest)
    raw = validate_canonical_signature(signature)
    recovered = Account._recover_hash(bytes.fromhex(digest[2:]), signature=raw).lower()
    assert signer.address == recovered == METER
    assert "private" not in repr(signer).lower()


@pytest.mark.parametrize(
    "signature",
    [
        "",
        "0x" + "00" * 65,
        "0x" + "11" * 64 + "00",
        "0x" + "11" * 64 + "1d",
        "0x" + "11" * 63,
    ],
)
def test_noncanonical_signatures_are_rejected(signature):
    with pytest.raises(SignerUnavailable):
        validate_canonical_signature(signature)


def test_production_derivation_rejects_simulator_environment(monkeypatch):
    monkeypatch.setenv("DSTACK_SIMULATOR_ENDPOINT", "http://localhost:8090")
    with pytest.raises(SignerUnavailable):
        DstackMeteringSigner.from_policy_set_hash("0x" + "12" * 32)
    with pytest.raises(SignerUnavailable):
        derive_dstack_replay_key("0x" + "12" * 32)


def test_dstack_paths_are_policy_rotating_and_purposes_are_separate(monkeypatch):
    calls: list[tuple[str, str]] = []

    class Result:
        def decode_key(self):
            return b"r" * 32

    class Client:
        def is_reachable(self):
            return True

        def get_key(self, path, purpose):
            calls.append((path, purpose))
            return Result()

    monkeypatch.setattr("compute_metering.signing.DstackClient", Client)
    monkeypatch.setattr("compute_metering.signing.to_account_secure", lambda _result: METER_ACCOUNT)
    first_hash = "0x" + "12" * 32
    second_hash = "0x" + "13" * 32
    signer = DstackMeteringSigner.from_policy_set_hash(first_hash)
    first_key = derive_dstack_replay_key(first_hash)
    second_key = derive_dstack_replay_key(second_hash)
    assert signer.address == METER
    assert calls[0][0].endswith(first_hash[2:]) and calls[0][1] == "ethereum-signing"
    assert calls[1][0].endswith(first_hash[2:]) and calls[1][1] == "hmac-sha256"
    assert calls[2][0].endswith(second_hash[2:]) and calls[2][1] == "hmac-sha256"
    assert first_key != second_key
    assert first_key == hashlib.sha256(
        REPLAY_DERIVATION_DOMAIN + bytes.fromhex(first_hash[2:]) + b"r" * 32
    ).digest()


@pytest.mark.parametrize("value", ["", "0x" + "00" * 32, "0x12", "0X" + "12" * 32])
def test_invalid_policy_set_hash_fails_before_dstack(value):
    with pytest.raises(SignerUnavailable):
        DstackMeteringSigner.from_policy_set_hash(value)
