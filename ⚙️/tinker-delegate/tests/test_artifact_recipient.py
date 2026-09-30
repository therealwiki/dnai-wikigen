"""Artifact-only dstack key lifecycle; synthetic key material, no provider I/O."""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from tinker_delegate import api, card_channel, dstack_utils
from tinker_delegate.arena_ingress import INGRESS_DSTACK_KEY_PATH, resolve_arena_keypair
from tinker_delegate.artifacts import artifact_commitment, encrypt_artifact_payload
from tinker_delegate.card_channel import ArtifactRecipientUnavailable, get_artifact_keypair
from tinker_delegate.crypto import TEEKeyPair
from tinker_delegate.recipient_evidence import RecipientQuoteCollector


@pytest.fixture
def real_dstack(monkeypatch):
    """Mock only key/quote acquisition; execute real resolver and API code."""
    calls = []
    for module in (dstack_utils, card_channel):
        monkeypatch.setattr(module, "is_dstack_enabled", lambda: True)
        monkeypatch.setattr(module, "is_dstack_simulator", lambda: False)

    def derive(path):
        calls.append(path)
        return hashlib.sha256(b"synthetic non-authorizing dstack material:" + path.encode()).digest()

    def quote(report):
        report = report.ljust(64, b"\x00")
        raw = bytearray(b"\x51" * 1024)
        raw[:2] = (4).to_bytes(2, "little")
        raw[4:8] = (0x81).to_bytes(4, "little")
        raw[568:632] = report
        return {
            "quote": "0x" + raw.hex(), "quote_report_data": "0x" + report.hex(),
            "compose_hash": "0x" + "55" * 32, "app_id": "66" * 20,
            "os_image_hash": "77" * 32,
        }

    monkeypatch.setattr(dstack_utils, "derive_storage_key", derive)
    monkeypatch.setattr(dstack_utils, "get_attestation_details", quote)
    monkeypatch.setattr(card_channel, "get_attestation_details", quote)
    return calls


def test_fresh_objects_rederive_restart_stable_key_independent_of_boot_key(real_dstack, monkeypatch):
    first = get_artifact_keypair(require_dstack=True)
    monkeypatch.setattr(card_channel, "_tee_keypair", TEEKeyPair())
    restarted = get_artifact_keypair(require_dstack=True)
    assert restarted is not first
    assert restarted.public_key_bytes == first.public_key_bytes
    assert real_dstack == ["tinker/artifact_ingress", "tinker/artifact_ingress"]


def test_artifact_key_is_separate_from_billing_shared_ingress_and_arena(real_dstack, monkeypatch):
    billing = TEEKeyPair.from_private_key_hex("31" * 32)
    monkeypatch.setattr(card_channel, "_tee_keypair", billing)
    artifact = get_artifact_keypair(require_dstack=True)
    arena = resolve_arena_keypair()
    assert len({artifact.public_key_bytes, billing.public_key_bytes, arena.public_key_bytes}) == 3
    assert card_channel.get_tee_keypair() is billing
    assert real_dstack == ["tinker/artifact_ingress", INGRESS_DSTACK_KEY_PATH]
    for context in ("billing", "ingress"):
        assert card_channel.get_attestation(context)["encryption_public_key"] == billing.public_key_bytes.hex()
    assert len(real_dstack) == 2


@pytest.mark.parametrize("enabled,simulator", [(False, False), (True, True)])
def test_production_recipient_path_rejects_local_and_simulator(monkeypatch, enabled, simulator):
    for module in (dstack_utils, card_channel):
        monkeypatch.setattr(module, "is_dstack_enabled", lambda: enabled)
        monkeypatch.setattr(module, "is_dstack_simulator", lambda: simulator)
    monkeypatch.setattr(dstack_utils, "derive_storage_key", lambda _: pytest.fail("must not derive outside real dstack"))
    monkeypatch.setattr(card_channel, "get_attestation_details", lambda _: {
        "quote": "modeled-only", "app_id": "modeled", "compose_hash": "modeled",
    })
    with pytest.raises(ArtifactRecipientUnavailable, match="^Artifact recipient is unavailable$"):
        get_artifact_keypair(require_dstack=True)
    with TestClient(api.app) as client:
        response = client.post("/attestation/recipient-quote", json={
            "context": "artifact", "challenge_digest": "0x" + "99" * 32,
        })
    assert response.status_code == 503
    assert response.json() == {"detail": "Recipient evidence is unavailable"}
    # Explicitly modeled legacy/development flows remain supported.
    assert get_artifact_keypair() is card_channel.get_tee_keypair()
    assert card_channel.get_attestation("artifact")["mode"] == ("simulator" if simulator else "local")


@pytest.mark.parametrize("material", [b"", b"x" * 31, b"x" * 33, b"\x00" * 32, "secret-invalid-material"])
def test_invalid_production_material_never_falls_back_or_leaks(real_dstack, monkeypatch, material):
    monkeypatch.setattr(dstack_utils, "derive_storage_key", lambda _: material)
    with pytest.raises(ArtifactRecipientUnavailable) as failure:
        get_artifact_keypair()
    assert str(failure.value) == "Artifact recipient is unavailable"
    assert failure.value.__cause__ is None


def test_derivation_failure_is_fixed_unavailable_not_a_new_boot_key(real_dstack, monkeypatch):
    def failure(_):
        raise RuntimeError("synthetic-private-derivation-error")
    monkeypatch.setattr(dstack_utils, "derive_storage_key", failure)
    with TestClient(api.app) as client:
        response = client.get("/attestation?context=artifact")
    assert response.status_code == 503
    assert response.json() == {"detail": "Artifact recipient is unavailable"}
    assert response.headers["cache-control"] == "no-store"


def test_bootstrap_legacy_attestation_and_decrypt_share_artifact_key_after_restart(real_dstack, monkeypatch):
    seller, room, evaluator = "0x" + "11" * 20, "0x" + "33" * 20, "0x" + "44" * 32
    artifact, secret = b"synthetic-private-artifact", b"\x12" * 32
    commitment = artifact_commitment(artifact, secret)
    seen = []

    def receive(deal_id, plaintext, artifact_hash, commitment_secret):
        seen.append((deal_id, bytes(plaintext), artifact_hash, bytes(commitment_secret)))

    cp = SimpleNamespace(
        get_deal_context=lambda _: SimpleNamespace(
            seller=seller, committed_artifact_hash=commitment, evaluator_policy_commitment=evaluator),
        receive_artifact=receive,
    )
    monkeypatch.setattr(api, "_get_control_plane", lambda: cp)
    monkeypatch.setattr(api, "_require_wallet_auth", lambda *_, **__: SimpleNamespace(address=seller))
    monkeypatch.setattr(api.settings, "diligence_chain_id", 84532)
    monkeypatch.setattr(api.settings, "diligence_room_address", room)
    monkeypatch.setattr(api, "_recipient_quote_collector", RecipientQuoteCollector())
    with TestClient(api.app) as client:
        advertised = client.get("/attestation?context=artifact")
        bootstrap = client.post("/attestation/recipient-quote", json={
            "context": "artifact", "challenge_digest": "0x" + "99" * 32,
        })
        assert advertised.status_code == bootstrap.status_code == 200
        public_key = advertised.json()["encryption_public_key"]
        assert bootstrap.json()["recipient"]["encryption_public_key"] == public_key
        assert bootstrap.json()["recipient"]["report_data"] == advertised.json()["report_data"]
        encrypted = encrypt_artifact_payload(
            artifact, public_key, deal_id="1", artifact_hash=commitment,
            commitment_secret=secret, chain_id=84532, diligence_room_address=room,
            evaluator_policy_commitment=evaluator,
        )
        # An unrelated fresh boot key must not change production artifact custody.
        monkeypatch.setattr(card_channel, "_tee_keypair", TEEKeyPair())
        response = client.post("/deal/1/artifact/encrypted", json=encrypted,
                               headers={"Authorization": "Bearer synthetic-wallet"})
    assert response.status_code == 200
    assert seen == [("1", artifact, commitment, secret)]
    assert public_key != card_channel.get_tee_keypair().public_key_bytes.hex()
    assert real_dstack == ["tinker/artifact_ingress"] * 3
