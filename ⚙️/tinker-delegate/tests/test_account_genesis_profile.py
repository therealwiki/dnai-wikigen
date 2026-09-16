from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path
import stat

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

from tinker_delegate.account_genesis_profile import (
    ACCOUNT_GENESIS_RECEIPT_SCHEMA,
    MAILBOX_HANDOFF_AAD,
    MAILBOX_HANDOFF_KEY_PATH,
    MAILBOX_HANDOFF_SCHEMA,
    AccountGenesisProfileError,
    run_account_genesis_profile,
)
from tinker_delegate.config import Settings
from tinker_delegate.tinker_account_binding import (
    derive_tinker_account_binding_root,
    derive_tinker_account_commitment,
)


RELEASE_SHA = "1" * 40
APP_ID = "0x" + "2" * 40
COMPOSE_HASH = "3" * 64
OS_IMAGE_HASH = "4" * 64
HANDOFF_KEY = b"\x55" * 32
FIRST_SHARE = b"\x11" * 32
SECOND_SHARE = b"\x22" * 32
EXPECTED_COMMITMENT = derive_tinker_account_commitment(
    derive_tinker_account_binding_root([FIRST_SHARE, SECOND_SHARE])
)


def _lineage() -> dict:
    return {
        "release_sha": RELEASE_SHA,
        "deployment_intent_sha256": "sha256:" + "5" * 64,
        "genesis_authorization_sha256": "sha256:" + "6" * 64,
        "main_qvl_verdict_sha256": "sha256:" + "7" * 64,
        "measurement_policy_sha256": "sha256:" + "8" * 64,
        "main_runtime_cvm_id": "cvm-main-1",
        "main_app_id": APP_ID,
        "main_compose_hash": COMPOSE_HASH,
        "main_os_image_hash": OS_IMAGE_HASH,
        "tinker_account_binding_ceremony_receipt_sha256": (
            "sha256:" + "b" * 64
        ),
        "reviewer_genesis_acceptance_sha256": "sha256:" + "9" * 64,
        "reviewer_current_status_epoch": 3,
        "reviewer_current_status_sha256": "sha256:" + "a" * 64,
    }


def _runtime(_report_data: bytes) -> dict:
    return {
        "app_id": APP_ID,
        "compose_hash": COMPOSE_HASH,
        "os_image_hash": OS_IMAGE_HASH,
    }


def _write_handoff(path: Path, email: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True)
    plaintext = (
        json.dumps(
            {"schema": MAILBOX_HANDOFF_SCHEMA, "email": email},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")
    nonce = b"\x44" * 12
    ciphertext = AESGCM(HANDOFF_KEY).encrypt(
        nonce,
        plaintext,
        MAILBOX_HANDOFF_AAD,
    )
    payload = {
        "schema": MAILBOX_HANDOFF_SCHEMA,
        "algorithm": "AES-256-GCM",
        "key_path": MAILBOX_HANDOFF_KEY_PATH,
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }
    descriptor = path.open("x", encoding="ascii")
    try:
        path.chmod(0o600)
        json.dump(payload, descriptor, sort_keys=True, separators=(",", ":"))
        descriptor.write("\n")
    finally:
        descriptor.close()


def _shares() -> tuple[bytearray, bytearray]:
    return bytearray(FIRST_SHARE), bytearray(SECOND_SHARE)


def test_account_genesis_recomputes_immutable_binding_before_provider_and_retires(
    tmp_path: Path,
    capsys,
) -> None:
    mailbox = "private-user@example.test"
    handoff = tmp_path / "handoff" / "signup-mailbox.enc"
    _write_handoff(handoff, mailbox)
    evidence = tmp_path / "evidence" / "tinker-account-genesis"
    settings = Settings()
    calls = 0
    shares = _shares()

    async def signup(received: Settings) -> dict:
        nonlocal calls
        calls += 1
        assert received.email == mailbox
        print("private-user@example.test tml-private-api-key")
        return {
            "success": True,
            "stored": True,
            "api_key_created": True,
            # These legacy bounded signup fields must not be projected into the
            # genesis receipt because they are derived from secret material.
            "email_hash": "b" * 64,
            "api_key_hash": "c" * 64,
        }

    receipt = asyncio.run(
        run_account_genesis_profile(
            settings,
            lineage=_lineage(),
            expected_commitment=EXPECTED_COMMITMENT,
            shares=shares,
            evidence_directory=evidence,
            handoff_path=handoff,
            signup_fn=signup,
            api_key_roundtrip_fn=lambda _settings: True,
            runtime_evidence_fn=_runtime,
            handoff_key=HANDOFF_KEY,
            clock=iter((100, 101, 102)).__next__,
            evidence_mode="injected_local_test",
        )
    )

    assert calls == 1
    assert "private-user@example.test" not in capsys.readouterr().out
    assert receipt["schema"] == ACCOUNT_GENESIS_RECEIPT_SCHEMA
    assert receipt["success"] is True
    assert receipt["upstream_account_exists"] is True
    assert receipt["identity_check_performed"] is True
    assert receipt["identity_check_status"] == "passed"
    assert receipt["api_key_sealed"] is True
    assert receipt["binding"]["commitment"] == EXPECTED_COMMITMENT
    assert receipt["binding"]["provider_identifier_committed"] is False
    assert receipt["binding"]["attested_provider_binding_required"] is True
    assert receipt["independent_qvl_verified_by_profile"] is False
    assert receipt["raw_secret_egress"] is False
    assert settings.email == ""
    assert bytes(shares[0]) == b"\x00" * 32
    assert bytes(shares[1]) == b"\x00" * 32
    assert stat.S_IMODE((evidence / "receipt.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((evidence / "retirement.json").stat().st_mode) == 0o600
    assert (evidence / "receipt.json").stat().st_nlink == 1
    assert (evidence / "receipt.json").stat().st_uid == os.geteuid()

    rendered = (evidence / "receipt.json").read_text(encoding="ascii")
    private_root = derive_tinker_account_binding_root([FIRST_SHARE, SECOND_SHARE])
    for forbidden in (
        mailbox,
        "private-user",
        "example.test",
        FIRST_SHARE.hex(),
        SECOND_SHARE.hex(),
        private_root.hex(),
        "email_hash",
        "api_key_hash",
        "provider_account_id",
        "ciphertext_b64",
        "nonce_b64",
    ):
        assert forbidden not in rendered

    retirement = json.loads(
        (evidence / "retirement.json").read_text(encoding="ascii")
    )
    assert retirement["retry_permitted"] is False
    assert retirement["profile_must_remain_disabled"] is True
    assert (
        retirement["tinker_account_binding_ceremony_receipt_sha256"]
        == _lineage()["tinker_account_binding_ceremony_receipt_sha256"]
    )


def test_account_genesis_rejects_share_mismatch_before_provider_side_operation(
    tmp_path: Path,
) -> None:
    called = False

    async def signup(_settings: Settings) -> dict:
        nonlocal called
        called = True
        raise AssertionError("must not run")

    shares = _shares()
    with pytest.raises(
        AccountGenesisProfileError,
        match="do not match deployment intent",
    ):
        asyncio.run(
            run_account_genesis_profile(
                Settings(),
                lineage=_lineage(),
                expected_commitment="0x" + "f" * 64,
                shares=shares,
                evidence_directory=tmp_path / "evidence",
                handoff_path=tmp_path / "missing-handoff",
                signup_fn=signup,
                api_key_roundtrip_fn=lambda _settings: True,
                runtime_evidence_fn=_runtime,
                handoff_key=HANDOFF_KEY,
                evidence_mode="injected_local_test",
            )
        )
    assert called is False
    assert not (tmp_path / "evidence" / "claim.json").exists()
    assert bytes(shares[0]) == b"\x00" * 32
    assert bytes(shares[1]) == b"\x00" * 32


def test_account_genesis_wipes_shares_when_public_authority_is_invalid(
    tmp_path: Path,
) -> None:
    called = False

    async def signup(_settings: Settings) -> dict:
        nonlocal called
        called = True
        raise AssertionError("must not run")

    shares = _shares()
    with pytest.raises(
        AccountGenesisProfileError,
        match="deployment-intent account-binding commitment is invalid",
    ):
        asyncio.run(
            run_account_genesis_profile(
                Settings(),
                lineage=_lineage(),
                expected_commitment="invalid",
                shares=shares,
                evidence_directory=tmp_path / "evidence",
                handoff_path=tmp_path / "missing-handoff",
                signup_fn=signup,
                api_key_roundtrip_fn=lambda _settings: True,
                runtime_evidence_fn=_runtime,
                handoff_key=HANDOFF_KEY,
                evidence_mode="injected_local_test",
            )
        )
    assert called is False
    assert not (tmp_path / "evidence").exists()
    assert bytes(shares[0]) == b"\x00" * 32
    assert bytes(shares[1]) == b"\x00" * 32


def test_account_genesis_failure_is_bounded_and_no_retry_is_possible(
    tmp_path: Path,
) -> None:
    handoff = tmp_path / "handoff" / "signup-mailbox.enc"
    _write_handoff(handoff, "private-user@example.test")
    evidence = tmp_path / "evidence" / "tinker-account-genesis"
    calls = 0

    async def fail(_settings: Settings) -> dict:
        nonlocal calls
        calls += 1
        raise RuntimeError("provider body with tml-private-secret")

    receipt = asyncio.run(
        run_account_genesis_profile(
            Settings(),
            lineage=_lineage(),
            expected_commitment=EXPECTED_COMMITMENT,
            shares=_shares(),
            evidence_directory=evidence,
            handoff_path=handoff,
            signup_fn=fail,
            api_key_roundtrip_fn=lambda _settings: False,
            runtime_evidence_fn=_runtime,
            handoff_key=HANDOFF_KEY,
            clock=iter((200, 201, 202)).__next__,
            evidence_mode="injected_local_test",
        )
    )

    assert receipt["success"] is False
    assert receipt["upstream_account_exists"] is None
    assert receipt["identity_check_performed"] is False
    rendered = (evidence / "receipt.json").read_text(encoding="ascii")
    assert "tml-private-secret" not in rendered
    assert "private-user@example.test" not in rendered

    with pytest.raises(AccountGenesisProfileError, match="already exists"):
        asyncio.run(
            run_account_genesis_profile(
                Settings(),
                lineage=_lineage(),
                expected_commitment=EXPECTED_COMMITMENT,
                shares=_shares(),
                evidence_directory=evidence,
                handoff_path=handoff,
                signup_fn=fail,
                api_key_roundtrip_fn=lambda _settings: False,
                runtime_evidence_fn=_runtime,
                handoff_key=HANDOFF_KEY,
                evidence_mode="injected_local_test",
            )
        )
    assert calls == 1


@pytest.mark.parametrize("roundtrip_result", ["false", 1])
def test_account_genesis_requires_exact_true_api_key_roundtrip(
    tmp_path: Path,
    roundtrip_result,
) -> None:
    handoff = tmp_path / "handoff" / "signup-mailbox.enc"
    _write_handoff(handoff, "private-user@example.test")

    async def signup(_settings: Settings) -> dict:
        return {
            "success": True,
            "stored": True,
            "api_key_created": True,
        }

    receipt = asyncio.run(
        run_account_genesis_profile(
            Settings(),
            lineage=_lineage(),
            expected_commitment=EXPECTED_COMMITMENT,
            shares=_shares(),
            evidence_directory=(
                tmp_path / "evidence" / "tinker-account-genesis"
            ),
            handoff_path=handoff,
            signup_fn=signup,
            api_key_roundtrip_fn=lambda _settings: roundtrip_result,
            runtime_evidence_fn=_runtime,
            handoff_key=HANDOFF_KEY,
            clock=iter((250, 251, 252)).__next__,
            evidence_mode="injected_local_test",
        )
    )

    assert receipt["success"] is False
    assert receipt["api_key_sealed"] is False
    assert receipt["upstream_account_exists"] is None


@pytest.mark.parametrize("invalid_timestamp", [True, -1, 1 << 53])
def test_account_genesis_rejects_noncanonical_timestamp_before_claim(
    tmp_path: Path,
    invalid_timestamp,
) -> None:
    called = False

    async def signup(_settings: Settings) -> dict:
        nonlocal called
        called = True
        raise AssertionError("must not run")

    with pytest.raises(
        AccountGenesisProfileError,
        match="timestamp is invalid",
    ):
        asyncio.run(
            run_account_genesis_profile(
                Settings(),
                lineage=_lineage(),
                expected_commitment=EXPECTED_COMMITMENT,
                shares=_shares(),
                evidence_directory=tmp_path / "evidence",
                handoff_path=tmp_path / "missing-handoff",
                signup_fn=signup,
                api_key_roundtrip_fn=lambda _settings: True,
                runtime_evidence_fn=_runtime,
                handoff_key=HANDOFF_KEY,
                clock=lambda: invalid_timestamp,
                evidence_mode="injected_local_test",
            )
        )
    assert called is False
    assert not (tmp_path / "evidence" / "claim.json").exists()


def test_account_genesis_runtime_identity_drift_prevents_provider_call(
    tmp_path: Path,
) -> None:
    handoff = tmp_path / "handoff" / "signup-mailbox.enc"
    _write_handoff(handoff, "private-user@example.test")
    called = False

    async def signup(_settings: Settings) -> dict:
        nonlocal called
        called = True
        raise AssertionError("must not run")

    receipt = asyncio.run(
        run_account_genesis_profile(
            Settings(),
            lineage=_lineage(),
            expected_commitment=EXPECTED_COMMITMENT,
            shares=_shares(),
            evidence_directory=tmp_path / "evidence",
            handoff_path=handoff,
            signup_fn=signup,
            api_key_roundtrip_fn=lambda _settings: True,
            runtime_evidence_fn=lambda _data: {
                "app_id": "0x" + "f" * 40,
                "compose_hash": COMPOSE_HASH,
                "os_image_hash": OS_IMAGE_HASH,
            },
            handoff_key=HANDOFF_KEY,
            clock=iter((300, 301, 302)).__next__,
            evidence_mode="injected_local_test",
        )
    )

    assert called is False
    assert receipt["success"] is False
