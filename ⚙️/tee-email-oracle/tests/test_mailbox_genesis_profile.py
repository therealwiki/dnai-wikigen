from __future__ import annotations

import asyncio
from contextlib import redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from email_oracle import api
from email_oracle.config import Settings
from email_oracle.cred_store import EmailCredentials
from email_oracle.mailbox_genesis_profile import (
    ACCOUNT_GENESIS_RETIREMENT_SCHEMA,
    MAILBOX_GENESIS_RECEIPT_SCHEMA,
    MAILBOX_HANDOFF_RETIREMENT_SCHEMA,
    MailboxGenesisProfileError,
    account_retirement_is_complete,
    durably_unlink_mailbox_handoff,
    publish_mailbox_handoff_retirement,
    run_mailbox_genesis_profile,
)


RELEASE_SHA = "1" * 40
APP_ID = "0x" + "2" * 40
COMPOSE_HASH = "3" * 64
OS_IMAGE_HASH = "4" * 64


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
        "account_binding_commitment": "0x" + "c" * 64,
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


class _MemoryStore:
    def __init__(self) -> None:
        self.credentials: EmailCredentials | None = None

    def exists(self) -> bool:
        return self.credentials is not None

    def save(self, credentials: EmailCredentials) -> None:
        self.credentials = credentials

    def load(self) -> EmailCredentials | None:
        return self.credentials


def _mailbox_genesis_writes_bounded_create_only_receipt_and_retirement(
    tmp_path: Path,
    case: unittest.TestCase,
) -> None:
    store = _MemoryStore()
    credentials = EmailCredentials(
        username="private-user",
        domain="example.test",
        password="private-password",
    )
    calls = 0

    async def create(_settings, target) -> EmailCredentials:
        nonlocal calls
        calls += 1
        print("private-user@example.test private-password")
        target.save(credentials)
        return credentials

    evidence = tmp_path / "evidence" / "mailbox-genesis"
    handoff = tmp_path / "handoff" / "signup-mailbox.enc"
    output = StringIO()
    with redirect_stdout(output):
        receipt = asyncio.run(
            run_mailbox_genesis_profile(
                SimpleNamespace(),
                store,  # type: ignore[arg-type]
                lineage=_lineage(),
                evidence_directory=evidence,
                handoff_path=handoff,
                create_account_fn=create,
                runtime_evidence_fn=_runtime,
                handoff_key=b"\x11" * 32,
                clock=iter((100, 101, 102)).__next__,
                evidence_mode="injected_local_test",
            )
        )

    assert calls == 1
    assert "private-user@example.test" not in output.getvalue()
    assert receipt["schema"] == MAILBOX_GENESIS_RECEIPT_SCHEMA
    assert receipt["success"] is True
    assert receipt["mailbox_created"] is True
    assert receipt["sealed_credentials_roundtrip_verified"] is True
    assert receipt["sealed_mailbox_handoff_created"] is True
    assert receipt["independent_qvl_verified_by_profile"] is False
    assert receipt["raw_secret_egress"] is False
    assert handoff.is_file()
    assert stat.S_IMODE(handoff.stat().st_mode) == 0o600
    assert stat.S_IMODE((evidence / "receipt.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((evidence / "retirement.json").stat().st_mode) == 0o600
    assert (evidence / "receipt.json").stat().st_nlink == 1
    assert (evidence / "receipt.json").stat().st_uid == os.geteuid()

    rendered_receipt = (evidence / "receipt.json").read_text(encoding="ascii")
    for forbidden in (
        credentials.username,
        credentials.domain,
        credentials.email,
        credentials.password,
        hashlib.sha256(credentials.email.encode()).hexdigest(),
        hashlib.sha256(credentials.password.encode()).hexdigest(),
        "nonce_b64",
        "ciphertext_b64",
    ):
        assert forbidden not in rendered_receipt

    with case.assertRaisesRegex(
        MailboxGenesisProfileError,
        "already exists",
    ):
        asyncio.run(
            run_mailbox_genesis_profile(
                SimpleNamespace(),
                _MemoryStore(),  # type: ignore[arg-type]
                lineage=_lineage(),
                evidence_directory=evidence,
                handoff_path=tmp_path / "different-handoff" / "mailbox.enc",
                create_account_fn=create,
                runtime_evidence_fn=_runtime,
                handoff_key=b"\x11" * 32,
                evidence_mode="injected_local_test",
            )
        )
    assert calls == 1


def _mailbox_genesis_runtime_bearer_is_dstack_derived_and_never_empty(
    case: unittest.TestCase,
) -> None:
    settings = Settings(
        runtime_auth_required=True,
        runtime_auth_token="",
        runtime_auth_key_path="oracle/runtime-auth",
        dstack_enabled=True,
    )
    key = b"\x91" * 32
    expected = hashlib.sha256(
        b"email-oracle-runtime-auth:" + key
    ).hexdigest()

    with patch.object(api.state, "settings", settings):
        with patch("email_oracle.api.derive_storage_key", return_value=key):
            with case.assertRaises(HTTPException) as missing:
                api.require_runtime_auth("")
            assert missing.exception.status_code == 401

            with case.assertRaises(HTTPException) as wrong:
                api.require_runtime_auth("Bearer wrong")
            assert wrong.exception.status_code == 403

            api.require_runtime_auth(f"Bearer {expected}")


def _mailbox_genesis_rejects_noncanonical_timestamp_before_claim(
    tmp_path: Path,
    invalid_timestamp,
    case: unittest.TestCase,
) -> None:
    called = False

    async def create(_settings, _store):
        nonlocal called
        called = True
        raise AssertionError("must not run")

    evidence = tmp_path / "evidence" / "mailbox-genesis"
    with case.assertRaisesRegex(
        MailboxGenesisProfileError,
        "timestamp is invalid",
    ):
        asyncio.run(
            run_mailbox_genesis_profile(
                SimpleNamespace(),
                _MemoryStore(),  # type: ignore[arg-type]
                lineage=_lineage(),
                evidence_directory=evidence,
                handoff_path=tmp_path / "handoff" / "mailbox.enc",
                create_account_fn=create,
                runtime_evidence_fn=_runtime,
                handoff_key=b"\x11" * 32,
                clock=lambda: invalid_timestamp,
                evidence_mode="injected_local_test",
            )
        )
    assert called is False
    assert not (evidence / "claim.json").exists()


def _account_retirement(lineage: dict) -> dict:
    return {
        "schema": ACCOUNT_GENESIS_RETIREMENT_SCHEMA,
        "status": "retired_after_single_attempt",
        "account_genesis_success": True,
        "retry_permitted": False,
        "profile_must_remain_disabled": True,
        "retired_at": 400,
        "release_sha": lineage["release_sha"],
        "deployment_intent_sha256": lineage[
            "deployment_intent_sha256"
        ],
        "genesis_authorization_sha256": lineage[
            "genesis_authorization_sha256"
        ],
        "tinker_account_binding_ceremony_receipt_sha256": lineage[
            "tinker_account_binding_ceremony_receipt_sha256"
        ],
        "account_binding_commitment": lineage[
            "account_binding_commitment"
        ],
        "reviewer_genesis_acceptance_sha256": lineage[
            "reviewer_genesis_acceptance_sha256"
        ],
        "reviewer_current_status_epoch": lineage[
            "reviewer_current_status_epoch"
        ],
        "reviewer_current_status_sha256": lineage[
            "reviewer_current_status_sha256"
        ],
        "raw_secret_egress": False,
    }


def _mailbox_watcher_rejects_partial_or_substituted_retirement(
    tmp_path: Path,
) -> None:
    lineage = _lineage()
    parent = tmp_path / "account-evidence" / "tinker-account-genesis"
    parent.mkdir(mode=0o700, parents=True)
    retirement_path = parent / "retirement.json"
    retirement_path.write_bytes(b"")
    retirement_path.chmod(0o600)
    assert not account_retirement_is_complete(
        retirement_path,
        lineage=lineage,
    )

    retirement_path.write_bytes(b'{"schema":')
    assert not account_retirement_is_complete(
        retirement_path,
        lineage=lineage,
    )

    complete = _account_retirement(lineage)
    retirement_path.write_text(
        json.dumps(
            complete,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    assert account_retirement_is_complete(
        retirement_path,
        lineage=lineage,
    )

    complete["account_binding_commitment"] = "0x" + "d" * 64
    retirement_path.write_text(
        json.dumps(
            complete,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    assert not account_retirement_is_complete(
        retirement_path,
        lineage=lineage,
    )


def _mailbox_handoff_unlink_is_durable_and_rejects_link_race(
    tmp_path: Path,
    case: unittest.TestCase,
) -> None:
    parent = tmp_path / "handoff" / "mailbox-genesis"
    parent.mkdir(mode=0o700, parents=True)
    handoff = parent / "signup-mailbox.enc"
    handoff.write_text('{"sealed":true}\n', encoding="ascii")
    handoff.chmod(0o600)

    alias = parent / "alias.enc"
    alias.hardlink_to(handoff)
    with case.assertRaisesRegex(
        MailboxGenesisProfileError,
        "retirement binding is invalid",
    ):
        durably_unlink_mailbox_handoff(handoff)
    assert handoff.exists()
    alias.unlink()

    durably_unlink_mailbox_handoff(handoff)
    assert not handoff.exists()


def _mailbox_handoff_retirement_receipt_is_create_only_and_bounded(
    tmp_path: Path,
    case: unittest.TestCase,
) -> None:
    parent = tmp_path / "handoff" / "mailbox-genesis"
    parent.mkdir(mode=0o700, parents=True)
    handoff = parent / "signup-mailbox.enc"
    receipt_path = (
        tmp_path / "evidence" / "mailbox-genesis" / "handoff-retirement.json"
    )
    receipt = publish_mailbox_handoff_retirement(
        handoff_path=handoff,
        lineage=_lineage(),
        retirement_receipt_path=receipt_path,
        clock=lambda: 777,
    )
    assert receipt == {
        "schema": MAILBOX_HANDOFF_RETIREMENT_SCHEMA,
        "status": "encrypted_mailbox_handoff_retired",
        "account_genesis_retirement_observed": True,
        "handoff_path_absent_after_directory_fsync": True,
        "release_sha": RELEASE_SHA,
        "genesis_authorization_sha256": "sha256:" + "6" * 64,
        "tinker_account_binding_ceremony_receipt_sha256": (
            "sha256:" + "b" * 64
        ),
        "retired_at": 777,
        "raw_secret_egress": False,
    }
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600
    assert json.loads(receipt_path.read_text(encoding="ascii")) == receipt
    with case.assertRaisesRegex(
        MailboxGenesisProfileError,
        "already exists",
    ):
        publish_mailbox_handoff_retirement(
            handoff_path=handoff,
            lineage=_lineage(),
            retirement_receipt_path=receipt_path,
            clock=lambda: 778,
        )

    second_parent = tmp_path / "handoff-present"
    second_parent.mkdir(mode=0o700)
    present = second_parent / "signup-mailbox.enc"
    present.write_text('{"sealed":true}\n', encoding="ascii")
    present.chmod(0o600)
    with case.assertRaisesRegex(
        MailboxGenesisProfileError,
        "present after retirement",
    ):
        publish_mailbox_handoff_retirement(
            handoff_path=present,
            lineage=_lineage(),
            retirement_receipt_path=tmp_path / "must-not-exist.json",
            clock=lambda: 779,
        )
    assert not (tmp_path / "must-not-exist.json").exists()


def _mailbox_genesis_failure_is_bounded_and_permanently_retires(
    tmp_path: Path,
) -> None:
    calls = 0

    async def fail(_settings, _store):
        nonlocal calls
        calls += 1
        raise RuntimeError("provider body with private@example.test")

    evidence = tmp_path / "evidence" / "mailbox-genesis"
    receipt = asyncio.run(
        run_mailbox_genesis_profile(
            SimpleNamespace(),
            _MemoryStore(),  # type: ignore[arg-type]
            lineage=_lineage(),
            evidence_directory=evidence,
            handoff_path=tmp_path / "handoff" / "signup-mailbox.enc",
            create_account_fn=fail,
            runtime_evidence_fn=_runtime,
            handoff_key=b"\x22" * 32,
            clock=iter((200, 201, 202)).__next__,
            evidence_mode="injected_local_test",
        )
    )

    assert calls == 1
    assert receipt["success"] is False
    assert receipt["mailbox_created"] is None
    assert receipt["runtime"] is None
    rendered = (evidence / "receipt.json").read_text(encoding="ascii")
    assert "private@example.test" not in rendered
    retirement = json.loads(
        (evidence / "retirement.json").read_text(encoding="ascii")
    )
    assert retirement["retry_permitted"] is False
    assert retirement["profile_must_remain_disabled"] is True


def _mailbox_genesis_rejects_dstack_identity_drift_before_provider_call(
    tmp_path: Path,
) -> None:
    called = False

    async def create(_settings, _store):
        nonlocal called
        called = True
        raise AssertionError("must not run")

    receipt = asyncio.run(
        run_mailbox_genesis_profile(
            SimpleNamespace(),
            _MemoryStore(),  # type: ignore[arg-type]
            lineage=_lineage(),
            evidence_directory=tmp_path / "evidence" / "mailbox-genesis",
            handoff_path=tmp_path / "handoff" / "signup-mailbox.enc",
            create_account_fn=create,
            runtime_evidence_fn=lambda _data: {
                "app_id": "0x" + "f" * 40,
                "compose_hash": COMPOSE_HASH,
                "os_image_hash": OS_IMAGE_HASH,
            },
            handoff_key=b"\x33" * 32,
            clock=iter((300, 301, 302)).__next__,
            evidence_mode="injected_local_test",
        )
    )

    assert called is False
    assert receipt["success"] is False


class MailboxGenesisProfileTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.tmp_path = Path(temporary_directory.name)

    def test_mailbox_genesis_writes_bounded_create_only_receipt_and_retirement(
        self,
    ) -> None:
        _mailbox_genesis_writes_bounded_create_only_receipt_and_retirement(
            self.tmp_path,
            self,
        )

    def test_mailbox_genesis_runtime_bearer_is_dstack_derived_and_never_empty(
        self,
    ) -> None:
        _mailbox_genesis_runtime_bearer_is_dstack_derived_and_never_empty(
            self,
        )

    def test_mailbox_genesis_rejects_boolean_timestamp_before_claim(
        self,
    ) -> None:
        _mailbox_genesis_rejects_noncanonical_timestamp_before_claim(
            self.tmp_path,
            True,
            self,
        )

    def test_mailbox_genesis_rejects_negative_timestamp_before_claim(
        self,
    ) -> None:
        _mailbox_genesis_rejects_noncanonical_timestamp_before_claim(
            self.tmp_path,
            -1,
            self,
        )

    def test_mailbox_genesis_rejects_oversized_timestamp_before_claim(
        self,
    ) -> None:
        _mailbox_genesis_rejects_noncanonical_timestamp_before_claim(
            self.tmp_path,
            1 << 53,
            self,
        )

    def test_mailbox_watcher_rejects_partial_or_substituted_retirement(
        self,
    ) -> None:
        _mailbox_watcher_rejects_partial_or_substituted_retirement(
            self.tmp_path,
        )

    def test_mailbox_handoff_unlink_is_durable_and_rejects_link_race(
        self,
    ) -> None:
        _mailbox_handoff_unlink_is_durable_and_rejects_link_race(
            self.tmp_path,
            self,
        )

    def test_mailbox_handoff_retirement_receipt_is_create_only_and_bounded(
        self,
    ) -> None:
        _mailbox_handoff_retirement_receipt_is_create_only_and_bounded(
            self.tmp_path,
            self,
        )

    def test_mailbox_genesis_failure_is_bounded_and_permanently_retires(
        self,
    ) -> None:
        _mailbox_genesis_failure_is_bounded_and_permanently_retires(
            self.tmp_path,
        )

    def test_mailbox_genesis_rejects_dstack_identity_drift_before_provider_call(
        self,
    ) -> None:
        _mailbox_genesis_rejects_dstack_identity_drift_before_provider_call(
            self.tmp_path,
        )
