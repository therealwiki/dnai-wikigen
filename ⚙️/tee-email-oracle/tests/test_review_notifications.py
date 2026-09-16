import asyncio
import json
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from email_oracle.api import app, state
from email_oracle.config import Settings
from email_oracle.cred_store import EmailCredentials
from email_oracle.review_notifications import (
    REVIEW_NOTIFICATION_REQUEST_SCHEMA,
    REVIEW_NOTIFICATION_ROLES,
    _read_bounded_request_body,
    ReviewNotificationReceiptStore,
    ReviewNotificationService,
    reset_review_notification_service,
    review_notification_idempotency_key,
    review_recipient_policy_sha256,
)


def _recipient_document() -> dict:
    return {
        "schema": "dnai.review-notification-recipients.v1",
        "roles": [
            {
                "role": role,
                "recipients": [f"{role}@reviewers.example"],
            }
            for role in sorted(REVIEW_NOTIFICATION_ROLES)
        ],
    }


def _settings(root: Path, **updates) -> Settings:
    recipients = _recipient_document()
    values = {
        "runtime_auth_required": True,
        "runtime_auth_token": "oracle-runtime-secret",
        "review_notifications_enabled": True,
        "review_notification_recipients_json": json.dumps(recipients),
        "review_notification_recipients_sha256": (
            review_recipient_policy_sha256(recipients)
        ),
        "review_notification_smtp_host": "smtp.reviewers.example",
        "review_notification_smtp_port": 465,
        "review_notification_receipt_store_path": str(
            root / "notification-receipts.json"
        ),
        "review_notification_receipt_store_key": "31" * 32,
        "review_notification_main_runtime_cvm_id": "cvm-main-review-0001",
        "review_notification_deployment_intent_sha256": "sha256:" + "41" * 32,
        "review_notification_release_authority_sha256": "sha256:" + "42" * 32,
        "review_notification_ceremony_nonce": "0x" + "43" * 32,
        "review_notification_policy_sha256": "sha256:" + "44" * 32,
        "review_notification_active_reviewers_sha256": "sha256:" + "45" * 32,
        "review_notification_genesis_acceptance_sha256": "sha256:" + "46" * 32,
        "review_notification_current_status_epoch": 7,
        "review_notification_current_status_sha256": "sha256:" + "47" * 32,
    }
    values.update(updates)
    return Settings(**values)


def _request(settings: Settings, **updates) -> dict:
    unsigned = {
        "schema": REVIEW_NOTIFICATION_REQUEST_SCHEMA,
        "event": "pending",
        "ticket_ref_hash": "51" * 32,
        "routed_role": "biosecurity-review",
        "opened_at": 1_800_000_000,
        "expires_at": 1_800_086_400,
        "authority_context_hash": "52" * 32,
        "release_binding": {
            "chain_id": 84532,
            "wallet_domain": "www.wikigen.me",
            "wallet_uri": "https://www.wikigen.me",
            "main_runtime_cvm_id": (
                settings.review_notification_main_runtime_cvm_id
            ),
            "deployment_intent_sha256": (
                settings.review_notification_deployment_intent_sha256
            ),
            "release_authority_sha256": (
                settings.review_notification_release_authority_sha256
            ),
            "ceremony_nonce": settings.review_notification_ceremony_nonce,
            "policy_sha256": settings.review_notification_policy_sha256,
            "active_reviewers_sha256": (
                settings.review_notification_active_reviewers_sha256
            ),
            "genesis_acceptance_sha256": (
                settings.review_notification_genesis_acceptance_sha256
            ),
            "current_status_epoch": (
                settings.review_notification_current_status_epoch
            ),
            "current_status_sha256": (
                settings.review_notification_current_status_sha256
            ),
        },
    }
    unsigned.update(updates)
    return {
        **unsigned,
        "idempotency_key": review_notification_idempotency_key(unsigned),
    }


class FakeConnection:
    def __init__(self, *, fail_send: bool = False, refused=None):
        self.fail_send = fail_send
        self.refused = refused or {}
        self.calls = []

    def send_message(self, message, *, from_addr, to_addrs):
        self.calls.append(
            {
                "message": message,
                "from_addr": from_addr,
                "to_addrs": list(to_addrs),
            }
        )
        if self.fail_send:
            raise OSError("post-DATA transport outcome unknown")
        return self.refused


class FakeMailer:
    def __init__(self, connection: FakeConnection):
        self.connection = connection
        self.connect_count = 0

    @contextmanager
    def connect(self, _credentials):
        self.connect_count += 1
        yield self.connection


class ReviewNotificationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings = _settings(self.root)
        self.original_settings = state.settings
        self.original_creds = state.creds
        state.settings = self.settings
        state.creds = EmailCredentials(
            "oracle",
            "mail.example",
            "mailbox-password",
        )
        reset_review_notification_service()
        self.client = TestClient(app)

    def tearDown(self):
        reset_review_notification_service()
        state.settings = self.original_settings
        state.creds = self.original_creds
        self.tmp.cleanup()

    @staticmethod
    def _allowed():
        return SimpleNamespace(allowed=True, checked=True)

    def _install_service(self, *, fail_send: bool = False, refused=None):
        connection = FakeConnection(fail_send=fail_send, refused=refused)
        mailer = FakeMailer(connection)
        service = ReviewNotificationService(
            self.settings,
            state.creds,
            mailer=mailer,
            clock=lambda: 1_800_000_100,
        )
        patcher = patch(
            "email_oracle.review_notifications._review_notification_service",
            return_value=service,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        return connection, mailer

    def _assert_no_store(self, *responses):
        for response in responses:
            self.assertEqual(
                response.headers.get("cache-control"),
                "no-store, max-age=0",
                response.text,
            )

    def _post(self, body: dict):
        return self.client.post(
            "/review/notifications",
            headers={"Authorization": "Bearer oracle-runtime-secret"},
            json=body,
        )

    def test_delivery_is_idempotent_and_keeps_recipient_identity_in_smtp_envelope(self):
        connection, mailer = self._install_service()
        request = _request(self.settings)
        private_reason = "raw review reason must not escape"
        private_artifact = "ACTG-private-artifact"
        private_reviewer = "reviewer-primary@example.test"

        with patch(
            "email_oracle.review_notifications.check_consumer_authorization",
            return_value=self._allowed(),
        ) as authorization:
            first = self._post(request)
            replay = self._post(request)

        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(replay.status_code, 200, replay.text)
        self._assert_no_store(first, replay)
        self.assertFalse(first.json()["idempotent"])
        self.assertTrue(replay.json()["idempotent"])
        self.assertEqual(
            first.json()["receipt_sha256"],
            replay.json()["receipt_sha256"],
        )
        self.assertEqual(len(connection.calls), 1)
        # A duplicate may establish a new authenticated SMTP connection before
        # it reads the durable receipt, but it never submits a second message.
        self.assertEqual(mailer.connect_count, 2)

        sent = connection.calls[0]
        message_text = sent["message"].as_string()
        message_body = sent["message"].get_content()
        self.assertIn(request["ticket_ref_hash"], message_body)
        self.assertIn("biosecurity-review", message_body)
        self.assertEqual(sent["message"]["To"], "undisclosed-recipients:;")
        self.assertNotIn(sent["to_addrs"][0], message_text)
        self.assertEqual(
            sent["to_addrs"],
            ["biosecurity-review@reviewers.example"],
        )

        rendered = first.text + replay.text
        store = Path(
            self.settings.review_notification_receipt_store_path
        ).read_text(encoding="utf-8")
        for secret in (
            private_reason,
            private_artifact,
            private_reviewer,
            "biosecurity-review@reviewers.example",
            "mailbox-password",
        ):
            self.assertNotIn(secret, rendered)
            self.assertNotIn(secret, store)
        self.assertFalse(first.json()["raw_review_reason_egress"])
        self.assertFalse(first.json()["raw_artifact_egress"])
        self.assertFalse(first.json()["raw_reviewer_identity_egress"])
        for call in authorization.call_args_list:
            self.assertEqual(
                call.kwargs["caller_identity"],
                "tinker-delegate.review-operations",
            )
            self.assertIs(call.kwargs["required"], True)
            self.assertEqual(
                call.args[0].auth_expected_caller_identity,
                "tinker-delegate.review-operations",
            )

    def test_ambiguous_smtp_outcome_is_never_automatically_retried(self):
        connection, _mailer = self._install_service(fail_send=True)
        request = _request(self.settings)

        with patch(
            "email_oracle.review_notifications.check_consumer_authorization",
            return_value=self._allowed(),
        ):
            first = self._post(request)
            retry = self._post(request)

        self.assertEqual(first.status_code, 409, first.text)
        self.assertEqual(retry.status_code, 409, retry.text)
        self._assert_no_store(first, retry)
        self.assertEqual(len(connection.calls), 1)
        self.assertEqual(
            retry.json(),
            {
                "detail": (
                    "Review notification delivery is ambiguous; "
                    "automatic retry is held"
                )
            },
        )

    def test_release_mismatch_and_onchain_denial_happen_before_smtp(self):
        connection, mailer = self._install_service()
        drifted = _request(self.settings)
        drifted["release_binding"]["release_authority_sha256"] = (
            "sha256:" + "99" * 32
        )
        drifted["idempotency_key"] = review_notification_idempotency_key(
            {key: value for key, value in drifted.items() if key != "idempotency_key"}
        )

        with patch(
            "email_oracle.review_notifications.check_consumer_authorization",
            return_value=self._allowed(),
        ):
            mismatch = self._post(drifted)
        self.assertEqual(mismatch.status_code, 409, mismatch.text)
        self._assert_no_store(mismatch)
        self.assertEqual(mailer.connect_count, 0)
        self.assertEqual(connection.calls, [])

        denied = SimpleNamespace(allowed=False, checked=True)
        with patch(
            "email_oracle.review_notifications.check_consumer_authorization",
            return_value=denied,
        ):
            response = self._post(_request(self.settings))
        self.assertEqual(response.status_code, 403, response.text)
        self._assert_no_store(response)
        self.assertEqual(mailer.connect_count, 0)
        self.assertEqual(connection.calls, [])

    def test_disabled_delivery_and_missing_runtime_auth_fail_closed(self):
        state.settings = self.settings.model_copy(
            update={"review_notifications_enabled": False}
        )
        disabled = self._post(_request(self.settings))
        self.assertEqual(disabled.status_code, 503)
        self._assert_no_store(disabled)

        state.settings = self.settings.model_copy(
            update={"runtime_auth_required": False, "runtime_auth_token": ""}
        )
        missing_auth = self._post(_request(self.settings))
        self.assertEqual(missing_auth.status_code, 503)
        self._assert_no_store(missing_auth)
        self.assertEqual(
            missing_auth.json(),
            {"detail": "Review notification runtime auth is unavailable"},
        )

    def test_invalid_extra_fields_are_not_reflected(self):
        raw_reason = "highly sensitive raw review reason"
        body = _request(self.settings)
        body["review_reason"] = raw_reason

        response = self._post(body)

        self.assertEqual(response.status_code, 400, response.text)
        self._assert_no_store(response)
        self.assertEqual(
            response.json(),
            {"detail": "Review notification request is invalid"},
        )
        self.assertNotIn(raw_reason, response.text)

    def test_missing_or_unchecked_chain_authorization_fails_closed(self):
        connection, mailer = self._install_service()
        request = _request(self.settings)

        # The local test settings deliberately have no auth contract. The
        # notification endpoint must still force the policy check instead of
        # inheriting the generic oracle's optional-policy behavior.
        missing_policy = self._post(request)
        self.assertEqual(missing_policy.status_code, 503, missing_policy.text)

        unchecked_allow = SimpleNamespace(allowed=True, checked=False)
        with patch(
            "email_oracle.review_notifications.check_consumer_authorization",
            return_value=unchecked_allow,
        ):
            unchecked = self._post(request)
        self.assertEqual(unchecked.status_code, 503, unchecked.text)
        self._assert_no_store(missing_policy, unchecked)
        self.assertEqual(mailer.connect_count, 0)
        self.assertEqual(connection.calls, [])

    def test_caller_identity_configuration_must_be_exact(self):
        connection, mailer = self._install_service()
        state.settings = self.settings.model_copy(
            update={"review_notification_caller_identity": "tinker-delegate.signup"}
        )

        with patch(
            "email_oracle.review_notifications.check_consumer_authorization"
        ) as authorization:
            response = self._post(_request(self.settings))

        self.assertEqual(response.status_code, 503, response.text)
        self._assert_no_store(response)
        authorization.assert_not_called()
        self.assertEqual(mailer.connect_count, 0)
        self.assertEqual(connection.calls, [])

    def test_partial_recipient_refusal_is_ambiguous_and_never_retried(self):
        connection, _mailer = self._install_service(
            refused={
                "biosecurity-review@reviewers.example": (
                    450,
                    b"mailbox temporarily unavailable",
                )
            }
        )
        request = _request(self.settings)

        with patch(
            "email_oracle.review_notifications.check_consumer_authorization",
            return_value=self._allowed(),
        ):
            first = self._post(request)
            retry = self._post(request)

        self.assertEqual(first.status_code, 409, first.text)
        self.assertEqual(retry.status_code, 409, retry.text)
        self._assert_no_store(first, retry)
        self.assertEqual(len(connection.calls), 1)

    def test_noncanonical_release_types_and_runtime_auth_errors_are_no_store(self):
        connection, mailer = self._install_service()
        request = _request(self.settings)
        request["release_binding"]["chain_id"] = 84_532.0
        request["idempotency_key"] = review_notification_idempotency_key(
            {key: value for key, value in request.items() if key != "idempotency_key"}
        )

        with patch(
            "email_oracle.review_notifications.check_consumer_authorization",
            return_value=self._allowed(),
        ):
            noncanonical = self._post(request)
        missing_bearer = self.client.post(
            "/review/notifications",
            json=_request(self.settings),
        )

        self.assertEqual(noncanonical.status_code, 409, noncanonical.text)
        self.assertEqual(missing_bearer.status_code, 401, missing_bearer.text)
        self._assert_no_store(noncanonical, missing_bearer)
        self.assertEqual(mailer.connect_count, 0)
        self.assertEqual(connection.calls, [])

    def test_recipient_policy_is_redacted_and_invalid_policy_errors_do_not_echo_it(self):
        recipient_sentinel = "private-reviewer-identity@example.test"
        invalid_policy = json.dumps(
            {
                "schema": "dnai.review-notification-recipients.v1",
                "roles": [
                    {
                        "role": "biosecurity-review",
                        "recipients": [recipient_sentinel],
                    }
                ],
            }
        )
        state.settings = self.settings.model_copy(
            update={"review_notification_recipients_json": invalid_policy}
        )
        reset_review_notification_service()

        with patch(
            "email_oracle.review_notifications.check_consumer_authorization",
            return_value=self._allowed(),
        ):
            response = self._post(_request(state.settings))

        self.assertEqual(response.status_code, 503, response.text)
        self._assert_no_store(response)
        self.assertNotIn(recipient_sentinel, response.text)
        self.assertNotIn(
            "biosecurity-review@reviewers.example",
            repr(self.settings),
        )
        self.assertIn("**********", repr(self.settings))
        receipt_path = Path(
            state.settings.review_notification_receipt_store_path
        )
        self.assertFalse(receipt_path.exists())

    def test_chunked_body_is_rejected_while_streaming_at_the_exact_cap(self):
        def oversized_chunks():
            yield b"{" + (b" " * 8_191)
            yield b" " * 8_193

        with patch(
            "email_oracle.review_notifications.check_consumer_authorization"
        ) as authorization:
            response = self.client.post(
                "/review/notifications",
                headers={
                    "Authorization": "Bearer oracle-runtime-secret",
                    "Content-Type": "application/json",
                },
                content=oversized_chunks(),
            )

        self.assertEqual(response.status_code, 413, response.text)
        self._assert_no_store(response)
        authorization.assert_not_called()

        receive_calls = 0
        messages = iter(
            (
                {
                    "type": "http.request",
                    "body": b"a" * 8_192,
                    "more_body": True,
                },
                {
                    "type": "http.request",
                    "body": b"b" * 8_193,
                    "more_body": True,
                },
                {
                    "type": "http.request",
                    "body": b"must-not-be-read",
                    "more_body": False,
                },
            )
        )

        async def receive():
            nonlocal receive_calls
            receive_calls += 1
            return next(messages)

        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/review/notifications",
                "headers": [],
            },
            receive,
        )
        with self.assertRaisesRegex(HTTPException, "too large") as raised:
            asyncio.run(_read_bounded_request_body(request))
        self.assertEqual(raised.exception.status_code, 413)
        self.assertEqual(receive_calls, 2)

    def test_receipt_store_rejects_authenticated_state_tamper(self):
        path = self.root / "receipts.json"
        store = ReviewNotificationReceiptStore(path, bytes.fromhex("31" * 32))
        store.reserve(
            idempotency_key="51" * 32,
            request_sha256="52" * 32,
            now=1_800_000_000,
        )
        document = json.loads(path.read_text(encoding="utf-8"))
        document["records"][0]["status"] = "delivered"
        path.write_text(json.dumps(document), encoding="utf-8")

        with self.assertRaisesRegex(RuntimeError, "integrity"):
            store.reserve(
                idempotency_key="51" * 32,
                request_sha256="52" * 32,
                now=1_800_000_100,
            )


if __name__ == "__main__":
    unittest.main()
