import json
import unittest
from unittest.mock import patch

import httpx
from pydantic import ValidationError

from tinker_delegate.review_operations import (
    ReviewOperationsError,
    ReviewOperationsRetryable,
    ReviewOperationsSettings,
    ReviewOperationsWorker,
)


def _settings(**updates) -> ReviewOperationsSettings:
    values = {
        "enabled": True,
        "delegate_url": "http://delegate:8080",
        "oracle_url": "http://oracle:8000",
        "poll_interval_seconds": 30,
        "request_timeout_seconds": 5,
        "maximum_queue_pages": 4,
        "maximum_notifications_per_tick": 16,
        "notifications_enabled": True,
        "runtime_auth_token": "delegate-runtime-secret",
        "oracle_auth_token": "oracle-runtime-secret",
        "main_runtime_cvm_id": "cvm-main-review-0001",
        "deployment_intent_sha256": "sha256:" + "41" * 32,
        "release_authority_sha256": "sha256:" + "42" * 32,
        "ceremony_nonce": "0x" + "43" * 32,
        "policy_sha256": "sha256:" + "44" * 32,
        "active_reviewers_sha256": "sha256:" + "45" * 32,
        "genesis_acceptance_sha256": "sha256:" + "46" * 32,
        "current_status_epoch": 7,
        "current_status_sha256": "sha256:" + "47" * 32,
    }
    values.update(updates)
    return ReviewOperationsSettings(**values)


def _authority(settings: ReviewOperationsSettings) -> dict:
    return {
        "enabled": True,
        "chain_id": 84532,
        "authority_context_hash": "52" * 32,
        "release_context": {
            "schema": "dnai.review-release-context.v1",
            "chain_id": 84532,
            "wallet_domain": "www.wikigen.me",
            "wallet_uri": "https://www.wikigen.me",
            "main_runtime_cvm_id": settings.main_runtime_cvm_id,
            "deployment_intent_sha256": settings.deployment_intent_sha256,
            "release_authority_sha256": settings.release_authority_sha256,
            "ceremony_nonce": settings.ceremony_nonce,
        },
        "release_provenance": {
            "reviewer_authority_genesis_acceptance_sha256": (
                settings.genesis_acceptance_sha256
            ),
            "reviewer_authority_current_status_epoch": (
                settings.current_status_epoch
            ),
            "reviewer_authority_current_status_sha256": (
                settings.current_status_sha256
            ),
            "reviewer_authority_active_reviewers_sha256": (
                settings.active_reviewers_sha256
            ),
        },
        "active_reviewers": {
            "active_reviewer_count": 8,
            "active_reviewers_sha256": settings.active_reviewers_sha256,
            "raw_reviewer_identity_egress": False,
        },
        "policy_sha256": settings.policy_sha256,
        "rollback_protection": "base_sepolia_execution_policy_anchor",
        "rollback_anchor": {
            "block_number": 123,
            "state_hash": "53" * 32,
        },
    }


def _ticket(ref: str = "61" * 32, **updates) -> dict:
    value = {
        "ticket_ref_hash": ref,
        "turn_ref_hash": "62" * 32,
        "corpus_ref_hash": "63" * 32,
        "routed_role": "biosecurity-review",
        "reason_hash": "64" * 32,
        "opened_at": 1_800_000_000,
        "expires_at": 1_800_086_400,
        "status": "pending",
        "reviewer_ref_hash": "",
        "submitter_ref_hash": "65" * 32,
        "required_approvals": 2,
        "approvals_count": 0,
        "approval_reviewer_hashes": [],
        "approval_authorization_hashes": [],
        "reviewer_authorization_hash": "",
        "authority_context_hash": "",
        "decision_hash": "",
        "updated_at": 1_800_000_000,
        "raw_secret_egress": False,
    }
    value.update(updates)
    return value


def _queue(
    settings: ReviewOperationsSettings,
    *,
    tickets=None,
    has_more=False,
    next_cursor="",
) -> dict:
    ticket_values = list(tickets if tickets is not None else [_ticket()])
    return {
        "surface": "human_review_queue",
        "schema_version": 2,
        "ticket_count": len(ticket_values),
        "pending_count": len(ticket_values),
        "status_counts": {
            "pending": len(ticket_values),
            "released": 0,
            "denied": 0,
            "expired": 0,
        },
        "tickets": ticket_values,
        "audit_hash": "66" * 32,
        "audit_count": len(ticket_values),
        "raw_secret_egress": False,
        "page": {
            "limit": 100,
            "returned_count": len(ticket_values),
            "has_more": has_more,
            "next_cursor": next_cursor,
        },
        "authority": _authority(settings),
    }


def _receipt(body: dict, *, idempotent=False) -> dict:
    return {
        "schema": "dnai.review-notification-receipt.v1",
        "idempotency_key": body["idempotency_key"],
        "receipt_sha256": "71" * 32,
        "status": "delivered",
        "idempotent": idempotent,
        "raw_review_reason_egress": False,
        "raw_artifact_egress": False,
        "raw_reviewer_identity_egress": False,
    }


def _production_rollback_anchor() -> dict:
    return {
        "schema": "dnai.review-queue-rollback-anchor.v1",
        "state_hash": "81" * 32,
        "decision_hash": "82" * 32,
        "sequence": 9,
        "rollback_anchor": {
            "schema": "dnai-wikigen/execution-policy-anchor-status/v1",
            "status": "rpc_reported_finalized_release_match",
            "verification_model": (
                "single_rpc_reported_finalized_with_confirmation_depth"
            ),
            "chain_id": 84532,
            "independent_rpc_quorum_verified": False,
            "consensus_proof_verified": False,
            "opaque_commitments_only": True,
            "raw_resource_id_egress": False,
            "raw_policy_egress": False,
        },
        "opaque_commitments_only": True,
        "raw_ticket_egress": False,
        "raw_reviewer_identity_egress": False,
    }


class ReviewOperationsWorkerTest(unittest.TestCase):
    def test_tick_calls_authenticated_expiry_and_hash_only_oracle_boundary(self):
        settings = _settings()
        observed = []

        def handler(request: httpx.Request):
            observed.append(request)
            self.assertEqual(request.headers["cache-control"], "no-store")
            if request.url.host == "delegate":
                self.assertEqual(request.method, "POST")
                self.assertEqual(request.url.path, "/review/expire")
                self.assertEqual(
                    request.headers["authorization"],
                    "Bearer delegate-runtime-secret",
                )
                return httpx.Response(200, json=_queue(settings))
            body = json.loads(request.content)
            self.assertEqual(request.url.path, "/review/notifications")
            self.assertEqual(
                request.headers["authorization"],
                "Bearer oracle-runtime-secret",
            )
            self.assertEqual(
                set(body),
                {
                    "schema",
                    "event",
                    "ticket_ref_hash",
                    "routed_role",
                    "opened_at",
                    "expires_at",
                    "authority_context_hash",
                    "release_binding",
                    "idempotency_key",
                },
            )
            rendered = json.dumps(body, sort_keys=True)
            for private in (
                "reason_hash",
                "review_reason",
                "artifact",
                "reviewer_ref_hash",
                "submitter_ref_hash",
                "61" * 0 + "private-reviewer@example.test",
            ):
                self.assertNotIn(private, rendered)
            return httpx.Response(200, json=_receipt(body))

        client = httpx.Client(transport=httpx.MockTransport(handler))
        worker = ReviewOperationsWorker(
            settings,
            client=client,
            clock=lambda: 1_800_000_100,
        )

        tick = worker.run_once()

        self.assertEqual(len(observed), 2)
        self.assertEqual(tick.observed_pending, 1)
        self.assertEqual(tick.notification_delivered, 1)
        self.assertEqual(tick.notification_idempotent, 0)
        self.assertFalse(tick.page_limit_reached)
        public = tick.to_public_dict()
        self.assertFalse(public["raw_review_reason_egress"])
        self.assertFalse(public["raw_artifact_egress"])
        self.assertFalse(public["raw_reviewer_identity_egress"])

    def test_notifications_remain_unavailable_until_explicitly_enabled(self):
        settings = _settings(
            notifications_enabled=False,
            oracle_auth_token="",
        )
        calls = []

        def handler(request: httpx.Request):
            calls.append((request.method, request.url.host, request.url.path))
            return httpx.Response(200, json=_queue(settings))

        worker = ReviewOperationsWorker(
            settings,
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            clock=lambda: 1_800_000_100,
        )

        tick = worker.run_once()

        self.assertEqual(calls, [("POST", "delegate", "/review/expire")])
        self.assertEqual(tick.notification_skipped, 1)
        self.assertEqual(tick.notification_delivered, 0)

    def test_release_drift_fails_before_notification(self):
        settings = _settings()
        queue = _queue(settings)
        queue["authority"]["release_context"]["release_authority_sha256"] = (
            "sha256:" + "99" * 32
        )
        calls = []

        def handler(request: httpx.Request):
            calls.append(request.url.host)
            return httpx.Response(200, json=queue)

        worker = ReviewOperationsWorker(
            settings,
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            clock=lambda: 1_800_000_100,
        )

        with self.assertRaisesRegex(
            ReviewOperationsError,
            "release context changed",
        ):
            worker.run_once()
        self.assertEqual(calls, ["delegate"])

    def test_private_queue_field_fails_closed_before_notification(self):
        settings = _settings()
        queue = _queue(
            settings,
            tickets=[_ticket(artifact_content="private DNA sequence")],
        )
        calls = []

        def handler(request: httpx.Request):
            calls.append(request.url.host)
            return httpx.Response(200, json=queue)

        worker = ReviewOperationsWorker(
            settings,
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            clock=lambda: 1_800_000_100,
        )

        with self.assertRaisesRegex(ReviewOperationsError, "private ticket field"):
            worker.run_once()
        self.assertEqual(calls, ["delegate"])

    def test_expiry_retry_and_notification_ambiguity_are_separate(self):
        settings = _settings()
        expiry_worker = ReviewOperationsWorker(
            settings,
            client=httpx.Client(
                transport=httpx.MockTransport(
                    lambda _request: httpx.Response(503, json={"detail": "held"})
                )
            ),
            clock=lambda: 1_800_000_100,
        )
        with self.assertRaises(ReviewOperationsRetryable):
            expiry_worker.run_once()

        def ambiguous(request: httpx.Request):
            if request.url.host == "delegate":
                return httpx.Response(200, json=_queue(settings))
            return httpx.Response(
                409,
                json={
                    "detail": (
                        "Review notification delivery is ambiguous; "
                        "automatic retry is held"
                    )
                },
            )

        notification_worker = ReviewOperationsWorker(
            settings,
            client=httpx.Client(transport=httpx.MockTransport(ambiguous)),
            clock=lambda: 1_800_000_100,
        )
        tick = notification_worker.run_once()
        self.assertEqual(tick.notification_ambiguous, 1)
        self.assertEqual(tick.notification_retryable, 0)

    def test_non_ambiguity_conflict_fails_closed(self):
        settings = _settings()

        def rejected(request: httpx.Request):
            if request.url.host == "delegate":
                return httpx.Response(200, json=_queue(settings))
            return httpx.Response(
                409,
                json={"detail": "Review notification request was rejected"},
            )

        worker = ReviewOperationsWorker(
            settings,
            client=httpx.Client(transport=httpx.MockTransport(rejected)),
            clock=lambda: 1_800_000_100,
        )

        with self.assertRaisesRegex(
            ReviewOperationsError,
            "review notification was rejected",
        ):
            worker.run_once()

    def test_duplicate_response_fields_and_unknown_ticket_fields_fail_closed(self):
        settings = _settings()
        duplicate_worker = ReviewOperationsWorker(
            settings,
            client=httpx.Client(
                transport=httpx.MockTransport(
                    lambda _request: httpx.Response(
                        200,
                        content=b'{"surface":"human_review_queue","surface":"drifted"}',
                    )
                )
            ),
            clock=lambda: 1_800_000_100,
        )
        with self.assertRaisesRegex(ReviewOperationsError, "response is invalid"):
            duplicate_worker.run_once()

        queue = _queue(settings, tickets=[_ticket(unreviewed_private_field="secret")])
        shape_worker = ReviewOperationsWorker(
            settings,
            client=httpx.Client(
                transport=httpx.MockTransport(
                    lambda _request: httpx.Response(200, json=queue)
                )
            ),
            clock=lambda: 1_800_000_100,
        )
        with self.assertRaisesRegex(ReviewOperationsError, "ticket shape is invalid"):
            shape_worker.run_once()

    def test_production_requires_structured_reported_finalized_witness(self):
        with (
            patch(
                "tinker_delegate.review_operations.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.review_operations.dstack_utils.derive_storage_key",
                return_value=b"d" * 32,
            ),
        ):
            settings = _settings(
                production_release=True,
                runtime_auth_token="",
                oracle_auth_token="",
            )
            valid = _queue(settings)
            valid["authority"]["rollback_anchor"] = _production_rollback_anchor()

            valid_worker = ReviewOperationsWorker(
                settings,
                client=httpx.Client(
                    transport=httpx.MockTransport(
                        lambda request: (
                            httpx.Response(200, json=valid)
                            if request.url.host == "delegate"
                            else httpx.Response(
                                200,
                                json=_receipt(json.loads(request.content)),
                            )
                        )
                    )
                ),
                clock=lambda: 1_800_000_100,
            )
            self.assertEqual(valid_worker.run_once().notification_delivered, 1)

            drifted = _queue(settings)
            drifted["authority"]["rollback_anchor"] = {
                "block_number": 123,
                "state_hash": "53" * 32,
            }
            drifted_worker = ReviewOperationsWorker(
                settings,
                client=httpx.Client(
                    transport=httpx.MockTransport(
                        lambda _request: httpx.Response(200, json=drifted)
                    )
                ),
                clock=lambda: 1_800_000_100,
            )
            with self.assertRaisesRegex(
                ReviewOperationsError,
                "rollback witness is invalid",
            ):
                drifted_worker.run_once()

    def test_pagination_is_bounded_and_release_checked_on_every_page(self):
        settings = _settings(maximum_queue_pages=2)
        first_cursor = "61" * 32
        first = _queue(
            settings,
            tickets=[_ticket(ref=first_cursor)],
            has_more=True,
            next_cursor=first_cursor,
        )
        second = _queue(
            settings,
            tickets=[_ticket(ref="72" * 32)],
            has_more=True,
            next_cursor="72" * 32,
        )
        notified = []

        def handler(request: httpx.Request):
            if request.url.host == "delegate" and request.method == "POST":
                return httpx.Response(200, json=first)
            if request.url.host == "delegate":
                self.assertEqual(request.url.params["cursor"], first_cursor)
                return httpx.Response(200, json=second)
            body = json.loads(request.content)
            notified.append(body["ticket_ref_hash"])
            return httpx.Response(200, json=_receipt(body))

        worker = ReviewOperationsWorker(
            settings,
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            clock=lambda: 1_800_000_100,
        )
        tick = worker.run_once()

        self.assertEqual(notified, [first_cursor, "72" * 32])
        self.assertTrue(tick.page_limit_reached)

    def test_production_rejects_static_tokens_and_unreviewed_internal_urls(self):
        with patch(
            "tinker_delegate.review_operations.dstack_utils.is_dstack_enabled",
            return_value=True,
        ):
            with self.assertRaises(ValidationError):
                _settings(production_release=True)
            with self.assertRaises(ValidationError):
                _settings(
                    production_release=True,
                    runtime_auth_token="",
                    oracle_auth_token="",
                    delegate_url="http://127.0.0.1:8080",
                )

    def test_production_derives_two_exact_purpose_separated_bearers(self):
        settings_values = {
            "production_release": True,
            "runtime_auth_token": "",
            "oracle_auth_token": "",
        }
        with (
            patch(
                "tinker_delegate.review_operations.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.review_operations.dstack_utils.derive_storage_key",
                side_effect=lambda path: (
                    b"d" * 32 if path == "tinker/runtime-auth" else b"o" * 32
                ),
            ) as derive,
        ):
            settings = _settings(**settings_values)
            worker = ReviewOperationsWorker(
                settings,
                client=httpx.Client(
                    transport=httpx.MockTransport(
                        lambda _request: httpx.Response(503)
                    )
                ),
            )

        self.assertEqual(
            derive.call_args_list[0].args,
            ("tinker/runtime-auth",),
        )
        self.assertEqual(
            derive.call_args_list[1].args,
            ("oracle/runtime-auth",),
        )
        self.assertNotEqual(worker.delegate_token, worker.oracle_token)


if __name__ == "__main__":
    unittest.main()
