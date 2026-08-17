import json
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.config import Settings
from tinker_delegate.coordination import (
    CollabSession,
    ConsentGrant,
    CoordinationState,
    Corpus,
    DelegationGrant,
    GateDecision,
    GateResults,
    GatedQuery,
    Participant,
    ParticipantRole,
    SubmitTurn,
    Turn,
    coordinate,
)
from tinker_delegate.review_authority import (
    REVIEW_ACTIVE_REVIEWERS_SCHEMA,
    REVIEW_AUTHORITY_POLICY_SCHEMA,
    REVIEW_AUTHORITY_ROLES,
    ReviewChallengeStore,
    ReviewQueueReadLimiter,
    review_authority_context_hash,
    review_authority_active_reviewers_sha256,
    review_authority_policy,
    review_authority_policy_sha256,
    review_queue_integrity_key,
)
from tinker_delegate.review_queue import (
    ReviewQueueState,
    enqueue_handoff_tickets,
    load_review_queue,
    review_ticket_ref_hash,
    save_review_queue,
)
from tinker_delegate.wallet_challenge_limiter import (
    WalletChallengeAdmissionLimiter,
    WalletChallengePeerPolicy,
)


def _held_tickets():
    session = CollabSession(
        participants=(
            Participant("owner-atlas", ParticipantRole.OWNER),
            Participant("sponsor", ParticipantRole.REQUESTER),
            Participant("cro-agent", ParticipantRole.AGENT, owner_ref="sponsor"),
            Participant("access-officer", ParticipantRole.REVIEWER),
        ),
        corpora=(Corpus("corpus://atlas", "owner-atlas", policy_hash="atlas-policy"),),
        consent_grants=(
            ConsentGrant("corpus://atlas", "owner-atlas", "sponsor", "rank", "sft"),
        ),
        delegation_grants=(
            DelegationGrant(
                "cro-agent", "sponsor", ("corpus://atlas",), ("rank",), ("sft",)
            ),
        ),
    )
    turn = Turn(
        turn_id="turn-1",
        by="cro-agent",
        requester_ref="sponsor",
        purpose="rank",
        pipeline="sft",
        corpora=("corpus://atlas",),
        requests={"corpus://atlas": {"purpose": "rank"}},
    )
    state = coordinate(CoordinationState(session), SubmitTurn(turn))
    state = coordinate(
        state,
        GateResults(
            "turn-1",
            (
                GatedQuery(
                    "corpus://atlas",
                    GateDecision.HOLD,
                    stage=2,
                    reason="dual-use review",
                    routed_role="access-review-officer",
                ),
            ),
        ),
    )
    return state.turns["turn-1"].tickets


class ReviewQueueApiTest(unittest.TestCase):
    def setUp(self):
        self.originals = {
            "settings": api.settings,
            "review_challenges": api._review_challenges,
            "wallet_limiter": api._wallet_challenge_limiter,
            "peer_policy": api._wallet_challenge_peer_policy,
            "read_limiter": api._review_queue_read_limiter,
            "repository_lock": api._review_queue_repository_lock,
        }
        self._tmp = tempfile.TemporaryDirectory()
        self.queue_path = str(Path(self._tmp.name).resolve() / "review-queue.json")
        self.reviewer_a = Account.create()
        self.reviewer_b = Account.create()
        self.submitter = Account.create()
        self.outsider = Account.create()
        reviewer_roster = [
            {
                "address": self.reviewer_a.address,
                "reviewer_ref": "officer-a",
            },
            {
                "address": self.reviewer_b.address,
                "reviewer_ref": "officer-b",
            },
            {
                "address": self.submitter.address,
                "reviewer_ref": "cro-agent",
            },
        ]
        self.policy_document = {
            "schema": REVIEW_AUTHORITY_POLICY_SCHEMA,
            "roles": [
                {
                    "role": role,
                    "threshold": 2,
                    "reviewers": [dict(reviewer) for reviewer in reviewer_roster],
                }
                for role in sorted(REVIEW_AUTHORITY_ROLES)
            ],
        }
        self.active_reviewers_document = {
            "schema": REVIEW_ACTIVE_REVIEWERS_SCHEMA,
            "reviewers": [
                {
                    "address": reviewer["address"],
                    "controller_id": reviewer["reviewer_ref"],
                }
                for reviewer in reviewer_roster
            ],
        }
        policy_sha = review_authority_policy_sha256(self.policy_document)
        active_reviewers_sha = review_authority_active_reviewers_sha256(
            self.active_reviewers_document
        )
        self.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
            review_queue_path=self.queue_path,
            review_queue_store_integrity_key="review-queue-test-integrity-" + "k" * 48,
            review_authority_policy_json=json.dumps(self.policy_document),
            review_authority_policy_sha256=policy_sha,
            release_reviewer_authority_active_reviewers_json=json.dumps(
                self.active_reviewers_document
            ),
            release_reviewer_authority_active_reviewers_sha256=(
                active_reviewers_sha
            ),
            review_authority_challenge_ttl_seconds=300,
            review_authority_max_pending_challenges=1024,
            main_runtime_cvm_id="cvm-main-runtime-0001",
            release_deployment_intent_sha256="sha256:" + "41" * 32,
            release_authority_sha256="sha256:" + "42" * 32,
            release_ceremony_nonce="0x" + "43" * 32,
            release_reviewer_authority_genesis_acceptance_sha256=(
                "sha256:" + "44" * 32
            ),
            release_reviewer_authority_current_status_epoch=7,
            release_reviewer_authority_current_status_sha256=(
                "sha256:" + "45" * 32
            ),
        )
        self.policy = review_authority_policy(self.settings)
        self.authority_context_hash = review_authority_context_hash(
            self.settings, self.policy
        )
        self.integrity_key = review_queue_integrity_key(self.settings)
        queue = enqueue_handoff_tickets(
            ReviewQueueState.empty(),
            _held_tickets(),
            opened_at=int(time.time()),
            ttl_seconds=100_000,
            required_approvals_by_role=self.policy.required_approvals_by_role(),
        )
        save_review_queue(
            self.queue_path,
            queue,
            integrity_key=self.integrity_key,
            authority_context_hash=self.authority_context_hash,
        )
        self.ticket_id = next(iter(queue.tickets))
        self.ticket_ref_hash = review_ticket_ref_hash(self.ticket_id)

        api.settings = self.settings
        api._review_challenges = ReviewChallengeStore(max_pending=1024)
        api._wallet_challenge_limiter = WalletChallengeAdmissionLimiter.from_settings(
            self.settings
        )
        api._wallet_challenge_peer_policy = WalletChallengePeerPolicy()
        api._review_queue_read_limiter = ReviewQueueReadLimiter.from_settings(
            self.settings
        )
        api._review_queue_repository_lock = threading.RLock()
        self.client = TestClient(api.app)

    def tearDown(self):
        api.settings = self.originals["settings"]
        api._review_challenges = self.originals["review_challenges"]
        api._wallet_challenge_limiter = self.originals["wallet_limiter"]
        api._wallet_challenge_peer_policy = self.originals["peer_policy"]
        api._review_queue_read_limiter = self.originals["read_limiter"]
        api._review_queue_repository_lock = self.originals["repository_lock"]
        self._tmp.cleanup()

    @staticmethod
    def _runtime_header():
        return {"Authorization": "Bearer operator-secret"}

    def _challenge(self, account, *, decision="release", ticket_ref_hash=None):
        response = self.client.post(
            "/auth/review/challenge",
            json={
                "address": account.address,
                "ticket_ref_hash": ticket_ref_hash or self.ticket_ref_hash,
                "decision": decision,
            },
        )
        if response.status_code != 200:
            return response, ""
        message = response.json()["message"]
        signature = Account.sign_message(
            encode_defunct(text=message), account.key
        ).signature.hex()
        return response, signature

    def _decide(self, challenge_response, signature):
        return self.client.post(
            "/review/decide",
            json={"nonce": challenge_response.json()["nonce"], "signature": signature},
        )

    @staticmethod
    def _new_handoff_payload(**updates):
        handoff = {
            "ticket_id": "ticket-new",
            "turn_id": "turn-new",
            "corpus_ref": "bio://held-result",
            "routed_role": "biosecurity-review",
            "reason_hash": "9" * 64,
            "submitter_ref": "agent-new",
        }
        handoff.update(updates)
        return {"tickets": [handoff]}

    def test_internal_enqueue_requires_configured_runtime_bearer(self):
        payload = self._new_handoff_payload()
        missing = self.client.post("/review/internal/enqueue", json=payload)
        self.assertEqual(missing.status_code, 401, missing.text)
        self.assertEqual(missing.json(), {"detail": "Bearer token required"})

        wrong = self.client.post(
            "/review/internal/enqueue",
            json=payload,
            headers={"Authorization": "Bearer wrong-secret"},
        )
        self.assertEqual(wrong.status_code, 403, wrong.text)
        self.assertEqual(wrong.json(), {"detail": "Invalid bearer token"})

        api.settings = self.settings.model_copy(
            update={"runtime_auth_required": False, "runtime_auth_token": ""}
        )
        disabled = self.client.post(
            "/review/internal/enqueue",
            json=payload,
            headers=self._runtime_header(),
        )
        self.assertEqual(disabled.status_code, 503, disabled.text)
        self.assertEqual(
            disabled.json(),
            {
                "detail": (
                    "Runtime bearer auth must be configured for this internal endpoint"
                )
            },
        )
        api.settings = self.settings

    def test_internal_enqueue_is_anchored_hash_only_and_idempotent(self):
        payload = self._new_handoff_payload()
        first = self.client.post(
            "/review/internal/enqueue",
            json=payload,
            headers=self._runtime_header(),
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.headers.get("cache-control"), "no-store, max-age=0")
        body = first.json()
        self.assertEqual(body["surface"], "human_review_queue_ingress")
        self.assertEqual(body["created_count"], 1)
        self.assertEqual(body["idempotent_count"], 0)
        self.assertFalse(body["raw_ticket_egress"])
        self.assertFalse(body["raw_corpus_egress"])
        self.assertFalse(body["raw_submitter_egress"])
        new_ticket = next(
            ticket
            for ticket in body["queue"]["tickets"]
            if ticket["ticket_ref_hash"] == review_ticket_ref_hash("ticket-new")
        )
        self.assertEqual(new_ticket["routed_role"], "biosecurity-review")
        self.assertEqual(new_ticket["required_approvals"], 2)
        self.assertEqual(new_ticket["approvals_count"], 0)

        retry = self.client.post(
            "/review/internal/enqueue",
            json=payload,
            headers=self._runtime_header(),
        )
        self.assertEqual(retry.status_code, 200, retry.text)
        self.assertEqual(retry.json()["created_count"], 0)
        self.assertEqual(retry.json()["idempotent_count"], 1)

        persisted = Path(self.queue_path).read_text(encoding="utf-8")
        for raw in (
            "ticket-new",
            "turn-new",
            "bio://held-result",
            "agent-new",
            "operator-secret",
        ):
            self.assertNotIn(raw, persisted)

        reloaded = load_review_queue(
            self.queue_path,
            integrity_key=self.integrity_key,
            expected_authority_context_hash=self.authority_context_hash,
        )
        persisted_ticket = next(
            ticket
            for ticket in reloaded.tickets.values()
            if ticket.ticket_ref_digest == review_ticket_ref_hash("ticket-new")
        )
        self.assertEqual(persisted_ticket.required_approvals, 2)

    def test_internal_enqueue_rejects_ticket_identity_drift(self):
        first = self.client.post(
            "/review/internal/enqueue",
            json=self._new_handoff_payload(),
            headers=self._runtime_header(),
        )
        self.assertEqual(first.status_code, 200, first.text)

        drift = self.client.post(
            "/review/internal/enqueue",
            json=self._new_handoff_payload(reason_hash="8" * 64),
            headers=self._runtime_header(),
        )
        self.assertEqual(drift.status_code, 409, drift.text)
        self.assertEqual(
            drift.json(),
            {"detail": "Review handoff could not be committed safely"},
        )

    def test_public_queue_needs_no_bearer_and_exposes_hashes_only(self):
        response = self.client.get("/review/queue")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers.get("cache-control"), "no-store, max-age=0")
        body = response.json()
        self.assertEqual(body["pending_count"], 1)
        self.assertEqual(body["page"]["returned_count"], 1)
        ticket = body["tickets"][0]
        self.assertEqual(ticket["ticket_ref_hash"], self.ticket_ref_hash)
        self.assertNotIn("ticket_id", ticket)
        self.assertNotIn("turn_id", ticket)
        self.assertNotIn("corpus_ref", ticket)
        self.assertEqual(
            body["authority"]["release_context"],
            {
                "schema": "dnai.review-release-context.v1",
                "chain_id": 84532,
                "wallet_domain": "www.wikigen.me",
                "wallet_uri": "https://www.wikigen.me",
                "main_runtime_cvm_id": "cvm-main-runtime-0001",
                "deployment_intent_sha256": "sha256:" + "41" * 32,
                "release_authority_sha256": "sha256:" + "42" * 32,
                "ceremony_nonce": "0x" + "43" * 32,
            },
        )
        self.assertEqual(
            body["authority"]["release_provenance"],
            {
                "reviewer_authority_genesis_acceptance_sha256": (
                    "sha256:" + "44" * 32
                ),
                "reviewer_authority_current_status_epoch": 7,
                "reviewer_authority_current_status_sha256": (
                    "sha256:" + "45" * 32
                ),
                "reviewer_authority_active_reviewers_sha256": (
                    self.settings.release_reviewer_authority_active_reviewers_sha256
                ),
            },
        )
        self.assertEqual(
            body["authority"]["active_reviewers"],
            {
                "active_reviewer_count": 3,
                "active_reviewers_sha256": (
                    self.settings.release_reviewer_authority_active_reviewers_sha256
                ),
                "raw_reviewer_identity_egress": False,
            },
        )
        self.assertEqual(
            {role["role"] for role in body["authority"]["roles"]},
            REVIEW_AUTHORITY_ROLES,
        )
        rendered = json.dumps(body, sort_keys=True)
        for secret in (
            "dual-use review",
            "corpus://atlas",
            "cro-agent",
            "officer-a",
            "officer-b",
            "operator-secret",
            self.reviewer_a.address.lower(),
            self.reviewer_b.address.lower(),
            json.dumps(self.policy_document, sort_keys=True),
        ):
            self.assertNotIn(secret, rendered)

    def test_release_requires_two_distinct_signed_current_head_approvals(self):
        first, first_signature = self._challenge(self.reviewer_a)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertNotIn(self.reviewer_a.address.lower(), first.text.lower())
        first_decision = self._decide(first, first_signature)
        self.assertEqual(first_decision.status_code, 200, first_decision.text)
        self.assertEqual(first_decision.json()["status_counts"]["pending"], 1)
        self.assertEqual(first_decision.headers.get("cache-control"), "no-store, max-age=0")

        replay = self._decide(first, first_signature)
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(
            replay.json(), {"detail": "Review authorization is invalid or stale"}
        )

        second, second_signature = self._challenge(self.reviewer_b)
        self.assertEqual(second.status_code, 200, second.text)
        second_decision = self._decide(second, second_signature)
        self.assertEqual(second_decision.status_code, 200, second_decision.text)
        self.assertEqual(second_decision.json()["status_counts"]["released"], 1)

        persisted = Path(self.queue_path).read_text(encoding="utf-8")
        for raw in (
            first_signature,
            second_signature,
            self.ticket_id,
            "turn-1",
            "corpus://atlas",
            "cro-agent",
            self.reviewer_a.address,
            self.reviewer_a.address.lower(),
            self.reviewer_b.address,
            self.reviewer_b.address.lower(),
            "officer-a",
            "officer-b",
            "operator-secret",
            json.dumps(self.policy_document, sort_keys=True),
        ):
            self.assertNotIn(raw, persisted)

    def test_concurrent_challenges_bind_prior_head_and_one_goes_stale(self):
        first, first_signature = self._challenge(self.reviewer_a)
        concurrent, concurrent_signature = self._challenge(self.reviewer_b)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(concurrent.status_code, 200)
        self.assertEqual(self._decide(first, first_signature).status_code, 200)
        stale = self._decide(concurrent, concurrent_signature)
        self.assertEqual(stale.status_code, 401)

        refreshed, refreshed_signature = self._challenge(self.reviewer_b)
        self.assertEqual(refreshed.status_code, 200)
        released = self._decide(refreshed, refreshed_signature)
        self.assertEqual(released.status_code, 200)
        self.assertEqual(released.json()["status_counts"]["released"], 1)

    def test_one_authenticated_deny_remains_immediately_fail_closed(self):
        approval, approval_signature = self._challenge(self.reviewer_a)
        self.assertEqual(self._decide(approval, approval_signature).status_code, 200)
        denial, denial_signature = self._challenge(
            self.reviewer_b, decision="deny"
        )
        denied = self._decide(denial, denial_signature)
        self.assertEqual(denied.status_code, 200, denied.text)
        self.assertEqual(denied.json()["status_counts"]["denied"], 1)

    def test_unknown_outsider_and_submitter_are_same_bounded_rejection(self):
        responses = [
            self._challenge(self.outsider)[0],
            self._challenge(self.reviewer_a, ticket_ref_hash="55" * 32)[0],
            self._challenge(self.submitter)[0],
        ]
        for response in responses:
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.json(), {"detail": "Review authorization denied"})

    def test_signature_identity_substitution_fails_without_consuming_unbounded_work(self):
        challenge, _ = self._challenge(self.reviewer_a)
        wrong_signature = Account.sign_message(
            encode_defunct(text=challenge.json()["message"]), self.reviewer_b.key
        ).signature.hex()
        response = self._decide(challenge, wrong_signature)
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(wrong_signature, response.text)

    def test_review_service_uses_shared_eip1271_verifier_contract(self):
        challenge, _ = self._challenge(self.reviewer_a)

        class ContractWalletVerifier:
            def verify(inner_self, *, address, message, signature):
                self.assertEqual(address, self.reviewer_a.address.lower())
                self.assertEqual(message, challenge.json()["message"])
                self.assertEqual(signature, "0x" + "ab" * 80)
                return "eip1271"

        with patch(
            "tinker_delegate.review_authority.wallet_signature_verifier_from_settings",
            return_value=ContractWalletVerifier(),
        ):
            response = self._decide(challenge, "0x" + "ab" * 80)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["tickets"][0]["approvals_count"], 1)

    def test_missing_policy_context_store_or_integrity_key_is_503(self):
        cases = (
            self.settings.model_copy(update={"review_authority_policy_json": ""}),
            self.settings.model_copy(update={"release_authority_sha256": ""}),
            self.settings.model_copy(
                update={"release_authority_sha256": "sha256:" + "99" * 32}
            ),
            self.settings.model_copy(update={"review_queue_path": str(Path(self._tmp.name) / "missing.json")}),
            self.settings.model_copy(update={"review_queue_store_integrity_key": ""}),
            self.settings.model_copy(
                update={
                    "release_reviewer_authority_genesis_acceptance_sha256": ""
                }
            ),
            self.settings.model_copy(
                update={"release_reviewer_authority_current_status_epoch": 0}
            ),
            self.settings.model_copy(
                update={"release_reviewer_authority_current_status_sha256": ""}
            ),
            self.settings.model_copy(
                update={"release_reviewer_authority_active_reviewers_json": ""}
            ),
            self.settings.model_copy(
                update={"release_reviewer_authority_active_reviewers_sha256": ""}
            ),
        )
        for broken in cases:
            api.settings = broken
            api._review_challenges = ReviewChallengeStore(max_pending=1024)
            response = self.client.post(
                "/auth/review/challenge",
                json={
                    "address": self.reviewer_a.address,
                    "ticket_ref_hash": self.ticket_ref_hash,
                    "decision": "release",
                },
            )
            self.assertEqual(response.status_code, 503, response.text)
            self.assertEqual(response.json(), {"detail": "Review authority is unavailable"})
            decision = self.client.post(
                "/review/decide",
                json={"nonce": "11" * 16, "signature": "0x" + "ab" * 65},
            )
            self.assertEqual(decision.status_code, 503, decision.text)
            self.assertEqual(
                decision.json(), {"detail": "Review authority is unavailable"}
            )
        api.settings = self.settings

    def test_every_descriptor_bound_authority_field_drift_fails_closed(self):
        drifts = (
            {"review_authority_policy_sha256": "sha256:" + "91" * 32},
            {
                "release_reviewer_authority_genesis_acceptance_sha256": (
                    "sha256:" + "92" * 32
                )
            },
            {"release_reviewer_authority_current_status_epoch": 8},
            {
                "release_reviewer_authority_current_status_sha256": (
                    "sha256:" + "93" * 32
                )
            },
            {
                "release_reviewer_authority_active_reviewers_sha256": (
                    "sha256:" + "95" * 32
                )
            },
            {"release_authority_sha256": "sha256:" + "94" * 32},
        )
        for drift in drifts:
            api.settings = self.settings.model_copy(update=drift)
            response = self.client.post(
                "/auth/review/challenge",
                json={
                    "address": self.reviewer_a.address,
                    "ticket_ref_hash": self.ticket_ref_hash,
                    "decision": "release",
                },
            )
            self.assertEqual(response.status_code, 503, response.text)
            self.assertEqual(
                response.json(), {"detail": "Review authority is unavailable"}
            )
        api.settings = self.settings

    def test_queue_with_unknown_product_role_is_unavailable(self):
        state = load_review_queue(
            self.queue_path,
            integrity_key=self.integrity_key,
            expected_authority_context_hash=self.authority_context_hash,
        )
        state_key, ticket = next(iter(state.tickets.items()))
        malformed = ReviewQueueState(
            tickets={state_key: replace(ticket, routed_role="unbound-review-role")},
            audit=state.audit,
        )
        save_review_queue(
            self.queue_path,
            malformed,
            integrity_key=self.integrity_key,
            authority_context_hash=self.authority_context_hash,
        )
        response = self.client.get("/review/queue")
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(
            response.json(), {"detail": "Review authority is unavailable"}
        )

    def test_production_missing_dual_rpc_is_503_before_wallet_prompt(self):
        with (
            patch(
                "tinker_delegate.review_authority.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.review_authority.dstack_utils.derive_storage_key",
                return_value=b"d" * 32,
            ),
        ):
            response = self.client.post(
                "/auth/review/challenge",
                json={
                    "address": self.reviewer_a.address,
                    "ticket_ref_hash": self.ticket_ref_hash,
                    "decision": "release",
                },
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"detail": "Review authority is unavailable"})

    def test_integrity_tamper_fails_closed(self):
        payload = json.loads(Path(self.queue_path).read_text(encoding="utf-8"))
        payload["tickets"][0]["required_approvals"] = 1
        Path(self.queue_path).write_text(json.dumps(payload), encoding="utf-8")
        response = self.client.get("/review/queue")
        self.assertEqual(response.status_code, 503)

    def test_expiry_is_separate_operator_only_conservative_path(self):
        stale = enqueue_handoff_tickets(
            ReviewQueueState.empty(),
            _held_tickets(),
            opened_at=int(time.time()) - 10_000,
            ttl_seconds=1,
            required_approvals_by_role=self.policy.required_approvals_by_role(),
        )
        save_review_queue(
            self.queue_path,
            stale,
            integrity_key=self.integrity_key,
            authority_context_hash=self.authority_context_hash,
        )
        self.assertEqual(self.client.post("/review/expire").status_code, 401)
        response = self.client.post(
            "/review/expire", headers=self._runtime_header()
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers.get("cache-control"), "no-store, max-age=0")
        self.assertEqual(response.json()["status_counts"]["expired"], 1)
        denied, _ = self._challenge(self.reviewer_a)
        self.assertEqual(denied.status_code, 403)

    def test_public_queue_is_paginated_and_peer_rate_limited(self):
        page = self.client.get("/review/queue", params={"limit": 1})
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.json()["page"]["limit"], 1)
        self.assertEqual(
            self.client.get("/review/queue", params={"limit": 101}).status_code,
            422,
        )

        api._review_queue_read_limiter = ReviewQueueReadLimiter(
            window_seconds=60, peer_capacity=1, max_peers=8
        )
        self.assertEqual(self.client.get("/review/queue").status_code, 200)
        limited = self.client.get("/review/queue")
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.headers.get("retry-after"), "60")

    def test_review_routes_have_prebuffer_body_caps(self):
        response = self.client.post(
            "/auth/review/challenge",
            content=b"{" + b"x" * 2048 + b"}",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.json(), {"detail": "request body exceeds route limit"}
        )

        enqueue = self.client.post(
            "/review/internal/enqueue",
            content=b"{" + b"x" * 65_536 + b"}",
            headers={
                "Content-Type": "application/json",
                **self._runtime_header(),
            },
        )
        self.assertEqual(enqueue.status_code, 413)
        self.assertEqual(
            enqueue.json(), {"detail": "request body exceeds route limit"}
        )


if __name__ == "__main__":
    unittest.main()
