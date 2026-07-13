import tempfile
import unittest
from pathlib import Path

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
from tinker_delegate.review_queue import (
    ReviewQueueState,
    enqueue_handoff_tickets,
    save_review_queue,
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
        consent_grants=(ConsentGrant("corpus://atlas", "owner-atlas", "sponsor", "rank", "sft"),),
        delegation_grants=(
            DelegationGrant("cro-agent", "sponsor", ("corpus://atlas",), ("rank",), ("sft",)),
        ),
    )
    turn = Turn(
        turn_id="turn-1", by="cro-agent", requester_ref="sponsor", purpose="rank",
        pipeline="sft", corpora=("corpus://atlas",), requests={"corpus://atlas": {"purpose": "rank"}},
    )
    state = coordinate(CoordinationState(session), SubmitTurn(turn))
    state = coordinate(
        state,
        GateResults("turn-1", (GatedQuery(
            "corpus://atlas", GateDecision.HOLD, stage=2, reason="dual-use review",
            routed_role="access-review-officer"),)),
    )
    return state.turns["turn-1"].tickets


class ReviewQueueApiTest(unittest.TestCase):
    def setUp(self):
        import time

        self.original_settings = api.settings
        self._tmp = tempfile.TemporaryDirectory()
        self.queue_path = str(Path(self._tmp.name) / "review-queue.json")
        # Open near wall-clock now with a long TTL: the API decides/filters at
        # real time.time(), so an old opened_at would read as expired.
        queue = enqueue_handoff_tickets(
            ReviewQueueState.empty(), _held_tickets(), opened_at=int(time.time()), ttl_seconds=100000
        )
        save_review_queue(self.queue_path, queue)
        self.ticket_id = next(iter(queue.tickets))
        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
            review_queue_path=self.queue_path,
        )
        self.client = TestClient(api.app)

    def tearDown(self):
        api.settings = self.original_settings
        self._tmp.cleanup()

    def _hdr(self):
        return {"Authorization": "Bearer operator-secret"}

    def test_queue_requires_auth(self):
        self.assertEqual(self.client.get("/review/queue").status_code, 401)
        self.assertEqual(
            self.client.post("/review/decide", json={
                "ticket_id": "x", "decision": "release", "reviewer_ref": "r"}).status_code,
            401,
        )

    def test_get_queue_is_bounded(self):
        resp = self.client.get("/review/queue", headers=self._hdr())
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["pending_count"], 1)
        self.assertFalse(body["raw_secret_egress"])
        import json
        self.assertNotIn("dual-use review", json.dumps(body))
        self.assertNotIn("cro-agent", json.dumps(body))

    def test_get_queue_filtered_by_role(self):
        resp = self.client.get(
            "/review/queue", params={"routed_role": "access-review-officer"}, headers=self._hdr()
        )
        self.assertEqual(resp.json()["pending_count"], 1)
        resp2 = self.client.get(
            "/review/queue", params={"routed_role": "nobody"}, headers=self._hdr()
        )
        self.assertEqual(resp2.json()["pending_count"], 0)

    def test_decide_release_persists(self):
        resp = self.client.post("/review/decide", headers=self._hdr(), json={
            "ticket_id": self.ticket_id, "decision": "release", "reviewer_ref": "access-officer"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status_counts"]["released"], 1)
        # Persisted: a fresh GET reflects the release.
        after = self.client.get("/review/queue", headers=self._hdr()).json()
        self.assertEqual(after["pending_count"], 0)

    def test_submitter_self_approval_is_rejected(self):
        resp = self.client.post("/review/decide", headers=self._hdr(), json={
            "ticket_id": self.ticket_id, "decision": "release", "reviewer_ref": "cro-agent"})
        self.assertEqual(resp.status_code, 409)

    def test_unconfigured_queue_decide_is_503(self):
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        client = TestClient(api.app)
        resp = client.post("/review/decide", headers=self._hdr(), json={
            "ticket_id": self.ticket_id, "decision": "release", "reviewer_ref": "access-officer"})
        self.assertEqual(resp.status_code, 503)

    def test_expire_transitions_stale_tickets(self):
        import time

        # Seed a queue whose only ticket is already past its TTL.
        stale = enqueue_handoff_tickets(
            ReviewQueueState.empty(), _held_tickets(),
            opened_at=int(time.time()) - 10_000, ttl_seconds=1,
        )
        save_review_queue(self.queue_path, stale)
        resp = self.client.post("/review/expire", headers=self._hdr())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status_counts"].get("expired"), 1)
        # Persisted: the expired ticket can no longer be released.
        after = self.client.post("/review/decide", headers=self._hdr(), json={
            "ticket_id": next(iter(stale.tickets)),
            "decision": "release", "reviewer_ref": "access-officer"})
        self.assertEqual(after.status_code, 409)

    def test_expire_requires_auth_and_config(self):
        self.assertEqual(self.client.post("/review/expire").status_code, 401)
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        client = TestClient(api.app)
        self.assertEqual(client.post("/review/expire", headers=self._hdr()).status_code, 503)


if __name__ == "__main__":
    unittest.main()
