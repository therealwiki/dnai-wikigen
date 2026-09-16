import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from tinker_delegate.collaboration_store import (
    CHALLENGE_RETENTION_SECONDS,
    IDEMPOTENCY_RETENTION_SECONDS,
    ROOM_ARCHIVE_RETENTION_SECONDS,
    RUN_RETENTION_SECONDS,
    CollaborationAuthorizationError,
    CollaborationCapacityError,
    CollaborationConflictError,
    CollaborationNotFoundError,
    CollaborationStore,
    CollaborationStoreCorruptError,
    collaboration_allocation_commitment,
)


CREATOR = "0x" + "11" * 20
OWNER_A = "0x" + "22" * 20
OWNER_B = "0x" + "33" * 20
OUTSIDER = "0x" + "44" * 20
ROOM_A = "room_" + "a" * 32
KEY = b"collaboration-store-schema-v2-test-key"


def _commitment(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _room_id(index: int) -> str:
    return "room_" + f"{index:032x}"


def _room_request(
    *,
    room_id: str = ROOM_A,
    idempotency_key: str = "create-room-0001",
    creator: str = CREATOR,
    owners: tuple[str, ...] = (OWNER_A, OWNER_B),
    created_at: int = 100,
):
    allocations = (
        {owners[0]: 10_000}
        if len(owners) == 1
        else {owners[0]: 6_000, owners[1]: 4_000}
    )
    return {
        "room_id": room_id,
        "idempotency_key": idempotency_key,
        "creator_address": creator,
        "member_addresses": list(owners),
        "purpose_commitment": _commitment(f"purpose-{room_id}"),
        "pipeline_commitment": _commitment(f"pipeline-{room_id}"),
        "corpus_policy_commitments": {
            owner: _commitment(f"policy-{room_id}-{owner}")
            for owner in owners
        },
        "owner_allocations_bps": allocations,
        "created_at": created_at,
    }


class CollaborationStoreV2Test(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "collaboration.json"
        self.store = CollaborationStore(self.path, integrity_key=KEY)

    def create_room(self, **overrides):
        request = _room_request()
        request.update(overrides)
        return self.store.create_room(**request)

    def accept(self, owner: str, *, key: str, at: int):
        return self.store.respond_to_invitation(
            room_id=ROOM_A,
            participant_address=owner,
            decision="accept",
            idempotency_key=key,
            decided_at=at,
        )

    def role(
        self,
        owner: str,
        *,
        index: int,
        issued_at: int,
        decision: str = "activate",
        authorization: str | None = None,
    ):
        challenge = self.store.issue_consent_challenge(
            room_id=ROOM_A,
            owner_address=owner,
            decision=decision,
            issued_at=issued_at,
            expires_at=issued_at + 120,
            challenge_id="consent_" + f"{index:032x}",
        )
        digest = authorization or _commitment(f"role-{index}")
        room = self.store.consume_verified_consent(
            challenge_id=challenge["challenge_id"],
            owner_address=owner,
            decision=decision,
            authorization_hash=digest,
            verifier_confirmed=True,
            consumed_at=issued_at + 1,
        )
        return challenge, room, digest

    def activate_roles(self):
        self.accept(OWNER_A, key="accept-owner-a", at=101)
        self.accept(OWNER_B, key="accept-owner-b", at=102)
        self.role(OWNER_A, index=1, issued_at=110)
        self.role(OWNER_B, index=2, issued_at=120)

    def propose(self, query_ref: str, *, at: int, key: str):
        return self.store.propose_query(
            room_id=ROOM_A,
            query_ref=query_ref,
            proposer_address=CREATOR,
            idempotency_key=key,
            proposed_at=at,
        )

    def query_grant(
        self,
        owner: str,
        *,
        index: int,
        issued_at: int,
        decision: str = "approve",
        authorization: str | None = None,
    ):
        challenge = self.store.issue_query_grant_challenge(
            room_id=ROOM_A,
            owner_address=owner,
            decision=decision,
            issued_at=issued_at,
            expires_at=issued_at + 120,
            challenge_id="qgrant_" + f"{index:032x}",
        )
        digest = authorization or _commitment(f"query-grant-{index}")
        query = self.store.consume_verified_query_grant(
            challenge_id=challenge["challenge_id"],
            owner_address=owner,
            decision=decision,
            authorization_hash=digest,
            verifier_confirmed=True,
            consumed_at=issued_at + 1,
        )
        return challenge, query, digest

    def approve_query(self, query_ref: str = _commitment("query-a")):
        self.propose(query_ref, at=130, key="propose-query-a")
        self.query_grant(OWNER_A, index=1, issued_at=140)
        self.query_grant(OWNER_B, index=2, issued_at=150)
        return query_ref

    def test_declarations_are_pending_and_do_not_grant_authority(self):
        room = self.create_room()
        self.assertEqual(room["schema_version"], 2)
        self.assertEqual(room["requester_membership_status"], "accepted")
        self.assertEqual(
            room["accepted_member_addresses"],
            [CREATOR],
        )
        self.assertEqual(
            room["pending_invitation_addresses"],
            sorted([OWNER_A, OWNER_B]),
        )
        self.assertFalse(room["all_required_memberships_accepted"])
        self.assertFalse(room["all_required_roles_active"])
        self.assertFalse(room["all_required_query_grants_current"])
        invited = self.store.room_projection(ROOM_A, OWNER_A)
        self.assertEqual(invited["requester_membership_status"], "invited")
        with self.assertRaises(CollaborationAuthorizationError):
            self.store.issue_consent_challenge(
                room_id=ROOM_A,
                owner_address=OWNER_A,
                decision="activate",
                issued_at=110,
                expires_at=200,
            )
        with self.assertRaises(CollaborationAuthorizationError):
            self.store.authorize_joint_run(
                room_id=ROOM_A,
                query_ref=_commitment("query"),
                requester_address=OWNER_A,
                idempotency_key="run-before-accept",
                authorized_at=110,
            )

    def test_accept_and_decline_are_exact_idempotent_and_restart_safe(self):
        self.create_room()
        accepted = self.accept(OWNER_A, key="accept-owner-a", at=101)
        replay = self.accept(OWNER_A, key="accept-owner-a", at=999)
        self.assertEqual(accepted, replay)
        self.assertTrue(accepted["ordinary_participant_authority"])
        with self.assertRaises(CollaborationConflictError):
            self.store.respond_to_invitation(
                room_id=ROOM_A,
                participant_address=OWNER_A,
                decision="decline",
                idempotency_key="accept-owner-a",
                decided_at=102,
            )

        declined = self.store.respond_to_invitation(
            room_id=ROOM_A,
            participant_address=OWNER_B,
            decision="decline",
            idempotency_key="decline-owner-b",
            decided_at=102,
        )
        self.assertFalse(declined["visible_after_response"])
        restarted = CollaborationStore(self.path, integrity_key=KEY)
        self.assertEqual(
            restarted.respond_to_invitation(
                room_id=ROOM_A,
                participant_address=OWNER_B,
                decision="decline",
                idempotency_key="decline-owner-b",
                decided_at=9_999,
            ),
            declined,
        )
        self.assertEqual(restarted.list_room_projections(OWNER_B)["rooms"], [])
        with self.assertRaises(CollaborationAuthorizationError):
            restarted.room_projection(ROOM_A, OWNER_B)

    def test_pending_invites_do_not_consume_accepted_quota(self):
        with patch(
            "tinker_delegate.collaboration_store."
            "MAX_ACCEPTED_ROOMS_PER_PARTICIPANT",
            1,
        ):
            self.create_room()
            self.accept(OWNER_A, key="accept-owner-a", at=101)
            self.store.create_room(
                **_room_request(
                    room_id=_room_id(2),
                    idempotency_key="create-room-0002",
                    creator=OUTSIDER,
                    owners=(OWNER_A,),
                    created_at=102,
                )
            )
            with self.assertRaises(CollaborationCapacityError):
                self.store.respond_to_invitation(
                    room_id=_room_id(2),
                    participant_address=OWNER_A,
                    decision="accept",
                    idempotency_key="accept-owner-a-room-2",
                    decided_at=103,
                )

    def test_pending_invitation_spam_is_bounded_per_target_and_inviter(self):
        with patch(
            "tinker_delegate.collaboration_store."
            "MAX_PENDING_INVITATIONS_PER_TARGET",
            1,
        ):
            self.create_room()
            with self.assertRaisesRegex(
                CollaborationCapacityError,
                "invitee",
            ):
                self.store.create_room(
                    **_room_request(
                        room_id=_room_id(2),
                        idempotency_key="create-room-0002",
                        owners=(OWNER_A,),
                        created_at=101,
                    )
                )
        self.path.unlink()
        self.store = CollaborationStore(self.path, integrity_key=KEY)
        with patch(
            "tinker_delegate.collaboration_store."
            "MAX_PENDING_INVITATIONS_PER_INVITER",
            1,
        ):
            self.store.create_room(
                **_room_request(owners=(OWNER_A,))
            )
            with self.assertRaisesRegex(
                CollaborationCapacityError,
                "inviter",
            ):
                self.store.create_room(
                    **_room_request(
                        room_id=_room_id(2),
                        idempotency_key="create-room-0002",
                        owners=(OWNER_B,),
                        created_at=101,
                    )
                )

    def test_creator_can_cancel_pending_invitation_before_archive(self):
        self.create_room()
        cancelled = self.store.cancel_invitation(
            room_id=ROOM_A,
            creator_address=CREATOR,
            invitee_address=OWNER_A,
            idempotency_key="cancel-owner-a",
            cancelled_at=101,
        )
        self.assertEqual(cancelled["membership_status"], "cancelled")
        with self.assertRaises(CollaborationAuthorizationError):
            self.store.room_projection(ROOM_A, OWNER_A)
        with self.assertRaises(CollaborationAuthorizationError):
            self.store.cancel_invitation(
                room_id=ROOM_A,
                creator_address=OUTSIDER,
                invitee_address=OWNER_B,
                idempotency_key="cancel-owner-b",
                cancelled_at=102,
            )

    def test_role_and_query_signatures_are_distinct_exact_authority(self):
        self.create_room()
        self.activate_roles()
        room = self.store.room_projection(ROOM_A, CREATOR)
        self.assertTrue(room["all_required_roles_active"])
        self.assertIsNone(room["current_query"])
        query_ref = self.approve_query()
        room = self.store.room_projection(ROOM_A, CREATOR)
        self.assertTrue(room["all_required_query_grants_current"])
        self.assertIn(
            f"urn:dnai:collaboration:query:{query_ref}",
            self.store.issue_query_grant_challenge(
                room_id=ROOM_A,
                owner_address=OWNER_A,
                decision="approve",
                issued_at=160,
                expires_at=260,
                challenge_id="qgrant_" + f"{3:032x}",
            )["message"],
        )
        run = self.store.authorize_joint_run(
            room_id=ROOM_A,
            query_ref=query_ref,
            requester_address=CREATOR,
            idempotency_key="joint-snapshot-0001",
            authorized_at=170,
        )
        self.assertEqual(
            run["execution_status"],
            "joint_consent_snapshot_not_dispatched",
        )
        self.assertTrue(run["consent_snapshot_current"])
        self.assertFalse(run["execution_authority"])
        self.assertEqual(
            run["allocation_commitment"],
            collaboration_allocation_commitment(
                room_id=ROOM_A,
                query_ref=query_ref,
                room_commitment=room["room_commitment"],
                owner_allocations_bps={
                    OWNER_A: 6_000,
                    OWNER_B: 4_000,
                },
            ),
        )

    def test_arbitrary_query_cannot_inherit_prior_query_grants(self):
        self.create_room()
        self.activate_roles()
        query_a = self.approve_query()
        query_b = _commitment("query-b")
        with self.assertRaisesRegex(
            CollaborationConflictError,
            "Exact current query",
        ):
            self.store.authorize_joint_run(
                room_id=ROOM_A,
                query_ref=query_b,
                requester_address=CREATOR,
                idempotency_key="wrong-query-0001",
                authorized_at=160,
            )
        self.propose(query_b, at=160, key="propose-query-b")
        with self.assertRaisesRegex(
            CollaborationConflictError,
            "lacks every required",
        ):
            self.store.authorize_joint_run(
                room_id=ROOM_A,
                query_ref=query_b,
                requester_address=CREATOR,
                idempotency_key="new-query-no-grants",
                authorized_at=161,
            )
        room = self.store.room_projection(ROOM_A, CREATOR)
        self.assertEqual(room["current_query"]["query_ref"], query_b)
        self.assertFalse(room["all_required_query_grants_current"])
        self.assertNotEqual(query_a, query_b)

    def test_lost_response_role_and_query_consumption_retries_do_not_increment(self):
        self.create_room()
        self.accept(OWNER_A, key="accept-owner-a", at=101)
        challenge, first, authorization = self.role(
            OWNER_A,
            index=1,
            issued_at=110,
        )
        generation = first["generation"]
        replay = self.store.consume_verified_consent(
            challenge_id=challenge["challenge_id"],
            owner_address=OWNER_A,
            decision="activate",
            authorization_hash=authorization,
            verifier_confirmed=True,
            consumed_at=999,
        )
        self.assertEqual(replay["generation"], generation)
        with self.assertRaisesRegex(
            CollaborationConflictError,
            "does not match",
        ):
            self.store.consume_verified_consent(
                challenge_id=challenge["challenge_id"],
                owner_address=OWNER_A,
                decision="activate",
                authorization_hash=_commitment("other-signature"),
                verifier_confirmed=True,
                consumed_at=999,
            )

        self.accept(OWNER_B, key="accept-owner-b", at=112)
        self.role(OWNER_B, index=2, issued_at=120)
        self.propose(_commitment("query"), at=130, key="propose-query")
        qchallenge, first_query, qauthorization = self.query_grant(
            OWNER_A,
            index=1,
            issued_at=140,
        )
        grant_generation = first_query["owner_query_grants"][0][
            "grant_generation"
        ]
        replay_query = self.store.consume_verified_query_grant(
            challenge_id=qchallenge["challenge_id"],
            owner_address=OWNER_A,
            decision="approve",
            authorization_hash=qauthorization,
            verifier_confirmed=True,
            consumed_at=999,
        )
        self.assertEqual(
            replay_query["owner_query_grants"][0]["grant_generation"],
            grant_generation,
        )

    def test_room_list_cursor_is_opaque_bound_and_snapshot_fail_closed(self):
        for index in range(1, 4):
            self.store.create_room(
                **_room_request(
                    room_id=_room_id(index),
                    idempotency_key=f"create-room-{index:04d}",
                    owners=(CREATOR,),
                    created_at=100 + index,
                )
            )
        first = self.store.list_room_projections(CREATOR, limit=1)
        self.assertTrue(first["has_more"])
        self.assertIsNotNone(first["next_cursor"])
        second = self.store.list_room_projections(
            CREATOR,
            limit=1,
            cursor=first["next_cursor"],
        )
        self.assertNotEqual(
            first["rooms"][0]["room_id"],
            second["rooms"][0]["room_id"],
        )
        with self.assertRaisesRegex(
            CollaborationConflictError,
            "restart",
        ):
            self.store.list_room_projections(
                OUTSIDER,
                limit=1,
                cursor=first["next_cursor"],
            )
        tampered = first["next_cursor"][:-1] + (
            "0" if first["next_cursor"][-1] != "0" else "1"
        )
        with self.assertRaisesRegex(CollaborationConflictError, "restart"):
            self.store.list_room_projections(
                CREATOR,
                limit=1,
                cursor=tampered,
            )
        self.store.issue_consent_challenge(
            room_id=_room_id(3),
            owner_address=CREATOR,
            decision="activate",
            issued_at=200,
            expires_at=300,
        )
        with self.assertRaisesRegex(CollaborationConflictError, "stale"):
            self.store.list_room_projections(
                CREATOR,
                limit=1,
                cursor=first["next_cursor"],
            )
        restarted = self.store.list_room_projections(CREATOR, limit=1)
        self.assertEqual(
            restarted["rooms"][0]["room_id"],
            first["rooms"][0]["room_id"],
        )

    def test_max_page_projection_stays_below_browser_response_cap(self):
        owners = (CREATOR,) + tuple(
            "0x" + f"{index:040x}" for index in range(2, 17)
        )
        allocations = {owner: 625 for owner in owners}
        created_at = 2_000_000_000
        self.store.create_room(
            room_id=ROOM_A,
            idempotency_key="create-max-room",
            creator_address=CREATOR,
            member_addresses=list(owners),
            purpose_commitment=_commitment("max-purpose"),
            pipeline_commitment=_commitment("max-pipeline"),
            corpus_policy_commitments={
                owner: _commitment(f"max-policy-{owner}")
                for owner in owners
            },
            owner_allocations_bps=allocations,
            created_at=created_at,
        )
        for index, owner in enumerate(owners[1:], start=1):
            self.store.respond_to_invitation(
                room_id=ROOM_A,
                participant_address=owner,
                decision="accept",
                idempotency_key=f"accept-max-{index:02d}",
                decided_at=created_at + index,
            )
        for index, owner in enumerate(owners, start=1):
            issued_at = created_at + 100 + index * 2
            challenge = self.store.issue_consent_challenge(
                room_id=ROOM_A,
                owner_address=owner,
                decision="activate",
                issued_at=issued_at,
                expires_at=issued_at + 120,
                challenge_id="consent_" + f"{index + 1000:032x}",
            )
            self.store.consume_verified_consent(
                challenge_id=challenge["challenge_id"],
                owner_address=owner,
                decision="activate",
                authorization_hash=_commitment(f"max-role-{index}"),
                verifier_confirmed=True,
                consumed_at=issued_at + 1,
            )
        self.store.propose_query(
            room_id=ROOM_A,
            query_ref=_commitment("max-query"),
            proposer_address=CREATOR,
            idempotency_key="propose-max-query",
            proposed_at=created_at + 200,
        )
        one_room_page = self.store.list_room_projections(
            CREATOR,
            limit=16,
        )
        maximum_page_shape = {
            **one_room_page,
            "rooms": one_room_page["rooms"] * 16,
            "room_count": 16,
        }
        encoded = json.dumps(
            maximum_page_shape,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertLess(len(encoded), 256 * 1024)

    def test_challenge_and_run_caps_recover_after_public_retention(self):
        self.create_room()
        self.activate_roles()
        query_ref = self.approve_query()
        with patch(
            "tinker_delegate.collaboration_store.MAX_RUNS_PER_WALLET",
            1,
        ):
            run = self.store.authorize_joint_run(
                room_id=ROOM_A,
                query_ref=query_ref,
                requester_address=CREATOR,
                idempotency_key="joint-snapshot-0001",
                authorized_at=160,
            )
            with self.assertRaises(CollaborationCapacityError):
                self.store.authorize_joint_run(
                    room_id=ROOM_A,
                    query_ref=query_ref,
                    requester_address=CREATOR,
                    idempotency_key="joint-snapshot-0002",
                    authorized_at=161,
                )
            reclaimed = self.store.reclaim(
                now=run["reclaimable_after"],
            )
            self.assertEqual(
                reclaimed["reclaimed"]["joint_consent_snapshots"],
                1,
            )
            with self.assertRaises(CollaborationNotFoundError):
                self.store.run_projection(run["run_id"], CREATOR)
            replacement = self.store.authorize_joint_run(
                room_id=ROOM_A,
                query_ref=query_ref,
                requester_address=CREATOR,
                idempotency_key="joint-snapshot-0003",
                authorized_at=run["reclaimable_after"] + 1,
            )
            self.assertNotEqual(replacement["run_id"], run["run_id"])

        challenge = self.store.issue_query_grant_challenge(
            room_id=ROOM_A,
            owner_address=OWNER_A,
            decision="approve",
            issued_at=1_000_000,
            expires_at=1_000_100,
            challenge_id="qgrant_" + f"{9:032x}",
        )
        before = self.store.reclaim(
            now=challenge["reclaimable_after"] - 1,
        )
        self.assertEqual(
            before["reclaimed"]["query_grant_challenges"],
            0,
        )
        after = self.store.reclaim(now=challenge["reclaimable_after"])
        self.assertGreaterEqual(
            after["reclaimed"]["query_grant_challenges"],
            1,
        )

    def test_archived_rooms_are_explicit_bounded_and_globally_reclaimable(self):
        with patch(
            "tinker_delegate.collaboration_store.MAX_ROOMS",
            1,
        ):
            room = self.store.create_room(
                **_room_request(owners=(CREATOR,))
            )
            archived = self.store.archive_room(
                room_id=ROOM_A,
                creator_address=CREATOR,
                idempotency_key="archive-room-0001",
                archived_at=200,
            )
            self.assertEqual(archived["lifecycle_status"], "archived")
            self.assertEqual(
                archived["reclaimable_after"],
                200 + ROOM_ARCHIVE_RETENTION_SECONDS,
            )
            with self.assertRaises(CollaborationCapacityError):
                self.store.create_room(
                    **_room_request(
                        room_id=_room_id(2),
                        idempotency_key="create-room-0002",
                        owners=(CREATOR,),
                        created_at=201,
                    )
                )
            replacement = self.store.create_room(
                **_room_request(
                    room_id=_room_id(2),
                    idempotency_key="create-room-0002",
                    owners=(CREATOR,),
                    created_at=archived["reclaimable_after"],
                )
            )
            self.assertEqual(replacement["room_id"], _room_id(2))
            with self.assertRaises(CollaborationNotFoundError):
                self.store.room_projection(room["room_id"], CREATOR)

    def test_archive_never_prunes_pending_or_active_authority(self):
        self.create_room()
        with self.assertRaisesRegex(CollaborationConflictError, "Pending"):
            self.store.archive_room(
                room_id=ROOM_A,
                creator_address=CREATOR,
                idempotency_key="archive-room-0001",
                archived_at=101,
            )
        self.store.cancel_invitation(
            room_id=ROOM_A,
            creator_address=CREATOR,
            invitee_address=OWNER_A,
            idempotency_key="cancel-owner-a",
            cancelled_at=102,
        )
        self.store.cancel_invitation(
            room_id=ROOM_A,
            creator_address=CREATOR,
            invitee_address=OWNER_B,
            idempotency_key="cancel-owner-b",
            cancelled_at=103,
        )
        archived = self.store.archive_room(
            room_id=ROOM_A,
            creator_address=CREATOR,
            idempotency_key="archive-room-0001",
            archived_at=104,
        )
        self.assertEqual(archived["room_retention_policy"], (
            "explicit_archive_then_bounded_reclamation"
        ))
        self.assertFalse(
            self.store.reclaim(now=105)[
                "pending_or_active_authority_pruned"
            ]
        )

    def test_restart_tamper_schema_v1_and_concurrency_fail_closed(self):
        self.create_room()
        restarted = CollaborationStore(self.path, integrity_key=KEY)
        self.assertEqual(
            restarted.room_projection(ROOM_A, CREATOR)["schema_version"],
            2,
        )
        document = json.loads(self.path.read_text("utf-8"))
        document["payload"]["rooms"][ROOM_A]["generation"] = 999
        self.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(CollaborationStoreCorruptError):
            CollaborationStore(self.path, integrity_key=KEY)

        self.path.unlink()
        self.store = CollaborationStore(self.path, integrity_key=KEY)

        def create(index: int):
            store = CollaborationStore(self.path, integrity_key=KEY)
            return store.create_room(
                **_room_request(
                    room_id=_room_id(index + 1),
                    idempotency_key=f"concurrent-room-{index:04d}",
                    owners=(CREATOR,),
                    created_at=100 + index,
                )
            )["room_id"]

        with ThreadPoolExecutor(max_workers=8) as pool:
            room_ids = list(pool.map(create, range(8)))
        self.assertEqual(len(set(room_ids)), 8)
        self.assertEqual(
            CollaborationStore(
                self.path,
                integrity_key=KEY,
            ).list_room_projections(CREATOR, limit=8)["room_count"],
            8,
        )

        document = json.loads(self.path.read_text("utf-8"))
        document["schema_version"] = 1
        payload = document["payload"]
        import hmac

        document["integrity"]["value"] = hmac.new(
            KEY,
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        self.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            CollaborationStoreCorruptError,
            "envelope",
        ):
            CollaborationStore(self.path, integrity_key=KEY)

    def test_retention_constants_are_bounded_and_ordered(self):
        self.assertEqual(CHALLENGE_RETENTION_SECONDS, 86_400)
        self.assertEqual(RUN_RETENTION_SECONDS, 7 * 86_400)
        self.assertEqual(
            IDEMPOTENCY_RETENTION_SECONDS,
            RUN_RETENTION_SECONDS,
        )
        self.assertEqual(
            ROOM_ARCHIVE_RETENTION_SECONDS,
            RUN_RETENTION_SECONDS,
        )


if __name__ == "__main__":
    unittest.main()
