import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tinker_delegate import api
from tinker_delegate.config import Settings
from tinker_delegate.collaboration_royalty_settlement import (
    CollaborationRoyaltySettlementStore,
)


AUTH_KEY = "collaboration-api-wallet-key-" + "a" * 48
STORE_KEY = "collaboration-api-store-key-" + "s" * 48
ROOM_ID = "room_" + "a" * 32


def _commitment(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


class CollaborationApiV2Test(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {
                "DSTACK_ENABLED": "false",
                "TINKER_DSTACK_ENABLED": "false",
            },
        )
        self.env.start()
        self.original_settings = api.settings
        self.original_store = api._collaboration_store_instance
        self.original_identity = api._collaboration_store_instance_identity
        self.store_path = Path(self.temporary.name) / "collaboration.json"
        api.settings = Settings(
            collaboration_enabled=True,
            collaboration_wallet_auth_signing_key=AUTH_KEY,
            collaboration_store_integrity_key=STORE_KEY,
            collaboration_store_path=str(self.store_path),
            collaboration_consent_challenge_ttl_seconds=300,
        )
        api._collaboration_wallet_challenges.clear()
        api._collaboration_store_instance = None
        api._collaboration_store_instance_identity = None
        self.client = TestClient(api.app)
        self.creator = Account.from_key("0x" + "11" * 32)
        self.owner_a = Account.from_key("0x" + "22" * 32)
        self.owner_b = Account.from_key("0x" + "33" * 32)
        self.outsider = Account.from_key("0x" + "44" * 32)

    def tearDown(self):
        api._collaboration_wallet_challenges.clear()
        api._collaboration_store_instance = self.original_store
        api._collaboration_store_instance_identity = self.original_identity
        api.settings = self.original_settings
        self.env.stop()
        self.temporary.cleanup()

    def headers(self, account):
        challenge = self.client.post(
            "/auth/collaboration/challenge",
            json={"address": account.address},
        )
        self.assertEqual(challenge.status_code, 200, challenge.text)
        body = challenge.json()
        signature = account.sign_message(
            encode_defunct(text=body["message"])
        ).signature.hex()
        token = self.client.post(
            "/auth/collaboration/token",
            json={"nonce": body["nonce"], "signature": signature},
        )
        self.assertEqual(token.status_code, 200, token.text)
        return {
            "Authorization": f"Bearer {token.json()['access_token']}",
        }

    def room_payload(self, *, room_id: str = ROOM_ID, index: int = 1):
        return {
            "room_id": room_id,
            "idempotency_key": f"create-room-{index:04d}",
            "member_addresses": [
                self.owner_a.address,
                self.owner_b.address,
            ],
            "purpose_commitment": _commitment(f"purpose-{index}"),
            "pipeline_commitment": _commitment(f"pipeline-{index}"),
            "corpus_policy_commitments": {
                self.owner_a.address: _commitment(f"owner-a-policy-{index}"),
                self.owner_b.address: _commitment(f"owner-b-policy-{index}"),
            },
            "owner_allocations_bps": {
                self.owner_a.address: 6_000,
                self.owner_b.address: 4_000,
            },
        }

    def create_room(self, *, room_id: str = ROOM_ID, index: int = 1):
        response = self.client.post(
            "/collaboration/rooms",
            headers=self.headers(self.creator),
            json=self.room_payload(room_id=room_id, index=index),
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["room"]

    def invitation(self, account, action: str, *, key: str):
        response = self.client.post(
            f"/collaboration/rooms/{ROOM_ID}/invitations/{action}",
            headers=self.headers(account),
            json={"idempotency_key": key},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def role_consent(
        self,
        account,
        decision="activate",
        *,
        verifier=None,
        signature="",
    ):
        headers = self.headers(account)
        issued = self.client.post(
            f"/collaboration/rooms/{ROOM_ID}/consent-challenges",
            headers=headers,
            json={"decision": decision},
        )
        self.assertEqual(issued.status_code, 200, issued.text)
        challenge = issued.json()
        supplied = signature or account.sign_message(
            encode_defunct(text=challenge["message"])
        ).signature.hex()
        context = (
            patch(
                "tinker_delegate.wallet_signature_verifier."
                "wallet_signature_verifier_from_settings",
                return_value=verifier,
            )
            if verifier is not None
            else _NullContext()
        )
        with context:
            recorded = self.client.post(
                f"/collaboration/rooms/{ROOM_ID}/consents",
                headers=headers,
                json={
                    "challenge_id": challenge["challenge_id"],
                    "decision": decision,
                    "signature": supplied,
                },
            )
        self.assertEqual(recorded.status_code, 200, recorded.text)
        return headers, challenge, supplied, recorded.json()

    def query_grant(
        self,
        account,
        decision="approve",
        *,
        verifier=None,
        signature="",
    ):
        headers = self.headers(account)
        issued = self.client.post(
            f"/collaboration/rooms/{ROOM_ID}/query-grant-challenges",
            headers=headers,
            json={"decision": decision},
        )
        self.assertEqual(issued.status_code, 200, issued.text)
        challenge = issued.json()
        supplied = signature or account.sign_message(
            encode_defunct(text=challenge["message"])
        ).signature.hex()
        context = (
            patch(
                "tinker_delegate.wallet_signature_verifier."
                "wallet_signature_verifier_from_settings",
                return_value=verifier,
            )
            if verifier is not None
            else _NullContext()
        )
        with context:
            recorded = self.client.post(
                f"/collaboration/rooms/{ROOM_ID}/query-grants",
                headers=headers,
                json={
                    "challenge_id": challenge["challenge_id"],
                    "decision": decision,
                    "signature": supplied,
                },
            )
        self.assertEqual(recorded.status_code, 200, recorded.text)
        return headers, challenge, supplied, recorded.json()

    def prepare_roles(self):
        self.invitation(
            self.owner_a,
            "accept",
            key="accept-owner-a",
        )
        self.invitation(
            self.owner_b,
            "accept",
            key="accept-owner-b",
        )
        self.role_consent(self.owner_a)
        self.role_consent(self.owner_b)

    def test_disabled_is_default_strict_and_every_route_gates_before_state(self):
        self.assertFalse(Settings().collaboration_enabled)
        for loose in ("yes", "True", "1", 1):
            with self.subTest(loose=loose):
                with self.assertRaises(ValidationError):
                    Settings(collaboration_enabled=loose)

        api.settings = Settings(collaboration_enabled=False)
        api._collaboration_store_instance = None
        api._collaboration_store_instance_identity = None
        routes = [
            ("POST", "/auth/collaboration/challenge", {
                "address": self.creator.address,
            }),
            ("POST", "/auth/collaboration/token", {
                "nonce": "a" * 32,
                "signature": "0x12",
            }),
            ("POST", "/collaboration/rooms", self.room_payload()),
            ("GET", "/collaboration/rooms", None),
            ("GET", f"/collaboration/rooms/{ROOM_ID}", None),
            ("POST", f"/collaboration/rooms/{ROOM_ID}/invitations/accept", {
                "idempotency_key": "accept-room-0001",
            }),
            ("POST", f"/collaboration/rooms/{ROOM_ID}/invitations/decline", {
                "idempotency_key": "decline-room-0001",
            }),
            ("POST", f"/collaboration/rooms/{ROOM_ID}/invitations/cancel", {
                "invitee_address": self.owner_a.address,
                "idempotency_key": "cancel-room-0001",
            }),
            ("POST", f"/collaboration/rooms/{ROOM_ID}/archive", {
                "idempotency_key": "archive-room-0001",
            }),
            ("POST", f"/collaboration/rooms/{ROOM_ID}/consent-challenges", {
                "decision": "activate",
            }),
            ("GET", f"/collaboration/consent-challenges/consent_{'a' * 32}", None),
            ("POST", f"/collaboration/rooms/{ROOM_ID}/consents", {
                "challenge_id": "consent_" + "a" * 32,
                "decision": "activate",
                "signature": "0x12",
            }),
            ("POST", f"/collaboration/rooms/{ROOM_ID}/query-proposals", {
                "query_ref": _commitment("query"),
                "idempotency_key": "query-room-0001",
            }),
            ("POST", f"/collaboration/rooms/{ROOM_ID}/query-grant-challenges", {
                "decision": "approve",
            }),
            ("GET", f"/collaboration/query-grant-challenges/qgrant_{'a' * 32}", None),
            ("POST", f"/collaboration/rooms/{ROOM_ID}/query-grants", {
                "challenge_id": "qgrant_" + "a" * 32,
                "decision": "approve",
                "signature": "0x12",
            }),
            ("POST", f"/collaboration/rooms/{ROOM_ID}/runs", {
                "query_ref": _commitment("query"),
                "idempotency_key": "joint-run-0001",
            }),
            ("GET", f"/collaboration/runs/run_{'a' * 32}", None),
        ]
        for method, path, body in routes:
            with self.subTest(method=method, path=path):
                response = self.client.request(method, path, json=body)
                self.assertEqual(response.status_code, 503, response.text)
                self.assertEqual(
                    response.json()["detail"],
                    "Collaboration backend is disabled",
                )
        for method, path in (
            ("POST", "/auth/collaboration/challenge"),
            ("POST", "/collaboration/rooms"),
            ("GET", "/collaboration/rooms?limit=999"),
            ("GET", "/collaboration/not-a-route"),
        ):
            with self.subTest(invalid_before_route=True, method=method, path=path):
                response = self.client.request(method, path, json={})
                self.assertEqual(response.status_code, 503, response.text)
                self.assertEqual(
                    response.json()["detail"],
                    "Collaboration backend is disabled",
                )
                self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertFalse(self.store_path.exists())
        self.assertIsNone(api._collaboration_store_instance)

    def test_enabled_invitation_role_query_and_snapshot_flow(self):
        room = self.create_room()
        self.assertEqual(room["schema_version"], 2)
        self.assertEqual(
            room["accepted_member_addresses"],
            [self.creator.address.lower()],
        )
        self.assertEqual(len(room["pending_invitation_addresses"]), 2)
        owner_headers = self.headers(self.owner_a)
        invited = self.client.get(
            f"/collaboration/rooms/{ROOM_ID}",
            headers=owner_headers,
        )
        self.assertEqual(invited.status_code, 200, invited.text)
        self.assertEqual(
            invited.json()["requester_membership_status"],
            "invited",
        )
        denied = self.client.post(
            f"/collaboration/rooms/{ROOM_ID}/consent-challenges",
            headers=owner_headers,
            json={"decision": "activate"},
        )
        self.assertEqual(denied.status_code, 403, denied.text)

        self.prepare_roles()
        creator_headers = self.headers(self.creator)
        query_ref = _commitment("exact-query")
        proposed = self.client.post(
            f"/collaboration/rooms/{ROOM_ID}/query-proposals",
            headers=creator_headers,
            json={
                "query_ref": query_ref,
                "idempotency_key": "query-proposal-0001",
            },
        )
        self.assertEqual(proposed.status_code, 200, proposed.text)
        self.assertFalse(
            proposed.json()["query"]["all_required_query_grants_current"]
        )
        self.query_grant(self.owner_a)
        _, _, _, second = self.query_grant(self.owner_b)
        self.assertTrue(
            second["query"]["all_required_query_grants_current"]
        )

        inherited = self.client.post(
            f"/collaboration/rooms/{ROOM_ID}/runs",
            headers=creator_headers,
            json={
                "query_ref": _commitment("different-query"),
                "idempotency_key": "joint-run-wrong-query",
            },
        )
        self.assertEqual(inherited.status_code, 409, inherited.text)
        recorded = self.client.post(
            f"/collaboration/rooms/{ROOM_ID}/runs",
            headers=creator_headers,
            json={
                "query_ref": query_ref,
                "idempotency_key": "joint-run-0001",
            },
        )
        self.assertEqual(recorded.status_code, 200, recorded.text)
        snapshot = recorded.json()
        self.assertEqual(
            snapshot["surface"],
            "collaboration_joint_consent_snapshot",
        )
        self.assertTrue(snapshot["consent_snapshot_current"])
        self.assertFalse(snapshot["execution_authority"])
        self.assertGreater(
            snapshot["reclaimable_after"],
            snapshot["recorded_at"],
        )

    def test_decline_removes_visibility_and_replay_is_recoverable(self):
        self.create_room()
        first = self.invitation(
            self.owner_a,
            "decline",
            key="decline-owner-a",
        )
        replay = self.invitation(
            self.owner_a,
            "decline",
            key="decline-owner-a",
        )
        self.assertEqual(replay, first)
        headers = self.headers(self.owner_a)
        listing = self.client.get(
            "/collaboration/rooms",
            headers=headers,
        )
        self.assertEqual(listing.status_code, 200, listing.text)
        self.assertEqual(listing.json()["rooms"], [])
        direct = self.client.get(
            f"/collaboration/rooms/{ROOM_ID}",
            headers=headers,
        )
        self.assertEqual(direct.status_code, 403, direct.text)

    def test_snapshot_cursor_continuation_tamper_and_restart(self):
        creator_headers = self.headers(self.creator)
        for index in range(1, 4):
            room_id = "room_" + f"{index:032x}"
            response = self.client.post(
                "/collaboration/rooms",
                headers=creator_headers,
                json=self.room_payload(room_id=room_id, index=index),
            )
            self.assertEqual(response.status_code, 200, response.text)
        first = self.client.get(
            "/collaboration/rooms?limit=1",
            headers=creator_headers,
        )
        self.assertEqual(first.status_code, 200, first.text)
        cursor = first.json()["next_cursor"]
        second = self.client.get(
            "/collaboration/rooms",
            params={"limit": 1, "cursor": cursor},
            headers=creator_headers,
        )
        self.assertEqual(second.status_code, 200, second.text)
        self.assertNotEqual(
            first.json()["rooms"][0]["room_id"],
            second.json()["rooms"][0]["room_id"],
        )
        tampered = cursor[:-1] + ("0" if cursor[-1] != "0" else "1")
        invalid = self.client.get(
            "/collaboration/rooms",
            params={"limit": 1, "cursor": tampered},
            headers=creator_headers,
        )
        self.assertEqual(invalid.status_code, 409, invalid.text)

        self.client.post(
            f"/collaboration/rooms/room_{3:032x}/invitations/cancel",
            headers=creator_headers,
            json={
                "invitee_address": self.owner_a.address,
                "idempotency_key": "cancel-owner-a-room-3",
            },
        )
        stale = self.client.get(
            "/collaboration/rooms",
            params={"limit": 1, "cursor": cursor},
            headers=creator_headers,
        )
        self.assertEqual(stale.status_code, 409, stale.text)
        restarted = self.client.get(
            "/collaboration/rooms?limit=1",
            headers=creator_headers,
        )
        self.assertEqual(restarted.status_code, 200, restarted.text)

    def test_eip1271_lost_response_retries_are_exact_and_nonduplicating(self):
        self.create_room()
        self.invitation(
            self.owner_a,
            "accept",
            key="accept-owner-a",
        )

        class ContractVerifier:
            def verify(self, *, address, message, signature):
                self.calls = getattr(self, "calls", 0) + 1
                return "eip1271"

        verifier = ContractVerifier()
        headers = self.headers(self.owner_a)
        issued = self.client.post(
            f"/collaboration/rooms/{ROOM_ID}/consent-challenges",
            headers=headers,
            json={"decision": "activate"},
        )
        challenge = issued.json()
        body = {
            "challenge_id": challenge["challenge_id"],
            "decision": "activate",
            "signature": "0x1234",
        }
        with patch(
            "tinker_delegate.wallet_signature_verifier."
            "wallet_signature_verifier_from_settings",
            return_value=verifier,
        ):
            first = self.client.post(
                f"/collaboration/rooms/{ROOM_ID}/consents",
                headers=headers,
                json=body,
            )
            replay = self.client.post(
                f"/collaboration/rooms/{ROOM_ID}/consents",
                headers=headers,
                json=body,
            )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(
            first.json()["room"]["generation"],
            replay.json()["room"]["generation"],
        )
        self.assertEqual(verifier.calls, 2)
        stored = self.store_path.read_text("utf-8")
        self.assertNotIn("0x1234", stored)

        mismatch = dict(body, signature="0xabcd")
        with patch(
            "tinker_delegate.wallet_signature_verifier."
            "wallet_signature_verifier_from_settings",
            return_value=verifier,
        ):
            conflict = self.client.post(
                f"/collaboration/rooms/{ROOM_ID}/consents",
                headers=headers,
                json=mismatch,
            )
        self.assertEqual(conflict.status_code, 409, conflict.text)

    def test_store_configuration_failure_is_bounded_when_enabled(self):
        headers = self.headers(self.creator)
        api.settings.collaboration_store_path = ""
        api._collaboration_store_instance = None
        api._collaboration_store_instance_identity = None
        unavailable = self.client.post(
            "/collaboration/rooms",
            headers=headers,
            json=self.room_payload(),
        )
        self.assertEqual(unavailable.status_code, 503, unavailable.text)
        self.assertEqual(
            unavailable.json()["detail"],
            "Collaboration durable store is not configured",
        )

    def test_execution_capability_is_feature_gated_and_bounded(self):
        disabled = self.client.get("/collaboration/execution-capability")
        self.assertEqual(disabled.status_code, 503, disabled.text)

        api.settings.collaboration_execution_enabled = True
        enabled = self.client.get("/collaboration/execution-capability")
        self.assertEqual(enabled.status_code, 200, enabled.text)
        self.assertEqual(
            enabled.headers["cache-control"],
            "no-store, max-age=0",
        )
        body = enabled.json()
        self.assertEqual(
            body["evidence_classification"],
            "authenticated_worker_presence_not_job_attestation",
        )
        self.assertEqual(body["status"], "unavailable")
        self.assertFalse(body["onchain_reservation_ready"])
        self.assertFalse(body["tdx_job_attestation_proven"])
        self.assertFalse(body["qvl_job_verdict_proven"])

    def test_reservation_calldata_is_withheld_without_fresh_presence(self):
        value = {
            "royalty_reservation": {
                "transaction": {
                    "to": "0x" + "1" * 40,
                    "function_name": "reserveNative",
                    "abi_signature": "reserveNative((bytes32))",
                    "calldata": "0x1234",
                    "value": "10",
                    "erc20_approval_required": False,
                    "erc20_approval": None,
                }
            }
        }
        unavailable = {
            "onchain_reservation_ready": False,
            "evidence_classification": (
                "authenticated_worker_presence_not_job_attestation"
            ),
        }
        with patch.object(
            api,
            "_project_collaboration_execution_capability",
            return_value=unavailable,
        ):
            gated = api._with_collaboration_execution_capability(
                value,
                resource_kind="execution_authorization",
            )
        self.assertEqual(
            gated["surface"],
            "collaboration_execution_api_envelope",
        )
        self.assertEqual(gated["schema_version"], 1)
        self.assertEqual(
            gated["resource_kind"],
            "execution_authorization",
        )
        self.assertTrue(gated["queue_control"]["queued_not_executable"])
        self.assertEqual(
            gated["payload"]["royalty_reservation"]["transaction"]["status"],
            "gated_worker_presence_required",
        )
        self.assertEqual(
            set(gated["payload"]["royalty_reservation"]["transaction"]),
            {
                "schema",
                "status",
                "reason",
                "executable",
                "wallet_transaction_included",
                "erc20_approval_included",
            },
        )
        gated_serialized = json.dumps(gated, sort_keys=True)
        self.assertNotIn("0x1234", gated_serialized)
        self.assertNotIn('"value": "10"', gated_serialized)
        self.assertNotIn("reserveNative((bytes32))", gated_serialized)

        ready = dict(unavailable, onchain_reservation_ready=True)
        with patch.object(
            api,
            "_project_collaboration_execution_capability",
            return_value=ready,
        ):
            live = api._with_collaboration_execution_capability(
                value,
                resource_kind="execution_authorization",
            )
        self.assertFalse(live["queue_control"]["queued_not_executable"])
        self.assertEqual(
            live["payload"]["royalty_reservation"]["transaction"]["calldata"],
            "0x1234",
        )
        self.assertEqual(
            set(live["payload"]["royalty_reservation"]["transaction"]),
            {
                "to",
                "function_name",
                "abi_signature",
                "calldata",
                "value",
                "erc20_approval_required",
                "erc20_approval",
            },
        )

    def test_sponsor_settlement_prepare_status_broadcast_and_lost_response_replay(self):
        now = 1_800_000_000
        sponsor = self.creator.address.lower()
        execution_id = "exec_" + "a" * 64
        authority = {
            "execution_id": execution_id,
            "sponsor_address": sponsor,
            "funding_reservation_id": "0x" + "b" * 64,
            "settlement_id": "0x" + "c" * 64,
            "settlement_nonce": 2**53 + 17,
            "refund_after": now + 600,
        }
        settlement_store = CollaborationRoyaltySettlementStore(
            Path(self.temporary.name) / "royalty-settlement.json",
            integrity_key=b"r" * 32,
        )
        api.settings.collaboration_execution_enabled = True
        wallet_plan = {
            "schema": "dnai.collaboration.royalty-settlement-wallet-plan.v1",
            "plan_commitment": "0x" + "d" * 64,
            "settlement_nonce": str(2**53 + 17),
        }

        class Policy:
            def finalized_royalty_wallet_plan(self, *, plan_commitment, now):
                self.calls = getattr(self, "calls", 0) + 1
                assert plan_commitment == "0x" + "d" * 64
                return wallet_plan

        policy = Policy()
        common = (
            patch.object(
                api,
                "_require_collaboration_wallet_auth",
                return_value=SimpleNamespace(address=sponsor),
            ),
            patch.object(
                api,
                "_collaboration_royalty_settlement_authority",
                return_value=authority,
            ),
            patch.object(
                api,
                "_get_collaboration_royalty_settlement_store",
                return_value=settlement_store,
            ),
            patch.object(
                api,
                "_get_execution_policy_anchor_coordinator",
                return_value=policy,
            ),
            patch("time.time", return_value=now),
        )
        with common[0], common[1], common[2], common[3], common[4]:
            empty = self.client.get(
                f"/collaboration/executions/{execution_id}/royalty-settlement",
                headers={"Authorization": "Bearer bounded"},
            )
            self.assertEqual(empty.status_code, 200, empty.text)
            self.assertEqual(empty.json()["state"], "not_requested")
            self.assertEqual(empty.json()["settlement_nonce"], str(2**53 + 17))

            prepared = self.client.post(
                f"/collaboration/executions/{execution_id}/royalty-settlement/prepare",
                headers={"Authorization": "Bearer bounded"},
                json={
                    "idempotency_key": "prepare-settlement-0001",
                    "replace_expired": False,
                },
            )
            self.assertEqual(prepared.status_code, 202, prepared.text)
            self.assertEqual(prepared.json()["state"], "prepare_requested")
            self.assertEqual(
                prepared.headers["cache-control"],
                "no-store, max-age=0",
            )

            settlement_store.claim_next(claimed_at=now + 1)
            settlement_store.mark_plan_ready(
                execution_id=execution_id,
                generation=1,
                plan_commitment="0x" + "d" * 64,
                authorization_expires_at=now + 120,
                recorded_at=now + 2,
            )
            ready = self.client.get(
                f"/collaboration/executions/{execution_id}/royalty-settlement",
                headers={"Authorization": "Bearer bounded"},
            )
            self.assertEqual(ready.status_code, 200, ready.text)
            self.assertEqual(ready.json()["wallet_plan"], wallet_plan)

            body = {
                "idempotency_key": "broadcast-settlement-0001",
                "plan_commitment": "0x" + "d" * 64,
                "transaction_hash": "0x" + "e" * 64,
            }
            broadcast = self.client.post(
                f"/collaboration/executions/{execution_id}/royalty-settlement/broadcast",
                headers={"Authorization": "Bearer bounded"},
                json=body,
            )
            self.assertEqual(broadcast.status_code, 202, broadcast.text)
            self.assertEqual(broadcast.json()["state"], "broadcast_reported")

        settlement_store.mark_expired(
            execution_id=execution_id,
            generation=1,
            recorded_at=now + 121,
        )

        # A normal retry arrives in a later second; it must recover the
        # original advisory timestamp instead of manufacturing a conflict.
        with common[0], common[1], common[2], common[3], patch(
            "time.time", return_value=now + 1
        ):
            replay = self.client.post(
                f"/collaboration/executions/{execution_id}/royalty-settlement/broadcast",
                headers={"Authorization": "Bearer bounded"},
                json=body,
            )
        self.assertEqual(replay.status_code, 202, replay.text)
        self.assertEqual(replay.json()["state"], "expired")
        self.assertEqual(
            replay.json()["broadcast_hint"],
            broadcast.json()["broadcast_hint"],
        )

        settlement_store.mark_refunded(
            execution_id=execution_id,
            generation=1,
            terminal_evidence={
                "outcome": "reservation_refunded",
                "chain_id": 84_532,
                "block_number": 12_345_679,
                "block_hash": "0x" + "f" * 64,
                "block_timestamp": now + 700,
                "funding_reservation_id": authority[
                    "funding_reservation_id"
                ],
                "reservation_storage_status": "refunded",
                "reservation_active": False,
                "reservation_consumed": False,
                "reservation_deposited_amount": 0,
                "settlement_processed": False,
                "settlement_nonce_processed": False,
                "source_commitment": "sha256:" + "1" * 64,
            },
            recorded_at=now + 700,
        )
        # The first HTTP response may have been lost before either finality
        # transition. Exact idempotent replays remain recoverable even after
        # the reservation has reached its permanent refunded state.
        with common[0], common[1], common[2], common[3], patch(
            "time.time", return_value=now + 701
        ):
            terminal_replay = self.client.post(
                f"/collaboration/executions/{execution_id}/royalty-settlement/broadcast",
                headers={"Authorization": "Bearer bounded"},
                json=body,
            )
        self.assertEqual(terminal_replay.status_code, 202, terminal_replay.text)
        self.assertEqual(terminal_replay.json()["state"], "refunded")
        self.assertEqual(
            terminal_replay.json()["broadcast_hint"],
            broadcast.json()["broadcast_hint"],
        )


class _NullContext:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


if __name__ == "__main__":
    unittest.main()
