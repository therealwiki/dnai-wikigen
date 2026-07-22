import json
import tempfile
import threading
import unittest
from pathlib import Path

from eth_account import Account

from tinker_delegate.compute_auth import ComputeCredentialClaims
from tinker_delegate.compute_store import (
    ComputeAuthorizationError,
    ComputeCapExceeded,
    ComputeIdempotencyConflict,
    ComputeInsufficientCredits,
    ComputeJobStateConflict,
    ComputeStore,
    ComputeStoreCorruptError,
    ComputeStoreError,
)


class ComputeStoreTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "compute.json"
        self.key = b"k" * 32
        self.store = ComputeStore(self.path, integrity_key=self.key)
        self.owner = Account.from_key("0x" + "11" * 32).address.lower()
        self.other = Account.from_key("0x" + "22" * 32).address.lower()
        self.project, _ = self.store.create_project(
            owner_address=self.owner,
            name="atlas-research",
            idempotency_key="project-create-1234",
            created_at=100,
        )
        self.project_id = self.project["project_id"]

    def tearDown(self):
        self.temporary.cleanup()

    def _grant(self, amount=1000):
        return self.store.grant_credits(
            self.project_id,
            amount_credits=amount,
            reason="operator_testnet_grant",
            idempotency_key="operator-grant-1234",
            granted_at=101,
        )

    def _job(self, *, key="job-create-123456", max_credits=100, created_at=102):
        return self.store.create_job(
            self.project_id,
            actor_kind="wallet",
            actor_id=self.owner,
            credential_id=None,
            name="bounded-sample",
            operation="inference",
            model="qwen3_8b",
            recipe="qwen3_8b_bounded",
            max_credits=max_credits,
            result_policy="bounded_summary_receipt",
            environment_version="env_v1",
            idempotency_key=key,
            created_at=created_at,
        )

    def test_project_membership_is_wallet_authorized_and_owner_is_immutable(self):
        with self.assertRaises(ComputeAuthorizationError):
            self.store.project(self.project_id, self.other)
        updated = self.store.add_member(
            self.project_id,
            actor_address=self.owner,
            member_address=self.other,
            role="developer",
            updated_at=101,
        )
        member_roles = {item["address"]: item["role"] for item in updated["members"]}
        self.assertEqual(member_roles[self.other], "developer")
        self.assertEqual(self.store.project(self.project_id, self.other)["role"], "developer")
        with self.assertRaisesRegex(ValueError, "owner cannot be removed"):
            self.store.remove_member(
                self.project_id,
                actor_address=self.owner,
                member_address=self.owner,
                updated_at=102,
            )

    def test_grant_reserve_settle_is_double_entry_and_idempotent(self):
        grant, created = self._grant()
        self.assertTrue(created)
        replay, created = self._grant()
        self.assertFalse(created)
        self.assertEqual(replay["transaction_id"], grant["transaction_id"])
        job, created = self._job()
        self.assertTrue(created)
        self.assertEqual(
            self.store.balance(self.project_id, self.owner)["available_credits"], 900
        )
        self.assertEqual(
            self.store.balance(self.project_id, self.owner)["reserved_credits"], 100
        )
        settled, changed = self.store.settle_job(
            self.project_id,
            job["job_id"],
            actual_credits=16,
            usage_receipt_hash="sha256:" + "1" * 64,
            metering_source="operator_bounded_receipt",
            idempotency_key="settle-job-12345",
            settled_at=103,
        )
        self.assertTrue(changed)
        self.assertEqual(settled["settlement_authority"], "operator_runtime_not_provider_authoritative")
        balance = self.store.balance(self.project_id, self.owner)
        self.assertEqual(balance["available_credits"], 984)
        self.assertEqual(balance["reserved_credits"], 0)
        ledger = self.store.ledger(self.project_id, self.owner)
        self.assertTrue(ledger["append_only"])
        self.assertTrue(ledger["double_entry"])
        for transaction in ledger["transactions"]:
            self.assertEqual(sum(p["delta"] for p in transaction["postings"]), 0)
        self.assertFalse(settled["provider_authoritative_settlement"])

    def test_job_release_refunds_full_reservation_and_caps_are_enforced(self):
        self._grant()
        job, _ = self._job(max_credits=500)
        released, changed = self.store.release_job(
            self.project_id,
            job["job_id"],
            terminal_status="canceled",
            reason="dispatch_unavailable",
            idempotency_key="release-job-1234",
            released_at=103,
        )
        self.assertTrue(changed)
        self.assertEqual(released["released_credits"], 500)
        self.assertEqual(
            self.store.balance(self.project_id, self.owner)["available_credits"], 1000
        )
        with self.assertRaises(ComputeCapExceeded):
            self._job(key="oversized-job-1234", max_credits=501)

    def test_project_members_can_cancel_only_before_dispatch_with_exact_replay(self):
        self._grant()
        first, _ = self._job(key="owner-job-create-1234", max_credits=100)
        canceled, transaction, changed = self.store.cancel_queued_job(
            self.project_id,
            first["job_id"],
            actor_address=self.owner,
            reason="user_requested_before_dispatch",
            idempotency_key="owner-cancel-job-1234",
            canceled_at=103,
        )
        self.assertTrue(changed)
        self.assertEqual(canceled["status"], "canceled")
        self.assertEqual(canceled["actual_credits"], 0)
        self.assertEqual(canceled["released_credits"], 100)
        self.assertEqual(
            canceled["settlement_authority"],
            "project_member_pre_dispatch_cancel",
        )
        self.assertEqual(transaction["kind"], "job_cancel")
        self.assertEqual(transaction["authority"], "project_wallet_owner")
        self.assertEqual(
            transaction["settlement_status"],
            "user_canceled_before_dispatch",
        )
        self.assertEqual(
            transaction["postings"],
            [
                {
                    "account": f"project:{self.project_id}:reserved",
                    "delta": -100,
                },
                {
                    "account": f"project:{self.project_id}:available",
                    "delta": 100,
                },
            ],
        )

        replay, replay_transaction, changed = self.store.cancel_queued_job(
            self.project_id,
            first["job_id"],
            actor_address=self.owner,
            reason="user_requested_before_dispatch",
            idempotency_key="owner-cancel-job-1234",
            canceled_at=104,
        )
        self.assertFalse(changed)
        self.assertEqual(replay, canceled)
        self.assertEqual(
            replay_transaction["transaction_hash"], transaction["transaction_hash"]
        )

        self.store.add_member(
            self.project_id,
            actor_address=self.owner,
            member_address=self.other,
            role="admin",
            updated_at=104,
        )
        second, _ = self._job(
            key="admin-job-create-1234", max_credits=100, created_at=105
        )
        _job, admin_transaction, changed = self.store.cancel_queued_job(
            self.project_id,
            second["job_id"],
            actor_address=self.other,
            reason="user_requested_before_dispatch",
            idempotency_key="admin-cancel-job-1234",
            canceled_at=106,
        )
        self.assertTrue(changed)
        self.assertEqual(admin_transaction["authority"], "project_wallet_admin")

        self.store.add_member(
            self.project_id,
            actor_address=self.owner,
            member_address=self.other,
            role="developer",
            updated_at=107,
        )
        third, _ = self._job(
            key="developer-job-create-1234", max_credits=100, created_at=108
        )
        _job, developer_transaction, changed = self.store.cancel_queued_job(
            self.project_id,
            third["job_id"],
            actor_address=self.other,
            reason="user_requested_before_dispatch",
            idempotency_key="developer-cancel-1234",
            canceled_at=109,
        )
        self.assertTrue(changed)
        self.assertEqual(
            developer_transaction["authority"], "project_wallet_developer"
        )
        reopened = ComputeStore(self.path, integrity_key=self.key)
        reopened_job, reopened_transaction, changed = reopened.cancel_queued_job(
            self.project_id,
            third["job_id"],
            actor_address=self.other,
            reason="user_requested_before_dispatch",
            idempotency_key="developer-cancel-1234",
            canceled_at=110,
        )
        self.assertFalse(changed)
        self.assertEqual(reopened_job["status"], "canceled")
        self.assertEqual(
            reopened_transaction["transaction_hash"],
            developer_transaction["transaction_hash"],
        )
        balance = self.store.balance(self.project_id, self.owner)
        self.assertEqual(balance["available_credits"], 1000)
        self.assertEqual(balance["reserved_credits"], 0)
        cancels = [
            item
            for item in self.store.ledger(self.project_id, self.owner)["transactions"]
            if item["kind"] == "job_cancel"
        ]
        self.assertEqual(len(cancels), 3)
        self.assertTrue(all(sum(p["delta"] for p in tx["postings"]) == 0 for tx in cancels))

    def test_user_cancel_rejects_viewer_cross_project_running_settled_and_dispatched(self):
        self._grant()
        queued, _ = self._job(key="queued-job-create-1234", max_credits=100)
        self.store.add_member(
            self.project_id,
            actor_address=self.owner,
            member_address=self.other,
            role="viewer",
            updated_at=103,
        )
        with self.assertRaises(ComputeAuthorizationError):
            self.store.cancel_queued_job(
                self.project_id,
                queued["job_id"],
                actor_address=self.other,
                reason="user_requested_before_dispatch",
                idempotency_key="viewer-cancel-job-1234",
                canceled_at=104,
            )

        second_project, _ = self.store.create_project(
            owner_address=self.owner,
            name="other-project",
            idempotency_key="second-project-1234",
            created_at=104,
        )
        with self.assertRaisesRegex(ComputeStoreError, "job not found"):
            self.store.cancel_queued_job(
                second_project["project_id"],
                queued["job_id"],
                actor_address=self.owner,
                reason="user_requested_before_dispatch",
                idempotency_key="cross-project-cancel-1234",
                canceled_at=105,
            )

        self.store.start_job(
            self.project_id,
            queued["job_id"],
            idempotency_key="start-running-job-1234",
            started_at=105,
        )
        with self.assertRaises(ComputeJobStateConflict):
            self.store.cancel_queued_job(
                self.project_id,
                queued["job_id"],
                actor_address=self.owner,
                reason="user_requested_before_dispatch",
                idempotency_key="cancel-running-job-1234",
                canceled_at=106,
            )
        self.store.settle_job(
            self.project_id,
            queued["job_id"],
            actual_credits=10,
            usage_receipt_hash="sha256:" + "1" * 64,
            metering_source="operator_bounded_receipt",
            idempotency_key="settle-running-job-1234",
            settled_at=107,
        )
        with self.assertRaises(ComputeJobStateConflict):
            self.store.cancel_queued_job(
                self.project_id,
                queued["job_id"],
                actor_address=self.owner,
                reason="user_requested_before_dispatch",
                idempotency_key="cancel-settled-job-1234",
                canceled_at=108,
            )

        dispatched, _ = self._job(
            key="dispatched-job-create-1234", max_credits=100, created_at=108
        )
        # The current dispatcher is disabled, so inject the future state only
        # to prove this public guard is deny-by-default when that state exists.
        with self.store._lock:
            self.store._state["jobs"][dispatched["job_id"]][
                "dispatch_status"
            ] = "provider_dispatched"
        try:
            with self.assertRaises(ComputeJobStateConflict):
                self.store.cancel_queued_job(
                    self.project_id,
                    dispatched["job_id"],
                    actor_address=self.owner,
                    reason="user_requested_before_dispatch",
                    idempotency_key="cancel-dispatched-1234",
                    canceled_at=109,
                )
        finally:
            with self.store._lock:
                self.store._state["jobs"][dispatched["job_id"]][
                    "dispatch_status"
                ] = "not_dispatched"
        balance = self.store.balance(self.project_id, self.owner)
        self.assertEqual(balance["available_credits"], 890)
        self.assertEqual(balance["reserved_credits"], 100)

    def test_concurrent_identical_cancel_commits_one_credit_reversal(self):
        self._grant()
        job, _ = self._job(max_credits=250)
        barrier = threading.Barrier(3)
        results: list[tuple[dict, dict, bool]] = []
        errors: list[Exception] = []

        def cancel() -> None:
            barrier.wait()
            try:
                results.append(
                    self.store.cancel_queued_job(
                        self.project_id,
                        job["job_id"],
                        actor_address=self.owner,
                        reason="user_requested_before_dispatch",
                        idempotency_key="concurrent-cancel-1234",
                        canceled_at=103,
                    )
                )
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        threads = [threading.Thread(target=cancel) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(sorted(result[2] for result in results), [False, True])
        self.assertEqual(
            len({result[1]["transaction_hash"] for result in results}), 1
        )
        balance = self.store.balance(self.project_id, self.owner)
        self.assertEqual(balance["available_credits"], 1000)
        self.assertEqual(balance["reserved_credits"], 0)
        ledger = self.store.ledger(self.project_id, self.owner)
        cancellations = [
            item
            for item in ledger["transactions"]
            if item["kind"] == "job_cancel" and item["job_id"] == job["job_id"]
        ]
        self.assertEqual(len(cancellations), 1)
        self.assertEqual(sum(p["delta"] for p in cancellations[0]["postings"]), 0)

    def test_start_cancel_race_has_one_terminal_decision_and_no_double_release(self):
        self._grant()
        job, _ = self._job(max_credits=200)
        barrier = threading.Barrier(3)
        outcomes: list[tuple[str, bool | str]] = []

        def start() -> None:
            barrier.wait()
            try:
                _job, changed = self.store.start_job(
                    self.project_id,
                    job["job_id"],
                    idempotency_key="racing-start-job-1234",
                    started_at=103,
                )
                outcomes.append(("start", changed))
            except ComputeStoreError as exc:
                outcomes.append(("start_error", str(exc)))

        def cancel() -> None:
            barrier.wait()
            try:
                _job, _transaction, changed = self.store.cancel_queued_job(
                    self.project_id,
                    job["job_id"],
                    actor_address=self.owner,
                    reason="user_requested_before_dispatch",
                    idempotency_key="racing-cancel-job-1234",
                    canceled_at=103,
                )
                outcomes.append(("cancel", changed))
            except ComputeStoreError as exc:
                outcomes.append(("cancel_error", str(exc)))

        threads = [threading.Thread(target=start), threading.Thread(target=cancel)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(len(outcomes), 2)
        successes = [item for item in outcomes if item[0] in {"start", "cancel"}]
        self.assertEqual(len(successes), 1)
        self.assertTrue(successes[0][1])

        final_job = self.store.job(
            self.project_id,
            job["job_id"],
            wallet_address=self.owner,
        )
        balance = self.store.balance(self.project_id, self.owner)
        ledger = self.store.ledger(self.project_id, self.owner)
        cancellations = [
            item
            for item in ledger["transactions"]
            if item["kind"] == "job_cancel" and item["job_id"] == job["job_id"]
        ]
        if final_job["status"] == "canceled":
            self.assertEqual(len(cancellations), 1)
            self.assertEqual(balance["available_credits"], 1000)
            self.assertEqual(balance["reserved_credits"], 0)
        else:
            self.assertEqual(final_job["status"], "running")
            self.assertEqual(cancellations, [])
            self.assertEqual(balance["available_credits"], 800)
            self.assertEqual(balance["reserved_credits"], 200)
        self.assertTrue(
            all(
                sum(posting["delta"] for posting in transaction["postings"]) == 0
                for transaction in ledger["transactions"]
            )
        )

    def test_insufficient_credits_and_idempotency_conflict_fail_without_write(self):
        with self.assertRaises(ComputeInsufficientCredits):
            self._job()
        self._grant()
        self._job()
        with self.assertRaises(ComputeIdempotencyConflict):
            self.store.create_job(
                self.project_id,
                actor_kind="wallet",
                actor_id=self.owner,
                credential_id=None,
                name="different-job",
                operation="inference",
                model="qwen3_8b",
                recipe="qwen3_8b_bounded",
                max_credits=50,
                result_policy="bounded_summary_receipt",
                environment_version="env_v1",
                idempotency_key="job-create-123456",
                created_at=102,
            )

    def test_device_revocation_cascades_and_superseded_token_is_rejected(self):
        device = self.store.register_device(
            self.project_id,
            actor_address=self.owner,
            label="local-codex",
            kind="developer_device",
            public_key_hex="ab" * 32,
            registered_at=101,
        )
        jwt_id = "a" * 32
        jwt_hash = __import__("hashlib").sha256(
            b"compute_credential_jti:" + jwt_id.encode()
        ).hexdigest()
        credential = self.store.create_credential(
            self.project_id,
            actor_address=self.owner,
            credential_id="cred_12345678",
            device_id=device["device_id"],
            name="my-agent",
            scopes=("jobs:create", "jobs:read"),
            daily_credit_cap=500,
            generation=1,
            jwt_id_hash=jwt_hash,
            issued_at=102,
            expires_at=500,
        )
        claims = ComputeCredentialClaims(
            credential_id=credential["credential_id"],
            project_id=self.project_id,
            device_id=device["device_id"],
            generation=1,
            scopes=("jobs:create", "jobs:read"),
            daily_credit_cap=500,
            issued_at=102,
            expires_at=500,
            jwt_id=jwt_id,
        )
        self.store.authorize_credential(claims, required_scope="jobs:create", used_at=103)
        self.store.revoke_device(
            self.project_id,
            actor_address=self.owner,
            device_id=device["device_id"],
            revoked_at=104,
        )
        with self.assertRaises(ComputeAuthorizationError):
            self.store.authorize_credential(
                claims, required_scope="jobs:create", used_at=105
            )

    def test_hmac_tampering_and_wrong_key_fail_closed(self):
        persisted = json.loads(self.path.read_text())
        persisted["payload"]["projects"][self.project_id]["name"] = "tampered"
        self.path.write_text(json.dumps(persisted))
        with self.assertRaisesRegex(ComputeStoreCorruptError, "integrity"):
            ComputeStore(self.path, integrity_key=self.key)
        with self.assertRaises(ComputeStoreCorruptError):
            ComputeStore(self.path, integrity_key=b"z" * 32)

    def test_state_contains_no_token_or_raw_job_input_fields(self):
        self._grant()
        self._job()
        text = self.path.read_text()
        self.assertNotIn("access_token", text)
        self.assertNotIn("upstream_tinker", text)
        self.assertNotIn("prompt", text)
        self.assertNotIn("training_examples", text)


if __name__ == "__main__":
    unittest.main()
