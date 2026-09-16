"""Durability and fail-closed tests for execution-policy bindings."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.config import Settings
from tinker_delegate.execution_policy_store import (
    MAX_DECISION_TTL_SECONDS,
    ZERO_DECISION_HASH,
    ExecutionPolicyNotPassed,
    ExecutionPolicyStore,
    ExecutionPolicyStoreCorrupt,
    ExecutionPolicyStoreError,
    ExecutionPolicyStoreUnavailable,
    execution_policy_approval_message,
    execution_policy_approval_domain_hash,
    execution_policy_approver_hash,
    execution_policy_approver_root_hash,
    execution_policy_integrity_key,
    execution_resource_hash,
    verify_execution_policy_approval,
)
from tinker_delegate.policy_kernel import gate_access_request_payload


APPROVER_PRIVATE_KEY = "0x" + "33" * 32
APPROVER_ADDRESS = Account.from_key(APPROVER_PRIVATE_KEY).address
APPROVER_HASH = execution_policy_approver_hash(APPROVER_ADDRESS)
APPROVER_ROOT_HASH = execution_policy_approver_root_hash([APPROVER_HASH])
APPROVAL_HASH = "b" * 64
APPROVAL_DOMAIN = (
    "base-sepolia:84532:"
    + "1" * 64
    + ":0x"
    + "2" * 64
    + ":"
    + "3" * 64
    + ":"
    + APPROVER_ROOT_HASH
)
APPROVAL_DOMAIN_HASH = execution_policy_approval_domain_hash(APPROVAL_DOMAIN)


def _result(*, data_classes=None):
    request = {
        "request_id": "request-1",
        "requester_ref": "agent://sponsor",
        "purpose": "rank-candidates",
        "pipeline": "sft-rerank",
        "data_classes": data_classes or ["assay-summary"],
        "output_schema": "score-band-v1",
        "operations": ["score"],
    }
    policy = {
        "policy_id": "policy-1",
        "version": "policy-kernel/v1",
        "corpus_ref": "corpus://private",
        "allowed_purposes": ["rank-candidates"],
        "denied_purposes": [],
        "allowed_pipelines": ["sft-rerank"],
        "allowed_output_schemas": ["score-band-v1"],
        "allowed_operations": ["score"],
        "known_data_classes": ["assay-summary", "clinical-summary"],
        "restricted_categories": [],
        "hold_categories": ["clinical-summary"],
        "ambiguous_categories": [],
        "hold_routes": {"clinical-summary": "expert-in-the-loop"},
    }
    return gate_access_request_payload(request, policy)


def _capture(function):
    try:
        return function()
    except Exception as exc:  # exercised as the expected losing CAS branch
        return exc


class ExecutionPolicyStoreTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "policy-state.json"
        self.key = bytes(range(32))

    def tearDown(self):
        self.tempdir.cleanup()

    def _store(self):
        return ExecutionPolicyStore(self.path, integrity_key=self.key)

    def test_pass_round_trips_without_raw_resource_or_policy(self):
        store = self._store()
        record = store.append(
            surface="deal_evaluation",
            resource_id="private-deal-7",
            result=_result(),
            recorded_at=100,
            expires_at=200,
            expected_previous_decision_hash=ZERO_DECISION_HASH,
            approver_hash=APPROVER_HASH,
            approval_hash=APPROVAL_HASH,
            approval_domain_hash=APPROVAL_DOMAIN_HASH,
            approver_root_hash=APPROVER_ROOT_HASH,
        )

        self.assertEqual(record["decision"], "pass")
        self.assertEqual(record["approver_root_hash"], APPROVER_ROOT_HASH)
        self.assertEqual(
            record["resource_id_hash"],
            execution_resource_hash("deal_evaluation", "private-deal-7"),
        )
        self.assertNotIn("private-deal-7", json.dumps(record))
        self.assertFalse(record["raw_policy_egress"])
        self.assertFalse(record["raw_resource_id_egress"])
        self.assertEqual(store.require_pass(
            surface="deal_evaluation",
            resource_id="private-deal-7",
            now=150,
            expected_approval_domain_hash=APPROVAL_DOMAIN_HASH,
            expected_approver_root_hash=APPROVER_ROOT_HASH,
            approved_approver_hashes={APPROVER_HASH},
        )["decision"], "pass")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        persisted = self.path.read_text()
        self.assertNotIn("private-deal-7", persisted)
        self.assertNotIn("rank-candidates", persisted)
        self.assertNotIn("assay-summary", persisted)

    def test_pass_requires_exact_execution_context_when_caller_supplies_one(self):
        store = self._store()
        expected_context = "c" * 64
        record = store.append(
            surface="compute_dispatch",
            resource_id="job_bound_context",
            result=replace(
                _result(), execution_context_hash=expected_context
            ),
            recorded_at=100,
            expires_at=200,
            expected_previous_decision_hash=ZERO_DECISION_HASH,
            approver_hash=APPROVER_HASH,
            approval_hash=APPROVAL_HASH,
            approval_domain_hash=APPROVAL_DOMAIN_HASH,
            approver_root_hash=APPROVER_ROOT_HASH,
        )
        self.assertEqual(record["execution_context_hash"], expected_context)
        self.assertEqual(
            store.require_pass(
                surface="compute_dispatch",
                resource_id="job_bound_context",
                now=150,
                expected_approval_domain_hash=APPROVAL_DOMAIN_HASH,
                expected_approver_root_hash=APPROVER_ROOT_HASH,
                approved_approver_hashes={APPROVER_HASH},
                expected_execution_context_hash=expected_context,
            )["decision"],
            "pass",
        )
        with self.assertRaisesRegex(
            ExecutionPolicyNotPassed,
            "context does not match",
        ):
            store.require_pass(
                surface="compute_dispatch",
                resource_id="job_bound_context",
                now=150,
                expected_approval_domain_hash=APPROVAL_DOMAIN_HASH,
                expected_approver_root_hash=APPROVER_ROOT_HASH,
                approved_approver_hashes={APPROVER_HASH},
                expected_execution_context_hash="d" * 64,
            )

    def test_latest_hold_supersedes_pass_and_expiry_fails_closed(self):
        store = self._store()
        store.append(
            surface="deal_evaluation",
            resource_id="deal-7",
            result=_result(),
            recorded_at=100,
            expires_at=200,
            expected_previous_decision_hash=ZERO_DECISION_HASH,
            approver_hash=APPROVER_HASH,
            approval_hash=APPROVAL_HASH,
            approval_domain_hash=APPROVAL_DOMAIN_HASH,
            approver_root_hash=APPROVER_ROOT_HASH,
        )
        with self.assertRaises(ExecutionPolicyNotPassed):
            store.require_pass(
                surface="deal_evaluation",
                resource_id="deal-7",
                now=200,
                expected_approval_domain_hash=APPROVAL_DOMAIN_HASH,
                expected_approver_root_hash=APPROVER_ROOT_HASH,
                approved_approver_hashes={APPROVER_HASH},
            )

        held = store.append(
            surface="deal_evaluation",
            resource_id="deal-7",
            result=_result(data_classes=["clinical-summary"]),
            recorded_at=201,
            expires_at=300,
            expected_previous_decision_hash=store.latest_decision_hash(
                surface="deal_evaluation", resource_id="deal-7"
            ),
        )
        self.assertEqual(held["decision"], "hold")
        with self.assertRaises(ExecutionPolicyNotPassed):
            store.require_pass(
                surface="deal_evaluation",
                resource_id="deal-7",
                now=250,
                expected_approval_domain_hash=APPROVAL_DOMAIN_HASH,
                expected_approver_root_hash=APPROVER_ROOT_HASH,
                approved_approver_hashes={APPROVER_HASH},
            )

    def test_stale_replay_and_concurrent_compare_and_append_fail_closed(self):
        store = self._store()

        def append_first_pass():
            return store.append(
                surface="deal_evaluation",
                resource_id="deal-race",
                result=_result(),
                recorded_at=100,
                expires_at=300,
                expected_previous_decision_hash=ZERO_DECISION_HASH,
                approver_hash=APPROVER_HASH,
                approval_hash=APPROVAL_HASH,
                approval_domain_hash=APPROVAL_DOMAIN_HASH,
                approver_root_hash=APPROVER_ROOT_HASH,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _index: _capture(append_first_pass), range(2)))
        self.assertEqual(sum(isinstance(item, dict) for item in outcomes), 1)
        self.assertEqual(sum(isinstance(item, ExecutionPolicyStoreError) for item in outcomes), 1)

        first_head = store.latest_decision_hash(
            surface="deal_evaluation", resource_id="deal-race"
        )
        held = store.append(
            surface="deal_evaluation",
            resource_id="deal-race",
            result=_result(data_classes=["clinical-summary"]),
            recorded_at=101,
            expires_at=300,
            expected_previous_decision_hash=first_head,
        )
        self.assertEqual(held["previous_decision_hash"], first_head)
        with self.assertRaisesRegex(
            ExecutionPolicyStoreError, "previous decision changed"
        ):
            append_first_pass()

        # A different resource has an independent head and does not invalidate
        # this resource's compare-and-append chain.
        unrelated = store.append(
            surface="compute_dispatch",
            resource_id="job-unrelated",
            result=_result(data_classes=["clinical-summary"]),
            recorded_at=102,
            expires_at=300,
            expected_previous_decision_hash=ZERO_DECISION_HASH,
        )
        self.assertEqual(unrelated["previous_decision_hash"], ZERO_DECISION_HASH)

    def test_future_records_and_exhausted_revocation_capacity_fail_closed(self):
        store = self._store()
        store.append(
            surface="deal_evaluation",
            resource_id="deal-future",
            result=_result(),
            recorded_at=200,
            expires_at=300,
            expected_previous_decision_hash=ZERO_DECISION_HASH,
            approver_hash=APPROVER_HASH,
            approval_hash=APPROVAL_HASH,
            approval_domain_hash=APPROVAL_DOMAIN_HASH,
            approver_root_hash=APPROVER_ROOT_HASH,
        )
        with self.assertRaisesRegex(ExecutionPolicyNotPassed, "future-dated"):
            store.require_pass(
                surface="deal_evaluation",
                resource_id="deal-future",
                now=199,
                expected_approval_domain_hash=APPROVAL_DOMAIN_HASH,
                expected_approver_root_hash=APPROVER_ROOT_HASH,
                approved_approver_hashes={APPROVER_HASH},
            )

        with (
            patch("tinker_delegate.execution_policy_store.MAX_RECORDS", 2),
            patch("tinker_delegate.execution_policy_store.REVOCATION_RECORD_RESERVE", 1),
        ):
            capacity_store = ExecutionPolicyStore(
                Path(self.tempdir.name) / "capacity.json",
                integrity_key=self.key,
            )
            capacity_store.append(
                surface="deal_evaluation",
                resource_id="deal-capacity",
                result=_result(),
                recorded_at=100,
                expires_at=300,
                expected_previous_decision_hash=ZERO_DECISION_HASH,
                approver_hash=APPROVER_HASH,
                approval_hash=APPROVAL_HASH,
                approval_domain_hash=APPROVAL_DOMAIN_HASH,
                approver_root_hash=APPROVER_ROOT_HASH,
            )
            capacity_store.append(
                surface="compute_dispatch",
                resource_id="job-revocation",
                result=_result(data_classes=["clinical-summary"]),
                recorded_at=101,
                expires_at=300,
                expected_previous_decision_hash=ZERO_DECISION_HASH,
            )
            with self.assertRaisesRegex(
                ExecutionPolicyNotPassed, "revocation reserve is exhausted"
            ):
                capacity_store.require_pass(
                    surface="deal_evaluation",
                    resource_id="deal-capacity",
                    now=150,
                    expected_approval_domain_hash=APPROVAL_DOMAIN_HASH,
                    expected_approver_root_hash=APPROVER_ROOT_HASH,
                    approved_approver_hashes={APPROVER_HASH},
                )

    def test_missing_wrong_surface_and_overlong_ttl_fail_closed(self):
        store = self._store()
        with self.assertRaises(ExecutionPolicyNotPassed):
            store.require_pass(
                surface="compute_dispatch",
                resource_id="job-1",
                now=100,
                expected_approval_domain_hash=APPROVAL_DOMAIN_HASH,
                expected_approver_root_hash=APPROVER_ROOT_HASH,
                approved_approver_hashes={APPROVER_HASH},
            )
        with self.assertRaises(ExecutionPolicyStoreError):
            store.append(
                surface="deal_evaluation",
                resource_id="deal-7",
                result=_result(),
                recorded_at=100,
                expires_at=100 + MAX_DECISION_TTL_SECONDS + 1,
                expected_previous_decision_hash=ZERO_DECISION_HASH,
            )

    def test_tampering_is_detected_before_any_lookup(self):
        store = self._store()
        store.append(
            surface="deal_evaluation",
            resource_id="deal-7",
            result=_result(),
            recorded_at=100,
            expires_at=200,
            expected_previous_decision_hash=ZERO_DECISION_HASH,
            approver_hash=APPROVER_HASH,
            approval_hash=APPROVAL_HASH,
            approval_domain_hash=APPROVAL_DOMAIN_HASH,
            approver_root_hash=APPROVER_ROOT_HASH,
        )
        root = json.loads(self.path.read_text())
        root["payload"]["records"][0]["decision"] = "deny"
        self.path.write_text(json.dumps(root), encoding="utf-8")

        with self.assertRaises(ExecutionPolicyStoreCorrupt):
            self._store()

    def test_domain_change_or_signer_revocation_invalidates_stored_pass(self):
        store = self._store()
        store.append(
            surface="compute_dispatch",
            resource_id="job-7",
            result=_result(),
            recorded_at=100,
            expires_at=300,
            expected_previous_decision_hash=ZERO_DECISION_HASH,
            approver_hash=APPROVER_HASH,
            approval_hash=APPROVAL_HASH,
            approval_domain_hash=APPROVAL_DOMAIN_HASH,
            approver_root_hash=APPROVER_ROOT_HASH,
        )

        with self.assertRaises(ExecutionPolicyNotPassed):
            store.require_pass(
                surface="compute_dispatch",
                resource_id="job-7",
                now=150,
                expected_approval_domain_hash="d" * 64,
                expected_approver_root_hash=APPROVER_ROOT_HASH,
                approved_approver_hashes={APPROVER_HASH},
            )
        with self.assertRaises(ExecutionPolicyNotPassed):
            store.require_pass(
                surface="compute_dispatch",
                resource_id="job-7",
                now=150,
                expected_approval_domain_hash=APPROVAL_DOMAIN_HASH,
                expected_approver_root_hash=execution_policy_approver_root_hash(
                    ["e" * 64]
                ),
                approved_approver_hashes={"e" * 64},
            )

        store.append(
            surface="compute_dispatch",
            resource_id="job-wrong-persisted-root",
            result=_result(),
            recorded_at=100,
            expires_at=300,
            expected_previous_decision_hash=ZERO_DECISION_HASH,
            approver_hash=APPROVER_HASH,
            approval_hash=APPROVAL_HASH,
            approval_domain_hash=APPROVAL_DOMAIN_HASH,
            approver_root_hash="f" * 64,
        )
        with self.assertRaisesRegex(
            ExecutionPolicyNotPassed, "approver root"
        ):
            store.require_pass(
                surface="compute_dispatch",
                resource_id="job-wrong-persisted-root",
                now=150,
                expected_approval_domain_hash=APPROVAL_DOMAIN_HASH,
                expected_approver_root_hash=APPROVER_ROOT_HASH,
                approved_approver_hashes={APPROVER_HASH},
            )

    def test_local_and_dstack_key_resolution_are_separate_and_fail_closed(self):
        local = execution_policy_integrity_key(
            Settings(
                execution_policy_store_integrity_key=(
                    "local-policy-integrity-test-material-0001"
                )
            )
        )
        self.assertEqual(len(local), 32)
        with self.assertRaises(ExecutionPolicyStoreUnavailable):
            execution_policy_integrity_key(Settings())

        with (
            patch(
                "tinker_delegate.execution_policy_store.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.execution_policy_store.dstack_utils.derive_storage_key",
                return_value=b"d" * 32,
            ) as derive,
        ):
            dstack = execution_policy_integrity_key(Settings())
        self.assertEqual(len(dstack), 32)
        self.assertNotEqual(local, dstack)
        derive.assert_called_once_with("tinker/execution_policy_store_integrity")

        with patch(
            "tinker_delegate.execution_policy_store.dstack_utils.is_dstack_enabled",
            return_value=True,
        ):
            with self.assertRaises(ExecutionPolicyStoreUnavailable):
                execution_policy_integrity_key(
                    Settings(
                        execution_policy_store_integrity_key_path=(
                            "tinker/runtime-auth"
                        )
                    )
                )

    def test_hash_only_personal_sign_approval_is_independently_verified(self):
        account = Account.from_key(APPROVER_PRIVATE_KEY)
        result = _result()
        message = execution_policy_approval_message(
            surface="arena_execution",
            resource_id="submission-private-7",
            result=result,
            expires_at=500,
            approval_domain=APPROVAL_DOMAIN,
            approver_root_hash=APPROVER_ROOT_HASH,
            previous_decision_hash=ZERO_DECISION_HASH,
        )
        signature = Account.sign_message(
            encode_defunct(text=message), private_key=APPROVER_PRIVATE_KEY
        ).signature.hex()

        (
            approver_hash,
            approval_hash,
            approval_domain_hash,
            approver_root_hash,
        ) = verify_execution_policy_approval(
            settings=Settings(
                execution_policy_approved_signers=account.address,
                execution_policy_approval_domain=APPROVAL_DOMAIN,
                execution_policy_approver_root_hash=APPROVER_ROOT_HASH,
            ),
            surface="arena_execution",
            resource_id="submission-private-7",
            result=result,
            expires_at=500,
            approver_address=account.address,
            approval_signature=signature,
            previous_decision_hash=ZERO_DECISION_HASH,
        )

        self.assertEqual(len(approver_hash), 64)
        self.assertEqual(len(approval_hash), 64)
        self.assertEqual(len(approval_domain_hash), 64)
        self.assertEqual(approver_root_hash, APPROVER_ROOT_HASH)
        self.assertNotIn(account.address.lower(), message.lower())
        self.assertNotIn("submission-private-7", message)
        self.assertNotIn(APPROVAL_DOMAIN, message)
        self.assertIn(
            execution_resource_hash(
                "arena_execution", "submission-private-7"
            ),
            message,
        )

    def test_unconfigured_or_mismatched_approval_fails_closed(self):
        account = Account.from_key(APPROVER_PRIVATE_KEY)
        other = Account.from_key("0x" + "44" * 32)
        result = _result()
        message = execution_policy_approval_message(
            surface="compute_dispatch",
            resource_id="job-7",
            result=result,
            expires_at=500,
            approval_domain=APPROVAL_DOMAIN,
            approver_root_hash=APPROVER_ROOT_HASH,
            previous_decision_hash=ZERO_DECISION_HASH,
        )
        signature = Account.sign_message(
            encode_defunct(text=message), private_key=APPROVER_PRIVATE_KEY
        ).signature.hex()

        with self.assertRaises(ExecutionPolicyStoreUnavailable):
            verify_execution_policy_approval(
                settings=Settings(),
                surface="compute_dispatch",
                resource_id="job-7",
                result=result,
                expires_at=500,
                approver_address=account.address,
                approval_signature=signature,
                previous_decision_hash=ZERO_DECISION_HASH,
            )
        with self.assertRaises(ExecutionPolicyStoreError):
            verify_execution_policy_approval(
                settings=Settings(
                    execution_policy_approved_signers=(
                        f"{account.address},{other.address}"
                    ),
                    execution_policy_approval_domain=APPROVAL_DOMAIN,
                    execution_policy_approver_root_hash=APPROVER_ROOT_HASH,
                ),
                surface="compute_dispatch",
                resource_id="job-7",
                result=result,
                expires_at=500,
                approver_address=other.address,
                approval_signature=signature,
                previous_decision_hash=ZERO_DECISION_HASH,
            )
        with self.assertRaises(ExecutionPolicyStoreError):
            verify_execution_policy_approval(
                settings=Settings(
                    execution_policy_approved_signers=account.address,
                    execution_policy_approval_domain=(
                        "dnai-wikigen:different-test-deployment"
                    ),
                    execution_policy_approver_root_hash=APPROVER_ROOT_HASH,
                ),
                surface="compute_dispatch",
                resource_id="job-7",
                result=result,
                expires_at=500,
                approver_address=account.address,
                approval_signature=signature,
                previous_decision_hash=ZERO_DECISION_HASH,
            )


if __name__ == "__main__":
    unittest.main()
