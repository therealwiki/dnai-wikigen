import hashlib
import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from tinker_delegate.arena_store import (
    BIO_CHALLENGE_ID,
    BIO_CHALLENGE_VERSION,
    DNASEQ_SAFE_IR_CHALLENGE_ID,
    DNASEQ_SAFE_IR_CHALLENGE_VERSION,
    EXECUTION_ASSURANCE,
    PER_ROW_EXECUTION_ASSURANCE,
    PER_ROW_PRODUCT_STATUS,
    PRODUCT_STATUS,
    WORKER_REPORTED_EVIDENCE_CLASSIFICATION,
    ArenaIdempotencyConflict,
    ArenaStore,
    ArenaStoreCorruptError,
    ArenaStoreError,
    ExecutionCapability,
    ExecutionProvenance,
    QueueReason,
    QueueState,
    SubmissionIdentity,
    SubmissionManifest,
    SubmissionMode,
    default_challenge_catalog,
)
from tinker_delegate.ladder_release import LadderLeaderboard, LadderPolicy, LadderRelease


WALLET_A = "0x" + "ab" * 20
WALLET_B = "0x" + "cd" * 20
PROJECT_A = "wallet:" + "ab" * 20
PROJECT_B = "wallet:" + "cd" * 20


def _challenge():
    return default_challenge_catalog().get(BIO_CHALLENGE_ID, BIO_CHALLENGE_VERSION)


def _manifest(*, mode: SubmissionMode = SubmissionMode.LEADERBOARD, source_bytes: int = 128):
    challenge = _challenge()
    return SubmissionManifest(
        schema_version=1,
        challenge_manifest_hash=challenge.manifest_hash,
        candidate_kind=challenge.candidate_kind,
        runtime=challenge.runtime,
        entrypoint=challenge.entrypoint,
        source_bytes=source_bytes,
        mode=mode,
    )


def _dnaseq_challenge():
    return default_challenge_catalog().get(
        DNASEQ_SAFE_IR_CHALLENGE_ID,
        DNASEQ_SAFE_IR_CHALLENGE_VERSION,
    )


def _dnaseq_manifest(*, source_bytes: int = 128):
    challenge = _dnaseq_challenge()
    return SubmissionManifest(
        schema_version=1,
        challenge_manifest_hash=challenge.manifest_hash,
        candidate_kind=challenge.candidate_kind,
        runtime=challenge.runtime,
        entrypoint=challenge.entrypoint,
        source_bytes=source_bytes,
        mode=SubmissionMode.LEADERBOARD,
    )


def _commitment(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _submit(
    store: ArenaStore,
    label: str,
    *,
    wallet: str = WALLET_A,
    project_id: str = PROJECT_A,
    mode: SubmissionMode = SubmissionMode.LEADERBOARD,
    submitted_at: int = 100,
):
    return store.submit(
        challenge_id=BIO_CHALLENGE_ID,
        challenge_version=BIO_CHALLENGE_VERSION,
        identity=SubmissionIdentity(wallet, project_id),
        candidate_commitment=_commitment(label),
        encrypted_reference=f"sealed://candidates/{label}",
        manifest=_manifest(mode=mode),
        idempotency_key=f"request-{label}",
        submitted_at=submitted_at,
    )


def _submit_dnaseq(
    store: ArenaStore,
    label: str,
    *,
    submitted_at: int = 100,
):
    return store.submit(
        challenge_id=DNASEQ_SAFE_IR_CHALLENGE_ID,
        challenge_version=DNASEQ_SAFE_IR_CHALLENGE_VERSION,
        identity=SubmissionIdentity(WALLET_A, PROJECT_A),
        candidate_commitment=_commitment(label),
        encrypted_reference=f"sealed://candidates/{label}",
        manifest=_dnaseq_manifest(),
        idempotency_key=f"request-{label}",
        submitted_at=submitted_at,
    )


def _execution_provenance(
    *,
    manifest_hash: str | None = None,
    outcome: str = "completed",
) -> ExecutionProvenance:
    return ExecutionProvenance(
        outcome=outcome,
        runtime="dnai-safe-ir-v1",
        runtime_policy_commitment="sha256:" + "aa" * 32,
        challenge_manifest_hash=manifest_hash or _dnaseq_challenge().manifest_hash,
        compose_hash="bb" * 32,
        app_id="dnai-dnaseq-safe-ir",
        os_image_hash="cc" * 32,
        quote_sha256="sha256:" + "dd" * 32,
        verifier_address="0x" + "11" * 20,
        verdict_digest="0x" + "ee" * 32,
        tee_signer_address="0x" + "22" * 20,
        chain_id=84_532,
        challenge_registry_address="0x" + "33" * 20,
    )


def _advance_to_sealed_eval(store: ArenaStore, submission_id: str, *, start: int) -> None:
    transitions = (
        (QueueState.POLICY_SCREEN, QueueReason.POLICY_CHECK_STARTED),
        (QueueState.QUEUED, QueueReason.POLICY_PASSED),
        (QueueState.PROVISIONING, QueueReason.WORKER_CLAIMED),
        (QueueState.PUBLIC_TESTS, QueueReason.PUBLIC_TESTS_STARTED),
        (QueueState.SEALED_EVAL, QueueReason.SEALED_EVALUATION_STARTED),
    )
    for offset, (state, reason) in enumerate(transitions, start=1):
        store.transition_submission(
            submission_id,
            state,
            reason=reason,
            occurred_at=start + offset,
        )


def _assert_no_float(test: unittest.TestCase, value) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            test.assertIsInstance(key, str)
            _assert_no_float(test, child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_float(test, child)
    else:
        test.assertNotIsInstance(value, float)


def _assert_no_public_timing(test: unittest.TestCase, value) -> None:
    """Exact evaluator timing is internal state, never public Arena output."""

    forbidden = {"created_at", "updated_at", "occurred_at", "ladder_released_at"}
    if isinstance(value, dict):
        test.assertTrue(forbidden.isdisjoint(value))
        for child in value.values():
            _assert_no_public_timing(test, child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_public_timing(test, child)


class ArenaCatalogTest(unittest.TestCase):
    def test_default_catalog_has_modeled_python_preview_and_dnaseq_safe_ir(self):
        catalog = default_challenge_catalog().to_public_dict()

        self.assertEqual(
            set(catalog),
            {
                "surface",
                "schema_version",
                "challenge_count",
                "challenges",
                "product_status",
                "execution_assurance",
                "raw_secret_egress",
            },
        )
        self.assertEqual(catalog["schema_version"], 1)
        self.assertEqual(catalog["challenge_count"], 2)
        self.assertEqual(catalog["product_status"], PRODUCT_STATUS)
        self.assertEqual(catalog["execution_assurance"], EXECUTION_ASSURANCE)
        by_id = {item["challenge_id"]: item for item in catalog["challenges"]}
        manifest = by_id[BIO_CHALLENGE_ID]
        self.assertEqual(manifest["challenge_id"], BIO_CHALLENGE_ID)
        self.assertEqual(manifest["version"], BIO_CHALLENGE_VERSION)
        self.assertTrue(manifest["data_policy"]["synthetic_only"])
        self.assertFalse(manifest["data_policy"]["raw_data_egress"])
        self.assertFalse(manifest["evaluation"]["exact_reward_egress"])
        self.assertEqual(manifest["evaluation"]["release_mechanism"], "fixed_eta_ladder")
        self.assertEqual(manifest["product_status"], "modeled")
        self.assertEqual(
            manifest["execution_assurance"], "projection_only_no_hardened_executor"
        )
        capability = manifest["execution_capability"]
        self.assertEqual(capability["status"], "modeled")
        self.assertEqual(capability["isolation"], "non_hardened")
        self.assertFalse(capability["hostile_code_ready"])
        self.assertFalse(capability["live_execution"])
        self.assertFalse(capability["worker_connected"])
        self.assertIn("must not execute hostile public code", capability["warning"])
        safe_ir = by_id[DNASEQ_SAFE_IR_CHALLENGE_ID]
        self.assertEqual(safe_ir["challenge_id"], DNASEQ_SAFE_IR_CHALLENGE_ID)
        self.assertEqual(safe_ir["version"], DNASEQ_SAFE_IR_CHALLENGE_VERSION)
        self.assertEqual(safe_ir["title"], "DNASeq Variant QC · Safe IR")
        self.assertEqual(safe_ir["environment"], "synthetic_dnaseq_variant_qc")
        self.assertEqual(safe_ir["evaluation"]["metric"], "variant_quality_z_prime")
        self.assertEqual(safe_ir["candidate"]["runtime"], "dnai-safe-ir-v1")
        self.assertEqual(safe_ir["candidate"]["entrypoint"], "select_variant_evidence")
        self.assertEqual(
            safe_ir["manifest_hash"],
            "0812d8ab6cb26d60f1c28f6696773bd05a47e89fecc0ac6f28447ab0624f058f",
        )
        self.assertEqual(
            safe_ir["execution_capability"]["backend"],
            "dnai_safe_ir_v1_preview",
        )
        self.assertFalse(safe_ir["execution_capability"]["hostile_code_ready"])
        self.assertFalse(safe_ir["execution_capability"]["live_execution"])
        self.assertFalse(safe_ir["execution_capability"]["worker_connected"])
        self.assertIn("Execution remains disabled", safe_ir["execution_capability"]["warning"])
        self.assertIn("bases, reads", safe_ir["summary"])

    def test_execution_capability_cannot_claim_live_or_hardened(self):
        with self.assertRaisesRegex(ArenaStoreError, "must remain modeled"):
            ExecutionCapability(live_execution=True)
        with self.assertRaisesRegex(ArenaStoreError, "must remain modeled"):
            ExecutionCapability(isolation="hardened")

    def test_manifest_hash_is_stable_and_covers_execution_truth(self):
        a = _challenge()
        b = _challenge()
        self.assertEqual(a.manifest_hash, b.manifest_hash)
        self.assertRegex(a.manifest_hash, r"^[0-9a-f]{64}$")
        rendered = a.to_public_dict()
        self.assertEqual(rendered["manifest_hash"], a.manifest_hash)


class ArenaSubmissionBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "arena.json"
        self.store = ArenaStore(self.path)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_submission_persists_only_commitment_sealed_ref_and_bounded_manifest(self):
        result = _submit(self.store, "one")
        self.assertTrue(result.created)

        public = self.store.public_submission(result.submission.submission_id)
        owner = self.store.owner_submission(result.submission.submission_id)
        worker = self.store.worker_submission(result.submission.submission_id)
        persisted_text = self.path.read_text(encoding="utf-8")
        public_text = json.dumps(public, sort_keys=True)
        owner_text = json.dumps(owner, sort_keys=True)

        self.assertNotIn(WALLET_A, public_text)
        self.assertNotIn(WALLET_A[2:], public_text)
        self.assertNotIn(WALLET_A, owner_text)
        self.assertNotIn(WALLET_A[2:], owner_text)
        self.assertEqual(
            set(public["identity"]), {"wallet_address_hash", "project_id_hash"}
        )
        self.assertNotIn("encrypted_reference", public)
        self.assertFalse(public["encrypted_reference_public"])
        self.assertNotIn("encrypted_reference", owner)
        self.assertFalse(owner["encrypted_reference_egress"])
        self.assertFalse(owner["exact_score_egress"])
        self.assertFalse(owner["exact_reward_egress"])
        self.assertFalse(owner["internal_error_egress"])
        self.assertEqual(worker["encrypted_reference"], "sealed://candidates/one")
        self.assertEqual(public["product_status"], "modeled")
        self.assertEqual(public["execution_assurance"], EXECUTION_ASSURANCE)
        self.assertFalse(public["exact_timing_egress"])
        _assert_no_public_timing(self, public)
        _assert_no_public_timing(self, owner)
        self.assertIn(WALLET_A.lower(), persisted_text)
        self.assertIn("sealed://candidates/one", persisted_text)
        self.assertIn(_commitment("one"), persisted_text)
        self.assertNotIn("def process", persisted_text)
        self.assertIn('"raw_candidate_persisted":false', persisted_text)

    def test_identity_and_manifest_reject_unknown_plaintext_fields(self):
        with self.assertRaisesRegex(ArenaStoreError, "not allowlisted"):
            self.store.submit(
                challenge_id=BIO_CHALLENGE_ID,
                challenge_version=BIO_CHALLENGE_VERSION,
                identity={
                    "wallet_address": WALLET_A,
                    "project_id": PROJECT_A,
                    "display_name": "raw profile",
                },
                candidate_commitment=_commitment("bad-identity"),
                encrypted_reference="sealed://candidates/bad-identity",
                manifest=_manifest(),
                idempotency_key="request-bad-identity",
                submitted_at=100,
            )
        bad_manifest = _manifest().to_persisted_dict()
        bad_manifest["source"] = "def process(): pass"
        with self.assertRaisesRegex(ArenaStoreError, "not allowlisted"):
            self.store.submit(
                challenge_id=BIO_CHALLENGE_ID,
                challenge_version=BIO_CHALLENGE_VERSION,
                identity={"wallet_address": WALLET_A, "project_id": PROJECT_A},
                candidate_commitment=_commitment("bad-manifest"),
                encrypted_reference="sealed://candidates/bad-manifest",
                manifest=bad_manifest,
                idempotency_key="request-bad-manifest",
                submitted_at=100,
            )

    def test_owner_page_is_wallet_filtered_paginated_and_reference_free(self):
        newest = _submit(self.store, "owner-newest", submitted_at=103).submission
        middle = _submit(self.store, "owner-middle", submitted_at=102).submission
        oldest = _submit(self.store, "owner-oldest", submitted_at=101).submission
        outsider = _submit(
            self.store,
            "outsider",
            wallet=WALLET_B,
            project_id=PROJECT_B,
            submitted_at=104,
        ).submission

        first = self.store.owner_submissions(
            wallet_address=WALLET_A,
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            limit=2,
        )
        self.assertEqual(
            [item["submission_id"] for item in first["submissions"]],
            [newest.submission_id, middle.submission_id],
        )
        self.assertTrue(first["has_more"])
        self.assertEqual(first["next_cursor"], middle.submission_id)
        rendered = json.dumps(first, sort_keys=True)
        self.assertNotIn(WALLET_A, rendered)
        self.assertNotIn(WALLET_B, rendered)
        self.assertNotIn(outsider.submission_id, rendered)
        self.assertNotIn("sealed://", rendered)
        self.assertNotIn("encrypted_reference\"", rendered)
        self.assertNotIn("source_bytes", rendered)
        self.assertNotIn("queue_events", rendered)
        self.assertFalse(first["exact_score_egress"])
        self.assertFalse(first["exact_reward_egress"])
        self.assertFalse(first["exact_timing_egress"])
        self.assertFalse(first["internal_error_egress"])
        _assert_no_public_timing(self, first)

        second = self.store.owner_submissions(
            wallet_address="0x" + WALLET_A[2:].upper(),
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            limit=2,
            cursor=first["next_cursor"],
        )
        self.assertEqual(
            [item["submission_id"] for item in second["submissions"]],
            [oldest.submission_id],
        )
        self.assertFalse(second["has_more"])
        self.assertIsNone(second["next_cursor"])

        with self.assertRaisesRegex(ArenaStoreError, "outside this authenticated page"):
            self.store.owner_submissions(
                wallet_address=WALLET_A,
                challenge_id=BIO_CHALLENGE_ID,
                challenge_version=BIO_CHALLENGE_VERSION,
                cursor=outsider.submission_id,
            )
        with self.assertRaisesRegex(ArenaStoreError, "<= 100"):
            self.store.owner_submissions(
                wallet_address=WALLET_A,
                challenge_id=BIO_CHALLENGE_ID,
                challenge_version=BIO_CHALLENGE_VERSION,
                limit=101,
            )
    def test_commitment_and_manifest_are_strictly_bound_to_challenge(self):
        with self.assertRaisesRegex(ArenaStoreError, "sha256"):
            self.store.submit(
                challenge_id=BIO_CHALLENGE_ID,
                challenge_version=BIO_CHALLENGE_VERSION,
                identity=SubmissionIdentity(WALLET_A, PROJECT_A),
                candidate_commitment="plaintext program",
                encrypted_reference="sealed://candidates/bad-commitment",
                manifest=_manifest(),
                idempotency_key="request-bad-commitment",
                submitted_at=100,
            )
        mismatched = _manifest().to_persisted_dict()
        mismatched["challenge_manifest_hash"] = "0" * 64
        with self.assertRaisesRegex(ArenaStoreError, "does not match challenge"):
            self.store.submit(
                challenge_id=BIO_CHALLENGE_ID,
                challenge_version=BIO_CHALLENGE_VERSION,
                identity=SubmissionIdentity(WALLET_A, PROJECT_A),
                candidate_commitment=_commitment("mismatch"),
                encrypted_reference="sealed://candidates/mismatch",
                manifest=mismatched,
                idempotency_key="request-mismatch",
                submitted_at=100,
            )
    def test_source_size_limit_is_enforced(self):
        manifest = _manifest(source_bytes=_challenge().max_source_bytes + 1)
        with self.assertRaisesRegex(ArenaStoreError, "exceeds challenge"):
            self.store.submit(
                challenge_id=BIO_CHALLENGE_ID,
                challenge_version=BIO_CHALLENGE_VERSION,
                identity=SubmissionIdentity(WALLET_A, PROJECT_A),
                candidate_commitment=_commitment("oversized"),
                encrypted_reference="sealed://candidates/oversized",
                manifest=manifest,
                idempotency_key="request-oversized",
                submitted_at=100,
            )

    def test_encrypted_reference_rejects_signed_urls_and_path_tricks(self):
        bad_references = (
            "https://example.test/object",
            "r2://bucket/key?token=secret",
            "r2://bucket/key#fragment",
            "r2://user@bucket/key",
            "r2://bucket/key%2Fsecret",
            "r2://bucket/../secret",
            "r2://bucket//key",
            "sealed://single-segment",
            "sealed://bucket/key\nnext",
        )
        for index, reference in enumerate(bad_references):
            with self.subTest(reference=reference):
                with self.assertRaises(ArenaStoreError):
                    self.store.submit(
                        challenge_id=BIO_CHALLENGE_ID,
                        challenge_version=BIO_CHALLENGE_VERSION,
                        identity=SubmissionIdentity(WALLET_A, PROJECT_A),
                        candidate_commitment=_commitment(f"bad-ref-{index}"),
                        encrypted_reference=reference,
                        manifest=_manifest(),
                        idempotency_key=f"request-bad-ref-{index}",
                        submitted_at=100,
                    )

    def test_idempotency_replays_exact_request_and_conflicts_on_change(self):
        first = _submit(self.store, "idem")
        replay = _submit(self.store, "idem")
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(first.submission, replay.submission)
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn("request-idem", raw)
        self.assertIn('"key_hash"', raw)

        with self.assertRaises(ArenaIdempotencyConflict):
            self.store.submit(
                challenge_id=BIO_CHALLENGE_ID,
                challenge_version=BIO_CHALLENGE_VERSION,
                identity=SubmissionIdentity(WALLET_A, PROJECT_A),
                candidate_commitment=_commitment("changed"),
                encrypted_reference="sealed://candidates/changed",
                manifest=_manifest(),
                idempotency_key="request-idem",
                submitted_at=100,
            )

    def test_same_idempotency_text_is_scoped_to_identity(self):
        first = _submit(self.store, "scope", wallet=WALLET_A, project_id=PROJECT_A)
        second = self.store.submit(
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            identity=SubmissionIdentity(WALLET_B, PROJECT_B),
            candidate_commitment=_commitment("scope"),
            encrypted_reference="sealed://candidates/scope",
            manifest=_manifest(),
            idempotency_key="request-scope",
            submitted_at=100,
        )
        self.assertTrue(first.created)
        self.assertTrue(second.created)
        self.assertNotEqual(first.submission.submission_id, second.submission.submission_id)

    def test_concurrent_idempotent_submit_creates_one_record(self):
        def submit_once(_):
            return _submit(self.store, "threaded")

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(submit_once, range(24)))

        self.assertEqual(sum(result.created for result in results), 1)
        self.assertEqual(len({result.submission.submission_id for result in results}), 1)
        queue = self.store.public_queue(BIO_CHALLENGE_ID, BIO_CHALLENGE_VERSION)
        self.assertEqual(queue["submission_count"], 1)
        ArenaStore(self.path)  # A fresh loader sees one valid durable record.


class ArenaQueueAndLeaderboardTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "arena.json"
        self.store = ArenaStore(self.path)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_queue_transition_graph_reason_and_time_fail_closed(self):
        submission = _submit(self.store, "queue").submission
        with self.assertRaisesRegex(ArenaStoreError, "illegal"):
            self.store.transition_submission(
                submission.submission_id,
                QueueState.COMPLETED,
                reason=QueueReason.EVALUATION_COMPLETED,
                occurred_at=101,
            )
        with self.assertRaisesRegex(ArenaStoreError, "reason"):
            self.store.transition_submission(
                submission.submission_id,
                QueueState.POLICY_SCREEN,
                reason=QueueReason.WORKER_CLAIMED,
                occurred_at=101,
            )
        current = self.store.transition_submission(
            submission.submission_id,
            QueueState.POLICY_SCREEN,
            reason=QueueReason.POLICY_CHECK_STARTED,
            occurred_at=101,
        )
        with self.assertRaisesRegex(ArenaStoreError, "timestamp regressed"):
            self.store.transition_submission(
                submission.submission_id,
                QueueState.QUEUED,
                reason=QueueReason.POLICY_PASSED,
                occurred_at=99,
            )
        self.assertEqual(current.state, QueueState.POLICY_SCREEN)

    def test_leaderboard_mode_cannot_complete_without_ladder_release(self):
        submission = _submit(self.store, "no-release").submission
        _advance_to_sealed_eval(self.store, submission.submission_id, start=100)
        with self.assertRaisesRegex(ArenaStoreError, "without a bounded Ladder release"):
            self.store.transition_submission(
                submission.submission_id,
                QueueState.COMPLETED,
                reason=QueueReason.EVALUATION_COMPLETED,
                occurred_at=106,
            )

    def test_runtime_score_reduction_persists_only_ladder_release(self):
        first = _submit(self.store, "rank-a", submitted_at=100).submission
        _advance_to_sealed_eval(self.store, first.submission_id, start=100)
        release_one = self.store.evaluate_ladder_submission(
            first.submission_id, 0.7314159, occurred_at=106
        )
        self.assertTrue(release_one["accepted"])
        _assert_no_float(self, release_one)
        self.store.transition_submission(
            first.submission_id,
            QueueState.COMPLETED,
            reason=QueueReason.EVALUATION_COMPLETED,
            occurred_at=107,
        )

        second = _submit(
            self.store,
            "rank-b",
            wallet=WALLET_B,
            project_id=PROJECT_B,
            submitted_at=200,
        ).submission
        _advance_to_sealed_eval(self.store, second.submission_id, start=200)
        release_two = self.store.evaluate_ladder_submission(
            second.submission_id, 0.2, occurred_at=206
        )
        self.assertFalse(release_two["accepted"])
        self.assertEqual(
            release_two["leaderboard_step_index"],
            release_one["leaderboard_step_index"],
        )
        self.store.transition_submission(
            second.submission_id,
            QueueState.COMPLETED,
            reason=QueueReason.EVALUATION_COMPLETED,
            occurred_at=207,
        )

        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn("0.7314159", raw)
        self.assertNotIn('"internal_score"', raw)
        board = self.store.public_leaderboard(
            BIO_CHALLENGE_ID, BIO_CHALLENGE_VERSION
        )
        self.assertEqual(board["row_count"], 1)
        self.assertEqual(board["rows"][0]["submission_id"], first.submission_id)
        self.assertNotIn(WALLET_A, json.dumps(board))
        self.assertNotIn("sealed://", json.dumps(board))
        self.assertFalse(board["encrypted_reference_egress"])
        self.assertEqual(board["product_status"], PER_ROW_PRODUCT_STATUS)
        self.assertEqual(board["execution_assurance"], PER_ROW_EXECUTION_ASSURANCE)
        self.assertEqual(board["rows"][0]["product_status"], "modeled")
        self.assertEqual(
            board["rows"][0]["execution_assurance"], EXECUTION_ASSURANCE
        )
        self.assertEqual(
            board["rows"][0]["execution_provenance"]["status"],
            "not_executed",
        )
        self.assertFalse(board["exact_reward_egress"])
        self.assertFalse(board["exact_timing_egress"])
        _assert_no_public_timing(self, board)
        _assert_no_float(self, board)

        reloaded = ArenaStore(self.path)
        self.assertEqual(
            reloaded.public_leaderboard(BIO_CHALLENGE_ID, BIO_CHALLENGE_VERSION),
            board,
        )

    def test_record_ladder_release_validates_order_denominator_and_counters(self):
        submission = _submit(self.store, "strict-release").submission
        _advance_to_sealed_eval(self.store, submission.submission_id, start=100)
        malformed = (
            LadderRelease(2, True, 10, 20, 1),
            LadderRelease(1, True, 10, 10, 1),
            LadderRelease(1, True, -1, 20, 1),
            LadderRelease(1, False, 10, 20, 0),
        )
        for release in malformed:
            with self.subTest(release=release):
                with self.assertRaises(ArenaStoreError):
                    self.store.record_ladder_release(
                        submission.submission_id, release, occurred_at=106
                    )

        bounded = LadderLeaderboard(LadderPolicy(20, 32)).submit(0.7)
        updated = self.store.record_ladder_release(
            submission.submission_id, bounded, occurred_at=106
        )
        self.assertEqual(updated.ladder_release, bounded)
        replay = self.store.record_ladder_release(
            submission.submission_id, bounded, occurred_at=106
        )
        self.assertEqual(replay, updated)
        with self.assertRaisesRegex(ArenaStoreError, "different Ladder release"):
            self.store.record_ladder_release(
                submission.submission_id,
                LadderRelease(1, True, bounded.leaderboard_step_index + 1, 20, 1),
                occurred_at=106,
            )

    def test_dnaseq_worker_finalization_attaches_bounded_per_row_provenance(self):
        submission = _submit_dnaseq(self.store, "dnaseq-live").submission
        _advance_to_sealed_eval(self.store, submission.submission_id, start=100)
        self.store.evaluate_ladder_submission(
            submission.submission_id,
            0.81234,
            occurred_at=106,
        )
        self.store.finalize_safe_ir_execution(
            submission.submission_id,
            _execution_provenance(),
            occurred_at=107,
        )

        public = self.store.public_submission(submission.submission_id)
        evidence = public["execution_provenance"]
        self.assertEqual(public["schema_version"], 2)
        self.assertEqual(public["product_status"], "live")
        self.assertEqual(
            public["execution_assurance"],
            WORKER_REPORTED_EVIDENCE_CLASSIFICATION,
        )
        self.assertEqual(evidence["status"], "worker_reported")
        self.assertEqual(evidence["outcome"], "completed")
        self.assertEqual(evidence["runtime"], "dnai-safe-ir-v1")
        self.assertEqual(
            evidence["challenge_manifest_hash"],
            _dnaseq_challenge().manifest_hash,
        )
        self.assertFalse(evidence["independently_verified_by_client"])
        self.assertFalse(evidence["raw_tdx_quote_egress"])
        self.assertFalse(evidence["exact_score_egress"])
        self.assertFalse(evidence["exact_timing_egress"])
        rendered = json.dumps(public, sort_keys=True)
        self.assertNotIn('"quote"', rendered)
        self.assertNotIn('"signature"', rendered)
        self.assertNotIn("0.81234", self.path.read_text(encoding="utf-8"))

        board = self.store.public_leaderboard(
            DNASEQ_SAFE_IR_CHALLENGE_ID,
            DNASEQ_SAFE_IR_CHALLENGE_VERSION,
        )
        self.assertEqual(board["product_status"], PER_ROW_PRODUCT_STATUS)
        self.assertEqual(board["rows"][0]["product_status"], "live")
        self.assertEqual(board["rows"][0]["execution_provenance"], evidence)
        self.assertEqual(
            ArenaStore(self.path).public_submission(submission.submission_id),
            public,
        )

    def test_worker_provenance_cannot_upgrade_a_modeled_or_foreign_row(self):
        python_submission = _submit(self.store, "python-modeled").submission
        _advance_to_sealed_eval(
            self.store,
            python_submission.submission_id,
            start=100,
        )
        self.store.evaluate_ladder_submission(
            python_submission.submission_id,
            0.7,
            occurred_at=106,
        )
        with self.assertRaisesRegex(ArenaStoreError, "pinned DNASeq"):
            self.store.finalize_safe_ir_execution(
                python_submission.submission_id,
                _execution_provenance(),
                occurred_at=107,
            )
        self.store.transition_submission(
            python_submission.submission_id,
            QueueState.COMPLETED,
            reason=QueueReason.EVALUATION_COMPLETED,
            occurred_at=107,
        )
        modeled = self.store.public_submission(python_submission.submission_id)
        self.assertEqual(modeled["product_status"], "modeled")
        self.assertEqual(modeled["execution_provenance"]["status"], "not_executed")

        dnaseq = _submit_dnaseq(
            self.store,
            "foreign-manifest",
            submitted_at=200,
        ).submission
        _advance_to_sealed_eval(self.store, dnaseq.submission_id, start=200)
        self.store.evaluate_ladder_submission(
            dnaseq.submission_id,
            0.8,
            occurred_at=206,
        )
        with self.assertRaisesRegex(ArenaStoreError, "does not bind"):
            self.store.finalize_safe_ir_execution(
                dnaseq.submission_id,
                _execution_provenance(manifest_hash="ff" * 32),
                occurred_at=207,
            )
        unexecuted = self.store.public_submission(dnaseq.submission_id)
        self.assertEqual(unexecuted["product_status"], "modeled")
        self.assertEqual(
            unexecuted["execution_provenance"]["status"],
            "not_executed",
        )

    def test_public_queue_is_bounded_projection_not_execution_claim(self):
        _submit(self.store, "queue-public")
        queue = self.store.public_queue(BIO_CHALLENGE_ID, BIO_CHALLENGE_VERSION)
        rendered = json.dumps(queue, sort_keys=True)
        self.assertEqual(queue["product_status"], PER_ROW_PRODUCT_STATUS)
        self.assertEqual(queue["execution_assurance"], PER_ROW_EXECUTION_ASSURANCE)
        self.assertEqual(queue["submissions"][0]["product_status"], "modeled")
        self.assertEqual(
            queue["submissions"][0]["execution_provenance"]["status"],
            "not_executed",
        )
        self.assertEqual(queue["execution_capability"]["isolation"], "non_hardened")
        self.assertFalse(queue["execution_capability"]["live_execution"])
        self.assertNotIn(WALLET_A, rendered)
        self.assertNotIn("sealed://", rendered)
        self.assertFalse(queue["raw_candidate_egress"])
        self.assertFalse(queue["exact_timing_egress"])
        _assert_no_public_timing(self, queue)


class ArenaPersistenceTest(unittest.TestCase):
    def test_round_trip_preserves_owner_and_public_projections(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "arena.json"
            store = ArenaStore(path)
            submission = _submit(store, "round-trip").submission
            before_public = store.public_submission(submission.submission_id)
            before_owner = store.owner_submission(submission.submission_id)

            loaded = ArenaStore(path)

            self.assertEqual(loaded.public_submission(submission.submission_id), before_public)
            self.assertEqual(loaded.owner_submission(submission.submission_id), before_owner)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_atomic_write_failure_does_not_mutate_memory_or_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "arena.json"
            store = ArenaStore(path)
            original = path.read_bytes()
            with patch(
                "tinker_delegate.arena_store.os.replace",
                side_effect=OSError("simulated disk failure"),
            ):
                with self.assertRaises(OSError):
                    _submit(store, "atomic-failure")
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(
                store.public_queue(BIO_CHALLENGE_ID, BIO_CHALLENGE_VERSION)[
                    "submission_count"
                ],
                0,
            )
            recovered = _submit(store, "atomic-failure")
            self.assertTrue(recovered.created)

    def test_store_count_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ArenaStore(Path(directory) / "arena.json", max_submissions=1)
            _submit(store, "first")
            with self.assertRaisesRegex(ArenaStoreError, "store is full"):
                _submit(
                    store,
                    "second",
                    wallet=WALLET_B,
                    project_id=PROJECT_B,
                )

    def test_corrupt_malformed_duplicate_and_unknown_json_fail_closed(self):
        corrupt_documents = (
            b"not-json",
            b'{"surface":"arena_store","surface":"duplicate"}',
            b"{}",
            b'{"surface":"arena_store","schema_version":NaN}',
        )
        for document in corrupt_documents:
            with self.subTest(document=document[:40]):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "arena.json"
                    path.write_bytes(document)
                    with self.assertRaises(ArenaStoreCorruptError):
                        ArenaStore(path)

    def test_tampered_catalog_or_raw_candidate_marker_fails_closed(self):
        mutators = (
            lambda payload: payload.__setitem__("raw_candidate_persisted", True),
            lambda payload: payload["catalog"]["challenges"][0].__setitem__(
                "unexpected_live_claim", True
            ),
            lambda payload: payload["catalog"]["challenges"][0][
                "execution_capability"
            ].__setitem__("live_execution", True),
        )
        for mutator in mutators:
            with self.subTest(mutator=mutator):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "arena.json"
                    ArenaStore(path)
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    mutator(payload)
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaises(ArenaStoreCorruptError):
                        ArenaStore(path)

    def test_tampered_submission_or_idempotency_hash_fails_closed(self):
        mutators = (
            lambda payload: payload["submissions"][0].__setitem__(
                "candidate_source", "def process(): pass"
            ),
            lambda payload: payload["idempotency"][0].__setitem__(
                "request_hash", "0" * 64
            ),
            lambda payload: payload["submissions"][0].__setitem__(
                "raw_candidate_persisted", True
            ),
        )
        for mutator in mutators:
            with self.subTest(mutator=mutator):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "arena.json"
                    store = ArenaStore(path)
                    _submit(store, "tamper")
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    mutator(payload)
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaises(ArenaStoreCorruptError):
                        ArenaStore(path)


if __name__ == "__main__":
    unittest.main()
