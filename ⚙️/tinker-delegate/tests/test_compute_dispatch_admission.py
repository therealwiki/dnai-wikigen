import hashlib
import tempfile
import unittest
from pathlib import Path

from tinker_delegate.compute_dispatch_admission import (
    ComputeDispatchAdmissionService,
    compute_dispatch_claim_for_intent,
)
from tinker_delegate.compute_runtime import (
    ComputeDispatchIntent,
    ComputeExecutionJournal,
    ComputeRuntimePolicyError,
)
from tinker_delegate.compute_workload_ingress import (
    ComputeWorkloadDispatchClaim,
    ComputeWorkloadIngressService,
)


NOW = 1_800_000_000


def _intent(*, kind: str = "collaboration_one_shot", job: str = "job_alpha"):
    return ComputeDispatchIntent.create(
        project_reference="prj_alpha",
        job_reference=job,
        user="0x" + "11" * 20,
        asset="0x" + "00" * 20,
        authorization_nonce=7,
        max_asset_debit=123_456,
        authorization_expiry=NOW + 3_600,
        rate_policy_commitment="0x" + "44" * 32,
        compose_hash="0x" + "45" * 32,
        operation="inference",
        model="qwen3_8b",
        recipe="qwen3_8b_bounded",
        result_policy="bounded_summary_receipt",
        max_prefill_tokens=1_024,
        max_sample_tokens=128,
        max_train_tokens=0,
        workload_id="wrk_" + hashlib.sha256(job.encode("ascii")).hexdigest()[:32],
        workload_schema="dnai.compute.workload.inference.v1",
        manifest_commitment="0x" + "66" * 32,
        workload_commitment="0x" + "55" * 32,
        workload_source_kind="credential",
        workload_execution_binding_commitment="sha256:" + "77" * 32,
        workload_recipient_release_commitment="sha256:" + "88" * 32,
        authorization_kind=kind,
        authorization_context_commitment=(
            "sha256:" + "99" * 32 if kind == "collaboration_one_shot" else None
        ),
    )


class _ClaimingIngress(ComputeWorkloadIngressService):
    def __init__(self, journal: ComputeExecutionJournal) -> None:
        self.journal = journal
        self.claims: dict[str, ComputeWorkloadDispatchClaim] = {}
        self.calls = 0

    def claim_for_dispatch(self, workload_id: str, **fields):
        self.calls += 1
        current = self.journal.get(fields["job_id"])
        if current["stage"] != "workload_claim_pending":
            raise AssertionError("ingress claim was not journal-first")
        claim = ComputeWorkloadDispatchClaim(
            job_id=fields["job_id"],
            intent_commitment=fields["intent_commitment"],
            funding_wallet=fields["funding_wallet"],
            execution_binding_commitment=fields[
                "execution_binding_commitment"
            ],
        )
        existing = self.claims.get(workload_id)
        if existing is not None and existing != claim:
            raise AssertionError("test workload claim substitution")
        created = existing is None
        self.claims[workload_id] = claim
        return claim, created


class ComputeDispatchAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.journal = ComputeExecutionJournal(
            Path(self.temporary.name) / "dispatch.json",
            integrity_key=b"j" * 32,
        )
        self.ingress = _ClaimingIngress(self.journal)
        self.service = ComputeDispatchAdmissionService(
            self.journal,
            self.ingress,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_collaboration_admission_is_journal_first_exact_and_idempotent(self):
        intent = _intent()
        result = self.service.enqueue_collaboration_one_shot(
            intent,
            idempotency_key="chandoff_" + "ab" * 32,
            created_at=NOW,
        )
        self.assertTrue(result["created"])
        self.assertTrue(result["workload_claim_created"])
        self.assertTrue(result["workload_claim_confirmed"])
        self.assertEqual(result["intent"]["stage"], "intent_created")
        self.assertEqual(result["intent"]["authorization"]["kind"], "collaboration_one_shot")
        self.assertEqual(self.ingress.calls, 1)
        self.assertEqual(
            result["workload_claim_commitment"],
            compute_dispatch_claim_for_intent(intent).commitment,
        )

        replay = self.service.enqueue_collaboration_one_shot(
            intent,
            idempotency_key="chandoff_" + "ab" * 32,
            created_at=NOW + 1,
        )
        self.assertFalse(replay["created"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertFalse(replay["workload_claim_created"])
        self.assertEqual(self.ingress.calls, 1)

    def test_collaboration_method_rejects_standalone_and_expired_before_mutation(self):
        standalone = _intent(kind="standalone")
        with self.assertRaises(ComputeRuntimePolicyError):
            self.service.enqueue_collaboration_one_shot(
                standalone,
                idempotency_key="chandoff_" + "cd" * 32,
                created_at=NOW,
            )
        with self.assertRaises(ComputeRuntimePolicyError):
            self.service.enqueue_collaboration_one_shot(
                _intent(job="job_expired"),
                idempotency_key="chandoff_" + "ef" * 32,
                created_at=NOW + 3_600,
            )
        self.assertEqual(self.ingress.calls, 0)

    def test_recovers_both_journal_to_ingress_crash_windows_without_redispatch(self):
        before_ingress = _intent(job="job_before_ingress")
        self.journal.enqueue(
            before_ingress,
            idempotency_key="chandoff_" + "01" * 32,
            created_at=NOW,
        )
        recovered = self.service.enqueue_collaboration_one_shot(
            before_ingress,
            idempotency_key="chandoff_" + "01" * 32,
            created_at=NOW + 1,
        )
        self.assertFalse(recovered["created"])
        self.assertTrue(recovered["workload_claim_recovered"])

        after_ingress = _intent(job="job_after_ingress")
        self.journal.enqueue(
            after_ingress,
            idempotency_key="chandoff_" + "02" * 32,
            created_at=NOW + 2,
        )
        claim = compute_dispatch_claim_for_intent(after_ingress)
        self.ingress.claims[after_ingress.workload_id] = claim
        recovered = self.service.enqueue_collaboration_one_shot(
            after_ingress,
            idempotency_key="chandoff_" + "02" * 32,
            created_at=NOW + 3,
        )
        self.assertFalse(recovered["created"])
        self.assertTrue(recovered["workload_claim_recovered"])
        self.assertTrue(recovered["workload_claim_confirmed"])
        self.assertEqual(
            recovered["provider_dispatch_status"],
            "not_started",
        )


if __name__ == "__main__":
    unittest.main()
