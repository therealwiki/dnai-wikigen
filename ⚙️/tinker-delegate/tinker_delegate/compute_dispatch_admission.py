"""Journal-first admission for exact-asset Compute dispatch intents.

This is an in-process boundary shared by the standalone Compute API and the
Collaboration execution coordinator.  It owns no wallet or Collaboration
authorization: callers must construct and validate the exact intent before
admission.  The service only enforces the expected authorization kind and
atomically recovers the journal-to-ciphertext one-shot claim protocol.
"""

from __future__ import annotations

import hmac
from typing import Any

from tinker_delegate.compute_runtime import (
    ComputeDispatchIntent,
    ComputeExecutionJournal,
    ComputeIntentConflict,
    ComputeRuntimePolicyError,
)
from tinker_delegate.compute_workload_ingress import (
    ComputeWorkloadDispatchClaim,
    ComputeWorkloadIngressService,
)


def compute_dispatch_claim_for_intent(
    intent: ComputeDispatchIntent,
) -> ComputeWorkloadDispatchClaim:
    """Construct the only local ciphertext claim valid for intent v3."""

    if not isinstance(intent, ComputeDispatchIntent):
        raise ComputeRuntimePolicyError("Compute dispatch intent is required")
    return ComputeWorkloadDispatchClaim(
        job_id=intent.job_id,
        intent_commitment=intent.commitment,
        funding_wallet=intent.user,
        execution_binding_commitment=(
            intent.workload_execution_binding_commitment
        ),
    )


class ComputeDispatchAdmissionService:
    """Admit one exact intent and confirm its at-most-once workload claim."""

    def __init__(
        self,
        journal: ComputeExecutionJournal,
        ingress: ComputeWorkloadIngressService,
    ) -> None:
        if not isinstance(journal, ComputeExecutionJournal):
            raise ComputeRuntimePolicyError("Compute execution journal is required")
        if not callable(getattr(ingress, "claim_for_dispatch", None)):
            raise ComputeRuntimePolicyError("Compute workload ingress is required")
        self.journal = journal
        self.ingress = ingress

    def enqueue_standalone(
        self,
        intent: ComputeDispatchIntent,
        *,
        idempotency_key: str,
        created_at: int,
    ) -> dict[str, Any]:
        """Admit the public wallet flow without accepting a caller-selected kind."""

        return self._enqueue_exact_kind(
            intent,
            expected_kind="standalone",
            idempotency_key=idempotency_key,
            created_at=created_at,
        )

    def enqueue_collaboration_one_shot(
        self,
        intent: ComputeDispatchIntent,
        *,
        idempotency_key: str,
        created_at: int,
    ) -> dict[str, Any]:
        """Admit a preauthorized Collaboration plan after its funding claim.

        Collaboration must validate its Basis, complete fresh owner-grant set,
        current release/room state, and finalized vault observation under its
        own claim lock before this method is called.  This method deliberately
        does not reconstruct or re-read Collaboration state and never invokes
        a provider.
        """

        return self._enqueue_exact_kind(
            intent,
            expected_kind="collaboration_one_shot",
            idempotency_key=idempotency_key,
            created_at=created_at,
        )

    def _enqueue_exact_kind(
        self,
        intent: ComputeDispatchIntent,
        *,
        expected_kind: str,
        idempotency_key: str,
        created_at: int,
    ) -> dict[str, Any]:
        if not isinstance(intent, ComputeDispatchIntent):
            raise ComputeRuntimePolicyError("Compute dispatch intent is required")
        if intent.authorization_kind != expected_kind:
            raise ComputeRuntimePolicyError(
                f"Compute dispatch admission requires {expected_kind} authorization"
            )
        if created_at >= intent.authorization_expiry:
            raise ComputeRuntimePolicyError(
                "Compute dispatch authorization expired before admission"
            )
        _pending, created = self.journal.enqueue(
            intent,
            idempotency_key=idempotency_key,
            created_at=created_at,
        )
        record, claim, claim_created, claim_confirmed = self.recover_workload_claim(
            intent,
            updated_at=created_at,
        )
        return {
            "surface": "compute_dispatch_intent_result",
            "schema_version": 3,
            "created": created,
            "idempotent_replay": not created,
            "workload_claim_created": claim_created,
            "workload_claim_confirmed": record["workload_claim_confirmed"],
            "workload_claim_recovered": (
                not created and (claim_created or claim_confirmed)
            ),
            "workload_claim_commitment": claim.commitment,
            "intent": record,
            "legacy_credit_ledger_mutated": False,
            "provider_dispatch_status": record["provider_dispatch_status"],
            "provider_dispatch_may_have_occurred": record[
                "provider_dispatch_may_have_occurred"
            ],
            "provider_authoritative": False,
        }

    def recover_workload_claim(
        self,
        intent: ComputeDispatchIntent,
        *,
        updated_at: int,
    ) -> tuple[dict[str, Any], ComputeWorkloadDispatchClaim, bool, bool]:
        current = self.journal.get(intent.job_id)
        claim = compute_dispatch_claim_for_intent(intent)
        if current["workload_claim_commitment"] is not None:
            if not hmac.compare_digest(
                current["workload_claim_commitment"], claim.commitment
            ):
                raise ComputeIntentConflict(
                    "workload dispatch claim commitment does not match"
                )
            return self.journal.public_get(intent.job_id), claim, False, False
        if current["stage"] != "workload_claim_pending":
            raise ComputeIntentConflict(
                "dispatch intent does not have a recoverable workload claim"
            )
        claimed, claim_created = self.ingress.claim_for_dispatch(
            intent.workload_id,
            project_id=intent.project_reference,
            job_id=intent.job_id,
            intent_commitment=intent.commitment,
            funding_wallet=intent.user,
            source_kind=intent.workload_source_kind,
            execution_binding_commitment=(
                intent.workload_execution_binding_commitment
            ),
            recipient_release_commitment=(
                intent.workload_recipient_release_commitment
            ),
        )
        if claimed != claim or not hmac.compare_digest(
            claimed.commitment, claim.commitment
        ):
            raise ComputeIntentConflict(
                "workload dispatch claim does not match intent"
            )
        record, claim_confirmed = self.journal.confirm_workload_claim(
            intent.job_id,
            claim_commitment=claim.commitment,
            updated_at=updated_at,
        )
        return record, claim, claim_created, claim_confirmed
