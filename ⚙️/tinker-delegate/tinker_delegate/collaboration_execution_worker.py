"""Dedicated main-runtime worker for one-shot Collaboration execution.

This process has no provider, card, or wallet-token authority. It reads the
shared authenticated Collaboration, Compute, settlement, and ciphertext
stores, validates Base Sepolia at finalized heads, performs the dstack/QVL
dual-signing ceremony, and emits only an exact sponsor-wallet transaction.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, TextIO

from tinker_delegate import dstack_utils
from tinker_delegate.collaboration_execution import (
    CollaborationExecutionAuthorityInvalidated,
    CollaborationExecutionAuthorityUnavailable,
    CollaborationExecutionJournal,
)
from tinker_delegate.collaboration_royalty_settlement import (
    CollaborationRoyaltySettlementStore,
)
from tinker_delegate.collaboration_execution_evidence import (
    CollaborationExecutionWorkerHeartbeat,
    CollaborationExecutionWorkerHeartbeatStore,
    CollaborationExecutionWorkerReleaseBindings,
    collaboration_execution_worker_heartbeat_integrity_key,
    collaboration_execution_worker_release_bindings,
)
from tinker_delegate.collaboration_execution_service import (
    AuthenticatedComputeJournalReader,
    CollaborationExecutionCoordinator,
    CollaborationExecutionServiceUnavailable,
    CollaborationExecutionWorkerService,
    FinalizedComputeVaultReader,
    FinalizedRoyaltyAuthorityReader,
    collaboration_execution_integrity_key,
    royalty_release_binding_from_settings,
)
from tinker_delegate.compute_dispatch_admission import (
    ComputeDispatchAdmissionService,
)
from tinker_delegate.compute_runtime import (
    ComputeExecutionJournal,
    compute_execution_integrity_key,
)
from tinker_delegate.compute_workload_ingress import (
    build_compute_workload_ingress,
)
from tinker_delegate.config import Settings
from tinker_delegate.wallet_signature_verifier import (
    wallet_signature_verifier_from_settings,
)
from tinker_delegate.royalty_qvl_client import (
    ROYALTY_QVL_AUTH_TOKEN_ENV,
    AuthenticatedRoyaltyQvlCapabilityObservation,
    HttpsRoyaltySettlementQvlClient,
    RoyaltyQvlClientError,
)
from tinker_delegate.royalty_distribution_plan import DistributionRecipient
from tinker_delegate.royalty_settlement_authorization import (
    RoyaltySettlementIntent,
    RoyaltySettlementReleaseBinding,
    royalty_collaboration_resource_hash,
)


STATUS_SCHEMA = "dnai.collaboration.execution-worker-cycle.v1"


class CollaborationExecutionBootstrapError(RuntimeError):
    """The signed main-runtime worker configuration is incomplete."""


@dataclass
class CollaborationExecutionRuntime:
    worker: CollaborationExecutionWorkerService
    vault_reader: FinalizedComputeVaultReader
    heartbeat_store: CollaborationExecutionWorkerHeartbeatStore
    heartbeat_bindings: CollaborationExecutionWorkerReleaseBindings
    qvl_client: HttpsRoyaltySettlementQvlClient
    heartbeat_ttl_seconds: int
    settlement_store: CollaborationRoyaltySettlementStore | None = None
    policy_coordinator: Any | None = None
    royalty_release: RoyaltySettlementReleaseBinding | None = None
    qvl_observation: AuthenticatedRoyaltyQvlCapabilityObservation | None = None
    qvl_reachability: str = "configured_not_probed"
    qvl_last_probe_at: int = 0
    monotonic_clock: Callable[[], float] = time.monotonic

    def run_once(self, *, now: int) -> dict[str, Any]:
        """Advance Compute admission and one bounded Royalty action."""

        started = self.monotonic_clock()
        compute_cycle = self.worker.run_once(now=now)
        royalty_cycle = self.process_royalty_settlement_once(
            now=self._advancing_now(now, started)
        )
        return {
            "surface": "collaboration_execution_worker_cycle",
            "schema_version": 2,
            "compute": compute_cycle,
            "royalty_settlement": royalty_cycle,
            "provider_call_performed_by_collaboration": False,
            "automatic_provider_redispatch": False,
            "wallet_broadcast_performed_by_worker": False,
        }

    def process_royalty_settlement_once(self, *, now: int) -> dict[str, Any]:
        if (
            self.settlement_store is None
            or self.policy_coordinator is None
            or self.royalty_release is None
        ):
            raise CollaborationExecutionBootstrapError(
                "royalty_settlement_runtime_unavailable"
            )
        started = self.monotonic_clock()

        def validation_now() -> int:
            return self._advancing_now(now, started)

        reconciled = self._reconcile_royalty_settlement(
            now=validation_now()
        )
        request = self.settlement_store.claim_next(
            claimed_at=validation_now()
        )
        if request is None:
            return {
                "action": "settlement_reconciliation_only",
                "reconciliation": reconciled,
                "wallet_broadcast_performed_by_worker": False,
            }
        execution_id = request["execution_id"]
        try:
            source = self.worker.journal.royalty_settlement_source(
                execution_id
            )
            intent = source["intent"]
            reservation = source["funding_reservation"]
            result = source["bounded_result"]
            existing = self._recoverable_royalty_plan(
                source=source,
                request=request,
            )
            if existing is not None:
                resume_at = validation_now()
                wallet_plan, _snapshot = (
                    self.policy_coordinator.resume_royalty_settlement_anchor(
                        plan_commitment=existing.plan_commitment,
                        now=resume_at,
                    )
                )
                action = "settlement_plan_anchor_resumed"
            else:
                prepared_at = validation_now()
                prepared = self.qvl_client.prepare_attestation(
                    now=prepared_at
                )
                precondition_at = validation_now()
                finalized = self.worker.vault_reader.observe(
                    intent,
                    observed_at=precondition_at,
                )
                self.worker.royalty_reader.settlement_precondition(
                    self.royalty_release,
                    intent,
                    source["grants"],
                    finalized=finalized,
                    observed_at=precondition_at,
                )
                authorization_expiry = min(
                    prepared.challenge.expires_at,
                    reservation.refund_after,
                )
                authorization_checked_at = validation_now()
                if authorization_expiry - authorization_checked_at < 30:
                    raise CollaborationExecutionAuthorityInvalidated(
                        "Royalty reservation leaves no sponsor broadcast window"
                    )

                def intent_factory(chain_sequence: int) -> RoyaltySettlementIntent:
                    return RoyaltySettlementIntent(
                        settlement_id=reservation.settlement_id,
                        settlement_nonce=reservation.settlement_nonce,
                        royalty_reservation_id=reservation.reservation_id,
                        room_commitment=reservation.room_commitment,
                        room_state_commitment=(
                            reservation.room_state_commitment
                        ),
                        query_commitment=reservation.query_commitment,
                        grant_set_commitment=reservation.grant_set_commitment,
                        allocation_commitment=(
                            reservation.allocation_commitment
                        ),
                        owners_amounts_hash=reservation.owners_amounts_hash,
                        asset_address=reservation.asset,
                        total=reservation.total,
                        execution_commitment=reservation.execution_commitment,
                        result_commitment=_as_bytes32(
                            result.result_commitment
                        ),
                        usage_commitment=_as_bytes32(
                            result.usage_commitment
                        ),
                        anchor_sequence=chain_sequence,
                        expiry=authorization_expiry,
                    )

                recipients = tuple(
                    DistributionRecipient(
                        owner_address=owner,
                        amount=amount,
                    )
                    for owner, amount in source["owner_amounts"].items()
                )
                wallet_plan, _snapshot = (
                    self.policy_coordinator.prepare_and_anchor_royalty_settlement(
                        qvl_client=self.qvl_client,
                        prepared_attestation=prepared,
                        intent_factory=intent_factory,
                        recipients=recipients,
                        refund_after=reservation.refund_after,
                        recorded_at=authorization_checked_at,
                        replace_expired=request["replace_expired"],
                    )
                )
                action = "settlement_plan_dual_authorized_and_anchored"
            self.settlement_store.mark_plan_ready(
                execution_id=execution_id,
                generation=request["generation"],
                plan_commitment=wallet_plan.plan_commitment,
                authorization_expires_at=(
                    wallet_plan.authorized_plan.authorization_expires_at
                ),
                recorded_at=validation_now(),
            )
            return {
                "action": action,
                "execution_id": execution_id,
                "plan_commitment": wallet_plan.plan_commitment,
                "reconciliation": reconciled,
                "wallet_broadcast_performed_by_worker": False,
                "raw_quote_egress": False,
            }
        except CollaborationExecutionAuthorityInvalidated:
            self.settlement_store.mark_hold(
                execution_id=execution_id,
                generation=request["generation"],
                failure_code="settlement_authority_invalidated",
                retryable=False,
                recorded_at=validation_now(),
            )
            return {
                "action": "settlement_reconciliation_hold",
                "execution_id": execution_id,
                "retryable": False,
                "reconciliation": reconciled,
                "wallet_broadcast_performed_by_worker": False,
            }

        except CollaborationExecutionAuthorityUnavailable:
            self.settlement_store.defer_authorization(
                execution_id=execution_id,
                generation=request["generation"],
            )
            return {
                "action": "settlement_authority_temporarily_unavailable",
                "execution_id": execution_id,
                "retryable": True,
                "reconciliation": reconciled,
                "wallet_broadcast_performed_by_worker": False,
            }
        except RoyaltyQvlClientError as exc:
            if str(exc) in {
                "royalty_qvl_unavailable",
                "royalty_dstack_evidence_unavailable",
            }:
                self.settlement_store.defer_authorization(
                    execution_id=execution_id,
                    generation=request["generation"],
                )
                return {
                    "action": "settlement_authority_temporarily_unavailable",
                    "execution_id": execution_id,
                    "retryable": True,
                    "reconciliation": reconciled,
                    "wallet_broadcast_performed_by_worker": False,
                }
            self.settlement_store.mark_hold(
                execution_id=execution_id,
                generation=request["generation"],
                failure_code="settlement_qvl_authority_invalid",
                retryable=False,
                recorded_at=validation_now(),
            )
            return {
                "action": "settlement_reconciliation_hold",
                "execution_id": execution_id,
                "retryable": False,
                "reconciliation": reconciled,
                "wallet_broadcast_performed_by_worker": False,
            }

    def _advancing_now(self, initial_now: int, started: float) -> int:
        elapsed = max(0, int(self.monotonic_clock() - started))
        return initial_now + elapsed

    def _recoverable_royalty_plan(
        self,
        *,
        source: dict[str, Any],
        request: dict[str, Any],
    ) -> Any | None:
        intent = source["intent"]
        reservation = source["funding_reservation"]
        resource_hash = royalty_collaboration_resource_hash(
            chain_id=intent.chain_id,
            distributor_address=intent.royalty_distributor_address,
            room_commitment=reservation.room_commitment,
            query_commitment=reservation.query_commitment,
        )
        plan = self.policy_coordinator.store.latest_royalty_wallet_plan(
            anchor_resource_hash=resource_hash
        )
        if plan is None:
            return None
        authorization = plan.authorized_plan.authorization
        if authorization.expiry <= request["prepare_requested_at"]:
            return None
        expected = {
            "settlement_id": reservation.settlement_id,
            "settlement_nonce": reservation.settlement_nonce,
            "funding_reservation_id": reservation.reservation_id,
            "room_commitment": reservation.room_commitment,
            "room_state_commitment": reservation.room_state_commitment,
            "query_commitment": reservation.query_commitment,
            "grant_set_commitment": reservation.grant_set_commitment,
            "allocation_commitment": reservation.allocation_commitment,
            "owners_amounts_hash": reservation.owners_amounts_hash,
            "asset_address": reservation.asset,
            "total": reservation.total,
            "execution_commitment": reservation.execution_commitment,
            "result_commitment": _as_bytes32(
                source["bounded_result"].result_commitment
            ),
            "usage_commitment": _as_bytes32(
                source["bounded_result"].usage_commitment
            ),
        }
        if any(getattr(authorization, field) != value for field, value in expected.items()):
            return None
        return plan

    def _reconcile_royalty_settlement(self, *, now: int) -> dict[str, Any]:
        if self.settlement_store is None or self.royalty_release is None:
            raise CollaborationExecutionBootstrapError(
                "royalty_settlement_runtime_unavailable"
            )
        record = self.settlement_store.next_reconciliation()
        if record is None:
            return {"action": "no_settlement_plan_pending"}
        try:
            source = self.worker.journal.royalty_settlement_source(
                record["execution_id"]
            )
            reconciliation = self.worker.royalty_reader.reconcile_settlement(
                source["intent"],
                source["grants"],
                source["historical_royalty_observation"],
                observed_at=now,
            )
            finalized = reconciliation["finalized_settlement"]
            terminal_evidence = reconciliation.get("terminal_evidence")
            if reconciliation["state"] == "settled":
                if finalized is None:
                    raise CollaborationExecutionAuthorityInvalidated(
                        "settlement finality evidence is missing"
                    )
                self.settlement_store.mark_finalized(
                    execution_id=record["execution_id"],
                    generation=record["generation"],
                    finalized_settlement=finalized,
                    recorded_at=now,
                )
                return {
                    "action": "settlement_finalized",
                    "execution_id": record["execution_id"],
                    "source_commitment": finalized["source_commitment"],
                }
            if reconciliation["state"] == "refunded":
                if terminal_evidence is None:
                    raise CollaborationExecutionAuthorityInvalidated(
                        "refund finality evidence is missing"
                    )
                self.settlement_store.mark_refunded(
                    execution_id=record["execution_id"],
                    generation=record["generation"],
                    terminal_evidence=terminal_evidence,
                    recorded_at=now,
                )
                return {
                    "action": "settlement_reservation_refunded",
                    "execution_id": record["execution_id"],
                    "source_commitment": reconciliation[
                        "source_commitment"
                    ],
                }
            if reconciliation["state"] == "expired_unconsumed":
                if terminal_evidence is None:
                    raise CollaborationExecutionAuthorityInvalidated(
                        "reservation expiry evidence is missing"
                    )
                if (
                    record["state"] == "reservation_expired"
                ):
                    self.settlement_store.defer_reconciliation(
                        execution_id=record["execution_id"],
                        generation=record["generation"],
                    )
                else:
                    self.settlement_store.mark_reservation_expired(
                        execution_id=record["execution_id"],
                        generation=record["generation"],
                        terminal_evidence=terminal_evidence,
                        recorded_at=now,
                    )
                return {
                    "action": "settlement_reservation_expired",
                    "execution_id": record["execution_id"],
                    "source_commitment": reconciliation[
                        "source_commitment"
                    ],
                }
            # Expiry is authoritative only after the exact EIP-1898 read has
            # advanced past it while the reservation and both replay markers
            # remain untouched. Wall clock alone cannot close this race.
            if (
                record["authorization_expires_at"] is not None
                and reconciliation["block_timestamp"]
                > record["authorization_expires_at"]
            ):
                if (
                    record["state"] == "expired"
                    and record["failure_code"] == "authorization_expired"
                ):
                    self.settlement_store.defer_reconciliation(
                        execution_id=record["execution_id"],
                        generation=record["generation"],
                    )
                else:
                    self.settlement_store.mark_expired(
                        execution_id=record["execution_id"],
                        generation=record["generation"],
                        recorded_at=now,
                    )
                return {
                    "action": "settlement_authorization_expired",
                    "execution_id": record["execution_id"],
                }
            self.settlement_store.defer_reconciliation(
                execution_id=record["execution_id"],
                generation=record["generation"],
            )
            return {
                "action": "settlement_finality_pending",
                "execution_id": record["execution_id"],
            }
        except CollaborationExecutionAuthorityInvalidated:
            awaiting_refund = record["state"] == "reservation_expired"
            if awaiting_refund:
                self.settlement_store.defer_reconciliation(
                    execution_id=record["execution_id"],
                    generation=record["generation"],
                )
            else:
                self.settlement_store.mark_hold(
                    execution_id=record["execution_id"],
                    generation=record["generation"],
                    failure_code="settlement_finality_mismatch",
                    retryable=False,
                    recorded_at=now,
                )
            return {
                "action": (
                    "settlement_refund_reconciliation_mismatch"
                    if awaiting_refund
                    else "settlement_reconciliation_hold"
                ),
                "execution_id": record["execution_id"],
            }
        except CollaborationExecutionAuthorityUnavailable:
            self.settlement_store.defer_reconciliation(
                execution_id=record["execution_id"],
                generation=record["generation"],
            )
            return {
                "action": "settlement_finality_unavailable",
                "execution_id": record["execution_id"],
            }

    def write_heartbeat(self, *, observed_at: int, state: str) -> str:
        refresh_seconds = max(5, self.heartbeat_ttl_seconds // 2)
        observation = self.qvl_observation
        requires_probe = (
            observation is None
            or observed_at - observation.observed_at >= refresh_seconds
            or observation.challenge.expires_at <= observed_at + 5
        )
        # Bound retries during an outage while continuing to write an
        # authenticated unavailable heartbeat.  A previous observation is
        # cleared immediately after any failed refresh so stale capability can
        # never hide behind fresh worker presence.
        if requires_probe and (
            observation is not None
            or observed_at - self.qvl_last_probe_at >= 5
            or self.qvl_last_probe_at == 0
        ):
            self.qvl_last_probe_at = observed_at
            try:
                observation = self.qvl_client.probe_capability(
                    release_binding_sha256=(
                        self.heartbeat_bindings.royalty_release_binding_commitment
                    ),
                    now=observed_at,
                )
                self.qvl_observation = observation
                self.qvl_reachability = "authenticated_exact_capability"
            except RoyaltyQvlClientError as exc:
                self.qvl_observation = None
                observation = None
                self.qvl_reachability = (
                    "unreachable"
                    if str(exc) == "royalty_qvl_unavailable"
                    else "mismatch"
                )
        self.heartbeat_store.write(
            CollaborationExecutionWorkerHeartbeat(
                bindings=self.heartbeat_bindings,
                observed_at=observed_at,
                state=state,
                real_dstack=True,
                simulator=False,
                qvl_configuration="complete",
                qvl_reachability=self.qvl_reachability,
                qvl_capability_observation=observation,
            )
        )
        return self.qvl_reachability

    def close(self) -> None:
        try:
            self.qvl_client.close()
        finally:
            self.vault_reader.close()

    def __enter__(self) -> "CollaborationExecutionRuntime":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def build_collaboration_execution_runtime(
    settings: Settings,
) -> CollaborationExecutionRuntime:
    if (
        settings.collaboration_enabled is not True
        or settings.collaboration_execution_enabled is not True
    ):
        raise CollaborationExecutionBootstrapError(
            "collaboration_execution_profile_disabled"
        )
    if not dstack_utils.is_dstack_enabled() or dstack_utils.is_dstack_simulator():
        raise CollaborationExecutionBootstrapError("real_dstack_cvm_required")
    execution_path = str(settings.collaboration_execution_journal_path or "").strip()
    compute_path = str(settings.compute_dispatch_store_path or "").strip()
    collaboration_path = str(settings.collaboration_store_path or "").strip()
    heartbeat_path = str(
        settings.collaboration_execution_worker_heartbeat_path or ""
    ).strip()
    if (
        not execution_path
        or not compute_path
        or not collaboration_path
        or not heartbeat_path
    ):
        raise CollaborationExecutionBootstrapError(
            "shared_authenticated_store_paths_missing"
        )
    # Force construction of the complete canonical release before any journal
    # or RPC action. This is configuration binding only; claim-time RPC reads
    # still prove active/unpaused/pending-empty state.
    royalty_release = royalty_release_binding_from_settings(settings)

    try:
        execution_key = collaboration_execution_integrity_key(settings)
        execution_journal = CollaborationExecutionJournal(
            execution_path,
            integrity_key=execution_key,
        )
        compute_key = compute_execution_integrity_key(settings)
        compute_journal = ComputeExecutionJournal(
            compute_path,
            integrity_key=compute_key,
        )
        workload_ingress = build_compute_workload_ingress(settings)

        # Reuse the API's canonical anchored-store builder in this dedicated
        # process. Both Settings objects are loaded from the exact same signed
        # environment; no request or command-line field can replace it.
        from tinker_delegate import api as api_runtime

        if api_runtime.settings.model_dump() != settings.model_dump():
            raise CollaborationExecutionBootstrapError(
                "worker_and_delegate_settings_differ"
            )
        collaboration_store = api_runtime._get_collaboration_store()
        coordinator = CollaborationExecutionCoordinator(
            settings=settings,
            collaboration_store=collaboration_store,
            execution_journal=execution_journal,
            integrity_key=execution_key,
            signature_verifier=wallet_signature_verifier_from_settings(settings),
        )
        vault_reader = FinalizedComputeVaultReader(
            rpc_url=str(settings.compute_chain_rpc_url or ""),
            vault_address=settings.compute_vault_address,
            runtime_code_hash=settings.compute_vault_runtime_code_hash,
            receipt_key=execution_key,
            max_block_age_seconds=int(
                settings.compute_execution_max_block_age_seconds
            ),
            max_future_block_skew_seconds=int(
                settings.compute_execution_max_future_block_skew_seconds
            ),
        )
        royalty_reader = FinalizedRoyaltyAuthorityReader(
            vault_reader,
            receipt_key=execution_key,
        )
        worker = CollaborationExecutionWorkerService(
            coordinator=coordinator,
            journal=execution_journal,
            vault_reader=vault_reader,
            royalty_reader=royalty_reader,
            admission=ComputeDispatchAdmissionService(
                compute_journal,
                workload_ingress,
            ),
            compute_reader=AuthenticatedComputeJournalReader(
                compute_journal,
                integrity_key=compute_key,
            ),
        )
        heartbeat_store = CollaborationExecutionWorkerHeartbeatStore(
            heartbeat_path,
            integrity_key=(
                collaboration_execution_worker_heartbeat_integrity_key(
                    settings
                )
            ),
        )
        heartbeat_bindings = collaboration_execution_worker_release_bindings(
            settings
        )
        qvl_client = HttpsRoyaltySettlementQvlClient(
            qvl_url=str(settings.royalty_settlement_qvl_url or ""),
            auth_token=os.environ.get(ROYALTY_QVL_AUTH_TOKEN_ENV, ""),
            trusted_verdict_verifier_address=(
                settings.royalty_qvl_verdict_verifier_address
            ),
            release=royalty_release,
            max_verdict_age_seconds=(
                settings.royalty_qvl_max_verdict_age_seconds
            ),
            revoked_quote_hashes=tuple(
                json.loads(settings.royalty_qvl_revoked_quote_hashes_json)
            ),
        )
        return CollaborationExecutionRuntime(
            worker=worker,
            vault_reader=vault_reader,
            heartbeat_store=heartbeat_store,
            heartbeat_bindings=heartbeat_bindings,
            qvl_client=qvl_client,
            heartbeat_ttl_seconds=int(
                settings.collaboration_execution_worker_heartbeat_ttl_seconds
            ),
            settlement_store=(
                api_runtime._get_collaboration_royalty_settlement_store()
            ),
            policy_coordinator=(
                api_runtime._get_execution_policy_anchor_coordinator()
            ),
            royalty_release=royalty_release,
        )
    except CollaborationExecutionBootstrapError:
        raise
    except Exception as exc:
        raise CollaborationExecutionBootstrapError(
            "collaboration_execution_runtime_unavailable"
        ) from exc


def run(
    settings: Settings,
    *,
    once: bool,
    output: TextIO,
) -> int:
    poll = float(settings.collaboration_execution_poll_interval_seconds)
    try:
        with build_collaboration_execution_runtime(settings) as runtime:
            while True:
                now = int(time.time())
                try:
                    cycle = runtime.run_once(now=now)
                    heartbeat_now = max(now, int(time.time()))
                    qvl_reachability = runtime.write_heartbeat(
                        observed_at=heartbeat_now,
                        state="ready",
                    )
                    status = {
                        "schema": STATUS_SCHEMA,
                        "ok": True,
                        "observed_at": heartbeat_now,
                        "wallet_adoption_enabled": (
                            settings.compute_workload_wallet_adoption_enabled
                        ),
                        "provider_call_performed_by_collaboration": False,
                        "automatic_provider_redispatch": False,
                        "royalty_qvl_capability": (
                            "authenticated_exact_capability"
                            if qvl_reachability
                            == "authenticated_exact_capability"
                            else "unavailable"
                        ),
                        "cycle": cycle,
                    }
                    print(json.dumps(status, sort_keys=True), file=output, flush=True)
                except Exception:
                    failure_now = max(now, int(time.time()))
                    try:
                        runtime.write_heartbeat(
                            observed_at=failure_now,
                            state="unavailable",
                        )
                    except Exception:
                        pass
                    print(
                        json.dumps(
                            {
                                "schema": STATUS_SCHEMA,
                                "ok": False,
                                "observed_at": failure_now,
                                "reason": "collaboration_execution_cycle_unavailable",
                                "provider_call_performed_by_collaboration": False,
                                "automatic_provider_redispatch": False,
                            },
                            sort_keys=True,
                        ),
                        file=output,
                        flush=True,
                    )
                    if once:
                        return 1
                if once:
                    return 0
                time.sleep(poll)
    except (
        CollaborationExecutionBootstrapError,
        CollaborationExecutionServiceUnavailable,
    ):
        print(
            json.dumps(
                {
                    "schema": STATUS_SCHEMA,
                    "ok": False,
                    "reason": "collaboration_execution_bootstrap_unavailable",
                    "provider_call_performed_by_collaboration": False,
                },
                sort_keys=True,
            ),
            file=output,
            flush=True,
        )
        return 1


def _as_bytes32(value: str) -> str:
    """Normalize an internal sha256/bytes32 commitment for EIP-712 fields."""

    if not isinstance(value, str):
        raise CollaborationExecutionAuthorityInvalidated(
            "Royalty settlement commitment is unavailable"
        )
    if value.startswith("sha256:"):
        normalized = "0x" + value[7:]
    else:
        normalized = value
    if (
        len(normalized) != 66
        or not normalized.startswith("0x")
        or normalized == "0x" + "0" * 64
    ):
        raise CollaborationExecutionAuthorityInvalidated(
            "Royalty settlement commitment is invalid"
        )
    try:
        int(normalized[2:], 16)
    except ValueError:
        raise CollaborationExecutionAuthorityInvalidated(
            "Royalty settlement commitment is invalid"
        ) from None
    return normalized.lower()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the Collaboration-to-Compute admission worker"
    )
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    return run(Settings(), once=args.once, output=sys.stdout)


if __name__ == "__main__":
    raise SystemExit(main())
