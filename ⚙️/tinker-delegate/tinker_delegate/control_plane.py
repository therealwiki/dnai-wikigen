"""Control Plane — orchestrates deal lifecycle inside the TEE.

Responsibilities:
  1. Session factory — creates IsolatedTinkerSession per deal
  2. Artifact ingress — receives artifact payloads, holds in memory
  3. Agent orchestration — runs evaluator with session + artifact
  4. Output bounding — maps raw metrics to score bands
  5. Cleanup — destroys sessions on deal resolution
  6. Orphan cleanup — scans for leaked sessions on boot

The control plane does NOT watch the chain directly — that's the
on-chain watcher's job. The control plane exposes an internal API
that the watcher calls when events occur.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

import tinker

from tinker_delegate.artifacts import verify_artifact_hash, zero_buffer
from tinker_delegate.cost_metering import reconcile_costs
from tinker_delegate.destruction_record import DestructionEvidence, build_destruction_record
from tinker_delegate.dstack_utils import get_attestation, is_dstack_enabled
from tinker_delegate.retention_policy import (
    RetentionAction,
    RetentionMode,
    RetentionPolicy,
    evaluate_retention,
)
from tinker_delegate.sealed_retention import SealedRetentionStore
from tinker_delegate.source_controller import SourceControllerRegistry


class SourceAccessDenied(PermissionError):
    """Raised when the TEE-held source account is not authorized for use."""
from tinker_delegate.run_metadata_store import (
    make_run_metadata_event,
    size_band,
    stable_hash,
    value_band,
)
from tinker_delegate.session import CleanupAttestation, IsolatedTinkerSession


# ---------------------------------------------------------------------------
# Output bounding
# ---------------------------------------------------------------------------

class ScoreBand(str, Enum):
    EXCEPTIONAL = "exceptional"   # >20% improvement
    HIGH = "high"                 # 10-20%
    MEDIUM = "medium"             # 5-10%
    LOW = "low"                   # 1-5%
    NEGLIGIBLE = "negligible"     # <1%


def bound_output(raw_delta: float) -> ScoreBand:
    """Map exact quality delta to a coarse score band.

    This prevents the buyer from learning the exact improvement,
    preserving the seller's information advantage.
    """
    if raw_delta >= 0.20:
        return ScoreBand.EXCEPTIONAL
    if raw_delta >= 0.10:
        return ScoreBand.HIGH
    if raw_delta >= 0.05:
        return ScoreBand.MEDIUM
    if raw_delta >= 0.01:
        return ScoreBand.LOW
    return ScoreBand.NEGLIGIBLE


def compute_offer(band: ScoreBand, budget_cap: int, reserve_price: int) -> int:
    """Compute offer price from score band and budget constraints.

    The offer is derived from the band, not the raw delta.
    This prevents reverse-engineering exact quality from price.
    """
    band_multipliers = {
        ScoreBand.EXCEPTIONAL: 0.90,
        ScoreBand.HIGH: 0.70,
        ScoreBand.MEDIUM: 0.50,
        ScoreBand.LOW: 0.30,
        ScoreBand.NEGLIGIBLE: 0.0,
    }
    multiplier = band_multipliers[band]
    offer = int(budget_cap * multiplier)

    # Clamp to reserve price
    if offer < reserve_price and band != ScoreBand.NEGLIGIBLE:
        offer = reserve_price

    return min(offer, budget_cap)


# ---------------------------------------------------------------------------
# Evaluation result (the only thing that leaves the TEE)
# ---------------------------------------------------------------------------

@dataclass
class EvaluationResult:
    """Bounded output — the only thing that leaves the TEE."""
    deal_id: str
    score_band: ScoreBand
    quality_delta: str          # banded, e.g. "+10-15% on benchmark X"
    offer_price: int            # in wei, within buyer's budget cap
    recommendation: str         # "accept" | "reject"
    confidence: str             # "high" | "medium" | "low"
    methodology_summary: str
    compute_cost_wei: int
    fee_wei: int
    tdx_quote: bytes = b""     # TDX attestation binding this result
    settlement_safe: bool = True       # cost reconciliation passed
    reconciliation_status: str = "reconciled"


# ---------------------------------------------------------------------------
# Deal state
# ---------------------------------------------------------------------------

class DealState(str, Enum):
    PENDING_ARTIFACT = "pending_artifact"
    EVALUATING = "evaluating"
    EVALUATED = "evaluated"
    RESOLVED = "resolved"


@dataclass
class DealContext:
    """State for an active deal inside the TEE."""
    deal_id: str
    buyer: str
    seller: str
    budget_cap: int       # wei
    reserve_price: int    # wei
    state: DealState = DealState.PENDING_ARTIFACT
    session: Optional[IsolatedTinkerSession] = None
    artifact: Optional[bytearray] = None
    artifact_hash: str = ""
    result: Optional[EvaluationResult] = None
    cleanup_attestation: Optional[CleanupAttestation] = None
    destruction_record: Optional[dict] = None
    retention_decision: Optional[dict] = None
    created_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Control plane
# ---------------------------------------------------------------------------

class ControlPlane:
    """Orchestrates deal lifecycle inside the TEE."""

    def __init__(
        self,
        tinker_api_key: str,
        run_metadata_store=None,
        project_id: str = "",
        base_url: str = "",
        service_client_factory: Callable[..., Any] | None = None,
        retention_policy: RetentionPolicy | None = None,
        retention_store: SealedRetentionStore | None = None,
        source_registry: SourceControllerRegistry | None = None,
        source_ref: str = "source://tinker-account",
        source_scope: str = "tinker_compute",
    ):
        self._api_key = tinker_api_key
        self._project_id = project_id
        self._base_url = base_url
        self._service_client_factory = service_client_factory
        self._deals: dict[str, DealContext] = {}
        self._run_metadata_store = run_metadata_store
        # Default: immediate destruction on resolution (safest data-locality).
        self._retention_policy = retention_policy or RetentionPolicy(RetentionMode.IMMEDIATE)
        self._retention_store = retention_store
        # Optional source-custody gate: when a registry is configured, the
        # TEE-held source account can only be used while a valid, non-self-approved
        # grant for `source_scope` is active.
        self._source_registry = source_registry
        self._source_ref = source_ref
        self._source_scope = source_scope

    def _create_service_client(self) -> Any:
        """Create a Tinker ServiceClient with the sealed API key."""
        kwargs = {"api_key": self._api_key}
        if self._project_id:
            kwargs["project_id"] = self._project_id
        if self._base_url:
            kwargs["base_url"] = self._base_url
        if self._service_client_factory is not None:
            return self._service_client_factory(**kwargs)
        return tinker.ServiceClient(**kwargs)

    def _authorize_source_use(self) -> None:
        """Fail closed unless the source account is authorized for the scope."""
        registry = getattr(self, "_source_registry", None)
        if registry is None:
            return
        source_ref = getattr(self, "_source_ref", "source://tinker-account")
        scope = getattr(self, "_source_scope", "tinker_compute")
        auth = registry.authorize(source_ref, scope, now=int(time.time()))
        if not auth.allowed:
            raise SourceAccessDenied(f"source access denied: {auth.reason_code}")

    # --- Deal lifecycle ---

    def on_deal_funded(
        self,
        deal_id: str,
        buyer: str,
        seller: str,
        budget_cap: int,
        reserve_price: int,
    ) -> DealContext:
        """Called when a deal is funded on-chain. Creates session."""
        self._authorize_source_use()
        sc = self._create_service_client()
        session = IsolatedTinkerSession(sc, deal_id)

        ctx = DealContext(
            deal_id=deal_id,
            buyer=buyer,
            seller=seller,
            budget_cap=budget_cap,
            reserve_price=reserve_price,
            session=session,
        )
        self._deals[deal_id] = ctx
        self._append_run_metadata(
            make_run_metadata_event(
                "deal_funded",
                deal_id,
                buyer_hash=stable_hash(buyer, prefix="buyer"),
                seller_hash=stable_hash(seller, prefix="seller"),
                budget_cap_band=value_band(budget_cap),
                reserve_price_band=value_band(reserve_price),
            )
        )
        return ctx

    def receive_artifact(
        self,
        deal_id: str,
        artifact: bytes | bytearray,
        artifact_hash: str,
    ) -> None:
        """Receive seller's artifact after verifying its committed hash."""
        ctx = self._deals[deal_id]
        assert ctx.state == DealState.PENDING_ARTIFACT
        ctx.artifact_hash = verify_artifact_hash(artifact, artifact_hash)
        ctx.artifact = bytearray(artifact)
        self._append_run_metadata(
            make_run_metadata_event(
                "artifact_received",
                deal_id,
                artifact_hash=ctx.artifact_hash,
                artifact_size_band=size_band(len(artifact)),
            )
        )
        # Ready for evaluation — but don't auto-start.
        # The watcher or API triggers evaluate().

    async def evaluate(
        self,
        deal_id: str,
        evaluator_fn,
    ) -> EvaluationResult:
        """Run the evaluator agent on a funded deal.

        evaluator_fn signature:
            async def evaluate(
                artifact: bytes,
                artifact_type: str,
                session: IsolatedTinkerSession,
                budget_cap: int,
                reserve_price: int,
            ) -> dict  # raw metrics from the agent
        """
        ctx = self._deals[deal_id]
        assert ctx.artifact is not None, "No artifact uploaded"
        assert ctx.session is not None, "No session"

        ctx.state = DealState.EVALUATING

        try:
            raw = await evaluator_fn(
                artifact=bytes(ctx.artifact),
                artifact_type="dataset",  # TODO: detect from artifact
                session=ctx.session,
                budget_cap=ctx.budget_cap,
                reserve_price=ctx.reserve_price,
            )

            # Bound the output
            raw_delta = raw.get("quality_delta", 0.0)
            band = bound_output(raw_delta)
            offer = compute_offer(band, ctx.budget_cap, ctx.reserve_price)
            recommendation = "accept" if band.value in ("exceptional", "high", "medium") else "reject"

            # Fail-closed cost reconciliation before this result can settle. The
            # on-chain constraint is offer + computeCost + fee <= budgetCap; we
            # check the developer charge (compute + fee) against the budget
            # headroom left after the seller offer, so an over-budget or
            # over-metered charge is caught in the TEE instead of reverting on
            # chain. Estimate == chain here (both from the meter); a real Tinker
            # backend would feed reported_cost separately.
            compute_cost_wei = ctx.session.compute_cost_wei
            fee_wei = ctx.session.fee_wei
            developer_charge = compute_cost_wei + fee_wei
            reconciliation = reconcile_costs(
                model=getattr(ctx.session, "model", "") or "unknown",
                estimated_cost_wei=developer_charge,
                chain_compute_cost_wei=developer_charge,
                budget_cap_wei=max(0, ctx.budget_cap - offer),
                fee_wei=fee_wei,
            )
            if not reconciliation.settlement_safe:
                # Cannot settle within budget — refuse to recommend acceptance.
                recommendation = "reject"

            # Build bounded result
            result = EvaluationResult(
                deal_id=deal_id,
                score_band=band,
                quality_delta=self._band_description(band, raw.get("benchmark", "unknown")),
                offer_price=offer,
                recommendation=recommendation,
                confidence=raw.get("confidence", "medium"),
                methodology_summary=raw.get("methodology", "LoRA fine-tune + benchmark evaluation"),
                compute_cost_wei=compute_cost_wei,
                fee_wei=fee_wei,
                settlement_safe=reconciliation.settlement_safe,
                reconciliation_status=reconciliation.status.value,
            )

            # Attach TDX attestation
            result.tdx_quote = self._get_tdx_quote(deal_id, result)

            ctx.result = result
            ctx.state = DealState.EVALUATED
            self._append_run_metadata(
                make_run_metadata_event(
                    "evaluation_completed",
                    deal_id,
                    score_band=result.score_band.value,
                    offer_price_band=value_band(result.offer_price),
                    recommendation=result.recommendation,
                    confidence=result.confidence,
                    compute_cost_band=value_band(result.compute_cost_wei),
                    fee_band=value_band(result.fee_wei),
                    settlement_safe=result.settlement_safe,
                    reconciliation_status=result.reconciliation_status,
                    tdx_quote_hash=stable_hash(result.tdx_quote, prefix="tdx_quote"),
                    training_run_id_hash=stable_hash(
                        getattr(ctx.session, "training_run_id", None),
                        prefix="training_run_id",
                    ),
                )
            )
            return result

        except Exception:
            # Cleanup on failure
            if ctx.session:
                ctx.cleanup_attestation = ctx.session.cleanup()
            ctx.state = DealState.RESOLVED
            self._append_run_metadata(
                make_run_metadata_event(
                    "evaluation_failed",
                    deal_id,
                    **self._cleanup_metadata_fields(ctx.cleanup_attestation),
                )
            )
            raise

    def on_deal_resolved(self, deal_id: str) -> None:
        """Called on ANY deal resolution (accept/reject/expire).

        Cleans up the session and discards the artifact.
        """
        ctx = self._deals.get(deal_id)
        if ctx is None:
            return

        resolved_at = int(time.time())
        policy = getattr(self, "_retention_policy", None) or RetentionPolicy(RetentionMode.IMMEDIATE)
        store = getattr(self, "_retention_store", None)
        decision = evaluate_retention(policy, settled_at=resolved_at, now=resolved_at)
        ctx.retention_decision = decision.to_public_dict()

        if ctx.session:
            ctx.cleanup_attestation = ctx.session.cleanup()

        had_artifact = ctx.artifact is not None
        retain = decision.action in (RetentionAction.RETAIN_SEALED, RetentionAction.ARCHIVE_ENCRYPTED)
        sealed_retained = False

        if retain and store is not None and ctx.artifact is not None:
            # Honor the retention decision: seal the artifact under the retention
            # key, then zero the plaintext buffer. Destruction happens later on
            # sweep_retention() once the window expires.
            store.seal(
                deal_id,
                bytes(ctx.artifact),
                retain_until=decision.retain_until,
                artifact_hash=ctx.artifact_hash or "",
                # Scope the key hierarchy per data owner: each seller's retained
                # corpus derives under its own key branch, not one shared key.
                corpus_ref=getattr(ctx, "seller", "") or "",
            )
            sealed_retained = True
            zero_buffer(ctx.artifact)
            ctx.artifact = None
        else:
            # Fail-closed default: destroy now (no store, or a destroy decision).
            if ctx.artifact:
                zero_buffer(ctx.artifact)
                ctx.artifact = None

        att = ctx.cleanup_attestation
        checkpoints_deleted = getattr(att, "deleted_checkpoint_count", 0) if att else 0
        fields: dict[str, Any] = {
            "retention_action": decision.action.value,
            "artifact_sealed_retained": sealed_retained,
        }
        if not sealed_retained:
            record = build_destruction_record(
                DestructionEvidence(
                    deal_ref=deal_id,
                    artifact_hash=ctx.artifact_hash,
                    artifact_deleted=True,   # no raw artifact remains
                    memory_zeroed=True,
                    keys_dropped=0,
                    checkpoints_deleted=checkpoints_deleted,
                    checkpoints_expired=0,
                    require_artifact_delete=had_artifact,
                ),
                at=resolved_at,
            )
            ctx.destruction_record = record.to_public_dict()
            fields["destruction_complete"] = record.complete
            fields["destruction_record_hash"] = record.record_hash

        ctx.state = DealState.RESOLVED
        self._append_run_metadata(
            make_run_metadata_event(
                "deal_resolved",
                deal_id,
                **fields,
                **self._cleanup_metadata_fields(ctx.cleanup_attestation),
            )
        )

    def sweep_retention(self, now: int | None = None) -> list[dict]:
        """Destroy expired sealed artifacts and emit attested destruction records.

        Returns the bounded destruction records for each swept deal. Safe to call
        periodically; a no-op when no retention store is configured.
        """
        store = getattr(self, "_retention_store", None)
        if store is None:
            return []
        swept_at = int(time.time()) if now is None else int(now)
        records: list[dict] = []
        for deal_id in store.sweep(swept_at):
            record = build_destruction_record(
                DestructionEvidence(
                    deal_ref=deal_id,
                    artifact_deleted=True,
                    memory_zeroed=True,
                    require_artifact_delete=True,
                ),
                at=swept_at,
            )
            ctx = self._deals.get(deal_id)
            if ctx is not None:
                ctx.destruction_record = record.to_public_dict()
            records.append(record.to_public_dict())
            self._append_run_metadata(
                make_run_metadata_event(
                    "retention_swept",
                    deal_id,
                    destruction_complete=record.complete,
                    destruction_record_hash=record.record_hash,
                )
            )
        return records

    def on_chain_event(
        self,
        event: str,
        deal_id: str,
        *,
        block_number: int | None = None,
        tx_hash: str = "",
        log_index: int | None = None,
        fields: dict[str, Any] | None = None,
    ) -> None:
        """Persist a bounded audit marker for a DiligenceRoom chain event."""
        event_fields = fields or {}
        metadata: dict[str, Any] = {"chain_event_name": event}
        if block_number is not None:
            metadata["chain_block_band"] = value_band(block_number)
        if log_index is not None:
            metadata["chain_log_index_band"] = value_band(log_index)
        if tx_hash:
            metadata["chain_tx_hash"] = stable_hash(tx_hash, prefix="chain_tx")

        address_fields = {
            "buyer": ("buyer_hash", "buyer"),
            "seller": ("seller_hash", "seller"),
            "tee_identity": ("tee_identity_hash", "tee_identity"),
        }
        for source, (target, prefix) in address_fields.items():
            value = event_fields.get(source)
            if value:
                metadata[target] = stable_hash(value, prefix=prefix)

        value_fields = {
            "budget_cap": "budget_cap_band",
            "reserve_price": "reserve_price_band",
            "expiry": "expiry_band",
            "compute_cost": "compute_cost_band",
            "seller_payment": "seller_payment_band",
            "dev_payment": "dev_payment_band",
            "buyer_refund": "buyer_refund_band",
            "refund": "refund_band",
        }
        for source, target in value_fields.items():
            if source in event_fields:
                metadata[target] = value_band(event_fields.get(source))

        if "score_band" in event_fields:
            metadata["score_band"] = str(event_fields["score_band"])
        for hash_field in ("artifact_hash", "result_hash"):
            value = event_fields.get(hash_field)
            if value:
                metadata[hash_field] = str(value)

        self._append_run_metadata(
            make_run_metadata_event("chain_event", deal_id, **metadata)
        )

    def get_result(self, deal_id: str) -> EvaluationResult | None:
        """Get bounded evaluation result for a deal."""
        ctx = self._deals.get(deal_id)
        if ctx and ctx.state == DealState.EVALUATED:
            return ctx.result
        return None

    def cleanup_orphans(self) -> list[str]:
        """Scan for sessions that weren't cleaned up (crash recovery).

        Called on CVM boot. Finds training runs with deal_id metadata
        that don't have a corresponding active deal.
        """
        sc = self._create_service_client()
        rc = sc.create_rest_client()
        cleaned = []

        try:
            runs = rc.list_training_runs(limit=100).result()
            for run in runs:
                meta = run.user_metadata or {}
                deal_id = meta.get("deal_id")
                if deal_id and deal_id not in self._deals:
                    # Orphan — clean it up
                    try:
                        checkpoints = rc.list_checkpoints(run.training_run_id).result()
                        for cp in checkpoints:
                            rc.delete_checkpoint(run.training_run_id, cp.checkpoint_id).result()
                        cleaned.append(deal_id)
                    except Exception:
                        pass  # TTL backstop
        except Exception:
            pass

        return cleaned

    @property
    def active_deals(self) -> list[str]:
        return [
            did for did, ctx in self._deals.items()
            if ctx.state not in (DealState.RESOLVED,)
        ]

    # --- Helpers ---

    @staticmethod
    def _band_description(band: ScoreBand, benchmark: str) -> str:
        ranges = {
            ScoreBand.EXCEPTIONAL: ">20%",
            ScoreBand.HIGH: "10-20%",
            ScoreBand.MEDIUM: "5-10%",
            ScoreBand.LOW: "1-5%",
            ScoreBand.NEGLIGIBLE: "<1%",
        }
        return f"+{ranges[band]} on {benchmark}"

    def _append_run_metadata(self, record: dict[str, Any]) -> None:
        store = getattr(self, "_run_metadata_store", None)
        if store is None:
            return
        store.append(record)

    @staticmethod
    def _cleanup_metadata_fields(attestation: CleanupAttestation | None) -> dict[str, Any]:
        if attestation is None:
            return {}
        if not hasattr(attestation, "success"):
            return {}
        return {
            "cleanup_success": bool(attestation.success),
            "listed_checkpoint_count": attestation.listed_checkpoint_count,
            "deleted_checkpoint_count": attestation.deleted_checkpoint_count,
            "failed_checkpoint_count": attestation.failed_checkpoint_count,
            "delete_attempts": attestation.delete_attempts,
            "checkpoint_ids_hash": attestation.checkpoint_ids_hash,
            "training_run_id_hash": stable_hash(
                attestation.training_run_id,
                prefix="training_run_id",
            ),
        }

    @staticmethod
    def _get_tdx_quote(deal_id: str, result: EvaluationResult) -> bytes:
        """Generate TDX quote binding the evaluation result to the enclave."""
        if is_dstack_enabled():
            try:
                report_data = f"{deal_id}:{result.score_band.value}:{result.offer_price}"
                quote, _, _ = get_attestation(report_data)
                return bytes.fromhex(quote)
            except Exception:
                return b""
        return b""
