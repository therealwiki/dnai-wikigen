"""Control Plane — orchestrates deal lifecycle inside the TEE.

Responsibilities:
  1. Session factory — creates IsolatedTinkerSession per deal
  2. Artifact ingress — receives plaintext only in-TEE; active state is
     optionally persisted as dstack-sealed ciphertext for restart recovery
  3. Agent orchestration — runs evaluator with session + artifact
  4. Output bounding — maps raw metrics to score bands
  5. Cleanup — destroys sessions on deal resolution
  6. Orphan cleanup — scans for leaked sessions on boot

The control plane does NOT watch the chain directly — that's the
on-chain watcher's job. The control plane exposes an internal API
that the watcher calls when events occur.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Optional

import tinker
from eth_hash.auto import keccak

from tinker_delegate.artifacts import (
    ARTIFACT_RAW_MAX_BYTES,
    encode_artifact_wrapper,
    normalize_artifact_commitment_secret,
    normalize_artifact_hash,
    verify_artifact_commitment,
    zero_buffer,
)
from tinker_delegate.active_deal_recovery import (
    ActiveDealRecoveryError,
    ActiveDealRecoveryStore,
)
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


LEGACY_LOCAL_EVALUATOR_POLICY_COMMITMENT = (
    "0x"
    + keccak(b"dnai-wikigen/evaluator-policy/legacy-local-only/v1").hex()
)


def normalize_evaluator_policy_commitment(value: str) -> str:
    """Normalize one nonzero onchain evaluator-policy bytes32."""

    if not isinstance(value, str):
        raise ValueError("evaluator policy commitment must be bytes32")
    raw = value[2:] if value.startswith(("0x", "0X")) else value
    if len(raw) != 64:
        raise ValueError("evaluator policy commitment must be bytes32")
    try:
        decoded = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError("evaluator policy commitment must be bytes32") from exc
    if not any(decoded):
        raise ValueError("evaluator policy commitment must be nonzero")
    return "0x" + raw.lower()


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


PUBLIC_CONFIDENCE = "withheld"
PUBLIC_METHODOLOGY_SUMMARY = "private_evaluator_details_withheld"
# The buyer pays a fixed, public evaluation tariff instead of the evaluator's
# exact token/call meter.  It is derived only from already-public deal terms,
# so evaluator-controlled work cannot encode artifact bits into settlement.
# Fresh DiligenceRoom deployments freeze the matching 1% protocol fee and
# enable the same one-way compute-settlement policy on-chain.
PUBLIC_COMPUTE_SETTLEMENT_BPS = 100  # 1% of the public budget cap
PUBLIC_PROTOCOL_FEE_BPS = 100        # 1% of the public compute tariff
_BPS_DENOMINATOR = 10_000


def reduce_private_evaluation(raw: Mapping[str, Any]) -> ScoreBand:
    """Reduce private evaluator metrics to the single approved public channel.

    Evaluators may keep arbitrary diagnostic strings and metrics inside the TEE,
    but none of those fields are trusted as public output.  The only accepted
    evaluator-controlled scalar is a finite quality delta in ``[0, 1]``; it is
    immediately quantized to :class:`ScoreBand`.  Benchmark names, confidence,
    methodology, counts, hashes, and any additional fields are deliberately
    ignored so they cannot become covert public egress channels.
    """

    if not isinstance(raw, Mapping):
        raise ValueError("evaluator result must be a mapping")
    delta = raw.get("quality_delta")
    if isinstance(delta, bool) or not isinstance(delta, (int, float)):
        raise ValueError("evaluator quality_delta must be a finite number")
    normalized = float(delta)
    if not math.isfinite(normalized) or not 0.0 <= normalized <= 1.0:
        raise ValueError("evaluator quality_delta must be within [0, 1]")
    return bound_output(normalized)


def _mul_bps(value: int, bps: int) -> int:
    """Overflow-safe floor(value * bps / 10_000), mirrored in Solidity."""

    quotient, remainder = divmod(value, _BPS_DENOMINATOR)
    return quotient * bps + (remainder * bps) // _BPS_DENOMINATOR


def _principal_before_fee(total: int, fee_bps: int) -> int:
    """Largest conservative principal whose principal + fee fits ``total``."""

    denominator = _BPS_DENOMINATOR + fee_bps
    quotient, remainder = divmod(total, denominator)
    return quotient * _BPS_DENOMINATOR + (
        remainder * _BPS_DENOMINATOR
    ) // denominator


def derive_public_settlement(
    *,
    budget_cap: int,
    reserve_price: int,
) -> tuple[int, int]:
    """Return the deterministic public compute tariff and protocol fee.

    Neither value reads the evaluator result, session meter, artifact size,
    token count, time, or call count.  The tariff is one percent of the public
    budget, conservatively capped so ``reserve + compute + fee <= budget``.
    Exact metering remains private and is reconciled independently below.
    """

    for label, value in (("budget_cap", budget_cap), ("reserve_price", reserve_price)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{label} must be a non-negative integer")
    if reserve_price > budget_cap:
        raise ValueError("reserve_price cannot exceed budget_cap")
    target = _mul_bps(budget_cap, PUBLIC_COMPUTE_SETTLEMENT_BPS)
    available = budget_cap - reserve_price
    compute_cost = min(
        target,
        _principal_before_fee(available, PUBLIC_PROTOCOL_FEE_BPS),
    )
    fee = _mul_bps(compute_cost, PUBLIC_PROTOCOL_FEE_BPS)
    return compute_cost, fee


def compute_offer(band: ScoreBand, budget_cap: int, reserve_price: int) -> int:
    """Compute offer price from score band and budget constraints.

    The offer is derived from the band, not the raw delta.
    This prevents reverse-engineering exact quality from price.
    """
    band_bps = {
        ScoreBand.EXCEPTIONAL: 9_000,
        ScoreBand.HIGH: 7_000,
        ScoreBand.MEDIUM: 5_000,
        ScoreBand.LOW: 3_000,
        ScoreBand.NEGLIGIBLE: 0,
    }
    offer = _mul_bps(budget_cap, band_bps[band])

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
    quality_delta: str          # fixed description derived only from score_band
    offer_price: int            # in wei, within buyer's budget cap
    recommendation: str         # "accept" | "reject"
    confidence: str             # fixed "withheld" marker; never evaluator text
    methodology_summary: str    # fixed marker; private methodology never leaves
    compute_cost_wei: int      # deterministic public tariff; never raw metering
    fee_wei: int               # deterministic fee over the public tariff
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
    committed_artifact_hash: str
    evaluator_policy_commitment: str = LEGACY_LOCAL_EVALUATOR_POLICY_COMMITMENT
    state: DealState = DealState.PENDING_ARTIFACT
    session: Optional[IsolatedTinkerSession] = None
    artifact: Optional[bytearray] = None
    artifact_commitment_secret: Optional[bytearray] = None
    artifact_hash: str = ""
    result: Optional[EvaluationResult] = None
    cleanup_attestation: Optional[CleanupAttestation] = None
    destruction_record: Optional[dict] = None
    retention_decision: Optional[dict] = None
    created_at: float = field(default_factory=time.time)
    recovery_status: str = "live"

    def __post_init__(self) -> None:
        # Normalize once at construction. The field is write-once because every
        # later artifact decision must stay anchored to the funded chain event.
        object.__setattr__(
            self,
            "committed_artifact_hash",
            normalize_artifact_hash(self.committed_artifact_hash),
        )
        object.__setattr__(
            self,
            "evaluator_policy_commitment",
            normalize_evaluator_policy_commitment(
                self.evaluator_policy_commitment
            ),
        )

    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"committed_artifact_hash", "evaluator_policy_commitment"} and name in self.__dict__:
            raise AttributeError(f"{name} is immutable")
        object.__setattr__(self, name, value)


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
        enable_tinker_session: bool = True,
        active_deal_store: ActiveDealRecoveryStore | None = None,
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
        self._enable_tinker_session = bool(enable_tinker_session)
        self._active_deal_store = active_deal_store
        if self._active_deal_store is not None:
            self._recover_active_deals()

    def _recover_active_deals(self) -> None:
        """Restore authenticated private snapshots without resuming execution."""

        store = getattr(self, "_active_deal_store", None)
        if store is None:
            return
        recovered = store.load()
        contexts: dict[str, DealContext] = {}
        for deal_id, entry in recovered.items():
            ctx = _deal_context_from_recovery_entry(deal_id, entry)
            # A process died while evaluator code may have been running.  Never
            # claim continuation of that execution or its upstream session.
            # The sealed artifact remains available for a new, explicit run.
            if ctx.state == DealState.EVALUATING:
                ctx.state = DealState.PENDING_ARTIFACT
                ctx.recovery_status = (
                    "interrupted_evaluation_recovered_fresh_run_required"
                )
            elif ctx.state == DealState.EVALUATED:
                ctx.recovery_status = "bounded_result_recovered"
            elif ctx.artifact is not None:
                ctx.recovery_status = "sealed_artifact_recovered"
            else:
                ctx.recovery_status = "seller_reupload_required"
            # Live provider sessions are intentionally not serialized.  A fresh
            # session is created only at the next authorized evaluation.
            ctx.session = None
            contexts[deal_id] = ctx
        self._deals = contexts
        # Persist the interrupted-evaluation demotion before serving traffic.
        if recovered:
            self._persist_active_deals()

    def _persist_active_deals(self) -> None:
        """Seal the exact active private state, if production recovery is on."""

        store = getattr(self, "_active_deal_store", None)
        if store is None:
            return
        entries = {
            deal_id: _deal_context_to_recovery_entry(ctx)
            for deal_id, ctx in self._deals.items()
            if ctx.state != DealState.RESOLVED
        }
        store.save(entries)

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
        committed_artifact_hash: str,
        evaluator_policy_commitment: str = LEGACY_LOCAL_EVALUATOR_POLICY_COMMITMENT,
    ) -> DealContext:
        """Called when a deal is funded on-chain. Creates session."""
        normalized_commitment = normalize_artifact_hash(committed_artifact_hash)
        normalized_evaluator_policy = normalize_evaluator_policy_commitment(
            evaluator_policy_commitment
        )
        existing = self._deals.get(deal_id)
        if existing is not None:
            same_funded_context = (
                existing.buyer == buyer
                and existing.seller == seller
                and existing.budget_cap == budget_cap
                and existing.reserve_price == reserve_price
                and hmac.compare_digest(
                    existing.committed_artifact_hash,
                    normalized_commitment,
                )
                and hmac.compare_digest(
                    existing.evaluator_policy_commitment,
                    normalized_evaluator_policy,
                )
            )
            if same_funded_context:
                return existing
            raise ValueError("funded deal context conflicts with immutable chain context")
        session = None
        if self._enable_tinker_session:
            self._authorize_source_use()
            sc = self._create_service_client()
            session = IsolatedTinkerSession(sc, deal_id)

        ctx = DealContext(
            deal_id=deal_id,
            buyer=buyer,
            seller=seller,
            budget_cap=budget_cap,
            reserve_price=reserve_price,
            committed_artifact_hash=normalized_commitment,
            evaluator_policy_commitment=normalized_evaluator_policy,
            session=session,
        )
        self._deals[deal_id] = ctx
        try:
            self._persist_active_deals()
        except Exception:
            self._deals.pop(deal_id, None)
            if session is not None:
                try:
                    session.cleanup()
                except Exception:
                    pass
            raise
        self._append_run_metadata(
            make_run_metadata_event(
                "deal_funded",
                deal_id,
                buyer_hash=stable_hash(buyer, prefix="buyer"),
                seller_hash=stable_hash(seller, prefix="seller"),
                budget_cap_band=value_band(budget_cap),
                reserve_price_band=value_band(reserve_price),
                evaluator_policy_commitment=normalized_evaluator_policy,
            )
        )
        return ctx

    def receive_artifact(
        self,
        deal_id: str,
        artifact: bytes | bytearray,
        artifact_hash: str,
        commitment_secret: bytes | bytearray | str,
    ) -> bool:
        """Store one deal-bound v2 artifact, or accept its exact retry.

        The return value is ``True`` only for the first write and ``False`` for
        an exact replay. Public ingress deliberately returns the same bounded
        acknowledgement for both outcomes.
        """
        ctx = self._deals[deal_id]
        submitted_hash = normalize_artifact_hash(artifact_hash)
        if not hmac.compare_digest(submitted_hash, ctx.committed_artifact_hash):
            raise ValueError("uploaded artifact commitment does not match the on-chain deal")
        verified_hash = verify_artifact_commitment(
            artifact,
            commitment_secret,
            ctx.committed_artifact_hash,
        )
        normalized_secret = normalize_artifact_commitment_secret(commitment_secret)
        secret_transferred = False
        try:
            existing_artifact = ctx.artifact
            existing_secret = ctx.artifact_commitment_secret
            if existing_artifact is not None or existing_secret is not None:
                if existing_artifact is None or existing_secret is None:
                    raise ValueError("stored artifact state is inconsistent")
                if (
                    hmac.compare_digest(existing_artifact, artifact)
                    and hmac.compare_digest(existing_secret, normalized_secret)
                    and hmac.compare_digest(ctx.artifact_hash, verified_hash)
                ):
                    return False
                raise ValueError(
                    "artifact replay conflicts with the stored deal-bound artifact"
                )

            if ctx.state != DealState.PENDING_ARTIFACT:
                raise ValueError("deal is not awaiting an artifact")
            ctx.artifact_hash = verified_hash
            ctx.artifact = bytearray(artifact)
            ctx.artifact_commitment_secret = normalized_secret
            secret_transferred = True
            try:
                self._persist_active_deals()
            except Exception:
                zero_buffer(ctx.artifact)
                zero_buffer(ctx.artifact_commitment_secret)
                ctx.artifact = None
                ctx.artifact_commitment_secret = None
                ctx.artifact_hash = ""
                raise
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
            return True
        finally:
            if not secret_transferred:
                zero_buffer(normalized_secret)

    def get_deal_context(self, deal_id: str) -> DealContext:
        """Return the in-TEE context used for role authorization.

        API callers use this only inside the process to compare the authenticated
        wallet with the funded seller.  The context itself is never serialized.
        """

        return self._deals[deal_id]

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
        assert ctx.artifact_commitment_secret is not None, "No artifact commitment secret"
        requires_tinker_session = bool(
            getattr(evaluator_fn, "requires_tinker_session", True)
        )
        if requires_tinker_session:
            if ctx.session is None and self._enable_tinker_session:
                self._authorize_source_use()
                ctx.session = IsolatedTinkerSession(
                    self._create_service_client(),
                    deal_id,
                )
            assert ctx.session is not None, "No session"

        ctx.state = DealState.EVALUATING
        # This write is the restart boundary.  A crash after it never looks
        # like a completed evaluation: recovery demotes EVALUATING to an
        # explicit fresh-evaluation state while retaining only sealed bytes.
        self._persist_active_deals()

        try:
            # Recompute at the last possible point before evaluator code sees
            # bytes. This prevents a future ingress bypass or in-memory mutation
            # from causing the TEE to evaluate anything other than the
            # chain-committed artifact.
            verify_artifact_commitment(
                ctx.artifact,
                ctx.artifact_commitment_secret,
                ctx.committed_artifact_hash,
            )
            raw = await evaluator_fn(
                artifact=bytes(ctx.artifact),
                artifact_type="dataset",  # TODO: detect from artifact
                session=ctx.session,
                budget_cap=ctx.budget_cap,
                reserve_price=ctx.reserve_price,
            )

            # Bound the output
            band = reduce_private_evaluation(raw)
            offer = compute_offer(band, ctx.budget_cap, ctx.reserve_price)
            recommendation = "accept" if band.value in ("exceptional", "high", "medium") else "reject"

            # Fail-closed cost reconciliation before this result can settle. The
            # on-chain constraint is offer + computeCost + fee <= budgetCap; we
            # check the developer charge (compute + fee) against the budget
            # headroom left after the seller offer, so an over-budget or
            # over-metered charge is caught in the TEE instead of reverting on
            # chain. Estimate == chain here (both from the meter); a real Tinker
            # backend would feed reported_cost separately.
            private_compute_cost_wei = (
                int(ctx.session.compute_cost_wei) if ctx.session is not None else 0
            )
            private_fee_wei = int(ctx.session.fee_wei) if ctx.session is not None else 0
            private_developer_charge = private_compute_cost_wei + private_fee_wei
            reconciliation = reconcile_costs(
                model=getattr(ctx.session, "model", "") or "deterministic",
                estimated_cost_wei=private_developer_charge,
                # This comparison remains entirely inside the TEE.  It checks
                # the exact metered charge against the buyer-authorized headroom
                # without publishing that high-cardinality value.
                chain_compute_cost_wei=private_developer_charge,
                budget_cap_wei=max(0, ctx.budget_cap - offer),
                fee_wei=private_fee_wei,
            )
            if not reconciliation.settlement_safe:
                raise RuntimeError("private metered evaluation cost exceeds deal budget policy")

            compute_cost_wei, fee_wei = derive_public_settlement(
                budget_cap=ctx.budget_cap,
                reserve_price=ctx.reserve_price,
            )

            # Build bounded result
            result = EvaluationResult(
                deal_id=deal_id,
                score_band=band,
                quality_delta=self._band_description(band),
                offer_price=offer,
                recommendation=recommendation,
                confidence=PUBLIC_CONFIDENCE,
                methodology_summary=PUBLIC_METHODOLOGY_SUMMARY,
                compute_cost_wei=compute_cost_wei,
                fee_wei=fee_wei,
                settlement_safe=reconciliation.settlement_safe,
                reconciliation_status=reconciliation.status.value,
            )

            # Attach TDX attestation
            result.tdx_quote = self._get_tdx_quote(deal_id, result)
            if not result.tdx_quote:
                raise RuntimeError("TDX result attestation quote is required")

            ctx.result = result
            ctx.state = DealState.EVALUATED
            self._persist_active_deals()
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
            # Fail closed on evaluator or integrity failure. A deal marked
            # resolved must not retain private bytes while waiting for another
            # on-chain notification that may never arrive.
            if ctx.session:
                try:
                    ctx.cleanup_attestation = ctx.session.cleanup()
                except Exception:
                    # Preserve the original evaluation/integrity error, but do
                    # not let a cleanup failure skip plaintext destruction.
                    ctx.cleanup_attestation = None
            if ctx.artifact is not None:
                zero_buffer(ctx.artifact)
                ctx.artifact = None
            if ctx.artifact_commitment_secret is not None:
                zero_buffer(ctx.artifact_commitment_secret)
                ctx.artifact_commitment_secret = None
            ctx.state = DealState.RESOLVED
            self._persist_active_deals()
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

        try:
            if retain and store is not None and ctx.artifact is not None:
                # Honor the retention decision: seal the versioned wrapper under
                # the retention key. Destruction happens later on
                # sweep_retention() once the window expires.
                if ctx.artifact_commitment_secret is None:
                    raise ValueError("cannot retain artifact without its v2 commitment secret")
                retained_wrapper = encode_artifact_wrapper(ctx.artifact, ctx.artifact_commitment_secret)
                try:
                    store.seal(
                        deal_id,
                        bytes(retained_wrapper),
                        retain_until=decision.retain_until,
                        artifact_hash=ctx.artifact_hash or "",
                        # Scope the key hierarchy per data owner: each seller's retained
                        # corpus derives under its own key branch, not one shared key.
                        corpus_ref=getattr(ctx, "seller", "") or "",
                    )
                finally:
                    zero_buffer(retained_wrapper)
                sealed_retained = True
        finally:
            # Plaintext and the commitment secret never survive resolution, even
            # when the retention store raises while sealing the wrapper.
            if ctx.artifact is not None:
                zero_buffer(ctx.artifact)
                ctx.artifact = None
            if ctx.artifact_commitment_secret is not None:
                zero_buffer(ctx.artifact_commitment_secret)
                ctx.artifact_commitment_secret = None

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
        self._persist_active_deals()
        self._append_run_metadata(
            make_run_metadata_event(
                "deal_resolved",
                deal_id,
                **fields,
                **self._cleanup_metadata_fields(ctx.cleanup_attestation),
            )
        )

    def on_chain_reorg(self, deal_id: str) -> None:
        """Quarantine private state invalidated by a canonical-chain rewrite.

        Reorg compensation never attempts to reinterpret an orphaned funded
        context.  It tears down the session, zeroes private bytes, deletes the
        sealed active entry, and requires the canonical funded notification
        plus a fresh seller upload before evaluation can run again.
        """

        ctx = self._deals.pop(str(deal_id), None)
        if ctx is None:
            store = getattr(self, "_active_deal_store", None)
            if store is not None:
                store.destroy(str(deal_id))
            retention_store = getattr(self, "_retention_store", None)
            if retention_store is not None:
                retention_store.destroy(str(deal_id))
            return
        if ctx.session is not None:
            try:
                ctx.cleanup_attestation = ctx.session.cleanup()
            except Exception:
                ctx.cleanup_attestation = None
        if ctx.artifact is not None:
            zero_buffer(ctx.artifact)
            ctx.artifact = None
        if ctx.artifact_commitment_secret is not None:
            zero_buffer(ctx.artifact_commitment_secret)
            ctx.artifact_commitment_secret = None
        ctx.result = None
        ctx.state = DealState.RESOLVED
        ctx.recovery_status = "reorg_quarantined_seller_reupload_required"
        retention_store = getattr(self, "_retention_store", None)
        if retention_store is not None:
            retention_store.destroy(str(deal_id))
        self._persist_active_deals()
        self._append_run_metadata(
            make_run_metadata_event(
                "deal_reorg_quarantined",
                str(deal_id),
                seller_reupload_required=True,
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
        block_hash: str = "",
        tx_hash: str = "",
        log_index: int | None = None,
        fields: dict[str, Any] | None = None,
    ) -> None:
        """Persist a bounded audit marker for a DiligenceRoom chain event."""
        event_fields = fields or {}
        metadata: dict[str, Any] = {"chain_event_name": event}
        if block_number is not None:
            metadata["chain_block_band"] = value_band(block_number)
        if block_hash:
            metadata["chain_block_hash"] = stable_hash(
                block_hash,
                prefix="chain_block",
            )
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
        for hash_field in (
            "artifact_hash",
            "result_hash",
            "evaluator_policy_commitment",
        ):
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
    def _band_description(band: ScoreBand) -> str:
        ranges = {
            ScoreBand.EXCEPTIONAL: ">20%",
            ScoreBand.HIGH: "10-20%",
            ScoreBand.MEDIUM: "5-10%",
            ScoreBand.LOW: "1-5%",
            ScoreBand.NEGLIGIBLE: "<1%",
        }
        return f"{ranges[band]} quality-improvement band"

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
                report_data = evaluation_attestation_report_data(deal_id, result)
                quote, _, _ = get_attestation(report_data)
                return bytes.fromhex(quote)
            except Exception:
                return b""
        return b""


_ACTIVE_RECOVERY_ENTRY_FIELDS = {
    "deal_id",
    "buyer",
    "seller",
    "budget_cap",
    "reserve_price",
    "committed_artifact_hash",
    "evaluator_policy_commitment",
    "state",
    "artifact_hex",
    "artifact_commitment_secret_hex",
    "artifact_hash",
    "result",
    "created_at",
    "recovery_status",
}
_ACTIVE_RECOVERY_RESULT_FIELDS = {
    "deal_id",
    "score_band",
    "quality_delta",
    "offer_price",
    "recommendation",
    "confidence",
    "methodology_summary",
    "compute_cost_wei",
    "fee_wei",
    "settlement_safe",
    "reconciliation_status",
}
_RECOVERY_BAND_DESCRIPTION = {
    ScoreBand.EXCEPTIONAL: ">20% quality-improvement band",
    ScoreBand.HIGH: "10-20% quality-improvement band",
    ScoreBand.MEDIUM: "5-10% quality-improvement band",
    ScoreBand.LOW: "1-5% quality-improvement band",
    ScoreBand.NEGLIGIBLE: "<1% quality-improvement band",
}


def _deal_context_to_recovery_entry(ctx: DealContext) -> dict[str, Any]:
    artifact = ctx.artifact
    secret = ctx.artifact_commitment_secret
    if (artifact is None) != (secret is None):
        raise ActiveDealRecoveryError(
            "active deal has inconsistent private artifact state"
        )
    if artifact is not None:
        if not 1 <= len(artifact) <= ARTIFACT_RAW_MAX_BYTES:
            raise ActiveDealRecoveryError(
                "active deal artifact is outside the recovery bound"
            )
        verify_artifact_commitment(
            artifact,
            secret,
            ctx.committed_artifact_hash,
        )
    return {
        "deal_id": ctx.deal_id,
        "buyer": ctx.buyer,
        "seller": ctx.seller,
        "budget_cap": ctx.budget_cap,
        "reserve_price": ctx.reserve_price,
        "committed_artifact_hash": ctx.committed_artifact_hash,
        "evaluator_policy_commitment": ctx.evaluator_policy_commitment,
        "state": ctx.state.value,
        "artifact_hex": bytes(artifact).hex() if artifact is not None else "",
        "artifact_commitment_secret_hex": (
            bytes(secret).hex() if secret is not None else ""
        ),
        "artifact_hash": ctx.artifact_hash,
        "result": (
            _evaluation_result_to_recovery_entry(ctx.result)
            if ctx.result is not None
            else None
        ),
        "created_at": ctx.created_at,
        "recovery_status": ctx.recovery_status,
    }


def _deal_context_from_recovery_entry(
    deal_id: str,
    entry: dict[str, Any],
) -> DealContext:
    if set(entry) != _ACTIVE_RECOVERY_ENTRY_FIELDS:
        raise ActiveDealRecoveryError(
            "active-deal recovery context shape is invalid"
        )
    if entry["deal_id"] != deal_id or not 1 <= len(deal_id) <= 160:
        raise ActiveDealRecoveryError(
            "active-deal recovery deal binding is invalid"
        )
    buyer = _recovery_address(entry["buyer"], "buyer")
    seller = _recovery_address(entry["seller"], "seller")
    budget_cap = _recovery_uint(entry["budget_cap"], "budget cap")
    reserve_price = _recovery_uint(entry["reserve_price"], "reserve price")
    if reserve_price > budget_cap:
        raise ActiveDealRecoveryError(
            "active-deal recovery public budget is invalid"
        )
    try:
        state = DealState(entry["state"])
    except (TypeError, ValueError) as exc:
        raise ActiveDealRecoveryError(
            "active-deal recovery state is invalid"
        ) from exc
    if state == DealState.RESOLVED:
        raise ActiveDealRecoveryError(
            "resolved deal cannot remain in active recovery"
        )
    created_at = entry["created_at"]
    if (
        isinstance(created_at, bool)
        or not isinstance(created_at, (int, float))
        or not math.isfinite(float(created_at))
        or float(created_at) <= 0
    ):
        raise ActiveDealRecoveryError(
            "active-deal recovery creation time is invalid"
        )
    recovery_status = entry["recovery_status"]
    if not isinstance(recovery_status, str) or len(recovery_status) > 80:
        raise ActiveDealRecoveryError(
            "active-deal recovery status is invalid"
        )

    artifact = None
    secret = None
    try:
        artifact_hex = entry["artifact_hex"]
        secret_hex = entry["artifact_commitment_secret_hex"]
        if not isinstance(artifact_hex, str) or not isinstance(secret_hex, str):
            raise ActiveDealRecoveryError(
                "active-deal recovery private encoding is invalid"
            )
        if bool(artifact_hex) != bool(secret_hex):
            raise ActiveDealRecoveryError(
                "active-deal recovery private state is inconsistent"
            )
        if artifact_hex:
            if (
                len(artifact_hex) > ARTIFACT_RAW_MAX_BYTES * 2
                or len(artifact_hex) % 2
            ):
                raise ActiveDealRecoveryError(
                    "active-deal recovery artifact size is invalid"
                )
            try:
                artifact = bytearray.fromhex(artifact_hex)
                secret = normalize_artifact_commitment_secret(secret_hex)
            except ValueError as exc:
                raise ActiveDealRecoveryError(
                    "active-deal recovery private encoding is invalid"
                ) from exc
            if not artifact:
                raise ActiveDealRecoveryError(
                    "active-deal recovery artifact is empty"
                )
        artifact_hash = entry["artifact_hash"]
        if artifact is None:
            if artifact_hash:
                raise ActiveDealRecoveryError(
                    "active-deal recovery artifact hash is inconsistent"
                )
        else:
            normalized_artifact_hash = normalize_artifact_hash(artifact_hash)
            verified = verify_artifact_commitment(
                artifact,
                secret,
                entry["committed_artifact_hash"],
            )
            if not hmac.compare_digest(verified, normalized_artifact_hash):
                raise ActiveDealRecoveryError(
                    "active-deal recovery artifact binding is invalid"
                )

        result_payload = entry["result"]
        result = (
            _evaluation_result_from_recovery_entry(deal_id, result_payload)
            if result_payload is not None
            else None
        )
        if (state == DealState.EVALUATED) != (result is not None):
            raise ActiveDealRecoveryError(
                "active-deal recovery result state is inconsistent"
            )
        if state == DealState.EVALUATING and artifact is None:
            raise ActiveDealRecoveryError(
                "interrupted evaluation has no sealed artifact"
            )
        ctx = DealContext(
            deal_id=deal_id,
            buyer=buyer,
            seller=seller,
            budget_cap=budget_cap,
            reserve_price=reserve_price,
            committed_artifact_hash=entry["committed_artifact_hash"],
            evaluator_policy_commitment=entry[
                "evaluator_policy_commitment"
            ],
            state=state,
            artifact=artifact,
            artifact_commitment_secret=secret,
            artifact_hash=(
                normalize_artifact_hash(artifact_hash)
                if artifact_hash
                else ""
            ),
            result=result,
            created_at=float(created_at),
            recovery_status=recovery_status,
        )
        artifact = None
        secret = None
        return ctx
    finally:
        zero_buffer(artifact)
        zero_buffer(secret)


def _evaluation_result_to_recovery_entry(
    result: EvaluationResult,
) -> dict[str, Any]:
    return {
        "deal_id": result.deal_id,
        "score_band": result.score_band.value,
        "quality_delta": result.quality_delta,
        "offer_price": result.offer_price,
        "recommendation": result.recommendation,
        "confidence": result.confidence,
        "methodology_summary": result.methodology_summary,
        "compute_cost_wei": result.compute_cost_wei,
        "fee_wei": result.fee_wei,
        "settlement_safe": result.settlement_safe,
        "reconciliation_status": result.reconciliation_status,
    }


def _evaluation_result_from_recovery_entry(
    deal_id: str,
    payload: Any,
) -> EvaluationResult:
    if not isinstance(payload, dict) or set(payload) != _ACTIVE_RECOVERY_RESULT_FIELDS:
        raise ActiveDealRecoveryError(
            "active-deal recovery bounded result shape is invalid"
        )
    if payload["deal_id"] != deal_id:
        raise ActiveDealRecoveryError(
            "active-deal recovery bounded result binding is invalid"
        )
    try:
        band = ScoreBand(payload["score_band"])
    except (TypeError, ValueError) as exc:
        raise ActiveDealRecoveryError(
            "active-deal recovery score band is invalid"
        ) from exc
    for field_name in ("offer_price", "compute_cost_wei", "fee_wei"):
        _recovery_uint(payload[field_name], field_name)
    recommendation = (
        "accept"
        if band in {ScoreBand.EXCEPTIONAL, ScoreBand.HIGH, ScoreBand.MEDIUM}
        else "reject"
    )
    if (
        payload["quality_delta"] != _RECOVERY_BAND_DESCRIPTION[band]
        or payload["recommendation"] != recommendation
        or payload["confidence"] != PUBLIC_CONFIDENCE
        or payload["methodology_summary"] != PUBLIC_METHODOLOGY_SUMMARY
        or payload["settlement_safe"] is not True
        or payload["reconciliation_status"] != "reconciled"
    ):
        raise ActiveDealRecoveryError(
            "active-deal recovery bounded result is invalid"
        )
    return EvaluationResult(
        deal_id=deal_id,
        score_band=band,
        quality_delta=payload["quality_delta"],
        offer_price=payload["offer_price"],
        recommendation=payload["recommendation"],
        confidence=payload["confidence"],
        methodology_summary=payload["methodology_summary"],
        compute_cost_wei=payload["compute_cost_wei"],
        fee_wei=payload["fee_wei"],
        # Raw quotes are intentionally not restart-persisted. Settlement
        # collects a fresh signer/QVL quote after recovery.
        tdx_quote=b"",
        settlement_safe=True,
        reconciliation_status="reconciled",
    )


def _recovery_uint(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ActiveDealRecoveryError(
            f"active-deal recovery {label} is invalid"
        )
    return value


def _recovery_address(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 42
        or not value.startswith("0x")
    ):
        raise ActiveDealRecoveryError(
            f"active-deal recovery {label} address is invalid"
        )
    try:
        int(value[2:], 16)
    except ValueError as exc:
        raise ActiveDealRecoveryError(
            f"active-deal recovery {label} address is invalid"
        ) from exc
    return value.lower()


def evaluation_attestation_report_data(
    deal_id: str,
    result: EvaluationResult,
) -> bytes:
    """Bind a quote only to the fixed, approved public result projection.

    The digest is high entropy, but its preimage contains only public deal data,
    the five-way score band, fixed labels, and the deterministic settlement
    tariff.  No evaluator-authored string, raw metric, or private meter is read.
    """

    payload = {
        "schema": "dnai-wikigen/evaluation-public-result/v1",
        "deal_id": str(deal_id),
        "score_band": result.score_band.value,
        "quality_delta": result.quality_delta,
        "offer_price": result.offer_price,
        "recommendation": result.recommendation,
        "confidence": result.confidence,
        "methodology_summary": result.methodology_summary,
        "compute_cost_wei": result.compute_cost_wei,
        "fee_wei": result.fee_wei,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(
        b"dnai-wikigen/evaluation-attestation/v1\0" + canonical
    ).digest()
