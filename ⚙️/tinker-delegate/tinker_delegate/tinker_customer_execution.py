"""At-most-once customer-authorized Tinker training execution.

This is deliberately separate from the operator/proxy ``/tinker/train``
surface.  A customer supplies only the lower-authority credential minted by
``TinkerCustomerAdapter`` plus three bounded controls.  The service:

1. reserves an exact integer micro-USD policy ceiling,
2. durably claims the provider-dispatch boundary,
3. runs the existing sealed Tinker SDK path once,
4. signs a bounded result and authority-accounting settlement, and
5. projects that settlement through the anchored customer journal.

The integer policy units are not a claim about upstream provider billing.
Every uncertain outcome after the dispatch claim remains open for explicit
reconciliation; an automatic retry never invokes the provider again.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from tinker_delegate.tinker_customer_adapter import (
    AttestedSettlementResult,
    TinkerCustomerAdapter,
    TinkerCustomerUnavailable,
)
from tinker_delegate.tinker_customer_runtime import (
    SignedSettlementResultProvider,
    TinkerCustomerRuntimeError,
)
from tinker_delegate.tinker_training import (
    HARD_TRAIN_MAX_USD,
    TinkerTrainingRequest,
    run_tinker_training,
)


TINKER_CUSTOMER_TRAINING_POLICY_UNIT = (
    "one_policy_unit_per_requested_max_usd_micro"
)
MAX_TINKER_CUSTOMER_TRAINING_MICROS = int(HARD_TRAIN_MAX_USD * 1_000_000)
MAX_TINKER_CUSTOMER_TRAINING_STEPS = 50
MIN_TINKER_CUSTOMER_TRAINING_TTL_SECONDS = 60
MAX_TINKER_CUSTOMER_TRAINING_TTL_SECONDS = 3_600

_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_STAGE = re.compile(
    r"^(?:policy_checked|api_key_loaded|training_created|checkpoint_saved|"
    r"cleanup_completed|step_[1-9][0-9]*_completed)$"
)
_RESULT_OUTCOMES = frozenset(
    {
        "policy_check_failed",
        "policy_denied",
        "api_key_missing",
        "training_completed",
        "training_failed",
        "provider_outcome_ambiguous",
    }
)
_VALUE_BANDS = frozenset(
    {
        "unknown",
        "invalid",
        "zero",
        "<1e6",
        "1e6-1e9",
        "1e9-1e12",
        "1e12-1e15",
        "1e15-1e18",
        ">=1e18",
    }
)


@dataclass(frozen=True)
class TinkerCustomerTrainingRequest:
    max_usd_micros: int
    steps: int = 1
    ttl_seconds: int = 900

    def __post_init__(self) -> None:
        if (
            type(self.max_usd_micros) is not int
            or not 1
            <= self.max_usd_micros
            <= MAX_TINKER_CUSTOMER_TRAINING_MICROS
        ):
            raise ValueError(
                "customer training max_usd_micros is outside the release cap"
            )
        if (
            type(self.steps) is not int
            or not 1 <= self.steps <= MAX_TINKER_CUSTOMER_TRAINING_STEPS
        ):
            raise ValueError(
                "customer training steps are outside the release cap"
            )
        if (
            type(self.ttl_seconds) is not int
            or not MIN_TINKER_CUSTOMER_TRAINING_TTL_SECONDS
            <= self.ttl_seconds
            <= MAX_TINKER_CUSTOMER_TRAINING_TTL_SECONDS
        ):
            raise ValueError(
                "customer training ttl is outside the release cap"
            )


class TinkerCustomerReconciliationRequired(TinkerCustomerUnavailable):
    """A provider-bound reservation must not be dispatched automatically."""

    def __init__(
        self,
        *,
        reservation_id: str,
        reservation_commitment: str,
        workload_commitment: str,
    ) -> None:
        super().__init__(
            "Tinker customer training outcome requires reconciliation"
        )
        self.reservation_id = reservation_id
        self.reservation_commitment = reservation_commitment
        self.workload_commitment = workload_commitment

    def public_receipt(self) -> dict[str, Any]:
        return {
            "surface": "tinker_customer_training_reconciliation",
            "schema_version": 1,
            "status": "reconciliation_required",
            "reservation_id": self.reservation_id,
            "reservation_commitment": self.reservation_commitment,
            "workload_commitment": self.workload_commitment,
            "at_most_once_claim_committed": True,
            "automatic_provider_redispatch": False,
            "provider_outcome_confirmed": False,
            "provider_authoritative_billing": False,
            "authority_accounting_only": True,
            "raw_secret_egress": False,
        }


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise TinkerCustomerUnavailable(
            "Tinker customer training result is not canonical"
        ) from exc


def _digest(label: str, value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        label.encode("ascii") + b"\0" + _canonical_json(value)
    ).hexdigest()


def _child_idempotency(base: str, phase: str) -> str:
    if (
        type(base) is not str
        or _IDEMPOTENCY.fullmatch(base) is None
    ):
        raise ValueError("customer training idempotency key is invalid")
    suffix = hashlib.sha256(base.encode("ascii")).hexdigest()
    return f"customer-train-{phase}:{suffix}"


def _configured_workload(
    settings: Any,
    request: TinkerCustomerTrainingRequest,
    adapter: TinkerCustomerAdapter,
) -> tuple[dict[str, Any], str]:
    model = str(getattr(settings, "real_sdk_model", "") or "")
    rank = getattr(settings, "real_sdk_rank", 0)
    compose_hash = str(
        getattr(settings, "encumbrance_compose_hash", "") or ""
    ).lower()
    approved = adapter.expected_release.approved_compose_hashes
    if (
        not model
        or len(model) > 512
        or type(rank) is not int
        or not 1 <= rank <= 256
        or not compose_hash
        or compose_hash not in approved
    ):
        raise TinkerCustomerUnavailable(
            "Tinker customer training configuration differs from release authority"
        )
    workload = {
        "schema": "dnai.tinker-customer-training-workload.v1",
        "operation": "training",
        "max_usd_micros": str(request.max_usd_micros),
        "steps": request.steps,
        "ttl_seconds": request.ttl_seconds,
        "model_hash": hashlib.sha256(model.encode("utf-8")).hexdigest(),
        "rank": rank,
        "learning_rate": "0.0001",
        "compose_hash": compose_hash,
        "built_in_training_examples": True,
        "browser_supplied_examples_accepted": False,
    }
    return workload, _digest("tinker_customer_training_workload", workload)


def _bounded_training_result(
    raw: Mapping[str, Any],
    *,
    request: TinkerCustomerTrainingRequest,
    workload: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise TinkerCustomerUnavailable(
            "Tinker customer training runner returned an unsupported result"
        )
    required = {
        "surface",
        "schema_version",
        "success",
        "outcome",
        "furthest_stage",
        "deal_id_hash",
        "model_hash",
        "rank",
        "steps_requested",
        "steps_completed",
        "max_usd_band",
        "metered_cost_band",
        "checkpoint_saved",
        "policy",
        "error_kind",
        "bounded_message",
        "issued_at",
        "provider_dispatch_attempted",
        "provider_dispatch_performed",
        "provider_outcome_ambiguous",
        "raw_secret_egress",
    }
    if set(raw) != required:
        raise TinkerCustomerUnavailable(
            "Tinker customer training runner result fields are not exact"
        )
    for key in (
        "success",
        "checkpoint_saved",
        "provider_dispatch_attempted",
        "provider_dispatch_performed",
        "provider_outcome_ambiguous",
        "raw_secret_egress",
    ):
        if type(raw[key]) is not bool:
            raise TinkerCustomerUnavailable(
                "Tinker customer training runner truth fields are not exact"
            )
    if (
        raw["surface"] != "tinker_training"
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or raw["raw_secret_egress"] is not False
        or raw["outcome"] not in _RESULT_OUTCOMES
        or type(raw["furthest_stage"]) is not str
        or _STAGE.fullmatch(raw["furthest_stage"]) is None
        or type(raw["deal_id_hash"]) is not str
        or _HEX_64.fullmatch(raw["deal_id_hash"]) is None
        or type(raw["model_hash"]) is not str
        or not hmac.compare_digest(raw["model_hash"], workload["model_hash"])
        or type(raw["rank"]) is not int
        or raw["rank"] != workload["rank"]
        or type(raw["steps_requested"]) is not int
        or raw["steps_requested"] != request.steps
        or type(raw["steps_completed"]) is not int
        or not 0 <= raw["steps_completed"] <= request.steps
        or raw["max_usd_band"] not in _VALUE_BANDS
        or raw["metered_cost_band"] not in _VALUE_BANDS
        or type(raw["issued_at"]) is not int
        or raw["issued_at"] <= 0
        or not isinstance(raw["policy"], Mapping)
    ):
        raise TinkerCustomerUnavailable(
            "Tinker customer training runner result is invalid"
        )
    error_kind = raw["error_kind"]
    bounded_message = raw["bounded_message"]
    if (
        type(error_kind) is not str
        or len(error_kind) > 128
        or re.fullmatch(r"[A-Za-z0-9_.:-]*", error_kind) is None
        or type(bounded_message) is not str
        or len(bounded_message) > 128
        or (
            bounded_message not in _RESULT_OUTCOMES
            and re.fullmatch(
                r"[A-Za-z][A-Za-z0-9_.:-]{0,127}",
                bounded_message,
            )
            is None
        )
    ):
        raise TinkerCustomerUnavailable(
            "Tinker customer training runner error projection is invalid"
        )
    if raw["success"] is True:
        if (
            raw["outcome"] != "training_completed"
            or raw["provider_dispatch_attempted"] is not True
            or raw["provider_dispatch_performed"] is not True
            or raw["provider_outcome_ambiguous"] is not False
        ):
            raise TinkerCustomerUnavailable(
                "Tinker customer training success evidence is inconsistent"
            )
    elif (
        raw["provider_dispatch_attempted"] is True
        or raw["provider_dispatch_performed"] is True
        or raw["provider_outcome_ambiguous"] is True
    ):
        raise TinkerCustomerUnavailable(
            "Tinker customer provider outcome is ambiguous"
        )
    return {
        "surface": "tinker_customer_training_result",
        "schema_version": 1,
        "success": raw["success"],
        "outcome": raw["outcome"],
        "furthest_stage": raw["furthest_stage"],
        "deal_id_hash": raw["deal_id_hash"],
        "model_hash": raw["model_hash"],
        "rank": raw["rank"],
        "steps_requested": raw["steps_requested"],
        "steps_completed": raw["steps_completed"],
        "max_usd_band": raw["max_usd_band"],
        "metered_cost_band": raw["metered_cost_band"],
        "checkpoint_saved": raw["checkpoint_saved"],
        "error_kind": error_kind,
        "bounded_message": bounded_message,
        "issued_at": raw["issued_at"],
        "provider_dispatch_attempted": raw["provider_dispatch_attempted"],
        "provider_dispatch_performed": raw["provider_dispatch_performed"],
        "provider_outcome_ambiguous": raw["provider_outcome_ambiguous"],
        "raw_secret_egress": False,
    }


class TinkerCustomerTrainingService:
    """Execute one release-bound customer training reservation at most once."""

    def __init__(
        self,
        settings: Any,
        adapter: TinkerCustomerAdapter,
        *,
        runner: Callable[..., Mapping[str, Any]] = run_tinker_training,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if type(adapter) is not TinkerCustomerAdapter:
            raise TinkerCustomerUnavailable(
                "Tinker customer training adapter is unavailable"
            )
        if not isinstance(
            adapter.settlement_provider,
            SignedSettlementResultProvider,
        ) or adapter.settlement_provider.signing_key is None:
            raise TinkerCustomerUnavailable(
                "Tinker customer settlement writer is unavailable"
            )
        self.settings = settings
        self.adapter = adapter
        self.runner = runner
        self.clock = clock
        self.settlement_provider = adapter.settlement_provider

    def execute(
        self,
        *,
        credential_token: str,
        request: TinkerCustomerTrainingRequest,
        idempotency_key: str,
    ) -> dict[str, Any]:
        if type(request) is not TinkerCustomerTrainingRequest:
            raise ValueError("customer training request is invalid")
        workload, workload_commitment = _configured_workload(
            self.settings,
            request,
            self.adapter,
        )
        reserve_key = _child_idempotency(idempotency_key, "reserve")
        claim_key = _child_idempotency(idempotency_key, "claim")
        final_key = _child_idempotency(idempotency_key, "final")
        reservation = self.adapter.reserve_spend(
            credential_token=credential_token,
            operation="training",
            amount_policy_units=request.max_usd_micros,
            workload_commitment=workload_commitment,
            idempotency_key=reserve_key,
        )
        reservation_id = reservation["reservation_id"]
        reservation_commitment = reservation["reservation_commitment"]
        claim = self.adapter.claim_reservation_dispatch(
            reservation_id=reservation_id,
            reservation_commitment=reservation_commitment,
            idempotency_key=claim_key,
        )

        if claim["idempotent_replay"] is True:
            return self._recover_and_finalize(
                reservation_id=reservation_id,
                reservation_commitment=reservation_commitment,
                workload_commitment=workload_commitment,
                final_key=final_key,
            )

        try:
            raw_result = self.runner(
                self.settings,
                TinkerTrainingRequest(
                    deal_id=f"customer-{reservation_id}",
                    max_usd=request.max_usd_micros / 1_000_000,
                    model=str(self.settings.real_sdk_model),
                    rank=int(self.settings.real_sdk_rank),
                    steps=request.steps,
                    learning_rate=1e-4,
                    ttl_seconds=request.ttl_seconds,
                    compose_hash=workload["compose_hash"],
                    require_encumbrance=True,
                    examples=None,
                ),
                strict_at_most_once=True,
            )
            training_result = _bounded_training_result(
                raw_result,
                request=request,
                workload=workload,
            )
        except TinkerCustomerUnavailable:
            raise self._reconciliation(
                reservation_id,
                reservation_commitment,
                workload_commitment,
            ) from None
        except Exception:
            # Once claimed, even an unstructured runner exception cannot prove
            # that the provider did not accept work.
            raise self._reconciliation(
                reservation_id,
                reservation_commitment,
                workload_commitment,
            ) from None

        current = int(self.clock())
        succeeded = training_result["success"] is True
        settlement = AttestedSettlementResult(
            reservation_id=reservation_id,
            reservation_commitment=reservation_commitment,
            outcome="settled" if succeeded else "released",
            actual_policy_units=(
                request.max_usd_micros if succeeded else 0
            ),
            usage_receipt_hash=_digest(
                "tinker_customer_training_usage",
                training_result,
            ),
            release_policy_tuple_digest=claim["gate"][
                "release_policy_tuple_digest"
            ],
            runtime_evidence_digest=claim[
                "dispatch_runtime_evidence_digest"
            ],
            issued_at=current,
            expires_at=current + 60,
            provider_dispatch_performed=succeeded,
            provider_authoritative_billing=False,
            raw_secret_egress=False,
        )
        try:
            self.settlement_provider.publish_training_result(
                settlement=settlement,
                training_result=training_result,
            )
            final = self.adapter.finalize_reservation(
                reservation_id=reservation_id,
                idempotency_key=final_key,
                now=current,
            )
        except Exception:
            # Signed evidence may already exist and can be recovered by the
            # exact retry; the provider must never be called here again.
            raise self._reconciliation(
                reservation_id,
                reservation_commitment,
                workload_commitment,
            ) from None
        return self._response(
            workload_commitment=workload_commitment,
            training_result=training_result,
            final=final,
            idempotent_replay=False,
        )

    def _recover_and_finalize(
        self,
        *,
        reservation_id: str,
        reservation_commitment: str,
        workload_commitment: str,
        final_key: str,
    ) -> dict[str, Any]:
        try:
            recovered = self.settlement_provider.ensure_settlement_projection(
                reservation_id=reservation_id,
                reservation_commitment=reservation_commitment,
            )
            training_result = recovered["training_result"]
            if not isinstance(training_result, Mapping):
                raise TinkerCustomerRuntimeError(
                    "Tinker customer training replay result is invalid"
                )
            current = int(self.clock())
            final = self.adapter.finalize_reservation(
                reservation_id=reservation_id,
                idempotency_key=final_key,
                now=current,
            )
        except Exception:
            raise self._reconciliation(
                reservation_id,
                reservation_commitment,
                workload_commitment,
            ) from None
        return self._response(
            workload_commitment=workload_commitment,
            training_result=dict(training_result),
            final=final,
            idempotent_replay=True,
        )

    @staticmethod
    def _reconciliation(
        reservation_id: str,
        reservation_commitment: str,
        workload_commitment: str,
    ) -> TinkerCustomerReconciliationRequired:
        return TinkerCustomerReconciliationRequired(
            reservation_id=reservation_id,
            reservation_commitment=reservation_commitment,
            workload_commitment=workload_commitment,
        )

    @staticmethod
    def _response(
        *,
        workload_commitment: str,
        training_result: Mapping[str, Any],
        final: Mapping[str, Any],
        idempotent_replay: bool,
    ) -> dict[str, Any]:
        if (
            not isinstance(training_result, Mapping)
            or not isinstance(final, Mapping)
            or final.get("status") not in {"settled", "released"}
            or _SHA256.fullmatch(workload_commitment) is None
        ):
            raise TinkerCustomerUnavailable(
                "Tinker customer training projection is unavailable"
            )
        return {
            "surface": "tinker_customer_training_execution",
            "schema_version": 1,
            "status": final["status"],
            "reservation_id": final["reservation_id"],
            "reservation_commitment": final["reservation_commitment"],
            "workload_commitment": workload_commitment,
            "reserved_policy_units": final["reserved_policy_units"],
            "actual_policy_units": final["actual_policy_units"],
            "released_policy_units": final["released_policy_units"],
            "policy_unit_definition":
                TINKER_CUSTOMER_TRAINING_POLICY_UNIT,
            "provider_authoritative_billing": False,
            "authority_accounting_only": True,
            "fixed_ceiling_accounting": True,
            "at_most_once_claim_committed": True,
            "automatic_provider_redispatch": False,
            "reconciliation_required": False,
            "training_result": dict(training_result),
            "settlement": {
                "status": final["status"],
                "usage_receipt_hash": final["usage_receipt_hash"],
                "dispatch_runtime_evidence_digest": final[
                    "dispatch_runtime_evidence_digest"
                ],
                "provider_dispatch_performed": final[
                    "provider_dispatch_performed"
                ],
            },
            "idempotent_replay": idempotent_replay,
            "raw_secret_egress": False,
        }


__all__ = [
    "MAX_TINKER_CUSTOMER_TRAINING_MICROS",
    "MAX_TINKER_CUSTOMER_TRAINING_STEPS",
    "TINKER_CUSTOMER_TRAINING_POLICY_UNIT",
    "TinkerCustomerReconciliationRequired",
    "TinkerCustomerTrainingRequest",
    "TinkerCustomerTrainingService",
]
