"""Bounded delegated Tinker training operation (the ``tinker:train`` scope).

This is the training analogue of ``tinker_smoke``: a downstream holder of a
scoped ``tinker:train`` proxy JWT can drive a *real* LoRA training run through
the sealed upstream account, but never touches the ``tml-...`` key, chooses only
bounded parameters, and receives only a bounded receipt (steps completed, cost
band, model hash) — never sample text, checkpoint paths, or raw run ids.

It reuses the same custody discipline as the smoke: encumbrance preflight, a
wall-clock deadline on connect/create, and a per-step meter cap so spend can
never exceed the approved (and proxy-scope-limited) ``max_usd``.

Real multi-step runs require the upstream account to be billing-active; until
then the operation fails closed at the SDK boundary with a bounded receipt,
exactly like the smoke. The bounded request-shaping and receipt logic here are
pure and unit-tested without a live account.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from tinker_delegate.api_key_store import resolve_api_key
from tinker_delegate.redaction import redact_text
from tinker_delegate.run_metadata_store import stable_hash, value_band
from tinker_delegate.session import DEFAULT_TTL, IsolatedTinkerSession
from tinker_delegate.tinker_client_config_store import resolve_tinker_client_config
from tinker_delegate.tinker_encumbrance import (
    TinkerOperationKind,
    preflight_tinker_operation,
)
from tinker_delegate.tinker_smoke import (
    DEFAULT_SMOKE_CONNECT_TIMEOUT,
    _call_with_deadline,
    _create_service_client,
    _enforce_meter_cap,
    _wait,
)

# Training may spend more than the tiny smoke, but stays hard-capped so a scoped
# token can never run away with the account.
HARD_TRAIN_MAX_USD = 5.0
DEFAULT_TRAIN_MAX_USD = 0.25
# Bounded fan-out: a scoped run cannot request unbounded steps/examples.
MAX_TRAIN_STEPS = 50
MAX_TRAIN_EXAMPLES = 64

# A tiny built-in dataset so a run is exercisable without the caller shipping
# raw training text through the boundary.
_DEFAULT_EXAMPLES = (
    ("Question: What is 2 + 2?\nAnswer:", " 4"),
    ("Question: What is 3 + 5?\nAnswer:", " 8"),
    ("Question: What is 10 - 6?\nAnswer:", " 4"),
)


@dataclass
class TinkerTrainingRequest:
    deal_id: str = ""
    max_usd: float | None = None
    model: str = ""
    rank: int | None = None
    steps: int = 1
    learning_rate: float = 1e-4
    ttl_seconds: int = DEFAULT_TTL
    compose_hash: str = ""
    require_encumbrance: bool = True
    # Optional (prompt, completion) pairs; falls back to the built-in dataset.
    examples: tuple[tuple[str, str], ...] | None = None


def resolve_train_max_usd(settings, requested: float | None) -> float:
    value = requested if requested is not None else getattr(
        settings, "train_max_usd", DEFAULT_TRAIN_MAX_USD
    )
    value = float(value)
    if value != value or value in (float("inf"), float("-inf")):  # NaN/inf guard
        raise ValueError("max_usd must be finite and positive")
    if value <= 0:
        raise ValueError("max_usd must be finite and positive")
    if value > HARD_TRAIN_MAX_USD:
        raise ValueError(f"max_usd must be <= {HARD_TRAIN_MAX_USD}")
    return value


def clamp_steps(requested: int) -> int:
    steps = int(requested or 1)
    if steps < 1:
        return 1
    return min(steps, MAX_TRAIN_STEPS)


def resolve_examples(
    examples: tuple[tuple[str, str], ...] | None,
) -> tuple[tuple[str, str], ...]:
    if not examples:
        return _DEFAULT_EXAMPLES
    bounded = tuple(examples)[:MAX_TRAIN_EXAMPLES]
    cleaned = tuple((p, c) for p, c in bounded if isinstance(p, str) and isinstance(c, str) and p)
    return cleaned or _DEFAULT_EXAMPLES


def _train_receipt(
    *,
    issued_at: int,
    deal_id: str,
    model: str,
    rank: int,
    max_usd: float,
    steps_requested: int,
    steps_completed: int,
    success: bool,
    outcome: str,
    furthest_stage: str,
    policy: dict[str, Any] | None = None,
    checkpoint_saved: bool = False,
    spent_usd: float = 0.0,
    error_kind: str = "",
    bounded_message: str = "",
    provider_dispatch_attempted: bool = False,
    provider_dispatch_performed: bool = False,
    provider_outcome_ambiguous: bool = False,
) -> dict[str, Any]:
    return {
        "surface": "tinker_training",
        "schema_version": 1,
        "success": success,
        "outcome": outcome,
        "furthest_stage": furthest_stage,
        "deal_id_hash": stable_hash(deal_id, prefix="tinker_deal") if deal_id else "",
        "model_hash": stable_hash(model, prefix="tinker_model") if model else "",
        "rank": rank,
        "steps_requested": steps_requested,
        "steps_completed": steps_completed,
        "max_usd_band": value_band(max_usd),
        "metered_cost_band": value_band(spent_usd),
        "checkpoint_saved": checkpoint_saved,
        "policy": policy or {},
        "error_kind": error_kind,
        "bounded_message": bounded_message or outcome,
        "issued_at": issued_at,
        "provider_dispatch_attempted": provider_dispatch_attempted,
        "provider_dispatch_performed": provider_dispatch_performed,
        "provider_outcome_ambiguous": provider_outcome_ambiguous,
        "raw_secret_egress": False,
    }


def run_tinker_training(
    settings,
    request: TinkerTrainingRequest | None = None,
    *,
    service_client_factory=None,
    strict_at_most_once: bool = False,
) -> dict[str, Any]:
    """Run a bounded multi-step LoRA training pass through the sealed account.

    ``service_client_factory(api_key=..., project_id=..., base_url=...)`` injects
    the Tinker service client. Defaults to the real SDK; tests/demos pass a
    synthetic backend (``FakeTinkerServiceClient``) to exercise the full
    create → forward/backward → optim → checkpoint path without live compute.
    """
    request = request or TinkerTrainingRequest()
    issued_at = int(time.time())
    deal_id = request.deal_id or f"tinker-train-{uuid.uuid4()}"
    max_usd = resolve_train_max_usd(settings, request.max_usd)
    model = request.model or getattr(settings, "real_sdk_model", "")
    rank = int(request.rank if request.rank is not None else getattr(settings, "real_sdk_rank", 4))
    steps = clamp_steps(request.steps)
    examples = resolve_examples(request.examples)
    ttl_seconds = int(request.ttl_seconds or DEFAULT_TTL)
    connect_timeout = float(getattr(settings, "smoke_connect_timeout", DEFAULT_SMOKE_CONNECT_TIMEOUT))

    # 1. Encumbrance / spend preflight (same gate as the smoke).
    try:
        policy = preflight_tinker_operation(
            settings,
            operation_kind=TinkerOperationKind.SPEND_TINKER_COMPUTE,
            amount_dollars=max_usd,
            compose_hash=request.compose_hash,
            required=request.require_encumbrance,
        )
    except Exception as exc:
        return _train_receipt(
            issued_at=issued_at, deal_id=deal_id, model=model, rank=rank, max_usd=max_usd,
            steps_requested=steps, steps_completed=0, success=False,
            outcome="policy_check_failed", furthest_stage="policy_checked",
            error_kind=exc.__class__.__name__, bounded_message="policy_check_failed",
        )
    if not policy.allowed:
        return _train_receipt(
            issued_at=issued_at, deal_id=deal_id, model=model, rank=rank, max_usd=max_usd,
            steps_requested=steps, steps_completed=0, success=False,
            outcome="policy_denied", furthest_stage="policy_checked",
            policy=policy.to_public_dict(), error_kind=policy.reason,
        )

    api_key = resolve_api_key(settings)
    if not api_key:
        return _train_receipt(
            issued_at=issued_at, deal_id=deal_id, model=model, rank=rank, max_usd=max_usd,
            steps_requested=steps, steps_completed=0, success=False,
            outcome="api_key_missing", furthest_stage="policy_checked",
            policy=policy.to_public_dict(), error_kind="api_key_missing",
        )

    client_config = resolve_tinker_client_config(settings)
    project_id = client_config["project_id"]
    base_url = client_config["base_url"]
    session: IsolatedTinkerSession | None = None
    steps_completed = 0
    checkpoint_saved = False
    furthest_stage = "api_key_loaded"
    provider_dispatch_attempted = False
    provider_dispatch_performed = False

    try:
        import tinker  # data types (Datum/AdamParams) are local, no network

        if service_client_factory is not None:
            service_client = _call_with_deadline(
                lambda: service_client_factory(
                    api_key=api_key, project_id=project_id, base_url=base_url
                ),
                connect_timeout, label="service_client_create",
            )
        else:
            service_client = _call_with_deadline(
                lambda: _create_service_client(tinker, api_key, project_id, base_url),
                connect_timeout, label="service_client_create",
            )
        session = IsolatedTinkerSession(service_client, deal_id)
        # The durable customer wrapper commits its dispatch claim before
        # entering this boundary. A timeout or exception after this line cannot
        # safely prove whether the provider created a paid training resource.
        provider_dispatch_attempted = True
        _call_with_deadline(
            lambda: session.create_training(base_model=model, rank=rank),
            connect_timeout, label="create_training",
        )
        provider_dispatch_performed = True
        furthest_stage = "training_created"

        tokenizer = session.get_tokenizer()
        data = _build_training_data(tinker, tokenizer, examples)
        if not data:
            raise RuntimeError("no usable training examples after tokenization")

        for step in range(steps):
            _wait(session.forward_backward(data, loss_fn="cross_entropy"))
            _enforce_meter_cap(session, max_usd)
            _wait(session.optim_step(tinker.AdamParams(learning_rate=request.learning_rate)))
            _enforce_meter_cap(session, max_usd)
            steps_completed = step + 1
            furthest_stage = f"step_{steps_completed}_completed"

        checkpoint_path = session.save_for_sampling("budgeted-train", ttl_seconds=ttl_seconds)
        checkpoint_saved = bool(checkpoint_path)
        furthest_stage = "checkpoint_saved"

        session.cleanup()
        spent = float(session.meter.total_cost_usd)
        return _train_receipt(
            issued_at=issued_at, deal_id=deal_id, model=model, rank=rank, max_usd=max_usd,
            steps_requested=steps, steps_completed=steps_completed, success=True,
            outcome="training_completed", furthest_stage="cleanup_completed",
            policy=policy.to_public_dict(), checkpoint_saved=checkpoint_saved,
            spent_usd=spent, bounded_message="training_completed",
            provider_dispatch_attempted=provider_dispatch_attempted,
            provider_dispatch_performed=provider_dispatch_performed,
        )
    except Exception as exc:
        spent = float(session.meter.total_cost_usd) if session is not None else 0.0
        if session is not None:
            try:
                session.cleanup()
            except Exception:
                pass
        provider_outcome_ambiguous = (
            strict_at_most_once and provider_dispatch_attempted
        )
        return _train_receipt(
            issued_at=issued_at, deal_id=deal_id, model=model, rank=rank, max_usd=max_usd,
            steps_requested=steps, steps_completed=steps_completed, success=False,
            outcome=(
                "provider_outcome_ambiguous"
                if provider_outcome_ambiguous
                else "training_failed"
            ),
            furthest_stage=furthest_stage,
            policy=policy.to_public_dict(), checkpoint_saved=checkpoint_saved,
            spent_usd=spent, error_kind=exc.__class__.__name__,
            bounded_message=(
                "provider_outcome_ambiguous"
                if provider_outcome_ambiguous
                else redact_text(exc.__class__.__name__)
            ),
            provider_dispatch_attempted=provider_dispatch_attempted,
            provider_dispatch_performed=provider_dispatch_performed,
            provider_outcome_ambiguous=provider_outcome_ambiguous,
        )


def _build_training_data(tinker_module, tokenizer, examples):
    """Tokenize (prompt, completion) pairs into masked cross-entropy Datums."""
    data = []
    for prompt, completion in examples:
        prompt_tokens = tokenizer.encode(prompt, add_special_tokens=True)
        completion_tokens = tokenizer.encode(completion, add_special_tokens=False)
        all_tokens = prompt_tokens + completion_tokens
        if len(all_tokens) < 2:
            continue
        input_tokens = all_tokens[:-1]
        target_tokens = all_tokens[1:]
        weights = [0.0] * max(0, len(prompt_tokens) - 1) + [1.0] * len(completion_tokens)
        weights = weights[: len(target_tokens)]
        data.append(
            tinker_module.Datum(
                model_input=tinker_module.ModelInput.from_ints(input_tokens),
                loss_fn_inputs={
                    "weights": tinker_module.TensorData(
                        data=weights, dtype="float32", shape=[len(weights)]
                    ),
                    "target_tokens": tinker_module.TensorData(
                        data=target_tokens, dtype="int64", shape=[len(target_tokens)]
                    ),
                },
            )
        )
    return data
