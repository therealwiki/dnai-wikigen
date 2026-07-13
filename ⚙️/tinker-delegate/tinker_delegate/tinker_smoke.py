"""Bounded real-Tinker SDK smoke test for the funded TEE account."""

from __future__ import annotations

import math
import re
import threading
import time
import uuid
from dataclasses import dataclass
from importlib import metadata
from typing import Any, Callable
from urllib.parse import urlparse

from tinker_delegate.api_key_store import resolve_api_key
from tinker_delegate.redaction import redact_text
from tinker_delegate.run_metadata_store import stable_hash, value_band
from tinker_delegate.session import DEFAULT_TTL, IsolatedTinkerSession
from tinker_delegate.tinker_client_config_store import resolve_tinker_client_config
from tinker_delegate.tinker_encumbrance import (
    TinkerOperationKind,
    preflight_tinker_operation,
)


HARD_SMOKE_MAX_USD = 0.50
DEFAULT_SMOKE_MAX_USD = 0.05
# A blocked/unactivated Tinker account makes the first authenticated SDK calls
# (ServiceClient connect, create_training) hang on internal retry/backoff for
# minutes. Cap them so the smoke returns a bounded ``transient_timeout`` verdict
# in seconds instead of hanging — the operator gets a definitive answer fast.
DEFAULT_SMOKE_CONNECT_TIMEOUT = 45.0


class SmokeTimeoutError(TimeoutError):
    """Raised when a Tinker SDK call exceeds the smoke connect deadline.

    The name carries ``timeout`` so ``_classify_sdk_error`` buckets it as
    ``transient_timeout``.
    """


def _call_with_deadline(fn: Callable[[], Any], seconds: float, *, label: str) -> Any:
    """Run ``fn`` on a daemon thread; raise SmokeTimeoutError past the deadline.

    The worker is a daemon so a genuinely-stuck SDK call cannot block process
    exit; it is abandoned (not cancellable) but the smoke returns promptly.
    """
    box: dict[str, Any] = {}

    def _runner() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - propagate SDK errors intact
            box["error"] = exc

    worker = threading.Thread(target=_runner, name=f"tinker-smoke-{label}", daemon=True)
    worker.start()
    worker.join(timeout=max(1.0, float(seconds)))
    if worker.is_alive():
        raise SmokeTimeoutError(f"tinker smoke {label} exceeded {int(seconds)}s deadline")
    if "error" in box:
        raise box["error"]
    return box.get("value")


@dataclass(frozen=True)
class TinkerSmokeRequest:
    deal_id: str = ""
    max_usd: float | None = None
    model: str = ""
    rank: int | None = None
    ttl_seconds: int = DEFAULT_TTL
    compose_hash: str = ""
    require_encumbrance: bool = False


def run_tinker_sdk_smoke(settings, request: TinkerSmokeRequest | None = None) -> dict[str, Any]:
    """Run one tiny training/checkpoint/sample/cleanup path through Tinker.

    The returned receipt is intentionally bounded: no API key, prompt tokens,
    sample text, raw checkpoint path, or raw training-run id leaves the process.
    """

    request = request or TinkerSmokeRequest()
    issued_at = int(time.time())
    deal_id = request.deal_id or f"tinker-smoke-{uuid.uuid4()}"
    max_usd = _resolve_max_usd(settings, request.max_usd)
    model = request.model or getattr(settings, "real_sdk_model", "")
    rank = int(request.rank if request.rank is not None else getattr(settings, "real_sdk_rank", 4))
    ttl_seconds = int(request.ttl_seconds or DEFAULT_TTL)

    try:
        policy = preflight_tinker_operation(
            settings,
            operation_kind=TinkerOperationKind.SPEND_TINKER_COMPUTE,
            amount_dollars=max_usd,
            compose_hash=request.compose_hash,
            required=request.require_encumbrance,
        )
    except Exception as exc:
        return _base_receipt(
            issued_at=issued_at,
            deal_id=deal_id,
            model=model,
            rank=rank,
            max_usd=max_usd,
            success=False,
            outcome="policy_check_failed",
            furthest_stage="policy_checked",
            policy={
                "checked": False,
                "allowed": False,
                "reason": "policy_check_exception",
                "operation": TinkerOperationKind.SPEND_TINKER_COMPUTE.name.lower(),
                "operation_kind": int(TinkerOperationKind.SPEND_TINKER_COMPUTE),
                "raw_secret_egress": False,
            },
            error_kind=exc.__class__.__name__,
            bounded_message="policy_check_failed",
        )
    if not policy.allowed:
        return _base_receipt(
            issued_at=issued_at,
            deal_id=deal_id,
            model=model,
            rank=rank,
            max_usd=max_usd,
            success=False,
            outcome="policy_denied",
            furthest_stage="policy_checked",
            policy=policy.to_public_dict(),
            error_kind=policy.reason,
        )

    api_key = resolve_api_key(settings)
    if not api_key:
        return _base_receipt(
            issued_at=issued_at,
            deal_id=deal_id,
            model=model,
            rank=rank,
            max_usd=max_usd,
            success=False,
            outcome="api_key_missing",
            furthest_stage="policy_checked",
            policy=policy.to_public_dict(),
            error_kind="api_key_missing",
        )

    session: IsolatedTinkerSession | None = None
    furthest_stage = "api_key_loaded"
    checkpoint_path = ""
    cleanup = None
    failure_site = "service_client_create"
    client_config = resolve_tinker_client_config(settings)
    project_id = client_config["project_id"]
    base_url = client_config["base_url"]
    sdk_diagnostics = _bounded_sdk_diagnostics(
        service_client=None,
        model=model,
        rank=rank,
        deal_id=deal_id,
        project_id=project_id,
        base_url=base_url,
    )
    connect_timeout = float(
        getattr(settings, "smoke_connect_timeout", DEFAULT_SMOKE_CONNECT_TIMEOUT)
    )
    try:
        import tinker

        service_client = _call_with_deadline(
            lambda: _create_service_client(tinker, api_key, project_id, base_url),
            connect_timeout,
            label="service_client_create",
        )
        sdk_diagnostics = _bounded_sdk_diagnostics(
            service_client=service_client,
            model=model,
            rank=rank,
            deal_id=deal_id,
            project_id=project_id,
            base_url=base_url,
        )
        session = IsolatedTinkerSession(service_client, deal_id)

        failure_site = "create_training_client"
        _call_with_deadline(
            lambda: session.create_training(base_model=model, rank=rank),
            connect_timeout,
            label="create_training",
        )
        furthest_stage = "training_created"
        failure_site = "tokenizer"
        tokenizer = session.get_tokenizer()

        prompt_tokens = tokenizer.encode("Question: What is 2 + 2?\nAnswer:", add_special_tokens=True)
        completion_tokens = tokenizer.encode(" 4", add_special_tokens=False)
        all_tokens = prompt_tokens + completion_tokens
        if len(all_tokens) < 4:
            raise RuntimeError("tokenizer returned too few smoke tokens")

        input_tokens = all_tokens[:-1]
        target_tokens = all_tokens[1:]
        weights = [0.0] * max(0, len(prompt_tokens) - 1) + [1.0] * len(completion_tokens)
        weights = weights[: len(target_tokens)]

        datum = tinker.Datum(
            model_input=tinker.ModelInput.from_ints(input_tokens),
            loss_fn_inputs={
                "weights": tinker.TensorData(
                    data=weights,
                    dtype="float32",
                    shape=[len(weights)],
                ),
                "target_tokens": tinker.TensorData(
                    data=target_tokens,
                    dtype="int64",
                    shape=[len(target_tokens)],
                ),
            },
        )

        failure_site = "forward_backward"
        _wait(session.forward_backward([datum], loss_fn="cross_entropy"))
        furthest_stage = "forward_backward_completed"
        _enforce_meter_cap(session, max_usd)
        failure_site = "optimizer_step"
        _wait(session.optim_step(tinker.AdamParams(learning_rate=1e-4)))
        furthest_stage = "optimizer_step_completed"

        failure_site = "checkpoint_save"
        checkpoint_path = session.save_for_sampling("budgeted-smoke", ttl_seconds=ttl_seconds)
        furthest_stage = "checkpoint_saved"
        failure_site = "sampler_create"
        sampler = session.create_sampler(checkpoint_path)

        sampling_params = tinker.SamplingParams(max_tokens=1, temperature=0)
        failure_site = "sample"
        sample_result = _wait(
            session.sample(
                sampler,
                tinker.ModelInput.from_ints(prompt_tokens),
                sampling_params=sampling_params,
                num_samples=1,
            )
        )
        furthest_stage = "sample_completed"
        _enforce_meter_cap(session, max_usd)

        failure_site = "cleanup"
        cleanup = session.cleanup()
        furthest_stage = "cleanup_completed"
        return _success_receipt(
            issued_at=issued_at,
            deal_id=deal_id,
            model=model,
            rank=rank,
            max_usd=max_usd,
            policy=policy.to_public_dict(),
            session=session,
            checkpoint_path=checkpoint_path,
            cleanup=cleanup,
            sample_observed=sample_result is not None,
            sdk_diagnostics=sdk_diagnostics,
        )
    except Exception as exc:
        cleanup_error_kind = ""
        if session is not None:
            try:
                cleanup = session.cleanup()
            except Exception as cleanup_exc:  # pragma: no cover - defensive.
                cleanup_error_kind = cleanup_exc.__class__.__name__
        return _base_receipt(
            issued_at=issued_at,
            deal_id=deal_id,
            model=model,
            rank=rank,
            max_usd=max_usd,
            success=False,
            outcome="smoke_failed",
            furthest_stage=furthest_stage,
            policy=policy.to_public_dict(),
            error_kind=exc.__class__.__name__,
            bounded_message=redact_text(exc.__class__.__name__),
            sdk_error=_bounded_sdk_error(exc, failure_site=failure_site),
            session=session,
            checkpoint_path=checkpoint_path,
            cleanup=cleanup,
            cleanup_error_kind=cleanup_error_kind,
            sdk_diagnostics=sdk_diagnostics,
        )


def _resolve_max_usd(settings, requested: float | None) -> float:
    value = requested if requested is not None else getattr(settings, "real_sdk_max_usd", DEFAULT_SMOKE_MAX_USD)
    value = float(value)
    if not math.isfinite(value) or value <= 0:
        raise ValueError("max_usd must be finite and positive")
    if value > HARD_SMOKE_MAX_USD:
        raise ValueError(f"max_usd must be <= {HARD_SMOKE_MAX_USD}")
    return value


def _wait(value):
    if hasattr(value, "result"):
        return value.result()
    return value


def _create_service_client(tinker_module, api_key: str, project_id: str, base_url: str = ""):
    kwargs: dict[str, str] = {"api_key": api_key}
    if project_id:
        kwargs["project_id"] = project_id
    if base_url:
        kwargs["base_url"] = base_url
    return tinker_module.ServiceClient(**kwargs)


def _enforce_meter_cap(session: IsolatedTinkerSession, max_usd: float) -> None:
    if session.meter.total_cost_usd > max_usd:
        raise RuntimeError("tinker smoke meter cap exceeded")


def _success_receipt(
    *,
    issued_at: int,
    deal_id: str,
    model: str,
    rank: int,
    max_usd: float,
    policy: dict[str, Any],
    session: IsolatedTinkerSession,
    checkpoint_path: str,
    cleanup,
    sample_observed: bool,
    sdk_diagnostics: dict[str, Any],
) -> dict[str, Any]:
    return _base_receipt(
        issued_at=issued_at,
        deal_id=deal_id,
        model=model,
        rank=rank,
        max_usd=max_usd,
        success=True,
        outcome="success",
        furthest_stage="cleanup_completed",
        policy=policy,
        session=session,
        checkpoint_path=checkpoint_path,
        cleanup=cleanup,
        sample_observed=sample_observed,
        sdk_diagnostics=sdk_diagnostics,
    )


def _base_receipt(
    *,
    issued_at: int,
    deal_id: str,
    model: str,
    rank: int,
    max_usd: float,
    success: bool,
    outcome: str,
    furthest_stage: str,
    policy: dict[str, Any],
    error_kind: str = "",
    bounded_message: str = "",
    session: IsolatedTinkerSession | None = None,
    checkpoint_path: str = "",
    cleanup=None,
    cleanup_error_kind: str = "",
    sample_observed: bool = False,
    sdk_error: dict[str, Any] | None = None,
    sdk_diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cleanup_public = _bounded_cleanup(cleanup)
    spent_usd = float(session.meter.total_cost_usd) if session is not None else 0.0
    return {
        "surface": "tinker_sdk_smoke",
        "success": bool(success),
        "outcome": outcome,
        "furthest_stage": furthest_stage,
        "issued_at": issued_at,
        "deal_hash": stable_hash(deal_id, prefix="deal"),
        "training_run_id_hash": stable_hash(
            session.training_run_id if session is not None else None,
            prefix="training_run_id",
        ),
        "checkpoint_path_hash": stable_hash(checkpoint_path or None, prefix="checkpoint_path"),
        "model_hash": stable_hash(model, prefix="tinker_model"),
        "rank": rank,
        "max_usd_band": _usd_band(max_usd),
        "metered_cost_band": _usd_band(spent_usd),
        "compute_cost_band": value_band(session.compute_cost_wei if session is not None else 0),
        "fee_band": value_band(session.fee_wei if session is not None else 0),
        "sample_observed": bool(sample_observed),
        "sample_output_returned": False,
        "cleanup": cleanup_public,
        "cleanup_error_kind": cleanup_error_kind,
        "policy": policy,
        "error_kind": error_kind,
        "sdk_error": sdk_error or _empty_sdk_error(),
        "sdk_diagnostics": sdk_diagnostics or _empty_sdk_diagnostics(),
        "bounded_message": bounded_message or outcome,
        "raw_secret_egress": False,
    }


def _bounded_cleanup(cleanup) -> dict[str, Any]:
    if cleanup is None:
        return {
            "success": False,
            "listed_checkpoint_count": 0,
            "deleted_checkpoint_count": 0,
            "failed_checkpoint_count": 0,
            "delete_attempts": 0,
            "checkpoint_ids_hash": "",
            "training_run_id_hash": "",
            "error_type": "",
        }
    return {
        "success": bool(cleanup.success),
        "listed_checkpoint_count": cleanup.listed_checkpoint_count,
        "deleted_checkpoint_count": cleanup.deleted_checkpoint_count,
        "failed_checkpoint_count": cleanup.failed_checkpoint_count,
        "delete_attempts": cleanup.delete_attempts,
        "checkpoint_ids_hash": cleanup.checkpoint_ids_hash,
        "training_run_id_hash": stable_hash(cleanup.training_run_id, prefix="training_run_id"),
        "error_type": cleanup.error_type,
    }


def _usd_band(value: float) -> str:
    if value <= 0:
        return "zero"
    if value <= 0.01:
        return "<=0.01"
    if value <= 0.05:
        return "<=0.05"
    if value <= 0.10:
        return "<=0.10"
    if value <= 0.50:
        return "<=0.50"
    if value <= 1.0:
        return "<=1.00"
    return ">1.00"


def _empty_sdk_error() -> dict[str, Any]:
    return {
        "bucket": "",
        "provider_error_category": "",
        "message_hash": "",
        "message_length_band": "zero",
        "http_status": 0,
        "http_status_class": "",
        "failure_site": "",
        "operator_action": "",
    }


def _bounded_sdk_error(exc: Exception, *, failure_site: str) -> dict[str, Any]:
    """Return a correlation-safe SDK error fingerprint without raw provider text."""

    normalized = _normalize_exception_message(exc)
    bucket = _classify_sdk_error(exc, normalized)
    provider_error_category = _provider_error_category(exc, normalized)
    status = _extract_http_status(exc)
    return {
        "bucket": bucket,
        "provider_error_category": provider_error_category,
        "message_hash": stable_hash(normalized or exc.__class__.__name__, prefix="tinker_sdk_error"),
        "message_length_band": _message_length_band(normalized),
        "http_status": status if status is not None and 100 <= status < 600 else 0,
        "http_status_class": _http_status_class(exc),
        "failure_site": failure_site,
        "operator_action": _operator_action(bucket, failure_site, provider_error_category),
    }


def _empty_sdk_diagnostics() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "sdk_package": "tinker",
        "sdk_version": "unknown",
        "training_create": {},
        "project": {
            "configured": False,
            "project_hash": "",
        },
        "client_config": {
            "api_key_argument": "unknown",
            "project_id_argument": "unknown",
            "base_url_argument": "unknown",
            "base_url_host_family": "unknown",
            "base_url_hash": "",
        },
        "capabilities": {
            "checked": False,
            "method": "",
            "attempted_model_supported": None,
            "supported_model_count_band": "unknown",
            "supported_models_hash": "",
            "max_batch_size_band": "unknown",
            "error_kind": "",
            "http_status_class": "",
        },
    }


def _bounded_sdk_diagnostics(
    *,
    service_client,
    model: str,
    rank: int,
    deal_id: str,
    project_id: str = "",
    base_url: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "sdk_package": "tinker",
        "sdk_version": _sdk_version(),
        "training_create": {
            "method": "ServiceClient.create_lora_training_client",
            "explicit_kwargs": ["base_model", "rank"],
            "injected_user_metadata_keys": ["deal_id"],
            "implicit_sdk_defaults": [
                "seed=None",
                "train_mlp=True",
                "train_attn=True",
                "train_unembed=True",
            ],
            "model_hash": stable_hash(model, prefix="tinker_model"),
            "model_family": _model_family(model),
            "rank": rank,
            "rank_band": _rank_band(rank),
            "deal_hash": stable_hash(deal_id, prefix="deal"),
            "request_shape": {
                "has_base_model": bool(model),
                "has_rank": True,
                "has_user_metadata_deal_id": True,
                "extra_kwargs_count": 0,
            },
        },
        "project": {
            "configured": bool(project_id),
            "project_hash": stable_hash(project_id, prefix="tinker_project") if project_id else "",
        },
        "client_config": _bounded_client_config(project_id=project_id, base_url=base_url),
        "capabilities": _bounded_capability_probe(service_client, model),
    }


def _bounded_client_config(*, project_id: str = "", base_url: str = "") -> dict[str, Any]:
    return {
        "api_key_argument": "provided",
        "project_id_argument": "provided" if project_id else "omitted",
        "base_url_argument": "provided" if base_url else "sdk_default",
        "base_url_host_family": _base_url_host_family(base_url),
        "base_url_hash": stable_hash(base_url, prefix="tinker_base_url") if base_url else "",
    }


def _base_url_host_family(base_url: str) -> str:
    if not base_url:
        return "sdk_default"
    try:
        host = (urlparse(base_url).hostname or "").lower()
    except Exception:
        return "invalid"
    if not host:
        return "invalid"
    if host in {"localhost", "127.0.0.1", "::1"}:
        return "localhost"
    if (
        host.startswith("10.")
        or host.startswith("192.168.")
        or re.match(r"^172\.(1[6-9]|2\d|3[0-1])\.", host)
    ):
        return "private_network"
    if host.endswith("thinkingmachines.ai") or host.endswith("thinkingmachines.dev"):
        return "thinkingmachines"
    return "other"


def _sdk_version() -> str:
    try:
        return metadata.version("tinker")
    except metadata.PackageNotFoundError:
        return "unknown"


def _bounded_capability_probe(service_client, attempted_model: str) -> dict[str, Any]:
    method = "ServiceClient.get_server_capabilities"
    base = {
        "checked": False,
        "method": method,
        "attempted_model_supported": None,
        "supported_model_count_band": "unknown",
        "supported_models_hash": "",
        "max_batch_size_band": "unknown",
        "error_kind": "",
        "http_status_class": "",
    }
    if service_client is None or not hasattr(service_client, "get_server_capabilities"):
        return base
    try:
        capabilities = service_client.get_server_capabilities()
    except Exception as exc:
        return {
            **base,
            "checked": True,
            "error_kind": exc.__class__.__name__,
            "http_status_class": _http_status_class(exc),
        }

    supported_models = sorted(set(_extract_capability_models(capabilities)))
    supported_hash = (
        stable_hash("\n".join(supported_models), prefix="tinker_supported_models")
        if supported_models
        else ""
    )
    return {
        **base,
        "checked": True,
        "attempted_model_supported": attempted_model in supported_models if supported_models else None,
        "supported_model_count_band": _count_band(len(supported_models)) if supported_models else "unknown",
        "supported_models_hash": supported_hash,
        "max_batch_size_band": _max_batch_size_band(capabilities),
    }


def _extract_capability_models(value: Any) -> list[str]:
    models: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key).lower()
            if "model" in key_text:
                models.extend(_string_items(item))
            models.extend(_extract_capability_models(item))
        return models
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if isinstance(item, str):
                continue
            models.extend(_extract_capability_models(item))
        return models
    if hasattr(value, "__dict__"):
        return _extract_capability_models(vars(value))
    return models


def _string_items(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if isinstance(item, str)]
    return []


def _max_batch_size_band(capabilities: Any) -> str:
    value = _find_numeric_capability(capabilities, ("max_batch_size", "maximum_batch_size"))
    if value is None:
        return "unknown"
    if value <= 0:
        return "invalid"
    if value <= 8:
        return "<=8"
    if value <= 32:
        return "<=32"
    return ">32"


def _find_numeric_capability(value: Any, keys: tuple[str, ...]) -> int | None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key).lower()
            if key_text in keys and isinstance(item, int):
                return item
            found = _find_numeric_capability(item, keys)
            if found is not None:
                return found
    if isinstance(value, (list, tuple, set)):
        for item in value:
            found = _find_numeric_capability(item, keys)
            if found is not None:
                return found
    if hasattr(value, "__dict__"):
        return _find_numeric_capability(vars(value), keys)
    return None


def _model_family(model: str) -> str:
    lowered = model.lower()
    if lowered.startswith("meta-llama/") or "llama" in lowered:
        return "meta-llama"
    if lowered.startswith("qwen/") or "qwen" in lowered:
        return "qwen"
    if "gpt" in lowered:
        return "gpt"
    return "other"


def _rank_band(rank: int) -> str:
    if rank <= 0:
        return "invalid"
    if rank <= 8:
        return "<=8"
    if rank <= 32:
        return "<=32"
    if rank <= 64:
        return "<=64"
    return ">64"


def _count_band(count: int) -> str:
    if count <= 0:
        return "zero"
    if count <= 10:
        return "1-10"
    if count <= 50:
        return "11-50"
    return ">50"


def _http_status_class(exc: Exception) -> str:
    status = _extract_http_status(exc)
    if status is None:
        kind = exc.__class__.__name__.lower()
        if "badrequest" in kind:
            return "4xx"
        if "permission" in kind or "auth" in kind or "forbidden" in kind:
            return "4xx"
        if "notfound" in kind:
            return "4xx"
        if "rate" in kind and "limit" in kind:
            return "4xx"
        return ""
    if 100 <= status < 600:
        return f"{status // 100}xx"
    return "unknown"


def _extract_http_status(exc: Exception) -> int | None:
    for attr in ("status_code", "status"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            return value
    response = getattr(exc, "response", None)
    value = getattr(response, "status_code", None)
    if isinstance(value, int):
        return value
    return None


def _normalize_exception_message(exc: Exception) -> str:
    text = redact_text(exc)
    text = re.sub(r"https?://\S+", "<url>", text, flags=re.IGNORECASE)
    text = re.sub(r"\b[0-9a-fA-F]{32,}\b", "<hex>", text)
    text = re.sub(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        "<uuid>",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"\b\d+\b", "<n>", text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text[:512]


def _classify_sdk_error(exc: Exception, normalized_message: str) -> str:
    kind = exc.__class__.__name__.lower()
    text = f"{kind} {normalized_message}"
    if "timeout" in text or "timed out" in text:
        return "transient_timeout"
    if "rate" in text and "limit" in text:
        return "rate_limited"
    if "unauthor" in text or "forbidden" in text or "permission" in text:
        return "auth_or_entitlement"
    if "quota" in text or "balance" in text or "billing" in text or "fund" in text or "payment" in text:
        return "quota_or_funding"
    if "model" in text or "rank" in text or "lora" in text or "base_model" in text:
        return "model_or_rank"
    if "not found" in text or "404" in text:
        return "not_found"
    if "badrequest" in kind or "bad request" in text or "invalid" in text or "required" in text:
        return "invalid_request"
    if "connection" in text or "network" in text:
        return "transient_network"
    return "unknown"


def _provider_error_category(exc: Exception, normalized_message: str) -> str:
    """Map provider details to a fixed troubleshooting enum without returning them."""

    body_text = _bounded_provider_body_text(getattr(exc, "body", None))
    text = f"{normalized_message} {body_text}".lower()
    if any(term in text for term in ("invalid api key", "api key invalid", "unknown api key")):
        return "invalid_api_key"
    if "api key" in text and any(term in text for term in ("expired", "revoked", "disabled")):
        return "inactive_api_key"
    if "project" in text and any(
        term in text for term in ("not found", "invalid", "unknown", "does not exist", "not accessible")
    ):
        return "invalid_or_inaccessible_project"
    if any(term in text for term in ("not authorized", "not permitted", "entitlement", "access denied")):
        return "account_not_entitled"
    if any(term in text for term in ("insufficient credit", "insufficient balance", "quota", "billing")):
        return "funding_or_quota"
    if any(term in text for term in ("unsupported sdk", "sdk version", "upgrade the sdk")):
        return "sdk_version_unsupported"
    if any(term in text for term in ("route not found", "endpoint not found", "unknown endpoint")):
        return "endpoint_mismatch"
    return "unclassified"


def _bounded_provider_body_text(value: Any, *, depth: int = 0) -> str:
    """Flatten only short scalar provider fields for internal classification."""

    if depth > 4:
        return ""
    if isinstance(value, dict):
        return " ".join(
            _bounded_provider_body_text(item, depth=depth + 1)
            for key, item in value.items()
            if str(key).lower() in {"code", "type", "error", "message", "detail", "reason"}
        )[:2048]
    if isinstance(value, (list, tuple)):
        return " ".join(_bounded_provider_body_text(item, depth=depth + 1) for item in value)[:2048]
    if isinstance(value, (str, int, float, bool)):
        return str(value)[:512]
    return ""


def _operator_action(bucket: str, failure_site: str, provider_error_category: str = "") -> str:
    if failure_site == "service_client_create":
        if provider_error_category in {"invalid_api_key", "inactive_api_key"}:
            return "refresh_or_reseal_api_key"
        if provider_error_category == "invalid_or_inaccessible_project":
            return "remove_or_correct_optional_project_id"
        if provider_error_category == "account_not_entitled":
            return "request_tinker_training_entitlement"
        if provider_error_category == "funding_or_quota":
            return "check_tinker_balance_or_quota"
        if provider_error_category == "sdk_version_unsupported":
            return "upgrade_tinker_sdk"
        if provider_error_category == "endpoint_mismatch":
            return "check_tinker_base_url"
        if bucket == "auth_or_entitlement":
            return "refresh_or_reseal_api_key"
        if bucket in {"transient_timeout", "transient_network", "rate_limited"}:
            return "retry_or_check_tinker_account_activation"
        return "check_sdk_client_configuration"
    if failure_site == "create_training_client":
        if bucket in {"invalid_request", "model_or_rank", "auth_or_entitlement"}:
            return "check_project_or_account_entitlement"
        if bucket == "quota_or_funding":
            return "check_tinker_balance_or_quota"
        if bucket in {"rate_limited", "transient_timeout", "transient_network"}:
            return "retry_later"
        return "escalate_with_message_hash"
    if failure_site in {"forward_backward", "optimizer_step", "checkpoint_save", "sample"}:
        if bucket in {"rate_limited", "transient_timeout", "transient_network"}:
            return "retry_later"
        return "inspect_bounded_training_inputs"
    if failure_site == "cleanup":
        return "inspect_cleanup_receipt"
    return "escalate_with_message_hash"


def _message_length_band(value: str) -> str:
    length = len(value)
    if length == 0:
        return "zero"
    if length <= 64:
        return "<=64"
    if length <= 256:
        return "<=256"
    if length <= 512:
        return "<=512"
    return ">512"
