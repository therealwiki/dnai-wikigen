from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from tinker_delegate import tinker_training
from tinker_delegate.fake_tinker_backend import FakeTinkerServiceClient
from tinker_delegate.run_metadata_store import stable_hash
from tinker_delegate.tinker_customer_adapter import TinkerCustomerAdapter
from tinker_delegate.tinker_customer_execution import (
    TinkerCustomerReconciliationRequired,
    TinkerCustomerTrainingRequest,
    TinkerCustomerTrainingService,
)
from tinker_delegate.tinker_customer_runtime import (
    SignedSettlementResultProvider,
)


NOW = 1_900_000_000
RESERVATION_ID = "tcr_" + "22" * 12
RESERVATION_COMMITMENT = (
    "sha256:" + hashlib.sha256(b"reservation").hexdigest()
)
COMPOSE = "0x" + "66" * 32
MODEL = "meta-llama/Llama-3.2-1B"


def _public_key(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _runner_result(
    *,
    request,
    success: bool = True,
    attempted: bool | None = None,
    performed: bool | None = None,
    ambiguous: bool = False,
) -> dict:
    attempted = success if attempted is None else attempted
    performed = success if performed is None else performed
    return {
        "surface": "tinker_training",
        "schema_version": 1,
        "success": success,
        "outcome": (
            "training_completed"
            if success
            else (
                "provider_outcome_ambiguous"
                if ambiguous
                else "api_key_missing"
            )
        ),
        "furthest_stage": (
            "cleanup_completed" if success else "policy_checked"
        ),
        "deal_id_hash": hashlib.sha256(b"deal").hexdigest(),
        "model_hash": stable_hash(request.model, prefix="tinker_model"),
        "rank": request.rank,
        "steps_requested": request.steps,
        "steps_completed": request.steps if success else 0,
        "max_usd_band": "<1e6",
        "metered_cost_band": "<1e6" if success else "zero",
        "checkpoint_saved": success,
        "policy": {},
        "error_kind": "" if success else "api_key_missing",
        "bounded_message": (
            "training_completed"
            if success
            else (
                "provider_outcome_ambiguous"
                if ambiguous
                else "api_key_missing"
            )
        ),
        "issued_at": NOW,
        "provider_dispatch_attempted": attempted,
        "provider_dispatch_performed": performed,
        "provider_outcome_ambiguous": ambiguous,
        "raw_secret_egress": False,
    }


def _service(tmp_path: Path, runner):
    settlement_directory = tmp_path / "settlements"
    settlement_directory.mkdir(mode=0o700)
    signing_key = Ed25519PrivateKey.generate()
    provider = SignedSettlementResultProvider(
        settlement_directory,
        _public_key(signing_key),
        signing_key=signing_key,
    )
    adapter = object.__new__(TinkerCustomerAdapter)
    adapter.expected_release = SimpleNamespace(
        approved_compose_hashes=(COMPOSE,),
    )
    adapter.settlement_provider = provider
    calls = {
        "reserve": 0,
        "claim": 0,
        "finalize": 0,
        "runner": 0,
        "claimed": False,
    }

    def reserve_spend(**kwargs):
        calls["reserve"] += 1
        calls["reserve_kwargs"] = kwargs
        return {
            "reservation_id": RESERVATION_ID,
            "reservation_commitment": RESERVATION_COMMITMENT,
            "idempotent_replay": calls["reserve"] > 1,
        }

    def claim_reservation_dispatch(**kwargs):
        calls["claim"] += 1
        replay = calls["claimed"]
        calls["claimed"] = True
        calls["claim_kwargs"] = kwargs
        return {
            "reservation_id": RESERVATION_ID,
            "reservation_commitment": RESERVATION_COMMITMENT,
            "dispatch_runtime_evidence_digest": (
                "sha256:" + hashlib.sha256(b"runtime").hexdigest()
            ),
            "gate": {
                "release_policy_tuple_digest": (
                    "sha256:" + hashlib.sha256(b"release").hexdigest()
                ),
            },
            "idempotent_replay": replay,
        }

    def finalize_reservation(**kwargs):
        calls["finalize"] += 1
        settlement = provider.consume(
            reservation_id=RESERVATION_ID,
            reservation_commitment=RESERVATION_COMMITMENT,
            now=NOW,
        )
        reserved = calls["reserve_kwargs"]["amount_policy_units"]
        return {
            "status": settlement.outcome,
            "reservation_id": RESERVATION_ID,
            "reservation_commitment": RESERVATION_COMMITMENT,
            "reserved_policy_units": str(reserved),
            "actual_policy_units": str(settlement.actual_policy_units),
            "released_policy_units": str(
                reserved - settlement.actual_policy_units
            ),
            "usage_receipt_hash": settlement.usage_receipt_hash,
            "dispatch_runtime_evidence_digest":
                settlement.runtime_evidence_digest,
            "provider_dispatch_performed":
                settlement.provider_dispatch_performed,
        }

    def counted_runner(*args, **kwargs):
        calls["runner"] += 1
        return runner(*args, **kwargs)

    adapter.reserve_spend = reserve_spend
    adapter.claim_reservation_dispatch = claim_reservation_dispatch
    adapter.finalize_reservation = finalize_reservation
    settings = SimpleNamespace(
        real_sdk_model=MODEL,
        real_sdk_rank=4,
        encumbrance_compose_hash=COMPOSE,
    )
    service = TinkerCustomerTrainingService(
        settings,
        adapter,
        runner=counted_runner,
        clock=lambda: NOW,
    )
    return service, calls, settlement_directory


def test_success_is_reserved_claimed_signed_settled_and_never_redispatched(
    tmp_path: Path,
) -> None:
    def runner(_settings, request, *, strict_at_most_once):
        assert strict_at_most_once is True
        assert request.examples is None
        assert request.require_encumbrance is True
        return _runner_result(request=request)

    service, calls, settlement_directory = _service(tmp_path, runner)
    request = TinkerCustomerTrainingRequest(
        max_usd_micros=125_000,
        steps=3,
        ttl_seconds=600,
    )
    first = service.execute(
        credential_token="customer-credential",
        request=request,
        idempotency_key="customer-training-request-0001",
    )
    replay = service.execute(
        credential_token="customer-credential",
        request=request,
        idempotency_key="customer-training-request-0001",
    )

    assert first["status"] == "settled"
    assert first["actual_policy_units"] == "125000"
    assert first["provider_authoritative_billing"] is False
    assert first["authority_accounting_only"] is True
    assert first["fixed_ceiling_accounting"] is True
    assert first["automatic_provider_redispatch"] is False
    assert first["idempotent_replay"] is False
    assert replay["idempotent_replay"] is True
    assert replay["training_result"] == first["training_result"]
    assert calls["runner"] == 1
    assert calls["reserve_kwargs"]["amount_policy_units"] == 125_000
    assert calls["claim"] == 2
    assert calls["finalize"] == 2
    assert (settlement_directory / f"{RESERVATION_ID}.training.json").is_file()
    assert (settlement_directory / f"{RESERVATION_ID}.json").is_file()


def test_pre_dispatch_failure_releases_the_full_policy_reservation(
    tmp_path: Path,
) -> None:
    def runner(_settings, request, *, strict_at_most_once):
        assert strict_at_most_once is True
        return _runner_result(
            request=request,
            success=False,
            attempted=False,
            performed=False,
        )

    service, calls, _directory = _service(tmp_path, runner)
    receipt = service.execute(
        credential_token="customer-credential",
        request=TinkerCustomerTrainingRequest(max_usd_micros=50_000),
        idempotency_key="customer-training-request-0002",
    )

    assert receipt["status"] == "released"
    assert receipt["actual_policy_units"] == "0"
    assert receipt["released_policy_units"] == "50000"
    assert receipt["settlement"]["provider_dispatch_performed"] is False
    assert calls["runner"] == 1


def test_actual_training_runner_receipt_settles_and_replays_without_redispatch(
    tmp_path: Path, monkeypatch,
) -> None:
    """Actual runner and signed results; adapter, policy, and SDK boundaries fake."""
    backend = FakeTinkerServiceClient(api_key="synthetic-test-only")
    connections = []

    def preflight(_settings, **kwargs):
        assert kwargs["required"] is True
        assert kwargs["compose_hash"] == COMPOSE
        assert kwargs["amount_dollars"] == 0.125
        return SimpleNamespace(allowed=True, to_public_dict=lambda: {})

    def connect(_sdk, api_key, project_id, base_url):
        connections.append((project_id, base_url))
        assert api_key == "synthetic-test-only"
        return backend

    monkeypatch.setattr(tinker_training, "time", SimpleNamespace(time=lambda: NOW))
    monkeypatch.setattr(tinker_training, "preflight_tinker_operation", preflight)
    monkeypatch.setattr(tinker_training, "resolve_api_key", lambda _: "synthetic-test-only")
    monkeypatch.setattr(tinker_training, "resolve_tinker_client_config", lambda _: {
        "project_id": "synthetic-project", "base_url": "https://provider.invalid",
    })
    monkeypatch.setattr(tinker_training, "_create_service_client", connect)
    service, calls, directory = _service(tmp_path, tinker_training.run_tinker_training)
    request = TinkerCustomerTrainingRequest(max_usd_micros=125_000, steps=2)
    kwargs = {
        "credential_token": "customer-credential", "request": request,
        "idempotency_key": "actual-runner-settlement-0001",
    }
    first = service.execute(**kwargs)
    replay = service.execute(**kwargs)

    assert first["status"] == "settled"
    assert first["actual_policy_units"] == "125000"
    assert first["released_policy_units"] == "0"
    assert first["training_result"]["model_hash"] == hashlib.sha256(
        b"tinker_model\0" + MODEL.encode("utf-8")
    ).hexdigest()
    assert first["training_result"]["outcome"] == "training_completed"
    assert first["training_result"]["steps_completed"] == 2
    assert first["training_result"]["checkpoint_saved"] is True
    assert first["training_result"]["provider_dispatch_performed"] is True
    assert first["provider_authoritative_billing"] is False
    assert first["authority_accounting_only"] is True
    assert replay["idempotent_replay"] is True
    assert replay["training_result"] == first["training_result"]
    assert calls["runner"] == 1 and calls["finalize"] == 2
    assert connections == [("synthetic-project", "https://provider.invalid")]
    assert len(backend.created_training_clients) == 1
    training_client = backend.created_training_clients[0][1]
    assert len(training_client.forward_backward_calls) == 2
    assert len(training_client.optim_step_calls) == 2
    assert backend.rest_client.deleted
    assert (directory / f"{RESERVATION_ID}.training.json").is_file()
    assert (directory / f"{RESERVATION_ID}.json").is_file()


def test_actual_training_runner_pre_dispatch_failure_releases_and_replays(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr(tinker_training, "time", SimpleNamespace(time=lambda: NOW))
    monkeypatch.setattr(tinker_training, "preflight_tinker_operation", lambda *_, **__: (
        SimpleNamespace(allowed=True, to_public_dict=lambda: {})
    ))
    monkeypatch.setattr(tinker_training, "resolve_api_key", lambda _: "")
    monkeypatch.setattr(tinker_training, "resolve_tinker_client_config", lambda _: pytest.fail(
        "definite pre-dispatch failure must not configure a provider client"
    ))
    monkeypatch.setattr(tinker_training, "_create_service_client", lambda *_, **__: pytest.fail(
        "definite pre-dispatch failure must not contact a provider"
    ))
    service, calls, directory = _service(tmp_path, tinker_training.run_tinker_training)
    kwargs = {
        "credential_token": "customer-credential",
        "request": TinkerCustomerTrainingRequest(max_usd_micros=50_000),
        "idempotency_key": "actual-runner-release-0001",
    }
    first = service.execute(**kwargs)
    replay = service.execute(**kwargs)

    assert first["status"] == "released"
    assert first["actual_policy_units"] == "0"
    assert first["released_policy_units"] == "50000"
    assert first["training_result"]["model_hash"] == stable_hash(MODEL, prefix="tinker_model")
    assert first["training_result"]["outcome"] == "api_key_missing"
    assert first["training_result"]["provider_dispatch_attempted"] is False
    assert first["training_result"]["provider_dispatch_performed"] is False
    assert first["settlement"]["provider_dispatch_performed"] is False
    assert replay["idempotent_replay"] is True
    assert replay["training_result"] == first["training_result"]
    assert calls["runner"] == 1 and calls["finalize"] == 2
    assert (directory / f"{RESERVATION_ID}.training.json").is_file()
    assert (directory / f"{RESERVATION_ID}.json").is_file()


@pytest.mark.parametrize("model_hash", [
    hashlib.sha256(MODEL.encode("utf-8")).hexdigest(),
    stable_hash("different-model", prefix="tinker_model"),
])
def test_mismatched_model_hash_still_requires_reconciliation_without_redispatch(
    tmp_path: Path, model_hash: str,
) -> None:
    def runner(_settings, request, **_kwargs):
        return {**_runner_result(request=request), "model_hash": model_hash}

    service, calls, directory = _service(tmp_path, runner)
    for _attempt in range(2):
        with pytest.raises(TinkerCustomerReconciliationRequired):
            service.execute(
                credential_token="customer-credential",
                request=TinkerCustomerTrainingRequest(max_usd_micros=50_000),
                idempotency_key="mismatched-model-receipt-0001",
            )
    assert calls["runner"] == 1
    assert calls["finalize"] == 0
    assert not list(directory.iterdir())


def test_ambiguous_post_claim_outcome_is_held_and_retry_never_dispatches(
    tmp_path: Path,
) -> None:
    def runner(_settings, request, *, strict_at_most_once):
        return _runner_result(
            request=request,
            success=False,
            attempted=True,
            performed=False,
            ambiguous=True,
        )

    service, calls, settlement_directory = _service(tmp_path, runner)
    request = TinkerCustomerTrainingRequest(max_usd_micros=50_000)

    for _attempt in range(2):
        with pytest.raises(
            TinkerCustomerReconciliationRequired,
            match="requires reconciliation",
        ) as caught:
            service.execute(
                credential_token="customer-credential",
                request=request,
                idempotency_key="customer-training-request-0003",
            )
        public = caught.value.public_receipt()
        assert public["status"] == "reconciliation_required"
        assert public["automatic_provider_redispatch"] is False
        assert public["provider_outcome_confirmed"] is False

    assert calls["runner"] == 1
    assert calls["finalize"] == 0
    assert not list(settlement_directory.iterdir())


@pytest.mark.parametrize(
    "request_factory",
    (
        lambda: TinkerCustomerTrainingRequest(max_usd_micros=True),
        lambda: TinkerCustomerTrainingRequest(max_usd_micros=0),
        lambda: TinkerCustomerTrainingRequest(
            max_usd_micros=5_000_001
        ),
        lambda: TinkerCustomerTrainingRequest(
            max_usd_micros=1,
            steps=51,
        ),
        lambda: TinkerCustomerTrainingRequest(
            max_usd_micros=1,
            ttl_seconds=59,
        ),
    ),
)
def test_request_caps_use_exact_integers(request_factory) -> None:
    with pytest.raises(ValueError):
        request_factory()
