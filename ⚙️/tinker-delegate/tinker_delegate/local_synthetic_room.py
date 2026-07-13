"""Local synthetic NDAI room harness with a fake Tinker backend.

The harness is deliberately narrow: it gives tests a full vertical slice over
encrypted artifact ingress, buyer cap/reserve, TEE-side evaluator execution,
bounded result construction, and cleanup without requiring a real Tinker
project. The public packet emitted here is a modeled receipt, not deployed
Phala evidence and not an on-chain settlement receipt.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from tinker_delegate.control_plane import EvaluationResult
from tinker_delegate.fake_tinker_backend import FakeTinkerDatum, FakeTinkerPrompt, FakeTinkerServiceClient
from tinker_delegate.run_metadata_store import size_band, stable_hash, value_band
from tinker_delegate.session import CleanupAttestation, IsolatedTinkerSession


SYNTHETIC_ROOM_MODEL = "meta-llama/Llama-3.1-8B"
SYNTHETIC_ROOM_BENCHMARK = "synthetic-room"


async def synthetic_room_evaluator(
    *,
    artifact: bytes,
    artifact_type: str,
    session: IsolatedTinkerSession,
    budget_cap: int,
    reserve_price: int,
) -> dict[str, Any]:
    """Run a deterministic modeled evaluator through IsolatedTinkerSession."""
    token_count = max(1, min(len(artifact), 128))
    training_client = session.create_training(
        SYNTHETIC_ROOM_MODEL,
        rank=4,
        user_metadata={"surface": "local_synthetic_room", "artifact_type": artifact_type},
    )
    session.forward_backward([FakeTinkerDatum(token_count)], loss_fn="cross_entropy").result()
    session.optim_step({"learning_rate": 0.0}).result()
    session.save_state("cleanup-proof", ttl_seconds=300)
    sampler = session.save_and_get_sampler("bounded-eval", ttl_seconds=300)
    session.sample(
        sampler,
        FakeTinkerPrompt(8),
        {"max_tokens": 4, "temperature": 0.0},
        num_samples=1,
    )

    if training_client.get_tokenizer() is None:
        raise RuntimeError("fake tokenizer unavailable")

    # Exact metrics are intentionally collapsed by ControlPlane.bound_output().
    return {
        "quality_delta": 0.08,
        "benchmark": SYNTHETIC_ROOM_BENCHMARK,
        "confidence": "high",
        "methodology": (
            "modeled fake-Tinker session over encrypted synthetic artifact; "
            "only bounded score, offer, cost, and cleanup evidence may leave"
        ),
        "budget_cap_seen": value_band(budget_cap),
        "reserve_price_seen": value_band(reserve_price),
    }


def build_synthetic_room_public_packet(
    *,
    deal_id: str,
    artifact_hash: str,
    artifact_size: int,
    budget_cap: int,
    reserve_price: int,
    result: EvaluationResult,
    cleanup_attestation: CleanupAttestation | None,
    service_client: FakeTinkerServiceClient,
) -> dict[str, Any]:
    """Return the bounded modeled proof that can leave the local harness."""
    result_public = {
        "deal_hash": stable_hash(deal_id, prefix="deal_id"),
        "score_band": result.score_band.value,
        "quality_delta": result.quality_delta,
        "offer_price_band": value_band(result.offer_price),
        "recommendation": result.recommendation,
        "confidence": result.confidence,
        "compute_cost_band": value_band(result.compute_cost_wei),
        "fee_band": value_band(result.fee_wei),
        "tdx_quote_hash": stable_hash(result.tdx_quote, prefix="tdx_quote"),
    }
    result_hash = hashlib.sha256(
        json.dumps(result_public, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    cleanup_public: dict[str, Any] = {
        "success": False,
        "training_run_id_returned": False,
        "checkpoint_paths_returned": False,
    }
    if cleanup_attestation is not None:
        cleanup_public.update(
            {
                "success": bool(cleanup_attestation.success),
                "training_run_id_hash": stable_hash(
                    cleanup_attestation.training_run_id,
                    prefix="training_run_id",
                ),
                "listed_checkpoint_count": cleanup_attestation.listed_checkpoint_count,
                "deleted_checkpoint_count": cleanup_attestation.deleted_checkpoint_count,
                "failed_checkpoint_count": cleanup_attestation.failed_checkpoint_count,
                "delete_attempts": cleanup_attestation.delete_attempts,
                "checkpoint_ids_hash": cleanup_attestation.checkpoint_ids_hash,
            }
        )

    return {
        "surface": "local_synthetic_room",
        "mode": "modeled_fake_tinker",
        "success": result.recommendation == "accept" and cleanup_public["success"],
        "artifact_hash": artifact_hash,
        "artifact_size_band": size_band(artifact_size),
        "budget_cap_band": value_band(budget_cap),
        "reserve_price_band": value_band(reserve_price),
        "result": result_public,
        "result_hash": result_hash,
        "cleanup": cleanup_public,
        "fake_tinker": {
            "training_run_count": len(service_client.created_training_clients),
            "sampling_call_count": sum(len(sampler.sample_calls) for sampler in service_client.samplers),
            "deleted_checkpoint_count": len(service_client.rest_client.deleted),
        },
        "egress": {
            "raw_artifact_returned": False,
            "raw_sample_returned": False,
            "raw_training_run_id_returned": False,
            "raw_checkpoint_path_returned": False,
            "raw_secret_egress": False,
        },
        "real_tinker_sdk_used": False,
        "deployed_phala_evidence": False,
        "on_chain_settlement_evidence": False,
    }
