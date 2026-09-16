#!/usr/bin/env python3
"""Prove a local synthetic DNAI room against real Anvil settlement.

This proof stitches together the source-modeled local room with the real
``DiligenceRoom`` contract path:

1. start ephemeral Anvil
2. derive TEE submitter and verifier addresses from the dstack simulator
3. deploy ``DiligenceRoom`` with the dstack-derived verifier
4. create/fund a deal whose ``teeIdentity`` is the dstack-derived signer
5. upload an encrypted synthetic artifact through the FastAPI encrypted ingress
6. evaluate through ``ControlPlane`` + ``IsolatedTinkerSession`` + fake Tinker
7. authorize and submit the bounded result through the real CLI paths
8. accept the deal, verify settlement events, and trigger cleanup

It emits bounded JSON only. It does not prove deployed Phala execution, real
Tinker SDK training, Base Sepolia state, or frontend verification.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import tempfile
import types
from pathlib import Path
from typing import Any
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.modules.setdefault(
    "tinker",
    types.SimpleNamespace(ServiceClient=object, TrainingClient=object, SamplingClient=object),
)

from tinker_delegate import api
from tinker_delegate.artifacts import artifact_commitment, encrypt_artifact_payload
from tinker_delegate.chain_submitter import (
    get_dstack_signer_attestation,
    score_band_to_contract_value,
)
from tinker_delegate.chain_watcher import JsonRpcLogSource
from tinker_delegate.control_plane import ControlPlane
from tinker_delegate.fake_tinker_backend import FakeTinkerServiceClient
from tinker_delegate.local_synthetic_room import (
    build_synthetic_room_public_packet,
    synthetic_room_evaluator,
)


ROOT = Path(__file__).resolve().parents[3]
TINKER_DIR = ROOT / "⚙️" / "tinker-delegate"
SUBMITTER_PROOF_PATH = TINKER_DIR / "scripts" / "prove-chain-submitter-dstack-anvil.py"

ANVIL_DEVELOPER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ANVIL_BUYER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
ANVIL_SELLER = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
NATIVE_TOKEN = "0x0000000000000000000000000000000000000000"
PRIVATE_ARTIFACT = b"private synthetic diligence artifact for local proof only"
COMMITMENT_SECRET = bytes(range(32))


def main() -> int:
    proof = _load_submitter_proof()
    simulator_started = False
    anvil_port = proof._free_port()
    rpc_url = f"http://127.0.0.1:{anvil_port}"
    anvil = proof._start_anvil(anvil_port)

    try:
        dstack_endpoint, simulator_started = proof._ensure_dstack_simulator()
        signer_address = proof._derive_dstack_signer_address(dstack_endpoint)
        verifier_address = proof._derive_result_verifier_address(dstack_endpoint)

        proof._wait_for_rpc(rpc_url)
        contract_address = proof._deploy_diligence_room(rpc_url, verifier_address)
        start_block = proof._block_number(rpc_url)
        fund_signer_tx = proof._fund_signer(rpc_url, signer_address)
        artifact_hash = artifact_commitment(PRIVATE_ARTIFACT, COMMITMENT_SECRET)
        create_tx, _deal_expiry = _create_deal(
            proof,
            rpc_url=rpc_url,
            contract_address=contract_address,
            tee_identity=signer_address,
            artifact_hash=artifact_hash,
        )
        fund_deal_tx = _fund_deal(proof, rpc_url=rpc_url, contract_address=contract_address)

        room = _run_local_synthetic_room(artifact_hash, contract_address)
        result = room["result"]
        packet = room["packet"]
        compute_cost_wei = int(result.compute_cost_wei)
        score_band = result.score_band.value
        band_value, _band_label = score_band_to_contract_value(score_band)

        authorization = _authorize_result(
            proof,
            rpc_url=rpc_url,
            contract_address=contract_address,
            signer_address=signer_address,
            dstack_endpoint=dstack_endpoint,
            score_band=score_band,
            compute_cost_wei=compute_cost_wei,
        )
        submit_receipt = _submit_result(
            proof,
            rpc_url=rpc_url,
            contract_address=contract_address,
            dstack_endpoint=dstack_endpoint,
            score_band=score_band,
            compute_cost_wei=compute_cost_wei,
            authorization_expiry=int(authorization["authorization_expiry"]),
            verifier_signature=str(authorization["verifier_signature"]),
        )
        accept_tx = _accept_deal(
            proof,
            rpc_url=rpc_url,
            contract_address=contract_address,
            deal_payment=int(result.offer_price),
        )
        after_accept_block = proof._block_number(rpc_url)
        submitted_event = _find_event(
            rpc_url,
            contract_address,
            from_block=start_block,
            to_block=after_accept_block,
            event_name="EvaluationSubmitted",
        )
        accepted_event = _find_event(
            rpc_url,
            contract_address,
            from_block=start_block,
            to_block=after_accept_block,
            event_name="DealAccepted",
        )
        if submitted_event is None:
            raise AssertionError("EvaluationSubmitted event not found")
        if accepted_event is None:
            raise AssertionError("DealAccepted event not found")
        canonical_hashes = {
            str(authorization["result_hash"]).lower(),
            str(submit_receipt["result_hash"]).lower(),
            str(submitted_event.fields["result_hash"]).lower(),
        }
        if len(canonical_hashes) != 1:
            raise AssertionError("verifier, submitter, and contract canonical hashes diverged")

        cleanup_packet = _cleanup_local_room(room)
        settlement = _read_settlement(
            proof,
            rpc_url=rpc_url,
            contract_address=contract_address,
        )

        output = {
            "ok": True,
            "proof": "local_synthetic_room_to_anvil_settlement",
            "scope": {
                "real_contract": True,
                "real_anvil_events": True,
                "dstack_simulator_signer": True,
                "evaluation_attestation_mode": "local_simulator_not_intel_verified",
                "fake_tinker_backend": True,
                "deployed_phala_evidence": False,
                "base_sepolia_evidence": False,
                "real_tinker_sdk_used": False,
            },
            "chain": {
                "rpc": "ephemeral_anvil",
                "contract_address": contract_address,
                "result_verifier": verifier_address,
                "tee_signer": signer_address,
                "start_block": start_block,
                "after_accept_block": after_accept_block,
            },
            "transactions": {
                "fund_signer_tx_hash": fund_signer_tx,
                "create_deal_tx_hash": create_tx,
                "fund_deal_tx_hash": fund_deal_tx,
                "submit_result_tx_hash": submit_receipt["tx_hash"],
                "accept_deal_tx_hash": accept_tx,
            },
            "artifact": {
                "artifact_hash": artifact_hash,
                "artifact_size_band": packet["artifact_size_band"],
                "encrypted_ingress": True,
                "raw_artifact_returned": False,
            },
            "evaluation": {
                "score_band": score_band,
                "score_band_value": band_value,
                "compute_cost_band": submit_receipt["compute_cost_band"],
                "submitted_result_hash": submit_receipt["result_hash"],
                "compose_hash": submit_receipt["compose_hash"],
                "authorization_digest": authorization["authorization_digest"],
                "authorization_policy_hash": authorization["policy_hash"],
                "event_result_hash": submitted_event.fields["result_hash"],
            },
            "settlement": settlement | {
                "accepted_event_fields": accepted_event.fields,
                "deal_payment_band": _value_band(int(result.offer_price)),
            },
            "cleanup": cleanup_packet["cleanup"],
            "egress": {
                "raw_artifact_returned": False,
                "raw_sample_returned": False,
                "raw_checkpoint_path_returned": False,
                "raw_secret_egress": False,
            },
        }
        _assert_no_forbidden(output)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    finally:
        anvil.terminate()
        try:
            anvil.wait(timeout=5)
        except Exception:
            anvil.kill()
            anvil.wait(timeout=5)
        if simulator_started:
            proof._stop_dstack_simulator()


def _load_submitter_proof():
    spec = importlib.util.spec_from_file_location("dnai_submitter_proof", SUBMITTER_PROOF_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load submitter proof helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_local_synthetic_room(artifact_hash: str, contract_address: str) -> dict[str, Any]:
    evaluator_policy_commitment = "0x" + "44" * 32
    fake_tinker = FakeTinkerServiceClient(api_key="sealed-fake-local-proof-key")
    cp = ControlPlane(
        "sealed-fake-local-proof-key",
        project_id="sealed-local-proof-project",
        service_client_factory=lambda **_kwargs: fake_tinker,
    )
    cp.on_deal_funded(
        "0",
        buyer=ANVIL_BUYER,
        seller=ANVIL_SELLER,
        budget_cap=10**18,
        reserve_price=10**15,
        committed_artifact_hash=artifact_hash,
        evaluator_policy_commitment=evaluator_policy_commitment,
    )
    encrypted = encrypt_artifact_payload(
        PRIVATE_ARTIFACT,
        api.get_tee_keypair().public_key_bytes.hex(),
        deal_id="0",
        artifact_hash=artifact_hash,
        commitment_secret=COMMITMENT_SECRET,
        chain_id=84532,
        diligence_room_address=contract_address,
        evaluator_policy_commitment=evaluator_policy_commitment,
    )
    client = TestClient(api.app)
    with (
        patch("tinker_delegate.api._get_control_plane", return_value=cp),
        patch(
            "tinker_delegate.api._require_wallet_auth",
            return_value=types.SimpleNamespace(address=ANVIL_SELLER.lower()),
        ),
    ):
        with patch.object(api.settings, "diligence_room_address", contract_address):
            response = client.post(
                "/deal/0/artifact/encrypted",
                json=encrypted,
                headers={"Authorization": "Bearer explicit-local-proof-token"},
            )
    if response.status_code != 200:
        raise RuntimeError(f"encrypted artifact ingress failed: {response.status_code}")
    # Explicit localhost-only evaluation evidence. This proof validates the
    # bounded control-plane/chain integration; it does not present simulator
    # bytes as an Intel-verified TDX quote.
    with patch.object(
        cp,
        "_get_tdx_quote",
        return_value=b"local-simulator-evaluation-evidence-not-intel-tdx",
    ):
        result = asyncio.run(cp.evaluate("0", synthetic_room_evaluator))
    packet = build_synthetic_room_public_packet(
        deal_id="0",
        artifact_hash=artifact_hash,
        artifact_size=len(PRIVATE_ARTIFACT),
        budget_cap=10**18,
        reserve_price=10**15,
        result=result,
        cleanup_attestation=None,
        service_client=fake_tinker,
    )
    return {
        "control_plane": cp,
        "fake_tinker": fake_tinker,
        "result": result,
        "packet": packet,
    }


def _cleanup_local_room(room: dict[str, Any]) -> dict[str, Any]:
    cp = room["control_plane"]
    cp.on_deal_resolved("0")
    ctx = cp._deals["0"]
    return build_synthetic_room_public_packet(
        deal_id="0",
        artifact_hash=ctx.artifact_hash,
        artifact_size=len(PRIVATE_ARTIFACT),
        budget_cap=10**18,
        reserve_price=10**15,
        result=room["result"],
        cleanup_attestation=ctx.cleanup_attestation,
        service_client=room["fake_tinker"],
    )


def _authorize_result(
    proof,
    *,
    rpc_url: str,
    contract_address: str,
    signer_address: str,
    dstack_endpoint: str,
    score_band: str,
    compute_cost_wei: int,
) -> dict[str, Any]:
    chain_id = int(proof._run(["cast", "chain-id", "--rpc-url", rpc_url]).strip())
    env = proof._proof_env(dstack_endpoint)
    old_env = os.environ.copy()
    os.environ.update(env)
    try:
        attestation = get_dstack_signer_attestation(
            signer_address=signer_address,
            chain_id=chain_id,
            contract_address=contract_address,
        )
    finally:
        os.environ.clear()
        os.environ.update(old_env)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as attestation_file:
        json.dump(attestation.to_public_dict(), attestation_file)
        attestation_file.flush()
        output = proof._run([
            sys.executable,
            "-m",
            "tinker_delegate.main",
            "authorize-result",
            "0",
            score_band,
            str(compute_cost_wei),
            "--contract-address",
            contract_address,
            "--rpc-url",
            rpc_url,
            "--compose-hash",
            attestation.compose_hash,
            "--signer-attestation-json",
            attestation_file.name,
            "--allow-unverified-local-attestation",
            "--allow-compose-hash",
            attestation.compose_hash,
            "--allow-app-id",
            attestation.app_id,
            "--allow-os-image-hash",
            attestation.os_image_hash,
            "--ttl-seconds",
            "600",
        ], cwd=TINKER_DIR, env=env)
    authorization = json.loads(output)
    if authorization.get("authorized") is not True:
        raise RuntimeError("authorize-result did not authorize submission")
    if not authorization.get("result_hash"):
        raise RuntimeError("authorize-result omitted the canonical public result hash")
    return authorization


def _submit_result(
    proof,
    *,
    rpc_url: str,
    contract_address: str,
    dstack_endpoint: str,
    score_band: str,
    compute_cost_wei: int,
    authorization_expiry: int,
    verifier_signature: str,
) -> dict[str, Any]:
    output = proof._run([
        sys.executable,
        "-m",
        "tinker_delegate.main",
        "submit-result",
        "0",
        score_band,
        str(compute_cost_wei),
        "--authorization-expiry",
        str(authorization_expiry),
        "--verifier-signature",
        verifier_signature,
        "--rpc-url",
        rpc_url,
        "--contract-address",
        contract_address,
    ], cwd=TINKER_DIR, env=proof._proof_env(dstack_endpoint))
    receipt = json.loads(output)
    if receipt.get("submitted") is not True:
        raise RuntimeError("submit-result did not submit")
    return receipt


def _create_deal(
    proof,
    *,
    rpc_url: str,
    contract_address: str,
    tee_identity: str,
    artifact_hash: str,
) -> tuple[str, int]:
    expiry = int(__import__("time").time()) + 3600
    output = proof._run_json([
        "cast",
        "send",
        contract_address,
        "createDeal(uint256,uint256,bytes32,address)",
        "1000000000000000",
        str(expiry),
        artifact_hash,
        tee_identity,
        "--rpc-url",
        rpc_url,
        "--unlocked",
        "--from",
        ANVIL_SELLER,
        "--json",
    ])
    return proof._tx_hash(output), expiry


def _fund_deal(proof, *, rpc_url: str, contract_address: str) -> str:
    output = proof._run_json([
        "cast",
        "send",
        contract_address,
        "fundDeal(uint256)",
        "0",
        "--value",
        "1ether",
        "--rpc-url",
        rpc_url,
        "--unlocked",
        "--from",
        ANVIL_BUYER,
        "--json",
    ])
    return proof._tx_hash(output)


def _accept_deal(proof, *, rpc_url: str, contract_address: str, deal_payment: int) -> str:
    output = proof._run_json([
        "cast",
        "send",
        contract_address,
        "acceptDeal(uint256,uint256)",
        "0",
        str(deal_payment),
        "--rpc-url",
        rpc_url,
        "--unlocked",
        "--from",
        ANVIL_BUYER,
        "--json",
    ])
    return proof._tx_hash(output)


def _read_settlement(proof, *, rpc_url: str, contract_address: str) -> dict[str, Any]:
    developer_pending = _parse_cast_uint(proof._run([
        "cast",
        "call",
        contract_address,
        "pendingWithdrawals(address,address)(uint256)",
        NATIVE_TOKEN,
        ANVIL_DEVELOPER,
        "--rpc-url",
        rpc_url,
    ]))
    seller_pending = _parse_cast_uint(proof._run([
        "cast",
        "call",
        contract_address,
        "pendingWithdrawals(address,address)(uint256)",
        NATIVE_TOKEN,
        ANVIL_SELLER,
        "--rpc-url",
        rpc_url,
    ]))
    buyer_pending = _parse_cast_uint(proof._run([
        "cast",
        "call",
        contract_address,
        "pendingWithdrawals(address,address)(uint256)",
        NATIVE_TOKEN,
        ANVIL_BUYER,
        "--rpc-url",
        rpc_url,
    ]))
    return {
        "developer_pending_band": _value_band(developer_pending),
        "seller_pending_band": _value_band(seller_pending),
        "buyer_pending_band": _value_band(buyer_pending),
        "pull_payment_settlement": True,
    }


def _parse_cast_uint(output: str) -> int:
    value = output.strip().split()[0]
    base = 16 if value.startswith("0x") else 10
    return int(value, base)


def _find_event(
    rpc_url: str,
    contract_address: str,
    *,
    from_block: int,
    to_block: int,
    event_name: str,
):
    source = JsonRpcLogSource(rpc_url, contract_address)
    try:
        for event in source.get_events(from_block, to_block):
            if event.name == event_name and str(event.deal_id) == "0":
                return event
    finally:
        source.close()
    return None


def _value_band(value: int) -> str:
    if value == 0:
        return "zero"
    if value < 10**15:
        return "<1e15"
    if value < 10**18:
        return "1e15-1e18"
    return ">=1e18"


def _assert_no_forbidden(output: dict[str, Any]) -> None:
    rendered = json.dumps(output, sort_keys=True)
    forbidden_values = (
        PRIVATE_ARTIFACT.decode("utf-8"),
        "sealed-fake-local-proof-key",
        "sealed-local-proof-project",
        "fake-run-1",
        "tinker://fake-run-1",
        "fake-sample-derived-from-sealed-artifact",
    )
    for forbidden in forbidden_values:
        if forbidden in rendered:
            raise AssertionError(f"bounded proof leaked forbidden value: {forbidden[:16]}")
    if "private_key" in rendered.lower():
        raise AssertionError("bounded proof contains private-key-shaped label")


if __name__ == "__main__":
    sys.exit(main())
