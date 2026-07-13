#!/usr/bin/env python3
"""Prove dstack-derived submitResult signing against real local Anvil.

This script uses the Phala/dstack simulator as the TEE key source, starts an
ephemeral Anvil chain, deploys DiligenceRoom, creates/funds a deal whose
teeIdentity is the dstack-derived Ethereum address, authorizes the result
through the real ``tinker-delegate authorize-result`` verifier CLI, and invokes
the real ``tinker-delegate submit-result`` CLI. It verifies that Anvil accepts
the raw signed transaction and emits ``EvaluationSubmitted``. It never accepts
or prints raw private keys.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from dstack_sdk import DstackClient

from tinker_delegate.chain_submitter import (
    DstackEthereumSigner,
    ResultCommitment,
    get_dstack_signer_attestation,
)
from tinker_delegate.chain_watcher import JsonRpcLogSource
from tinker_delegate.config import Settings


ROOT = Path(__file__).resolve().parents[3]
TINKER_DIR = ROOT / "⚙️" / "tinker-delegate"
CONTRACTS_DIR = TINKER_DIR / "contracts"
SIMULATOR_VERSION = "0.5.3"
DEFAULT_DSTACK_SOCKET = (
    Path.home() / ".phala-cloud" / "simulator" / SIMULATOR_VERSION / "dstack.sock"
)

ANVIL_SELLER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ANVIL_BUYER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
ARTIFACT_HASH = "0x" + "ab" * 32
RESULT_HASH = "0x" + "cd" * 32
# Bind an RLVR proof-carrying reward-transcript commitment into the on-chain
# resultHash (v2 commitment) so the settled record commits to the reward run.
REWARD_TRANSCRIPT_COMMITMENT = "0x" + "9a" * 32


def main() -> int:
    simulator_started = False
    anvil_port = _free_port()
    rpc_url = f"http://127.0.0.1:{anvil_port}"
    anvil = _start_anvil(anvil_port)

    try:
        dstack_endpoint, simulator_started = _ensure_dstack_simulator()
        signer_address = _derive_dstack_signer_address(dstack_endpoint)
        verifier_address = _derive_result_verifier_address(dstack_endpoint)

        _wait_for_rpc(rpc_url)
        contract_address = _deploy_diligence_room(rpc_url, verifier_address)
        start_block = _block_number(rpc_url)
        fund_signer_tx = _fund_signer(rpc_url, signer_address)
        create_tx, deal_expiry = _create_deal(rpc_url, contract_address, signer_address)
        fund_deal_tx = _fund_deal(rpc_url, contract_address)
        authorization = _authorize_result_via_cli(
            rpc_url=rpc_url,
            contract_address=contract_address,
            signer_address=signer_address,
            dstack_endpoint=dstack_endpoint,
            deal_expiry=deal_expiry,
        )
        before_submit_block = _block_number(rpc_url)

        receipt = _submit_result_via_cli(
            rpc_url=rpc_url,
            contract_address=contract_address,
            dstack_endpoint=dstack_endpoint,
            authorization_expiry=int(authorization["authorization_expiry"]),
            verifier_signature=str(authorization["verifier_signature"]),
        )
        after_submit_block = _block_number(rpc_url)
        submitted_event = _find_evaluation_submitted(
            rpc_url,
            contract_address,
            from_block=start_block,
            to_block=after_submit_block,
        )

        if not submitted_event:
            raise AssertionError("submit-result transaction did not emit EvaluationSubmitted")
        _assert_receipt(receipt, signer_address, contract_address, submitted_event.fields)
        _assert_reward_transcript_binding(receipt, authorization, submitted_event.fields)

        print(json.dumps({
            "ok": True,
            "proof": "dstack_simulator_to_anvil_submit_result",
            "dstack": {
                "endpoint_kind": "unix_socket" if str(dstack_endpoint).endswith(".sock") else "http",
                "signer_address": signer_address,
                "result_verifier_address": verifier_address,
                "result_verifier_custody": authorization.get("verifier_custody"),
                "custody": receipt.get("custody"),
                "signer_attestation_hash": receipt.get("signer_attestation_hash"),
                "signer_attestation_quote_size": receipt.get("signer_attestation_quote_size"),
                "signer_attestation_report_data": receipt.get("signer_attestation_report_data"),
            },
            "chain": {
                "rpc": "ephemeral_anvil",
                "chain_id": receipt.get("chain_id"),
                "contract_address": contract_address,
                "result_verifier": verifier_address,
                "start_block": start_block,
                "before_submit_block": before_submit_block,
                "after_submit_block": after_submit_block,
            },
            "transactions": {
                "fund_signer_tx_hash": fund_signer_tx,
                "create_deal_tx_hash": create_tx,
                "fund_deal_tx_hash": fund_deal_tx,
                "submit_result_tx_hash": receipt.get("tx_hash"),
            },
            "submit_result": {
                "deal_id": receipt.get("deal_id"),
                "score_band": receipt.get("score_band"),
                "score_band_value": receipt.get("score_band_value"),
                "compute_cost_band": receipt.get("compute_cost_band"),
                "payload_result_hash": receipt.get("payload_result_hash"),
                "submitted_result_hash": receipt.get("result_hash"),
                "reward_transcript_commitment": receipt.get("reward_transcript_commitment"),
                "unbound_v1_commitment": authorization.get("_v1_commitment"),
                "compose_hash": receipt.get("compose_hash"),
                "authorization_expiry": receipt.get("authorization_expiry"),
                "verifier_signature_hash": receipt.get("verifier_signature_hash"),
                "authorization_policy_hash": authorization.get("policy_hash"),
                "authorization_digest": authorization.get("authorization_digest"),
                "nonce": receipt.get("nonce"),
                "event_name": submitted_event.name,
                "event_fields": submitted_event.fields,
            },
            "raw_secret_egress": False,
        }, indent=2, sort_keys=True))
        return 0
    finally:
        anvil.terminate()
        try:
            anvil.wait(timeout=5)
        except subprocess.TimeoutExpired:
            anvil.kill()
            anvil.wait(timeout=5)
        if simulator_started:
            _stop_dstack_simulator()


def _ensure_dstack_simulator() -> tuple[str, bool]:
    configured = os.environ.get("DSTACK_SIMULATOR_ENDPOINT", "").strip()
    if configured and _dstack_reachable(configured):
        return configured, False
    default = str(DEFAULT_DSTACK_SOCKET)
    if DEFAULT_DSTACK_SOCKET.exists() and _dstack_reachable(default):
        return default, False

    _start_dstack_simulator()
    deadline = time.time() + 15
    while time.time() < deadline:
        if DEFAULT_DSTACK_SOCKET.exists() and _dstack_reachable(default):
            return default, True
        time.sleep(0.2)
    raise RuntimeError("Phala simulator did not become reachable")


def _start_dstack_simulator() -> None:
    """Start simulator, adding a temporary wget wrapper if this Mac lacks wget."""

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpbin = Path(tmpdir)
        wget = tmpbin / "wget"
        wget.write_text("#!/bin/sh\nexec curl -L -O \"$@\"\n", encoding="utf-8")
        wget.chmod(0o755)
        env = dict(os.environ)
        env["PATH"] = f"{tmpbin}{os.pathsep}{env.get('PATH', '')}"
        _run(["phala", "simulator", "start"], env=env)


def _stop_dstack_simulator() -> None:
    try:
        _run(["phala", "simulator", "stop"])
    except Exception:
        pass


def _dstack_reachable(endpoint: str) -> bool:
    try:
        return bool(DstackClient(endpoint).is_reachable())
    except Exception:
        return False


def _derive_dstack_signer_address(dstack_endpoint: str) -> str:
    env = _proof_env(dstack_endpoint)
    old_env = os.environ.copy()
    os.environ.update(env)
    try:
        return DstackEthereumSigner.from_settings(Settings()).address
    finally:
        os.environ.clear()
        os.environ.update(old_env)


def _derive_result_verifier_address(dstack_endpoint: str) -> str:
    output = _run([
        sys.executable,
        "-m",
        "tinker_delegate.main",
        "result-verifier-address",
    ], cwd=TINKER_DIR, env=_proof_env(dstack_endpoint))
    body = json.loads(output)
    address = body.get("verifier_address")
    if not isinstance(address, str) or not address.startswith("0x"):
        raise RuntimeError("result-verifier-address did not return a verifier address")
    return address


def _start_anvil(port: int) -> subprocess.Popen:
    return subprocess.Popen(
        ["anvil", "--port", str(port), "--chain-id", "31337"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=ROOT,
        text=True,
    )


def _deploy_diligence_room(rpc_url: str, verifier_address: str) -> str:
    output = _run_json([
        "forge",
        "create",
        "src/DiligenceRoom.sol:DiligenceRoom",
        "--rpc-url",
        rpc_url,
        "--unlocked",
        "--from",
        ANVIL_SELLER,
        "--broadcast",
        "--json",
        "--constructor-args",
        verifier_address,
    ], cwd=CONTRACTS_DIR)
    address = output.get("deployedTo") or output.get("contractAddress")
    if not address:
        raise RuntimeError("forge create did not return deployed contract address")
    return str(address)


def _fund_signer(rpc_url: str, signer_address: str) -> str:
    output = _run_json([
        "cast",
        "send",
        signer_address,
        "--value",
        "1ether",
        "--rpc-url",
        rpc_url,
        "--unlocked",
        "--from",
        ANVIL_SELLER,
        "--json",
    ])
    return _tx_hash(output)


def _create_deal(rpc_url: str, contract_address: str, tee_identity: str) -> tuple[str, int]:
    expiry = int(time.time()) + 3600
    output = _run_json([
        "cast",
        "send",
        contract_address,
        "createDeal(uint256,uint256,bytes32,address)",
        "1000000000000000",
        str(expiry),
        ARTIFACT_HASH,
        tee_identity,
        "--rpc-url",
        rpc_url,
        "--unlocked",
        "--from",
        ANVIL_SELLER,
        "--json",
    ])
    return _tx_hash(output), expiry


def _fund_deal(rpc_url: str, contract_address: str) -> str:
    output = _run_json([
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
    return _tx_hash(output)


def _submit_result_via_cli(
    *,
    rpc_url: str,
    contract_address: str,
    dstack_endpoint: str,
    authorization_expiry: int,
    verifier_signature: str,
) -> dict[str, Any]:
    output = _run([
        sys.executable,
        "-m",
        "tinker_delegate.main",
        "submit-result",
        "0",
        "high",
        "1000000000000000",
        RESULT_HASH,
        "--authorization-expiry",
        str(authorization_expiry),
        "--verifier-signature",
        verifier_signature,
        "--reward-transcript-commitment",
        REWARD_TRANSCRIPT_COMMITMENT,
        "--rpc-url",
        rpc_url,
        "--contract-address",
        contract_address,
    ], cwd=TINKER_DIR, env=_proof_env(dstack_endpoint))
    return json.loads(output)


def _authorize_result_via_cli(
    *,
    rpc_url: str,
    contract_address: str,
    signer_address: str,
    dstack_endpoint: str,
    deal_expiry: int,
) -> dict[str, Any]:
    chain_id = int(_run(["cast", "chain-id", "--rpc-url", rpc_url]).strip())
    nonce = int(_run(["cast", "nonce", signer_address, "--rpc-url", rpc_url]).strip())
    env = _proof_env(dstack_endpoint)
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

    commitment_fields = dict(
        chain_id=chain_id,
        contract_address=contract_address,
        deal_id=0,
        nonce=nonce,
        compose_hash=attestation.compose_hash,
        payload_result_hash=RESULT_HASH,
        score_band_value=3,
        compute_cost_wei=10**15,
        expiry=deal_expiry,
    )
    v1_commitment = ResultCommitment(**commitment_fields).digest()
    commitment = ResultCommitment(
        reward_transcript_commitment=REWARD_TRANSCRIPT_COMMITMENT,
        **commitment_fields,
    ).digest()
    if commitment == v1_commitment:
        raise AssertionError("v2 reward-transcript binding did not change the commitment")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as attestation_file:
        json.dump(attestation.to_public_dict(), attestation_file)
        attestation_file.flush()
        output = _run([
            sys.executable,
            "-m",
            "tinker_delegate.main",
            "authorize-result",
            "0",
            "high",
            "1000000000000000",
            commitment,
            "--chain-id",
            str(chain_id),
            "--contract-address",
            contract_address,
            "--tee-identity",
            signer_address,
            "--compose-hash",
            attestation.compose_hash,
            "--signer-attestation-json",
            attestation_file.name,
            "--allow-compose-hash",
            attestation.compose_hash,
            "--allow-app-id",
            attestation.app_id,
            "--allow-os-image-hash",
            attestation.os_image_hash,
            "--ttl-seconds",
            "600",
        ], cwd=TINKER_DIR, env=_proof_env(dstack_endpoint))
    authorization = json.loads(output)
    if authorization.get("authorized") is not True:
        raise RuntimeError("authorize-result did not authorize submission")
    if authorization.get("result_hash") != commitment:
        raise RuntimeError("authorize-result did not authorize the replay-bound commitment")
    if str(authorization.get("tee_identity", "")).lower() != signer_address.lower():
        raise RuntimeError("authorize-result tee identity mismatch")
    if str(authorization.get("contract_address", "")).lower() != contract_address.lower():
        raise RuntimeError("authorize-result contract mismatch")
    # Proof-local: retain the unbound v1 digest so the on-chain result can be
    # shown to equal the v2 (transcript-bound) commitment and differ from v1.
    authorization["_v1_commitment"] = v1_commitment
    authorization["_v2_commitment"] = commitment
    return authorization


def _proof_env(dstack_endpoint: str) -> dict[str, str]:
    env = dict(os.environ)
    env.update({
        "DSTACK_SIMULATOR_ENDPOINT": dstack_endpoint,
        "DSTACK_ENABLED": "true",
        "TINKER_DSTACK_ENABLED": "true",
        "TINKER_CHAIN_SIGNER_KEY_PATH": "tinker/chain_signer/proof",
        "TINKER_CHAIN_RESULT_VERIFIER_KEY_PATH": "tinker/chain_result_verifier/proof",
    })
    env.pop("ETH_PRIVATE_KEY", None)
    env.pop("PRIVATE_KEY", None)
    return env


def _find_evaluation_submitted(
    rpc_url: str,
    contract_address: str,
    *,
    from_block: int,
    to_block: int,
):
    source = JsonRpcLogSource(rpc_url, contract_address)
    try:
        for event in source.get_events(from_block, to_block):
            if event.name == "EvaluationSubmitted" and str(event.deal_id) == "0":
                return event
    finally:
        source.close()
    return None


def _assert_receipt(
    receipt: dict[str, Any],
    signer_address: str,
    contract_address: str,
    event_fields: dict[str, Any],
) -> None:
    if not receipt.get("submitted"):
        raise AssertionError("submit-result receipt did not report submitted=true")
    if receipt.get("custody") != "dstack_derived":
        raise AssertionError("submit-result did not use dstack-derived custody")
    if str(receipt.get("signer_address", "")).lower() != signer_address.lower():
        raise AssertionError("submit-result signer address did not match dstack signer")
    if str(receipt.get("contract_address", "")).lower() != contract_address.lower():
        raise AssertionError("submit-result contract address mismatch")
    if receipt.get("raw_secret_egress") is not False:
        raise AssertionError("submit-result receipt did not assert raw_secret_egress=false")
    if receipt.get("payload_result_hash") != RESULT_HASH:
        raise AssertionError("receipt did not preserve the bounded payload result hash")
    if not receipt.get("signer_attestation_hash"):
        raise AssertionError("receipt did not include signer attestation hash")
    if not receipt.get("signer_attestation_report_data"):
        raise AssertionError("receipt did not include signer attestation report data")
    if int(receipt.get("signer_attestation_quote_size") or 0) <= 0:
        raise AssertionError("receipt did not include signer attestation quote size")
    if event_fields.get("result_hash") != receipt.get("result_hash"):
        raise AssertionError("EvaluationSubmitted result_hash did not match submission commitment")
    if event_fields.get("result_hash") == receipt.get("payload_result_hash"):
        raise AssertionError("submitted result_hash was not replay-bound")
    if "private" in json.dumps(receipt).lower():
        raise AssertionError("bounded receipt contained private-key-shaped text")


def _assert_reward_transcript_binding(
    receipt: dict[str, Any],
    authorization: dict[str, Any],
    event_fields: dict[str, Any],
) -> None:
    """Prove the on-chain resultHash binds the RLVR reward-transcript commitment."""
    if receipt.get("reward_transcript_commitment") != REWARD_TRANSCRIPT_COMMITMENT:
        raise AssertionError("receipt did not record the bound reward-transcript commitment")
    v1_commitment = authorization.get("_v1_commitment")
    v2_commitment = authorization.get("_v2_commitment")
    on_chain = event_fields.get("result_hash")
    if on_chain != v2_commitment:
        raise AssertionError("on-chain result_hash did not equal the v2 transcript-bound commitment")
    if on_chain == v1_commitment:
        raise AssertionError("on-chain result_hash was not changed by the transcript binding")
    if receipt.get("result_hash") != v2_commitment:
        raise AssertionError("submitted result_hash did not equal the v2 commitment")


def _wait_for_rpc(rpc_url: str) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            _block_number(rpc_url)
            return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("Anvil RPC did not become ready")


def _block_number(rpc_url: str) -> int:
    return int(_run(["cast", "block-number", "--rpc-url", rpc_url]).strip())


def _run_json(args: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> dict[str, Any]:
    output = _run(args, cwd=cwd, env=env)
    return json.loads(output)


def _run(args: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    clean_env = dict(env or os.environ)
    clean_env.pop("ETH_PRIVATE_KEY", None)
    clean_env.pop("PRIVATE_KEY", None)
    result = subprocess.run(
        args,
        cwd=cwd or ROOT,
        env=clean_env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(args)}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result.stdout


def _tx_hash(receipt: dict[str, Any]) -> str:
    tx_hash = receipt.get("transactionHash") or receipt.get("transaction_hash")
    if not tx_hash:
        raise RuntimeError("cast receipt did not include transaction hash")
    return str(tx_hash)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


if __name__ == "__main__":
    sys.exit(main())
