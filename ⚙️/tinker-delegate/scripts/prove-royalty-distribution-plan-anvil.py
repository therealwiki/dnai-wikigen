#!/usr/bin/env python3
"""Prove a prefunded `settleReserved` distribution plan on Anvil.

This closes the v2 loop: it proves the fresh fail-closed constructor state,
timelock-configures the rollback anchor and dual Royalty authority, anchors one
settlement intent, escrows its exact native funding, anchors the resulting
reservation-bound decision, approves both EIP-712 digests through local
ERC-1271 test doubles, broadcasts the builder's exact no-value calldata, and
proves permanent reconciliation plus conservation.
The test doubles are not TDX/QVL evidence. No raw keys or dstack are used.
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from types import ModuleType
from typing import Any

from tinker_delegate.royalty_distribution_plan import (
    DistributionRecipient,
    build_royalty_distribution_plan,
    compute_owner_amounts_hash,
)
from eth_hash.auto import keccak

ROOT = Path(__file__).resolve().parents[3]
TINKER_DIR = ROOT / "⚙️" / "tinker-delegate"
CONTRACTS_DIR = TINKER_DIR / "contracts"

DEPLOYER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
PAYER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
OWNER_A = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
OWNER_B = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"

SETTLEMENT_ID = "0x" + "b1" * 32
ROOM_COMMITMENT = "0x" + "b2" * 32
ROOM_STATE_COMMITMENT = "0x" + "b3" * 32
QUERY_COMMITMENT = "0x" + "b4" * 32
GRANT_SET_COMMITMENT = "0x" + "b5" * 32
ALLOCATION_COMMITMENT = "0x" + "b6" * 32
EXECUTION_COMMITMENT = "0x" + "b7" * 32
RESULT_COMMITMENT = "0x" + "b8" * 32
USAGE_COMMITMENT = "0x" + "b9" * 32
ATTESTATION_EVIDENCE_HASH = "0x" + "ba" * 32
AMOUNT_A = 700_000_000_000_000_000  # 0.7 ETH
AMOUNT_B = 300_000_000_000_000_000  # 0.3 ETH
ZERO_ADDRESS = "0x" + "00" * 20
FUNDING_REQUEST_TUPLE = (
    "(bytes32,uint256,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,"
    "address,uint256,bytes32,uint64)"
)


def main() -> int:
    port = _free_port()
    rpc_url = f"http://127.0.0.1:{port}"
    anvil = _start_anvil(port)
    try:
        _wait_for_rpc(rpc_url)
        harness = _load_royalty_harness()
        release = harness._deploy_configured_release(rpc_url)
        recipients = [
            DistributionRecipient(OWNER_A, AMOUNT_A),
            DistributionRecipient(OWNER_B, AMOUNT_B),
        ]
        owners_amounts_hash = compute_owner_amounts_hash(recipients)
        refund_after = harness._latest_timestamp(rpc_url) + 3_600
        reservation_request = _funding_reservation_tuple(
            release_policy_commitment=release.release_policy_commitment,
            owners_amounts_hash=owners_amounts_hash,
            refund_after=refund_after,
        )
        reservation_id = harness._bytes32_call(
            rpc_url,
            release.distributor,
            f"fundingReservationId(address,{FUNDING_REQUEST_TUPLE})(bytes32)",
            [PAYER, reservation_request],
        )
        harness._send(
            rpc_url,
            PAYER,
            release.distributor,
            f"reserveNative({FUNDING_REQUEST_TUPLE})",
            [reservation_request],
            value=str(AMOUNT_A + AMOUNT_B),
        )
        admission_before = _view_words(
            rpc_url,
            release.distributor,
            "collaborationFundingReservation(bytes32)",
            reservation_id,
            10,
        )
        authorization, settlement_signature, qvl_signature = harness._authorize_native_settlement(
            rpc_url,
            release,
            recipients,
            settlement_id=SETTLEMENT_ID,
            room_commitment=ROOM_COMMITMENT,
            room_state_commitment=ROOM_STATE_COMMITMENT,
            query_commitment=QUERY_COMMITMENT,
            grant_set_commitment=GRANT_SET_COMMITMENT,
            allocation_commitment=ALLOCATION_COMMITMENT,
            execution_commitment=EXECUTION_COMMITMENT,
            result_commitment=RESULT_COMMITMENT,
            usage_commitment=USAGE_COMMITMENT,
            attestation_evidence_hash=ATTESTATION_EVIDENCE_HASH,
            funding_reservation_id=reservation_id,
        )

        plan = build_royalty_distribution_plan(
            contract_address=release.distributor,
            authorization=authorization,
            recipients=recipients,
            settlement_signature=settlement_signature,
            qvl_signature=qvl_signature,
        )

        # Broadcast the exact prefunded calldata. No transaction value or
        # client-supplied calldata participates in reconstruction.
        _run([
            "cast", "send", release.distributor, plan.calldata,
            "--rpc-url", rpc_url, "--unlocked", "--from", PAYER, "--json",
        ])

        admission_after = _view_words(
            rpc_url,
            release.distributor,
            "collaborationFundingReservation(bytes32)",
            reservation_id,
            10,
        )
        settlement_state = _view_words(
            rpc_url,
            release.distributor,
            "fundingReservationSettlementState(bytes32)",
            reservation_id,
            8,
        )

        pending_a = _pending(rpc_url, release.distributor, OWNER_A)
        pending_b = _pending(rpc_url, release.distributor, OWNER_B)
        held = _balance(rpc_url, release.distributor)

        _run(["cast", "send", release.distributor, "withdraw()", "--rpc-url", rpc_url, "--unlocked", "--from", OWNER_A, "--json"])
        _run(["cast", "send", release.distributor, "withdraw()", "--rpc-url", rpc_url, "--unlocked", "--from", OWNER_B, "--json"])
        drained = _balance(rpc_url, release.distributor)

        ok = (
            release.fresh_state_verified
            and release.active_state_verified
            and pending_a == AMOUNT_A
            and pending_b == AMOUNT_B
            and held == plan.total_amount
            and drained == 0
            and plan.prefunded
            and "--value" not in plan.cast_command
            and admission_before[0] == 1
            and admission_before[1] == 0
            and _word_address(admission_before[2]) == PAYER.lower()
            and admission_before[3] == 0
            and admission_before[4] == plan.total_amount
            and _word_bytes32(admission_before[5]) == owners_amounts_hash
            and _word_bytes32(admission_before[6])
            == release.release_policy_commitment
            and _word_bytes32(admission_before[7]) == EXECUTION_COMMITMENT
            and admission_before[8] == refund_after
            and admission_before[9] == plan.total_amount
            and admission_after[0] == 0
            and admission_after[1] == 1
            and admission_after[9] == 0
            and settlement_state[0:3] == [1, 1, 1]
            and _word_bytes32(settlement_state[3]) == SETTLEMENT_ID
            and settlement_state[4] == 1
            and settlement_state[5] == 0
            and settlement_state[6] == plan.total_amount
            and _word_bytes32(settlement_state[7]) == owners_amounts_hash
        )
        summary = {
            "proof": "royalty_prefunded_settle_reserved_plan_executes_anvil",
            "contract_address": release.distributor,
            "anchor_address": release.anchor,
            "fresh_owner_paused_empty_authority_verified": release.fresh_state_verified,
            "timelocked_active_release_verified": release.active_state_verified,
            "anchor_currentness_verified": True,
            "dual_erc1271_authorizations_verified": True,
            "erc1271_signers_are_local_test_doubles": True,
            "tdx_or_qvl_evidence_claimed": False,
            "deterministic_reservation_id_verified": (
                authorization.funding_reservation_id == reservation_id
            ),
            "active_prefunding_verified_before_handoff": admission_before[0] == 1,
            "no_value_settle_reserved_calldata_verified": (
                plan.prefunded and "--value" not in plan.cast_command
            ),
            "permanent_consumed_reconciliation_verified": (
                admission_after[1] == 1
                and admission_after[9] == 0
                and settlement_state[0:3] == [1, 1, 1]
            ),
            "plan_total_matches": held == plan.total_amount,
            "pending_owner_a_matches_plan": pending_a == AMOUNT_A,
            "pending_owner_b_matches_plan": pending_b == AMOUNT_B,
            "drained_to_zero_after_withdraw": drained == 0,
            "plan_executes_and_conserves": ok,
            "raw_secret_egress": False,
        }
        print(json.dumps(summary, indent=2))
        return 0 if ok else 1
    finally:
        anvil.terminate()
        try:
            anvil.wait(timeout=5)
        except subprocess.TimeoutExpired:
            anvil.kill()
            anvil.wait(timeout=5)


def _load_royalty_harness() -> ModuleType:
    path = Path(__file__).with_name("prove-royalty-distributor-anvil.py")
    spec = importlib.util.spec_from_file_location("dnai_royalty_anvil_harness", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the RoyaltyDistributor Anvil harness")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _funding_reservation_tuple(
    *,
    release_policy_commitment: str,
    owners_amounts_hash: str,
    refund_after: int,
) -> str:
    return "(" + ",".join(
        (
            SETTLEMENT_ID,
            "1",
            release_policy_commitment,
            ROOM_COMMITMENT,
            ROOM_STATE_COMMITMENT,
            QUERY_COMMITMENT,
            GRANT_SET_COMMITMENT,
            ALLOCATION_COMMITMENT,
            owners_amounts_hash,
            ZERO_ADDRESS,
            str(AMOUNT_A + AMOUNT_B),
            EXECUTION_COMMITMENT,
            str(refund_after),
        )
    ) + ")"


def _view_words(
    rpc_url: str,
    contract: str,
    signature: str,
    bytes32_argument: str,
    expected_words: int,
) -> list[int]:
    calldata = "0x" + keccak(signature.encode("ascii"))[:4].hex() + bytes32_argument[2:]
    request = urllib.request.Request(
        rpc_url,
        data=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_call",
                "params": [{"to": contract, "data": calldata}, "latest"],
            },
            separators=(",", ":"),
        ).encode("ascii"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.loads(response.read().decode("ascii"))
    raw = payload.get("result")
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise RuntimeError(f"invalid finalized view response: {payload!r}")
    body = raw[2:]
    if len(body) != expected_words * 64:
        raise RuntimeError(
            f"finalized view returned {len(body) // 64} words, expected {expected_words}"
        )
    return [int(body[index : index + 64], 16) for index in range(0, len(body), 64)]


def _word_address(value: int) -> str:
    return "0x" + value.to_bytes(32, "big")[-20:].hex()


def _word_bytes32(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def _pending(rpc_url: str, contract: str, owner: str) -> int:
    out = _run([
        "cast", "call", contract, "pending(address,address)(uint256)",
        "0x0000000000000000000000000000000000000000", owner, "--rpc-url", rpc_url,
    ]).strip()
    return int(out.split()[0]) if out else 0


def _balance(rpc_url: str, address: str) -> int:
    return int(_run(["cast", "balance", address, "--rpc-url", rpc_url]).strip())


def _start_anvil(port: int) -> subprocess.Popen:
    return subprocess.Popen(
        ["anvil", "--port", str(port), "--chain-id", "31337"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT, text=True,
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_rpc(rpc_url: str) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            int(_run(["cast", "block-number", "--rpc-url", rpc_url]).strip())
            return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("Anvil RPC did not become ready")


def _clean_env() -> dict[str, str]:
    env = dict(os.environ)
    env.pop("ETH_PRIVATE_KEY", None)
    env.pop("PRIVATE_KEY", None)
    return env


def _run_json(args: list[str], *, cwd: Path | None = None) -> dict[str, Any]:
    return json.loads(_run(args, cwd=cwd))


def _run(args: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        args, cwd=cwd or ROOT, env=_clean_env(), check=False,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(args)}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result.stdout


if __name__ == "__main__":
    raise SystemExit(main())
