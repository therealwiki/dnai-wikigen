#!/usr/bin/env python3
"""Full-stack proof: bio diligence flow -> derived plan -> on-chain settlement.

Runs a real synthetic-assay diligence flow in Python, derives the royalty
distribution plan from the settled receipt, deploys RoyaltyDistributor on Anvil,
broadcasts the plan's exact calldata, and asserts each owner was credited the
flow's payout and the contract drains to zero after withdrawal. Anvil unlocked
accounts only — no raw keys, no dstack. Emits a bounded JSON summary.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from tinker_delegate.bio_data_quality import DataQualityBand
from tinker_delegate.bio_dual_use import DualUseTier
from tinker_delegate.bio_evaluators import SyntheticAssay, evaluate_synthetic_assay_qc
from tinker_delegate.bio_reid import ReidRiskBand
from tinker_delegate.diligence_flow import (
    FlowDecision,
    distribution_plan_from_flow,
    run_bio_diligence_flow,
)
from tinker_delegate.rental_stages import RentalStage, default_rental_ladder
from tinker_delegate.royalty_settlement import OwnerShare

ROOT = Path(__file__).resolve().parents[3]
CONTRACTS_DIR = ROOT / "⚙️" / "tinker-delegate" / "contracts"

DEPLOYER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
PAYER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
OWNER_A = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
OWNER_B = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"

QUERY_REF = "0x" + "d4" * 32
ROYALTY_TOTAL = 1_000_000_000  # 1 gwei, split 70/30


class _StubBand:
    def __init__(self, value):
        self.quality_band = value
        self.risk_band = value
        self.tier = value


def _run_flow():
    assay = SyntheticAssay(
        positive_controls=(100.0, 102.0, 98.0, 101.0),
        negative_controls=(10.0, 9.0, 11.0, 10.5),
        replicates=3,
    )
    receipt = run_bio_diligence_flow(
        result_candidate=evaluate_synthetic_assay_qc(assay),
        data_quality=type("DQ", (), {"quality_band": DataQualityBand.GOOD})(),
        reid=type("RE", (), {"risk_band": ReidRiskBand.LOW})(),
        dual_use=type("DU", (), {"tier": DualUseTier.CLEARED})(),
        bounded_result={"raw_secret_egress": False},
        offer_wei=5, offer_cap_wei=10, cost_wei=3, budget_wei=10,
        ladder=default_rental_ladder(),
        current_stage=RentalStage.RAW_INSPECTION,
        target_stage=RentalStage.TRAINING,
        consent_ok=True,
        payment_wei=10**16,
        royalty_total=ROYALTY_TOTAL,
        royalty_shares=[OwnerShare("owner-a", 7000), OwnerShare("owner-b", 3000)],
    )
    return receipt


def main() -> int:
    receipt = _run_flow()
    if receipt.flow_decision != FlowDecision.PROCEED:
        print(json.dumps({"proof": "diligence_flow_settlement_anvil", "flow_decision": receipt.flow_decision.value, "ok": False}))
        return 1
    expected = {p["owner_ref"]: p["amount"] for p in receipt.royalty_payouts}

    port = _free_port()
    rpc_url = f"http://127.0.0.1:{port}"
    anvil = _start_anvil(port)
    try:
        _wait_for_rpc(rpc_url)
        contract = _deploy(rpc_url)

        plan = distribution_plan_from_flow(
            receipt,
            contract_address=contract,
            query_ref=QUERY_REF,
            owner_addresses={"owner-a": OWNER_A, "owner-b": OWNER_B},
        )
        _run([
            "cast", "send", contract, plan.calldata,
            "--value", str(plan.total_amount),
            "--rpc-url", rpc_url, "--unlocked", "--from", PAYER, "--json",
        ])

        pending_a = _pending(rpc_url, contract, OWNER_A)
        pending_b = _pending(rpc_url, contract, OWNER_B)
        held = _balance(rpc_url, contract)

        _run(["cast", "send", contract, "withdraw()", "--rpc-url", rpc_url, "--unlocked", "--from", OWNER_A, "--json"])
        _run(["cast", "send", contract, "withdraw()", "--rpc-url", rpc_url, "--unlocked", "--from", OWNER_B, "--json"])
        drained = _balance(rpc_url, contract)

        ok = (
            pending_a == expected["owner-a"]
            and pending_b == expected["owner-b"]
            and held == plan.total_amount
            and drained == 0
        )
        summary = {
            "proof": "diligence_flow_settlement_anvil",
            "flow_decision": receipt.flow_decision.value,
            "contract_address": contract,
            "owner_a_credited_flow_payout": pending_a == expected["owner-a"],
            "owner_b_credited_flow_payout": pending_b == expected["owner-b"],
            "held_full_total": held == plan.total_amount,
            "drained_to_zero_after_withdraw": drained == 0,
            "flow_to_settlement_conserves": ok,
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


def _deploy(rpc_url: str) -> str:
    output = _run_json([
        "forge", "create", "src/RoyaltyDistributor.sol:RoyaltyDistributor",
        "--rpc-url", rpc_url, "--unlocked", "--from", DEPLOYER, "--broadcast", "--json",
    ], cwd=CONTRACTS_DIR)
    address = output.get("deployedTo") or output.get("contractAddress")
    if not address:
        raise RuntimeError("forge create did not return a deployed address")
    return str(address)


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
