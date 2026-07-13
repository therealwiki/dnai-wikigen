#!/usr/bin/env python3
"""Prove that a `build_royalty_distribution_plan` plan executes correctly on Anvil.

This closes the loop on the bounded distribution plan: it deploys
RoyaltyDistributor, builds a native distribution plan with the Python builder,
broadcasts the plan's *exact calldata* (the value verified against `cast
calldata` in unit tests), then withdraws and asserts the contract drains to zero
and each owner was credited the planned amount. Anvil unlocked accounts only — no
raw keys, no dstack. Emits a bounded JSON summary.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from tinker_delegate.royalty_distribution_plan import (
    DistributionRecipient,
    build_royalty_distribution_plan,
)

ROOT = Path(__file__).resolve().parents[3]
TINKER_DIR = ROOT / "⚙️" / "tinker-delegate"
CONTRACTS_DIR = TINKER_DIR / "contracts"

DEPLOYER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
PAYER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
OWNER_A = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
OWNER_B = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"

QUERY_REF = "0x" + "b2" * 32
AMOUNT_A = 700_000_000_000_000_000  # 0.7 ETH
AMOUNT_B = 300_000_000_000_000_000  # 0.3 ETH


def main() -> int:
    port = _free_port()
    rpc_url = f"http://127.0.0.1:{port}"
    anvil = _start_anvil(port)
    try:
        _wait_for_rpc(rpc_url)
        contract = _deploy(rpc_url)

        plan = build_royalty_distribution_plan(
            contract_address=contract,
            query_ref=QUERY_REF,
            recipients=[
                DistributionRecipient(OWNER_A, AMOUNT_A),
                DistributionRecipient(OWNER_B, AMOUNT_B),
            ],
        )

        # Broadcast the plan's exact calldata (raw), proving the builder output works.
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
            pending_a == AMOUNT_A
            and pending_b == AMOUNT_B
            and held == plan.total_amount
            and drained == 0
        )
        summary = {
            "proof": "royalty_distribution_plan_executes_anvil",
            "contract_address": contract,
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
