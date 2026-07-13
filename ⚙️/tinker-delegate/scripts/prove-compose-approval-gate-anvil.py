#!/usr/bin/env python3
"""Prove the DiligenceRoom on-chain compose-approval gate against real Anvil.

This isolates the gate cleanly without needing dstack, a real verifier
signature, or any raw private keys. It uses Anvil's unlocked default accounts
(``cast --unlocked --from``), enables ``composeApprovalRequired``, and drives
``submitResult`` on a funded deal whose only failing precondition is the gate:

1. Gate ON, compose UNAPPROVED  -> ``submitResult`` reverts ComposeHashNotApproved.
2. developer ``approveComposeHash(compose)``.
3. Gate ON, compose APPROVED    -> the same call now passes the gate and reverts
   later on the dummy verifier signature (InvalidResultAuthorization).
4. developer ``revokeComposeHash(compose)`` -> back to ComposeHashNotApproved.

The revert reason moving past the gate (1->3) and back (4) proves the gate admits
exactly governance-approved measurements. It prints a bounded JSON summary and
never accepts or prints raw private keys.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from eth_hash.auto import keccak

ROOT = Path(__file__).resolve().parents[3]
TINKER_DIR = ROOT / "⚙️" / "tinker-delegate"
CONTRACTS_DIR = TINKER_DIR / "contracts"

# Deterministic Anvil default accounts (unlocked; no raw keys used here).
DEVELOPER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # deploys -> developer
SELLER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
VERIFIER = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
TEE = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
BUYER = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"

ARTIFACT_HASH = "0x" + "ab" * 32
RESULT_HASH = "0x" + "cd" * 32
COMPOSE_HASH = "0x" + "e5" * 32
DUMMY_SIG = "0x" + "11" * 65

COMPOSE_NOT_APPROVED_SELECTOR = "0x" + keccak(b"ComposeHashNotApproved()")[:4].hex()
INVALID_AUTHORIZATION_SELECTOR = "0x" + keccak(b"InvalidResultAuthorization()")[:4].hex()


def main() -> int:
    port = _free_port()
    rpc_url = f"http://127.0.0.1:{port}"
    anvil = _start_anvil(port)
    try:
        _wait_for_rpc(rpc_url)
        contract = _deploy(rpc_url)

        _send(rpc_url, DEVELOPER, contract, "setComposeApprovalRequired(bool)", ["true"])
        expiry = _create_deal(rpc_url, contract)
        _fund_deal(rpc_url, contract)
        auth_expiry = int(time.time()) + 3600

        unapproved = _submit_revert_reason(rpc_url, contract, auth_expiry)
        _send(rpc_url, DEVELOPER, contract, "approveComposeHash(bytes32)", [COMPOSE_HASH])
        approved = _submit_revert_reason(rpc_url, contract, auth_expiry)
        _send(rpc_url, DEVELOPER, contract, "revokeComposeHash(bytes32)", [COMPOSE_HASH])
        revoked = _submit_revert_reason(rpc_url, contract, auth_expiry)

        ok = (
            _is_selector(unapproved, COMPOSE_NOT_APPROVED_SELECTOR)
            and _is_selector(approved, INVALID_AUTHORIZATION_SELECTOR)
            and _is_selector(revoked, COMPOSE_NOT_APPROVED_SELECTOR)
        )
        summary = {
            "proof": "diligence_room_compose_approval_gate_anvil",
            "contract_address": contract,
            "gate_required": True,
            "revert_when_unapproved": _classify(unapproved),
            "revert_when_approved": _classify(approved),
            "revert_after_revoke": _classify(revoked),
            "gate_admits_only_approved": ok,
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
        "forge", "create", "src/DiligenceRoom.sol:DiligenceRoom",
        "--rpc-url", rpc_url, "--unlocked", "--from", DEVELOPER,
        "--broadcast", "--json", "--constructor-args", VERIFIER,
    ], cwd=CONTRACTS_DIR)
    address = output.get("deployedTo") or output.get("contractAddress")
    if not address:
        raise RuntimeError("forge create did not return a deployed address")
    return str(address)


def _create_deal(rpc_url: str, contract: str) -> int:
    expiry = int(time.time()) + 3600
    _send(
        rpc_url, SELLER, contract,
        "createDeal(uint256,uint256,bytes32,address)",
        ["1000000000000000", str(expiry), ARTIFACT_HASH, TEE],
    )
    return expiry


def _fund_deal(rpc_url: str, contract: str) -> None:
    _send(rpc_url, BUYER, contract, "fundDeal(uint256)", ["0"], value="1ether")


def _submit_revert_reason(rpc_url: str, contract: str, auth_expiry: int) -> str:
    """cast call submitResult from the TEE account; return the revert output."""
    args = [
        "cast", "call", contract,
        "submitResult(uint256,uint8,uint256,bytes32,bytes32,uint256,bytes)",
        "0", "3", "1000000000000000", RESULT_HASH, COMPOSE_HASH, str(auth_expiry), DUMMY_SIG,
        "--from", TEE, "--rpc-url", rpc_url,
    ]
    result = subprocess.run(
        args, cwd=CONTRACTS_DIR, env=_clean_env(), check=False,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        raise RuntimeError(f"submitResult unexpectedly succeeded: {result.stdout}")
    return (result.stdout + "\n" + result.stderr).strip()


def _is_selector(revert_output: str, selector: str) -> bool:
    text = revert_output.lower()
    if selector.lower() in text:
        return True
    # cast may decode the custom error by name instead of returning the selector.
    names = {
        COMPOSE_NOT_APPROVED_SELECTOR: "composehashnotapproved",
        INVALID_AUTHORIZATION_SELECTOR: "invalidresultauthorization",
    }
    return names.get(selector, "\0") in text


def _classify(revert_output: str) -> str:
    if _is_selector(revert_output, COMPOSE_NOT_APPROVED_SELECTOR):
        return "ComposeHashNotApproved"
    if _is_selector(revert_output, INVALID_AUTHORIZATION_SELECTOR):
        return "InvalidResultAuthorization"
    return "unknown"


def _send(rpc_url: str, sender: str, to: str, sig: str, args: list[str], *, value: str = "") -> str:
    cmd = ["cast", "send", to, sig, *args, "--rpc-url", rpc_url, "--unlocked", "--from", sender, "--json"]
    if value:
        cmd += ["--value", value]
    output = _run_json(cmd)
    return str(output.get("transactionHash") or output.get("transaction_hash") or "")


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
