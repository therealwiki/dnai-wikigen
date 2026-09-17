#!/usr/bin/env python3
"""Prove the DiligenceRoom on-chain compose-approval gate against real Anvil.

This is a local-mode, synthetic proof, not a production admission or TEE proof.
It uses Anvil's unlocked default accounts (``cast --unlocked --from``), stages
and freezes separate result/QVL signer bindings through their real timelocks,
enables ``composeApprovalRequired``, and drives the current nine-argument
``submitResult`` on a funded deal:

1. Gate ON, compose UNAPPROVED  -> ``submitResult`` reverts ComposeHashNotApproved.
2. developer proposes the compose hash, waits the fixed two-day on-chain
   admission timelock, and activates it.
3. Gate ON, compose APPROVED    -> the same call now passes the gate and reverts
   later on the dummy verifier signature (InvalidResultAuthorization).
4. developer ``revokeComposeHash(compose)`` -> back to ComposeHashNotApproved.

The revert reason moving past the gate (1->3) and back (4) proves the gate admits
exactly governance-approved measurements in this isolated local configuration.
Production mode deliberately fails earlier with AttestationBindingNotReady
when its exact one-compose admission set is missing or revoked; weakening that
outer guard to obtain this local proof would be incorrect. The setup mirrors
contracts/test/DiligenceRoom.t.sol's local setUp and compose-gate tests.

No dstack, genuine QVL evidence, valid result signature, external RPC, or raw
private key is used. The bounded JSON summary preserves those truth boundaries.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from eth_hash.auto import keccak

ROOT = Path(__file__).resolve().parents[3]
TINKER_DIR = ROOT / "⚙️" / "tinker-delegate"
CONTRACTS_DIR = TINKER_DIR / "contracts"

# Deterministic Anvil default accounts (unlocked; no raw keys used here).
DEVELOPER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # deploys -> developer
SELLER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
VERIFIER = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
ATTESTATION_VERIFIER = "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"
TEE = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
BUYER = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"
ZERO_ADDRESS = "0x" + "00" * 20
LOCAL_CHAIN_ID = 31337

ARTIFACT_HASH = "0x" + "ab" * 32
COMPOSE_HASH = "0x" + "e5" * 32
ATTESTATION_RELEASE_POLICY_HASH = "0x" + "c4" * 32
ATTESTATION_EVIDENCE_HASH = "0x" + "d8" * 32
EVALUATOR_POLICY_COMMITMENT = "0x" + "a9" * 32
DUMMY_SIG = "0x" + "11" * 65
SUBMIT_RESULT_SIGNATURE = "submitResult(uint256,uint8,uint256,bytes32,uint256,bytes32,uint256,bytes,bytes)"

COMPOSE_NOT_APPROVED_SELECTOR = "0x" + keccak(b"ComposeHashNotApproved()")[:4].hex()
INVALID_AUTHORIZATION_SELECTOR = "0x" + keccak(b"InvalidResultAuthorization()")[:4].hex()
EARLY_ADMISSION_SELECTOR = "0x" + keccak(b"AdmissionActivationTooEarly(uint256)")[:4].hex()
EARLY_RESULT_BINDING_SELECTOR = "0x" + keccak(b"ResultVerifierActivationTooEarly(uint256)")[:4].hex()
EARLY_ATTESTATION_BINDING_SELECTOR = "0x" + keccak(b"AttestationBindingActivationTooEarly(uint256)")[:4].hex()


def main() -> int:
    port = _free_port()
    rpc_url = f"http://127.0.0.1:{port}"
    anvil = _start_anvil(port)
    try:
        _wait_for_rpc(rpc_url)
        _assert_local_chain(rpc_url)
        contract = _deploy(rpc_url)
        _configure_authorization_bindings(rpc_url, contract)
        admission_delay = _read_uint(rpc_url, contract, "ADMISSION_TIMELOCK_DELAY()(uint256)")
        if admission_delay != 172800:
            raise RuntimeError("compose admission timelock differs from the reviewed two-day policy")
        _send(rpc_url, DEVELOPER, contract, "setComposeApprovalRequired(bool)", ["true"])
        _require_readback(rpc_url, contract, "composeApprovalRequired()(bool)", "true")
        _create_deal(rpc_url, contract)
        _fund_deal(rpc_url, contract)

        unapproved = _submit_revert_reason(rpc_url, contract)
        _send(rpc_url, DEVELOPER, contract, "proposeComposeHash(bytes32)", [COMPOSE_HASH])
        pending = _read_uint(rpc_url, contract, "pendingComposeActivations(bytes32)(uint256)", [COMPOSE_HASH])
        if pending != _block_timestamp(rpc_url) + admission_delay:
            raise RuntimeError("compose proposal did not establish the exact on-chain admission delay")
        early = _call_revert_reason(rpc_url, DEVELOPER, contract, "activateComposeHash(bytes32)", [COMPOSE_HASH])
        _require_selector(early, EARLY_ADMISSION_SELECTOR)
        _require_readback(rpc_url, contract, "pendingComposeCount()(uint256)", "1")
        _require_readback(rpc_url, contract, "approvedComposeCount()(uint256)", "0")
        _advance_to(rpc_url, pending)
        _require_selector(_submit_revert_reason(rpc_url, contract), COMPOSE_NOT_APPROVED_SELECTOR)
        _send(rpc_url, DEVELOPER, contract, "activateComposeHash(bytes32)", [COMPOSE_HASH])
        _require_readback(rpc_url, contract, "approvedComposeHashes(bytes32)(bool)", "true", [COMPOSE_HASH])
        _require_readback(rpc_url, contract, "pendingComposeCount()(uint256)", "0")
        _require_readback(rpc_url, contract, "approvedComposeCount()(uint256)", "1")
        _require_readback(rpc_url, contract, "pendingComposeActivations(bytes32)(uint256)", "0", [COMPOSE_HASH])
        approved = _submit_revert_reason(rpc_url, contract)
        _send(rpc_url, DEVELOPER, contract, "revokeComposeHash(bytes32)", [COMPOSE_HASH])
        _require_readback(rpc_url, contract, "approvedComposeHashes(bytes32)(bool)", "false", [COMPOSE_HASH])
        _require_readback(rpc_url, contract, "approvedComposeCount()(uint256)", "0")
        revoked = _submit_revert_reason(rpc_url, contract)

        ok = (
            _is_selector(unapproved, COMPOSE_NOT_APPROVED_SELECTOR)
            and _is_selector(approved, INVALID_AUTHORIZATION_SELECTOR)
            and _is_selector(revoked, COMPOSE_NOT_APPROVED_SELECTOR)
        )
        summary = {
            "proof": "diligence_room_compose_approval_gate_anvil",
            "proof_scope": "local_mode_synthetic_compose_gate_only",
            "chain_id": LOCAL_CHAIN_ID,
            "contract_address": contract,
            "production_release": False,
            "production_e2e": False,
            "genuine_attestation_evidence": False,
            "authorization_bindings_frozen": True,
            "authorization_binding_timelocks_checked": True,
            "gate_required": True,
            "admission_timelock_seconds": admission_delay,
            "early_compose_activation_rejected": True,
            "elapsed_timelock_alone_does_not_admit": True,
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
        "--broadcast", "--json", "--constructor-args", "false", ZERO_ADDRESS,
    ], cwd=CONTRACTS_DIR)
    address = output.get("deployedTo") or output.get("contractAddress")
    if not address:
        raise RuntimeError("forge create did not return a deployed address")
    return str(address)


def _configure_authorization_bindings(rpc_url: str, contract: str) -> None:
    _require_readback(rpc_url, contract, "productionRelease()(bool)", "false")
    _require_readback(rpc_url, contract, "releaseGovernanceController()(address)", ZERO_ADDRESS)
    _require_readback(rpc_url, contract, "developer()(address)", DEVELOPER)
    delay = _read_uint(rpc_url, contract, "ATTESTATION_BINDING_TIMELOCK_DELAY()(uint256)")
    if delay != 172800:
        raise RuntimeError("authorization binding timelock differs from the reviewed two-day policy")
    _send(rpc_url, DEVELOPER, contract, "proposeResultVerifier(address)", [VERIFIER])
    result_at = _read_uint(rpc_url, contract, "pendingResultVerifierActivatesAt()(uint256)")
    if result_at != _block_timestamp(rpc_url) + delay:
        raise RuntimeError("result signer proposal did not establish the exact on-chain delay")
    _send(rpc_url, DEVELOPER, contract, "proposeAttestationBinding(address,bytes32)",
          [ATTESTATION_VERIFIER, ATTESTATION_RELEASE_POLICY_HASH])
    attestation_at = _read_uint(rpc_url, contract, "pendingAttestationBindingActivatesAt()(uint256)")
    if attestation_at != _block_timestamp(rpc_url) + delay:
        raise RuntimeError("attestation signer proposal did not establish the exact on-chain delay")
    _require_selector(_call_revert_reason(rpc_url, DEVELOPER, contract, "activateResultVerifier()", []),
                      EARLY_RESULT_BINDING_SELECTOR)
    _require_selector(_call_revert_reason(rpc_url, DEVELOPER, contract, "activateAttestationBinding()", []),
                      EARLY_ATTESTATION_BINDING_SELECTOR)
    _advance_to(rpc_url, max(result_at, attestation_at))
    _send(rpc_url, DEVELOPER, contract, "activateResultVerifier()", [])
    _send(rpc_url, DEVELOPER, contract, "freezeResultVerifier()", [])
    _send(rpc_url, DEVELOPER, contract, "activateAttestationBinding()", [])
    _send(rpc_url, DEVELOPER, contract, "freezeAttestationBinding()", [])
    for signature, expected in (
        ("resultVerifier()(address)", VERIFIER),
        ("attestationVerifier()(address)", ATTESTATION_VERIFIER),
        ("attestationReleasePolicyHash()(bytes32)", ATTESTATION_RELEASE_POLICY_HASH),
        ("resultVerifierFrozen()(bool)", "true"),
        ("attestationBindingFrozen()(bool)", "true"),
    ):
        _require_readback(rpc_url, contract, signature, expected)


def _create_deal(rpc_url: str, contract: str) -> int:
    # The local chain has already advanced through the signer admission window.
    expiry = _block_timestamp(rpc_url) + (3 * 24 * 60 * 60)
    _send(
        rpc_url, SELLER, contract,
        "createDeal(uint256,uint256,bytes32,address)",
        ["1000000000000000", str(expiry), ARTIFACT_HASH, TEE],
    )
    return expiry


def _fund_deal(rpc_url: str, contract: str) -> None:
    _send(rpc_url, BUYER, contract, "fundDeal(uint256,bytes32)",
          ["0", EVALUATOR_POLICY_COMMITMENT], value="1ether")


def _advance_to(rpc_url: str, timestamp: int) -> None:
    if timestamp <= _block_timestamp(rpc_url):
        raise RuntimeError("expected a pending on-chain timelock")
    _run(["cast", "rpc", "evm_setNextBlockTimestamp", str(timestamp), "--rpc-url", rpc_url])
    _run(["cast", "rpc", "evm_mine", "--rpc-url", rpc_url])


def _read(rpc_url: str, contract: str, signature: str, args: list[str] | None = None) -> str:
    return _run(["cast", "call", contract, signature, *(args or []), "--rpc-url", rpc_url]).strip()


def _read_uint(rpc_url: str, contract: str, signature: str, args: list[str] | None = None) -> int:
    return int(_read(rpc_url, contract, signature, args).split()[0])


def _require_readback(rpc_url: str, contract: str, signature: str, expected: str,
                      args: list[str] | None = None) -> None:
    if _read(rpc_url, contract, signature, args).lower() != expected.lower():
        raise RuntimeError(f"unexpected on-chain readback for {signature}")


def _block_timestamp(rpc_url: str) -> int:
    block = _run_json(["cast", "block", "latest", "--rpc-url", rpc_url, "--json"])
    value = block["timestamp"]
    return int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value)


def _submit_revert_reason(rpc_url: str, contract: str) -> str:
    """Use fresh bounded leases and synthetic evidence; neither signature is valid."""
    now = _block_timestamp(rpc_url)
    return _call_revert_reason(rpc_url, TEE, contract, SUBMIT_RESULT_SIGNATURE, [
        "0", "3", "1000000000000000", COMPOSE_HASH, str(now + 300),
        ATTESTATION_EVIDENCE_HASH, str(now + 240), DUMMY_SIG, DUMMY_SIG,
    ])


def _call_revert_reason(rpc_url: str, sender: str, contract: str, signature: str, values: list[str]) -> str:
    args = ["cast", "call", contract, signature, *values, "--from", sender, "--rpc-url", rpc_url]
    result = subprocess.run(
        args, cwd=CONTRACTS_DIR, env=_clean_env(), check=False,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        raise RuntimeError(f"{signature} unexpectedly succeeded")
    return (result.stdout + "\n" + result.stderr).strip()


def _is_selector(revert_output: str, selector: str) -> bool:
    text = revert_output.lower()
    if selector.lower() in text:
        return True
    # cast may decode the custom error by name instead of returning the selector.
    names = {
        COMPOSE_NOT_APPROVED_SELECTOR: "composehashnotapproved",
        INVALID_AUTHORIZATION_SELECTOR: "invalidresultauthorization",
        EARLY_ADMISSION_SELECTOR: "admissionactivationtooearly",
        EARLY_RESULT_BINDING_SELECTOR: "resultverifieractivationtooearly",
        EARLY_ATTESTATION_BINDING_SELECTOR: "attestationbindingactivationtooearly",
    }
    return names.get(selector, "\0") in text


def _require_selector(revert_output: str, selector: str) -> None:
    if not _is_selector(revert_output, selector):
        raise RuntimeError(f"expected local contract error {selector}, got {revert_output}")


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
        ["anvil", "--host", "127.0.0.1", "--port", str(port), "--chain-id", str(LOCAL_CHAIN_ID)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT, env=_clean_env(), text=True,
    )


def _assert_local_chain(rpc_url: str) -> None:
    endpoint = urlsplit(rpc_url)
    if (endpoint.scheme != "http" or endpoint.hostname != "127.0.0.1"
            or endpoint.username is not None or endpoint.password is not None
            or endpoint.port is None or endpoint.path or endpoint.query or endpoint.fragment):
        raise RuntimeError("proof requires its own loopback-only Anvil RPC")
    if int(_run(["cast", "chain-id", "--rpc-url", rpc_url]).strip()) != LOCAL_CHAIN_ID:
        raise RuntimeError("proof requires disposable local chain 31337")


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
