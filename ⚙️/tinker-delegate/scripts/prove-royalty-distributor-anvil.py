#!/usr/bin/env python3
"""Prove the authorized RoyaltyDistributor v3 path end-to-end on real Anvil.

No dstack and no raw private keys: the proof uses Anvil's unlocked accounts plus
two local ERC-1271 signer doubles. It proves the fresh fail-closed constructor
state, timelocked anchor and distributor admission, an exact anchored
dual-approved native settlement, and conserving owner withdrawals. The signer
doubles prove contract-signature plumbing only; they are not TDX/QVL evidence.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from tinker_delegate.royalty_distribution_plan import (
    DistributionRecipient,
    SettlementAuthorization,
    build_royalty_distribution_plan,
    compute_owner_amounts_hash,
)

ROOT = Path(__file__).resolve().parents[3]
TINKER_DIR = ROOT / "⚙️" / "tinker-delegate"
CONTRACTS_DIR = TINKER_DIR / "contracts"

# Deterministic Anvil default accounts (unlocked; no raw keys used here).
DEPLOYER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
PAYER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
OWNER_A = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
OWNER_B = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
ANCHOR_WRITER = "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"

ZERO_ADDRESS = "0x" + "00" * 20
ZERO_BYTES32 = "0x" + "00" * 32
DEPLOYMENT_INTENT = "0x" + "11" * 32
REVIEWER_GENESIS = "0x" + "22" * 32
ANCHOR_WRITER_RELEASE = "0x" + "33" * 32
SETTLEMENT_ID = "0x" + "a1" * 32
ROOM_COMMITMENT = "0x" + "a2" * 32
ROOM_STATE_COMMITMENT = "0x" + "a3" * 32
QUERY_COMMITMENT = "0x" + "a4" * 32
GRANT_SET_COMMITMENT = "0x" + "a5" * 32
ALLOCATION_COMMITMENT = "0x" + "a6" * 32
EXECUTION_COMMITMENT = "0x" + "a7" * 32
RESULT_COMMITMENT = "0x" + "a8" * 32
USAGE_COMMITMENT = "0x" + "a9" * 32
ATTESTATION_EVIDENCE_HASH = "0x" + "aa" * 32
AUTHORIZATION_TUPLE = (
    "(bytes32,uint256,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,"
    "address,uint256,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint256)"
)
AMOUNT_A = 700_000_000_000_000_000  # 0.7 ETH
AMOUNT_B = 300_000_000_000_000_000  # 0.3 ETH
TOTAL = AMOUNT_A + AMOUNT_B


@dataclass(frozen=True)
class ConfiguredRelease:
    distributor: str
    anchor: str
    settlement_signer: str
    qvl_signer: str
    release_policy_commitment: str
    fresh_state_verified: bool
    active_state_verified: bool


def main() -> int:
    port = _free_port()
    rpc_url = f"http://127.0.0.1:{port}"
    anvil = _start_anvil(port)
    try:
        _wait_for_rpc(rpc_url)
        release = _deploy_configured_release(rpc_url)
        recipients = [
            DistributionRecipient(OWNER_A, AMOUNT_A),
            DistributionRecipient(OWNER_B, AMOUNT_B),
        ]
        authorization, settlement_signature, qvl_signature = _authorize_native_settlement(
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
        )
        plan = build_royalty_distribution_plan(
            contract_address=release.distributor,
            authorization=authorization,
            recipients=recipients,
            settlement_signature=settlement_signature,
            qvl_signature=qvl_signature,
        )
        _send_raw(rpc_url, PAYER, release.distributor, plan.calldata, value=str(plan.total_amount))

        pending_a = _pending(rpc_url, release.distributor, OWNER_A)
        pending_b = _pending(rpc_url, release.distributor, OWNER_B)
        contract_balance_after_distribute = _balance(rpc_url, release.distributor)

        _send(rpc_url, OWNER_A, release.distributor, "withdraw()", [])
        _send(rpc_url, OWNER_B, release.distributor, "withdraw()", [])
        # Owners pay gas, so compare pending credited vs balance delta approximately
        # via the contract draining to exactly zero (the strict conservation proof).
        contract_balance_after_withdraw = _balance(rpc_url, release.distributor)

        ok = (
            release.fresh_state_verified
            and release.active_state_verified
            and pending_a == AMOUNT_A
            and pending_b == AMOUNT_B
            and contract_balance_after_distribute == TOTAL
            and contract_balance_after_withdraw == 0
        )
        summary = {
            "proof": "royalty_distributor_v3_authorized_pull_payment_anvil",
            "contract_address": release.distributor,
            "anchor_address": release.anchor,
            "fresh_owner_paused_empty_authority_verified": release.fresh_state_verified,
            "timelocked_active_release_verified": release.active_state_verified,
            "anchor_currentness_verified": True,
            "dual_erc1271_authorizations_verified": True,
            "erc1271_signers_are_local_test_doubles": True,
            "tdx_or_qvl_evidence_claimed": False,
            "pending_owner_a_matches": pending_a == AMOUNT_A,
            "pending_owner_b_matches": pending_b == AMOUNT_B,
            "held_full_total_after_distribute": contract_balance_after_distribute == TOTAL,
            "drained_to_zero_after_withdraw": contract_balance_after_withdraw == 0,
            "conserved": ok,
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


def _deploy_contract(rpc_url: str, source: str, constructor_args: list[str] | None = None) -> str:
    command = [
        "forge",
        "create",
        source,
        "--rpc-url",
        rpc_url,
        "--unlocked",
        "--from",
        DEPLOYER,
        "--broadcast",
        "--json",
    ]
    if constructor_args:
        command.extend(["--constructor-args", *constructor_args])
    output = _run_json(command, cwd=CONTRACTS_DIR)
    address = output.get("deployedTo") or output.get("contractAddress")
    if not address:
        raise RuntimeError("forge create did not return a deployed address")
    return str(address)


def _deploy_configured_release(rpc_url: str) -> ConfiguredRelease:
    anchor = _deploy_contract(
        rpc_url,
        "src/ExecutionPolicyAnchor.sol:ExecutionPolicyAnchor",
        [DEPLOYER, DEPLOYMENT_INTENT, REVIEWER_GENESIS],
    )
    settlement_signer = _deploy_contract(
        rpc_url, "test/RoyaltyDistributor.t.sol:MockRoyalty1271Signer"
    )
    qvl_signer = _deploy_contract(
        rpc_url, "test/RoyaltyDistributor.t.sol:MockRoyalty1271Signer"
    )
    distributor = _deploy_contract(
        rpc_url, "src/RoyaltyDistributor.sol:RoyaltyDistributor", [DEPLOYER]
    )

    fresh_state_verified = (
        _address_call(rpc_url, distributor, "owner()(address)").lower() == DEPLOYER.lower()
        and _address_call(rpc_url, distributor, "pendingOwner()(address)") == ZERO_ADDRESS
        and _bool_call(rpc_url, distributor, "paused()(bool)")
        and _uint_call(rpc_url, distributor, "authorityNonce()(uint256)") == 0
        and _address_call(rpc_url, distributor, "settlementVerifier()(address)") == ZERO_ADDRESS
        and _address_call(rpc_url, distributor, "qvlVerifier()(address)") == ZERO_ADDRESS
        and _address_call(rpc_url, distributor, "executionPolicyAnchor()(address)") == ZERO_ADDRESS
        and _bytes32_call(
            rpc_url, distributor, "anchorWriterReleaseCommitment()(bytes32)"
        )
        == ZERO_BYTES32
        and _bytes32_call(rpc_url, distributor, "releasePolicyCommitment()(bytes32)") == ZERO_BYTES32
        and _address_call(
            rpc_url, distributor, "pendingSettlementVerifier()(address)"
        )
        == ZERO_ADDRESS
        and _address_call(rpc_url, distributor, "pendingQvlVerifier()(address)")
        == ZERO_ADDRESS
        and _address_call(
            rpc_url, distributor, "pendingExecutionPolicyAnchor()(address)"
        )
        == ZERO_ADDRESS
        and _bytes32_call(
            rpc_url, distributor, "pendingAnchorWriterReleaseCommitment()(bytes32)"
        )
        == ZERO_BYTES32
        and _bytes32_call(
            rpc_url, distributor, "pendingReleasePolicyCommitment()(bytes32)"
        )
        == ZERO_BYTES32
        and _uint_call(rpc_url, distributor, "pendingAuthorityNonce()(uint256)") == 0
        and _uint_call(rpc_url, distributor, "pendingAuthorityActivatesAt()(uint64)") == 0
        and not _bool_call(rpc_url, distributor, "pendingAuthorityRevocation()(bool)")
    )
    if not fresh_state_verified:
        raise RuntimeError("RoyaltyDistributor did not deploy owner-controlled, paused, and authority-empty")

    _send(
        rpc_url,
        DEPLOYER,
        anchor,
        "proposeWriter(address,bytes32)",
        [ANCHOR_WRITER, ANCHOR_WRITER_RELEASE],
    )
    _increase_time(rpc_url, 2 * 24 * 60 * 60)
    _send(rpc_url, DEPLOYER, anchor, "activateWriter()", [])
    _send(rpc_url, DEPLOYER, anchor, "freezeWriterRotations()", [])
    _send(rpc_url, DEPLOYER, anchor, "setPaused(bool)", ["false"])

    _send(
        rpc_url,
        DEPLOYER,
        distributor,
        "proposeAuthorityBinding(address,address,address,bytes32)",
        [settlement_signer, qvl_signer, anchor, ANCHOR_WRITER_RELEASE],
    )
    _increase_time(rpc_url, 2 * 24 * 60 * 60)
    _send(rpc_url, DEPLOYER, distributor, "activateAuthorityProposal()", [])
    _send(rpc_url, DEPLOYER, distributor, "setPaused(bool)", ["false"])

    release_policy = _bytes32_call(
        rpc_url, distributor, "releasePolicyCommitment()(bytes32)"
    )
    expected_release_policy = _bytes32_call(
        rpc_url,
        distributor,
        "computeReleasePolicyCommitment(uint256,address,address,address,bytes32)(bytes32)",
        ["1", settlement_signer, qvl_signer, anchor, ANCHOR_WRITER_RELEASE],
    )
    active_state_verified = (
        _address_call(rpc_url, distributor, "owner()(address)").lower() == DEPLOYER.lower()
        and _address_call(rpc_url, distributor, "pendingOwner()(address)") == ZERO_ADDRESS
        and not _bool_call(rpc_url, distributor, "paused()(bool)")
        and _uint_call(rpc_url, distributor, "authorityNonce()(uint256)") == 1
        and _address_call(rpc_url, distributor, "settlementVerifier()(address)").lower()
        == settlement_signer.lower()
        and _address_call(rpc_url, distributor, "qvlVerifier()(address)").lower()
        == qvl_signer.lower()
        and _address_call(rpc_url, distributor, "executionPolicyAnchor()(address)").lower()
        == anchor.lower()
        and _bytes32_call(
            rpc_url, distributor, "anchorWriterReleaseCommitment()(bytes32)"
        )
        == ANCHOR_WRITER_RELEASE
        and release_policy == expected_release_policy
        and _address_call(
            rpc_url, distributor, "pendingSettlementVerifier()(address)"
        )
        == ZERO_ADDRESS
        and _address_call(rpc_url, distributor, "pendingQvlVerifier()(address)")
        == ZERO_ADDRESS
        and _address_call(
            rpc_url, distributor, "pendingExecutionPolicyAnchor()(address)"
        )
        == ZERO_ADDRESS
        and _bytes32_call(
            rpc_url, distributor, "pendingAnchorWriterReleaseCommitment()(bytes32)"
        )
        == ZERO_BYTES32
        and _bytes32_call(
            rpc_url, distributor, "pendingReleasePolicyCommitment()(bytes32)"
        )
        == ZERO_BYTES32
        and _uint_call(rpc_url, distributor, "pendingAuthorityNonce()(uint256)") == 0
        and _uint_call(rpc_url, distributor, "pendingAuthorityActivatesAt()(uint64)") == 0
        and not _bool_call(rpc_url, distributor, "pendingAuthorityRevocation()(bool)")
        and _bool_call(
            rpc_url,
            distributor,
            "settlementVerifierEverConfigured(address)(bool)",
            [settlement_signer],
        )
        and _bool_call(
            rpc_url,
            distributor,
            "qvlVerifierEverConfigured(address)(bool)",
            [qvl_signer],
        )
        and _bool_call(
            rpc_url,
            distributor,
            "anchorWriterEverConfigured(address)(bool)",
            [ANCHOR_WRITER],
        )
        and _address_call(rpc_url, anchor, "writer()(address)").lower()
        == ANCHOR_WRITER.lower()
        and _bytes32_call(rpc_url, anchor, "writerReleaseCommitment()(bytes32)")
        == ANCHOR_WRITER_RELEASE
        and _bool_call(rpc_url, anchor, "writerRotationsFrozen()(bool)")
        and not _bool_call(rpc_url, anchor, "paused()(bool)")
        and _address_call(rpc_url, anchor, "pendingOwner()(address)") == ZERO_ADDRESS
        and _address_call(rpc_url, anchor, "pendingWriter()(address)") == ZERO_ADDRESS
        and _bytes32_call(
            rpc_url, anchor, "pendingWriterReleaseCommitment()(bytes32)"
        )
        == ZERO_BYTES32
        and _uint_call(rpc_url, anchor, "pendingWriterActivatesAt()(uint64)") == 0
    )
    if not active_state_verified:
        raise RuntimeError("RoyaltyDistributor active release poststate mismatch")
    return ConfiguredRelease(
        distributor=distributor,
        anchor=anchor,
        settlement_signer=settlement_signer,
        qvl_signer=qvl_signer,
        release_policy_commitment=release_policy,
        fresh_state_verified=fresh_state_verified,
        active_state_verified=active_state_verified,
    )


def _authorize_native_settlement(
    rpc_url: str,
    release: ConfiguredRelease,
    recipients: list[DistributionRecipient],
    *,
    settlement_id: str,
    room_commitment: str,
    room_state_commitment: str,
    query_commitment: str,
    grant_set_commitment: str,
    allocation_commitment: str,
    execution_commitment: str,
    result_commitment: str,
    usage_commitment: str,
    attestation_evidence_hash: str,
    funding_reservation_id: str = ZERO_BYTES32,
) -> tuple[SettlementAuthorization, str, str]:
    total = sum(recipient.amount for recipient in recipients)
    owners_amounts_hash = compute_owner_amounts_hash(recipients)
    resource_hash = _bytes32_call(
        rpc_url,
        release.distributor,
        "collaborationResourceHash(bytes32,bytes32)(bytes32)",
        [room_commitment, query_commitment],
    )
    draft = SettlementAuthorization(
        settlement_id=settlement_id,
        settlement_nonce=1,
        funding_reservation_id=funding_reservation_id,
        release_policy_commitment=release.release_policy_commitment,
        room_commitment=room_commitment,
        room_state_commitment=room_state_commitment,
        query_commitment=query_commitment,
        grant_set_commitment=grant_set_commitment,
        allocation_commitment=allocation_commitment,
        owners_amounts_hash=owners_amounts_hash,
        asset_address=ZERO_ADDRESS,
        total=total,
        execution_commitment=execution_commitment,
        result_commitment=result_commitment,
        usage_commitment=usage_commitment,
        attestation_evidence_hash=attestation_evidence_hash,
        anchor_resource_hash=resource_hash,
        anchor_decision_hash=ZERO_BYTES32,
        anchor_sequence=0,
        expiry=_latest_timestamp(rpc_url) + 300,
    )
    decision_hash = _bytes32_call(
        rpc_url,
        release.distributor,
        f"settlementDecisionHash({AUTHORIZATION_TUPLE})(bytes32)",
        [_authorization_tuple(draft)],
    )
    global_sequence = _uint_call(rpc_url, release.anchor, "globalSequence()(uint256)")
    global_head = _bytes32_call(rpc_url, release.anchor, "globalHead()(bytes32)")
    resource_head = _bytes32_call(
        rpc_url,
        release.anchor,
        "resourceDecisionHead(bytes32)(bytes32)",
        [resource_hash],
    )
    _send(
        rpc_url,
        ANCHOR_WRITER,
        release.anchor,
        "anchorDecision(uint256,bytes32,bytes32,bytes32,bytes32,bytes32)",
        [
            str(global_sequence),
            global_head,
            resource_hash,
            resource_head,
            decision_hash,
            ANCHOR_WRITER_RELEASE,
        ],
    )
    anchor_sequence = _uint_call(
        rpc_url,
        release.anchor,
        "decisionSequence(bytes32)(uint256)",
        [decision_hash],
    )
    authorization = replace(
        draft,
        anchor_decision_hash=decision_hash,
        anchor_sequence=anchor_sequence,
    )
    tuple_argument = _authorization_tuple(authorization)
    settlement_digest = _bytes32_call(
        rpc_url,
        release.distributor,
        f"settlementAuthorizationDigest({AUTHORIZATION_TUPLE})(bytes32)",
        [tuple_argument],
    )
    qvl_digest = _bytes32_call(
        rpc_url,
        release.distributor,
        f"settlementQvlAuthorizationDigest({AUTHORIZATION_TUPLE})(bytes32)",
        [tuple_argument],
    )
    _send(rpc_url, DEPLOYER, release.settlement_signer, "approve(bytes32)", [settlement_digest])
    _send(rpc_url, DEPLOYER, release.qvl_signer, "approve(bytes32)", [qvl_digest])
    return authorization, "0x01", "0x02"


def _authorization_tuple(authorization: SettlementAuthorization) -> str:
    return "(" + ",".join(
        str(value)
        for value in (
            authorization.settlement_id,
            authorization.settlement_nonce,
            authorization.funding_reservation_id,
            authorization.release_policy_commitment,
            authorization.room_commitment,
            authorization.room_state_commitment,
            authorization.query_commitment,
            authorization.grant_set_commitment,
            authorization.allocation_commitment,
            authorization.owners_amounts_hash,
            authorization.asset_address,
            authorization.total,
            authorization.execution_commitment,
            authorization.result_commitment,
            authorization.usage_commitment,
            authorization.attestation_evidence_hash,
            authorization.anchor_resource_hash,
            authorization.anchor_decision_hash,
            authorization.anchor_sequence,
            authorization.expiry,
        )
    ) + ")"


def _pending(rpc_url: str, contract: str, owner: str) -> int:
    out = _run([
        "cast", "call", contract,
        "pending(address,address)(uint256)",
        "0x0000000000000000000000000000000000000000", owner,
        "--rpc-url", rpc_url,
    ]).strip()
    return int(out.split()[0]) if out else 0


def _address_call(rpc_url: str, contract: str, signature: str, args: list[str] | None = None) -> str:
    return _call(rpc_url, contract, signature, args).split()[0]


def _bytes32_call(rpc_url: str, contract: str, signature: str, args: list[str] | None = None) -> str:
    return _call(rpc_url, contract, signature, args).split()[0]


def _uint_call(rpc_url: str, contract: str, signature: str, args: list[str] | None = None) -> int:
    return int(_call(rpc_url, contract, signature, args).split()[0], 0)


def _bool_call(rpc_url: str, contract: str, signature: str, args: list[str] | None = None) -> bool:
    value = _call(rpc_url, contract, signature, args).strip().lower()
    if value not in {"true", "false"}:
        raise RuntimeError(f"unexpected bool result: {value}")
    return value == "true"


def _call(rpc_url: str, contract: str, signature: str, args: list[str] | None = None) -> str:
    return _run(
        ["cast", "call", contract, signature, *(args or []), "--rpc-url", rpc_url]
    ).strip()


def _balance(rpc_url: str, address: str) -> int:
    return int(_run(["cast", "balance", address, "--rpc-url", rpc_url]).strip())


def _send(rpc_url: str, sender: str, to: str, sig: str, args: list[str], *, value: str = "") -> str:
    cmd = ["cast", "send", to, sig, *args, "--rpc-url", rpc_url, "--unlocked", "--from", sender, "--json"]
    if value:
        cmd += ["--value", value]
    output = _run_json(cmd)
    return str(output.get("transactionHash") or output.get("transaction_hash") or "")


def _send_raw(rpc_url: str, sender: str, to: str, calldata: str, *, value: str = "") -> str:
    command = [
        "cast",
        "send",
        to,
        calldata,
        "--rpc-url",
        rpc_url,
        "--unlocked",
        "--from",
        sender,
        "--json",
    ]
    if value:
        command.extend(["--value", value])
    output = _run_json(command)
    return str(output.get("transactionHash") or output.get("transaction_hash") or "")


def _increase_time(rpc_url: str, seconds: int) -> None:
    _run(["cast", "rpc", "evm_increaseTime", str(seconds), "--rpc-url", rpc_url])
    _run(["cast", "rpc", "evm_mine", "--rpc-url", rpc_url])


def _latest_timestamp(rpc_url: str) -> int:
    value = _run(
        ["cast", "block", "latest", "--field", "timestamp", "--rpc-url", rpc_url]
    ).strip()
    return int(value, 0)


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
