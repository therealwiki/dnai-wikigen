"""Bounded on-chain governance action plans driven by verified attestation.

The `DiligenceRoom` compose-approval and TEE-identity gates admit a measurement
only when the developer has approved it on-chain. This module closes the loop:
given a *verified* ``ResultAuthorization`` (the attestation already passed the
`result_verifier` policy — allowed compose hash, allowed app ID, matching quote
report data, not revoked), it produces the exact governance calls needed to admit
that identity/measurement pair on-chain:

    approveComposeHash(composeHash)
    approveTeeIdentity(teeIdentity, composeHash)

It does NOT self-execute. Per the project invariant that agents may request,
evaluate, and report but never self-approve, this emits only a bounded plan — the
developer/governance broadcasts the calls with a keystore account. The output is
bounded: contract address, function signatures, hash/address args, calldata, and
`cast` command templates using `--account dev` (never a raw key).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from eth_hash.auto import keccak

from tinker_delegate.chain_submitter import (
    ChainSubmitterError,
    encode_address_word,
    normalize_address,
    normalize_bytes32,
)
from tinker_delegate.result_verifier import ResultAuthorization, ResultVerifierError

APPROVE_COMPOSE_HASH_SELECTOR = keccak(b"approveComposeHash(bytes32)")[:4]
APPROVE_TEE_IDENTITY_SELECTOR = keccak(b"approveTeeIdentity(address,bytes32)")[:4]


@dataclass(frozen=True)
class GovernanceCall:
    """One bounded governance transaction the developer must broadcast."""

    function: str
    signature: str
    args: tuple[str, ...]
    calldata: str
    cast_command: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "signature": self.signature,
            "args": list(self.args),
            "calldata": self.calldata,
            "cast_command": self.cast_command,
        }


@dataclass(frozen=True)
class GovernanceApprovalPlan:
    """Bounded plan admitting a verified identity/measurement pair on-chain."""

    contract_address: str
    tee_identity: str
    compose_hash: str
    policy_hash: str
    calls: tuple[GovernanceCall, ...]
    requires_developer_broadcast: bool = True
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "action": "diligence_room_governance_approval_plan",
            "contract_address": self.contract_address,
            "tee_identity": self.tee_identity,
            "compose_hash": self.compose_hash,
            "policy_hash": self.policy_hash,
            "calls": [call.to_public_dict() for call in self.calls],
            "requires_developer_broadcast": self.requires_developer_broadcast,
            "raw_secret_egress": self.raw_secret_egress,
        }


def build_governance_plan_from_authorization(
    authorization: ResultAuthorization,
    *,
    keystore_account: str = "dev",
    rpc_url_placeholder: str = "$BASE_SEPOLIA_RPC_URL",
) -> GovernanceApprovalPlan:
    """Build the on-chain approval plan from a verified result authorization.

    The authorization must be ``authorized=True`` — it means the attestation
    passed the verifier policy, so approving its compose hash and binding its TEE
    identity to that measurement is what governance should commit on-chain.
    """
    if not authorization.authorized:
        raise ResultVerifierError("cannot build a governance plan from an unauthorized result")

    try:
        contract = normalize_address(authorization.contract_address)
        tee_identity = normalize_address(authorization.tee_identity)
        # A verified authorization always carries a non-zero compose hash; reject
        # a zero/invalid one here as a consistent ResultVerifierError.
        compose_hash = normalize_bytes32(authorization.compose_hash)
    except ChainSubmitterError as exc:
        raise ResultVerifierError(str(exc)) from exc

    compose_word = bytes.fromhex(compose_hash[2:])
    approve_compose_calldata = "0x" + (APPROVE_COMPOSE_HASH_SELECTOR + compose_word).hex()
    approve_identity_calldata = "0x" + (
        APPROVE_TEE_IDENTITY_SELECTOR + encode_address_word(tee_identity) + compose_word
    ).hex()

    def _cast(signature: str, *call_args: str) -> str:
        joined = " ".join(f'"{arg}"' for arg in call_args)
        return (
            f"cast send {contract} '{signature}' {joined} "
            f"--rpc-url {rpc_url_placeholder} --account {keystore_account}"
        )

    calls = (
        GovernanceCall(
            function="approveComposeHash",
            signature="approveComposeHash(bytes32)",
            args=(compose_hash,),
            calldata=approve_compose_calldata,
            cast_command=_cast("approveComposeHash(bytes32)", compose_hash),
        ),
        GovernanceCall(
            function="approveTeeIdentity",
            signature="approveTeeIdentity(address,bytes32)",
            args=(tee_identity, compose_hash),
            calldata=approve_identity_calldata,
            cast_command=_cast("approveTeeIdentity(address,bytes32)", tee_identity, compose_hash),
        ),
    )

    return GovernanceApprovalPlan(
        contract_address=contract,
        tee_identity=tee_identity,
        compose_hash=compose_hash,
        policy_hash=authorization.policy_hash,
        calls=calls,
    )


def build_governance_plan_from_public_dict(
    payload: dict[str, Any],
    *,
    keystore_account: str = "dev",
    rpc_url_placeholder: str = "$BASE_SEPOLIA_RPC_URL",
) -> GovernanceApprovalPlan:
    """Build the plan from an ``authorize-result`` bounded authorization dict.

    Only the identity/measurement fields are consumed; verifier signatures and
    digests in the authorization are ignored (they are not needed to admit the
    measurement on-chain and must not appear in the plan).
    """
    required = ("authorized", "contract_address", "tee_identity", "compose_hash")
    missing = [field for field in required if field not in payload]
    if missing:
        raise ResultVerifierError(f"authorization payload missing fields: {', '.join(missing)}")
    if not payload["authorized"]:
        raise ResultVerifierError("cannot build a governance plan from an unauthorized result")

    minimal = ResultAuthorization(
        authorized=True,
        chain_id=int(payload.get("chain_id", 0)),
        contract_address=str(payload["contract_address"]),
        deal_id=int(payload.get("deal_id", 0)),
        tee_identity=str(payload["tee_identity"]),
        compose_hash=str(payload["compose_hash"]),
        score_band_value=int(payload.get("score_band_value", 0)),
        compute_cost_wei=int(payload.get("compute_cost_wei", 0)),
        result_hash=str(payload.get("result_hash", "0x" + "00" * 32)),
        authorization_expiry=int(payload.get("authorization_expiry", 0)),
        verifier_address=str(payload.get("verifier_address", "0x" + "00" * 20)),
        verifier_custody=str(payload.get("verifier_custody", "unknown")),
        verifier_signature="",
        verifier_signature_hash="",
        authorization_digest="",
        signer_attestation_hash="",
        signer_attestation_report_data="",
        signer_attestation_quote_size=0,
        policy_hash=str(payload.get("policy_hash", "")),
    )
    return build_governance_plan_from_authorization(
        minimal,
        keystore_account=keystore_account,
        rpc_url_placeholder=rpc_url_placeholder,
    )
