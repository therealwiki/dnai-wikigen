"""Fail-closed governance plans for admitting an attested DiligenceRoom CVM.

Governance calldata is emitted only after authenticating a complete independent
Intel TDX DCAP/QVL verdict against trust roots and exact release/CVM bindings
supplied outside that verdict. Summary booleans such as ``authorized`` or
``attestation_verdict_authenticated`` are never accepted as evidence.

The module still does not broadcast. It returns bounded ``cast --account dev``
templates for an operator to review and execute through the Foundry keystore.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from eth_hash.auto import keccak

from tinker_delegate.chain_submitter import (
    ChainSubmitterError,
    encode_address_word,
    normalize_address,
    normalize_bytes32,
    signer_attestation_report_data,
)
from tinker_delegate.result_verifier import (
    IndependentAttestationExpectation,
    IndependentAttestationVerdict,
    ResultVerifierError,
    authenticate_independent_attestation_verdict,
)


PROPOSE_COMPOSE_HASH_SELECTOR = keccak(b"proposeComposeHash(bytes32)")[:4]
ACTIVATE_COMPOSE_HASH_SELECTOR = keccak(b"activateComposeHash(bytes32)")[:4]
PROPOSE_TEE_IDENTITY_SELECTOR = keccak(b"proposeTeeIdentity(address,bytes32)")[:4]
ACTIVATE_TEE_IDENTITY_SELECTOR = keccak(b"activateTeeIdentity(address)")[:4]
FREEZE_COMPOSE_ADDITIONS_SELECTOR = keccak(b"freezeComposeAdditions()")[:4]
FREEZE_TEE_IDENTITY_ADDITIONS_SELECTOR = keccak(
    b"freezeTeeIdentityAdditions()"
)[:4]
DILIGENCE_ADMISSION_TIMELOCK_SECONDS = 2 * 24 * 60 * 60
GOVERNANCE_POLICY_DOMAIN = b"dnai-wikigen/governance-verdict-policy/v1\x00"
_KEYSTORE_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


@dataclass(frozen=True)
class GovernanceCall:
    """One bounded governance transaction the developer must broadcast."""

    function: str
    signature: str
    args: tuple[str, ...]
    calldata: str
    cast_command: str
    phase: int
    requires_previous_timelock_elapsed: bool

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "signature": self.signature,
            "args": list(self.args),
            "calldata": self.calldata,
            "cast_command": self.cast_command,
            "phase": self.phase,
            "requires_previous_timelock_elapsed": self.requires_previous_timelock_elapsed,
        }


@dataclass(frozen=True)
class GovernanceApprovalPlan:
    """Bounded plan backed by an authenticated independent QVL verdict."""

    chain_id: int
    contract_address: str
    tee_identity: str
    compose_hash: str
    app_id: str
    os_image_hash: str
    quote_hash: str
    report_data: str
    attestation_verifier_address: str
    attestation_verdict_digest: str
    attestation_verdict_expires_at: int
    policy_hash: str
    calls: tuple[GovernanceCall, ...]
    requires_developer_broadcast: bool = True
    attestation_verdict_authenticated: bool = True
    raw_secret_egress: bool = False
    admission_timelock_seconds: int = DILIGENCE_ADMISSION_TIMELOCK_SECONDS

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "action": "diligence_room_governance_approval_plan",
            "chain_id": self.chain_id,
            "contract_address": self.contract_address,
            "tee_identity": self.tee_identity,
            "compose_hash": self.compose_hash,
            "app_id": self.app_id,
            "os_image_hash": self.os_image_hash,
            "quote_hash": self.quote_hash,
            "report_data": self.report_data,
            "attestation_verifier_address": self.attestation_verifier_address,
            "attestation_verdict_digest": self.attestation_verdict_digest,
            "attestation_verdict_expires_at": self.attestation_verdict_expires_at,
            "attestation_verdict_authenticated": self.attestation_verdict_authenticated,
            "policy_hash": self.policy_hash,
            "calls": [call.to_public_dict() for call in self.calls],
            "requires_developer_broadcast": self.requires_developer_broadcast,
            "raw_secret_egress": self.raw_secret_egress,
            "admission_timelock_seconds": self.admission_timelock_seconds,
        }


def governance_expectation_hash(
    expectation: IndependentAttestationExpectation,
) -> str:
    """Commit the external trust roots and exact release/CVM pins."""

    try:
        payload = {
            "app_id": expectation.app_id,
            "chain_id": int(expectation.chain_id),
            "challenge_digest": normalize_bytes32(expectation.challenge_digest),
            "challenge_expires_at": int(expectation.challenge_expires_at),
            "challenge_id": normalize_bytes32(expectation.challenge_id),
            "challenge_issued_at": int(expectation.challenge_issued_at),
            "compose_hash": normalize_bytes32(expectation.compose_hash),
            "contract_address": normalize_address(expectation.contract_address),
            "max_age_seconds": int(expectation.max_age_seconds),
            "os_image_hash": expectation.os_image_hash,
            "profile": expectation.profile,
            "quote_hash": normalize_bytes32(expectation.quote_hash),
            "release_policy_hash": normalize_bytes32(
                expectation.release_policy_hash
            ),
            "report_data": normalize_bytes32(expectation.report_data),
            "signer_address": normalize_address(expectation.signer_address),
            "trusted_verifier_addresses": sorted(
                normalize_address(address)
                for address in expectation.trusted_verifier_addresses
            ),
        }
    except ChainSubmitterError as exc:
        raise ResultVerifierError(str(exc)) from exc
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "0x" + hashlib.sha256(GOVERNANCE_POLICY_DOMAIN + encoded).hexdigest()


def build_governance_plan_from_verdict(
    verdict: IndependentAttestationVerdict,
    *,
    expectation: IndependentAttestationExpectation,
    keystore_account: str = "dev",
    rpc_url_placeholder: str = "$BASE_SEPOLIA_RPC_URL",
    now: int | None = None,
) -> GovernanceApprovalPlan:
    """Authenticate ``verdict`` and build the three-phase admission plan.

    Every expected value is supplied through ``expectation``. The verdict may
    attest those values, but it cannot choose what governance trusts. Calls in
    phases two and three are informational until the preceding on-chain two-day
    timelock has elapsed; the production release helper rechecks exact state.
    """

    if not _KEYSTORE_ACCOUNT_RE.fullmatch(keystore_account):
        raise ResultVerifierError("invalid Foundry keystore account name")
    if expectation.chain_id <= 0:
        raise ResultVerifierError("expected chain ID must be positive")
    if expectation.profile != "diligence":
        raise ResultVerifierError("governance attestation profile must be diligence")
    if not expectation.app_id:
        raise ResultVerifierError("expected app ID is required")
    if not expectation.os_image_hash:
        raise ResultVerifierError("expected OS image hash is required")

    try:
        contract = normalize_address(expectation.contract_address)
        tee_identity = normalize_address(expectation.signer_address)
        compose_hash = normalize_bytes32(expectation.compose_hash)
        quote_hash = normalize_bytes32(expectation.quote_hash)
        expected_report_data = "0x" + signer_attestation_report_data(
            signer_address=tee_identity,
            chain_id=int(expectation.chain_id),
            contract_address=contract,
        ).hex()
        supplied_report_data = normalize_bytes32(expectation.report_data)
    except ChainSubmitterError as exc:
        raise ResultVerifierError(str(exc)) from exc
    if supplied_report_data != expected_report_data:
        raise ResultVerifierError(
            "external report-data pin does not match the canonical signer/chain/contract binding"
        )

    authenticated = authenticate_independent_attestation_verdict(
        verdict,
        expectation=expectation,
        now=now,
    )
    policy_hash = governance_expectation_hash(expectation)

    compose_word = bytes.fromhex(compose_hash[2:])
    propose_compose_calldata = "0x" + (
        PROPOSE_COMPOSE_HASH_SELECTOR + compose_word
    ).hex()
    activate_compose_calldata = "0x" + (
        ACTIVATE_COMPOSE_HASH_SELECTOR + compose_word
    ).hex()
    propose_identity_calldata = "0x" + (
        PROPOSE_TEE_IDENTITY_SELECTOR
        + encode_address_word(tee_identity)
        + compose_word
    ).hex()
    activate_identity_calldata = "0x" + (
        ACTIVATE_TEE_IDENTITY_SELECTOR + encode_address_word(tee_identity)
    ).hex()

    def _cast(signature: str, *call_args: str) -> str:
        joined = " ".join(f'"{arg}"' for arg in call_args)
        return (
            f"cast send {contract} '{signature}' {joined} "
            f"--rpc-url {rpc_url_placeholder} --account {keystore_account}"
        )

    calls = (
        GovernanceCall(
            function="proposeComposeHash",
            signature="proposeComposeHash(bytes32)",
            args=(compose_hash,),
            calldata=propose_compose_calldata,
            cast_command=_cast("proposeComposeHash(bytes32)", compose_hash),
            phase=1,
            requires_previous_timelock_elapsed=False,
        ),
        GovernanceCall(
            function="activateComposeHash",
            signature="activateComposeHash(bytes32)",
            args=(compose_hash,),
            calldata=activate_compose_calldata,
            cast_command=_cast("activateComposeHash(bytes32)", compose_hash),
            phase=2,
            requires_previous_timelock_elapsed=True,
        ),
        GovernanceCall(
            function="proposeTeeIdentity",
            signature="proposeTeeIdentity(address,bytes32)",
            args=(tee_identity, compose_hash),
            calldata=propose_identity_calldata,
            cast_command=_cast(
                "proposeTeeIdentity(address,bytes32)",
                tee_identity,
                compose_hash,
            ),
            phase=2,
            requires_previous_timelock_elapsed=True,
        ),
        GovernanceCall(
            function="activateTeeIdentity",
            signature="activateTeeIdentity(address)",
            args=(tee_identity,),
            calldata=activate_identity_calldata,
            cast_command=_cast("activateTeeIdentity(address)", tee_identity),
            phase=3,
            requires_previous_timelock_elapsed=True,
        ),
        GovernanceCall(
            function="freezeComposeAdditions",
            signature="freezeComposeAdditions()",
            args=(),
            calldata="0x" + FREEZE_COMPOSE_ADDITIONS_SELECTOR.hex(),
            cast_command=_cast("freezeComposeAdditions()"),
            phase=3,
            requires_previous_timelock_elapsed=True,
        ),
        GovernanceCall(
            function="freezeTeeIdentityAdditions",
            signature="freezeTeeIdentityAdditions()",
            args=(),
            calldata="0x" + FREEZE_TEE_IDENTITY_ADDITIONS_SELECTOR.hex(),
            cast_command=_cast("freezeTeeIdentityAdditions()"),
            phase=3,
            requires_previous_timelock_elapsed=True,
        ),
    )

    return GovernanceApprovalPlan(
        chain_id=int(expectation.chain_id),
        contract_address=contract,
        tee_identity=tee_identity,
        compose_hash=compose_hash,
        app_id=expectation.app_id,
        os_image_hash=expectation.os_image_hash,
        quote_hash=quote_hash,
        report_data=expected_report_data,
        attestation_verifier_address=authenticated.verifier_address,
        attestation_verdict_digest=authenticated.verdict_digest,
        attestation_verdict_expires_at=int(verdict.expires_at),
        policy_hash=policy_hash,
        calls=calls,
    )


def build_governance_plan_from_authorization(*_args, **_kwargs):
    """Reject the legacy boolean-summary trust path unconditionally."""

    raise ResultVerifierError(
        "authorization summaries are not governance evidence; provide a complete "
        "signed independent QVL verdict and external release policy"
    )


def build_governance_plan_from_public_dict(*_args, **_kwargs):
    """Reject the legacy boolean-summary JSON trust path unconditionally."""

    raise ResultVerifierError(
        "self-declared authorization JSON is not governance evidence; provide a "
        "complete signed independent QVL verdict and external release policy"
    )
