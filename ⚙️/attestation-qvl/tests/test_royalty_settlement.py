from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data
from eth_hash.auto import keccak
from fastapi.testclient import TestClient
from pydantic import ValidationError

DELEGATE_PROJECT = Path(__file__).resolve().parents[2] / "tinker-delegate"
sys.path.insert(0, str(DELEGATE_PROJECT))

from tinker_delegate.royalty_distribution_plan import (  # noqa: E402
    SettlementAuthorization as TinkerSettlementAuthorization,
    _encode_authorization as tinker_encode_authorization,
)

from attestation_qvl.errors import VerificationRejected, VerifierUnavailable
from attestation_qvl.models import MAX_BODY_BYTES
from attestation_qvl.qvl import (
    IndependentQuoteVerifier,
    VerifiedQuote,
    derive_royalty_settlement_attestation_evidence_hash,
    derive_royalty_settlement_policy_commitment,
)
from attestation_qvl.service import Runtime, _create_app
from attestation_qvl.signing import (
    EIP712_DOMAIN_TYPEHASH,
    ROYALTY_DISTRIBUTOR_NAME_HASH,
    ROYALTY_DISTRIBUTOR_VERSION_HASH,
    ROYALTY_SETTLEMENT_AUTHORIZATION_TYPEHASH,
    ROYALTY_SETTLEMENT_DECISION_TYPEHASH,
    ROYALTY_SETTLEMENT_QVL_AUTHORIZATION_TYPEHASH,
    independent_verdict_digest,
    royalty_collaboration_resource_hash,
    royalty_settlement_authorization_digest,
    royalty_settlement_decision_hash,
    royalty_settlement_qvl_authorization_digest,
)
from tests.support import (
    NOW,
    ROYALTY_DISTRIBUTOR,
    ROYALTY_QVL_ADDRESS,
    ROYALTY_SETTLEMENT_PRIVATE_KEY,
    TOKEN,
    FakeBackend,
    FakeRoyaltySigner,
    FakeVerdictSigner,
    make_context,
    measurement_bytes,
    policy_payload,
    write_policy,
)


KAT_INPUT = {
    "chain_id": 84_532,
    "distributor_address": "0x" + "55" * 20,
    "settlement_id": "0x" + "01" * 32,
    "settlement_nonce": 7,
    "funding_reservation_id": "0x" + "0f" * 32,
    "release_policy_commitment": "0x" + "02" * 32,
    "room_commitment": "0x" + "03" * 32,
    "room_state_commitment": "0x" + "04" * 32,
    "query_commitment": "0x" + "05" * 32,
    "grant_set_commitment": "0x" + "06" * 32,
    "allocation_commitment": "0x" + "07" * 32,
    "owners_amounts_hash": "0x" + "08" * 32,
    "asset": "0x" + "77" * 20,
    "total": 123_456_789,
    "execution_commitment": "0x" + "09" * 32,
    "result_commitment": "0x" + "0a" * 32,
    "usage_commitment": "0x" + "0b" * 32,
    "attestation_evidence_hash": "0x" + "0c" * 32,
    "anchor_resource_hash": "0x" + "0d" * 32,
    "anchor_decision_hash": "0x" + "0e" * 32,
    "anchor_sequence": 11,
    "expiry": 1_800_000_060,
}

DECISION_TYPE = (
    "RoyaltySettlementDecision(uint256 chainId,address distributor,bytes32 settlementId,"
    "uint256 settlementNonce,bytes32 fundingReservationId,bytes32 releasePolicyCommitment,"
    "bytes32 roomCommitment,bytes32 roomStateCommitment,bytes32 queryCommitment,"
    "bytes32 grantSetCommitment,bytes32 allocationCommitment,bytes32 ownersAmountsHash,"
    "address asset,uint256 total,bytes32 executionCommitment,bytes32 resultCommitment,"
    "bytes32 usageCommitment,bytes32 attestationEvidenceHash,bytes32 anchorResourceHash,"
    "uint256 expiry)"
)
SETTLEMENT_AUTHORIZATION_TYPE = (
    "RoyaltySettlementAuthorization(bytes32 settlementId,uint256 settlementNonce,"
    "bytes32 fundingReservationId,bytes32 releasePolicyCommitment,bytes32 roomCommitment,"
    "bytes32 roomStateCommitment,bytes32 queryCommitment,bytes32 grantSetCommitment,"
    "bytes32 allocationCommitment,bytes32 ownersAmountsHash,address asset,uint256 total,"
    "bytes32 executionCommitment,bytes32 resultCommitment,bytes32 usageCommitment,"
    "bytes32 attestationEvidenceHash,bytes32 anchorResourceHash,bytes32 anchorDecisionHash,"
    "uint256 anchorSequence,uint256 expiry)"
)
QVL_AUTHORIZATION_TYPE = SETTLEMENT_AUTHORIZATION_TYPE.replace(
    "RoyaltySettlementAuthorization", "RoyaltySettlementQvlAuthorization", 1
)

DIGEST_FIELD_MUTATIONS = {
    "settlement_id": "0x" + "91" * 32,
    "settlement_nonce": "8",
    "funding_reservation_id": "0x" + "90" * 32,
    "release_policy_commitment": "0x" + "92" * 32,
    "room_commitment": "0x" + "93" * 32,
    "room_state_commitment": "0x" + "94" * 32,
    "query_commitment": "0x" + "95" * 32,
    "grant_set_commitment": "0x" + "96" * 32,
    "allocation_commitment": "0x" + "97" * 32,
    "owners_amounts_hash": "0x" + "98" * 32,
    "asset": "0x" + "99" * 20,
    "total": "1001",
    "execution_commitment": "0x" + "9a" * 32,
    "result_commitment": "0x" + "9b" * 32,
    "usage_commitment": "0x" + "9c" * 32,
    "attestation_evidence_hash": "0x" + "9d" * 32,
    "anchor_resource_hash": "0x" + "9e" * 32,
    "anchor_decision_hash": "0x" + "9f" * 32,
    "anchor_sequence": "10",
    "expiry": NOW + 31,
}


def _digest_values(authorization: dict[str, object]) -> dict[str, object]:
    return {
        "settlement_id": authorization["settlement_id"],
        "settlement_nonce": int(authorization["settlement_nonce"]),
        "funding_reservation_id": authorization["funding_reservation_id"],
        "release_policy_commitment": authorization["release_policy_commitment"],
        "room_commitment": authorization["room_commitment"],
        "room_state_commitment": authorization["room_state_commitment"],
        "query_commitment": authorization["query_commitment"],
        "grant_set_commitment": authorization["grant_set_commitment"],
        "allocation_commitment": authorization["allocation_commitment"],
        "owners_amounts_hash": authorization["owners_amounts_hash"],
        "asset": authorization["asset"],
        "total": int(authorization["total"]),
        "execution_commitment": authorization["execution_commitment"],
        "result_commitment": authorization["result_commitment"],
        "usage_commitment": authorization["usage_commitment"],
        "attestation_evidence_hash": authorization["attestation_evidence_hash"],
        "anchor_resource_hash": authorization["anchor_resource_hash"],
        "anchor_decision_hash": authorization["anchor_decision_hash"],
        "anchor_sequence": int(authorization["anchor_sequence"]),
        "expiry": authorization["expiry"],
    }


def _tinker_authorization(values: dict[str, object]) -> TinkerSettlementAuthorization:
    return TinkerSettlementAuthorization(
        settlement_id=str(values["settlement_id"]),
        settlement_nonce=int(values["settlement_nonce"]),
        funding_reservation_id=str(values["funding_reservation_id"]),
        release_policy_commitment=str(values["release_policy_commitment"]),
        room_commitment=str(values["room_commitment"]),
        room_state_commitment=str(values["room_state_commitment"]),
        query_commitment=str(values["query_commitment"]),
        grant_set_commitment=str(values["grant_set_commitment"]),
        allocation_commitment=str(values["allocation_commitment"]),
        owners_amounts_hash=str(values["owners_amounts_hash"]),
        asset_address=str(values["asset"]),
        total=int(values["total"]),
        execution_commitment=str(values["execution_commitment"]),
        result_commitment=str(values["result_commitment"]),
        usage_commitment=str(values["usage_commitment"]),
        attestation_evidence_hash=str(values["attestation_evidence_hash"]),
        anchor_resource_hash=str(values["anchor_resource_hash"]),
        anchor_decision_hash=str(values["anchor_decision_hash"]),
        anchor_sequence=int(values["anchor_sequence"]),
        expiry=int(values["expiry"]),
    )


def _authorization(context, *, expiry: int = NOW + 30) -> dict[str, object]:
    binding = context.release.policy.royalty_settlement_binding
    royalty_signer = context.royalty_signer
    assert binding is not None and royalty_signer is not None
    policy_commitment = derive_royalty_settlement_policy_commitment(
        release=context.release,
        binding=binding,
        royalty_verifier_address=royalty_signer.address,
    )
    evidence_hash = derive_royalty_settlement_attestation_evidence_hash(
        request=context.request(),
        binding=binding,
        royalty_verifier_address=royalty_signer.address,
        royalty_policy_commitment=policy_commitment,
    )
    authorization: dict[str, object] = {
        "schema": "dnai.royalty-settlement-qvl-authorization-request.v2",
        "settlement_id": "0x" + "10" * 32,
        "settlement_nonce": "7",
        "funding_reservation_id": "0x" + "20" * 32,
        "release_policy_commitment": binding.release_policy_commitment,
        "room_commitment": "0x" + "11" * 32,
        "room_state_commitment": "0x" + "12" * 32,
        "query_commitment": "0x" + "13" * 32,
        "grant_set_commitment": "0x" + "14" * 32,
        "allocation_commitment": "0x" + "15" * 32,
        "owners_amounts_hash": "0x" + "16" * 32,
        "asset": "0x" + "00" * 20,
        "total": "1000",
        "execution_commitment": "0x" + "17" * 32,
        "result_commitment": "0x" + "18" * 32,
        "usage_commitment": "0x" + "19" * 32,
        "attestation_evidence_hash": evidence_hash,
        "anchor_resource_hash": "0x" + "01" * 32,
        "anchor_decision_hash": "0x" + "02" * 32,
        "anchor_sequence": "9",
        "expiry": expiry,
    }
    authorization["anchor_resource_hash"] = royalty_collaboration_resource_hash(
        chain_id=context.release.policy.chain_id,
        distributor_address=binding.distributor_address,
        room_commitment=str(authorization["room_commitment"]),
        query_commitment=str(authorization["query_commitment"]),
    )
    authorization["anchor_decision_hash"] = royalty_settlement_decision_hash(
        chain_id=context.release.policy.chain_id,
        distributor_address=binding.distributor_address,
        **{
            key: value
            for key, value in _digest_values(authorization).items()
            if key not in {"anchor_decision_hash", "anchor_sequence"}
        },
    )
    main_digest = royalty_settlement_authorization_digest(
        chain_id=context.release.policy.chain_id,
        distributor_address=binding.distributor_address,
        **_digest_values(authorization),
    )
    main_account = Account.from_key(ROYALTY_SETTLEMENT_PRIVATE_KEY)
    main_signature = main_account.unsafe_sign_hash(bytes.fromhex(main_digest[2:]))
    authorization["settlement_authorization_digest"] = main_digest
    authorization["settlement_authorization_signature"] = (
        "0x" + bytes(main_signature.signature).hex()
    )
    return authorization


def _request(context, authorization: dict[str, object]):
    payload = deepcopy(context.request_payload)
    payload["royalty_authorization"] = authorization
    return context.request(payload)


def _runtime(context) -> Runtime:
    return Runtime(
        release=context.release,
        verifier=context.verifier,
        auth_token=TOKEN,
        identity_attestor=None,
        challenge_store=context.challenge_store,
        max_concurrency=4,
        rate_capacity=30,
        rate_refill_per_second=0.5,
        request_body_timeout_seconds=5.0,
        verification_timeout_seconds=5.0,
    )


def test_royalty_distributor_v3_eip712_kat_matches_solidity_and_tinker_encoder():
    qvl_digest = royalty_settlement_qvl_authorization_digest(**KAT_INPUT)
    settlement_digest = royalty_settlement_authorization_digest(**KAT_INPUT)
    assert qvl_digest == (
        "0x872ab0d5ca653512b5fe9eed6da617e0f9c9a46691027c034bf18a134b27df2d"
    )
    assert settlement_digest == (
        "0x1f6a8677f6a1260071142b5485d2e41bcd7bad78a96b3990728f223c993523b8"
    )
    assert qvl_digest != settlement_digest

    assert ROYALTY_SETTLEMENT_DECISION_TYPEHASH == keccak(DECISION_TYPE.encode())
    assert ROYALTY_SETTLEMENT_AUTHORIZATION_TYPEHASH == keccak(
        SETTLEMENT_AUTHORIZATION_TYPE.encode()
    )
    assert ROYALTY_SETTLEMENT_QVL_AUTHORIZATION_TYPEHASH == keccak(
        QVL_AUTHORIZATION_TYPE.encode()
    )
    solidity = (
        Path(__file__).resolve().parents[2]
        / "tinker-delegate"
        / "contracts"
        / "src"
        / "RoyaltyDistributor.sol"
    ).read_text(encoding="utf-8")
    assert DECISION_TYPE in solidity
    assert SETTLEMENT_AUTHORIZATION_TYPE in solidity
    assert QVL_AUTHORIZATION_TYPE in solidity

    encoded_authorization = tinker_encode_authorization(
        _tinker_authorization(KAT_INPUT)
    )
    assert encoded_authorization[64:96] == bytes.fromhex(
        str(KAT_INPUT["funding_reservation_id"])[2:]
    )
    domain_separator = keccak(
        EIP712_DOMAIN_TYPEHASH
        + ROYALTY_DISTRIBUTOR_NAME_HASH
        + ROYALTY_DISTRIBUTOR_VERSION_HASH
        + int(KAT_INPUT["chain_id"]).to_bytes(32, "big")
        + bytes.fromhex(str(KAT_INPUT["distributor_address"])[2:]).rjust(
            32, b"\x00"
        )
    )
    assert settlement_digest == "0x" + keccak(
        b"\x19\x01"
        + domain_separator
        + keccak(ROYALTY_SETTLEMENT_AUTHORIZATION_TYPEHASH + encoded_authorization)
    ).hex()
    assert qvl_digest == "0x" + keccak(
        b"\x19\x01"
        + domain_separator
        + keccak(
            ROYALTY_SETTLEMENT_QVL_AUTHORIZATION_TYPEHASH
            + encoded_authorization
        )
    ).hex()

    typed = encode_typed_data(
        full_message={
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "RoyaltySettlementQvlAuthorization": [
                    {"name": "settlementId", "type": "bytes32"},
                    {"name": "settlementNonce", "type": "uint256"},
                    {"name": "fundingReservationId", "type": "bytes32"},
                    {"name": "releasePolicyCommitment", "type": "bytes32"},
                    {"name": "roomCommitment", "type": "bytes32"},
                    {"name": "roomStateCommitment", "type": "bytes32"},
                    {"name": "queryCommitment", "type": "bytes32"},
                    {"name": "grantSetCommitment", "type": "bytes32"},
                    {"name": "allocationCommitment", "type": "bytes32"},
                    {"name": "ownersAmountsHash", "type": "bytes32"},
                    {"name": "asset", "type": "address"},
                    {"name": "total", "type": "uint256"},
                    {"name": "executionCommitment", "type": "bytes32"},
                    {"name": "resultCommitment", "type": "bytes32"},
                    {"name": "usageCommitment", "type": "bytes32"},
                    {"name": "attestationEvidenceHash", "type": "bytes32"},
                    {"name": "anchorResourceHash", "type": "bytes32"},
                    {"name": "anchorDecisionHash", "type": "bytes32"},
                    {"name": "anchorSequence", "type": "uint256"},
                    {"name": "expiry", "type": "uint256"},
                ],
            },
            "primaryType": "RoyaltySettlementQvlAuthorization",
            "domain": {
                "name": "DNAI Royalty Distributor",
                "version": "3",
                "chainId": KAT_INPUT["chain_id"],
                "verifyingContract": KAT_INPUT["distributor_address"],
            },
            "message": {
                "settlementId": KAT_INPUT["settlement_id"],
                "settlementNonce": KAT_INPUT["settlement_nonce"],
                "fundingReservationId": KAT_INPUT["funding_reservation_id"],
                "releasePolicyCommitment": KAT_INPUT[
                    "release_policy_commitment"
                ],
                "roomCommitment": KAT_INPUT["room_commitment"],
                "roomStateCommitment": KAT_INPUT["room_state_commitment"],
                "queryCommitment": KAT_INPUT["query_commitment"],
                "grantSetCommitment": KAT_INPUT["grant_set_commitment"],
                "allocationCommitment": KAT_INPUT["allocation_commitment"],
                "ownersAmountsHash": KAT_INPUT["owners_amounts_hash"],
                "asset": KAT_INPUT["asset"],
                "total": KAT_INPUT["total"],
                "executionCommitment": KAT_INPUT["execution_commitment"],
                "resultCommitment": KAT_INPUT["result_commitment"],
                "usageCommitment": KAT_INPUT["usage_commitment"],
                "attestationEvidenceHash": KAT_INPUT[
                    "attestation_evidence_hash"
                ],
                "anchorResourceHash": KAT_INPUT["anchor_resource_hash"],
                "anchorDecisionHash": KAT_INPUT["anchor_decision_hash"],
                "anchorSequence": KAT_INPUT["anchor_sequence"],
                "expiry": KAT_INPUT["expiry"],
            },
        }
    )
    assert "0x" + keccak(
        b"\x19" + typed.version + typed.header + typed.body
    ).hex() == qvl_digest


def test_royalty_v3_qvl_digest_binds_every_authorization_field():
    qvl_digest = royalty_settlement_qvl_authorization_digest(**KAT_INPUT)
    for field, value in DIGEST_FIELD_MUTATIONS.items():
        mutated = dict(KAT_INPUT)
        mutated[field] = int(value) if field in {
            "settlement_nonce",
            "total",
            "anchor_sequence",
        } else value
        assert royalty_settlement_qvl_authorization_digest(**mutated) != qvl_digest


@pytest.mark.asyncio
async def test_fresh_royalty_appraisal_returns_only_bounded_secondary_authority(tmp_path):
    context = make_context(tmp_path, royalty=True)
    authorization = _authorization(context)
    verdict = await context.verifier.verify(_request(context, authorization))
    public = verdict.model_dump(mode="json", by_alias=True, exclude_none=True)

    assert public["profile"] == "royalty_settlement"
    assert public["contract_address"] == ROYALTY_DISTRIBUTOR
    assert public["qvl_royalty_verifier_address"] == ROYALTY_QVL_ADDRESS
    assert public["qvl_royalty_release_policy_commitment"] == (
        authorization["release_policy_commitment"]
    )
    assert public["qvl_royalty_attestation_evidence_hash"] == (
        authorization["attestation_evidence_hash"]
    )
    assert public["qvl_royalty_authorization_expiry"] == NOW + 30
    assert context.royalty_signer is not None
    assert context.royalty_signer.digests == [
        public["qvl_royalty_authorization_digest"]
    ]
    recovered = Account._recover_hash(
        bytes.fromhex(public["qvl_royalty_authorization_digest"][2:]),
        signature=public["qvl_royalty_authorization_signature"],
    )
    assert recovered.lower() == ROYALTY_QVL_ADDRESS
    assert context.royalty_signer.address != context.signer.address
    assert Account.recover_message(
        encode_defunct(hexstr=public["qvl_royalty_authorization_digest"]),
        signature=public["qvl_royalty_authorization_signature"],
    ).lower() != ROYALTY_QVL_ADDRESS
    compute_role_signature = context.signer.account.unsafe_sign_hash(
        bytes.fromhex(public["qvl_royalty_authorization_digest"][2:])
    )
    assert Account._recover_hash(
        bytes.fromhex(public["qvl_royalty_authorization_digest"][2:]),
        signature=compute_role_signature.signature,
    ).lower() == context.signer.address
    assert context.signer.address != ROYALTY_QVL_ADDRESS
    assert context.signer.digests[-1] == independent_verdict_digest(verdict)

    rendered = json.dumps(public, sort_keys=True)
    assert context.request_payload["quote"] not in rendered
    assert authorization["settlement_authorization_signature"] not in rendered
    assert authorization["settlement_id"] not in rendered
    assert set(key for key in public if key.startswith("qvl_royalty_")) == {
        "qvl_royalty_verifier_address",
        "qvl_royalty_policy_commitment",
        "qvl_royalty_release_policy_commitment",
        "qvl_royalty_attestation_evidence_hash",
        "qvl_royalty_anchor_evidence_commitment",
        "qvl_royalty_authorization_expiry",
        "qvl_royalty_authorization_digest",
        "qvl_royalty_authorization_signature",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            lambda authorization: authorization.update({"unexpected": True}),
            id="extra-field",
        ),
        pytest.param(
            lambda authorization: authorization.update({"settlement_nonce": 7}),
            id="coerced-number",
        ),
        pytest.param(
            lambda authorization: authorization.update({"total": "0"}),
            id="zero-total",
        ),
        pytest.param(
            lambda authorization: authorization.pop("funding_reservation_id"),
            id="missing-reservation",
        ),
        pytest.param(
            lambda authorization: authorization.update(
                {"funding_reservation_id": "0x" + "00" * 32}
            ),
            id="zero-reservation",
        ),
        pytest.param(
            lambda authorization: authorization.update(
                {
                    "schema": (
                        "dnai.royalty-settlement-qvl-authorization-request.v1"
                    )
                }
            ),
            id="legacy-v1-schema",
        ),
        pytest.param(
            lambda authorization: authorization.update(
                {
                    "schema": (
                        "dnai.royalty-settlement-qvl-authorization-request.v3"
                    )
                }
            ),
            id="unknown-schema",
        ),
        pytest.param(
            lambda authorization: (
                authorization.pop("funding_reservation_id"),
                authorization.update(
                    {"fundingReservationId": "0x" + "20" * 32}
                ),
            ),
            id="camelcase-alias",
        ),
        pytest.param(
            lambda authorization: authorization.update(
                {"settlement_authorization_signature": "0x" + "00" * 65}
            ),
            id="noncanonical-signature",
        ),
    ],
)
def test_royalty_v2_request_schema_rejects_legacy_ambiguous_or_zero_packets(
    tmp_path, mutation
):
    context = make_context(tmp_path, royalty=True)
    authorization = _authorization(context)
    mutation(authorization)
    payload = deepcopy(context.request_payload)
    payload["royalty_authorization"] = authorization
    with pytest.raises(ValidationError):
        context.request(payload)


@pytest.mark.asyncio
async def test_legacy_eip712_typehash_is_not_accepted_as_v2_authority(tmp_path):
    context = make_context(tmp_path, royalty=True)
    authorization = _authorization(context)
    encoded = tinker_encode_authorization(_tinker_authorization(authorization))
    legacy_words_without_reservation = encoded[:64] + encoded[96:]
    legacy_typehash = keccak(
        SETTLEMENT_AUTHORIZATION_TYPE.replace(
            "bytes32 fundingReservationId,", "", 1
        ).encode()
    )
    binding = context.release.policy.royalty_settlement_binding
    assert binding is not None
    domain_separator = keccak(
        EIP712_DOMAIN_TYPEHASH
        + ROYALTY_DISTRIBUTOR_NAME_HASH
        + ROYALTY_DISTRIBUTOR_VERSION_HASH
        + context.release.policy.chain_id.to_bytes(32, "big")
        + bytes.fromhex(binding.distributor_address[2:]).rjust(32, b"\x00")
    )
    legacy_digest = "0x" + keccak(
        b"\x19\x01"
        + domain_separator
        + keccak(legacy_typehash + legacy_words_without_reservation)
    ).hex()
    assert legacy_digest != authorization["settlement_authorization_digest"]
    legacy_signature = Account.from_key(
        ROYALTY_SETTLEMENT_PRIVATE_KEY
    ).unsafe_sign_hash(bytes.fromhex(legacy_digest[2:]))
    authorization["settlement_authorization_digest"] = legacy_digest
    authorization["settlement_authorization_signature"] = (
        "0x" + bytes(legacy_signature.signature).hex()
    )

    with pytest.raises(VerificationRejected):
        await context.verifier.verify(_request(context, authorization))


@pytest.mark.asyncio
async def test_funding_reservation_substitution_invalidates_both_authorities(tmp_path):
    context = make_context(tmp_path, royalty=True)
    authorization = _authorization(context)
    original_qvl_digest = royalty_settlement_qvl_authorization_digest(
        chain_id=context.release.policy.chain_id,
        distributor_address=ROYALTY_DISTRIBUTOR,
        **_digest_values(authorization),
    )
    authorization["funding_reservation_id"] = "0x" + "21" * 32
    substituted_qvl_digest = royalty_settlement_qvl_authorization_digest(
        chain_id=context.release.policy.chain_id,
        distributor_address=ROYALTY_DISTRIBUTOR,
        **_digest_values(authorization),
    )
    assert substituted_qvl_digest != original_qvl_digest

    with pytest.raises(VerificationRejected):
        await context.verifier.verify(_request(context, authorization))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"), list(DIGEST_FIELD_MUTATIONS.items())
)
async def test_main_runtime_signature_rejects_every_digest_field_mutation(
    tmp_path, field, value
):
    context = make_context(tmp_path, royalty=True)
    authorization = _authorization(context)
    authorization[field] = value

    with pytest.raises(VerificationRejected):
        await context.verifier.verify(_request(context, authorization))


@pytest.mark.asyncio
@pytest.mark.parametrize("expiry", [NOW, NOW + 61, NOW + 601])
async def test_royalty_authorization_rejects_expired_or_overbroad_lifetime(
    tmp_path, expiry
):
    context = make_context(tmp_path, royalty=True)
    with pytest.raises(VerificationRejected):
        await context.verifier.verify(
            _request(context, _authorization(context, expiry=expiry))
        )


@pytest.mark.asyncio
async def test_stale_quote_challenge_never_reaches_dcap_or_signing(tmp_path):
    context = make_context(tmp_path, royalty=True)
    context.verifier._clock = lambda: NOW + 60

    with pytest.raises(VerificationRejected):
        await context.verifier.verify(_request(context, _authorization(context)))
    assert context.backend.calls == []
    assert context.royalty_signer is not None
    assert context.royalty_signer.digests == []


@pytest.mark.asyncio
async def test_wrong_main_runtime_role_and_diligence_profile_cannot_authorize(tmp_path):
    context = make_context(tmp_path, royalty=True)
    authorization = _authorization(context)
    wrong = context.signer.account.unsafe_sign_hash(
        bytes.fromhex(str(authorization["settlement_authorization_digest"])[2:])
    )
    authorization["settlement_authorization_signature"] = (
        "0x" + bytes(wrong.signature).hex()
    )
    with pytest.raises(VerificationRejected):
        await context.verifier.verify(_request(context, authorization))

    profile_root = tmp_path / "profile"
    profile_root.mkdir()
    fresh = make_context(profile_root, royalty=True)
    payload = deepcopy(fresh.request_payload)
    payload["challenge"]["profile"] = "diligence"
    payload["royalty_authorization"] = _authorization(fresh)
    with pytest.raises(VerificationRejected):
        await fresh.verifier.verify(fresh.request(payload))
    assert fresh.backend.calls == []


def test_release_commitment_drift_prevents_verifier_construction(tmp_path):
    payload = policy_payload(royalty=True)
    payload["royalty_settlement_binding"]["release_policy_commitment"] = (
        "0x" + "ff" * 32
    )
    release = write_policy(tmp_path / "drifted-policy.json", payload)
    backend = FakeBackend(
        VerifiedQuote(
            quote_type="TDX",
            status="OK",
            report_data=bytes(64),
            measurements=measurement_bytes(),
        )
    )
    with pytest.raises(VerifierUnavailable):
        IndependentQuoteVerifier(
            release=release,
            backend=backend,
            signer=FakeVerdictSigner(),
            royalty_signer=FakeRoyaltySigner(),
        )


def test_legacy_royalty_policy_binding_is_rejected(tmp_path):
    payload = policy_payload(royalty=True)
    payload["royalty_settlement_binding"]["kind"] = "royalty_settlement_qvl_v1"
    with pytest.raises(VerifierUnavailable):
        write_policy(tmp_path / "legacy-royalty-policy.json", payload)


def test_identity_truthfully_advertises_secondary_royalty_capability(tmp_path):
    plain_root = tmp_path / "plain"
    royalty_root = tmp_path / "royalty"
    plain_root.mkdir()
    royalty_root.mkdir()
    plain = make_context(plain_root)
    royalty = make_context(royalty_root, royalty=True)
    with TestClient(_create_app(_runtime(plain))) as client:
        plain_capabilities = client.get("/capabilities").json()
        denied = client.post(
            "/challenge",
            headers={"Authorization": f"Bearer {TOKEN}"},
            json={
                **plain.challenge_request.model_dump(mode="json", by_alias=True),
                "profile": "royalty_settlement",
            },
        )
    with TestClient(_create_app(_runtime(royalty))) as client:
        royalty_capabilities = client.get("/capabilities").json()
        admitted = client.post(
            "/challenge",
            headers={"Authorization": f"Bearer {TOKEN}"},
            json=royalty.challenge_request.model_dump(mode="json", by_alias=True),
        )

    assert plain_capabilities == {
        "schema": "dnai.attestation-qvl-capabilities.v1",
        "royalty_settlement_qvl_enabled": False,
        "raw_secret_egress": False,
    }
    assert denied.status_code == 400
    assert royalty_capabilities["royalty_settlement_qvl_enabled"] is True
    assert royalty_capabilities["royalty_authorization_schema"] == (
        "dnai.royalty-settlement-qvl-authorization-request.v2"
    )
    assert royalty_capabilities["royalty_qvl_verifier_address"] == ROYALTY_QVL_ADDRESS
    assert royalty_capabilities["royalty_qvl_policy_commitment"] == (
        royalty.verifier.royalty_policy_commitment
    )
    assert admitted.status_code == 200


def test_royalty_request_obeys_global_authenticated_body_limit(tmp_path):
    context = make_context(tmp_path, royalty=True)
    oversized = b'{"padding":"' + (b"a" * MAX_BODY_BYTES) + b'"}'
    with TestClient(_create_app(_runtime(context)), raise_server_exceptions=False) as client:
        response = client.post(
            "/verify",
            headers={
                "Authorization": f"Bearer {TOKEN}",
                "Content-Type": "application/json",
            },
            content=oversized,
        )
    assert response.status_code == 413
    assert response.json() == {"error": "request_too_large"}
