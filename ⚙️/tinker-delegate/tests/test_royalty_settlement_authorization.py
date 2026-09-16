from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from unittest.mock import patch

import pytest
from eth_account import Account
from eth_hash.auto import keccak

from tinker_delegate.royalty_distribution_plan import (
    SETTLE_RESERVED_FUNCTION,
    SETTLE_RESERVED_SELECTOR,
    DistributionRecipient,
    SettlementAuthorization,
    compute_owner_amounts_hash,
)
from tinker_delegate.royalty_settlement_authorization import (
    BASE_SEPOLIA_CHAIN_ID,
    EIP712_DOMAIN_TYPEHASH,
    ROYALTY_DISTRIBUTOR_NAME_HASH,
    ROYALTY_DISTRIBUTOR_VERSION_HASH,
    ROYALTY_RELEASE_POLICY_TYPEHASH,
    ROYALTY_SETTLEMENT_POLICY_DOMAIN,
    ROYALTY_SETTLEMENT_SIGNER_CUSTODY,
    ROYALTY_SETTLEMENT_SIGNER_KEY_PATH,
    AuthorizedRoyaltySettlementPlan,
    DstackRoyaltySettlementSigner,
    RoyaltySettlementAuthorizationError,
    RoyaltySettlementIntent,
    RoyaltySettlementReleaseBinding,
    RoyaltySettlementReplayBinder,
    RoyaltySettlementReplayConflict,
    RoyaltySettlementSignerUnavailable,
    build_royalty_settlement_authorization_packet,
    derive_royalty_settlement_report_data,
    recover_raw_digest_address,
    royalty_collaboration_resource_hash,
    royalty_settlement_authorization_digest,
    royalty_settlement_decision_hash,
    royalty_settlement_qvl_authorization_digest,
)


NOW = 1_800_000_000
MAIN = Account.from_key("0x" + "11" * 32)
ROYALTY_QVL = Account.from_key("0x" + "22" * 32)
VERDICT_QVL = Account.from_key("0x" + "33" * 32)
ANCHOR = Account.from_key("0x" + "44" * 32)
FUNDING = Account.from_key("0x" + "55" * 32)


def _word_uint(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _word_address(value: str) -> bytes:
    return bytes.fromhex(value[2:]).rjust(32, b"\x00")


def _word_bytes32(value: str) -> bytes:
    return bytes.fromhex(value[2:])


def make_release() -> RoyaltySettlementReleaseBinding:
    values = {
        "distributor_address": FUNDING.address.lower(),
        "distributor_runtime_code_hash": "0x" + "61" * 32,
        "owner_address": "0x" + "60" * 20,
        "authority_nonce": 7,
        "settlement_verifier_address": MAIN.address.lower(),
        "royalty_qvl_verifier_address": ROYALTY_QVL.address.lower(),
        "execution_policy_anchor_address": ANCHOR.address.lower(),
        "anchor_writer_release_commitment": "0x" + "62" * 32,
        "royalty_qvl_signer_key_id": "0x" + "63" * 32,
        "qvl_release_policy_hash": "0x" + "64" * 32,
        "main_runtime_cvm_id": "main-runtime-royalty-001",
        "deployment_intent_sha256": "sha256:" + "65" * 32,
        "release_authority_sha256": "sha256:" + "66" * 32,
        "ceremony_nonce": "0x" + "67" * 32,
        "measurement_policy_sha256": "sha256:" + "68" * 32,
        "compose_hash": "0x" + "69" * 32,
        "app_id": "6a" * 20,
        "os_image_hash": "6b" * 32,
    }
    release_policy_commitment = "0x" + keccak(
        b"".join(
            (
                ROYALTY_RELEASE_POLICY_TYPEHASH,
                _word_uint(BASE_SEPOLIA_CHAIN_ID),
                _word_address(values["distributor_address"]),
                _word_uint(values["authority_nonce"]),
                _word_address(values["settlement_verifier_address"]),
                _word_address(values["royalty_qvl_verifier_address"]),
                _word_address(values["execution_policy_anchor_address"]),
                _word_bytes32(values["anchor_writer_release_commitment"]),
            )
        )
    ).hex()
    binding = {
        "kind": "royalty_settlement_qvl_v2",
        "distributor_address": values["distributor_address"],
        "distributor_runtime_code_hash": values["distributor_runtime_code_hash"],
        "owner": values["owner_address"],
        "settlement_verifier": values["settlement_verifier_address"],
        "settlement_verifier_key_path": ROYALTY_SETTLEMENT_SIGNER_KEY_PATH,
        "settlement_verifier_custody": ROYALTY_SETTLEMENT_SIGNER_CUSTODY,
        "execution_policy_anchor": values["execution_policy_anchor_address"],
        "anchor_writer_release_commitment": values[
            "anchor_writer_release_commitment"
        ],
        "release_policy_commitment": release_policy_commitment,
        "authority_nonce": str(values["authority_nonce"]),
        "qvl_signer_key_id": values["royalty_qvl_signer_key_id"],
        "main_runtime_cvm_id": values["main_runtime_cvm_id"],
        "deployment_intent_sha256": values["deployment_intent_sha256"],
        "release_authority_sha256": values["release_authority_sha256"],
        "measurement_policy_sha256": values["measurement_policy_sha256"],
        "max_authorization_lifetime_seconds": 600,
    }
    qvl_policy = {
        "schema": "dnai.royalty-settlement-qvl-policy.v2",
        "authorization_schema": (
            "dnai.royalty-settlement-qvl-authorization-request.v2"
        ),
        "qvl_release_policy_hash": values["qvl_release_policy_hash"],
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "compose_hash": values["compose_hash"],
        "app_id": values["app_id"],
        "os_image_hash": values["os_image_hash"],
        "royalty_qvl_verifier": values["royalty_qvl_verifier_address"],
        "binding": binding,
    }
    qvl_policy_commitment = "0x" + hashlib.sha256(
        ROYALTY_SETTLEMENT_POLICY_DOMAIN
        + json.dumps(
            qvl_policy,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()
    return RoyaltySettlementReleaseBinding(
        **values,
        release_policy_commitment=release_policy_commitment,
        royalty_qvl_policy_commitment=qvl_policy_commitment,
    )


def make_intent(*, expiry: int = NOW + 30) -> RoyaltySettlementIntent:
    return RoyaltySettlementIntent(
        settlement_id="0x" + "71" * 32,
        settlement_nonce=9,
        royalty_reservation_id="0x" + "70" * 32,
        room_commitment="0x" + "72" * 32,
        room_state_commitment="0x" + "73" * 32,
        query_commitment="0x" + "74" * 32,
        grant_set_commitment="0x" + "75" * 32,
        allocation_commitment="0x" + "76" * 32,
        owners_amounts_hash="0x" + "77" * 32,
        asset_address="0x" + "00" * 20,
        total=1_000,
        execution_commitment="0x" + "78" * 32,
        result_commitment="0x" + "79" * 32,
        usage_commitment="0x" + "7a" * 32,
        anchor_sequence=11,
        expiry=expiry,
    )


class RawSigner:
    key_path = ROYALTY_SETTLEMENT_SIGNER_KEY_PATH
    custody = ROYALTY_SETTLEMENT_SIGNER_CUSTODY

    def __init__(self, account=MAIN):
        self.account = account
        self.address = account.address.lower()

    def sign_raw_digest(self, digest: str) -> str:
        signed = self.account.unsafe_sign_hash(bytes.fromhex(digest[2:]))
        return "0x" + bytes(signed.signature).hex()


def make_packet(*, intent: RoyaltySettlementIntent | None = None):
    return build_royalty_settlement_authorization_packet(
        release=make_release(),
        intent=intent or make_intent(),
        attestation_evidence_hash="0x" + "7b" * 32,
        signer=RawSigner(),
    )


def make_plan(
    *, intent: RoyaltySettlementIntent | None = None
) -> AuthorizedRoyaltySettlementPlan:
    release = make_release()
    packet = make_packet(intent=intent)
    qvl_digest = royalty_settlement_qvl_authorization_digest(
        chain_id=release.chain_id,
        distributor_address=release.distributor_address,
        authorization=packet.authorization,
    )
    qvl_signed = ROYALTY_QVL.unsafe_sign_hash(bytes.fromhex(qvl_digest[2:]))
    return AuthorizedRoyaltySettlementPlan(
        chain_id=release.chain_id,
        distributor_address=release.distributor_address,
        authorization=packet.authorization,
        settlement_verifier_address=packet.settlement_verifier_address,
        settlement_authorization_digest=packet.settlement_authorization_digest,
        settlement_authorization_signature=packet.settlement_authorization_signature,
        qvl_verifier_address=release.royalty_qvl_verifier_address,
        qvl_policy_commitment=release.royalty_qvl_policy_commitment,
        qvl_authorization_digest=qvl_digest,
        qvl_authorization_signature="0x" + bytes(qvl_signed.signature).hex(),
        qvl_anchor_evidence_commitment="0x" + "7c" * 32,
        qvl_verdict_verifier_address=VERDICT_QVL.address.lower(),
        qvl_verdict_digest="0x" + "7d" * 32,
        qvl_release_policy_hash=release.qvl_release_policy_hash,
        quote_hash="0x" + "7e" * 32,
        report_data=derive_royalty_settlement_report_data(release),
        compose_hash=release.compose_hash,
        app_id=release.app_id,
        os_image_hash=release.os_image_hash,
        authorization_expires_at=packet.authorization.expiry,
    )


def test_royalty_distributor_v3_main_and_qvl_kats_match_contract_types():
    authorization = SettlementAuthorization(
        settlement_id="0x" + "01" * 32,
        settlement_nonce=7,
        funding_reservation_id="0x" + "0f" * 32,
        release_policy_commitment="0x" + "02" * 32,
        room_commitment="0x" + "03" * 32,
        room_state_commitment="0x" + "04" * 32,
        query_commitment="0x" + "05" * 32,
        grant_set_commitment="0x" + "06" * 32,
        allocation_commitment="0x" + "07" * 32,
        owners_amounts_hash="0x" + "08" * 32,
        asset_address="0x" + "77" * 20,
        total=123_456_789,
        execution_commitment="0x" + "09" * 32,
        result_commitment="0x" + "0a" * 32,
        usage_commitment="0x" + "0b" * 32,
        attestation_evidence_hash="0x" + "0c" * 32,
        anchor_resource_hash="0x" + "0d" * 32,
        anchor_decision_hash="0x" + "0e" * 32,
        anchor_sequence=11,
        expiry=1_800_000_060,
    )
    main_digest = royalty_settlement_authorization_digest(
        chain_id=BASE_SEPOLIA_CHAIN_ID,
        distributor_address="0x" + "55" * 20,
        authorization=authorization,
    )
    qvl_digest = royalty_settlement_qvl_authorization_digest(
        chain_id=BASE_SEPOLIA_CHAIN_ID,
        distributor_address="0x" + "55" * 20,
        authorization=authorization,
    )
    assert main_digest == (
        "0x1f6a8677f6a1260071142b5485d2e41bcd7bad78a96b3990728f223c993523b8"
    )
    assert qvl_digest == (
        "0x872ab0d5ca653512b5fe9eed6da617e0f9c9a46691027c034bf18a134b27df2d"
    )
    assert main_digest != qvl_digest

    mutations = {
        "settlement_id": "0x" + "81" * 32,
        "settlement_nonce": 8,
        "funding_reservation_id": "0x" + "80" * 32,
        "release_policy_commitment": "0x" + "82" * 32,
        "room_commitment": "0x" + "83" * 32,
        "room_state_commitment": "0x" + "84" * 32,
        "query_commitment": "0x" + "85" * 32,
        "grant_set_commitment": "0x" + "86" * 32,
        "allocation_commitment": "0x" + "87" * 32,
        "owners_amounts_hash": "0x" + "88" * 32,
        "asset_address": "0x" + "89" * 20,
        "total": 123_456_790,
        "execution_commitment": "0x" + "8a" * 32,
        "result_commitment": "0x" + "8b" * 32,
        "usage_commitment": "0x" + "8c" * 32,
        "attestation_evidence_hash": "0x" + "8d" * 32,
        "anchor_resource_hash": "0x" + "8e" * 32,
        "anchor_decision_hash": "0x" + "8f" * 32,
        "anchor_sequence": 12,
        "expiry": authorization.expiry + 1,
    }
    for field_name, value in mutations.items():
        mutated = replace(authorization, **{field_name: value})
        assert royalty_settlement_authorization_digest(
            chain_id=BASE_SEPOLIA_CHAIN_ID,
            distributor_address="0x" + "55" * 20,
            authorization=mutated,
        ) != main_digest
        assert royalty_settlement_qvl_authorization_digest(
            chain_id=BASE_SEPOLIA_CHAIN_ID,
            distributor_address="0x" + "55" * 20,
            authorization=mutated,
        ) != qvl_digest
    assert royalty_settlement_authorization_digest(
        chain_id=1,
        distributor_address="0x" + "55" * 20,
        authorization=authorization,
    ) != main_digest


def test_strict_packet_covers_all_20_fields_and_recomputes_anchor_hashes():
    release = make_release()
    intent = make_intent()
    packet = make_packet()
    public = packet.to_qvl_dict()
    contract_fields = {
        "settlement_id",
        "settlement_nonce",
        "funding_reservation_id",
        "release_policy_commitment",
        "room_commitment",
        "room_state_commitment",
        "query_commitment",
        "grant_set_commitment",
        "allocation_commitment",
        "owners_amounts_hash",
        "asset",
        "total",
        "execution_commitment",
        "result_commitment",
        "usage_commitment",
        "attestation_evidence_hash",
        "anchor_resource_hash",
        "anchor_decision_hash",
        "anchor_sequence",
        "expiry",
    }
    assert set(public) == contract_fields | {
        "schema",
        "settlement_authorization_digest",
        "settlement_authorization_signature",
    }
    assert public["schema"] == (
        "dnai.royalty-settlement-qvl-authorization-request.v2"
    )
    assert isinstance(public["settlement_nonce"], str)
    assert isinstance(public["total"], str)
    assert isinstance(public["anchor_sequence"], str)
    assert packet.authorization.release_policy_commitment == (
        release.release_policy_commitment
    )
    assert packet.authorization.anchor_resource_hash == (
        royalty_collaboration_resource_hash(
            chain_id=release.chain_id,
            distributor_address=release.distributor_address,
            room_commitment=intent.room_commitment,
            query_commitment=intent.query_commitment,
        )
    )
    assert packet.authorization.anchor_decision_hash == (
        royalty_settlement_decision_hash(
            chain_id=release.chain_id,
            distributor_address=release.distributor_address,
            authorization=packet.authorization,
        )
    )
    assert recover_raw_digest_address(
        digest=packet.settlement_authorization_digest,
        signature=packet.settlement_authorization_signature,
    ) == MAIN.address.lower()


def test_release_policy_role_and_commitment_drift_fail_closed():
    release = make_release()
    with pytest.raises(RoyaltySettlementAuthorizationError):
        replace(release, release_policy_commitment="0x" + "91" * 32)
    with pytest.raises(RoyaltySettlementAuthorizationError):
        replace(
            release,
            royalty_qvl_verifier_address=release.settlement_verifier_address,
        )
    with pytest.raises(RoyaltySettlementAuthorizationError):
        replace(release, royalty_qvl_policy_commitment="0x" + "92" * 32)


def test_wrong_main_signer_role_is_rejected_before_packet_creation():
    with pytest.raises(
        RoyaltySettlementAuthorizationError,
        match="purpose-separated release role",
    ):
        build_royalty_settlement_authorization_packet(
            release=make_release(),
            intent=make_intent(),
            attestation_evidence_hash="0x" + "93" * 32,
            signer=RawSigner(Account.from_key("0x" + "99" * 32)),
        )


def test_dstack_signer_rejects_disabled_and_simulator_custody():
    with patch(
        "tinker_delegate.royalty_settlement_authorization.dstack_utils.is_dstack_enabled",
        return_value=False,
    ):
        with pytest.raises(RoyaltySettlementSignerUnavailable):
            DstackRoyaltySettlementSigner.from_dstack()
    with (
        patch(
            "tinker_delegate.royalty_settlement_authorization.dstack_utils.is_dstack_enabled",
            return_value=True,
        ),
        patch(
            "tinker_delegate.royalty_settlement_authorization.dstack_utils.is_dstack_simulator",
            return_value=True,
        ),
    ):
        with pytest.raises(RoyaltySettlementSignerUnavailable):
            DstackRoyaltySettlementSigner.from_dstack()


def test_plan_replay_is_exact_only_and_never_claims_chain_side_effects():
    plan = make_plan()
    binder = RoyaltySettlementReplayBinder()
    assert binder.bind(plan) is False
    assert binder.bind(plan) is True
    drifted = replace(plan, qvl_verdict_digest="0x" + "94" * 32)
    assert drifted.settlement_scope == plan.settlement_scope
    assert drifted.plan_commitment != plan.plan_commitment
    with pytest.raises(RoyaltySettlementReplayConflict):
        binder.bind(drifted)

    public = plan.to_public_dict()
    assert public["status"] == "dual_authorized_not_broadcast"
    assert public["independent_qvl_tdx_verified"] is True
    assert public["funding_evidence_supplied"] is False
    assert public["anchor_finality_evidence_supplied"] is False
    assert public["contract_broadcast_performed"] is False
    assert public["finalized_chain_receipt_supplied"] is False
    assert public["withdrawal_performed"] is False
    assert public["raw_quote_egress"] is False
    assert public["provider_credential_egress"] is False
    plan.require_unexpired(now=NOW)
    with pytest.raises(RoyaltySettlementAuthorizationError, match="expired"):
        plan.require_unexpired(now=plan.authorization_expires_at)


def test_dual_authorized_plan_round_trips_strictly_for_durable_persistence():
    plan = make_plan()
    serialized = plan.to_public_dict()
    restored = AuthorizedRoyaltySettlementPlan.from_public_dict(serialized)
    assert restored.plan_commitment == plan.plan_commitment
    assert restored.settlement_scope == plan.settlement_scope
    assert restored.to_public_dict() == serialized

    mutations = (
        {**serialized, "schema": "dnai.royalty-settlement-authorization-plan.v1"},
        {**serialized, "status": "settled"},
        {**serialized, "contract_broadcast_performed": True},
        {**serialized, "plan_commitment": "0x" + "ff" * 32},
        {**serialized, "unexpected": True},
    )
    for mutation in mutations:
        with pytest.raises(
            RoyaltySettlementAuthorizationError,
            match="serialization drifted",
        ):
            AuthorizedRoyaltySettlementPlan.from_public_dict(mutation)

    incomplete = dict(serialized)
    incomplete.pop("qvl_authorization_signature")
    with pytest.raises(
        RoyaltySettlementAuthorizationError,
        match="serialization is incomplete",
    ):
        AuthorizedRoyaltySettlementPlan.from_public_dict(incomplete)


def test_dual_authorized_plan_exports_only_exact_settle_reserved_calldata():
    recipients = (
        DistributionRecipient("0x" + "12" * 20, 700),
        DistributionRecipient("0x" + "34" * 20, 300),
    )
    intent = replace(
        make_intent(),
        owners_amounts_hash=compute_owner_amounts_hash(recipients),
    )
    plan = make_plan(intent=intent)
    broadcast = plan.build_settle_reserved_broadcast_plan(recipients=recipients)

    assert broadcast.prefunded is True
    assert broadcast.function == SETTLE_RESERVED_FUNCTION
    assert bytes.fromhex(broadcast.calldata[2:10]) == SETTLE_RESERVED_SELECTOR
    assert broadcast.funding_reservation_id == intent.royalty_reservation_id
    assert "--value" not in broadcast.cast_command
    assert "--account dev" in broadcast.cast_command


def test_contract_domain_typehash_components_are_exact():
    assert EIP712_DOMAIN_TYPEHASH == keccak(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    )
    assert ROYALTY_DISTRIBUTOR_NAME_HASH == keccak(b"DNAI Royalty Distributor")
    assert ROYALTY_DISTRIBUTOR_VERSION_HASH == keccak(b"3")
