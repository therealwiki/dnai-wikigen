from __future__ import annotations

import pytest
from eth_abi import encode
from eth_account.messages import encode_typed_data
from eth_utils import keccak

from compute_metering.errors import ChainStateRejected, UpstreamUnavailable
from compute_metering.evm import (
    METERING_QVL_RECEIPT_TYPE,
    METERING_RECEIPT_TYPE,
    USAGE_COMMITMENT_TYPE,
    checked_add,
    checked_mul,
    compute_metering_qvl_receipt_digest,
    compute_metering_receipt_digest,
    compute_onchain_usage_commitment,
    decode_call_result,
    decode_quantity,
    encode_call,
    selector,
)
from compute_metering.models import UINT256_MAX
from tests.support import (
    ASSET,
    ATTESTATION_EVIDENCE_HASH,
    COMPOSE_HASH,
    DISPATCH_INTENT_COMMITMENT,
    JOB_ID,
    MANIFEST_COMMITMENT,
    NOW,
    PROJECT_ID,
    START_COMMITMENT,
    TEE,
    USER,
    VAULT,
    WORKLOAD_COMMITMENT,
)


def _receipt_fields() -> dict[str, object]:
    return dict(
        chain_id=84_532,
        vault_address=VAULT,
        project_id=PROJECT_ID,
        job_id=JOB_ID,
        user=USER,
        asset=ASSET,
        authorization_nonce=7,
        max_asset_debit=1000,
        actual_asset_debit=750,
        authorization_expiry=NOW + 600,
        rate_policy_commitment="0x" + "41" * 32,
        workload_commitment=WORKLOAD_COMMITMENT,
        manifest_commitment=MANIFEST_COMMITMENT,
        dispatch_intent_commitment=DISPATCH_INTENT_COMMITMENT,
        tee_identity=TEE,
        compose_hash=COMPOSE_HASH,
        start_commitment=START_COMMITMENT,
        billable_compute_units=1_500_000,
        usage_started_at=NOW - 60,
        usage_ended_at=NOW - 30,
        usage_commitment="0x" + "42" * 32,
        metering_policy_set_hash="0x" + "43" * 32,
        attestation_evidence_hash=ATTESTATION_EVIDENCE_HASH,
        receipt_expiry=NOW + 100,
    )


def _digest() -> str:
    return compute_metering_receipt_digest(**_receipt_fields())


def test_manual_digest_matches_eth_account_eip712_encoding():
    typed = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "ComputeMeteringReceipt": [
                {"name": "projectId", "type": "bytes32"},
                {"name": "jobId", "type": "bytes32"},
                {"name": "user", "type": "address"},
                {"name": "asset", "type": "address"},
                {"name": "authorizationNonce", "type": "uint256"},
                {"name": "maxAssetDebit", "type": "uint256"},
                {"name": "actualAssetDebit", "type": "uint256"},
                {"name": "authorizationExpiry", "type": "uint256"},
                {"name": "ratePolicyCommitment", "type": "bytes32"},
                {"name": "workloadCommitment", "type": "bytes32"},
                {"name": "manifestCommitment", "type": "bytes32"},
                {"name": "dispatchIntentCommitment", "type": "bytes32"},
                {"name": "teeIdentity", "type": "address"},
                {"name": "composeHash", "type": "bytes32"},
                {"name": "startCommitment", "type": "bytes32"},
                {"name": "billableComputeUnits", "type": "uint256"},
                {"name": "usageStartedAt", "type": "uint256"},
                {"name": "usageEndedAt", "type": "uint256"},
                {"name": "usageCommitment", "type": "bytes32"},
                {"name": "meteringPolicySetHash", "type": "bytes32"},
                {"name": "attestationEvidenceHash", "type": "bytes32"},
                {"name": "receiptExpiry", "type": "uint256"},
            ],
        },
        "primaryType": "ComputeMeteringReceipt",
        "domain": {
            "name": "DNAI Compute Credit Vault",
            "version": "2",
            "chainId": 84_532,
            "verifyingContract": VAULT,
        },
        "message": {
            "projectId": PROJECT_ID,
            "jobId": JOB_ID,
            "user": USER,
            "asset": ASSET,
            "authorizationNonce": 7,
            "maxAssetDebit": 1000,
            "actualAssetDebit": 750,
            "authorizationExpiry": NOW + 600,
            "ratePolicyCommitment": "0x" + "41" * 32,
            "workloadCommitment": WORKLOAD_COMMITMENT,
            "manifestCommitment": MANIFEST_COMMITMENT,
            "dispatchIntentCommitment": DISPATCH_INTENT_COMMITMENT,
            "teeIdentity": TEE,
            "composeHash": COMPOSE_HASH,
            "startCommitment": START_COMMITMENT,
            "billableComputeUnits": 1_500_000,
            "usageStartedAt": NOW - 60,
            "usageEndedAt": NOW - 30,
            "usageCommitment": "0x" + "42" * 32,
            "meteringPolicySetHash": "0x" + "43" * 32,
            "attestationEvidenceHash": ATTESTATION_EVIDENCE_HASH,
            "receiptExpiry": NOW + 100,
        },
    }
    message = encode_typed_data(full_message=typed)
    independently_encoded = "0x" + keccak(b"\x19" + message.version + message.header + message.body).hex()
    assert independently_encoded == _digest()
    assert METERING_RECEIPT_TYPE.startswith("ComputeMeteringReceipt(bytes32 projectId")


def test_qvl_domain_is_distinct_and_usage_commitment_is_exact():
    fields = _receipt_fields()
    meter_digest = compute_metering_receipt_digest(**fields)
    qvl_digest = compute_metering_qvl_receipt_digest(**fields)
    assert meter_digest != qvl_digest
    assert METERING_QVL_RECEIPT_TYPE.startswith(
        "ComputeMeteringQvlReceipt(bytes32 projectId"
    )

    usage_fields = dict(fields)
    usage_fields.pop("usage_commitment")
    usage_fields.pop("receipt_expiry")
    expected = keccak(
        encode(
            [
                "bytes32", "uint256", "address", "bytes32", "bytes32", "address",
                "address", "uint256", "uint256", "uint256", "uint256", "bytes32",
                "bytes32", "bytes32", "bytes32", "address", "bytes32", "bytes32",
                "uint256", "uint256", "uint256", "bytes32", "bytes32",
            ],
            [
                keccak(text=USAGE_COMMITMENT_TYPE),
                usage_fields["chain_id"],
                usage_fields["vault_address"],
                bytes.fromhex(str(usage_fields["project_id"])[2:]),
                bytes.fromhex(str(usage_fields["job_id"])[2:]),
                usage_fields["user"],
                usage_fields["asset"],
                usage_fields["authorization_nonce"],
                usage_fields["max_asset_debit"],
                usage_fields["actual_asset_debit"],
                usage_fields["authorization_expiry"],
                bytes.fromhex(str(usage_fields["rate_policy_commitment"])[2:]),
                bytes.fromhex(str(usage_fields["workload_commitment"])[2:]),
                bytes.fromhex(str(usage_fields["manifest_commitment"])[2:]),
                bytes.fromhex(str(usage_fields["dispatch_intent_commitment"])[2:]),
                usage_fields["tee_identity"],
                bytes.fromhex(str(usage_fields["compose_hash"])[2:]),
                bytes.fromhex(str(usage_fields["start_commitment"])[2:]),
                usage_fields["billable_compute_units"],
                usage_fields["usage_started_at"],
                usage_fields["usage_ended_at"],
                bytes.fromhex(str(usage_fields["metering_policy_set_hash"])[2:]),
                bytes.fromhex(str(usage_fields["attestation_evidence_hash"])[2:]),
            ],
        )
    )
    assert compute_onchain_usage_commitment(**usage_fields) == "0x" + expected.hex()


def test_function_selector_and_abi_call_encoding_are_exact():
    signature = "getJob(bytes32)"
    data = encode_call(signature, ("bytes32",), (bytes.fromhex(JOB_ID[2:]),))
    assert data[:10] == "0x" + selector(signature).hex()
    assert bytes.fromhex(data[10:]) == encode(["bytes32"], [bytes.fromhex(JOB_ID[2:])])


def test_abi_decoder_rejects_malformed_noncanonical_and_oversized_results():
    assert decode_call_result("0x" + encode(["uint16"], [500]).hex(), ("uint16",)) == (500,)
    for value in (None, "0X00", "0x0", "0xzz", "0x" + "00" * 20):
        with pytest.raises(UpstreamUnavailable):
            decode_call_result(value, ("uint256",))
    with pytest.raises(UpstreamUnavailable):
        decode_call_result("0x" + "00" * 20_000, ("uint256",))


@pytest.mark.parametrize(
    ("value", "expected"),
    [("0x0", 0), ("0x1", 1), ("0xabcdef", 0xABCDEF)],
)
def test_quantity_decoder_accepts_only_canonical_hex(value, expected):
    assert decode_quantity(value) == expected


@pytest.mark.parametrize("value", ["0x", "0x00", "0x01", "0X1", "1", -1, None, True])
def test_quantity_decoder_rejects_noncanonical_values(value):
    with pytest.raises(UpstreamUnavailable):
        decode_quantity(value)


def test_uint256_arithmetic_detects_overflow_without_overflowing_ceiling_trick():
    assert checked_mul(3, 4) == 12
    assert checked_add(UINT256_MAX - 1, 1) == UINT256_MAX
    with pytest.raises(ChainStateRejected):
        checked_mul(UINT256_MAX, 2)
    with pytest.raises(ChainStateRejected):
        checked_add(UINT256_MAX, 1)
