#!/usr/bin/env python3
"""Emit the Python-owned cross-language ``settleReserved`` calldata vector.

The input mirrors ``web/src/lib/collaborationRoyaltySettlement.test.ts``.
The output is produced by the production Python encoder rather than viem, so
the checked-in JSON can act as an independent browser-parser oracle.
"""

from __future__ import annotations

import hashlib
import json

from tinker_delegate.royalty_distribution_plan import (
    DistributionRecipient,
    SettlementAuthorization,
    build_royalty_distribution_plan,
    compute_owner_amounts_hash,
)


SCHEMA = "dnai.cross-language.settle-reserved-calldata-vector.v1"
CONTRACT_ADDRESS = "0x" + "1" * 40
OWNERS = ("0x" + "8" * 40, "0x" + "9" * 40)
AMOUNTS = (9_007_199_254_740_993, 29)
SETTLEMENT_SIGNATURE = "0x" + "1" * 130
QVL_SIGNATURE = "0x" + "2" * 130


def build_vector() -> dict[str, object]:
    recipients = tuple(
        DistributionRecipient(owner_address=owner, amount=amount)
        for owner, amount in zip(OWNERS, AMOUNTS, strict=True)
    )
    authorization = SettlementAuthorization(
        settlement_id="0x" + "1" * 64,
        settlement_nonce=9_007_199_254_741_011,
        funding_reservation_id="0x" + "2" * 64,
        release_policy_commitment="0x" + "3" * 64,
        room_commitment="0x" + "4" * 64,
        room_state_commitment="0x" + "5" * 64,
        query_commitment="0x" + "6" * 64,
        grant_set_commitment="0x" + "7" * 64,
        allocation_commitment="0x" + "8" * 64,
        owners_amounts_hash=compute_owner_amounts_hash(recipients),
        asset_address="0x" + "0" * 40,
        total=sum(AMOUNTS),
        execution_commitment="0x" + "9" * 64,
        result_commitment="0x" + "a" * 64,
        usage_commitment="0x" + "b" * 64,
        attestation_evidence_hash="0x" + "c" * 64,
        anchor_resource_hash="0x" + "d" * 64,
        anchor_decision_hash="0x" + "e" * 64,
        anchor_sequence=9_007_199_254_741_023,
        expiry=1_900_000_300,
    )
    plan = build_royalty_distribution_plan(
        contract_address=CONTRACT_ADDRESS,
        authorization=authorization,
        recipients=recipients,
        settlement_signature=SETTLEMENT_SIGNATURE,
        qvl_signature=QVL_SIGNATURE,
    )
    calldata_bytes = bytes.fromhex(plan.calldata[2:])
    return {
        "schema": SCHEMA,
        "producer": {
            "language": "python",
            "module": "tinker_delegate.royalty_distribution_plan",
            "function": "build_royalty_distribution_plan",
        },
        "input": {
            "contract_address": CONTRACT_ADDRESS,
            "authorization": {
                "settlement_id": authorization.settlement_id,
                "settlement_nonce": str(authorization.settlement_nonce),
                "funding_reservation_id": authorization.funding_reservation_id,
                "release_policy_commitment": (
                    authorization.release_policy_commitment
                ),
                "room_commitment": authorization.room_commitment,
                "room_state_commitment": authorization.room_state_commitment,
                "query_commitment": authorization.query_commitment,
                "grant_set_commitment": authorization.grant_set_commitment,
                "allocation_commitment": authorization.allocation_commitment,
                "owners_amounts_hash": authorization.owners_amounts_hash,
                "asset": authorization.asset_address,
                "total": str(authorization.total),
                "execution_commitment": authorization.execution_commitment,
                "result_commitment": authorization.result_commitment,
                "usage_commitment": authorization.usage_commitment,
                "attestation_evidence_hash": (
                    authorization.attestation_evidence_hash
                ),
                "anchor_resource_hash": authorization.anchor_resource_hash,
                "anchor_decision_hash": authorization.anchor_decision_hash,
                "anchor_sequence": str(authorization.anchor_sequence),
                "expiry": str(authorization.expiry),
            },
            "owners": list(OWNERS),
            "amounts": [str(amount) for amount in AMOUNTS],
            "settlement_signature": SETTLEMENT_SIGNATURE,
            "qvl_signature": QVL_SIGNATURE,
        },
        "expected": {
            "function": plan.function,
            "selector": plan.calldata[:10],
            "owners_amounts_hash": plan.owners_amounts_hash,
            "authorization_fields_hash": plan.authorization_fields_hash,
            "calldata_byte_length": len(calldata_bytes),
            "calldata_sha256": "sha256:"
            + hashlib.sha256(calldata_bytes).hexdigest(),
            "calldata": plan.calldata,
        },
    }


if __name__ == "__main__":
    print(
        json.dumps(
            build_vector(),
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
            allow_nan=False,
        )
    )
