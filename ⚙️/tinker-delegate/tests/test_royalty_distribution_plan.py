import json
import shutil
import subprocess
import unittest
from dataclasses import replace

from tinker_delegate.royalty_distribution_plan import (
    DISTRIBUTE_ERC20_FUNCTION,
    DISTRIBUTE_NATIVE_FUNCTION,
    SETTLE_RESERVED_FUNCTION,
    DistributionRecipient,
    RoyaltyDistributionError,
    SettlementAuthorization,
    build_royalty_distribution_plan,
    compute_owner_amounts_hash,
)

CONTRACT = "0x" + "55" * 20
TOKEN = "0x" + "66" * 20
OWNER_A = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
OWNER_B = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
SIGNATURE = "0x" + "aa" * 65
QVL_SIGNATURE = "0x" + "bb" * 65


def _cast_calldata(sig: str, *args: str) -> str:
    return subprocess.run(
        ["cast", "calldata", sig, *args], check=True, text=True, capture_output=True
    ).stdout.strip()


def _recipients():
    return [DistributionRecipient(OWNER_A, 700), DistributionRecipient(OWNER_B, 300)]


def _authorization(asset: str = "0x" + "00" * 20, recipients=None) -> SettlementAuthorization:
    recipients = recipients or _recipients()
    return SettlementAuthorization(
        settlement_id="0x" + "01" * 32,
        settlement_nonce=7,
        funding_reservation_id="0x" + "00" * 32,
        release_policy_commitment="0x" + "02" * 32,
        room_commitment="0x" + "03" * 32,
        room_state_commitment="0x" + "04" * 32,
        query_commitment="0x" + "05" * 32,
        grant_set_commitment="0x" + "06" * 32,
        allocation_commitment="0x" + "07" * 32,
        owners_amounts_hash=compute_owner_amounts_hash(recipients),
        asset_address=asset,
        total=sum(recipient.amount for recipient in recipients),
        execution_commitment="0x" + "08" * 32,
        result_commitment="0x" + "09" * 32,
        usage_commitment="0x" + "0a" * 32,
        attestation_evidence_hash="0x" + "0b" * 32,
        anchor_resource_hash="0x" + "0c" * 32,
        anchor_decision_hash="0x" + "0d" * 32,
        anchor_sequence=19,
        expiry=2_000_000_000,
    )


def _tuple_argument(authorization: SettlementAuthorization) -> str:
    return "(" + ",".join(
        (
            authorization.settlement_id,
            str(authorization.settlement_nonce),
            authorization.funding_reservation_id,
            authorization.release_policy_commitment,
            authorization.room_commitment,
            authorization.room_state_commitment,
            authorization.query_commitment,
            authorization.grant_set_commitment,
            authorization.allocation_commitment,
            authorization.owners_amounts_hash,
            authorization.asset_address,
            str(authorization.total),
            authorization.execution_commitment,
            authorization.result_commitment,
            authorization.usage_commitment,
            authorization.attestation_evidence_hash,
            authorization.anchor_resource_hash,
            authorization.anchor_decision_hash,
            str(authorization.anchor_sequence),
            str(authorization.expiry),
        )
    ) + ")"


class RoyaltyDistributionPlanTest(unittest.TestCase):
    def test_native_plan_shape(self):
        authorization = _authorization()
        plan = build_royalty_distribution_plan(
            contract_address=CONTRACT,
            authorization=authorization,
            recipients=_recipients(),
            settlement_signature=SIGNATURE,
            qvl_signature=QVL_SIGNATURE,
        )
        self.assertTrue(plan.native)
        self.assertEqual(plan.total_amount, 1000)
        self.assertEqual(plan.recipient_count, 2)
        self.assertEqual(plan.settlement_id, authorization.settlement_id)
        self.assertEqual(plan.owners_amounts_hash, authorization.owners_amounts_hash)
        self.assertIn("distributeNative", plan.function)
        blob = json.dumps(plan.to_public_dict())
        self.assertIn("--account dev", blob)
        self.assertNotIn("--private-key", blob)
        self.assertIn("--value 1000", plan.cast_command)
        self.assertTrue(plan.requires_release_signatures)
        self.assertFalse(plan.raw_secret_egress)

    def test_erc20_plan_shape(self):
        authorization = _authorization(TOKEN)
        plan = build_royalty_distribution_plan(
            contract_address=CONTRACT,
            authorization=authorization,
            recipients=_recipients(),
            settlement_signature=SIGNATURE,
            qvl_signature=QVL_SIGNATURE,
        )
        self.assertFalse(plan.native)
        self.assertIn("distributeERC20", plan.function)
        self.assertNotIn("--value", plan.cast_command)
        self.assertEqual(plan.asset_address.lower(), TOKEN.lower())

    @unittest.skipUnless(shutil.which("cast"), "cast not on PATH")
    def test_prefunded_plan_uses_exact_reserved_settlement_without_value(self):
        reservation_id = "0x" + "ef" * 32
        authorization = replace(
            _authorization(),
            funding_reservation_id=reservation_id,
        )
        plan = build_royalty_distribution_plan(
            contract_address=CONTRACT,
            authorization=authorization,
            recipients=_recipients(),
            settlement_signature=SIGNATURE,
            qvl_signature=QVL_SIGNATURE,
        )
        expected = _cast_calldata(
            SETTLE_RESERVED_FUNCTION,
            reservation_id,
            _tuple_argument(authorization),
            f"[{OWNER_A},{OWNER_B}]",
            "[700,300]",
            SIGNATURE,
            QVL_SIGNATURE,
        )
        self.assertTrue(plan.prefunded)
        self.assertEqual(plan.funding_reservation_id, reservation_id)
        self.assertIn("settleReserved", plan.function)
        self.assertNotIn("--value", plan.cast_command)
        self.assertEqual(plan.calldata.lower(), expected.lower())

    @unittest.skipUnless(shutil.which("cast"), "cast not on PATH")
    def test_native_calldata_matches_cast(self):
        authorization = _authorization()
        recipients = _recipients()
        plan = build_royalty_distribution_plan(
            contract_address=CONTRACT,
            authorization=authorization,
            recipients=recipients,
            settlement_signature=SIGNATURE,
            qvl_signature=QVL_SIGNATURE,
        )
        expected = _cast_calldata(
            DISTRIBUTE_NATIVE_FUNCTION,
            _tuple_argument(authorization),
            f"[{OWNER_A},{OWNER_B}]",
            "[700,300]",
            SIGNATURE,
            QVL_SIGNATURE,
        )
        self.assertEqual(plan.calldata.lower(), expected.lower())

    @unittest.skipUnless(shutil.which("cast"), "cast not on PATH")
    def test_erc20_calldata_matches_cast(self):
        authorization = _authorization(TOKEN)
        recipients = _recipients()
        plan = build_royalty_distribution_plan(
            contract_address=CONTRACT,
            authorization=authorization,
            recipients=recipients,
            settlement_signature=SIGNATURE,
            qvl_signature=QVL_SIGNATURE,
        )
        expected = _cast_calldata(
            DISTRIBUTE_ERC20_FUNCTION,
            _tuple_argument(authorization),
            f"[{OWNER_A},{OWNER_B}]",
            "[700,300]",
            SIGNATURE,
            QVL_SIGNATURE,
        )
        self.assertEqual(plan.calldata.lower(), expected.lower())

    def test_unsigned_or_mismatched_entitlement_is_rejected(self):
        recipients = _recipients()
        authorization = _authorization()
        with self.assertRaises(RoyaltyDistributionError):
            build_royalty_distribution_plan(
                contract_address=CONTRACT,
                authorization=authorization,
                recipients=recipients,
                settlement_signature="0x",
                qvl_signature=QVL_SIGNATURE,
            )

        changed = [DistributionRecipient(OWNER_A, 600), DistributionRecipient(OWNER_B, 400)]
        with self.assertRaises(RoyaltyDistributionError):
            build_royalty_distribution_plan(
                contract_address=CONTRACT,
                authorization=authorization,
                recipients=changed,
                settlement_signature=SIGNATURE,
                qvl_signature=QVL_SIGNATURE,
            )

    def test_empty_duplicate_zero_and_oversized_recipients_are_rejected(self):
        authorization = _authorization()
        for recipients in (
            [],
            [DistributionRecipient(OWNER_A, 500), DistributionRecipient(OWNER_A, 500)],
            [DistributionRecipient("0x" + "00" * 20, 1000)],
            [DistributionRecipient(OWNER_A, 0)],
            [DistributionRecipient("0x" + f"{index + 1:040x}", 1) for index in range(17)],
        ):
            with self.subTest(recipients=recipients):
                with self.assertRaises(RoyaltyDistributionError):
                    build_royalty_distribution_plan(
                        contract_address=CONTRACT,
                        authorization=authorization,
                        recipients=recipients,
                        settlement_signature=SIGNATURE,
                        qvl_signature=QVL_SIGNATURE,
                    )


if __name__ == "__main__":
    unittest.main()
