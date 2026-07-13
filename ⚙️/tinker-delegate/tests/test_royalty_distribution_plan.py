import json
import shutil
import subprocess
import unittest

from tinker_delegate.royalty_distribution_plan import (
    DistributionRecipient,
    RoyaltyDistributionError,
    build_royalty_distribution_plan,
)

CONTRACT = "0x" + "55" * 20
TOKEN = "0x" + "66" * 20
OWNER_A = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
OWNER_B = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
QUERY = "0x" + "a1" * 32


def _cast_calldata(sig: str, *args: str) -> str:
    return subprocess.run(
        ["cast", "calldata", sig, *args], check=True, text=True, capture_output=True
    ).stdout.strip()


class RoyaltyDistributionPlanTest(unittest.TestCase):
    def _recipients(self):
        return [DistributionRecipient(OWNER_A, 700), DistributionRecipient(OWNER_B, 300)]

    def test_native_plan_shape(self):
        plan = build_royalty_distribution_plan(
            contract_address=CONTRACT, query_ref=QUERY, recipients=self._recipients()
        )
        self.assertTrue(plan.native)
        self.assertEqual(plan.total_amount, 1000)
        self.assertEqual(plan.recipient_count, 2)
        self.assertIn("distributeNative", plan.function)
        blob = json.dumps(plan.to_public_dict())
        self.assertIn("--account dev", blob)
        self.assertNotIn("--private-key", blob)
        self.assertIn("--value 1000", plan.cast_command)
        self.assertFalse(plan.raw_secret_egress)

    def test_erc20_plan_shape(self):
        plan = build_royalty_distribution_plan(
            contract_address=CONTRACT,
            query_ref=QUERY,
            recipients=self._recipients(),
            token_address=TOKEN,
        )
        self.assertFalse(plan.native)
        self.assertIn("distributeERC20", plan.function)
        self.assertNotIn("--value", plan.cast_command)
        self.assertIn(TOKEN.lower(), plan.cast_command.lower())

    @unittest.skipUnless(shutil.which("cast"), "cast not on PATH")
    def test_native_calldata_matches_cast(self):
        plan = build_royalty_distribution_plan(
            contract_address=CONTRACT, query_ref=QUERY, recipients=self._recipients()
        )
        expected = _cast_calldata(
            "distributeNative(bytes32,address[],uint256[])",
            QUERY,
            f"[{OWNER_A},{OWNER_B}]",
            "[700,300]",
        )
        self.assertEqual(plan.calldata.lower(), expected.lower())

    @unittest.skipUnless(shutil.which("cast"), "cast not on PATH")
    def test_erc20_calldata_matches_cast(self):
        plan = build_royalty_distribution_plan(
            contract_address=CONTRACT,
            query_ref=QUERY,
            recipients=self._recipients(),
            token_address=TOKEN,
        )
        expected = _cast_calldata(
            "distributeERC20(bytes32,address,address[],uint256[])",
            QUERY,
            TOKEN,
            f"[{OWNER_A},{OWNER_B}]",
            "[700,300]",
        )
        self.assertEqual(plan.calldata.lower(), expected.lower())

    def test_empty_recipients_rejected(self):
        with self.assertRaises(RoyaltyDistributionError):
            build_royalty_distribution_plan(contract_address=CONTRACT, query_ref=QUERY, recipients=[])

    def test_zero_amount_rejected(self):
        with self.assertRaises(RoyaltyDistributionError):
            build_royalty_distribution_plan(
                contract_address=CONTRACT,
                query_ref=QUERY,
                recipients=[DistributionRecipient(OWNER_A, 0)],
            )

    def test_zero_owner_rejected(self):
        with self.assertRaises(RoyaltyDistributionError):
            build_royalty_distribution_plan(
                contract_address=CONTRACT,
                query_ref=QUERY,
                recipients=[DistributionRecipient("0x" + "00" * 20, 100)],
            )

    def test_bad_query_ref_rejected(self):
        with self.assertRaises(RoyaltyDistributionError):
            build_royalty_distribution_plan(
                contract_address=CONTRACT, query_ref="0xdead", recipients=self._recipients()
            )


if __name__ == "__main__":
    unittest.main()
