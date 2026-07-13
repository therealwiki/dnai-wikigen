import json
import unittest

from tinker_delegate.royalty_settlement import (
    OwnerShare,
    RoyaltyError,
    RoyaltyLedger,
    split_royalty,
)


class SplitRoyaltyTest(unittest.TestCase):
    def test_even_split_conserves(self):
        payouts = split_royalty(100, [OwnerShare("a", 5000), OwnerShare("b", 5000)])
        self.assertEqual({p.owner_ref: p.amount for p in payouts}, {"a": 50, "b": 50})

    def test_uneven_split_conserves_via_largest_remainder(self):
        # 10 wei / three equal owners: 3,3,3 floors + 1 leftover -> total 10.
        payouts = split_royalty(10, [OwnerShare("a", 3333), OwnerShare("b", 3333), OwnerShare("c", 3334)])
        self.assertEqual(sum(p.amount for p in payouts), 10)

    def test_conservation_across_many_amounts_and_weights(self):
        weight_sets = [
            [("a", 10000)],
            [("a", 6000), ("b", 4000)],
            [("a", 3333), ("b", 3333), ("c", 3334)],
            [("a", 1), ("b", 9999)],
            [("a", 2500), ("b", 2500), ("c", 2500), ("d", 2500)],
        ]
        for total in (0, 1, 2, 3, 7, 999, 10**18 + 7):
            for ws in weight_sets:
                shares = [OwnerShare(o, w) for o, w in ws]
                payouts = split_royalty(total, shares)
                self.assertEqual(sum(p.amount for p in payouts), total, (total, ws))
                self.assertTrue(all(p.amount >= 0 for p in payouts))

    def test_deterministic(self):
        shares = [OwnerShare("a", 3333), OwnerShare("b", 3333), OwnerShare("c", 3334)]
        self.assertEqual(split_royalty(7, shares), split_royalty(7, shares))

    def test_weights_must_sum_to_10000(self):
        with self.assertRaises(RoyaltyError):
            split_royalty(100, [OwnerShare("a", 5000), OwnerShare("b", 4000)])

    def test_duplicate_owner_rejected(self):
        with self.assertRaises(RoyaltyError):
            split_royalty(100, [OwnerShare("a", 5000), OwnerShare("a", 5000)])

    def test_negative_total_rejected(self):
        with self.assertRaises(RoyaltyError):
            split_royalty(-1, [OwnerShare("a", 10000)])


class RoyaltyLedgerTest(unittest.TestCase):
    def test_accrual_and_pull_payment_lifecycle(self):
        ledger = RoyaltyLedger()
        shares = [OwnerShare("owner-a", 6000), OwnerShare("owner-b", 4000)]
        ledger.accrue("q1", 100, shares)
        ledger.accrue("q2", 50, shares)
        # 60+30 = 90 for a, 40+20 = 60 for b.
        self.assertEqual(ledger.claimable("owner-a"), 90)
        self.assertEqual(ledger.claimable("owner-b"), 60)
        self.assertEqual(ledger.total_accrued(), 150)
        self.assertEqual(ledger.total_claimable(), 150)

        claimed = ledger.claim("owner-a")
        self.assertEqual(claimed, 90)
        self.assertEqual(ledger.claimable("owner-a"), 0)
        # b is unaffected; the claimed amount is now tracked so conservation
        # (claimable + claimed == accrued) still holds.
        self.assertEqual(ledger.claimable("owner-b"), 60)
        self.assertEqual(ledger.total_claimable() + ledger.total_claimed(), 150)

    def test_ledger_conserves_across_uneven_splits(self):
        ledger = RoyaltyLedger()
        shares = [OwnerShare("a", 3333), OwnerShare("b", 3333), OwnerShare("c", 3334)]
        for i in range(20):
            ledger.accrue(f"q{i}", i + 1, shares)
        self.assertEqual(ledger.total_claimable(), ledger.total_accrued())

    def test_conservation_holds_after_claims(self):
        # True conservation is a three-way ledger: claimable + claimed == accrued.
        # A withdrawal must NOT make the summary report not-conserved (the funds
        # left the pool legitimately, they were not lost).
        ledger = RoyaltyLedger()
        shares = [OwnerShare("a", 6000), OwnerShare("b", 4000)]
        ledger.accrue("q1", 1000, shares)
        ledger.accrue("q2", 333, shares)
        self.assertTrue(ledger.public_summary()["conserved"])

        claimed_a = ledger.claim("a")
        self.assertEqual(ledger.total_claimed(), claimed_a)
        summary = ledger.public_summary()
        self.assertTrue(summary["conserved"], summary)
        self.assertEqual(
            ledger.total_claimable() + ledger.total_claimed(), ledger.total_accrued()
        )

        ledger.claim("b")
        # Everything withdrawn: claimable 0, claimed == accrued, still conserved.
        self.assertEqual(ledger.total_claimable(), 0)
        self.assertEqual(ledger.total_claimed(), ledger.total_accrued())
        self.assertTrue(ledger.public_summary()["conserved"])

    def test_claim_nothing_raises(self):
        ledger = RoyaltyLedger()
        with self.assertRaises(RoyaltyError):
            ledger.claim("nobody")

    def test_public_summary_is_bounded_and_conserved(self):
        ledger = RoyaltyLedger()
        ledger.accrue("q1", 10**17, [OwnerShare("a", 7000), OwnerShare("b", 3000)])
        summary = ledger.public_summary()
        self.assertTrue(summary["conserved"])
        self.assertFalse(summary["raw_secret_egress"])
        self.assertEqual(summary["owner_count"], 2)
        blob = json.dumps(summary)
        self.assertIn("claimable_bands", blob)
        self.assertRegex(summary["settlement_hash"], r"^0x[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
