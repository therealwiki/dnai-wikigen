import json
import sys
import types
import unittest


sys.modules.setdefault(
    "tinker",
    types.SimpleNamespace(ServiceClient=object, TrainingClient=object, SamplingClient=object),
)

from tinker_delegate.cost_metering import (  # noqa: E402
    CostReconciliationStatus,
    reconcile_costs,
    reconcile_from_meter,
)
from tinker_delegate.private_reward import assert_bounded_egress  # noqa: E402


class ReconcileCostsTest(unittest.TestCase):
    def _base(self, **kw):
        args = dict(
            model="meta-llama/Llama-3.1-8B",
            estimated_cost_wei=1_000,
            chain_compute_cost_wei=1_000,
            budget_cap_wei=10_000,
            fee_wei=10,
        )
        args.update(kw)
        return reconcile_costs(**args)

    def test_reconciled_when_all_views_agree(self):
        rec = self._base()
        self.assertEqual(rec.status, CostReconciliationStatus.RECONCILED)
        self.assertTrue(rec.settlement_safe)
        self.assertFalse(rec.over_budget)
        self.assertEqual(rec.budget_remaining_wei, 9_000)

    def test_chain_below_estimate_is_still_reconciled(self):
        # The buyer simply pays less than metered — not an integrity fault.
        rec = self._base(chain_compute_cost_wei=800)
        self.assertEqual(rec.status, CostReconciliationStatus.RECONCILED)
        self.assertTrue(rec.settlement_safe)
        self.assertEqual(rec.budget_remaining_wei, 9_200)

    def test_over_budget_fails_closed(self):
        rec = self._base(chain_compute_cost_wei=12_000)
        self.assertEqual(rec.status, CostReconciliationStatus.OVER_BUDGET)
        self.assertTrue(rec.over_budget)
        self.assertFalse(rec.settlement_safe)
        self.assertEqual(rec.budget_remaining_wei, 0)  # floored, never negative

    def test_chain_exceeds_estimate_fails_closed(self):
        # On-chain charge above the delegate's own metered estimate = overcharge.
        rec = self._base(chain_compute_cost_wei=1_500)
        self.assertEqual(rec.status, CostReconciliationStatus.CHAIN_EXCEEDS_ESTIMATE)
        self.assertFalse(rec.settlement_safe)

    def test_over_budget_takes_priority_over_chain_exceeds_estimate(self):
        # Both faults present; buyer-harm (over budget) is reported first.
        rec = self._base(estimated_cost_wei=1_000, chain_compute_cost_wei=20_000)
        self.assertEqual(rec.status, CostReconciliationStatus.OVER_BUDGET)

    def test_over_budget_boundary_matches_onchain_strict_rule(self):
        # The off-chain gate's OVER_BUDGET boundary MUST match the on-chain
        # DiligenceRoom rule `offer + computeCost + fee > budgetCap` exactly: a
        # total charge equal to the cap is in-budget on both sides (strict `>`),
        # and cap+1 is over on both. A silent divergence here would either revert
        # valid settlements on chain or bless over-budget ones off chain.
        at_cap = self._base(
            estimated_cost_wei=1_000, chain_compute_cost_wei=1_000, budget_cap_wei=1_000
        )
        self.assertEqual(at_cap.status, CostReconciliationStatus.RECONCILED)
        self.assertTrue(at_cap.settlement_safe)
        self.assertFalse(at_cap.over_budget)
        self.assertEqual(at_cap.budget_remaining_wei, 0)

        over = self._base(
            estimated_cost_wei=1_001, chain_compute_cost_wei=1_001, budget_cap_wei=1_000
        )
        self.assertEqual(over.status, CostReconciliationStatus.OVER_BUDGET)
        self.assertTrue(over.over_budget)

    def test_reported_mismatch_fails_closed(self):
        rec = self._base(reported_cost_wei=5_000)
        self.assertEqual(rec.status, CostReconciliationStatus.REPORTED_MISMATCH)
        self.assertFalse(rec.settlement_safe)

    def test_reported_within_tolerance_reconciles(self):
        # 200 bps = 2% slack lets a small reported/estimate gap reconcile.
        rec = self._base(estimated_cost_wei=1_000, reported_cost_wei=1_015, tolerance_bps=200)
        self.assertEqual(rec.status, CostReconciliationStatus.RECONCILED)

    def test_tolerance_allows_small_chain_overage(self):
        rec = self._base(estimated_cost_wei=1_000, chain_compute_cost_wei=1_010, tolerance_bps=200)
        self.assertEqual(rec.status, CostReconciliationStatus.RECONCILED)

    def test_negative_input_is_invalid(self):
        rec = self._base(chain_compute_cost_wei=-1)
        self.assertEqual(rec.status, CostReconciliationStatus.INVALID)
        self.assertFalse(rec.settlement_safe)

    def test_public_dict_is_bounded(self):
        rec = self._base(model="secret/model-name", reported_cost_wei=1_000)
        public = rec.to_public_dict()
        # Wei amounts are banded, not raw (1_000 wei -> "<1e6").
        self.assertEqual(public["estimated_cost_band"], "<1e6")
        self.assertFalse(public["raw_secret_egress"])
        # No raw wei integer leaks into the bounded dict.
        blob = json.dumps(public)
        self.assertNotIn("1000", blob)
        # It passes the shared egress guard (cost bands are safe bounded egress).
        assert_bounded_egress(public)

    def test_model_label_is_sanitized(self):
        rec = self._base(model="  Weird Model!! v2  ")
        self.assertNotIn("!", rec.model)
        self.assertNotIn(" ", rec.model)


class ReconcileFromMeterTest(unittest.TestCase):
    def test_reconciles_against_a_real_cost_meter(self):
        # Drive the actual metering path: record tokens, then reconcile the
        # metered estimate against a matching chain cost and a budget.
        from tinker_delegate.session import CostMeter

        meter = CostMeter(model="meta-llama/Llama-3.1-8B")
        meter.record_train(1_000_000)
        meter.record_sample(200_000)
        estimate = meter.total_cost_wei
        self.assertGreater(estimate, 0)

        rec = reconcile_from_meter(
            meter,
            chain_compute_cost_wei=estimate,
            budget_cap_wei=estimate * 4,
            tolerance_bps=0,
        )
        self.assertEqual(rec.status, CostReconciliationStatus.RECONCILED)
        self.assertTrue(rec.settlement_safe)
        self.assertEqual(rec.estimated_cost_wei, estimate)
        self.assertEqual(rec.fee_wei, meter.fee_wei)

    def test_meter_estimate_over_budget_fails_closed(self):
        from tinker_delegate.session import CostMeter

        meter = CostMeter(model="meta-llama/Llama-3.1-8B")
        meter.record_train(5_000_000)
        estimate = meter.total_cost_wei
        rec = reconcile_from_meter(
            meter,
            chain_compute_cost_wei=estimate,
            budget_cap_wei=estimate // 2,  # buyer authorized less than metered
        )
        self.assertEqual(rec.status, CostReconciliationStatus.OVER_BUDGET)
        self.assertFalse(rec.settlement_safe)


if __name__ == "__main__":
    unittest.main()
