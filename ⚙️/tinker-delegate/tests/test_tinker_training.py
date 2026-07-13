"""Unit tests for the bounded delegated-training operation (tinker:train).

Covers the pure request-shaping and receipt-bounding logic plus the proxy-scope
wiring. The live SDK path needs a billing-active account; these lock down the
caps, clamps, and no-secret-egress guarantees that hold regardless.
"""
from __future__ import annotations

import unittest

from tinker_delegate.tinker_proxy import SPEND_LIMIT_PROXY_SCOPES, SUPPORTED_PROXY_SCOPES
from tinker_delegate.tinker_training import (
    DEFAULT_TRAIN_MAX_USD,
    HARD_TRAIN_MAX_USD,
    MAX_TRAIN_EXAMPLES,
    MAX_TRAIN_STEPS,
    _DEFAULT_EXAMPLES,
    _train_receipt,
    clamp_steps,
    resolve_examples,
    resolve_train_max_usd,
)


class _Settings:
    train_max_usd = DEFAULT_TRAIN_MAX_USD


class TestResolveTrainMaxUsd(unittest.TestCase):
    def test_default(self):
        self.assertEqual(resolve_train_max_usd(_Settings(), None), DEFAULT_TRAIN_MAX_USD)

    def test_explicit_within_cap(self):
        self.assertEqual(resolve_train_max_usd(_Settings(), 1.0), 1.0)

    def test_rejects_over_hard_cap(self):
        with self.assertRaises(ValueError):
            resolve_train_max_usd(_Settings(), HARD_TRAIN_MAX_USD + 0.01)

    def test_rejects_zero_and_negative(self):
        for bad in (0, -1.0):
            with self.assertRaises(ValueError):
                resolve_train_max_usd(_Settings(), bad)

    def test_rejects_nan_inf(self):
        for bad in (float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                resolve_train_max_usd(_Settings(), bad)


class TestClampSteps(unittest.TestCase):
    def test_normal(self):
        self.assertEqual(clamp_steps(5), 5)

    def test_floor_at_one(self):
        self.assertEqual(clamp_steps(0), 1)
        self.assertEqual(clamp_steps(-3), 1)

    def test_ceiling(self):
        self.assertEqual(clamp_steps(9999), MAX_TRAIN_STEPS)


class TestResolveExamples(unittest.TestCase):
    def test_default_when_none(self):
        self.assertEqual(resolve_examples(None), _DEFAULT_EXAMPLES)

    def test_default_when_empty(self):
        self.assertEqual(resolve_examples(()), _DEFAULT_EXAMPLES)

    def test_caps_count(self):
        many = tuple((f"p{i}", f" c{i}") for i in range(MAX_TRAIN_EXAMPLES + 20))
        self.assertEqual(len(resolve_examples(many)), MAX_TRAIN_EXAMPLES)

    def test_drops_malformed(self):
        mixed = (("good", " yes"), ("", " empty-prompt"), (123, " bad"))
        out = resolve_examples(mixed)
        self.assertEqual(out, (("good", " yes"),))

    def test_all_malformed_falls_back(self):
        self.assertEqual(resolve_examples((("", ""),)), _DEFAULT_EXAMPLES)


class TestTrainReceipt(unittest.TestCase):
    def test_bounded_no_raw_model_or_secret(self):
        r = _train_receipt(
            issued_at=1, deal_id="deal-xyz", model="Qwen/Qwen3-8B", rank=32,
            max_usd=0.25, steps_requested=3, steps_completed=3, success=True,
            outcome="training_completed", furthest_stage="cleanup_completed",
            checkpoint_saved=True, spent_usd=0.02,
        )
        self.assertTrue(r["success"])
        self.assertEqual(r["surface"], "tinker_training")
        self.assertFalse(r["raw_secret_egress"])
        # raw model/deal strings must be hashed, not embedded
        blob = str(r)
        self.assertNotIn("Qwen/Qwen3-8B", blob)
        self.assertNotIn("deal-xyz", blob)
        self.assertEqual(len(r["model_hash"]), 64)
        self.assertIn("metered_cost_band", r)
        self.assertEqual(r["steps_completed"], 3)

    def test_failure_receipt_shape(self):
        r = _train_receipt(
            issued_at=1, deal_id="", model="m", rank=4, max_usd=0.25,
            steps_requested=5, steps_completed=2, success=False,
            outcome="training_failed", furthest_stage="step_2_completed",
            error_kind="RuntimeError",
        )
        self.assertFalse(r["success"])
        self.assertEqual(r["steps_completed"], 2)
        self.assertEqual(r["error_kind"], "RuntimeError")


class TestProxyScopeWiring(unittest.TestCase):
    def test_train_scope_supported(self):
        self.assertIn("tinker:train", SUPPORTED_PROXY_SCOPES)

    def test_train_scope_requires_spend_limit(self):
        self.assertIn("tinker:train", SPEND_LIMIT_PROXY_SCOPES)


if __name__ == "__main__":
    unittest.main()
