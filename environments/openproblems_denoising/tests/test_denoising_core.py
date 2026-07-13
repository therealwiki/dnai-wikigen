"""Offline tests for the framework-free denoising core (numpy only)."""
import sys
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from denoising_core import (  # noqa: E402
    RewardBand,
    band_to_scalar,
    compute_denoising_metrics,
    log_normalized_mse,
    poisson_nll,
    public_problem,
    reward_band,
)
from openproblems_denoising import score_denoised_matrix  # noqa: E402


def _rng(seed: int) -> np.random.Generator:
    return np.random.default_rng(seed)


class DenoisingCoreTest(unittest.TestCase):
    def test_perfect_denoiser_has_zero_mse(self):
        test = _rng(1).poisson(3.0, size=(20, 8)).astype(float)
        self.assertAlmostEqual(log_normalized_mse(test, test), 0.0, places=12)

    def test_mse_and_poisson_reject_bad_shapes(self):
        a = np.ones((3, 4))
        b = np.ones((3, 5))
        with self.assertRaises(ValueError):
            log_normalized_mse(a, b)
        with self.assertRaises(ValueError):
            poisson_nll(a, b)

    def test_negative_counts_rejected(self):
        with self.assertRaises(ValueError):
            log_normalized_mse(-np.ones((2, 2)), np.ones((2, 2)))

    def test_better_denoiser_bands_higher(self):
        rng = _rng(2)
        truth = rng.poisson(5.0, size=(40, 12)).astype(float)
        train = rng.binomial(truth.astype(int), 0.5).astype(float)
        test = truth - train
        # A denoiser that recovers the smooth structure: mean-fill per gene.
        good = np.broadcast_to(test.mean(axis=0, keepdims=True), test.shape).copy()
        good_metrics = compute_denoising_metrics(good, train, test)
        # A denoiser that just returns noise scaled up.
        bad = train * 100.0
        bad_metrics = compute_denoising_metrics(bad, train, test)
        self.assertGreater(good_metrics.mse_improvement(), bad_metrics.mse_improvement())

    def test_poisson_constraint_violation_caps_band(self):
        rng = _rng(3)
        truth = rng.poisson(4.0, size=(30, 10)).astype(float)
        train = rng.binomial(truth.astype(int), 0.5).astype(float)
        test = truth - train
        metrics = compute_denoising_metrics(train, train, test)
        # Force a Poisson violation by hand and confirm the band caps out.
        from denoising_core import DenoisingMetrics

        violating = DenoisingMetrics(
            mse=metrics.mse * 0.1,  # great MSE
            poisson=metrics.baseline_poisson + 1.0,  # but worse Poisson
            baseline_mse=metrics.baseline_mse,
            baseline_poisson=metrics.baseline_poisson,
        )
        self.assertEqual(reward_band(violating), RewardBand.NEGLIGIBLE)

    def test_band_scalars_are_quantized_and_ordered(self):
        self.assertEqual(band_to_scalar(RewardBand.EXCEPTIONAL), 1.0)
        self.assertGreater(
            band_to_scalar(RewardBand.HIGH), band_to_scalar(RewardBand.MEDIUM)
        )
        self.assertEqual(band_to_scalar(RewardBand.NEGLIGIBLE), 0.0)

    def test_public_problem_is_egress_safe(self):
        problem = public_problem()
        self.assertFalse(problem["raw_data_egress"])
        self.assertEqual(problem["data_sensitivity"], "public_benchmark")
        self.assertEqual(problem["reward_kind"], "band")

    def test_score_helper_returns_only_bounded_fields(self):
        rng = _rng(4)
        truth = rng.poisson(5.0, size=(25, 9)).astype(float)
        train = rng.binomial(truth.astype(int), 0.5).astype(float)
        test = truth - train
        result = score_denoised_matrix(train, train, test)
        self.assertIn("reward_band", result)
        self.assertFalse(result["raw_secret_egress"])
        # No exact metric fields leak.
        self.assertNotIn("mse", result)
        self.assertNotIn("poisson", result)


if __name__ == "__main__":
    unittest.main()
