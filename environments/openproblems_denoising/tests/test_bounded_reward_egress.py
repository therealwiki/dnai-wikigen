"""Offline leakage-bound tests for the verifiers/prime-rl-facing surface.

`load_environment` needs the heavy verifiers stack, but the leakage-critical
pieces it wires up — the reward function `bounded_denoising_reward` (what a
trainer calls each rollout) and the dataset rows `_build_rows` — are pure and
testable without it. These tests prove the RL-trainer path keeps the private-
reward contract: only a bounded band leaves, raw counts / exact metrics never
land on rollout state or in dataset rows.
"""
import json
import unittest
from unittest.mock import patch

import numpy as np

from denoising_core import RewardBand, band_to_scalar
from openproblems_denoising import _build_rows, bounded_denoising_reward, score_denoised_matrix

_ALLOWED_SCALARS = {band_to_scalar(b) for b in RewardBand}

# Small synthetic split so the reward func runs without the fetched dataset.
_TRAIN = np.array([[10.0, 4.0, 2.0], [8.0, 5.0, 3.0], [9.0, 5.0, 3.0], [7.0, 6.0, 3.0]])
_TEST = np.array([[9.0, 5.0, 3.0], [9.0, 5.0, 3.0], [9.0, 5.0, 3.0], [9.0, 5.0, 3.0]])


class BuildRowsEgressTest(unittest.TestCase):
    def test_rows_carry_only_public_problem_and_split_handle(self):
        rows = _build_rows("some_split", n=2)
        self.assertEqual(len(rows), 2)
        for row in rows:
            # The question is the PUBLIC problem text (JSON) — never raw counts.
            problem = json.loads(row["question"])
            self.assertFalse(problem["raw_data_egress"])
            self.assertEqual(row["answer"], "some_split")
            self.assertEqual(row["info"]["split"], "some_split")
            # No raw count matrix anywhere in the row.
            blob = json.dumps(row)
            self.assertNotIn("10.0", blob)
            self.assertNotIn("[[", blob)  # no nested numeric matrix


class BoundedRewardEgressTest(unittest.TestCase):
    def _reward(self, denoised, state=None):
        with patch("openproblems_denoising.load_split_pair", return_value=(_TRAIN, _TEST)):
            return bounded_denoising_reward(
                completion=denoised.tolist(), answer="synthetic", state=state
            )

    def test_reward_returns_only_a_quantized_band_scalar(self):
        value = self._reward(_TEST.copy())  # perfect denoiser
        self.assertIn(value, _ALLOWED_SCALARS)

    def test_state_records_only_the_band_never_raw_or_exact_metrics(self):
        state: dict = {}
        self._reward(_TEST.copy(), state=state)
        # Exactly one bounded fact is recorded: the band string.
        self.assertIn("metrics", state)
        self.assertIn("denoising_band", state["metrics"])
        self.assertIsInstance(state["metrics"]["denoising_band"], str)
        blob = json.dumps(state)
        # No exact metric keys and no raw count values leak onto rollout state.
        for forbidden in ("mse", "poisson", "10.0", "[["):
            self.assertNotIn(forbidden, blob)

    def test_score_helper_returns_only_bounded_fields(self):
        result = score_denoised_matrix(_TEST.copy(), _TRAIN, _TEST)
        self.assertEqual(set(result), {"reward_band", "reward_scalar", "improved_over_baseline", "raw_secret_egress"})
        self.assertFalse(result["raw_secret_egress"])
        self.assertNotIn("mse", json.dumps(result))

    def test_malformed_completion_fails_closed_to_negligible(self):
        # A malformed / adversarial completion must NOT raise (crashing a rollout)
        # — it earns the NEGLIGIBLE band, matching the private-reward contract.
        negligible = band_to_scalar(RewardBand.NEGLIGIBLE)
        bad_completions = [
            "not json at all",
            [[1, 2], [3]],            # jagged
            "null",
            [[1.0, 2.0, 3.0, 4.0, 5.0]],  # wrong gene count
        ]
        with patch("openproblems_denoising.load_split_pair", return_value=(_TRAIN, _TEST)):
            for bad in bad_completions:
                state: dict = {}
                value = bounded_denoising_reward(completion=bad, answer="synthetic", state=state)
                self.assertEqual(value, negligible)
                self.assertEqual(state["metrics"]["denoising_band"], RewardBand.NEGLIGIBLE.value)

    def test_dataset_unavailable_still_propagates_as_infra_error(self):
        # An unavailable dataset is infrastructure, not a bad candidate: it must
        # propagate (not be masked as negligible), so the failure is visible.
        from denoising_data import DatasetUnavailable

        def _raise(_name):
            raise DatasetUnavailable("missing")

        with patch("openproblems_denoising.load_split_pair", side_effect=_raise):
            with self.assertRaises(DatasetUnavailable):
                bounded_denoising_reward(completion=_TEST.tolist(), answer="synthetic", state={})


if __name__ == "__main__":
    unittest.main()
