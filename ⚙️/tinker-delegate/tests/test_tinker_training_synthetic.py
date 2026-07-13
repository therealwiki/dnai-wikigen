"""Drive the full run_tinker_training path with the synthetic Tinker backend.

Proves the delegated-training operation actually executes end-to-end
(create LoRA client -> tokenize -> forward/backward + optim per step ->
checkpoint -> cleanup -> bounded receipt) without live compute. The real SDK is
swapped for FakeTinkerServiceClient via the service_client_factory hook, so this
covers everything our side does — only Tinker's compute (and its 402 billing
gate) is out of scope here.
"""
from __future__ import annotations

import unittest
from unittest import mock

from tinker_delegate.config import Settings
from tinker_delegate.fake_tinker_backend import FakeTinkerServiceClient
from tinker_delegate.tinker_training import TinkerTrainingRequest, run_tinker_training


class TestRunTinkerTrainingSynthetic(unittest.TestCase):
    def _run(self, steps: int, max_usd: float | None = None):
        settings = Settings(
            real_sdk_model="meta-llama/Llama-3.2-1B",
            real_sdk_rank=4,
            train_max_usd=0.25,
            encumbrance_required=False,
        )
        with mock.patch.dict("os.environ", {"TINKER_API_KEY": "sealed-fake-key"}):
            return run_tinker_training(
                settings,
                TinkerTrainingRequest(
                    deal_id="demo-proxy-train",
                    model="meta-llama/Llama-3.2-1B",
                    rank=4,
                    steps=steps,
                    max_usd=max_usd,
                    require_encumbrance=False,
                ),
                service_client_factory=lambda **_kw: FakeTinkerServiceClient(api_key="k"),
            )

    def test_full_training_executes_end_to_end(self):
        r = self._run(steps=3)
        self.assertTrue(r["success"], r)
        self.assertEqual(r["outcome"], "training_completed")
        self.assertEqual(r["furthest_stage"], "cleanup_completed")
        self.assertEqual(r["steps_completed"], 3)
        self.assertTrue(r["checkpoint_saved"])
        self.assertFalse(r["raw_secret_egress"])
        # bounded: model/deal exposed only as hashes
        blob = str(r)
        self.assertNotIn("meta-llama/Llama-3.2-1B", blob)
        self.assertEqual(len(r["model_hash"]), 64)

    def test_single_step(self):
        r = self._run(steps=1)
        self.assertTrue(r["success"])
        self.assertEqual(r["steps_completed"], 1)

    def test_meter_cap_aborts_runaway_spend(self):
        # A cap so tiny that the first step's tokens exceed it: the run must
        # abort mid-loop, not complete all 3 steps.
        r = self._run(steps=3, max_usd=1e-9)
        self.assertFalse(r["success"], r)
        self.assertEqual(r["outcome"], "training_failed")
        self.assertLess(r["steps_completed"], 3)
        self.assertFalse(r["raw_secret_egress"])


if __name__ == "__main__":
    unittest.main()
