import unittest

from tinker_delegate.optimizer_export_guard import (
    ExportLeakageError,
    audit_optimizer_export,
    certify_optimizer_export,
)
from tinker_delegate.private_reward import RewardBand
from tinker_delegate.private_reward_envs.bio_assay import (
    BioAssayCandidateSource,
    BioAssayRewardEnvironment,
)
from tinker_delegate.private_reward_loop import (
    HillClimbOptimizer,
    run_private_reward_loop,
)


class OptimizerExportGuardTest(unittest.TestCase):
    def test_bounded_loop_outcome_passes(self):
        env = BioAssayRewardEnvironment(max_queries=16)
        optimizer = HillClimbOptimizer(BioAssayCandidateSource(), budget=16)
        outcome = run_private_reward_loop(env, optimizer, max_rounds=16, target_band=RewardBand.HIGH)
        result = audit_optimizer_export(outcome.to_public_dict())
        self.assertTrue(result.allowed, result.reason_code)
        self.assertEqual(result.reason_code, "ok")

    def test_float_reward_value_rejected(self):
        payload = {"best_band": "high", "exact_reward": 0.9731}
        result = audit_optimizer_export(payload)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, "float_value")
        self.assertIn("exact_reward", result.offending_field_paths)

    def test_nested_float_rejected(self):
        payload = {"rounds": [{"band": "low", "reward": 0.1}]}
        result = audit_optimizer_export(payload)
        self.assertEqual(result.reason_code, "float_value")
        self.assertIn("rounds[0].reward", result.offending_field_paths)

    def test_numeric_array_gradient_rejected(self):
        payload = {"gradient": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]}
        result = audit_optimizer_export(payload)
        self.assertEqual(result.reason_code, "numeric_array")
        self.assertIn("gradient", result.offending_field_paths)

    def test_short_int_list_allowed(self):
        payload = {"histogram_counts": [1, 2, 3]}
        result = audit_optimizer_export(payload)
        self.assertTrue(result.allowed)

    def test_oversized_hex_blob_rejected(self):
        payload = {"weights": "0x" + "ab" * 400}
        result = audit_optimizer_export(payload)
        self.assertEqual(result.reason_code, "oversized_blob")

    def test_oversized_scalar_int_rejected(self):
        # A single unbounded int encoding a sealed blob (int.from_bytes) must fail
        # closed even though it is one scalar, not an over-length numeric array.
        smuggled = int.from_bytes(b"leak" * 100, "big")  # ~3200 bits
        payload = {"opaque_counter": smuggled}
        result = audit_optimizer_export(payload)
        self.assertEqual(result.reason_code, "oversized_int")
        self.assertFalse(result.allowed)
        self.assertEqual(result.offending_field_paths, ("opaque_counter",))

    def test_uint256_sized_int_allowed(self):
        # The largest legitimate on-chain integer (exactly 256 bits) is admitted.
        payload = {"amount_wei": 2**256 - 1, "chain_id": 8453, "expiry": 1783843561}
        result = audit_optimizer_export(payload)
        self.assertTrue(result.allowed)

    def test_int_just_over_256_bits_rejected(self):
        payload = {"n": 2**256}  # 257 bits
        result = audit_optimizer_export(payload)
        self.assertEqual(result.reason_code, "oversized_int")

    def test_big_int_smuggled_as_dict_key_rejected(self):
        # The KEY walk must also catch a giant int used as a dict key.
        payload = {int.from_bytes(b"key" * 100, "big"): "value"}
        result = audit_optimizer_export(payload)
        self.assertEqual(result.reason_code, "oversized_int")

    def test_aggregate_int_payload_rejected(self):
        # Many separately-in-bounds ints (each < 256 bits, arrays each <= cap) can
        # still sum to a bulk payload; the aggregate byte budget must catch it.
        # 40 fields * 32-byte ints = 1280 bytes > 512.
        payload = {f"f{i}": 2**255 for i in range(40)}
        result = audit_optimizer_export(payload)
        self.assertEqual(result.reason_code, "aggregate_int_payload")
        self.assertFalse(result.allowed)

    def test_aggregate_int_payload_spread_across_small_arrays_rejected(self):
        # Spread across many under-cap arrays (each <= 8 numeric children) so the
        # per-array check never fires, but the total still exceeds the budget.
        payload = {f"a{i}": [2**255] * 4 for i in range(40)}  # 160 * 32 = 5120 bytes
        result = audit_optimizer_export(payload)
        self.assertEqual(result.reason_code, "aggregate_int_payload")

    def test_realistic_int_heavy_export_allowed(self):
        # A realistic bounded export with many small counts/bands (moderate ints,
        # no long-digit runs that trip the orthogonal secret_shaped check) stays
        # well under the 512-byte aggregate budget.
        payload = {
            "chain_id": 8453, "deal_id": 42, "nonce": 99, "round": 7,
            "counts": [1, 2, 3, 4, 5, 6, 7, 8], "bands": [0, 1, 2, 3, 4],
            "hash": "0x" + "cd" * 32,
        }
        result = audit_optimizer_export(payload)
        self.assertTrue(result.allowed)

    def test_bytes32_hash_allowed(self):
        payload = {"candidate_hash": "0x" + "cd" * 32, "band": "medium", "count": 3}
        result = audit_optimizer_export(payload)
        self.assertTrue(result.allowed)

    def test_raw_secret_egress_flag_rejected(self):
        payload = {"band": "high", "raw_secret_egress": True}
        result = audit_optimizer_export(payload)
        self.assertEqual(result.reason_code, "reward_egress_flag")

    def test_disallowed_type_rejected(self):
        payload = {"band": "high", "obj": {1, 2, 3}}
        result = audit_optimizer_export(payload)
        self.assertEqual(result.reason_code, "disallowed_type")

    def test_certify_raises_on_leaky_and_returns_on_safe(self):
        with self.assertRaises(ExportLeakageError):
            certify_optimizer_export({"reward": 0.5})
        ok = certify_optimizer_export({"band": "high", "count": 2})
        self.assertTrue(ok.allowed)

    def test_leakage_hash_deterministic(self):
        payload = {"band": "high", "count": 2}
        self.assertEqual(
            audit_optimizer_export(payload).leakage_hash,
            audit_optimizer_export(payload).leakage_hash,
        )

    def test_result_never_declares_egress(self):
        result = audit_optimizer_export({"reward": 0.5})
        self.assertFalse(result.to_public_dict()["raw_secret_egress"])

    def test_deeply_nested_structure_fails_closed_not_recursion_error(self):
        # A hostile reducer sending a very deep structure must be rejected with a
        # clean verdict, never an uncontrolled RecursionError.
        node = {"x": "ok"}
        for _ in range(5000):
            node = {"n": node}
        result = audit_optimizer_export(node)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, "structure_too_deep")
        # A normally-shallow bounded output is unaffected.
        self.assertTrue(audit_optimizer_export({"a": {"b": {"c": "d"}}, "count": 1}).allowed)


if __name__ == "__main__":
    unittest.main()
