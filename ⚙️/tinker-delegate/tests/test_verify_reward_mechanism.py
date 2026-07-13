"""Point (3) canary calibration + the aggregate `verify_reward_mechanism`.

Completes the third-party "audit the mechanism, not the data" story: a reader can
verify, from bounded bytes plus the inputs they independently hold (env source,
sealed manifest, canary report), that the run is cryptographically sound, consumed
the committed code and dataset, respected its declared policy, and that the oracle
is calibrated — all without any sealed data.
"""
import copy
import unittest

from tinker_delegate.canary import CanaryCandidate, CanarySentinel
from tinker_delegate.private_reward import RewardBand, assert_bounded_egress
from tinker_delegate.private_reward_envs import SyntheticHiddenKeywordEnvironment
from tinker_delegate.private_reward_envs.denoising_demo import run_denoising_holdout_demo
from tinker_delegate.private_reward_envs import denoising as _denoising_mod
from tinker_delegate.run_verification import (
    verify_canary_calibration,
    verify_reward_mechanism,
)


def _clean_canary_report():
    records = {f"record-{i}": f"private alpha signal {i}".encode("utf-8") for i in range(10)}
    env = SyntheticHiddenKeywordEnvironment(records)
    canaries = [
        CanaryCandidate(label="strong", payload=b"alpha", min_band=RewardBand.MEDIUM, max_band=RewardBand.EXCEPTIONAL),
        CanaryCandidate(label="junk", payload=b"zzz", min_band=RewardBand.NEGLIGIBLE, max_band=RewardBand.LOW),
    ]
    return CanarySentinel(canaries).screen(env).to_public_dict()


class CanaryCalibrationTest(unittest.TestCase):
    def test_clean_report_is_calibrated_and_bounded(self):
        verdict = verify_canary_calibration(_clean_canary_report())
        self.assertTrue(verdict["canary_calibrated"])
        self.assertEqual(verdict["reason_code"], "canary_calibration_verified")
        self.assertEqual(verdict["explanation"]["disposition"], "allowed")
        assert_bounded_egress(verdict)

    def test_forged_outcome_is_inconsistent(self):
        # Claiming "inconclusive" while the observed band is not WITHHELD is a lie
        # (INCONCLUSIVE only arises from a withheld band), so it is caught.
        report = _clean_canary_report()
        report["results"][0]["outcome"] = "inconclusive"
        verdict = verify_canary_calibration(report)
        self.assertFalse(verdict["canary_calibrated"])
        self.assertEqual(verdict["reason_code"], "canary_report_inconsistent")

    def test_tampered_aggregate_flag_is_inconsistent(self):
        report = _clean_canary_report()
        report["clear"] = False  # contradicts the (zero) recomputed trip count
        verdict = verify_canary_calibration(report)
        self.assertEqual(verdict["reason_code"], "canary_report_inconsistent")

    def test_empty_report_fails_closed(self):
        self.assertEqual(verify_canary_calibration({"results": []})["reason_code"], "no_canaries")
        self.assertEqual(verify_canary_calibration({})["reason_code"], "no_canaries")

    def test_genuinely_tripped_report_is_not_calibrated(self):
        # A junk canary scoring above its ceiling (consistently recorded) means the
        # oracle is gamed/leaking — calibration must fail even though the report is
        # internally consistent.
        report = _clean_canary_report()
        junk = report["results"][1]
        junk["observed_band"] = "exceptional"
        junk["outcome"] = "tripped_high"
        report["tripped_count"] = 1
        report["clear"] = False
        verdict = verify_canary_calibration(report)
        self.assertFalse(verdict["canary_calibrated"])
        self.assertEqual(verdict["reason_code"], "canary_tripped")


class VerifyRewardMechanismTest(unittest.TestCase):
    def setUp(self):
        self.packet = run_denoising_holdout_demo()

    def test_all_requested_checks_pass(self):
        verdict = verify_reward_mechanism(
            self.packet,
            source_targets=_denoising_mod,
            canary_report=_clean_canary_report(),
        )
        self.assertTrue(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "mechanism_verified")
        self.assertTrue(verdict["checks"]["code_binding"]["code_binding_verified"])
        self.assertTrue(verdict["checks"]["canary_calibration"]["canary_calibrated"])
        self.assertTrue(verdict["checks"]["dataset_binding"]["skipped"])

    def test_only_packet_matches_run_verdict(self):
        verdict = verify_reward_mechanism(self.packet)
        self.assertTrue(verdict["verified"])
        for key in ("code_binding", "dataset_binding", "canary_calibration"):
            self.assertTrue(verdict["checks"][key]["skipped"])

    def test_wrong_source_fails_and_surfaces_reason(self):
        from tinker_delegate.private_reward_envs import synthetic as synthetic_mod

        verdict = verify_reward_mechanism(self.packet, source_targets=synthetic_mod)
        self.assertFalse(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "code_hash_mismatch")

    def test_bad_canary_fails_the_aggregate(self):
        report = _clean_canary_report()
        report["results"][0]["outcome"] = "inconclusive"  # forged
        verdict = verify_reward_mechanism(self.packet, canary_report=report)
        self.assertFalse(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "canary_report_inconsistent")

    def test_run_failure_surfaces_run_reason(self):
        packet = copy.deepcopy(self.packet)
        packet["reproducibility_certificate"]["code_hash"] = "0x" + "11" * 32
        verdict = verify_reward_mechanism(packet, source_targets=_denoising_mod)
        self.assertFalse(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "certificate_hash_mismatch")


class MechanismWitnessAndProvenanceTest(unittest.TestCase):
    """The aggregate threads the witness quorum + provenance checks."""

    def setUp(self):
        from eth_account import Account

        from tinker_delegate.sealed_dataset import (
            DataSensitivity,
            add_witness_signature,
            build_provenance,
            generate_recipient_keypair,
            manifest_hash,
            seal_dataset,
            sign_manifest,
        )

        self.wk = ["11" * 32, "22" * 32]
        self.addrs = [Account.from_key(k).address for k in self.wk]
        owner = "33" * 32
        self.owner_addr = Account.from_key(owner).address

        _priv, pub = generate_recipient_keypair()
        prov = build_provenance(
            source_pipeline="p", upstream_id="u", license="l",
            distribution_claim="rep", benchmark_ref="bench-v1",
        )
        _blob, manifest, _r = seal_dataset(
            b'{"x":1}', dataset_id="d1", task="t",
            data_sensitivity=DataSensitivity.PUBLIC_BENCHMARK,
            recipient_public_keys=[pub], provenance=prov,
        )
        manifest, _ = add_witness_signature(manifest, self.wk[0])
        manifest, _ = add_witness_signature(manifest, self.wk[1])
        manifest, _ = sign_manifest(manifest, owner)
        self.manifest = manifest

        # A packet that passes verify_reward_run, with a provenance block pointing
        # at our manifest (the run check does not inspect sealed_dataset_provenance).
        self.packet = run_denoising_holdout_demo()
        self.packet["sealed_dataset_provenance"] = {
            "dataset_id": "d1",
            "publish_ciphertext_sha256": manifest["ciphertext_sha256"],
            "manifest_hash": manifest_hash(manifest),
        }

    def test_full_audit_with_witness_and_provenance_passes(self):
        verdict = verify_reward_mechanism(
            self.packet, manifest=self.manifest, expected_signer=self.owner_addr,
            witness_quorum={"authorized_witnesses": self.addrs, "threshold": 2},
            expected_benchmark="bench-v1", require_provenance=True,
        )
        self.assertTrue(verdict["verified"])
        self.assertTrue(verdict["checks"]["dataset_binding"]["witness_quorum_met"])
        self.assertTrue(verdict["checks"]["provenance"]["ok"])

    def test_unmet_quorum_fails_the_aggregate(self):
        verdict = verify_reward_mechanism(
            self.packet, manifest=self.manifest, expected_signer=self.owner_addr,
            witness_quorum={"authorized_witnesses": self.addrs, "threshold": 3},
        )
        self.assertFalse(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "dataset_witness_quorum_unmet")

    def test_benchmark_mismatch_fails_the_aggregate(self):
        verdict = verify_reward_mechanism(
            self.packet, manifest=self.manifest, expected_signer=self.owner_addr,
            expected_benchmark="other-benchmark",
        )
        self.assertFalse(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "dataset_benchmark_mismatch")

    def test_provenance_skipped_when_not_requested(self):
        verdict = verify_reward_mechanism(
            self.packet, manifest=self.manifest, expected_signer=self.owner_addr,
        )
        self.assertTrue(verdict["verified"])
        self.assertTrue(verdict["checks"]["provenance"]["skipped"])


if __name__ == "__main__":
    unittest.main()
