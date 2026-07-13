import unittest

from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.canary import CanaryCandidate, CanarySentinel
from tinker_delegate.config import Settings
from tinker_delegate.private_reward import RewardBand
from tinker_delegate.private_reward_envs import SyntheticHiddenKeywordEnvironment
from tinker_delegate.private_reward_envs.denoising_demo import run_denoising_holdout_demo


def _clean_canary_report():
    records = {f"record-{i}": f"private alpha signal {i}".encode("utf-8") for i in range(10)}
    env = SyntheticHiddenKeywordEnvironment(records)
    canaries = [
        CanaryCandidate(label="strong", payload=b"alpha", min_band=RewardBand.MEDIUM, max_band=RewardBand.EXCEPTIONAL),
        CanaryCandidate(label="junk", payload=b"zzz", min_band=RewardBand.NEGLIGIBLE, max_band=RewardBand.LOW),
    ]
    return CanarySentinel(canaries).screen(env).to_public_dict()


class VerifyRewardMechanismEndpointTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        self.client = TestClient(api.app)
        self.packet = run_denoising_holdout_demo()

    def tearDown(self):
        api.settings = self.original_settings

    def _post(self, body):
        return self.client.post(
            "/verify/reward-mechanism",
            json=body,
            headers={"Authorization": "Bearer operator-secret"},
        )

    def test_requires_auth(self):
        resp = self.client.post("/verify/reward-mechanism", json={"packet": self.packet})
        self.assertEqual(resp.status_code, 401)

    def test_packet_only_verifies(self):
        resp = self._post({"packet": self.packet})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["verified"])
        self.assertEqual(body["reason_code"], "mechanism_verified")
        # Code binding is CLI-local; the HTTP surface skips it.
        self.assertTrue(body["checks"]["code_binding"]["skipped"])
        self.assertFalse(body["raw_secret_egress"])

    def test_valid_canary_report_passes(self):
        resp = self._post({"packet": self.packet, "canary_report": _clean_canary_report()})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["verified"])
        self.assertTrue(body["checks"]["canary_calibration"]["canary_calibrated"])

    def test_forged_canary_report_fails(self):
        report = _clean_canary_report()
        report["results"][0]["outcome"] = "inconclusive"  # forged
        resp = self._post({"packet": self.packet, "canary_report": report})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["verified"])
        self.assertEqual(body["reason_code"], "canary_report_inconsistent")

    def test_manifest_param_is_wired_and_fails_closed_without_provenance(self):
        # The denoising demo packet has no sealed_dataset_provenance, so supplying
        # a manifest must fail closed (proves the manifest param is threaded).
        resp = self._post({"packet": self.packet, "manifest": {"dataset_id": "x"}})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["verified"])
        self.assertEqual(body["reason_code"], "missing_dataset_commitment")

    def test_tampered_packet_reports_unverified(self):
        packet = dict(self.packet)
        cert = dict(packet["reproducibility_certificate"])
        cert["code_hash"] = "0x" + "11" * 32
        packet["reproducibility_certificate"] = cert
        resp = self._post({"packet": packet})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["verified"])

    def _sealed_setup(self):
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

        wk = ["11" * 32, "22" * 32]
        addrs = [Account.from_key(k).address for k in wk]
        owner = "33" * 32
        owner_addr = Account.from_key(owner).address
        _priv, pub = generate_recipient_keypair()
        prov = build_provenance(
            source_pipeline="p", upstream_id="u", license="l",
            distribution_claim="rep", benchmark_ref="bench-v1",
        )
        _b, manifest, _r = seal_dataset(
            b'{"x":1}', dataset_id="d1", task="t",
            data_sensitivity=DataSensitivity.PUBLIC_BENCHMARK,
            recipient_public_keys=[pub], provenance=prov,
        )
        manifest, _ = add_witness_signature(manifest, wk[0])
        manifest, _ = add_witness_signature(manifest, wk[1])
        manifest, _ = sign_manifest(manifest, owner)
        packet = dict(self.packet)
        packet["sealed_dataset_provenance"] = {
            "dataset_id": "d1",
            "publish_ciphertext_sha256": manifest["ciphertext_sha256"],
            "manifest_hash": manifest_hash(manifest),
        }
        return packet, manifest, addrs, owner_addr

    def test_witness_quorum_and_benchmark_threaded(self):
        packet, manifest, addrs, owner_addr = self._sealed_setup()
        resp = self._post({
            "packet": packet, "manifest": manifest, "expected_signer": owner_addr,
            "witness_quorum": {"authorized_witnesses": addrs, "threshold": 2},
            "expected_benchmark": "bench-v1", "require_provenance": True,
        })
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["verified"])

    def test_unmet_quorum_over_endpoint_fails(self):
        packet, manifest, addrs, owner_addr = self._sealed_setup()
        resp = self._post({
            "packet": packet, "manifest": manifest, "expected_signer": owner_addr,
            "witness_quorum": {"authorized_witnesses": addrs, "threshold": 3},
        })
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["verified"])
        self.assertEqual(body["reason_code"], "dataset_witness_quorum_unmet")


if __name__ == "__main__":
    unittest.main()
