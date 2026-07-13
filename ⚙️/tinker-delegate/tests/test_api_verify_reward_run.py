import unittest

from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.config import Settings
from tinker_delegate.private_reward_envs.bio_assay_program_demo import (
    run_bio_assay_program_reward_demo,
)


class VerifyRewardRunEndpointTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        self.client = TestClient(api.app)
        self.packet = run_bio_assay_program_reward_demo()

    def tearDown(self):
        api.settings = self.original_settings

    def _post(self, packet):
        return self.client.post(
            "/verify/reward-run",
            json={"packet": packet},
            headers={"Authorization": "Bearer operator-secret"},
        )

    def test_requires_auth(self):
        resp = self.client.post("/verify/reward-run", json={"packet": self.packet})
        self.assertEqual(resp.status_code, 401)

    def test_real_packet_verifies(self):
        resp = self._post(self.packet)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["verified"])
        self.assertEqual(body["reason_code"], "run_verified")
        self.assertFalse(body["raw_secret_egress"])

    def test_tampered_packet_reports_unverified(self):
        packet = dict(self.packet)
        cert = dict(packet["reproducibility_certificate"])
        cert["code_hash"] = "0x" + "11" * 32
        packet["reproducibility_certificate"] = cert
        resp = self._post(packet)
        self.assertEqual(resp.status_code, 200)  # verdict is data, not an HTTP error
        body = resp.json()
        self.assertFalse(body["verified"])
        self.assertEqual(body["reason_code"], "certificate_hash_mismatch")

    def test_empty_packet_fails_closed(self):
        resp = self._post({})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["verified"])


if __name__ == "__main__":
    unittest.main()
