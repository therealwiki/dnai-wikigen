import json
import unittest

from eth_account import Account

from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.config import Settings
from tests.test_consent_receipt import _grant, _signed_decision, _state_payload


class CoordinationConsentApiTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings

    def tearDown(self):
        api.settings = self.original_settings

    def _payload(self):
        return {
            "state": _state_payload(grants=[_grant("corpus://atlas", "owner-atlas")]),
            "decision": {
                "turn_id": "turn-1",
                "corpus_ref": "corpus://halcyon",
                "owner_ref": "owner-halcyon",
                "decision": "grant",
            },
            "now": 0,
        }

    def test_consent_decision_endpoint_requires_configured_runtime_auth(self):
        api.settings = Settings(runtime_auth_required=False, runtime_auth_token="")
        client = TestClient(api.app)

        response = client.post("/coordination/consent-decision", json=self._payload())

        self.assertEqual(response.status_code, 503)
        self.assertIn("Runtime bearer auth must be configured", response.json()["detail"])

    def test_consent_decision_endpoint_requires_valid_runtime_bearer(self):
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        client = TestClient(api.app)

        missing = client.post("/coordination/consent-decision", json=self._payload())
        wrong = client.post(
            "/coordination/consent-decision",
            json=self._payload(),
            headers={"Authorization": "Bearer wrong"},
        )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 403)

    def test_consent_decision_endpoint_returns_bounded_receipt(self):
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        client = TestClient(api.app)

        response = client.post(
            "/coordination/consent-decision",
            json=self._payload(),
            headers={"Authorization": "Bearer operator-secret"},
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["surface"], "coordination_consent_decision")
        self.assertEqual(body["action"], "settle_bounded_result")
        self.assertEqual(body["turn"]["status_after"], "settled")
        self.assertEqual(body["quorum"]["grant_count_after"], 2)
        rendered = json.dumps(body, sort_keys=True)
        self.assertNotIn("rank-candidates", rendered)
        self.assertNotIn("sft-rerank", rendered)
        self.assertNotIn("owner-halcyon", rendered)
        self.assertNotIn("ok", rendered)
        self.assertFalse(body["raw_secret_egress"])

    def test_consent_decision_endpoint_verifies_required_owner_signature(self):
        account = Account.from_key("0x" + "11" * 32)
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        client = TestClient(api.app)
        payload = self._payload()
        payload["decision"] = _signed_decision(payload["state"], payload["decision"], account)
        payload["require_signature"] = True
        payload["expected_signer"] = account.address

        response = client.post(
            "/coordination/consent-decision",
            json=payload,
            headers={"Authorization": "Bearer operator-secret"},
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["signature_binding"]["verified"])
        self.assertFalse(body["signature_binding"]["signature_returned"])
        self.assertFalse(body["signature_binding"]["signer_address_returned"])
        rendered = json.dumps(body, sort_keys=True)
        self.assertNotIn(account.address, rendered)
        self.assertNotIn(account.address.lower(), rendered)
        self.assertNotIn(payload["decision"]["signature"]["signature"], rendered)
        self.assertNotIn("owner-halcyon", rendered)

    def test_consent_decision_endpoint_required_signature_missing_fails_closed(self):
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        client = TestClient(api.app)
        payload = self._payload()
        payload["require_signature"] = True

        response = client.post(
            "/coordination/consent-decision",
            json=payload,
            headers={"Authorization": "Bearer operator-secret"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("signature is required", response.json()["detail"])

    def test_consent_decision_endpoint_rejects_malformed_state_bounded(self):
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        client = TestClient(api.app)
        payload = self._payload()
        payload["state"]["session"]["raw_private_note"] = "do not leak"

        response = client.post(
            "/coordination/consent-decision",
            json=payload,
            headers={"Authorization": "Bearer operator-secret"},
        )

        self.assertEqual(response.status_code, 400)
        rendered = json.dumps(response.json(), sort_keys=True)
        self.assertIn("unknown session field", rendered)
        self.assertNotIn("do not leak", rendered)


if __name__ == "__main__":
    unittest.main()
