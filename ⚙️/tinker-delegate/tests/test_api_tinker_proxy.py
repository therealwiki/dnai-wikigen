import json
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from eth_account import Account

from tinker_delegate import api
from tinker_delegate.config import Settings
from tinker_delegate.run_metadata_store import stable_hash
from tinker_delegate.tinker_proxy import issue_proxy_token, sign_proxy_identity_registry


SIGNING_KEY_HEX = "22" * 32
STORE_KEY_HEX = "77" * 32


def _write_proxy_issue_policy(path: str, *, subject: str, recipient_public_key_hex: str, scopes: list[str], ttl: int):
    policy = {
        "schema_version": 1,
        "grants": [
            {
                "subject_hash": stable_hash(subject, prefix="proxy_subject"),
                "recipient_public_key_hash": stable_hash(
                    recipient_public_key_hex.lower(),
                    prefix="proxy_recipient_public_key",
                ),
                "scopes": scopes,
                "max_ttl_seconds": ttl,
            }
        ],
    }
    with open(path, "w") as handle:
        json.dump(policy, handle, sort_keys=True)
    return policy


def _proxy_identity_registry(*, subject: str = "buyer-agent-1", reviewer: str = "reviewer-1") -> dict:
    return {
        "schema_version": 1,
        "identities": [
            {
                "identity_hash": stable_hash(subject, prefix="proxy_subject"),
                "role": "agent",
                "status": "active",
                "expires_at": 4_102_444_800,
                "raw_label": subject,
            },
            {
                "identity_hash": stable_hash(reviewer, prefix="proxy_grant_reviewer"),
                "role": "reviewer",
                "status": "active",
                "expires_at": 4_102_444_800,
                "raw_label": reviewer,
            },
        ],
    }


class TinkerProxyApiTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings

    def tearDown(self):
        api.settings = self.original_settings

    def _settings(self, tmpdir: str, **overrides) -> Settings:
        values = {
            "proxy_jwt_key": SIGNING_KEY_HEX,
            "proxy_token_store_path": f"{tmpdir}/proxy_tokens.enc",
            "proxy_token_store_key": STORE_KEY_HEX,
        }
        values.update(overrides)
        return Settings(**values)

    def test_proxy_status_disabled_by_default(self):
        api.settings = Settings(allow_tinker_proxy_endpoint=False)
        client = TestClient(api.app)

        response = client.get("/tinker/proxy/status")

        self.assertEqual(response.status_code, 403)
        self.assertIn("Tinker proxy endpoint is disabled", response.json()["detail"])

    def test_client_config_install_requires_runtime_auth_and_returns_hashes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = self._settings(
                tmpdir,
                runtime_auth_required=True,
                runtime_auth_token="operator-secret",
                client_config_store_path=f"{tmpdir}/client_config.enc",
                client_config_store_key=STORE_KEY_HEX,
            )
            client = TestClient(api.app)

            missing = client.put(
                "/tinker/proxy/client-config",
                json={
                    "project_id": "proj-sensitive",
                    "base_url": "https://api.thinkingmachines.ai/services/tinker-prod",
                },
            )
            response = client.put(
                "/tinker/proxy/client-config",
                headers={"Authorization": "Bearer operator-secret"},
                json={
                    "project_id": "proj-sensitive",
                    "base_url": "https://api.thinkingmachines.ai/services/tinker-prod",
                },
            )
            status = client.get(
                "/tinker/proxy/client-config",
                headers={"Authorization": "Bearer operator-secret"},
            )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(status.status_code, 200)
        body = response.json()
        rendered = json.dumps({"install": body, "status": status.json()}, sort_keys=True)
        self.assertEqual(body["surface"], "tinker_client_config_install")
        self.assertTrue(body["client_config"]["project_id_configured"])
        self.assertEqual(body["client_config"]["base_url_host_family"], "thinkingmachines")
        self.assertTrue(status.json()["store"]["exists"])
        self.assertNotIn("proj-sensitive", rendered)
        self.assertNotIn("api.thinkingmachines.ai", rendered)
        self.assertFalse(body["raw_secret_egress"])

    def test_proxy_status_uses_installed_client_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = self._settings(
                tmpdir,
                allow_tinker_proxy_endpoint=True,
                runtime_auth_required=True,
                runtime_auth_token="operator-secret",
                client_config_store_path=f"{tmpdir}/client_config.enc",
                client_config_store_key=STORE_KEY_HEX,
            )
            client = TestClient(api.app)
            client.put(
                "/tinker/proxy/client-config",
                headers={"Authorization": "Bearer operator-secret"},
                json={
                    "project_id": "proj-sensitive",
                    "base_url": "https://api.thinkingmachines.ai/services/tinker-prod",
                },
            )
            with patch.dict(os.environ, {"TINKER_API_KEY": "tml-secretsecretsecretsecretsecret"}, clear=False):
                response = client.get(
                    "/tinker/proxy/status",
                    headers={"Authorization": "Bearer operator-secret"},
                )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        rendered = json.dumps(body, sort_keys=True)
        self.assertTrue(body["sealed_client_config"]["project_id_configured"])
        self.assertEqual(body["sealed_client_config"]["base_url_host_family"], "thinkingmachines")
        self.assertNotIn("proj-sensitive", rendered)
        self.assertNotIn("api.thinkingmachines.ai", rendered)

    def test_proxy_token_issuance_disabled_by_default(self):
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        client = TestClient(api.app)
        recipient_public_key = X25519PrivateKey.generate().public_key().public_bytes_raw().hex()

        response = client.post(
            "/tinker/proxy/token",
            headers={"Authorization": "Bearer operator-secret"},
            json={
                "subject": "buyer-agent-1",
                "scopes": ["proxy:status"],
                "recipient_public_key": recipient_public_key,
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn("Tinker proxy token issuance is disabled", response.json()["detail"])

    def test_proxy_token_issuance_requires_configured_runtime_auth(self):
        api.settings = Settings(allow_tinker_proxy_token_issuance=True, proxy_jwt_key=SIGNING_KEY_HEX)
        client = TestClient(api.app)
        recipient_public_key = X25519PrivateKey.generate().public_key().public_bytes_raw().hex()

        response = client.post(
            "/tinker/proxy/token",
            json={
                "subject": "buyer-agent-1",
                "scopes": ["proxy:status"],
                "recipient_public_key": recipient_public_key,
            },
        )

        self.assertEqual(response.status_code, 503)
        self.assertIn("Runtime bearer auth must be configured", response.json()["detail"])

    def test_proxy_token_issuance_returns_encrypted_bounded_envelope(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = self._settings(
                tmpdir,
                allow_tinker_proxy_token_issuance=True,
                runtime_auth_required=True,
                runtime_auth_token="operator-secret",
                proxy_approved_subjects="buyer-agent-1",
            )
            client = TestClient(api.app)
            recipient_public_key = X25519PrivateKey.generate().public_key().public_bytes_raw().hex()

            response = client.post(
                "/tinker/proxy/token",
                headers={"Authorization": "Bearer operator-secret"},
                json={
                    "subject": "buyer-agent-1",
                    "scopes": ["proxy:status"],
                    "recipient_public_key": recipient_public_key,
                    "ttl_seconds": 30,
                },
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        rendered = repr(body)
        self.assertTrue(body["success"])
        self.assertEqual(body["delivery"], "x25519_aes_256_gcm_envelope")
        self.assertIn("encrypted_token", body)
        self.assertIn("associated_data", body)
        self.assertEqual(body["audit_record"]["event"], "issued")
        self.assertFalse(body["plaintext_token_returned"])
        self.assertFalse(body["raw_secret_egress"])
        self.assertNotIn("operator-secret", rendered)
        self.assertNotIn("buyer-agent-1", rendered)

    def test_proxy_issue_policy_endpoint_installs_and_returns_bounded_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recipient_public_key = X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            input_path = os.path.join(tmpdir, "input-policy.json")
            policy = _write_proxy_issue_policy(
                input_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=recipient_public_key,
                scopes=["proxy:status"],
                ttl=60,
            )
            api.settings = self._settings(
                tmpdir,
                runtime_auth_required=True,
                runtime_auth_token="operator-secret",
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
            )
            client = TestClient(api.app)

            installed = client.put(
                "/tinker/proxy/issue-policy",
                headers={"Authorization": "Bearer operator-secret"},
                json={"policy": policy},
            )
            status = client.get(
                "/tinker/proxy/issue-policy",
                headers={"Authorization": "Bearer operator-secret"},
            )

        self.assertEqual(installed.status_code, 200)
        self.assertEqual(status.status_code, 200)
        body = status.json()
        rendered = repr([installed.json(), body])
        self.assertTrue(body["success"])
        self.assertTrue(body["required"])
        self.assertTrue(body["policy_present"])
        self.assertEqual(body["grant_count"], 1)
        self.assertFalse(body["raw_secret_egress"])
        self.assertNotIn("operator-secret", rendered)
        self.assertNotIn("buyer-agent-1", rendered)
        self.assertNotIn(recipient_public_key, rendered)

    def test_proxy_identity_registry_endpoint_installs_signed_registry_bounded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            registry_path = os.path.join(tmpdir, "proxy-identity-registry.json")
            signer = Account.create("proxy identity registry api signer")
            signed_registry, sign_receipt = sign_proxy_identity_registry(
                _proxy_identity_registry(),
                signer.key.hex(),
            )
            api.settings = self._settings(
                tmpdir,
                runtime_auth_required=True,
                runtime_auth_token="operator-secret",
                proxy_require_identity_registry=True,
                proxy_identity_registry_path=registry_path,
                proxy_require_identity_registry_signature=True,
                proxy_identity_registry_signer=signer.address,
            )
            client = TestClient(api.app)

            installed = client.put(
                "/tinker/proxy/identity-registry",
                headers={"Authorization": "Bearer operator-secret"},
                json={"registry": signed_registry},
            )
            status = client.get(
                "/tinker/proxy/identity-registry",
                headers={"Authorization": "Bearer operator-secret"},
            )
            with open(registry_path, encoding="utf-8") as handle:
                stored = json.loads(handle.read())

        self.assertEqual(installed.status_code, 200)
        self.assertEqual(status.status_code, 200)
        body = status.json()
        rendered = repr([installed.json(), body])
        self.assertTrue(body["success"])
        self.assertTrue(body["required"])
        self.assertTrue(body["registry_present"])
        self.assertEqual(body["registry_hash"], sign_receipt["registry_hash"])
        self.assertTrue(body["signature_binding"]["verified"])
        self.assertEqual(body["role_counts"], {"agent": 1, "reviewer": 1})
        self.assertFalse(body["raw_secret_egress"])
        self.assertNotIn("operator-secret", rendered)
        self.assertNotIn("buyer-agent-1", rendered)
        self.assertNotIn("reviewer-1", rendered)
        self.assertNotIn(signer.address, rendered)
        self.assertNotIn(signed_registry["signature"]["signature"], rendered)
        self.assertNotIn("raw_label", repr(stored))

    def test_proxy_token_issuance_can_require_hash_only_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recipient_public_key = X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=recipient_public_key,
                scopes=["proxy:status", "billing:payment-method-status"],
                ttl=60,
            )
            api.settings = self._settings(
                tmpdir,
                allow_tinker_proxy_token_issuance=True,
                runtime_auth_required=True,
                runtime_auth_token="operator-secret",
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
            )
            client = TestClient(api.app)

            response = client.post(
                "/tinker/proxy/token",
                headers={"Authorization": "Bearer operator-secret"},
                json={
                    "subject": "buyer-agent-1",
                    "scopes": ["billing:payment-method-status"],
                    "recipient_public_key": recipient_public_key,
                    "ttl_seconds": 60,
                },
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        rendered = repr(body)
        self.assertTrue(body["policy_binding"]["required"])
        self.assertEqual(body["policy_binding"]["requested_scopes"], ["billing:payment-method-status"])
        self.assertFalse(body["policy_binding"]["raw_secret_egress"])
        self.assertNotIn("buyer-agent-1", rendered)
        self.assertNotIn(recipient_public_key, rendered)

    def test_proxy_status_accepts_scoped_proxy_jwt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = self._settings(tmpdir, allow_tinker_proxy_endpoint=True)
            claims, token = issue_proxy_token(
                api.settings,
                subject="buyer-agent-1",
                scopes=["proxy:status"],
                ttl_seconds=60,
            )
            client = TestClient(api.app)

            response = client.get(
                "/tinker/proxy/status",
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["surface"], "tinker_proxy")
        self.assertEqual(body["proxy_auth_context"]["auth_kind"], "proxy")
        self.assertEqual(body["proxy_auth_context"]["required_scope"], "proxy:status")
        self.assertEqual(body["proxy_auth_context"]["jwt_id_hash"], claims.to_public_dict()["jwt_id_hash"])
        self.assertFalse(body["raw_secret_egress"])

    def test_proxy_token_audit_and_revoke_are_operator_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = self._settings(
                tmpdir,
                allow_tinker_proxy_token_issuance=True,
                runtime_auth_required=True,
                runtime_auth_token="operator-secret",
            )
            client = TestClient(api.app)
            recipient_public_key = X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
            issued = client.post(
                "/tinker/proxy/token",
                headers={"Authorization": "Bearer operator-secret"},
                json={
                    "subject": "buyer-agent-1",
                    "scopes": ["proxy:status"],
                    "recipient_public_key": recipient_public_key,
                    "ttl_seconds": 30,
                },
            ).json()
            jwt_id_hash = issued["token"]["jwt_id_hash"]

            missing = client.get("/tinker/proxy/tokens")
            audit = client.get(
                "/tinker/proxy/tokens",
                headers={"Authorization": "Bearer operator-secret"},
            )
            revoked = client.post(
                "/tinker/proxy/token/revoke",
                headers={"Authorization": "Bearer operator-secret"},
                json={"jwt_id_hash": jwt_id_hash, "reason": "operator_requested"},
            )
            unknown_revoke = client.post(
                "/tinker/proxy/token/revoke",
                headers={"Authorization": "Bearer operator-secret"},
                json={"jwt_id_hash": "ab" * 32, "reason": "operator_requested"},
            )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(audit.status_code, 200)
        self.assertEqual(audit.json()["issued_count"], 1)
        self.assertEqual(revoked.status_code, 200)
        self.assertEqual(revoked.json()["record"]["event"], "revoked")
        self.assertFalse(revoked.json()["raw_secret_egress"])
        self.assertEqual(unknown_revoke.status_code, 400)
        self.assertIn("revoke target was not issued", unknown_revoke.json()["detail"])


if __name__ == "__main__":
    unittest.main()
