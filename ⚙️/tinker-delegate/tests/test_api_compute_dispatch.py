import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.compute_runtime import (
    canonical_compute_job_id,
    canonical_compute_project_id,
)
from tinker_delegate.config import Settings


PRIVATE_KEY = "0x" + "71" * 32
WALLET_KEY = "dispatch-wallet-test-key-" + "w" * 48
CREDENTIAL_KEY = "dispatch-credential-test-key-" + "c" * 48
STORE_KEY = "dispatch-legacy-store-test-key-" + "s" * 48
DISPATCH_KEY = "dispatch-exact-asset-journal-key-" + "j" * 48


class ComputeDispatchApiTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {"DSTACK_ENABLED": "false", "TINKER_DSTACK_ENABLED": "false"},
        )
        self.env.start()
        self.original_settings = api.settings
        api.settings = Settings(
            compute_wallet_auth_signing_key=WALLET_KEY,
            compute_credential_signing_key=CREDENTIAL_KEY,
            compute_store_integrity_key=STORE_KEY,
            compute_store_path=str(Path(self.temporary.name) / "legacy.json"),
            compute_dispatch_store_integrity_key=DISPATCH_KEY,
            compute_dispatch_store_path=str(
                Path(self.temporary.name) / "exact-asset-dispatch.json"
            ),
        )
        api._compute_wallet_challenges.clear()
        api._compute_store_instance = None
        api._compute_store_instance_identity = None
        api._compute_dispatch_journal_instance = None
        api._compute_dispatch_journal_instance_identity = None
        self.client = TestClient(api.app)
        self.account = Account.from_key(PRIVATE_KEY)

    def tearDown(self):
        api._compute_wallet_challenges.clear()
        api._compute_store_instance = None
        api._compute_store_instance_identity = None
        api._compute_dispatch_journal_instance = None
        api._compute_dispatch_journal_instance_identity = None
        api.settings = self.original_settings
        self.env.stop()
        self.temporary.cleanup()

    def _headers(self):
        challenge = self.client.post(
            "/auth/compute/challenge", json={"address": self.account.address}
        )
        self.assertEqual(challenge.status_code, 200, challenge.text)
        payload = challenge.json()
        signature = self.account.sign_message(
            encode_defunct(text=payload["message"])
        ).signature.hex()
        token = self.client.post(
            "/auth/compute/token",
            json={"nonce": payload["nonce"], "signature": signature},
        )
        self.assertEqual(token.status_code, 200, token.text)
        return {"Authorization": f"Bearer {token.json()['access_token']}"}

    def _project(self, headers):
        created = self.client.post(
            "/compute/projects",
            json={"name": "exact-asset-lab"},
            headers={**headers, "Idempotency-Key": "project-dispatch-0001"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        return created.json()["project"]["project_id"]

    def _payload(self):
        return {
            "job_reference": "wallet-job-0001",
            "workload_id": "wrk_" + "ab" * 16,
            "asset": "0x" + "00" * 20,
            "authorization_nonce": 0,
            "max_asset_debit": 10**15,
            "authorization_expiry": int(time.time()) + 600,
            "rate_policy_commitment": "0x" + "31" * 32,
            "compose_hash": "0x" + "32" * 32,
            "operation": "inference",
            "model": "qwen3_8b",
            "recipe": "qwen3_8b_bounded",
            "result_policy": "bounded_summary_receipt",
            "max_prefill_tokens": 1_000,
            "max_sample_tokens": 100,
            "max_train_tokens": 0,
        }

    def _enable_dispatch_for_test(self):
        capability = {
            "metadata_intent_creation": True,
            "provider_dispatch": True,
            "independent_metering": True,
            "settlement": True,
            "exact_asset_only": True,
            "mutation_route": "/compute/projects/{project_id}/dispatch-intents",
            "status_route_template": (
                "/compute/projects/{project_id}/dispatch-intents/{job_reference}"
            ),
            "reason": "unit_test_release_bound_dispatch_available",
        }
        patcher = patch.object(
            api,
            "_compute_dispatch_capability",
            return_value=capability,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        manifest = SimpleNamespace(
            schema="dnai.compute.workload.inference.v1",
            operation="inference",
            model="qwen3_8b",
            recipe="qwen3_8b_bounded",
            max_prefill_tokens=1_000,
            max_sample_tokens=100,
            max_train_tokens=0,
        )
        activation = SimpleNamespace(commitment="sha256:" + "41" * 32)
        binding = SimpleNamespace(
            recipient_key_id="sha256:" + "42" * 32,
            activation_commitment=activation.commitment,
            manifest=manifest,
            manifest_commitment="sha256:" + "43" * 32,
            workload_commitment="sha256:" + "44" * 32,
        )
        stored = SimpleNamespace(
            workload_id="wrk_" + "ab" * 16,
            binding=binding,
        )
        ingress = SimpleNamespace(
            recipient=SimpleNamespace(key_id=binding.recipient_key_id),
            current_activation=lambda: activation,
            store=SimpleNamespace(get_for_project=lambda *_args, **_kwargs: stored),
        )
        ingress_patcher = patch.object(
            api,
            "_get_compute_workload_ingress",
            return_value=ingress,
        )
        ingress_patcher.start()
        self.addCleanup(ingress_patcher.stop)

    def test_metadata_intent_uses_canonical_ids_without_legacy_charge(self):
        self._enable_dispatch_for_test()
        headers = self._headers()
        project = self._project(headers)
        projected = self.client.get(
            f"/compute/projects/{project}", headers=headers
        )
        self.assertEqual(projected.status_code, 200, projected.text)
        self.assertTrue(projected.json()["provider_dispatch_enabled"])
        self.assertTrue(
            self.client.get("/compute/funding-capabilities")
            .json()["dispatch_intents"]["metadata_intent_creation"]
        )
        balance_before = self.client.get(
            f"/compute/projects/{project}/balance", headers=headers
        ).json()
        ledger_before = self.client.get(
            f"/compute/projects/{project}/ledger", headers=headers
        ).json()
        request_headers = {
            **headers,
            "Idempotency-Key": "exact-dispatch-create-0001",
        }
        created = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers=request_headers,
        )
        self.assertEqual(created.status_code, 200, created.text)
        body = created.json()
        self.assertTrue(body["created"])
        self.assertFalse(body["legacy_credit_ledger_mutated"])
        self.assertFalse(body["provider_authoritative"])
        intent = body["intent"]
        self.assertEqual(intent["project_id"], canonical_compute_project_id(project))
        self.assertEqual(
            intent["job_id"], canonical_compute_job_id("wallet-job-0001")
        )
        self.assertFalse(intent["raw_prompt_accepted"])
        self.assertFalse(intent["raw_examples_accepted"])
        self.assertEqual(intent["workload_id"], "wrk_" + "ab" * 16)
        self.assertEqual(intent["manifest_commitment"], "0x" + "43" * 32)
        self.assertEqual(intent["workload_commitment"], "0x" + "44" * 32)

        replay = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers=request_headers,
        )
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertFalse(replay.json()["created"])
        self.assertTrue(replay.json()["idempotent_replay"])

        fetched = self.client.get(
            f"/compute/projects/{project}/dispatch-intents/wallet-job-0001",
            headers=headers,
        )
        self.assertEqual(fetched.status_code, 200, fetched.text)
        self.assertEqual(fetched.json()["job_id"], intent["job_id"])

        balance_after = self.client.get(
            f"/compute/projects/{project}/balance", headers=headers
        ).json()
        ledger_after = self.client.get(
            f"/compute/projects/{project}/ledger", headers=headers
        ).json()
        self.assertEqual(balance_after, balance_before)
        self.assertEqual(ledger_after, ledger_before)

    def test_prompt_and_examples_are_rejected_without_reflecting_values(self):
        headers = self._headers()
        project = self._project(headers)
        for forbidden_field, secret in (
            ("prompt", "SECRET PRIVATE PROMPT VALUE"),
            ("examples", "SECRET PRIVATE EXAMPLES VALUE"),
        ):
            payload = self._payload()
            payload[forbidden_field] = secret
            response = self.client.post(
                f"/compute/projects/{project}/dispatch-intents",
                json=payload,
                headers={
                    **headers,
                    "Idempotency-Key": f"forbidden-{forbidden_field}-0001",
                },
            )
            self.assertEqual(response.status_code, 422, response.text)
            self.assertNotIn(secret, response.text)

    def test_browser_decimal_uint256_strings_are_canonicalized_without_precision_loss(self):
        self._enable_dispatch_for_test()
        headers = self._headers()
        project = self._project(headers)
        payload = self._payload()
        payload.update(
            {
                "job_reference": "wallet-job-large-uint",
                "authorization_nonce": "9007199254740993",
                "max_asset_debit": "1000000000000000000",
            }
        )
        response = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=payload,
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-large-uint-0001",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        intent = response.json()["intent"]
        self.assertEqual(intent["authorization_nonce"], 9_007_199_254_740_993)
        self.assertEqual(intent["max_asset_debit"], 1_000_000_000_000_000_000)

    def test_disabled_release_gate_returns_503_without_journal_mutation(self):
        headers = self._headers()
        project = self._project(headers)
        projected = self.client.get(
            f"/compute/projects/{project}", headers=headers
        )
        self.assertEqual(projected.status_code, 200, projected.text)
        self.assertFalse(projected.json()["provider_dispatch_enabled"])
        listed = self.client.get("/compute/projects", headers=headers)
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertFalse(listed.json()["projects"][0]["provider_dispatch_enabled"])

        response = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers={
                **headers,
                "Idempotency-Key": "disabled-dispatch-create-0001",
            },
        )
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(
            response.json()["detail"],
            "Exact-asset dispatch intent creation is disabled by this release",
        )

        fetched = self.client.get(
            f"/compute/projects/{project}/dispatch-intents/wallet-job-0001",
            headers=headers,
        )
        self.assertEqual(fetched.status_code, 404, fetched.text)

    def test_funding_capabilities_use_release_bound_exact_asset_language(self):
        response = self.client.get("/compute/funding-capabilities")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(
            body["eth"]["reason"],
            "release_generated_base_sepolia_vault_evidence_required",
        )
        self.assertEqual(
            body["exact_asset_vault"]["review_status"],
            "reviewed_and_extensively_tested_not_formally_audited",
        )
        self.assertFalse(
            body["exact_asset_vault"]["provider_dispatch_authoritative"]
        )
        self.assertEqual(
            body["dispatch_intents"],
            {
                "metadata_intent_creation": False,
                "provider_dispatch": False,
                "independent_metering": False,
                "settlement": False,
                "exact_asset_only": True,
                "mutation_route": None,
                "status_route_template": (
                    "/compute/projects/{project_id}/dispatch-intents/"
                    "{job_reference}"
                ),
                "reason": "idempotent_tinker_provider_adapter_unavailable",
            },
        )
        self.assertTrue(body["credits"]["distinct_from_exact_asset_vault"])
        self.assertNotIn("audited_deposit_vault_not_deployed", response.text)


if __name__ == "__main__":
    unittest.main()
