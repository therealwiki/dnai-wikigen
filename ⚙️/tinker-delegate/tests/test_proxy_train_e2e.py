"""End-to-end proof: a scoped, spend-limited proxy JWT drives a real training
run through the actual /tinker/train endpoint.

This exercises the true request path — proxy-token verification, scope check,
spend-limit enforcement, then run_tinker_training executing create → forward/
backward + optim per step → checkpoint → bounded receipt — with only the Tinker
compute backend swapped for the synthetic FakeTinkerServiceClient (the real
upstream is externally 402-blocked). Nothing about our auth/delegation/training
wiring is stubbed here; only the remote GPU is.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from tinker_delegate import api as api_mod
from tinker_delegate import tinker_training as tt
from tinker_delegate.config import Settings
from tinker_delegate.fake_tinker_backend import FakeTinkerServiceClient
from tinker_delegate.tinker_proxy import issue_proxy_token


def _settings() -> Settings:
    tmp = tempfile.mkdtemp()
    return Settings(
        proxy_jwt_key="11" * 32,
        proxy_approved_subjects="",
        proxy_token_store_path=tmp + "/proxy_tokens.enc",
        proxy_token_store_key="22" * 32,
        allow_tinker_train_endpoint=True,
        runtime_auth_token="operator-token-xyz",
        real_sdk_model="meta-llama/Llama-3.2-1B",
        real_sdk_rank=4,
        train_max_usd=0.25,
        encumbrance_required=False,
    )


class TestProxyTrainEndToEnd(unittest.TestCase):
    def test_scoped_proxy_token_drives_training_through_endpoint(self):
        s = _settings()
        # A downstream principal's token: scoped to tinker:train with a spend cap.
        _claims, jwt = issue_proxy_token(
            s, subject="downstream-user",
            scopes=["tinker:train"],
            scope_limits={"tinker:train": {"max_amount_usd": 0.10}},
        )
        with mock.patch.object(api_mod, "settings", s), \
             mock.patch.dict(os.environ, {"TINKER_API_KEY": "sealed-fake-key"}), \
             mock.patch.object(tt, "_create_service_client",
                               lambda *a, **k: FakeTinkerServiceClient(api_key="k")):
            client = TestClient(api_mod.app)
            r = client.post(
                "/tinker/train",
                headers={"Authorization": f"Bearer {jwt}"},
                json={"steps": 2, "max_usd": 0.05, "require_encumbrance": False},
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["success"], body)
        self.assertEqual(body["outcome"], "training_completed")
        self.assertEqual(body["steps_completed"], 2)
        self.assertTrue(body["checkpoint_saved"])
        self.assertFalse(body["raw_secret_egress"])
        # Went through the PROXY auth path (not operator/runtime).
        self.assertEqual(body.get("proxy_auth_context", {}).get("auth_kind"), "proxy")

    def test_proxy_token_without_train_scope_is_refused(self):
        s = _settings()
        _claims, jwt = issue_proxy_token(
            s, subject="downstream-user", scopes=["proxy:status"],
            scope_limits={},
        )
        with mock.patch.object(api_mod, "settings", s), \
             mock.patch.dict(os.environ, {"TINKER_API_KEY": "sealed-fake-key"}), \
             mock.patch.object(tt, "_create_service_client",
                               lambda *a, **k: FakeTinkerServiceClient(api_key="k")):
            client = TestClient(api_mod.app)
            r = client.post(
                "/tinker/train",
                headers={"Authorization": f"Bearer {jwt}"},
                json={"steps": 2, "max_usd": 0.05, "require_encumbrance": False},
            )
        # Rejected before any training runs.
        self.assertEqual(r.status_code, 403, r.text)

    def test_proxy_token_over_spend_limit_is_refused(self):
        s = _settings()
        _claims, jwt = issue_proxy_token(
            s, subject="downstream-user", scopes=["tinker:train"],
            scope_limits={"tinker:train": {"max_amount_usd": 0.01}},
        )
        with mock.patch.object(api_mod, "settings", s), \
             mock.patch.dict(os.environ, {"TINKER_API_KEY": "sealed-fake-key"}), \
             mock.patch.object(tt, "_create_service_client",
                               lambda *a, **k: FakeTinkerServiceClient(api_key="k")):
            client = TestClient(api_mod.app)
            r = client.post(
                "/tinker/train",
                headers={"Authorization": f"Bearer {jwt}"},
                json={"steps": 2, "max_usd": 0.05, "require_encumbrance": False},  # 0.05 > 0.01 cap
            )
        self.assertEqual(r.status_code, 403, r.text)


if __name__ == "__main__":
    unittest.main()
