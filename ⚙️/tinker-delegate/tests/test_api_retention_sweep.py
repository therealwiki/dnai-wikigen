import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.config import Settings


class _FakeControlPlane:
    def __init__(self, records):
        self._records = records

    def sweep_retention(self):
        return self._records


class RetentionSweepEndpointTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings

    def tearDown(self):
        api.settings = self.original_settings

    def test_sweep_returns_bounded_records(self):
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        client = TestClient(api.app)
        records = [
            {
                "kind": "destruction_record",
                "deal_ref_hash": "0x" + "ab" * 32,
                "complete": True,
                "record_hash": "0x" + "cd" * 32,
                "raw_secret_egress": False,
            }
        ]
        with patch("tinker_delegate.api._get_control_plane", return_value=_FakeControlPlane(records)):
            resp = client.post(
                "/retention/sweep", headers={"Authorization": "Bearer operator-secret"}
            )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["swept_count"], 1)
        self.assertFalse(body["raw_secret_egress"])
        self.assertEqual(body["destruction_records"][0]["deal_ref_hash"], "0x" + "ab" * 32)
        # No raw deal ids or artifacts leak.
        self.assertNotIn("deal://", json.dumps(body))

    def test_sweep_requires_auth(self):
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        client = TestClient(api.app)
        resp = client.post("/retention/sweep")
        self.assertEqual(resp.status_code, 401)

    def test_sweep_degrades_when_control_plane_unavailable(self):
        from fastapi import HTTPException

        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        client = TestClient(api.app)
        with patch("tinker_delegate.api._get_control_plane", side_effect=HTTPException(503, "no tinker")):
            resp = client.post(
                "/retention/sweep", headers={"Authorization": "Bearer operator-secret"}
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["swept_count"], 0)


class SourceGrantsEndpointTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings

    def tearDown(self):
        api.settings = self.original_settings

    def test_manifest_empty_when_unconfigured(self):
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        client = TestClient(api.app)
        resp = client.get("/source/grants", headers={"Authorization": "Bearer operator-secret"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["grant_count"], 0)

    def test_manifest_requires_auth(self):
        api.settings = Settings(runtime_auth_required=True, runtime_auth_token="operator-secret")
        client = TestClient(api.app)
        self.assertEqual(client.get("/source/grants").status_code, 401)

    def test_manifest_is_bounded_when_configured(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grants.json"
            path.write_text(
                json.dumps(
                    {
                        "grants": [
                            {
                                "source_ref": "source://secret-acct",
                                "controller_ref": "tee-runtime",
                                "approved_by": "owner",
                                "scopes": ["tinker_compute"],
                                "granted_at": 0,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            api.settings = Settings(
                runtime_auth_required=True,
                runtime_auth_token="operator-secret",
                source_grants_path=str(path),
            )
            client = TestClient(api.app)
            resp = client.get("/source/grants", headers={"Authorization": "Bearer operator-secret"})
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertEqual(body["grant_count"], 1)
            self.assertNotIn("secret-acct", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
