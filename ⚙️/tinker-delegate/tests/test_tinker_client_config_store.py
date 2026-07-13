import json
import os
import tempfile
import unittest
from unittest.mock import patch

from tinker_delegate.config import Settings
from tinker_delegate.tinker_client_config_store import (
    build_tinker_client_config_status,
    resolve_tinker_client_config,
    save_tinker_client_config,
)
from tinker_delegate.tinker_proxy import build_tinker_proxy_status


STORE_KEY_HEX = "88" * 32
UPSTREAM_KEY = "tml-secretsecretsecretsecretsecret"
PROJECT_ID = "proj-sensitive"
BASE_URL = "https://api.thinkingmachines.ai/services/tinker-prod"


class TinkerClientConfigStoreTest(unittest.TestCase):
    def _settings(self, tmpdir: str, **overrides) -> Settings:
        values = {
            "project_id": "",
            "base_url": "",
            "client_config_store_path": os.path.join(tmpdir, "client_config.enc"),
            "client_config_store_key": STORE_KEY_HEX,
        }
        values.update(overrides)
        return Settings(**values)

    def test_save_and_resolve_client_config_without_raw_egress(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = self._settings(tmpdir)
            receipt = save_tinker_client_config(settings, project_id=PROJECT_ID, base_url=BASE_URL)
            resolved = resolve_tinker_client_config(settings)
            status = build_tinker_client_config_status(settings)

        rendered = json.dumps({"receipt": receipt, "status": status}, sort_keys=True)
        self.assertEqual(resolved["project_id"], PROJECT_ID)
        self.assertEqual(resolved["base_url"], BASE_URL)
        self.assertTrue(receipt["client_config"]["project_id_configured"])
        self.assertEqual(receipt["client_config"]["base_url_host_family"], "thinkingmachines")
        self.assertTrue(status["store"]["exists"])
        self.assertFalse(receipt["raw_secret_egress"])
        self.assertNotIn(PROJECT_ID, rendered)
        self.assertNotIn(BASE_URL, rendered)
        self.assertNotIn("thinkingmachines.ai/services", rendered)

    def test_env_settings_override_store_values(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = self._settings(tmpdir)
            save_tinker_client_config(settings, project_id=PROJECT_ID, base_url=BASE_URL)
            resolved = resolve_tinker_client_config(
                self._settings(
                    tmpdir,
                    project_id="proj-env",
                    base_url="https://override.thinkingmachines.dev",
                )
            )

        self.assertEqual(resolved["project_id"], "proj-env")
        self.assertEqual(resolved["base_url"], "https://override.thinkingmachines.dev")

    def test_proxy_status_uses_stored_client_config_without_leaking_it(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = self._settings(tmpdir)
            save_tinker_client_config(settings, project_id=PROJECT_ID, base_url=BASE_URL)
            with patch.dict(os.environ, {"TINKER_API_KEY": UPSTREAM_KEY}, clear=False):
                status = build_tinker_proxy_status(settings)

        rendered = json.dumps(status, sort_keys=True)
        self.assertTrue(status["sealed_client_config"]["api_key_configured"])
        self.assertTrue(status["sealed_client_config"]["project_id_configured"])
        self.assertEqual(status["sealed_client_config"]["base_url_host_family"], "thinkingmachines")
        self.assertNotIn(PROJECT_ID, rendered)
        self.assertNotIn(BASE_URL, rendered)
        self.assertNotIn(UPSTREAM_KEY, rendered)

    def test_invalid_base_url_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(ValueError, "http"):
                save_tinker_client_config(
                    self._settings(tmpdir),
                    project_id=PROJECT_ID,
                    base_url="ftp://example.com",
                )


if __name__ == "__main__":
    unittest.main()
