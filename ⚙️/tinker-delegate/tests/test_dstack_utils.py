import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tinker_delegate.dstack_utils import get_attestation_details


class DstackUtilsTest(unittest.TestCase):
    def test_attestation_details_never_collect_raw_dstack_metadata(self):
        sentinel = "sentinel-runtime-auth-secret"
        tcb_info = Mock()
        tcb_info.model_dump.return_value = {
            "app_compose": {
                "docker_compose_file": f"TINKER_RUNTIME_AUTH_TOKEN={sentinel}",
            },
        }
        client = Mock()
        client.info.return_value = SimpleNamespace(
            app_id="app-ok",
            os_image_hash="os-ok",
            compose_hash="compose-ok",
            tcb_info=tcb_info,
        )
        client.get_quote.return_value = SimpleNamespace(
            quote="aa",
            report_data="bb",
            event_log={"secret": sentinel},
            vm_config={"secret": sentinel},
        )

        with patch("tinker_delegate.dstack_utils._client", return_value=client):
            details = get_attestation_details(b"artifact-binding")

        self.assertEqual(
            details,
            {
                "quote": "aa",
                "quote_report_data": "bb",
                "app_id": "app-ok",
                "os_image_hash": "os-ok",
                "compose_hash": "compose-ok",
            },
        )
        self.assertNotIn(sentinel, repr(details))
        tcb_info.model_dump.assert_not_called()


if __name__ == "__main__":
    unittest.main()
