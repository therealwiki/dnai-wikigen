import tempfile
import unittest
from pathlib import Path

from tinker_delegate.debug_artifacts import purge_secret_debug_artifacts


class DebugArtifactsTest(unittest.TestCase):
    def test_purge_noops_without_configured_directory(self):
        self.assertEqual(purge_secret_debug_artifacts(""), 0)

    def test_purge_noops_for_missing_directory(self):
        self.assertEqual(purge_secret_debug_artifacts("/tmp/does-not-exist-dnai-wikigen"), 0)

    def test_purge_deletes_known_secret_bearing_browser_artifacts_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            secret_names = [
                "trace.zip",
                "trace-payment.zip",
                "card-flow.har",
                "checkout.webm",
                "screen.mp4",
                "screenshot_billing_filled.png",
                "screenshot_saved_card.png",
                "screenshot_stripe_iframe.png",
            ]
            safe_names = [
                "notes.txt",
                "screenshot_no_stripe.png",
                "billing-summary.json",
            ]
            for name in secret_names + safe_names:
                (root / name).write_text("placeholder")

            deleted = purge_secret_debug_artifacts(root)

            self.assertEqual(deleted, len(secret_names))
            for name in secret_names:
                self.assertFalse((root / name).exists(), name)
            for name in safe_names:
                self.assertTrue((root / name).exists(), name)


if __name__ == "__main__":
    unittest.main()
