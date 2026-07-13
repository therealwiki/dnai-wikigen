import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tinker_delegate.deployed_log_safety import scan_deployed_log_text


ROOT = Path(__file__).resolve().parents[1]


class DeployedLogSafetyTest(unittest.TestCase):
    def test_clean_logs_return_bounded_success(self):
        scan = scan_deployed_log_text(
            "\n".join(
                [
                    "[billing] navigating to billing page",
                    "[proxy] raw_secret_egress=false",
                    "health status ok",
                ]
            ),
            source_label="unit",
        ).to_public_dict()

        self.assertTrue(scan["success"])
        self.assertEqual(scan["surface"], "deployed_log_safety")
        self.assertEqual(scan["finding_count"], 0)
        self.assertEqual(scan["finding_counts"], {})
        self.assertFalse(scan["log_snippets_returned"])
        self.assertFalse(scan["raw_secret_egress"])

    def test_card_and_credential_shapes_are_reported_by_hash_only(self):
        raw_logs = "\n".join(
            [
                "card_number=4242424242424242",
                "cvc=123",
                "Authorization: Bearer secret-token-material",
                "api_key=tml-secretkeymaterialsecretkeymaterial",
                "verification_code=123456",
            ]
        )
        scan = scan_deployed_log_text(raw_logs, source_label="unit").to_public_dict()
        rendered = json.dumps(scan)

        self.assertFalse(scan["success"])
        self.assertGreaterEqual(scan["finding_count"], 5)
        self.assertIn("luhn_card_number", scan["finding_counts"])
        self.assertIn("unredacted_card_field", scan["finding_counts"])
        self.assertIn("unredacted_cvc_field", scan["finding_counts"])
        self.assertIn("bearer_token", scan["finding_counts"])
        self.assertIn("tinker_api_key", scan["finding_counts"])
        self.assertIn("otp_field", scan["finding_counts"])
        self.assertFalse(scan["log_snippets_returned"])
        self.assertFalse(scan["raw_secret_egress"])
        self.assertNotIn("4242424242424242", rendered)
        self.assertNotIn("secret-token-material", rendered)
        self.assertNotIn("tml-secretkeymaterialsecretkeymaterial", rendered)
        self.assertNotIn("123456", rendered)

    def test_cli_scans_file_and_writes_bounded_receipt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            logs_path = tmp / "logs.txt"
            output_path = tmp / "receipt.json"
            logs_path.write_text("health ok\ncard_number=<redacted>\n", encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "verify-deployed-log-safety",
                    "--logs-file",
                    str(logs_path),
                    "--source-label",
                    "test-file",
                    "--output",
                    str(output_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            receipt = json.loads(output_path.read_text(encoding="utf-8"))
            rendered = json.dumps(receipt)
            self.assertTrue(receipt["success"])
            self.assertEqual(receipt["source_label"], "test-file")
            self.assertFalse(receipt["log_snippets_returned"])
            self.assertFalse(receipt["raw_secret_egress"])
            self.assertNotIn("card_number", rendered)

    def test_cli_fails_closed_on_leak(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "tinker_delegate.main",
                "verify-deployed-log-safety",
                "--source-label",
                "stdin",
            ],
            cwd=ROOT,
            input="payment card 4242 4242 4242 4242\n",
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 1)
        receipt = json.loads(result.stdout)
        rendered = json.dumps(receipt)
        self.assertFalse(receipt["success"])
        self.assertEqual(receipt["finding_counts"]["luhn_card_number"], 1)
        self.assertFalse(receipt["log_snippets_returned"])
        self.assertFalse(receipt["raw_secret_egress"])
        self.assertNotIn("4242 4242 4242 4242", rendered)


if __name__ == "__main__":
    unittest.main()
