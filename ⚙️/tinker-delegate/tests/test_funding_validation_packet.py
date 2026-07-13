import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tinker_delegate.billing_uploader import BillingCardUploadResult
from tinker_delegate.config import Settings
from tinker_delegate.funding_validation_packet import (
    check_funding_validation_packet,
    run_funding_validation_packet,
)


def _receipt() -> dict:
    return {
        "surface": "payment_method",
        "outcome": "card_declined",
        "furthest_stage": "payment_submitted",
        "bounded_message": "Your card was declined.",
        "evidence_hash": "a" * 64,
        "account_hash": "",
        "amount_band": "",
        "balance_band": "",
        "tdx_quote_hash": "b" * 64,
        "card_payload_destroyed": True,
        "raw_secret_egress": False,
        "issued_at": 123,
    }


def _add_balance_receipt() -> dict:
    return {
        "surface": "add_balance",
        "outcome": "payment_method_required",
        "furthest_stage": "not_started",
        "bounded_message": "Payment method required before adding balance",
        "evidence_hash": "d" * 64,
        "account_hash": "",
        "amount_band": "5_25_usd",
        "balance_band": "unknown",
        "tdx_quote_hash": "",
        "card_payload_destroyed": False,
        "raw_secret_egress": False,
        "issued_at": 124,
    }


def _reauth_response() -> dict:
    return {
        "success": True,
        "authenticated": True,
        "error_kind": "",
        "attempt_record": {
            "surface": "tinker_auth",
            "outcome": "success",
            "furthest_stage": "authenticated",
            "bounded_message": "reauthenticated",
            "evidence_hash": "e" * 64,
            "account_hash": "f" * 64,
            "amount_band": "",
            "balance_band": "",
            "tdx_quote_hash": "",
            "card_payload_destroyed": False,
            "raw_secret_egress": False,
            "issued_at": 122,
        },
    }


def _env(tmpdir: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "TINKER_FUNDING_MODE": "operator_capped_validation",
            "TINKER_FUNDING_RECEIPT_STORE_PATH": str(Path(tmpdir) / "funding_receipts.enc"),
            "TINKER_FUNDING_RECEIPT_STORE_KEY": "88" * 32,
        }
    )
    return env


class FundingValidationPacketTest(unittest.TestCase):
    def test_runner_builds_and_verifies_packet_from_existing_bounded_receipt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "existing-receipt.json"
            add_balance_receipt_path = Path(tmpdir) / "existing-add-balance-receipt.json"
            output_dir = Path(tmpdir) / "packet"
            receipt_path.write_text(json.dumps(_receipt()), encoding="utf-8")
            add_balance_receipt_path.write_text(json.dumps(_add_balance_receipt()), encoding="utf-8")
            settings = Settings(
                funding_mode="operator_capped_validation",
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="88" * 32,
            )

            result = run_funding_validation_packet(
                settings,
                output_dir=output_dir,
                api_url="http://localhost:8080",
                amount_dollars=10.0,
                expected_compose_hash="c" * 64,
                allow_local_attestation=True,
                validation_id="operator-run-1",
                receipt_json=receipt_path,
                add_balance_receipt_json=add_balance_receipt_path,
            ).to_public_dict()

            self.assertTrue(result["ok"])
            self.assertTrue(result["preflight_ready"])
            self.assertFalse(result["card_attempt_run"])
            self.assertEqual(result["receipt_outcome"], "card_declined")
            self.assertEqual(result["add_balance_receipt_outcome"], "payment_method_required")
            self.assertTrue(result["add_balance_verification_ok"])
            for name in (
                "preflight.json",
                "payment-method-receipt.json",
                "funding-manifest.json",
                "funding-verification.json",
                "add-balance-receipt.json",
                "add-balance-manifest.json",
                "add-balance-verification.json",
                "funding-validation-summary.json",
            ):
                self.assertTrue((output_dir / name).exists(), name)
            summary = json.loads((output_dir / "funding-validation-summary.json").read_text(encoding="utf-8"))
            self.assertTrue(summary["ok"])
            self.assertNotIn("4242424242424242", json.dumps(summary))

    def test_cli_packet_rejects_card_fields_without_explicit_run_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "funding-validation-packet",
                    "--output-dir",
                    str(Path(tmpdir) / "packet"),
                    "--api-url",
                    "http://localhost:8080",
                    "--amount",
                    "10",
                    "--allow-local-attestation",
                    "--number",
                    "4242424242424242",
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=_env(tmpdir),
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("--run-card-attempt", result.stdout)
            self.assertNotIn("4242424242424242", result.stdout)
            self.assertNotIn("4242424242424242", result.stderr)

    def test_cli_packet_prompt_requires_deployed_policy_before_prompting(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "funding-validation-packet",
                    "--output-dir",
                    str(Path(tmpdir) / "packet"),
                    "--api-url",
                    "http://localhost:8080",
                    "--amount",
                    "10",
                    "--run-card-attempt",
                    "--prompt-card",
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=_env(tmpdir),
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("policy rejected", result.stdout)
            self.assertIn("--compose-hash", result.stdout)
            self.assertNotIn("Card number", result.stdout)

    def test_cli_packet_rejects_mixed_prompt_and_test_card_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "funding-validation-packet",
                    "--output-dir",
                    str(Path(tmpdir) / "packet"),
                    "--api-url",
                    "http://localhost:8080",
                    "--amount",
                    "10",
                    "--allow-local-attestation",
                    "--run-card-attempt",
                    "--prompt-card",
                    "--number",
                    "4242424242424242",
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=_env(tmpdir),
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("either --prompt-card or test-card fields", result.stdout)
            self.assertNotIn("4242424242424242", result.stdout)
            self.assertNotIn("4242424242424242", result.stderr)

    def test_runner_card_attempt_uses_fake_uploader_and_zeroes_card_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "packet"
            card_data = {
                "card_number": "4242424242424242",
                "exp_month": "12",
                "exp_year": "2030",
                "cvc": "123",
                "cardholder_name": "Stripe Test User",
                "address_postal": "94105",
            }
            settings = Settings(
                funding_mode="operator_capped_validation",
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="99" * 32,
            )

            def fake_upload(api_url, submitted_card, policy):
                self.assertEqual(api_url, "http://localhost:8080")
                self.assertEqual(submitted_card["card_number"], "4242424242424242")
                self.assertTrue(policy.allow_local)
                return BillingCardUploadResult(
                    status_code=200,
                    response={
                        "success": False,
                        "error": "Your card was declined.",
                        "attempt_record": _receipt(),
                    },
                )

            result = run_funding_validation_packet(
                settings,
                output_dir=output_dir,
                api_url="http://localhost:8080",
                amount_dollars=10.0,
                allow_local_attestation=True,
                validation_id="operator-run-1",
                run_card_attempt=True,
                card_data=card_data,
                upload_fn=fake_upload,
            ).to_public_dict()

            self.assertTrue(result["ok"])
            self.assertTrue(result["card_attempt_run"])
            self.assertTrue(all(value == "" for value in card_data.values()))
            rendered_packet = "\n".join(path.read_text(encoding="utf-8") for path in output_dir.iterdir())
            self.assertNotIn("4242424242424242", rendered_packet)
            self.assertNotIn("Stripe Test User", rendered_packet)

    def test_runner_add_balance_attempt_uses_fake_poster(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "existing-receipt.json"
            output_dir = Path(tmpdir) / "packet"
            receipt_path.write_text(json.dumps(_receipt()), encoding="utf-8")
            settings = Settings(
                funding_mode="operator_capped_validation",
                allow_add_balance_endpoint=True,
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="aa" * 32,
            )

            def fake_add_balance(api_url, amount_dollars, auth_token):
                self.assertEqual(api_url, "http://localhost:8080")
                self.assertEqual(amount_dollars, 10.0)
                self.assertEqual(auth_token, "operator-secret")
                return {
                    "success": False,
                    "error": "Payment method required before adding balance",
                    "attempt_record": _add_balance_receipt(),
                }

            result = run_funding_validation_packet(
                settings,
                output_dir=output_dir,
                api_url="http://localhost:8080",
                amount_dollars=10.0,
                allow_local_attestation=True,
                validation_id="operator-run-1",
                receipt_json=receipt_path,
                run_add_balance_attempt=True,
                auth_token="operator-secret",
                add_balance_fn=fake_add_balance,
            ).to_public_dict()

            self.assertTrue(result["ok"])
            self.assertTrue(result["add_balance_attempt_run"])
            self.assertEqual(result["add_balance_receipt_outcome"], "payment_method_required")
            verification = json.loads((output_dir / "add-balance-verification.json").read_text(encoding="utf-8"))
            self.assertTrue(verification["ok"])

    def test_runner_allows_add_balance_only_packet_when_card_is_on_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "packet"
            settings = Settings(
                funding_mode="operator_capped_validation",
                allow_add_balance_endpoint=True,
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="ab" * 32,
            )

            def fake_add_balance(api_url, amount_dollars, auth_token):
                self.assertEqual(api_url, "http://localhost:8080")
                self.assertEqual(amount_dollars, 10.0)
                self.assertEqual(auth_token, "operator-secret")
                return {
                    "success": False,
                    "error": "Add-balance completion not confirmed",
                    "attempt_record": {
                        **_add_balance_receipt(),
                        "outcome": "unknown_failure",
                        "furthest_stage": "add_balance_submitted",
                        "bounded_message": "Add-balance completion not confirmed",
                    },
                }

            result = run_funding_validation_packet(
                settings,
                output_dir=output_dir,
                api_url="http://localhost:8080",
                amount_dollars=10.0,
                allow_local_attestation=True,
                validation_id="operator-run-1",
                run_add_balance_attempt=True,
                auth_token="operator-secret",
                add_balance_fn=fake_add_balance,
            ).to_public_dict()

            self.assertTrue(result["ok"])
            self.assertTrue(result["add_balance_attempt_run"])
            self.assertFalse(result["card_attempt_run"])
            self.assertEqual(result["receipt_path"], "")
            self.assertEqual(result["manifest_path"], "")
            self.assertEqual(result["verification_path"], "")
            self.assertEqual(result["receipt_surface"], "")
            self.assertEqual(result["receipt_outcome"], "")
            self.assertEqual(result["manifest_hash"], "")
            self.assertFalse(result["verification_ok"])
            self.assertEqual(result["add_balance_receipt_outcome"], "unknown_failure")
            self.assertTrue(result["add_balance_receipt_path"].endswith("add-balance-receipt.json"))
            self.assertTrue(result["add_balance_manifest_path"].endswith("add-balance-manifest.json"))
            self.assertTrue(result["add_balance_verification_path"].endswith("add-balance-verification.json"))
            self.assertFalse((output_dir / "payment-method-receipt.json").exists())
            self.assertFalse((output_dir / "funding-manifest.json").exists())
            self.assertFalse((output_dir / "funding-verification.json").exists())

            check = check_funding_validation_packet(
                packet_dir=output_dir,
                validation_id="operator-run-1",
                require_add_balance=True,
            ).to_public_dict()
            self.assertTrue(check["ok"])
            self.assertEqual(check["payment_manifest_hash"], "")
            checks = {item["name"]: item for item in check["checks"]}
            self.assertEqual(checks["payment_files"]["status"], "not_required_for_add_balance_only")
            self.assertEqual(checks["add_balance_manifest_replay"]["status"], "ok")

    def test_runner_reauth_attempt_uses_runtime_auth_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "existing-receipt.json"
            output_dir = Path(tmpdir) / "packet"
            receipt_path.write_text(json.dumps(_receipt()), encoding="utf-8")
            settings = Settings(
                funding_mode="operator_capped_validation",
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="aa" * 32,
            )

            def fake_reauth(api_url, auth_token):
                self.assertEqual(api_url, "http://localhost:8080")
                self.assertEqual(auth_token, "operator-secret")
                return _reauth_response()

            result = run_funding_validation_packet(
                settings,
                output_dir=output_dir,
                api_url="http://localhost:8080",
                amount_dollars=10.0,
                allow_local_attestation=True,
                validation_id="operator-run-1",
                receipt_json=receipt_path,
                run_reauth_attempt=True,
                auth_token="operator-secret",
                reauth_fn=fake_reauth,
            ).to_public_dict()

            self.assertTrue(result["ok"])
            self.assertTrue(result["reauth_attempt_run"])
            self.assertEqual(result["reauth_receipt_outcome"], "success")
            self.assertTrue((output_dir / "reauth-receipt.json").exists())

    def test_cli_packet_rejects_add_balance_attempt_without_amount(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "funding-validation-packet",
                    "--output-dir",
                    str(Path(tmpdir) / "packet"),
                    "--api-url",
                    "http://localhost:8080",
                    "--allow-local-attestation",
                    "--run-add-balance-attempt",
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=_env(tmpdir),
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("--amount", result.stdout)

    def test_cli_packet_writes_bounded_packet_from_existing_receipt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "receipt.json"
            add_balance_receipt_path = Path(tmpdir) / "add-balance-receipt.json"
            output_dir = Path(tmpdir) / "packet"
            receipt_path.write_text(json.dumps(_receipt()), encoding="utf-8")
            add_balance_receipt_path.write_text(json.dumps(_add_balance_receipt()), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "funding-validation-packet",
                    "--output-dir",
                    str(output_dir),
                    "--api-url",
                    "http://localhost:8080",
                    "--amount",
                    "10",
                    "--compose-hash",
                    "c" * 64,
                    "--allow-local-attestation",
                    "--validation-id",
                    "operator-run-1",
                    "--receipt-json",
                    str(receipt_path),
                    "--add-balance-receipt-json",
                    str(add_balance_receipt_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=_env(tmpdir),
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            body = json.loads(result.stdout)
            self.assertTrue(body["ok"])
            self.assertEqual(body["receipt_outcome"], "card_declined")
            self.assertEqual(body["add_balance_receipt_outcome"], "payment_method_required")
            verification = json.loads((output_dir / "funding-verification.json").read_text(encoding="utf-8"))
            self.assertTrue(verification["ok"])
            add_balance_verification = json.loads(
                (output_dir / "add-balance-verification.json").read_text(encoding="utf-8")
            )
            self.assertTrue(add_balance_verification["ok"])

    def test_checker_accepts_complete_local_packet_and_marks_no_deployed_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "receipt.json"
            add_balance_receipt_path = Path(tmpdir) / "add-balance-receipt.json"
            output_dir = Path(tmpdir) / "packet"
            receipt_path.write_text(json.dumps(_receipt()), encoding="utf-8")
            add_balance_receipt_path.write_text(json.dumps(_add_balance_receipt()), encoding="utf-8")
            settings = Settings(
                funding_mode="operator_capped_validation",
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="bb" * 32,
            )
            run_funding_validation_packet(
                settings,
                output_dir=output_dir,
                api_url="http://localhost:8080",
                amount_dollars=10.0,
                expected_compose_hash="c" * 64,
                allow_local_attestation=True,
                validation_id="operator-run-1",
                receipt_json=receipt_path,
                add_balance_receipt_json=add_balance_receipt_path,
            )

            check = check_funding_validation_packet(
                packet_dir=output_dir,
                validation_id="operator-run-1",
                expected_compose_hash="c" * 64,
                require_add_balance=True,
            ).to_public_dict()

            self.assertTrue(check["ok"])
            self.assertFalse(check["deployed_evidence"])
            checks = {item["name"]: item for item in check["checks"]}
            self.assertEqual(checks["deployed_attestation"]["status"], "not_required")
            self.assertEqual(checks["add_balance_manifest_replay"]["status"], "ok")

    def test_checker_rejects_deployed_claim_without_tdx_attestation_fetch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "receipt.json"
            output_dir = Path(tmpdir) / "packet"
            receipt_path.write_text(json.dumps(_receipt()), encoding="utf-8")
            settings = Settings(
                funding_mode="operator_capped_validation",
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="cc" * 32,
            )
            run_funding_validation_packet(
                settings,
                output_dir=output_dir,
                api_url="http://localhost:8080",
                amount_dollars=10.0,
                allow_local_attestation=True,
                validation_id="operator-run-1",
                receipt_json=receipt_path,
            )

            check = check_funding_validation_packet(
                packet_dir=output_dir,
                validation_id="operator-run-1",
                require_deployed_attestation=True,
            ).to_public_dict()

            self.assertFalse(check["ok"])
            checks = {item["name"]: item for item in check["checks"]}
            self.assertEqual(checks["deployed_attestation"]["status"], "missing")

    def test_checker_rejects_tampered_packet(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "receipt.json"
            output_dir = Path(tmpdir) / "packet"
            receipt_path.write_text(json.dumps(_receipt()), encoding="utf-8")
            settings = Settings(
                funding_mode="operator_capped_validation",
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="dd" * 32,
            )
            run_funding_validation_packet(
                settings,
                output_dir=output_dir,
                api_url="http://localhost:8080",
                amount_dollars=10.0,
                allow_local_attestation=True,
                validation_id="operator-run-1",
                receipt_json=receipt_path,
            )
            receipt = json.loads((output_dir / "payment-method-receipt.json").read_text(encoding="utf-8"))
            receipt["outcome"] = "success"
            (output_dir / "payment-method-receipt.json").write_text(json.dumps(receipt), encoding="utf-8")

            check = check_funding_validation_packet(
                packet_dir=output_dir,
                validation_id="operator-run-1",
            ).to_public_dict()

            self.assertFalse(check["ok"])
            checks = {item["name"]: item for item in check["checks"]}
            self.assertEqual(checks["payment_manifest_replay"]["status"], "failed")

    def test_cli_checker_writes_bounded_check_result(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "receipt.json"
            output_dir = Path(tmpdir) / "packet"
            check_path = Path(tmpdir) / "packet-check.json"
            receipt_path.write_text(json.dumps(_receipt()), encoding="utf-8")
            settings = Settings(
                funding_mode="operator_capped_validation",
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="ee" * 32,
            )
            run_funding_validation_packet(
                settings,
                output_dir=output_dir,
                api_url="http://localhost:8080",
                amount_dollars=10.0,
                allow_local_attestation=True,
                validation_id="operator-run-1",
                receipt_json=receipt_path,
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "check-funding-validation-packet",
                    "--packet-dir",
                    str(output_dir),
                    "--validation-id",
                    "operator-run-1",
                    "--output",
                    str(check_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=_env(tmpdir),
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            body = json.loads(check_path.read_text(encoding="utf-8"))
            self.assertTrue(body["ok"])


if __name__ == "__main__":
    unittest.main()
