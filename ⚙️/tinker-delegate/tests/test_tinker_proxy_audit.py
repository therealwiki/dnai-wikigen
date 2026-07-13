import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tinker_delegate.tinker_proxy_audit import verify_proxy_token_audit


SUBJECT_HASH = "a" * 64
JTI_HASH = "b" * 64
RECIPIENT_HASH = "c" * 64


def _issue_record(**overrides):
    record = {
        "event": "issued",
        "subject_hash": SUBJECT_HASH,
        "jwt_id_hash": JTI_HASH,
        "recipient_public_key_hash": RECIPIENT_HASH,
        "scopes": ["billing:add-balance", "proxy:status"],
        "issued_at": 100,
        "expires_at": 200,
        "raw_secret_egress": False,
    }
    record.update(overrides)
    return record


def _revoke_record(**overrides):
    record = {
        "event": "revoked",
        "jwt_id_hash": JTI_HASH,
        "revoked_at": 180,
        "revocation_reason": "operator_requested",
        "raw_secret_egress": False,
    }
    record.update(overrides)
    return record


def _audit(records=None):
    records = records or [_issue_record(), _revoke_record()]
    issued = [record for record in records if record["event"] == "issued"]
    revoked = [record for record in records if record["event"] == "revoked"]
    return {
        "surface": "tinker_proxy_token_audit",
        "record_count": len(records),
        "issued_count": len(issued),
        "revoked_count": len(revoked),
        "active_unexpired_or_unknown_count": len(issued) - len(revoked),
        "records": records,
        "raw_secret_egress": False,
    }


def _operation_receipt(**overrides):
    receipt = {
        "surface": "add_balance",
        "outcome": "success",
        "issued_at": 150,
        "raw_secret_egress": False,
        "proxy_auth_context": {
            "auth_kind": "proxy",
            "required_scope": "billing:add-balance",
            "subject_hash": SUBJECT_HASH,
            "jwt_id_hash": JTI_HASH,
            "scopes": ["billing:add-balance", "proxy:status"],
            "expires_at": 200,
            "raw_secret_egress": False,
        },
    }
    receipt.update(overrides)
    return receipt


class TinkerProxyAuditVerifierTest(unittest.TestCase):
    def test_verifies_issue_revoke_chronology_and_bound_operation_receipt(self):
        result = verify_proxy_token_audit(
            audit=_audit(),
            operation_receipts=[_operation_receipt()],
            require_operation_binding=True,
        ).to_public_dict()

        self.assertTrue(result["ok"])
        self.assertEqual(result["issued_count"], 1)
        self.assertEqual(result["revoked_count"], 1)
        self.assertEqual(result["bound_operation_receipt_count"], 1)
        self.assertFalse(result["raw_secret_egress"])

    def test_fails_when_operation_happened_after_revocation(self):
        result = verify_proxy_token_audit(
            audit=_audit(),
            operation_receipts=[_operation_receipt(issued_at=181)],
            require_operation_binding=True,
        ).to_public_dict()

        self.assertFalse(result["ok"])
        statuses = {check["name"]: check["status"] for check in result["checks"]}
        self.assertEqual(statuses["operation_receipt_0_before_revocation"], "revoked_before_operation")

    def test_fails_required_operation_binding_when_context_is_missing(self):
        result = verify_proxy_token_audit(
            audit=_audit(),
            operation_receipts=[{"surface": "add_balance", "issued_at": 150, "raw_secret_egress": False}],
            require_operation_binding=True,
        ).to_public_dict()

        self.assertFalse(result["ok"])
        self.assertEqual(result["missing_operation_binding_count"], 1)

    def test_fails_unsupported_issued_scope(self):
        result = verify_proxy_token_audit(
            audit=_audit([_issue_record(scopes=["billing:add-balance", "admin:all"])]),
        ).to_public_dict()

        self.assertFalse(result["ok"])
        statuses = {check["name"]: check["status"] for check in result["checks"]}
        self.assertEqual(statuses["issued_scopes_supported"], "unsupported_scope")

    def test_rejects_secret_key_material_in_inputs(self):
        result = verify_proxy_token_audit(
            audit=_audit(),
            operation_receipts=[{"surface": "add_balance", "raw_secret_egress": False, "token": "secret"}],
        ).to_public_dict()

        self.assertFalse(result["ok"])
        self.assertEqual(result["checks"][0]["name"], "secret_material")

    def test_cli_verifies_exported_audit_and_receipt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "audit.json"
            receipt_path = Path(tmpdir) / "receipt.json"
            output_path = Path(tmpdir) / "verification.json"
            audit_path.write_text(json.dumps(_audit()), encoding="utf-8")
            receipt_path.write_text(json.dumps(_operation_receipt()), encoding="utf-8")
            env = os.environ.copy()
            env.update(
                {
                    "TINKER_PROXY_TOKEN_STORE_PATH": str(Path(tmpdir) / "proxy_tokens.enc"),
                    "TINKER_PROXY_TOKEN_STORE_KEY": "88" * 32,
                }
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "verify-tinker-proxy-token-audit",
                    "--audit-json",
                    str(audit_path),
                    "--operation-receipt-json",
                    str(receipt_path),
                    "--require-operation-binding",
                    "--output",
                    str(output_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            body = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(body["ok"])
            self.assertEqual(body["surface"], "tinker_proxy_audit_verification")
            self.assertEqual(body["bound_operation_receipt_count"], 1)


if __name__ == "__main__":
    unittest.main()
