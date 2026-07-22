import json
import hashlib
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from eth_account import Account

from tinker_delegate.main import _render_bounded_json
from tinker_delegate.run_metadata_store import stable_hash
from tests.test_consent_receipt import _grant, _signed_decision, _state_payload


def _env(tmpdir: str, *, funding_mode: str = "manual_prefund") -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "TINKER_FUNDING_MODE": funding_mode,
            "TINKER_FUNDING_RECEIPT_STORE_PATH": str(Path(tmpdir) / "funding_receipts.enc"),
            "TINKER_FUNDING_RECEIPT_STORE_KEY": "77" * 32,
            "TINKER_PROXY_TOKEN_STORE_PATH": str(Path(tmpdir) / "proxy_tokens.enc"),
            "TINKER_PROXY_TOKEN_STORE_KEY": "78" * 32,
        }
    )
    return env


class CliBoundedOutputsTest(unittest.TestCase):
    def test_policy_gate_cli_writes_bounded_receipt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            request_path = Path(tmpdir) / "request.json"
            policy_path = Path(tmpdir) / "policy.json"
            output_path = Path(tmpdir) / "policy-gate.json"
            request_path.write_text(
                json.dumps(
                    {
                        "request_id": "request-1",
                        "requester_ref": "agent://buyer",
                        "purpose": "rank-candidates",
                        "pipeline": "sft-rerank",
                        "data_classes": ["dual-use-uncertain"],
                        "output_schema": "score-band-v1",
                        "operations": ["score"],
                    }
                ),
                encoding="utf-8",
            )
            policy_path.write_text(
                json.dumps(
                    {
                        "policy_id": "policy-atlas",
                        "version": "policy-kernel/v1",
                        "corpus_ref": "corpus://atlas",
                        "allowed_purposes": ["rank-candidates"],
                        "denied_purposes": ["publish-raw-records"],
                        "allowed_pipelines": ["sft-rerank"],
                        "allowed_output_schemas": ["score-band-v1"],
                        "allowed_operations": ["score"],
                        "known_data_classes": ["dual-use-uncertain"],
                        "restricted_categories": [],
                        "hold_categories": [],
                        "ambiguous_categories": ["dual-use-uncertain"],
                        "hold_routes": {"dual-use-uncertain": "ethics-legal-reviewer"},
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "policy-gate",
                    "--request-json",
                    str(request_path),
                    "--policy-json",
                    str(policy_path),
                    "--output",
                    str(output_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=_env(tmpdir),
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            receipt = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["surface"], "conseca_policy_gate")
            self.assertEqual(receipt["decision"], "hold")
            self.assertEqual(receipt["action"], "route_to_review")
            rendered = json.dumps(receipt, sort_keys=True)
            self.assertNotIn("dual-use-uncertain", rendered)
            self.assertNotIn("rank-candidates", rendered)
            self.assertFalse(receipt["raw_secret_egress"])

    def test_consent_decision_cli_writes_bounded_receipt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "coordination-state.json"
            decision_path = Path(tmpdir) / "consent-decision.json"
            output_path = Path(tmpdir) / "consent-receipt.json"
            account = Account.from_key("0x" + "11" * 32)
            state_path.write_text(
                json.dumps(_state_payload(grants=[_grant("corpus://atlas", "owner-atlas")])),
                encoding="utf-8",
            )
            decision_path.write_text(
                json.dumps(
                    _signed_decision(
                        json.loads(state_path.read_text(encoding="utf-8")),
                        {
                            "turn_id": "turn-1",
                            "corpus_ref": "corpus://halcyon",
                            "owner_ref": "owner-halcyon",
                            "decision": "grant",
                        },
                        account,
                    )
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "consent-decision",
                    "--state-json",
                    str(state_path),
                    "--decision-json",
                    str(decision_path),
                    "--require-signature",
                    "--expected-signer",
                    account.address,
                    "--output",
                    str(output_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=_env(tmpdir),
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            receipt = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["surface"], "coordination_consent_decision")
            self.assertEqual(receipt["action"], "settle_bounded_result")
            self.assertEqual(receipt["turn"]["status_after"], "settled")
            self.assertTrue(receipt["signature_binding"]["verified"])
            rendered = json.dumps(receipt, sort_keys=True)
            self.assertNotIn("rank-candidates", rendered)
            self.assertNotIn("sft-rerank", rendered)
            self.assertNotIn("owner-halcyon", rendered)
            self.assertNotIn(account.address, rendered)
            self.assertNotIn(account.address.lower(), rendered)
            self.assertNotIn(json.loads(decision_path.read_text(encoding="utf-8"))["signature"]["signature"], rendered)
            self.assertFalse(receipt["raw_secret_egress"])

    def test_balance_can_query_deployed_delegate_api(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "balance.json"
            seen_headers: list[str] = []

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path != "/billing/balance":
                        self.send_response(404)
                        self.end_headers()
                        return
                    seen_headers.append(self.headers.get("Authorization", ""))
                    body = json.dumps(
                        {
                            "success": True,
                            "attempt_record": {
                                "surface": "balance",
                                "outcome": "success",
                                "amount_band": "",
                                "balance_band": "0_25_usd",
                                "raw_secret_egress": False,
                            },
                        }
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, format, *args):
                    return

            server = HTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                env = _env(tmpdir)
                env["TINKER_RUNTIME_AUTH_TOKEN"] = "operator-secret"
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "tinker_delegate.main",
                        "balance",
                        "--api-url",
                        f"http://127.0.0.1:{server.server_port}",
                        "--auth-token-env",
                        "TINKER_RUNTIME_AUTH_TOKEN",
                        "--output",
                        str(output_path),
                    ],
                    check=False,
                    cwd=Path(__file__).resolve().parents[1],
                    env=env,
                    text=True,
                    capture_output=True,
                )
            finally:
                server.shutdown()
                server.server_close()

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(seen_headers, ["Bearer operator-secret"])
            body = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(body["success"])
            self.assertEqual(body["attempt_record"]["balance_band"], "0_25_usd")
            self.assertFalse(body["attempt_record"]["raw_secret_egress"])

    def test_tinker_smoke_can_query_deployed_delegate_api(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "smoke.json"
            seen_headers: list[str] = []
            seen_body: list[dict] = []

            class Handler(BaseHTTPRequestHandler):
                def do_POST(self):
                    if self.path != "/tinker/smoke":
                        self.send_response(404)
                        self.end_headers()
                        return
                    seen_headers.append(self.headers.get("Authorization", ""))
                    length = int(self.headers.get("Content-Length", "0"))
                    seen_body.append(json.loads(self.rfile.read(length).decode("utf-8")))
                    body = json.dumps(
                        {
                            "surface": "tinker_sdk_smoke",
                            "success": True,
                            "outcome": "success",
                            "furthest_stage": "cleanup_completed",
                            "training_run_id_hash": "a" * 64,
                            "checkpoint_path_hash": "b" * 64,
                            "sample_observed": True,
                            "sample_output_returned": False,
                            "raw_secret_egress": False,
                        }
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, format, *args):
                    return

            server = HTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                env = _env(tmpdir)
                env["TINKER_RUNTIME_AUTH_TOKEN"] = "operator-secret"
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "tinker_delegate.main",
                        "tinker-smoke",
                        "--api-url",
                        f"http://127.0.0.1:{server.server_port}",
                        "--auth-token-env",
                        "TINKER_RUNTIME_AUTH_TOKEN",
                        "--max-usd",
                        "0.05",
                        "--model",
                        "Qwen/Qwen3-8B",
                        "--rank",
                        "32",
                        "--output",
                        str(output_path),
                    ],
                    check=False,
                    cwd=Path(__file__).resolve().parents[1],
                    env=env,
                    text=True,
                    capture_output=True,
                )
            finally:
                server.shutdown()
                server.server_close()

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(seen_headers, ["Bearer operator-secret"])
            self.assertEqual(seen_body[0]["max_usd"], 0.05)
            self.assertEqual(seen_body[0]["rank"], 32)
            body = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(body["success"])
            self.assertTrue(body["sample_observed"])
            self.assertFalse(body["sample_output_returned"])
            self.assertFalse(body["raw_secret_egress"])

    def test_add_balance_can_query_deployed_delegate_api(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "add-balance.json"
            receipt_path = Path(tmpdir) / "add-balance-receipt.json"
            seen_headers: list[str] = []
            seen_body: list[dict] = []

            class Handler(BaseHTTPRequestHandler):
                def do_POST(self):
                    if self.path != "/billing/add-balance":
                        self.send_response(404)
                        self.end_headers()
                        return
                    seen_headers.append(self.headers.get("Authorization", ""))
                    length = int(self.headers.get("Content-Length", "0"))
                    seen_body.append(json.loads(self.rfile.read(length).decode("utf-8")))
                    body = json.dumps(
                        {
                            "success": False,
                            "error": "Add-balance completion not confirmed",
                            "amount_dollars": 10.0,
                            "attempt_record": {
                                "surface": "add_balance",
                                "outcome": "unknown_failure",
                                "furthest_stage": "add_balance_submitted",
                                "bounded_message": "Add-balance completion not confirmed",
                                "evidence_hash": "a" * 64,
                                "account_hash": "",
                                "amount_band": "10_25_usd",
                                "balance_band": "unknown",
                                "tdx_quote_hash": "",
                                "card_payload_destroyed": False,
                                "raw_secret_egress": False,
                                "issued_at": 123,
                            },
                        }
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, format, *args):
                    return

            server = HTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                env = _env(tmpdir)
                env["TINKER_PROXY_JWT"] = "scoped-proxy-token"
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "tinker_delegate.main",
                        "add-balance",
                        "10",
                        "--api-url",
                        f"http://127.0.0.1:{server.server_port}",
                        "--auth-token-env",
                        "TINKER_PROXY_JWT",
                        "--receipt-output",
                        str(receipt_path),
                        "--output",
                        str(output_path),
                    ],
                    check=False,
                    cwd=Path(__file__).resolve().parents[1],
                    env=env,
                    text=True,
                    capture_output=True,
                )
            finally:
                server.shutdown()
                server.server_close()

            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(seen_headers, ["Bearer scoped-proxy-token"])
            self.assertEqual(seen_body, [{"amount_dollars": 10.0}])
            body = json.loads(output_path.read_text(encoding="utf-8"))
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertFalse(body["success"])
            self.assertEqual(receipt["surface"], "add_balance")
            self.assertFalse(receipt["raw_secret_egress"])

    def test_issue_tinker_proxy_token_can_query_deployed_delegate_api(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "proxy-token.json"
            seen_headers: list[str] = []
            seen_body: list[dict] = []

            class Handler(BaseHTTPRequestHandler):
                def do_POST(self):
                    if self.path != "/tinker/proxy/token":
                        self.send_response(404)
                        self.end_headers()
                        return
                    seen_headers.append(self.headers.get("Authorization", ""))
                    length = int(self.headers.get("Content-Length", "0"))
                    seen_body.append(json.loads(self.rfile.read(length).decode("utf-8")))
                    body = json.dumps(
                        {
                            "surface": "tinker_proxy_token",
                            "schema_version": 1,
                            "success": True,
                            "delivery": "x25519_aes_256_gcm_envelope",
                            "encrypted_token": {
                                "ephemeral_public_key": "11" * 32,
                                "nonce": "22" * 12,
                                "ciphertext": "33" * 48,
                            },
                            "associated_data": "44" * 32,
                            "token": {
                                "subject_hash": "a" * 64,
                                "scopes": ["proxy:status"],
                                "issued_at": 1000,
                                "expires_at": 1060,
                                "ttl_seconds": 60,
                                "jwt_id_hash": "b" * 64,
                            },
                            "plaintext_token_returned": False,
                            "raw_secret_egress": False,
                        }
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, format, *args):
                    return

            server = HTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                env = _env(tmpdir)
                env["TINKER_RUNTIME_AUTH_TOKEN"] = "operator-secret"
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "tinker_delegate.main",
                        "issue-tinker-proxy-token",
                        "--api-url",
                        f"http://127.0.0.1:{server.server_port}",
                        "--auth-token-env",
                        "TINKER_RUNTIME_AUTH_TOKEN",
                        "--subject",
                        "buyer-agent-1",
                        "--scope",
                        "proxy:status",
                        "--recipient-public-key",
                        "44" * 32,
                        "--output",
                        str(output_path),
                    ],
                    check=False,
                    cwd=Path(__file__).resolve().parents[1],
                    env=env,
                    text=True,
                    capture_output=True,
                )
            finally:
                server.shutdown()
                server.server_close()

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(seen_headers, ["Bearer operator-secret"])
            self.assertEqual(seen_body[0]["subject"], "buyer-agent-1")
            self.assertEqual(seen_body[0]["scopes"], ["proxy:status"])
            body = json.loads(output_path.read_text(encoding="utf-8"))
            rendered = repr(body)
            self.assertTrue(body["success"])
            self.assertFalse(body["plaintext_token_returned"])
            self.assertFalse(body["raw_secret_egress"])
            self.assertNotIn("operator-secret", rendered)
            self.assertNotIn("buyer-agent-1", rendered)

    def test_issue_proxy_token_remote_rejection_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "proxy-token-rejected.json"
            seen_headers: list[str] = []
            seen_body: list[dict] = []

            class Handler(BaseHTTPRequestHandler):
                def do_POST(self):
                    if self.path != "/tinker/proxy/token":
                        self.send_response(404)
                        self.end_headers()
                        return
                    seen_headers.append(self.headers.get("Authorization", ""))
                    length = int(self.headers.get("Content-Length", "0"))
                    seen_body.append(json.loads(self.rfile.read(length).decode("utf-8")))
                    body = json.dumps(
                        {
                            "detail": (
                                "proxy deployment policy denied token issuance: "
                                "compose_hash_not_approved"
                            )
                        }
                    ).encode("utf-8")
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, format, *args):
                    return

            server = HTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                env = _env(tmpdir)
                env["TINKER_RUNTIME_AUTH_TOKEN"] = "operator-secret"
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "tinker_delegate.main",
                        "issue-tinker-proxy-token",
                        "--api-url",
                        f"http://127.0.0.1:{server.server_port}",
                        "--auth-token-env",
                        "TINKER_RUNTIME_AUTH_TOKEN",
                        "--subject",
                        "buyer-agent-1",
                        "--scope",
                        "proxy:status",
                        "--recipient-public-key",
                        "44" * 32,
                        "--output",
                        str(output_path),
                    ],
                    check=False,
                    cwd=Path(__file__).resolve().parents[1],
                    env=env,
                    text=True,
                    capture_output=True,
                )
            finally:
                server.shutdown()
                server.server_close()

            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertEqual(seen_headers, ["Bearer operator-secret"])
            self.assertEqual(seen_body[0]["subject"], "buyer-agent-1")
            body = json.loads(output_path.read_text(encoding="utf-8"))
            rendered = repr(body)
            self.assertFalse(body["success"])
            self.assertEqual(body["surface"], "tinker_proxy_token")
            self.assertEqual(body["outcome"], "remote_rejected")
            self.assertEqual(body["status_code"], 403)
            self.assertEqual(body["error_kind"], "remote_error")
            self.assertIn("compose_hash_not_approved", body["bounded_message"])
            self.assertFalse(body["plaintext_token_returned"])
            self.assertFalse(body["raw_secret_egress"])
            self.assertNotIn("operator-secret", rendered)
            self.assertNotIn("buyer-agent-1", rendered)
            self.assertNotIn("44" * 32, rendered)

    def test_tinker_proxy_issue_policy_can_install_on_deployed_delegate_api(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "proxy-policy-status.json"
            policy_path = Path(tmpdir) / "proxy-policy.json"
            policy = {
                "schema_version": 1,
                "grants": [
                    {
                        "subject_hash": "a" * 64,
                        "recipient_public_key_hash": "b" * 64,
                        "scopes": ["billing:add-balance"],
                        "scope_limits": {"billing:add-balance": {"max_amount_usd": 10}},
                        "max_ttl_seconds": 60,
                    }
                ],
            }
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            seen_headers: list[str] = []
            seen_body: list[dict] = []

            class Handler(BaseHTTPRequestHandler):
                def do_PUT(self):
                    if self.path != "/tinker/proxy/issue-policy":
                        self.send_response(404)
                        self.end_headers()
                        return
                    seen_headers.append(self.headers.get("Authorization", ""))
                    length = int(self.headers.get("Content-Length", "0"))
                    seen_body.append(json.loads(self.rfile.read(length).decode("utf-8")))
                    body = json.dumps(
                        {
                            "surface": "tinker_proxy_issue_policy",
                            "schema_version": 1,
                            "success": True,
                            "required": True,
                            "path_configured": True,
                            "policy_present": True,
                            "policy_hash": "c" * 64,
                            "grant_count": 1,
                            "grants": [
                                {
                                    "grant_hash": "d" * 64,
                                    "subject_hash": "a" * 64,
                                    "recipient_public_key_hash": "b" * 64,
                                    "scopes": ["billing:add-balance"],
                                    "scope_limits": {"billing:add-balance": {"max_amount_usd": 10.0}},
                                    "max_ttl_seconds": 60,
                                    "raw_secret_egress": False,
                                }
                            ],
                            "raw_secret_egress": False,
                        }
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, format, *args):
                    return

            server = HTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                env = _env(tmpdir)
                env["TINKER_RUNTIME_AUTH_TOKEN"] = "operator-secret"
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "tinker_delegate.main",
                        "tinker-proxy-issue-policy",
                        "--api-url",
                        f"http://127.0.0.1:{server.server_port}",
                        "--auth-token-env",
                        "TINKER_RUNTIME_AUTH_TOKEN",
                        "--policy-json",
                        str(policy_path),
                        "--output",
                        str(output_path),
                    ],
                    check=False,
                    cwd=Path(__file__).resolve().parents[1],
                    env=env,
                    text=True,
                    capture_output=True,
                )
            finally:
                server.shutdown()
                server.server_close()

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(seen_headers, ["Bearer operator-secret"])
            self.assertEqual(seen_body, [{"policy": policy}])
            body = json.loads(output_path.read_text(encoding="utf-8"))
            rendered = repr(body)
            self.assertTrue(body["success"])
            self.assertFalse(body["raw_secret_egress"])
            self.assertNotIn("operator-secret", rendered)

    def test_tinker_client_config_cli_installs_from_env_without_leaking_values(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "client-config.json"
            env = _env(tmpdir)
            env.update(
                {
                    "TINKER_CLIENT_CONFIG_STORE_PATH": str(Path(tmpdir) / "client_config.enc"),
                    "TINKER_CLIENT_CONFIG_STORE_KEY": "88" * 32,
                    "TINKER_PROJECT_ID": "proj-sensitive",
                    "TINKER_BASE_URL": "https://api.thinkingmachines.ai/services/tinker-prod",
                }
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "tinker-client-config",
                    "--install",
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
            rendered = json.dumps(body, sort_keys=True)
            self.assertEqual(body["surface"], "tinker_client_config_install")
            self.assertTrue(body["client_config"]["project_id_configured"])
            self.assertEqual(body["client_config"]["base_url_host_family"], "thinkingmachines")
            self.assertNotIn("proj-sensitive", rendered)
            self.assertNotIn("api.thinkingmachines.ai", rendered)
            self.assertFalse(body["raw_secret_egress"])

    def test_tinker_client_config_cli_can_install_on_deployed_delegate_api(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "client-config.json"

            class Handler(BaseHTTPRequestHandler):
                def do_PUT(self):  # noqa: N802
                    if self.path != "/tinker/proxy/client-config":
                        self.send_response(404)
                        self.end_headers()
                        return
                    body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                    if self.headers.get("Authorization") != "Bearer runtime-secret":
                        self.send_response(403)
                        self.end_headers()
                        return
                    if body != {
                        "project_id": "proj-sensitive",
                        "base_url": "https://api.thinkingmachines.ai/services/tinker-prod",
                    }:
                        self.send_response(400)
                        self.end_headers()
                        return
                    response = json.dumps(
                        {
                            "surface": "tinker_client_config_install",
                            "success": True,
                            "client_config": {
                                "project_id_configured": True,
                                "project_id_hash": "a" * 64,
                                "project_id_returned": False,
                                "base_url_configured": True,
                                "base_url_host_family": "thinkingmachines",
                                "base_url_hash": "b" * 64,
                                "base_url_returned": False,
                            },
                            "store": {"encrypted": True, "exists": True, "path_returned": False},
                            "raw_secret_egress": False,
                        }
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)

                def log_message(self, format, *args):  # noqa: A002
                    return

            server = HTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            env = _env(tmpdir)
            env.update(
                {
                    "TINKER_RUNTIME_AUTH_TOKEN": "runtime-secret",
                    "TINKER_PROJECT_ID": "proj-sensitive",
                    "TINKER_BASE_URL": "https://api.thinkingmachines.ai/services/tinker-prod",
                }
            )

            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "tinker_delegate.main",
                        "tinker-client-config",
                        "--api-url",
                        f"http://127.0.0.1:{server.server_port}",
                        "--install",
                        "--output",
                        str(output_path),
                    ],
                    check=False,
                    cwd=Path(__file__).resolve().parents[1],
                    env=env,
                    text=True,
                    capture_output=True,
                )
            finally:
                server.shutdown()
                server.server_close()

            self.assertEqual(result.returncode, 0, result.stderr)
            body = json.loads(output_path.read_text(encoding="utf-8"))
            rendered = json.dumps(body, sort_keys=True)
            self.assertEqual(body["surface"], "tinker_client_config_install")
            self.assertNotIn("proj-sensitive", rendered)
            self.assertNotIn("api.thinkingmachines.ai", rendered)
            self.assertFalse(body["raw_secret_egress"])

    def test_proxy_recipient_keygen_issue_and_decrypt_keep_token_off_stdout(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key_path = Path(tmpdir) / "recipient.key"
            keygen_path = Path(tmpdir) / "recipient-public.json"
            issue_path = Path(tmpdir) / "encrypted-token.json"
            decrypt_path = Path(tmpdir) / "decrypt-receipt.json"
            audit_path = Path(tmpdir) / "proxy-audit.json"
            revoke_path = Path(tmpdir) / "proxy-revoke.json"
            token_path = Path(tmpdir) / "proxy.jwt"
            env = _env(tmpdir)
            env["TINKER_PROXY_JWT_KEY"] = "55" * 32

            keygen = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "tinker-proxy-recipient-keygen",
                    "--private-key-output",
                    str(private_key_path),
                    "--output",
                    str(keygen_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )
            public_key = json.loads(keygen_path.read_text(encoding="utf-8"))["public_key"]
            issued = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "issue-tinker-proxy-token",
                    "--subject",
                    "buyer-agent-1",
                    "--scope",
                    "proxy:status",
                    "--recipient-public-key",
                    public_key,
                    "--output",
                    str(issue_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )
            decrypted = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "decrypt-tinker-proxy-token",
                    "--encrypted-token-json",
                    str(issue_path),
                    "--private-key-file",
                    str(private_key_path),
                    "--token-output",
                    str(token_path),
                    "--output",
                    str(decrypt_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )
            jwt_id_hash = json.loads(issue_path.read_text(encoding="utf-8"))["token"]["jwt_id_hash"]
            audit = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "tinker-proxy-token-audit",
                    "--output",
                    str(audit_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )
            revoked = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "revoke-tinker-proxy-token",
                    "--jwt-id-hash",
                    jwt_id_hash,
                    "--reason",
                    "operator_requested",
                    "--output",
                    str(revoke_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )

            self.assertEqual(keygen.returncode, 0, keygen.stderr)
            self.assertEqual(issued.returncode, 0, issued.stderr)
            self.assertEqual(decrypted.returncode, 0, decrypted.stderr)
            self.assertEqual(audit.returncode, 0, audit.stderr)
            self.assertEqual(revoked.returncode, 0, revoked.stderr)
            self.assertEqual(keygen.stdout, "")
            self.assertEqual(issued.stdout, "")
            self.assertEqual(decrypted.stdout, "")
            self.assertEqual(audit.stdout, "")
            self.assertEqual(revoked.stdout, "")
            self.assertTrue(token_path.read_text(encoding="utf-8").strip().count(".") == 2)
            self.assertEqual(private_key_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(token_path.stat().st_mode & 0o777, 0o600)
            keygen_receipt = json.loads(keygen_path.read_text(encoding="utf-8"))
            issue_receipt = json.loads(issue_path.read_text(encoding="utf-8"))
            decrypt_receipt = json.loads(decrypt_path.read_text(encoding="utf-8"))
            audit_receipt = json.loads(audit_path.read_text(encoding="utf-8"))
            revoke_receipt = json.loads(revoke_path.read_text(encoding="utf-8"))
            rendered = repr([keygen_receipt, issue_receipt, decrypt_receipt, audit_receipt, revoke_receipt])
            self.assertTrue(keygen_receipt["private_key_saved"])
            self.assertFalse(keygen_receipt["private_key_returned"])
            self.assertEqual(
                keygen_receipt["public_key_hash"],
                stable_hash(public_key.lower(), prefix="proxy_recipient_public_key"),
            )
            self.assertNotEqual(
                keygen_receipt["public_key_hash"],
                hashlib.sha256(bytes.fromhex(public_key)).hexdigest(),
            )
            self.assertFalse(issue_receipt["plaintext_token_returned"])
            self.assertEqual(
                issue_receipt["recipient_public_key_hash"],
                keygen_receipt["public_key_hash"],
            )
            self.assertEqual(
                issue_receipt["audit_record"]["recipient_public_key_hash"],
                keygen_receipt["public_key_hash"],
            )
            self.assertEqual(issue_receipt["audit_record"]["event"], "issued")
            self.assertTrue(decrypt_receipt["plaintext_token_saved"])
            self.assertFalse(decrypt_receipt["plaintext_token_returned"])
            self.assertEqual(audit_receipt["issued_count"], 1)
            self.assertEqual(revoke_receipt["record"]["event"], "revoked")
            self.assertNotIn(token_path.read_text(encoding="utf-8").strip(), rendered)
            self.assertNotIn(private_key_path.read_text(encoding="utf-8").strip(), rendered)

    def test_proxy_token_revoke_unknown_hash_fails_bounded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            revoke_path = Path(tmpdir) / "proxy-revoke-missing.json"
            env = _env(tmpdir)
            env["TINKER_PROXY_JWT_KEY"] = "55" * 32

            revoked = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "revoke-tinker-proxy-token",
                    "--jwt-id-hash",
                    "ab" * 32,
                    "--reason",
                    "operator_requested",
                    "--output",
                    str(revoke_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )

            self.assertEqual(revoked.returncode, 1)
            self.assertEqual(revoked.stdout, "")
            body = json.loads(revoke_path.read_text(encoding="utf-8"))
            rendered = json.dumps(body, sort_keys=True)
            self.assertEqual(body["surface"], "tinker_proxy_token_revoke")
            self.assertFalse(body["success"])
            self.assertEqual(body["outcome"], "revoke_rejected")
            self.assertIn("revoke target was not issued", body["bounded_message"])
            self.assertFalse(body["raw_secret_egress"])
            self.assertNotIn("tml-", rendered)
            self.assertNotIn(env["TINKER_PROXY_JWT_KEY"], rendered)

    def test_proxy_token_decrypt_failed_issue_receipt_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            failed_issue_path = tmp / "failed-issue.json"
            private_key_path = tmp / "recipient.key"
            decrypt_path = tmp / "decrypt-receipt.json"
            token_path = tmp / "proxy.jwt"
            private_key = "44" * 32
            failed_issue_path.write_text(
                json.dumps(
                    {
                        "detail": "proxy deployment policy denied token issuance: compose_hash_not_approved",
                    }
                ),
                encoding="utf-8",
            )
            private_key_path.write_text(private_key, encoding="utf-8")

            decrypted = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "decrypt-tinker-proxy-token",
                    "--encrypted-token-json",
                    str(failed_issue_path),
                    "--private-key-file",
                    str(private_key_path),
                    "--token-output",
                    str(token_path),
                    "--output",
                    str(decrypt_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=_env(tmpdir),
                text=True,
                capture_output=True,
            )

            self.assertEqual(decrypted.returncode, 1)
            self.assertEqual(decrypted.stdout, "")
            self.assertEqual(decrypted.stderr, "")
            self.assertFalse(token_path.exists())
            receipt = json.loads(decrypt_path.read_text(encoding="utf-8"))
            rendered = repr(receipt)
            self.assertFalse(receipt["success"])
            self.assertEqual(receipt["error_kind"], "missing_encrypted_token")
            self.assertFalse(receipt["plaintext_token_saved"])
            self.assertFalse(receipt["plaintext_token_returned"])
            self.assertFalse(receipt["private_key_read"])
            self.assertFalse(receipt["private_key_returned"])
            self.assertFalse(receipt["raw_secret_egress"])
            self.assertNotIn(private_key, rendered)

    def test_proxy_identity_registry_sign_verify_and_issue_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env = _env(tmpdir)
            signer = Account.create("proxy identity registry verifier")
            signer_key = signer.key.hex()
            env["TINKER_PROXY_IDENTITY_REGISTRY_SIGNER_KEY"] = signer_key
            env["TINKER_PROXY_JWT_KEY"] = "55" * 32
            env["TINKER_PROXY_REQUIRE_ISSUE_POLICY"] = "true"
            env["TINKER_PROXY_REQUIRE_GRANT_LIFECYCLE"] = "true"
            env["TINKER_PROXY_REQUIRE_IDENTITY_REGISTRY"] = "true"
            env["TINKER_PROXY_REQUIRE_IDENTITY_REGISTRY_SIGNATURE"] = "true"
            env["TINKER_PROXY_IDENTITY_REGISTRY_SIGNER"] = signer.address
            policy_path = tmp / "proxy-policy.json"
            registry_path = tmp / "identity-registry.json"
            signed_registry_path = tmp / "signed-identity-registry.json"
            sign_receipt_path = tmp / "sign-receipt.json"
            verify_receipt_path = tmp / "verify-receipt.json"
            install_receipt_path = tmp / "install-registry-receipt.json"
            registry_status_path = tmp / "registry-status.json"
            installed_registry_path = tmp / "installed-identity-registry.json"
            issue_receipt_path = tmp / "issue-receipt.json"
            recipient_private_key_path = tmp / "recipient.key"
            recipient_keygen_path = tmp / "recipient-keygen.json"

            keygen = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "tinker-proxy-recipient-keygen",
                    "--private-key-output",
                    str(recipient_private_key_path),
                    "--output",
                    str(recipient_keygen_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )
            public_key = json.loads(recipient_keygen_path.read_text(encoding="utf-8"))["public_key"]
            policy = {
                "schema_version": 1,
                "grants": [
                    {
                        "subject_hash": stable_hash("buyer-agent-1", prefix="proxy_subject"),
                        "recipient_public_key_hash": stable_hash(
                            public_key.lower(),
                            prefix="proxy_recipient_public_key",
                        ),
                        "scopes": ["proxy:status"],
                        "max_ttl_seconds": 60,
                        "lifecycle": {
                            "status": "active",
                            "approved_by_hash": stable_hash("reviewer-1", prefix="proxy_grant_reviewer"),
                            "approval_event_hash": stable_hash(
                                "approval-event-1",
                                prefix="proxy_grant_approval",
                            ),
                            "approved_at": 1,
                            "expires_at": 4_102_444_800,
                        },
                    }
                ],
            }
            registry = {
                "schema_version": 1,
                "identities": [
                    {
                        "identity_hash": stable_hash("buyer-agent-1", prefix="proxy_subject"),
                        "role": "agent",
                        "status": "active",
                        "expires_at": 4_102_444_800,
                        "ignored_raw_label": "buyer-agent-1",
                    },
                    {
                        "identity_hash": stable_hash("reviewer-1", prefix="proxy_grant_reviewer"),
                        "role": "reviewer",
                        "status": "active",
                        "expires_at": 4_102_444_800,
                        "ignored_raw_label": "reviewer-1",
                    },
                ],
            }
            policy_path.write_text(json.dumps(policy, sort_keys=True), encoding="utf-8")
            registry_path.write_text(json.dumps(registry, sort_keys=True), encoding="utf-8")
            env["TINKER_PROXY_ISSUE_POLICY_PATH"] = str(policy_path)
            env["TINKER_PROXY_IDENTITY_REGISTRY_PATH"] = str(installed_registry_path)

            signed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "sign-tinker-proxy-identity-registry",
                    "--registry-json",
                    str(registry_path),
                    "--signed-registry-output",
                    str(signed_registry_path),
                    "--output",
                    str(sign_receipt_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )
            verified = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "verify-tinker-proxy-identity-registry",
                    "--registry-json",
                    str(signed_registry_path),
                    "--expected-signer",
                    signer.address,
                    "--output",
                    str(verify_receipt_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )
            installed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "tinker-proxy-identity-registry",
                    "--registry-json",
                    str(signed_registry_path),
                    "--output",
                    str(install_receipt_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )
            status = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "tinker-proxy-identity-registry",
                    "--output",
                    str(registry_status_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )
            issued = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "issue-tinker-proxy-token",
                    "--subject",
                    "buyer-agent-1",
                    "--scope",
                    "proxy:status",
                    "--recipient-public-key",
                    public_key,
                    "--ttl-seconds",
                    "60",
                    "--output",
                    str(issue_receipt_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )

            self.assertEqual(keygen.returncode, 0, keygen.stderr)
            self.assertEqual(signed.returncode, 0, signed.stderr)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertEqual(issued.returncode, 0, issued.stderr)
            self.assertEqual(signed.stdout, "")
            self.assertEqual(verified.stdout, "")
            self.assertEqual(installed.stdout, "")
            self.assertEqual(status.stdout, "")
            self.assertEqual(issued.stdout, "")
            sign_receipt = json.loads(sign_receipt_path.read_text(encoding="utf-8"))
            verify_receipt = json.loads(verify_receipt_path.read_text(encoding="utf-8"))
            install_receipt = json.loads(install_receipt_path.read_text(encoding="utf-8"))
            registry_status = json.loads(registry_status_path.read_text(encoding="utf-8"))
            signed_registry = json.loads(signed_registry_path.read_text(encoding="utf-8"))
            installed_registry = json.loads(installed_registry_path.read_text(encoding="utf-8"))
            issue_receipt = json.loads(issue_receipt_path.read_text(encoding="utf-8"))
            rendered_receipts = repr([sign_receipt, verify_receipt, install_receipt, registry_status, issue_receipt])
            rendered_registry = repr([signed_registry, installed_registry])

            self.assertTrue(sign_receipt["success"])
            self.assertTrue(verify_receipt["success"])
            self.assertTrue(install_receipt["success"])
            self.assertTrue(registry_status["success"])
            self.assertTrue(issue_receipt["success"])
            self.assertTrue(verify_receipt["signature_binding"]["verified"])
            self.assertEqual(sign_receipt["registry_hash"], verify_receipt["registry_hash"])
            self.assertEqual(sign_receipt["registry_hash"], install_receipt["registry_hash"])
            self.assertEqual(sign_receipt["registry_hash"], registry_status["registry_hash"])
            self.assertEqual(
                issue_receipt["policy_binding"]["identity_binding"]["signature_binding"]["registry_hash"],
                sign_receipt["registry_hash"],
            )
            self.assertEqual(sign_receipt["role_counts"], {"agent": 1, "reviewer": 1})
            self.assertEqual(registry_status["role_counts"], {"agent": 1, "reviewer": 1})
            self.assertTrue(install_receipt["signature_binding"]["verified"])
            self.assertTrue(registry_status["signature_binding"]["verified"])
            self.assertFalse(sign_receipt["signature"]["private_key_returned"])
            self.assertFalse(sign_receipt["signature"]["signature_returned"])
            self.assertFalse(sign_receipt["signature"]["signer_address_returned"])
            self.assertFalse(sign_receipt["signed_registry_returned"])
            self.assertNotIn(signer_key.replace("0x", ""), rendered_receipts)
            self.assertNotIn(signer.address, rendered_receipts)
            self.assertNotIn(signed_registry["signature"]["signature"], rendered_receipts)
            self.assertNotIn("buyer-agent-1", rendered_receipts)
            self.assertNotIn("reviewer-1", rendered_receipts)
            self.assertNotIn("ignored_raw_label", rendered_registry)
            self.assertNotIn("buyer-agent-1", rendered_registry)
            self.assertNotIn("reviewer-1", rendered_registry)

            failed_verify_path = tmp / "failed-verify.json"
            failed_verify = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "verify-tinker-proxy-identity-registry",
                    "--registry-json",
                    str(signed_registry_path),
                    "--expected-signer",
                    Account.create("wrong registry signer").address,
                    "--output",
                    str(failed_verify_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(failed_verify.returncode, 0)
            failed_receipt = json.loads(failed_verify_path.read_text(encoding="utf-8"))
            self.assertFalse(failed_receipt["success"])
            self.assertFalse(failed_receipt["raw_secret_egress"])
            self.assertNotIn(signer_key.replace("0x", ""), repr(failed_receipt))

    def test_proxy_grant_lifecycle_sign_cli_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env = _env(tmpdir)
            reviewer = Account.create("proxy grant lifecycle reviewer")
            reviewer_key = reviewer.key.hex()
            env["TINKER_PROXY_GRANT_REVIEWER_KEY"] = reviewer_key
            grant_path = tmp / "grant.json"
            signed_grant_path = tmp / "signed-grant.json"
            sign_receipt_path = tmp / "grant-sign-receipt.json"
            recipient_public_key = "ab" * 32
            grant = {
                "subject_hash": stable_hash("buyer-agent-1", prefix="proxy_subject"),
                "recipient_public_key_hash": stable_hash(
                    recipient_public_key,
                    prefix="proxy_recipient_public_key",
                ),
                "scopes": ["proxy:status"],
                "max_ttl_seconds": 60,
                "lifecycle": {
                    "status": "active",
                    "approved_by_hash": stable_hash(reviewer.address.lower(), prefix="proxy_grant_reviewer"),
                    "approval_event_hash": stable_hash("approval-event-1", prefix="proxy_grant_approval"),
                    "approved_at": 1,
                    "expires_at": 4_102_444_800,
                },
            }
            grant_path.write_text(json.dumps(grant, sort_keys=True), encoding="utf-8")

            signed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "sign-tinker-proxy-grant-lifecycle",
                    "--grant-json",
                    str(grant_path),
                    "--signed-grant-output",
                    str(signed_grant_path),
                    "--output",
                    str(sign_receipt_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                text=True,
                capture_output=True,
            )

            self.assertEqual(signed.returncode, 0, signed.stderr)
            self.assertEqual(signed.stdout, "")
            receipt = json.loads(sign_receipt_path.read_text(encoding="utf-8"))
            signed_grant = json.loads(signed_grant_path.read_text(encoding="utf-8"))
            rendered_receipt = repr(receipt)
            self.assertTrue(receipt["success"])
            self.assertEqual(receipt["surface"], "tinker_proxy_grant_lifecycle_sign")
            self.assertTrue(receipt["signed_grant_written"])
            self.assertFalse(receipt["signed_grant_returned"])
            self.assertFalse(receipt["signature"]["private_key_returned"])
            self.assertFalse(receipt["signature"]["signature_returned"])
            self.assertFalse(receipt["signature"]["signer_address_returned"])
            self.assertIn("approval_signature", signed_grant["lifecycle"])
            self.assertNotIn(reviewer_key.replace("0x", ""), rendered_receipt)
            self.assertNotIn(reviewer.address, rendered_receipt)
            self.assertNotIn(signed_grant["lifecycle"]["approval_signature"]["signature"], rendered_receipt)
            self.assertNotIn("buyer-agent-1", rendered_receipt)

    def test_tinker_smoke_non_json_remote_response_writes_bounded_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "smoke.json"

            class Handler(BaseHTTPRequestHandler):
                def do_POST(self):
                    # Consume the request before closing the HTTP/1.0 connection.
                    # On macOS, closing a socket with unread request bytes can send
                    # a TCP RST after the response headers.  httpx then sometimes
                    # reports a transport error, so the CLI exits before it can
                    # write the bounded non-JSON failure receipt this test covers.
                    request_length = int(self.headers.get("Content-Length", "0"))
                    self.rfile.read(request_length)
                    body = b"Internal Server Error"
                    self.send_response(500)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, format, *args):
                    return

            server = HTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "tinker_delegate.main",
                        "tinker-smoke",
                        "--api-url",
                        f"http://127.0.0.1:{server.server_port}",
                        "--max-usd",
                        "0.05",
                        "--output",
                        str(output_path),
                    ],
                    check=False,
                    cwd=Path(__file__).resolve().parents[1],
                    env=_env(tmpdir),
                    text=True,
                    capture_output=True,
                )
            finally:
                server.shutdown()
                server.server_close()

            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            body = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(body["surface"], "tinker_sdk_smoke")
            self.assertEqual(body["outcome"], "remote_non_json_response")
            self.assertEqual(body["status_code"], 500)
            self.assertNotIn("Internal Server Error", json.dumps(body))
            self.assertFalse(body["raw_secret_egress"])

    def test_preflight_can_write_bounded_json_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "preflight.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "funding-preflight",
                    "--amount",
                    "10",
                    "--api-url",
                    "http://localhost:8080",
                    "--allow-local-attestation",
                    "--output",
                    str(output_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=_env(tmpdir, funding_mode="operator_capped_validation"),
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            body = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(body["ready"])
            self.assertEqual(body["policy"]["mode"], "operator_capped_validation")

    def test_add_balance_can_write_policy_denied_receipt_file_without_card_material(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "add-balance-receipt.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "add-balance",
                    "5",
                    "--receipt-output",
                    str(receipt_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=_env(tmpdir),
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 1)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            rendered = json.dumps(receipt)
            self.assertEqual(receipt["surface"], "add_balance")
            self.assertEqual(receipt["outcome"], "policy_denied")
            self.assertFalse(receipt["raw_secret_egress"])
            self.assertNotIn("4242424242424242", rendered)
            self.assertNotIn("card_number", rendered)

    def test_bounded_renderer_rejects_secret_like_or_echoed_card_output(self):
        with self.assertRaisesRegex(ValueError, "secret-like material"):
            _render_bounded_json({"response": {"card_number": "4242424242424242"}})

        with self.assertRaisesRegex(ValueError, "submitted secret material"):
            _render_bounded_json(
                {"response": {"message": "Stripe Test User"}},
                forbidden_values=("Stripe Test User",),
            )

    def test_bounded_renderer_allows_explicit_public_chain_fields(self):
        rendered = _render_bounded_json(
            {
                "contract_address": "0x" + "12" * 20,
                "compose_hash": "0x" + "34" * 32,
                "amount_wei": "5000000000000000000",
                "max_amount_wei": "5000000000000000000",
                "raw_secret_egress": False,
            },
            public_hex_fields=("contract_address", "compose_hash"),
            public_decimal_fields=("amount_wei", "max_amount_wei"),
        )

        body = json.loads(rendered)
        self.assertEqual(body["amount_wei"], "5000000000000000000")
        self.assertFalse(body["raw_secret_egress"])

    def test_synthetic_private_reward_demo_cli_writes_bounded_packet(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "synthetic-reward.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "synthetic-private-reward-demo",
                    "--candidate",
                    "alpha",
                    "--candidate",
                    "beta",
                    "--output",
                    str(output_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=_env(tmpdir),
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            body = json.loads(output_path.read_text(encoding="utf-8"))
            rendered = json.dumps(body)
            self.assertEqual(body["demo"], "synthetic_hidden_keyword")
            self.assertEqual(body["submitted_candidate_count"], 2)
            self.assertFalse(body["raw_secret_egress"])
            self.assertNotIn("alpha", rendered)
            self.assertNotIn("beta", rendered)
            self.assertNotIn("sealed alpha", rendered)

    def test_bio_assay_qc_reward_demo_cli_writes_bounded_packet(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "bio-assay-qc-reward.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "bio-assay-qc-reward-demo",
                    "--output",
                    str(output_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                env=_env(tmpdir),
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            body = json.loads(output_path.read_text(encoding="utf-8"))
            rendered = json.dumps(body)
            self.assertEqual(body["demo"], "bio_assay_program_qc")
            self.assertEqual(body["submitted_candidate_count"], 3)
            self.assertFalse(body["raw_secret_egress"])
            # Sealed raw well readings (including the outliers) must not leak.
            self.assertNotIn("140.0", rendered)
            self.assertNotIn("100.5", rendered)


if __name__ == "__main__":
    unittest.main()
