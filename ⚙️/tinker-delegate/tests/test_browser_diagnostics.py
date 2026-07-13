import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.browser_diagnostics import (
    _http_probe_cdp,
    _probe_cdp_protocol_command,
    _probe_cdp_websocket_handshake,
    browser_readiness,
)
from tinker_delegate.config import Settings
from tinker_delegate.main import _render_bounded_json


class FakeResponse:
    def __init__(self, payload: dict):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self.payload


class FakeSocket:
    def __init__(self, response: bytes):
        self.response = response
        self.sent = b""
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, payload: bytes):
        self.sent += payload

    def recv(self, size: int) -> bytes:
        if not self.response:
            return b""
        chunk = self.response[:size]
        self.response = self.response[size:]
        return chunk

    def close(self):
        self.closed = True


class ChunkedFakeSocket:
    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks
        self.sent = b""
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, payload: bytes):
        self.sent += payload

    def recv(self, size: int) -> bytes:
        if not self.chunks:
            return b""
        chunk = self.chunks[0]
        if len(chunk) <= size:
            return self.chunks.pop(0)
        self.chunks[0] = chunk[size:]
        return chunk[:size]

    def close(self):
        self.closed = True


def server_text_frame(payload: dict) -> bytes:
    payload_bytes = json.dumps(payload).encode("utf-8")
    length = len(payload_bytes)
    if length < 126:
        return bytes([0x81, length]) + payload_bytes
    return bytes([0x81, 126, (length >> 8) & 0xFF, length & 0xFF]) + payload_bytes


class BrowserDiagnosticsTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.original_settings = api.settings

    def tearDown(self):
        api.settings = self.original_settings

    async def test_browser_readiness_no_config_is_bounded(self):
        result = await browser_readiness(
            Settings(browser_ws_endpoint="", cdp_url="", local_browser_fallback=False)
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["error_kind"], "browser_not_configured")
        self.assertFalse(result["raw_secret_egress"])
        self.assertTrue(result["bounded_output"])
        self.assertFalse(result["captures_page_text"])
        _render_bounded_json(result)

    def test_cdp_http_probe_hashes_raw_browser_urls(self):
        raw_cdp_url = "http://172.20.0.3:9223"
        raw_ws_url = "ws://172.20.0.3:9223/devtools/browser/raw-session-id"
        response = FakeResponse(
            {
                "Browser": "Chrome/120.0.0.0",
                "webSocketDebuggerUrl": raw_ws_url,
            }
        )

        with patch("tinker_delegate.browser_diagnostics.urlopen", return_value=response):
            result = _http_probe_cdp(Settings(cdp_url=raw_cdp_url))

        self.assertTrue(result["success"])
        self.assertEqual(result["browser_family"], "chromium")
        self.assertEqual(result["websocket_url_class"], "private_network")
        rendered = _render_bounded_json(result)
        self.assertNotIn(raw_cdp_url, rendered)
        self.assertNotIn(raw_ws_url, rendered)
        self.assertIn("websocket_url_hash", result)

    def test_cdp_websocket_handshake_is_bounded(self):
        raw_cdp_url = "http://172.20.0.3:9223"
        raw_ws_url = "ws://172.20.0.3:9223/devtools/browser/raw-session-id"
        response = FakeResponse({"webSocketDebuggerUrl": raw_ws_url})
        fake_socket = FakeSocket(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n\r\n"
        )

        with (
            patch("tinker_delegate.browser_diagnostics.urlopen", return_value=response),
            patch("tinker_delegate.browser_diagnostics.socket.create_connection", return_value=fake_socket),
        ):
            result = _probe_cdp_websocket_handshake(Settings(cdp_url=raw_cdp_url))

        self.assertTrue(result["success"])
        self.assertTrue(result["metadata_success"])
        self.assertTrue(result["tcp_connect"])
        self.assertTrue(result["upgrade_request_sent"])
        self.assertEqual(result["http_status_band"], "101")
        self.assertEqual(result["url_class"], "private_network")
        rendered = _render_bounded_json(result)
        self.assertNotIn(raw_cdp_url, rendered)
        self.assertNotIn(raw_ws_url, rendered)
        self.assertIn("url_hash", result)

    def test_cdp_websocket_handshake_rejects_are_bounded(self):
        raw_ws_url = "ws://172.20.0.3:9223/devtools/browser/raw-session-id"
        response = FakeResponse({"webSocketDebuggerUrl": raw_ws_url})
        fake_socket = FakeSocket(b"HTTP/1.1 403 Forbidden\r\n\r\n")

        with (
            patch("tinker_delegate.browser_diagnostics.urlopen", return_value=response),
            patch("tinker_delegate.browser_diagnostics.socket.create_connection", return_value=fake_socket),
        ):
            result = _probe_cdp_websocket_handshake(Settings(cdp_url="http://172.20.0.3:9223"))

        self.assertFalse(result["success"])
        self.assertEqual(result["error_kind"], "upgrade_rejected")
        self.assertEqual(result["http_status_band"], "4xx")
        rendered = _render_bounded_json(result)
        self.assertNotIn(raw_ws_url, rendered)

    def test_cdp_protocol_probe_sends_minimal_command_and_is_bounded(self):
        raw_cdp_url = "http://172.20.0.3:9223"
        raw_ws_url = "ws://172.20.0.3:9223/devtools/browser/raw-session-id"
        raw_product = "Chrome/123.0.0.0"
        raw_user_agent = "Mozilla/5.0 internal browser string"
        response = FakeResponse({"webSocketDebuggerUrl": raw_ws_url})
        fake_socket = ChunkedFakeSocket(
            [
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n\r\n",
                server_text_frame(
                    {
                        "id": 1,
                        "result": {
                            "product": raw_product,
                            "userAgent": raw_user_agent,
                        },
                    }
                ),
            ]
        )

        with (
            patch("tinker_delegate.browser_diagnostics.urlopen", return_value=response),
            patch("tinker_delegate.browser_diagnostics.socket.create_connection", return_value=fake_socket),
        ):
            result = _probe_cdp_protocol_command(Settings(cdp_url=raw_cdp_url))

        self.assertTrue(result["success"])
        self.assertTrue(result["metadata_success"])
        self.assertTrue(result["upgrade_success"])
        self.assertTrue(result["command_sent"])
        self.assertTrue(result["response_received"])
        self.assertTrue(result["response_json"])
        self.assertEqual(result["response_kind"], "result")
        self.assertEqual(result["browser_family"], "chromium")
        self.assertGreater(len(fake_socket.sent), 0)
        rendered = _render_bounded_json(result)
        self.assertNotIn(raw_cdp_url, rendered)
        self.assertNotIn(raw_ws_url, rendered)
        self.assertNotIn(raw_product, rendered)
        self.assertNotIn(raw_user_agent, rendered)

    def test_cdp_protocol_probe_error_response_is_bounded(self):
        raw_ws_url = "ws://172.20.0.3:9223/devtools/browser/raw-session-id"
        response = FakeResponse({"webSocketDebuggerUrl": raw_ws_url})
        fake_socket = ChunkedFakeSocket(
            [
                b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
                server_text_frame({"id": 1, "error": {"code": -32601, "message": "raw error text"}}),
            ]
        )

        with (
            patch("tinker_delegate.browser_diagnostics.urlopen", return_value=response),
            patch("tinker_delegate.browser_diagnostics.socket.create_connection", return_value=fake_socket),
        ):
            result = _probe_cdp_protocol_command(Settings(cdp_url="http://172.20.0.3:9223"))

        self.assertFalse(result["success"])
        self.assertTrue(result["response_json"])
        self.assertEqual(result["response_kind"], "error")
        self.assertEqual(result["error_kind"], "unexpected_cdp_response")
        rendered = _render_bounded_json(result)
        self.assertNotIn(raw_ws_url, rendered)
        self.assertNotIn("raw error text", rendered)

    def test_cdp_protocol_probe_tolerates_event_before_response(self):
        raw_ws_url = "ws://172.20.0.3:9223/devtools/browser/raw-session-id"
        response = FakeResponse({"webSocketDebuggerUrl": raw_ws_url})
        fake_socket = ChunkedFakeSocket(
            [
                b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
                server_text_frame({"method": "Target.targetInfoChanged", "params": {"ignored": True}}),
                server_text_frame({"id": 1, "result": {"product": "Chrome/123.0.0.0"}}),
            ]
        )

        with (
            patch("tinker_delegate.browser_diagnostics.urlopen", return_value=response),
            patch("tinker_delegate.browser_diagnostics.socket.create_connection", return_value=fake_socket),
        ):
            result = _probe_cdp_protocol_command(Settings(cdp_url="http://172.20.0.3:9223"))

        self.assertTrue(result["success"])
        self.assertEqual(result["response_kind"], "result")

    def test_browser_readiness_endpoint_disabled_by_default(self):
        api.settings = Settings(allow_browser_readiness_endpoint=False)
        client = TestClient(api.app)

        response = client.get("/browser/readiness")

        self.assertEqual(response.status_code, 403)
        self.assertIn("browser readiness endpoint is disabled", response.json()["detail"])

    def test_browser_readiness_endpoint_returns_bounded_probe(self):
        api.settings = Settings(allow_browser_readiness_endpoint=True)
        client = TestClient(api.app)
        bounded = {
            "surface": "browser_control_path",
            "raw_secret_egress": False,
            "bounded_output": True,
            "read_only": True,
            "success": False,
            "error_kind": "browser_not_configured",
        }

        async def fake_readiness(settings):
            return bounded

        with patch("tinker_delegate.browser_diagnostics.browser_readiness", new=fake_readiness):
            response = client.get("/browser/readiness")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), bounded)


if __name__ == "__main__":
    unittest.main()
