import asyncio
import json
import socket
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.config import Settings
from tinker_delegate.main import _render_bounded_json
from tinker_delegate.redaction import redact_text
from tinker_delegate.selector_map import (
    _probe_raw_cdp_targets,
    build_selector_map,
    probe_live_selector_map,
    probe_selector_map_context,
    selector_map_hash,
)


class FakeLocator:
    def __init__(self, count: int):
        self._count = count

    async def count(self):
        return self._count


class FakeScope:
    def __init__(self, *, url: str = "", name: str = "", counts: dict[str, int] | None = None):
        self.url = url
        self.name = name
        self._counts = counts or {}

    def locator(self, selector: str):
        return FakeLocator(self._counts.get(selector, 0))


class FakePage(FakeScope):
    def __init__(self, *, url: str, counts: dict[str, int], frames: list[FakeScope] | None = None):
        super().__init__(url=url, counts=counts)
        self.frames = frames or []


class FakeContext:
    def __init__(self, pages: list[FakePage]):
        self.pages = pages


class FakeResponse:
    def __init__(self, payload: dict):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self.payload


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


class TimeoutAfterChunksSocket(ChunkedFakeSocket):
    def recv(self, size: int) -> bytes:
        if not self.chunks:
            raise socket.timeout("timed out")
        return super().recv(size)


def server_text_frame(payload: dict) -> bytes:
    payload_bytes = json.dumps(payload).encode("utf-8")
    length = len(payload_bytes)
    if length < 126:
        return bytes([0x81, length]) + payload_bytes
    return bytes([0x81, 126, (length >> 8) & 0xFF, length & 0xFF]) + payload_bytes


def runtime_selector_matrix(*, api_key_create: str = "0", api_key_confirm: str = "0") -> list[list[str]]:
    return [
        ["0", "0", "0", "0", "0"],
        ["0"],
        ["0", "0", "0"],
        [api_key_create, api_key_confirm, "0"],
        ["0", "0", "0", "0", "0", "0", "0", "0"],
        ["0", "0", "0"],
        ["0", "0", "0", "0"],
        ["0", "0", "0", "0"],
    ]


class SelectorMapTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings

    def tearDown(self):
        api.settings = self.original_settings

    def test_selector_map_covers_required_tinker_and_billing_flows(self):
        selector_map = build_selector_map()
        flow_names = {flow["name"] for flow in selector_map["flows"]}

        self.assertEqual(selector_map["surface"], "tinker_console_and_stripe_billing")
        self.assertFalse(selector_map["raw_secret_egress"])
        self.assertEqual(selector_map["deployed_cvm_selector_evidence"], "pending_deployed_cvm_capture")
        self.assertTrue(
            {
                "email_auth",
                "magic_code_otp",
                "onboarding",
                "api_keys",
                "billing_payment_method",
                "stripe_card_iframe",
                "balance_top_up",
                "auto_reload",
            }.issubset(flow_names)
        )

    def test_selector_map_contains_no_secret_shaped_material(self):
        selector_map = build_selector_map()
        rendered = _render_bounded_json(selector_map)

        self.assertEqual(redact_text(rendered), rendered)
        self.assertNotIn("tml-", rendered)
        self.assertNotIn("one-time-code value", rendered)
        self.assertNotIn("card number", rendered.lower())

    def test_summary_mode_preserves_counts_without_selectors(self):
        selector_map = build_selector_map(include_selectors=False)

        for flow in selector_map["flows"]:
            for family in flow["families"]:
                self.assertIn("selector_count", family)
                self.assertNotIn("selectors", family)

    def test_selector_map_hash_is_recomputable(self):
        selector_map = build_selector_map()

        self.assertRegex(selector_map["selector_map_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(selector_map["selector_map_hash"], selector_map_hash(selector_map))

    def test_probe_reports_count_bands_without_raw_urls(self):
        async def run_probe():
            return await probe_selector_map_context(FakeContext([page]), issued_at=123)

        page = FakePage(
            url="https://tinker-console.thinkingmachines.ai/keys?session=secret",
            counts={
                '[data-testid="create-api-key"]': 1,
                'button:has-text("Generate key")': 1,
                'button:has-text("Done")': 3,
            },
            frames=[
                FakeScope(
                    url="https://js.stripe.com/elements-inner-card.html#private",
                    name="__privateStripeFrame123",
                    counts={
                        'input[name="cardnumber"]': 1,
                        'input[data-elements-stable-field-name="cardExpiry"]': 1,
                        'input[name="cvc"]': 1,
                    },
                )
            ],
        )

        result = asyncio.run(run_probe())
        rendered = _render_bounded_json(result)

        self.assertNotIn("session=secret", rendered)
        self.assertNotIn("elements-inner-card.html#private", rendered)
        self.assertEqual(redact_text(rendered), rendered)
        self.assertTrue(result["success"])
        self.assertEqual(result["page_count_band"], "1")
        self.assertEqual(result["pages"][0]["url_class"], "tinker_console_keys")
        self.assertEqual(result["pages"][0]["frame_observations"][0]["kind"], "stripe_card")
        api_flow = next(
            flow for flow in result["pages"][0]["flow_observations"] if flow["name"] == "api_keys"
        )
        create_family = next(
            family for family in api_flow["family_observations"] if family["name"] == "create_key"
        )
        close_family = next(
            family for family in api_flow["family_observations"] if family["name"] == "close_key_dialog"
        )
        self.assertEqual(create_family["match_band"], "1")
        self.assertEqual(close_family["match_band"], "2+")

    def test_selector_probe_endpoint_disabled_by_default(self):
        api.settings = Settings(allow_selector_probe_endpoint=False)
        client = TestClient(api.app)

        response = client.get("/browser/selector-probe")

        self.assertEqual(response.status_code, 403)
        self.assertIn("selector probe endpoint is disabled", response.json()["detail"])

    def test_selector_probe_endpoint_returns_bounded_probe(self):
        api.settings = Settings(allow_selector_probe_endpoint=True)
        client = TestClient(api.app)
        bounded = {
            "surface": "tinker_console_and_stripe_billing",
            "raw_secret_egress": False,
            "bounded_output": True,
            "read_only": True,
            "success": True,
            "pages": [],
        }

        async def fake_probe(settings):
            return bounded

        with patch("tinker_delegate.selector_map.probe_live_selector_map", new=fake_probe):
            response = client.get("/browser/selector-probe")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), bounded)

    def test_selector_probe_endpoint_fails_closed_when_browser_unavailable(self):
        api.settings = Settings(allow_selector_probe_endpoint=True)
        client = TestClient(api.app)

        async def failing_probe(settings):
            raise RuntimeError("browser_ws_endpoint=ws://secret unavailable for oracle@example.com")

        with patch("tinker_delegate.selector_map.probe_live_selector_map", new=failing_probe):
            response = client.get("/browser/selector-probe")

        self.assertEqual(response.status_code, 503)
        body = response.json()
        self.assertFalse(body["success"])
        self.assertEqual(body["error_kind"], "browser_unavailable")
        self.assertFalse(body["raw_secret_egress"])
        self.assertNotIn("oracle@example.com", repr(body))
        self.assertNotIn("ws://secret", repr(body))

    def test_raw_cdp_target_frame_probe_is_bounded(self):
        raw_cdp_url = "http://172.20.0.3:9223"
        raw_ws_url = "ws://172.20.0.3:9223/devtools/browser/raw-session-id"
        raw_page_url = "https://tinker-console.thinkingmachines.ai/keys?session=secret"
        raw_frame_url = "https://js.stripe.com/elements-inner-card.html#private"
        response = FakeResponse({"webSocketDebuggerUrl": raw_ws_url})
        fake_socket = ChunkedFakeSocket(
            [
                b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
                server_text_frame(
                    {
                        "id": 1,
                        "result": {
                            "targetInfos": [
                                {"targetId": "page-1", "type": "page", "url": raw_page_url},
                                {"targetId": "worker-1", "type": "worker", "url": ""},
                            ]
                        },
                    }
                ),
                server_text_frame({"id": 2, "result": {"sessionId": "session-1"}}),
                server_text_frame({"id": 3, "sessionId": "session-1", "result": {}}),
                server_text_frame(
                    {
                        "sessionId": "session-1",
                        "method": "Runtime.executionContextCreated",
                        "params": {"context": {"id": 42, "origin": "https://secret.example"}},
                    }
                ),
                server_text_frame(
                    {
                        "id": 4,
                        "sessionId": "session-1",
                        "result": {},
                    }
                ),
                server_text_frame(
                    {
                        "id": 5,
                        "sessionId": "session-1",
                        "result": {"result": {"type": "string", "value": "dnai_runtime_ok"}},
                    }
                ),
                server_text_frame(
                    {
                        "id": 6,
                        "sessionId": "session-1",
                        "result": {
                            "result": {
                                "type": "object",
                                "value": runtime_selector_matrix(
                                    api_key_create="1",
                                    api_key_confirm="2+",
                                ),
                            }
                        },
                    }
                ),
                server_text_frame(
                    {
                        "id": 7,
                        "sessionId": "session-1",
                        "result": {
                            "frameTree": {
                                "frame": {"url": raw_page_url},
                                "childFrames": [{"frame": {"url": raw_frame_url}}],
                            }
                        },
                    }
                ),
            ]
        )

        with (
            patch("tinker_delegate.selector_map.urlopen", return_value=response),
            patch("tinker_delegate.selector_map.socket.create_connection", return_value=fake_socket),
        ):
            result = _probe_raw_cdp_targets(Settings(cdp_url=raw_cdp_url))

        self.assertTrue(result["success"])
        self.assertTrue(result["metadata_success"])
        self.assertTrue(result["upgrade_success"])
        self.assertTrue(result["target_command_success"])
        self.assertTrue(result["page_enable_command_success"])
        self.assertTrue(result["runtime_enable_command_success"])
        self.assertTrue(result["runtime_execution_context_event_observed"])
        self.assertTrue(result["runtime_micro_probe_command_success"])
        self.assertTrue(result["runtime_selector_command_success"])
        self.assertTrue(result["frame_tree_command_success"])
        self.assertEqual(result["probe_backend"], "raw_cdp")
        self.assertEqual(result["method"], "raw_cdp_target_frame_inventory")
        self.assertEqual(result["pages"][0]["url_class"], "tinker_console_keys")
        self.assertTrue(result["pages"][0]["page_enable_success"])
        self.assertEqual(result["pages"][0]["page_enable_error_kind"], "")
        self.assertTrue(result["pages"][0]["runtime_enable_success"])
        self.assertEqual(result["pages"][0]["runtime_enable_error_kind"], "")
        self.assertTrue(result["pages"][0]["runtime_event_before_enable_response"])
        self.assertEqual(result["pages"][0]["runtime_event_count_band"], "1")
        self.assertTrue(result["pages"][0]["runtime_execution_context_created"])
        self.assertTrue(result["pages"][0]["runtime_micro_probe_success"])
        self.assertTrue(result["pages"][0]["runtime_selector_success"])
        api_flow = next(
            flow for flow in result["pages"][0]["flow_observations"] if flow["name"] == "api_keys"
        )
        create_family = next(
            family for family in api_flow["family_observations"] if family["name"] == "create_key"
        )
        confirm_family = next(
            family for family in api_flow["family_observations"] if family["name"] == "confirm_key_generation"
        )
        self.assertEqual(create_family["match_band"], "1")
        self.assertEqual(confirm_family["match_band"], "2+")
        self.assertEqual(result["pages"][0]["frame_observations"][1]["kind"], "stripe_card")
        rendered = _render_bounded_json(result)
        self.assertNotIn(raw_cdp_url, rendered)
        self.assertNotIn(raw_ws_url, rendered)
        self.assertNotIn("session=secret", rendered)
        self.assertNotIn("elements-inner-card.html#private", rendered)
        self.assertEqual(redact_text(rendered), rendered)

    def test_raw_cdp_preserves_page_inventory_when_frame_tree_times_out(self):
        raw_cdp_url = "http://172.20.0.3:9223"
        raw_ws_url = "ws://172.20.0.3:9223/devtools/browser/raw-session-id"
        raw_page_url = "https://tinker-console.thinkingmachines.ai/keys?session=secret"
        response = FakeResponse({"webSocketDebuggerUrl": raw_ws_url})
        fake_socket = TimeoutAfterChunksSocket(
            [
                b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
                server_text_frame(
                    {
                        "id": 1,
                        "result": {
                            "targetInfos": [
                                {"targetId": "page-1", "type": "page", "url": raw_page_url},
                                {"targetId": "worker-1", "type": "worker", "url": ""},
                            ]
                        },
                    }
                ),
                server_text_frame({"id": 2, "result": {"sessionId": "session-1"}}),
                server_text_frame({"id": 3, "sessionId": "session-1", "result": {}}),
                server_text_frame(
                    {
                        "id": 4,
                        "sessionId": "session-1",
                        "result": {},
                    }
                ),
                server_text_frame(
                    {
                        "id": 5,
                        "sessionId": "session-1",
                        "result": {"result": {"type": "string", "value": "dnai_runtime_ok"}},
                    }
                ),
                server_text_frame(
                    {
                        "id": 6,
                        "sessionId": "session-1",
                        "result": {
                            "result": {
                                "type": "object",
                                "value": runtime_selector_matrix(api_key_create="1"),
                            }
                        },
                    }
                ),
            ]
        )

        with (
            patch("tinker_delegate.selector_map.urlopen", return_value=response),
            patch("tinker_delegate.selector_map.socket.create_connection", return_value=fake_socket),
        ):
            result = _probe_raw_cdp_targets(Settings(cdp_url=raw_cdp_url))

        self.assertTrue(result["success"])
        self.assertTrue(result["target_command_success"])
        self.assertTrue(result["page_enable_command_success"])
        self.assertTrue(result["runtime_enable_command_success"])
        self.assertTrue(result["runtime_micro_probe_command_success"])
        self.assertTrue(result["runtime_selector_command_success"])
        self.assertFalse(result["frame_tree_command_success"])
        self.assertEqual(result["partial_error_kind"], "frame_tree_timeout")
        self.assertEqual(result["target_count_band"], "2+")
        self.assertEqual(result["page_count_band"], "1")
        self.assertEqual(result["pages_observed"], 1)
        self.assertEqual(result["pages"][0]["url_class"], "tinker_console_keys")
        self.assertTrue(result["pages"][0]["attached"])
        self.assertTrue(result["pages"][0]["page_enable_success"])
        self.assertTrue(result["pages"][0]["runtime_enable_success"])
        self.assertEqual(result["pages"][0]["runtime_event_count_band"], "0")
        self.assertTrue(result["pages"][0]["runtime_micro_probe_success"])
        self.assertTrue(result["pages"][0]["runtime_selector_success"])
        api_flow = next(
            flow for flow in result["pages"][0]["flow_observations"] if flow["name"] == "api_keys"
        )
        create_family = next(
            family for family in api_flow["family_observations"] if family["name"] == "create_key"
        )
        self.assertEqual(create_family["match_band"], "1")
        self.assertFalse(result["pages"][0]["frame_tree_success"])
        self.assertEqual(result["pages"][0]["frame_tree_error_kind"], "timeout")
        self.assertEqual(result["pages"][0]["frame_count_band"], "0")
        self.assertEqual(result["pages"][0]["frame_observations"], [])
        rendered = _render_bounded_json(result)
        self.assertNotIn(raw_cdp_url, rendered)
        self.assertNotIn(raw_ws_url, rendered)
        self.assertNotIn("session=secret", rendered)
        self.assertEqual(redact_text(rendered), rendered)

    def test_raw_cdp_preserves_runtime_micro_probe_when_selector_runtime_times_out(self):
        raw_cdp_url = "http://172.20.0.3:9223"
        raw_ws_url = "ws://172.20.0.3:9223/devtools/browser/raw-session-id"
        raw_page_url = "https://tinker-console.thinkingmachines.ai/keys?session=secret"
        response = FakeResponse({"webSocketDebuggerUrl": raw_ws_url})
        fake_socket = TimeoutAfterChunksSocket(
            [
                b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
                server_text_frame(
                    {
                        "id": 1,
                        "result": {
                            "targetInfos": [
                                {"targetId": "page-1", "type": "page", "url": raw_page_url},
                                {"targetId": "worker-1", "type": "worker", "url": ""},
                            ]
                        },
                    }
                ),
                server_text_frame({"id": 2, "result": {"sessionId": "session-1"}}),
                server_text_frame({"id": 3, "sessionId": "session-1", "result": {}}),
                server_text_frame(
                    {
                        "id": 4,
                        "sessionId": "session-1",
                        "result": {},
                    }
                ),
                server_text_frame(
                    {
                        "id": 5,
                        "sessionId": "session-1",
                        "result": {"result": {"type": "string", "value": "dnai_runtime_ok"}},
                    }
                ),
            ]
        )

        with (
            patch("tinker_delegate.selector_map.urlopen", return_value=response),
            patch("tinker_delegate.selector_map.socket.create_connection", return_value=fake_socket),
        ):
            result = _probe_raw_cdp_targets(Settings(cdp_url=raw_cdp_url))

        self.assertTrue(result["success"])
        self.assertTrue(result["page_enable_command_success"])
        self.assertTrue(result["runtime_enable_command_success"])
        self.assertTrue(result["runtime_micro_probe_command_success"])
        self.assertFalse(result["runtime_selector_command_success"])
        self.assertEqual(result["partial_error_kind"], "runtime_selector_timeout")
        self.assertEqual(result["pages_observed"], 1)
        page = result["pages"][0]
        self.assertEqual(page["url_class"], "tinker_console_keys")
        self.assertTrue(page["attached"])
        self.assertTrue(page["page_enable_success"])
        self.assertTrue(page["runtime_enable_success"])
        self.assertTrue(page["runtime_micro_probe_success"])
        self.assertEqual(page["runtime_micro_probe_error_kind"], "")
        self.assertFalse(page["runtime_selector_success"])
        self.assertEqual(page["runtime_selector_error_kind"], "timeout")
        self.assertEqual(page["flow_observations"], [])
        self.assertFalse(page["frame_tree_success"])
        self.assertEqual(page["frame_observations"], [])
        rendered = _render_bounded_json(result)
        self.assertNotIn(raw_cdp_url, rendered)
        self.assertNotIn(raw_ws_url, rendered)
        self.assertNotIn("session=secret", rendered)
        self.assertEqual(redact_text(rendered), rendered)

    def test_raw_cdp_preserves_runtime_enable_timeout_before_micro_probe(self):
        raw_cdp_url = "http://172.20.0.3:9223"
        raw_ws_url = "ws://172.20.0.3:9223/devtools/browser/raw-session-id"
        raw_page_url = "https://tinker-console.thinkingmachines.ai/keys?session=secret"
        response = FakeResponse({"webSocketDebuggerUrl": raw_ws_url})
        fake_socket = TimeoutAfterChunksSocket(
            [
                b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
                server_text_frame(
                    {
                        "id": 1,
                        "result": {
                            "targetInfos": [
                                {"targetId": "page-1", "type": "page", "url": raw_page_url},
                            ]
                        },
                    }
                ),
                server_text_frame({"id": 2, "result": {"sessionId": "session-1"}}),
                server_text_frame({"id": 3, "sessionId": "session-1", "result": {}}),
            ]
        )

        with (
            patch("tinker_delegate.selector_map.urlopen", return_value=response),
            patch("tinker_delegate.selector_map.socket.create_connection", return_value=fake_socket),
        ):
            result = _probe_raw_cdp_targets(Settings(cdp_url=raw_cdp_url))

        self.assertTrue(result["success"])
        self.assertTrue(result["page_enable_command_success"])
        self.assertFalse(result["runtime_enable_command_success"])
        self.assertFalse(result["runtime_execution_context_event_observed"])
        self.assertFalse(result["runtime_micro_probe_command_success"])
        self.assertFalse(result["runtime_selector_command_success"])
        self.assertEqual(result["partial_error_kind"], "runtime_enable_timeout")
        page = result["pages"][0]
        self.assertTrue(page["attached"])
        self.assertTrue(page["page_enable_success"])
        self.assertEqual(page["page_enable_error_kind"], "")
        self.assertFalse(page["runtime_enable_success"])
        self.assertEqual(page["runtime_enable_error_kind"], "timeout")
        self.assertFalse(page["runtime_event_before_enable_response"])
        self.assertEqual(page["runtime_event_count_band"], "0")
        self.assertFalse(page["runtime_execution_context_created"])
        self.assertFalse(page["runtime_micro_probe_success"])
        self.assertEqual(page["flow_observations"], [])
        rendered = _render_bounded_json(result)
        self.assertNotIn(raw_cdp_url, rendered)
        self.assertNotIn(raw_ws_url, rendered)
        self.assertNotIn("session=secret", rendered)
        self.assertNotIn("origin", rendered)
        self.assertEqual(redact_text(rendered), rendered)

    def test_raw_cdp_tries_direct_page_runtime_when_attached_session_times_out(self):
        raw_cdp_url = "http://172.20.0.3:9223"
        raw_browser_ws_url = "ws://172.20.0.3:9223/devtools/browser/raw-session-id"
        raw_page_ws_url = "ws://127.0.0.1:9222/devtools/page/raw-page-session"
        raw_page_url = "https://tinker-console.thinkingmachines.ai/keys?session=secret"
        metadata_response = FakeResponse({"webSocketDebuggerUrl": raw_browser_ws_url})
        target_list_response = FakeResponse(
            [
                {
                    "id": "page-1",
                    "type": "page",
                    "url": raw_page_url,
                    "webSocketDebuggerUrl": raw_page_ws_url,
                }
            ]
        )
        browser_socket = TimeoutAfterChunksSocket(
            [
                b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
                server_text_frame(
                    {
                        "id": 1,
                        "result": {
                            "targetInfos": [
                                {"targetId": "page-1", "type": "page", "url": raw_page_url},
                            ]
                        },
                    }
                ),
                server_text_frame({"id": 2, "result": {"sessionId": "session-1"}}),
                server_text_frame({"id": 3, "sessionId": "session-1", "result": {}}),
            ]
        )
        direct_page_socket = ChunkedFakeSocket(
            [
                b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
                server_text_frame({"id": 1, "result": {}}),
                server_text_frame(
                    {
                        "method": "Runtime.executionContextCreated",
                        "params": {"context": {"id": 7, "origin": "https://secret.example"}},
                    }
                ),
                server_text_frame({"id": 2, "result": {}}),
                server_text_frame(
                    {
                        "id": 3,
                        "result": {"result": {"type": "string", "value": "dnai_runtime_ok"}},
                    }
                ),
                server_text_frame(
                    {
                        "id": 4,
                        "result": {
                            "result": {
                                "type": "object",
                                "value": runtime_selector_matrix(api_key_create="1"),
                            }
                        },
                    }
                ),
            ]
        )

        with (
            patch(
                "tinker_delegate.selector_map.urlopen",
                side_effect=[metadata_response, target_list_response],
            ),
            patch(
                "tinker_delegate.selector_map.socket.create_connection",
                side_effect=[browser_socket, direct_page_socket],
            ),
        ):
            result = _probe_raw_cdp_targets(Settings(cdp_url=raw_cdp_url))

        self.assertTrue(result["success"])
        self.assertTrue(result["page_enable_command_success"])
        self.assertFalse(result["runtime_enable_command_success"])
        self.assertTrue(result["direct_page_runtime_attempted"])
        self.assertTrue(result["direct_page_runtime_enable_success"])
        self.assertTrue(result["direct_page_runtime_micro_probe_success"])
        self.assertTrue(result["direct_page_runtime_selector_success"])
        self.assertEqual(result["partial_error_kind"], "runtime_enable_timeout")
        page = result["pages"][0]
        direct = page["direct_page_runtime"]
        self.assertTrue(direct["page_list_success"])
        self.assertTrue(direct["page_websocket_available"])
        self.assertTrue(direct["page_enable_success"])
        self.assertEqual(direct["page_enable_error_kind"], "")
        self.assertTrue(direct["runtime_enable_success"])
        self.assertTrue(direct["runtime_event_before_enable_response"])
        self.assertEqual(direct["runtime_event_count_band"], "1")
        self.assertTrue(direct["runtime_execution_context_created"])
        self.assertTrue(direct["runtime_micro_probe_success"])
        self.assertTrue(direct["runtime_selector_success"])
        api_flow = next(flow for flow in direct["flow_observations"] if flow["name"] == "api_keys")
        create_family = next(
            family for family in api_flow["family_observations"] if family["name"] == "create_key"
        )
        self.assertEqual(create_family["match_band"], "1")
        rendered = _render_bounded_json(result)
        self.assertNotIn(raw_cdp_url, rendered)
        self.assertNotIn(raw_browser_ws_url, rendered)
        self.assertNotIn(raw_page_ws_url, rendered)
        self.assertNotIn("session=secret", rendered)
        self.assertNotIn("secret.example", rendered)
        self.assertEqual(redact_text(rendered), rendered)

    def test_live_selector_probe_falls_back_to_raw_cdp(self):
        async def failing_context(_playwright, _settings):
            raise RuntimeError("playwright cdp timeout")

        fallback = {
            "surface": "tinker_console_and_stripe_billing",
            "raw_secret_egress": False,
            "bounded_output": True,
            "read_only": True,
            "method": "raw_cdp_target_frame_inventory",
            "success": True,
            "pages": [],
        }

        with (
            patch("tinker_delegate.selector_map.connect_chromium", new=failing_context),
            patch("tinker_delegate.selector_map._probe_raw_cdp_targets", return_value=fallback),
        ):
            result = asyncio.run(probe_live_selector_map(Settings(cdp_url="http://172.20.0.3:9223")))

        self.assertTrue(result["success"])
        self.assertEqual(result["method"], "raw_cdp_target_frame_inventory")

    def test_live_selector_probe_returns_bounded_raw_cdp_failure(self):
        async def failing_context(_playwright, _settings):
            raise RuntimeError("playwright cdp timeout ws://secret")

        fallback = {
            "surface": "tinker_console_and_stripe_billing",
            "raw_secret_egress": False,
            "bounded_output": True,
            "read_only": True,
            "probe_backend": "raw_cdp",
            "method": "raw_cdp_target_frame_inventory",
            "success": False,
            "error_kind": "metadata_unavailable",
            "pages": [],
        }

        with (
            patch("tinker_delegate.selector_map.connect_chromium", new=failing_context),
            patch("tinker_delegate.selector_map._probe_raw_cdp_targets", return_value=fallback),
        ):
            result = asyncio.run(probe_live_selector_map(Settings(cdp_url="http://172.20.0.3:9223")))

        self.assertFalse(result["success"])
        self.assertEqual(result["probe_backend"], "raw_cdp")
        self.assertEqual(result["error_kind"], "metadata_unavailable")
        self.assertEqual(result["fallback_from_backend"], "playwright")
        self.assertEqual(result["fallback_reason_kind"], "timeout")
        rendered = _render_bounded_json(result)
        self.assertNotIn("ws://secret", rendered)
        self.assertEqual(redact_text(rendered), rendered)


if __name__ == "__main__":
    unittest.main()
