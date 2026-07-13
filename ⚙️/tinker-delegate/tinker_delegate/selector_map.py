"""Bounded Tinker browser selector and frame contract.

The map is safe to print in logs or attach to deployment evidence: it records
declared selectors, expected frame matchers, and evidence status, but never live
page text, account identifiers, OTPs, cards, API keys, cookies, or browser URLs.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlparse, urlunparse
from urllib.request import urlopen

from playwright.async_api import async_playwright

from tinker_delegate.browser_ready import _cdp_probe_url, connect_chromium, get_browser_context
from tinker_delegate.billing import (
    ADD_BALANCE_AMOUNT_SELECTORS,
    ADD_BALANCE_CONFIRM_SELECTORS,
    ADD_BALANCE_DIALOG_SELECTORS,
    ADD_PAYMENT_METHOD_SELECTORS,
    ADD_TO_BALANCE_SELECTORS,
    ADDRESS_FIELD_SELECTORS,
    AUTO_RELOAD_AMOUNT_SELECTORS,
    AUTO_RELOAD_SAVE_SELECTORS,
    AUTO_RELOAD_THRESHOLD_SELECTORS,
    AUTO_RELOAD_TOGGLE_SELECTORS,
    BILLING_BALANCE_URL,
    CARDHOLDER_NAME_SELECTORS,
    PAYMENT_METHODS_SELECTORS,
    STRIPE_CARD_CVC_SELECTORS,
    STRIPE_CARD_EXPIRY_SELECTORS,
    STRIPE_CARD_NUMBER_SELECTORS,
    STRIPE_FRAME_MATCHERS,
)
from tinker_delegate.config import Settings
from tinker_delegate.signup import (
    API_KEY_CLOSE_SELECTORS,
    API_KEY_CONFIRM_SELECTORS,
    API_KEY_CREATE_SELECTORS,
    AUTH_EMAIL_SELECTORS,
    AUTH_FIRST_NAME_SELECTORS,
    AUTH_LAST_NAME_SELECTORS,
    AUTH_SIGNUP_LINK_SELECTORS,
    AUTH_SUBMIT_SELECTORS,
    ONBOARDING_CONTINUE_SELECTORS,
    ONBOARDING_FULL_NAME_SELECTORS,
    ONBOARDING_TOS_SELECTORS,
    OTP_INPUT_SELECTORS,
)

SELECTOR_MAP_VERSION = "2026-07-08.1"
DEPLOYED_SELECTOR_EVIDENCE_STATUS = "pending_deployed_cvm_capture"
PROBE_VERSION = "2026-07-08.1"
RAW_CDP_PROBE_VERSION = "2026-07-08.4"
COUNT_BAND_CAP = 2
MATCH_BANDS = {"0", "1", "2+", "probe_error"}


def _public_selector(selector: str) -> str:
    """Keep printable selector maps shape-only for card fields."""

    return selector.replace("card number", "[card-field]").replace("Card number", "[card-field]")


def _family(name: str, selectors: tuple[str, ...], *, required: bool = True) -> dict[str, Any]:
    return {
        "name": name,
        "required": required,
        "selector_count": len(selectors),
        "selectors": [_public_selector(selector) for selector in selectors],
    }


def _flow(name: str, *, evidence: str, families: list[dict[str, Any]], notes: list[str] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "evidence": evidence,
        "families": families,
        "notes": notes or [],
    }


def build_selector_map(*, include_selectors: bool = True) -> dict[str, Any]:
    """Return the bounded selector/frame map for current Tinker automation."""

    address_families = [
        _family(f"billing_{field}", selectors, required=field != "address_country")
        for field, selectors in ADDRESS_FIELD_SELECTORS
    ]
    flows = [
        _flow(
            "email_auth",
            evidence="local_neko_validated_phala_bounded_failure",
            families=[
                _family("email_input", AUTH_EMAIL_SELECTORS),
                _family("submit_email", AUTH_SUBMIT_SELECTORS),
                _family("signup_link", AUTH_SIGNUP_LINK_SELECTORS, required=False),
                _family("signup_first_name", AUTH_FIRST_NAME_SELECTORS, required=False),
                _family("signup_last_name", AUTH_LAST_NAME_SELECTORS, required=False),
            ],
            notes=[
                "Local Neko/CDP reached Tinker OTP auth.",
                "Latest Phala one-shot reached bounded tinker_auth failure without raw page evidence.",
            ],
        ),
        _flow(
            "magic_code_otp",
            evidence="local_neko_validated_oracle_otp",
            families=[
                _family("otp_inputs", OTP_INPUT_SELECTORS),
            ],
            notes=["OTP values are consumed through the email oracle and are not exposed by this map."],
        ),
        _flow(
            "onboarding",
            evidence="local_neko_validated",
            families=[
                _family("full_name", ONBOARDING_FULL_NAME_SELECTORS),
                _family("tos_label", ONBOARDING_TOS_SELECTORS, required=False),
                _family("continue", ONBOARDING_CONTINUE_SELECTORS),
            ],
        ),
        _flow(
            "api_keys",
            evidence="local_neko_validated_mock_replay_tested",
            families=[
                _family("create_key", API_KEY_CREATE_SELECTORS),
                _family("confirm_key_generation", API_KEY_CONFIRM_SELECTORS, required=False),
                _family("close_key_dialog", API_KEY_CLOSE_SELECTORS, required=False),
            ],
            notes=["Raw API keys are sealed by the signup path and represented only by hashes/status metadata."],
        ),
        _flow(
            "billing_payment_method",
            evidence="local_test_card_reached_stripe_submission_mock_replay_tested",
            families=[
                _family("open_add_balance", ADD_TO_BALANCE_SELECTORS, required=False),
                _family("payment_methods_tab", PAYMENT_METHODS_SELECTORS, required=False),
                _family("add_payment_method", ADD_PAYMENT_METHOD_SELECTORS),
                _family("cardholder_name", CARDHOLDER_NAME_SELECTORS),
                *address_families,
            ],
            notes=["Card details are intentionally absent; payment-method receipts are bounded."],
        ),
        _flow(
            "stripe_card_iframe",
            evidence="local_test_card_reached_stripe_submission_mock_replay_tested",
            families=[
                _family("stripe_frame_matchers", STRIPE_FRAME_MATCHERS),
                _family("stripe_card_number", STRIPE_CARD_NUMBER_SELECTORS),
                _family("stripe_card_expiry", STRIPE_CARD_EXPIRY_SELECTORS),
                _family("stripe_card_cvc", STRIPE_CARD_CVC_SELECTORS),
            ],
            notes=["Stripe iframe selectors are shape-only and contain no card data."],
        ),
        _flow(
            "balance_top_up",
            evidence="local_add_balance_policy_and_selector_mock_replay_tested",
            families=[
                _family("open_add_balance", ADD_TO_BALANCE_SELECTORS),
                _family("add_balance_dialog", ADD_BALANCE_DIALOG_SELECTORS, required=False),
                _family("add_balance_amount", ADD_BALANCE_AMOUNT_SELECTORS),
                _family("confirm_add_balance", ADD_BALANCE_CONFIRM_SELECTORS),
            ],
        ),
        _flow(
            "auto_reload",
            evidence="selector_declared_not_live_validated",
            families=[
                _family("auto_reload_toggle", AUTO_RELOAD_TOGGLE_SELECTORS),
                _family("auto_reload_threshold", AUTO_RELOAD_THRESHOLD_SELECTORS, required=False),
                _family("auto_reload_amount", AUTO_RELOAD_AMOUNT_SELECTORS, required=False),
                _family("auto_reload_save", AUTO_RELOAD_SAVE_SELECTORS, required=False),
            ],
            notes=["Auto-reload remains a declared selector surface; it has not been promoted to production funding."],
        ),
    ]
    payload: dict[str, Any] = {
        "version": SELECTOR_MAP_VERSION,
        "surface": "tinker_console_and_stripe_billing",
        "raw_secret_egress": False,
        "bounded_output": True,
        "deployed_cvm_selector_evidence": DEPLOYED_SELECTOR_EVIDENCE_STATUS,
        "urls": {
            "billing_balance": BILLING_BALANCE_URL,
            "auth": "https://auth.thinkingmachines.ai/",
            "console": "https://tinker-console.thinkingmachines.ai/",
            "api_keys": "https://tinker-console.thinkingmachines.ai/keys",
        },
        "flows": flows,
    }
    if not include_selectors:
        for flow in payload["flows"]:
            for family in flow["families"]:
                family.pop("selectors", None)
    payload["selector_map_hash"] = selector_map_hash(payload)
    return payload


def selector_map_hash(payload: dict[str, Any]) -> str:
    """Hash the map while excluding the self-referential hash field."""

    clone = {key: value for key, value in payload.items() if key != "selector_map_hash"}
    encoded = json.dumps(clone, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _count_band(count: int) -> str:
    if count <= 0:
        return "0"
    if count == 1:
        return "1"
    return f"{COUNT_BAND_CAP}+"


def _classify_url(url: str) -> str:
    """Return a coarse public route class without emitting the raw URL."""

    try:
        parsed = urlparse(url or "")
    except Exception:
        return "unknown"
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    if "auth.thinkingmachines.ai" in host:
        return "tinker_auth_magic_code" if "magic-code" in path else "tinker_auth"
    if "tinker-console.thinkingmachines.ai" in host:
        if "billing" in path:
            return "tinker_console_billing"
        if "keys" in path:
            return "tinker_console_keys"
        if "onboarding" in path:
            return "tinker_console_onboarding"
        return "tinker_console"
    if "stripe" in host:
        return "stripe"
    if not url:
        return "empty"
    return "other"


def _frame_kind(frame: Any) -> str:
    url = str(getattr(frame, "url", "") or "")
    name = str(getattr(frame, "name", "") or "")
    if "elements-inner-card" in url or "StripeFrame" in name:
        return "stripe_card"
    return _classify_url(url)


def _url_summary(url: str) -> dict[str, Any]:
    return {
        "url_class": _classify_url(url),
        "url_hash": _hash_text(url) if url else "",
    }


def _read_exact(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < length:
        chunk = sock.recv(length - total)
        if not chunk:
            raise ConnectionError("socket closed before enough bytes were read")
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _websocket_text_frame(payload: str) -> bytes:
    payload_bytes = payload.encode("utf-8")
    length = len(payload_bytes)
    if length > 65535:
        raise ValueError("payload too large")
    header = bytearray([0x81])
    if length < 126:
        header.append(0x80 | length)
    else:
        header.extend([0x80 | 126, (length >> 8) & 0xFF, length & 0xFF])
    mask = os.urandom(4)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload_bytes))
    return bytes(header) + mask + masked


def _read_websocket_text_frame(sock: socket.socket, max_payload: int = 65535) -> dict[str, Any]:
    first = _read_exact(sock, 2)
    opcode = first[0] & 0x0F
    masked = bool(first[1] & 0x80)
    length = first[1] & 0x7F
    if length == 126:
        extended = _read_exact(sock, 2)
        length = (extended[0] << 8) | extended[1]
    elif length == 127:
        extended = _read_exact(sock, 8)
        length = int.from_bytes(extended, "big")
    if length > max_payload:
        return {"received": True, "opcode": opcode, "too_large": True, "payload": b""}
    mask = _read_exact(sock, 4) if masked else b""
    payload = _read_exact(sock, length)
    if masked:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return {"received": True, "opcode": opcode, "too_large": False, "payload": payload}


def _read_http_headers(sock: socket.socket) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < 4096:
        chunk = sock.recv(512)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        joined = b"".join(chunks)
        if b"\r\n\r\n" in joined:
            return joined.split(b"\r\n\r\n", 1)[0]
    return b"".join(chunks)


def _parse_http_status(headers: str) -> int:
    first_line = headers.splitlines()[0] if headers.splitlines() else ""
    parts = first_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return 0


def _http_status_band(status_code: int) -> str:
    if status_code == 101:
        return "101"
    if 100 <= status_code <= 599:
        return f"{status_code // 100}xx"
    return "unknown"


def _cdp_list_url(cdp_url: str) -> str:
    probe_url = _cdp_probe_url(cdp_url)
    if probe_url.endswith("/json/version"):
        return probe_url[: -len("/json/version")] + "/json/list"
    return probe_url.rstrip("/") + "/json/list"


def _normalize_target_websocket_url(cdp_url: str, websocket_url: str) -> str:
    parsed_ws = urlparse(websocket_url)
    if parsed_ws.scheme not in {"ws", "wss"} or not parsed_ws.hostname:
        raise RuntimeError("unsupported_websocket_url")
    parsed_cdp = urlparse(cdp_url)
    if not parsed_cdp.netloc:
        raise RuntimeError("unsupported_websocket_url")
    host = parsed_ws.hostname.lower()
    if host in {"127.0.0.1", "localhost", "0.0.0.0", "::1"}:
        scheme = "wss" if parsed_cdp.scheme in {"wss", "https"} else "ws"
        return urlunparse((scheme, parsed_cdp.netloc, parsed_ws.path, "", parsed_ws.query, ""))
    return websocket_url


def _read_matching_cdp_response(
    sock: socket.socket,
    command_id: int,
    *,
    session_id: str = "",
    max_frames: int = 8,
) -> dict[str, Any]:
    saw_event = False
    runtime_event_count = 0
    saw_runtime_execution_context_created = False
    for _ in range(max_frames):
        frame = _read_websocket_text_frame(sock)
        if frame.get("too_large"):
            raise RuntimeError("response_too_large")
        opcode = int(frame.get("opcode") or 0)
        if opcode == 8:
            raise RuntimeError("websocket_closed")
        if opcode not in {1, 2}:
            raise RuntimeError("unexpected_websocket_frame")
        try:
            payload = json.loads(bytes(frame.get("payload") or b"").decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise RuntimeError("invalid_json") from exc
        if payload.get("id") == command_id and (not session_id or payload.get("sessionId") == session_id):
            payload["_saw_event_before_response"] = saw_event
            payload["_runtime_event_count_before_response"] = runtime_event_count
            payload["_saw_runtime_execution_context_created_before_response"] = (
                saw_runtime_execution_context_created
            )
            return payload
        if "method" in payload:
            method = str(payload.get("method") or "")
            if method.startswith("Runtime."):
                runtime_event_count += 1
            if method == "Runtime.executionContextCreated":
                saw_runtime_execution_context_created = True
            saw_event = True
            continue
    raise RuntimeError("missing_cdp_response")


class _RawCdpClient:
    def __init__(self, websocket_url: str, timeout_seconds: float):
        self.websocket_url = websocket_url
        self.timeout_seconds = timeout_seconds
        self.sock: socket.socket | None = None
        self.raw_sock: socket.socket | None = None
        self.wrapped_sock: socket.socket | None = None
        self.next_id = 1
        self.http_status_band = ""
        self.tls = False

    def __enter__(self) -> "_RawCdpClient":
        parsed = urlparse(self.websocket_url)
        if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
            raise RuntimeError("unsupported_websocket_url")
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        host_header = parsed.hostname if parsed.port is None else f"{parsed.hostname}:{port}"
        self.raw_sock = socket.create_connection((parsed.hostname, port), timeout=self.timeout_seconds)
        self.raw_sock.settimeout(self.timeout_seconds)
        if parsed.scheme == "wss":
            self.wrapped_sock = ssl.create_default_context().wrap_socket(
                self.raw_sock,
                server_hostname=parsed.hostname,
            )
            self.sock = self.wrapped_sock
            self.tls = True
        else:
            self.sock = self.raw_sock

        nonce = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {nonce}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self.sock.sendall(request.encode("ascii"))
        status_code = _parse_http_status(_read_http_headers(self.sock).decode("iso-8859-1", errors="replace"))
        self.http_status_band = _http_status_band(status_code)
        if status_code != 101:
            raise RuntimeError("upgrade_rejected" if status_code else "invalid_upgrade_response")
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        for sock in (self.wrapped_sock, self.raw_sock):
            if sock is None:
                continue
            try:
                sock.close()
            except OSError:
                pass
        return False

    def command(self, method: str, params: dict[str, Any] | None = None, *, session_id: str = "") -> dict[str, Any]:
        if self.sock is None:
            raise RuntimeError("not_connected")
        command_id = self.next_id
        self.next_id += 1
        payload: dict[str, Any] = {"id": command_id, "method": method}
        if params is not None:
            payload["params"] = params
        if session_id:
            payload["sessionId"] = session_id
        self.sock.sendall(_websocket_text_frame(json.dumps(payload, separators=(",", ":"))))
        return _read_matching_cdp_response(self.sock, command_id, session_id=session_id)


def _frame_tree_items(frame_tree: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def visit(node: dict[str, Any], depth: int) -> None:
        frame = node.get("frame") if isinstance(node, dict) else {}
        frame_url = str(frame.get("url") or "") if isinstance(frame, dict) else ""
        items.append(
            {
                "depth_band": "2+" if depth >= 2 else str(depth),
                "kind": "stripe_card" if "elements-inner-card" in frame_url else _classify_url(frame_url),
                **_url_summary(frame_url),
            }
        )
        for child in list(node.get("childFrames", []) or [])[:10]:
            if isinstance(child, dict):
                visit(child, depth + 1)

    visit(frame_tree, 0)
    return items


def _runtime_selector_matrix(selector_map: dict[str, Any]) -> list[list[list[str]]]:
    matrix: list[list[list[str]]] = []
    for flow in selector_map["flows"]:
        flow_selectors: list[list[str]] = []
        for family in flow["families"]:
            if family["name"] == "stripe_frame_matchers":
                continue
            flow_selectors.append(list(family.get("selectors", []) or []))
        matrix.append(flow_selectors)
    return matrix


def _runtime_selector_expression(selector_map: dict[str, Any]) -> str:
    selector_matrix = json.dumps(_runtime_selector_matrix(selector_map), separators=(",", ":"))
    return (
        "(() => {"
        f"const flows={selector_matrix};"
        "const cap=2;"
        "const band=(count)=>count<=0?'0':count===1?'1':'2+';"
        "return flows.map((families)=>families.map((selectors)=>{"
        "let total=0;"
        "for (const selector of selectors){"
        "try { total += document.querySelectorAll(selector).length; }"
        "catch (_) { continue; }"
        "if (total >= cap) return '2+';"
        "}"
        "return band(total);"
        "}));"
        "})()"
    )


def _runtime_micro_probe_expression() -> str:
    return "(() => 'dnai_runtime_ok')()"


def _runtime_selector_observations(value: Any, selector_map: dict[str, Any]) -> list[dict[str, Any]]:
    flow_observations: list[dict[str, Any]] = []
    matrix = value if isinstance(value, list) else []
    for flow_index, flow in enumerate(selector_map["flows"]):
        raw_flow = matrix[flow_index] if flow_index < len(matrix) and isinstance(matrix[flow_index], list) else []
        family_observations = []
        emitted_index = 0
        for family in flow["families"]:
            if family["name"] == "stripe_frame_matchers":
                continue
            raw_band = raw_flow[emitted_index] if emitted_index < len(raw_flow) else "probe_error"
            emitted_index += 1
            match_band = raw_band if isinstance(raw_band, str) and raw_band in MATCH_BANDS else "probe_error"
            family_observations.append(
                {
                    "name": family["name"],
                    "required": family["required"],
                    "match_band": match_band,
                }
            )
        present_required = sum(
            1
            for item in family_observations
            if item["required"] and item["match_band"] not in {"0", "probe_error"}
        )
        flow_observations.append(
            {
                "name": flow["name"],
                "present_required_families": present_required,
                "family_observations": family_observations,
            }
        )
    return flow_observations


def _runtime_evaluate_value(response: dict[str, Any]) -> Any:
    result = response.get("result", {})
    if not isinstance(result, dict):
        raise RuntimeError("missing_runtime_result")
    remote_object = result.get("result")
    if not isinstance(remote_object, dict):
        raise RuntimeError("missing_runtime_result")
    if remote_object.get("subtype") == "error" or "exceptionDetails" in result:
        raise RuntimeError("runtime_exception")
    if "value" not in remote_object:
        raise RuntimeError("missing_runtime_value")
    return remote_object["value"]


def _empty_direct_page_runtime_result() -> dict[str, Any]:
    return {
        "attempted": False,
        "page_list_success": False,
        "page_websocket_available": False,
        "page_enable_success": False,
        "page_enable_error_kind": "",
        "runtime_enable_success": False,
        "runtime_enable_error_kind": "",
        "runtime_event_before_enable_response": False,
        "runtime_event_count_band": "0",
        "runtime_execution_context_created": False,
        "runtime_micro_probe_success": False,
        "runtime_micro_probe_error_kind": "",
        "runtime_selector_success": False,
        "runtime_selector_error_kind": "",
        "flow_observations": [],
        "error_kind": "",
    }


def _probe_direct_page_runtime(
    settings: Settings,
    target_id: str,
    selector_map: dict[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    result = _empty_direct_page_runtime_result()
    result["attempted"] = True
    try:
        with urlopen(_cdp_list_url(settings.cdp_url), timeout=5) as response:
            targets = json.loads(response.read().decode("utf-8", errors="replace"))
    except Exception:
        result["error_kind"] = "page_list_unavailable"
        return result
    if not isinstance(targets, list):
        result["error_kind"] = "page_list_invalid"
        return result
    result["page_list_success"] = True
    page_target = next(
        (
            target
            for target in targets
            if isinstance(target, dict)
            and str(target.get("type") or "") == "page"
            and str(target.get("id") or target.get("targetId") or "") == target_id
        ),
        None,
    )
    if not isinstance(page_target, dict):
        result["error_kind"] = "page_target_not_found"
        return result
    websocket_url = str(page_target.get("webSocketDebuggerUrl") or "")
    if not websocket_url:
        result["error_kind"] = "missing_page_websocket_url"
        return result
    result["page_websocket_available"] = True
    try:
        normalized_websocket_url = _normalize_target_websocket_url(settings.cdp_url, websocket_url)
        with _RawCdpClient(normalized_websocket_url, timeout_seconds) as client:
            try:
                client.command("Page.enable")
            except Exception as exc:
                result["page_enable_error_kind"] = _raw_cdp_error_kind(exc)
                result["error_kind"] = f"page_enable_{result['page_enable_error_kind']}"
                return result
            result["page_enable_success"] = True
            try:
                runtime_enable_response = client.command("Runtime.enable")
            except Exception as exc:
                result["runtime_enable_error_kind"] = _raw_cdp_error_kind(exc)
                result["error_kind"] = f"runtime_enable_{result['runtime_enable_error_kind']}"
                return result
            result["runtime_enable_success"] = True
            result["runtime_event_before_enable_response"] = bool(
                runtime_enable_response.get("_saw_event_before_response")
            )
            result["runtime_event_count_band"] = _count_band(
                int(runtime_enable_response.get("_runtime_event_count_before_response") or 0)
            )
            result["runtime_execution_context_created"] = bool(
                runtime_enable_response.get("_saw_runtime_execution_context_created_before_response")
            )
            try:
                micro_probe_response = client.command(
                    "Runtime.evaluate",
                    {
                        "expression": _runtime_micro_probe_expression(),
                        "returnByValue": True,
                        "awaitPromise": False,
                        "silent": True,
                    },
                )
                micro_probe_value = _runtime_evaluate_value(micro_probe_response)
                if micro_probe_value != "dnai_runtime_ok":
                    raise RuntimeError("runtime_exception")
            except Exception as exc:
                result["runtime_micro_probe_error_kind"] = _raw_cdp_error_kind(exc)
                result["error_kind"] = f"runtime_micro_probe_{result['runtime_micro_probe_error_kind']}"
                return result
            result["runtime_micro_probe_success"] = True
            try:
                runtime_response = client.command(
                    "Runtime.evaluate",
                    {
                        "expression": _runtime_selector_expression(selector_map),
                        "returnByValue": True,
                        "awaitPromise": False,
                        "silent": True,
                    },
                )
                runtime_value = _runtime_evaluate_value(runtime_response)
            except Exception as exc:
                result["runtime_selector_error_kind"] = _raw_cdp_error_kind(exc)
                result["error_kind"] = f"runtime_selector_{result['runtime_selector_error_kind']}"
                return result
            result["runtime_selector_success"] = True
            result["flow_observations"] = _runtime_selector_observations(runtime_value, selector_map)
            return result
    except Exception as exc:
        result["error_kind"] = _raw_cdp_error_kind(exc)
        return result


def _raw_cdp_error_kind(exc: Exception) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionError):
        return "connection_closed"
    if isinstance(exc, RuntimeError):
        value = str(exc)
        allowed = {
            "response_too_large",
            "websocket_closed",
            "unexpected_websocket_frame",
            "invalid_json",
            "missing_cdp_response",
            "unsupported_websocket_url",
            "upgrade_rejected",
            "invalid_upgrade_response",
            "missing_runtime_result",
            "missing_runtime_value",
            "runtime_exception",
        }
        if value in allowed:
            return value
        if value:
            return "cdp_protocol_error"
    return "raw_cdp_probe_failed"


def _probe_raw_cdp_targets(settings: Settings) -> dict[str, Any]:
    result: dict[str, Any] = {
        "version": RAW_CDP_PROBE_VERSION,
        "surface": "tinker_console_and_stripe_billing",
        "raw_secret_egress": False,
        "bounded_output": True,
        "read_only": True,
        "probe_backend": "raw_cdp",
        "method": "raw_cdp_target_frame_inventory",
        "success": False,
        "attempted": bool(settings.cdp_url),
        "metadata_success": False,
        "upgrade_success": False,
        "target_command_success": False,
        "page_enable_command_success": False,
        "runtime_enable_command_success": False,
        "runtime_execution_context_event_observed": False,
        "direct_page_runtime_attempted": False,
        "direct_page_runtime_enable_success": False,
        "direct_page_runtime_micro_probe_success": False,
        "direct_page_runtime_selector_success": False,
        "runtime_micro_probe_command_success": False,
        "runtime_selector_command_success": False,
        "frame_tree_command_success": False,
        "http_status_band": "",
        "target_count_band": "0",
        "page_count_band": "0",
        "pages_observed": 0,
        "pages": [],
        "partial_error_kind": "",
        "error_kind": "not_configured" if not settings.cdp_url else "",
    }
    if not settings.cdp_url:
        return result

    try:
        with urlopen(_cdp_probe_url(settings.cdp_url), timeout=5) as response:
            metadata = json.loads(response.read().decode("utf-8", errors="replace"))
    except Exception:
        result["error_kind"] = "metadata_unavailable"
        return result

    result["metadata_success"] = True
    websocket_url = str(metadata.get("webSocketDebuggerUrl") or "")
    if not websocket_url:
        result["error_kind"] = "missing_websocket_debugger_url"
        return result

    timeout_seconds = max(0.1, min(float(settings.cdp_connect_timeout or 5.0), 10.0))
    try:
        with _RawCdpClient(websocket_url, timeout_seconds) as client:
            result["upgrade_success"] = True
            result["http_status_band"] = client.http_status_band
            targets_response = client.command("Target.getTargets")
            targets = list(targets_response.get("result", {}).get("targetInfos", []) or [])
            result["target_command_success"] = True
            result["target_count_band"] = _count_band(len(targets))
            selector_map = build_selector_map(include_selectors=True)
            result["selector_map_hash"] = selector_map["selector_map_hash"]
            page_targets = [
                target
                for target in targets
                if isinstance(target, dict) and str(target.get("type") or "") == "page"
            ]
            result["page_count_band"] = _count_band(len(page_targets))
            pages: list[dict[str, Any]] = []
            partial_errors: list[str] = []
            for page_index, target in enumerate(page_targets[:5]):
                target_url = str(target.get("url") or "")
                page_result: dict[str, Any] = {
                    "page_index": page_index,
                    **_url_summary(target_url),
                    "target_type": "page",
                    "attached": False,
                    "attach_error_kind": "",
                    "page_enable_success": False,
                    "page_enable_error_kind": "",
                    "runtime_enable_success": False,
                    "runtime_enable_error_kind": "",
                    "runtime_event_before_enable_response": False,
                    "runtime_event_count_band": "0",
                    "runtime_execution_context_created": False,
                    "direct_page_runtime": _empty_direct_page_runtime_result(),
                    "runtime_micro_probe_success": False,
                    "runtime_micro_probe_error_kind": "",
                    "runtime_selector_success": False,
                    "runtime_selector_error_kind": "",
                    "flow_observations": [],
                    "frame_tree_success": False,
                    "frame_tree_error_kind": "",
                    "frame_count_band": "0",
                    "frame_observations": [],
                }
                stop_after_page = False
                target_id = str(target.get("targetId") or "")
                if target_id:
                    try:
                        attach = client.command(
                            "Target.attachToTarget",
                            {"targetId": target_id, "flatten": True},
                        )
                        session_id = str(attach.get("result", {}).get("sessionId") or "")
                    except Exception as exc:
                        error_kind = _raw_cdp_error_kind(exc)
                        page_result["attach_error_kind"] = error_kind
                        partial_errors.append(f"attach_{error_kind}")
                        stop_after_page = True
                        session_id = ""
                    page_result["attached"] = bool(session_id)
                    if session_id:
                        try:
                            client.command("Page.enable", session_id=session_id)
                        except Exception as exc:
                            error_kind = _raw_cdp_error_kind(exc)
                            page_result["page_enable_error_kind"] = error_kind
                            partial_errors.append(f"page_enable_{error_kind}")
                            stop_after_page = True
                        else:
                            page_result["page_enable_success"] = True
                            result["page_enable_command_success"] = True
                        if stop_after_page:
                            direct_page_runtime = _probe_direct_page_runtime(
                                settings,
                                target_id,
                                selector_map,
                                timeout_seconds,
                            )
                            page_result["direct_page_runtime"] = direct_page_runtime
                            result["direct_page_runtime_attempted"] = bool(
                                result["direct_page_runtime_attempted"]
                                or direct_page_runtime["attempted"]
                            )
                            result["direct_page_runtime_enable_success"] = bool(
                                result["direct_page_runtime_enable_success"]
                                or direct_page_runtime["runtime_enable_success"]
                            )
                            result["direct_page_runtime_micro_probe_success"] = bool(
                                result["direct_page_runtime_micro_probe_success"]
                                or direct_page_runtime["runtime_micro_probe_success"]
                            )
                            result["direct_page_runtime_selector_success"] = bool(
                                result["direct_page_runtime_selector_success"]
                                or direct_page_runtime["runtime_selector_success"]
                            )
                        if not stop_after_page:
                            try:
                                runtime_enable_response = client.command("Runtime.enable", session_id=session_id)
                            except Exception as exc:
                                error_kind = _raw_cdp_error_kind(exc)
                                page_result["runtime_enable_error_kind"] = error_kind
                                partial_errors.append(f"runtime_enable_{error_kind}")
                                direct_page_runtime = _probe_direct_page_runtime(
                                    settings,
                                    target_id,
                                    selector_map,
                                    timeout_seconds,
                                )
                                page_result["direct_page_runtime"] = direct_page_runtime
                                result["direct_page_runtime_attempted"] = bool(
                                    result["direct_page_runtime_attempted"]
                                    or direct_page_runtime["attempted"]
                                )
                                result["direct_page_runtime_enable_success"] = bool(
                                    result["direct_page_runtime_enable_success"]
                                    or direct_page_runtime["runtime_enable_success"]
                                )
                                result["direct_page_runtime_micro_probe_success"] = bool(
                                    result["direct_page_runtime_micro_probe_success"]
                                    or direct_page_runtime["runtime_micro_probe_success"]
                                )
                                result["direct_page_runtime_selector_success"] = bool(
                                    result["direct_page_runtime_selector_success"]
                                    or direct_page_runtime["runtime_selector_success"]
                                )
                                stop_after_page = True
                            else:
                                page_result["runtime_enable_success"] = True
                                page_result["runtime_event_before_enable_response"] = bool(
                                    runtime_enable_response.get("_saw_event_before_response")
                                )
                                page_result["runtime_event_count_band"] = _count_band(
                                    int(
                                        runtime_enable_response.get(
                                            "_runtime_event_count_before_response"
                                        )
                                        or 0
                                    )
                                )
                                page_result["runtime_execution_context_created"] = bool(
                                    runtime_enable_response.get(
                                        "_saw_runtime_execution_context_created_before_response"
                                    )
                                )
                                result["runtime_enable_command_success"] = True
                                result["runtime_execution_context_event_observed"] = bool(
                                    result["runtime_execution_context_event_observed"]
                                    or page_result["runtime_execution_context_created"]
                                )
                        if not stop_after_page:
                            try:
                                micro_probe_response = client.command(
                                    "Runtime.evaluate",
                                    {
                                        "expression": _runtime_micro_probe_expression(),
                                        "returnByValue": True,
                                        "awaitPromise": False,
                                        "silent": True,
                                    },
                                    session_id=session_id,
                                )
                                micro_probe_value = _runtime_evaluate_value(micro_probe_response)
                                if micro_probe_value != "dnai_runtime_ok":
                                    raise RuntimeError("runtime_exception")
                            except Exception as exc:
                                error_kind = _raw_cdp_error_kind(exc)
                                page_result["runtime_micro_probe_error_kind"] = error_kind
                                partial_errors.append(f"runtime_micro_probe_{error_kind}")
                                stop_after_page = True
                            else:
                                page_result["runtime_micro_probe_success"] = True
                                result["runtime_micro_probe_command_success"] = True
                        if not stop_after_page:
                            try:
                                runtime_response = client.command(
                                    "Runtime.evaluate",
                                    {
                                        "expression": _runtime_selector_expression(selector_map),
                                        "returnByValue": True,
                                        "awaitPromise": False,
                                        "silent": True,
                                    },
                                    session_id=session_id,
                                )
                                runtime_value = _runtime_evaluate_value(runtime_response)
                            except Exception as exc:
                                error_kind = _raw_cdp_error_kind(exc)
                                page_result["runtime_selector_error_kind"] = error_kind
                                partial_errors.append(f"runtime_selector_{error_kind}")
                                stop_after_page = True
                            else:
                                page_result["runtime_selector_success"] = True
                                page_result["flow_observations"] = _runtime_selector_observations(
                                    runtime_value,
                                    selector_map,
                                )
                                result["runtime_selector_command_success"] = True
                        if not stop_after_page:
                            try:
                                frame_tree = client.command("Page.getFrameTree", session_id=session_id)
                                tree = frame_tree.get("result", {}).get("frameTree")
                            except Exception as exc:
                                error_kind = _raw_cdp_error_kind(exc)
                                page_result["frame_tree_error_kind"] = error_kind
                                partial_errors.append(f"frame_tree_{error_kind}")
                                stop_after_page = True
                            else:
                                if isinstance(tree, dict):
                                    observations = _frame_tree_items(tree)[:10]
                                    page_result["frame_tree_success"] = True
                                    page_result["frame_count_band"] = _count_band(len(observations))
                                    page_result["frame_observations"] = observations
                                    result["frame_tree_command_success"] = True
                                else:
                                    page_result["frame_tree_error_kind"] = "missing_frame_tree"
                                    partial_errors.append("frame_tree_missing_frame_tree")
                else:
                    page_result["attach_error_kind"] = "missing_target_id"
                    partial_errors.append("attach_missing_target_id")
                pages.append(page_result)
                if stop_after_page:
                    break
            if partial_errors:
                result["partial_error_kind"] = partial_errors[0]
            result["pages"] = pages
            result["pages_observed"] = len(pages)
    except socket.timeout:
        result["error_kind"] = "timeout"
        return result
    except RuntimeError as exc:
        result["error_kind"] = str(exc) or "cdp_protocol_error"
        return result
    except Exception:
        result["error_kind"] = "raw_cdp_probe_failed"
        return result

    result["success"] = bool(result["target_command_success"])
    result["error_kind"] = "" if result["success"] else "target_inventory_failed"
    return result


def _playwright_error_kind(exc: Exception) -> str:
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    message = str(exc).lower()
    if "timeout" in message or "timed out" in message:
        return "timeout"
    if "connect" in message:
        return "connect_failed"
    return "browser_unavailable"


async def _selector_count_band(scope: Any, selectors: list[str]) -> str:
    total = 0
    for selector in selectors:
        try:
            locator = scope.locator(selector)
            total += int(await locator.count())
        except Exception:
            return "probe_error"
        if total >= COUNT_BAND_CAP:
            return f"{COUNT_BAND_CAP}+"
    return _count_band(total)


async def probe_selector_map_context(context: Any, *, issued_at: int | None = None) -> dict[str, Any]:
    """Inspect current browser pages/frames without navigation or raw content egress."""

    selector_map = build_selector_map(include_selectors=True)
    pages = list(getattr(context, "pages", []) or [])
    page_results = []
    for page_index, page in enumerate(pages[:5]):
        page_url = str(getattr(page, "url", "") or "")
        page_result: dict[str, Any] = {
            "page_index": page_index,
            "url_class": _classify_url(page_url),
            "url_hash": _hash_text(page_url) if page_url else "",
            "flow_observations": [],
            "frame_observations": [],
        }
        for flow in selector_map["flows"]:
            family_observations = []
            for family in flow["families"]:
                if family["name"] == "stripe_frame_matchers":
                    continue
                family_observations.append(
                    {
                        "name": family["name"],
                        "required": family["required"],
                        "match_band": await _selector_count_band(page, family.get("selectors", [])),
                    }
                )
            present_required = sum(
                1
                for item in family_observations
                if item["required"] and item["match_band"] not in {"0", "probe_error"}
            )
            page_result["flow_observations"].append(
                {
                    "name": flow["name"],
                    "present_required_families": present_required,
                    "family_observations": family_observations,
                }
            )

        frames = list(getattr(page, "frames", []) or [])
        for frame_index, frame in enumerate(frames[:10]):
            frame_observation: dict[str, Any] = {
                "frame_index": frame_index,
                "kind": _frame_kind(frame),
                "url_class": _classify_url(str(getattr(frame, "url", "") or "")),
            }
            if frame_observation["kind"] == "stripe_card":
                frame_observation["stripe_field_observations"] = [
                    {
                        "name": "stripe_card_number",
                        "match_band": await _selector_count_band(frame, list(STRIPE_CARD_NUMBER_SELECTORS)),
                    },
                    {
                        "name": "stripe_card_expiry",
                        "match_band": await _selector_count_band(frame, list(STRIPE_CARD_EXPIRY_SELECTORS)),
                    },
                    {
                        "name": "stripe_card_cvc",
                        "match_band": await _selector_count_band(frame, list(STRIPE_CARD_CVC_SELECTORS)),
                    },
                ]
            page_result["frame_observations"].append(frame_observation)
        page_results.append(page_result)

    return {
        "version": PROBE_VERSION,
        "selector_map_hash": selector_map["selector_map_hash"],
        "surface": selector_map["surface"],
        "issued_at": int(issued_at if issued_at is not None else time.time()),
        "raw_secret_egress": False,
        "bounded_output": True,
        "read_only": True,
        "success": True,
        "page_count_band": _count_band(len(pages)),
        "pages_observed": len(page_results),
        "pages": page_results,
    }


async def probe_live_selector_map(settings: Settings | None = None) -> dict[str, Any]:
    """Connect to the configured browser and run a read-only bounded probe."""

    if settings is None:
        settings = Settings()
    try:
        async with async_playwright() as playwright:
            browser = await connect_chromium(playwright, settings)
            context = await get_browser_context(browser)
            result = await probe_selector_map_context(context)
            result["probe_backend"] = "playwright"
            return result
    except Exception as exc:
        raw_result = await asyncio.to_thread(_probe_raw_cdp_targets, settings)
        raw_result["fallback_from_backend"] = "playwright"
        raw_result["fallback_reason_kind"] = _playwright_error_kind(exc)
        return raw_result


def run_live_selector_map_probe(settings: Settings | None = None) -> dict[str, Any]:
    return asyncio.run(probe_live_selector_map(settings))
