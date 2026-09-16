import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.chain_watcher import (
    ChainEventDispatcher,
    ChainCursorStore,
    ChainCursorState,
    ChainWatcher,
    EVENT_SIGNATURES,
    JsonRpcLogSource,
    decode_diligence_room_log,
    event_topic,
)
from tinker_delegate.config import Settings


SELLER = "0x1111111111111111111111111111111111111111"
BUYER = "0x2222222222222222222222222222222222222222"
TEE = "0x3333333333333333333333333333333333333333"
TOKEN = "0x5555555555555555555555555555555555555555"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
EVALUATOR_POLICY_COMMITMENT = "0x" + "66" * 32


def _word(value: int) -> str:
    return f"{value:064x}"


def _word_bytes(value: str) -> str:
    raw = value[2:] if value.startswith("0x") else value
    return raw.rjust(64, "0").lower()


def _word_address(value: str) -> str:
    raw = value[2:] if value.startswith("0x") else value
    return raw.rjust(64, "0").lower()


def _topic_uint(value: int) -> str:
    return "0x" + _word(value)


def _topic_address(value: str) -> str:
    return "0x" + _word_address(value)


def _log(
    name: str,
    deal_id: int,
    data_words: list[str],
    *,
    indexed_addresses: list[str] | None = None,
    block: int = 10,
    index: int = 0,
) -> dict:
    return {
        "address": "0x4444444444444444444444444444444444444444",
        "topics": [
            event_topic(name),
            _topic_uint(deal_id),
            *[_topic_address(address) for address in indexed_addresses or []],
        ],
        "data": "0x" + "".join(data_words),
        "blockNumber": hex(block),
        "transactionHash": "0x" + f"{index + 1:064x}",
        "logIndex": hex(index),
    }


def _created_log(
    deal_id: int = 7,
    *,
    payment_token: str = ZERO_ADDRESS,
    block: int = 10,
    index: int = 0,
) -> dict:
    return _log(
        "DealCreated",
        deal_id,
        [
            _word(10**15),
            _word(1783502000),
            _word_bytes("0x" + "ab" * 32),
            _word_address(TEE),
            _word_address(payment_token),
        ],
        indexed_addresses=[SELLER],
        block=block,
        index=index,
    )


def _funded_log(
    deal_id: int = 7,
    *,
    payment_token: str = ZERO_ADDRESS,
    evaluator_policy_commitment: str = EVALUATOR_POLICY_COMMITMENT,
    block: int = 11,
    index: int = 0,
) -> dict:
    return _log(
        "DealFunded",
        deal_id,
        [
            _word(10**18),
            _word_address(payment_token),
            _word_bytes(evaluator_policy_commitment),
        ],
        indexed_addresses=[BUYER],
        block=block,
        index=index,
    )


class ChainWatcherDecodeTest(unittest.TestCase):
    def test_event_signatures_match_current_contract_abi(self):
        self.assertEqual(
            EVENT_SIGNATURES["DealCreated"],
            "DealCreated(uint256,address,uint256,uint256,bytes32,address,address)",
        )
        self.assertEqual(
            EVENT_SIGNATURES["DealFunded"],
            "DealFunded(uint256,address,uint256,address,bytes32)",
        )

    def test_decodes_deal_created_static_abi_log(self):
        event = decode_diligence_room_log(_created_log())

        self.assertIsNotNone(event)
        self.assertEqual(event.name, "DealCreated")
        self.assertEqual(event.deal_id, "7")
        self.assertEqual(event.fields["seller"], SELLER)
        self.assertEqual(event.fields["reserve_price"], 10**15)
        self.assertEqual(event.fields["artifact_hash"], "0x" + "ab" * 32)
        self.assertEqual(event.fields["tee_identity"], TEE)
        self.assertEqual(event.fields["payment_token"], ZERO_ADDRESS)

    def test_decodes_erc20_payment_token_from_created_and_funded_logs(self):
        created = decode_diligence_room_log(_created_log(payment_token=TOKEN))
        funded = decode_diligence_room_log(_funded_log(payment_token=TOKEN))

        self.assertEqual(created.fields["payment_token"], TOKEN)
        self.assertEqual(funded.fields["payment_token"], TOKEN)
        self.assertEqual(
            funded.fields["evaluator_policy_commitment"],
            EVALUATOR_POLICY_COMMITMENT,
        )

    def test_decodes_evaluation_and_resolution_events(self):
        evaluation = decode_diligence_room_log(
            _log(
                "EvaluationSubmitted",
                7,
                [_word(3), _word(10**12), _word_bytes("0x" + "cd" * 32)],
                block=12,
                index=0,
            )
        )
        accepted = decode_diligence_room_log(
            _log("DealAccepted", 7, [_word(10**15), _word(10**12), _word(9 * 10**17)], block=13)
        )

        self.assertEqual(evaluation.fields["score_band"], "high")
        self.assertEqual(evaluation.fields["compute_cost"], 10**12)
        self.assertEqual(evaluation.fields["result_hash"], "0x" + "cd" * 32)
        self.assertEqual(accepted.fields["seller_payment"], 10**15)
        self.assertEqual(accepted.fields["buyer_refund"], 9 * 10**17)

    def test_json_rpc_source_filters_and_sorts_logs(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content)
            requests.append(payload)
            self.assertEqual(payload["method"], "eth_getLogs")
            params = payload["params"][0]
            self.assertEqual(params["address"], "0x4444444444444444444444444444444444444444")
            self.assertIn(event_topic("DealCreated"), params["topics"][0])
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": [
                _funded_log(block=11, index=1),
                _created_log(block=10, index=0),
            ]})

        source = JsonRpcLogSource(
            "https://rpc.example",
            "0x4444444444444444444444444444444444444444",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        events = source.get_events(10, 11)

        self.assertEqual([event.name for event in events], ["DealCreated", "DealFunded"])
        self.assertEqual(requests[0]["params"][0]["fromBlock"], "0xa")
        self.assertEqual(requests[0]["params"][0]["toBlock"], "0xb")


class ChainWatcherDispatchTest(unittest.TestCase):
    def test_dispatcher_sends_runtime_bearer_only_in_header(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json={"ok": True})

        dispatcher = ChainEventDispatcher(
            "https://tee.example",
            auth_token="watcher-runtime-secret",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        dispatcher.dispatch([decode_diligence_room_log(_created_log())])

        self.assertEqual(
            requests[0].headers["authorization"],
            "Bearer watcher-runtime-secret",
        )
        self.assertNotIn(b"watcher-runtime-secret", requests[0].content)

    def test_dispatch_posts_chain_audit_then_funded_and_resolved_notifications(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append((request.url.path, json.loads(request.content)))
            return httpx.Response(200, json={"ok": True})

        dispatcher = ChainEventDispatcher(
            "https://tee.example",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        events = [
            decode_diligence_room_log(_created_log()),
            decode_diligence_room_log(_funded_log()),
            decode_diligence_room_log(
                _log("DealAccepted", 7, [_word(10**15), _word(10**12), _word(9 * 10**17)], block=12)
            ),
        ]

        summary = dispatcher.dispatch(events)

        self.assertEqual(summary.event_count, 3)
        self.assertEqual(summary.chain_event_posts, 3)
        self.assertEqual(summary.funded_notifications, 1)
        self.assertEqual(summary.resolved_notifications, 1)
        self.assertEqual(
            [path for path, _payload in requests],
            [
                "/deal/chain-event",
                "/deal/chain-event",
                "/deal/notify-funded",
                "/deal/chain-event",
                "/deal/7/resolve",
            ],
        )
        funded = requests[2][1]
        self.assertEqual(funded["buyer"], BUYER)
        self.assertEqual(funded["seller"], SELLER)
        self.assertEqual(funded["budget_cap"], 10**18)
        self.assertEqual(funded["reserve_price"], 10**15)
        self.assertEqual(funded["artifact_hash"], "0x" + "ab" * 32)
        self.assertEqual(
            funded["evaluator_policy_commitment"],
            EVALUATOR_POLICY_COMMITMENT,
        )

    def test_funded_without_created_context_is_audited_but_not_started(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append((request.url.path, json.loads(request.content)))
            return httpx.Response(200, json={"ok": True})

        dispatcher = ChainEventDispatcher(
            "https://tee.example",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        summary = dispatcher.dispatch([decode_diligence_room_log(_funded_log())])

        self.assertEqual(summary.chain_event_posts, 1)
        self.assertEqual(summary.funded_notifications, 0)
        self.assertEqual(summary.missing_created_context, 1)
        self.assertEqual([path for path, _payload in requests], ["/deal/chain-event"])

    def test_watcher_poll_once_reads_rpc_and_dispatches(self):
        api_requests = []

        def rpc_handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": [
                _created_log(block=10, index=0),
                _funded_log(block=11, index=0),
            ]})

        def api_handler(request: httpx.Request) -> httpx.Response:
            api_requests.append(request.url.path)
            return httpx.Response(200, json={"ok": True})

        source = JsonRpcLogSource(
            "https://rpc.example",
            "0x4444444444444444444444444444444444444444",
            client=httpx.Client(transport=httpx.MockTransport(rpc_handler)),
        )
        dispatcher = ChainEventDispatcher(
            "https://tee.example",
            client=httpx.Client(transport=httpx.MockTransport(api_handler)),
        )
        watcher = ChainWatcher(source, dispatcher)

        summary = watcher.poll_once(10, 11)

        self.assertEqual(summary.funded_notifications, 1)
        self.assertIn("/deal/notify-funded", api_requests)

    def test_cursor_persists_created_context_for_restart_recovery(self):
        api_requests = []

        def api_handler(request: httpx.Request) -> httpx.Response:
            api_requests.append((request.url.path, json.loads(request.content)))
            return httpx.Response(200, json={"ok": True})

        with tempfile.TemporaryDirectory() as tmpdir:
            cursor = ChainCursorStore(Path(tmpdir) / "cursor.json")

            created_source = _source_for_logs([_created_log(block=10, index=0)], latest_block=10)
            first_dispatcher = ChainEventDispatcher(
                "https://tee.example",
                client=httpx.Client(transport=httpx.MockTransport(api_handler)),
            )
            first_summary = ChainWatcher(created_source, first_dispatcher).poll_once_with_cursor(
                cursor_store=cursor,
                start_block=10,
                confirmations=0,
            )

            self.assertTrue(first_summary["cursor_advanced"])
            self.assertEqual(first_summary["chain_event_posts"], 1)
            saved = cursor.load()
            self.assertEqual(saved.next_block, 11)
            self.assertIn("7", saved.created_deals)
            self.assertEqual(saved.created_deals["7"]["seller"], SELLER)

            funded_source = _source_for_logs([_funded_log(block=11, index=0)], latest_block=11)
            restarted_dispatcher = ChainEventDispatcher(
                "https://tee.example",
                client=httpx.Client(transport=httpx.MockTransport(api_handler)),
                created_context=cursor.load().created_deals,
            )
            second_summary = ChainWatcher(funded_source, restarted_dispatcher).poll_once_with_cursor(
                cursor_store=cursor,
                confirmations=0,
            )

            self.assertEqual(second_summary["from_block"], 11)
            self.assertEqual(second_summary["funded_notifications"], 1)
            self.assertEqual(cursor.load().next_block, 12)

        self.assertEqual(
            [path for path, _payload in api_requests],
            [
                "/deal/chain-event",
                "/deal/chain-event",
                "/deal/notify-funded",
            ],
        )
        funded = api_requests[-1][1]
        self.assertEqual(funded["buyer"], BUYER)
        self.assertEqual(funded["seller"], SELLER)
        self.assertEqual(funded["artifact_hash"], "0x" + "ab" * 32)
        self.assertEqual(
            funded["evaluator_policy_commitment"],
            EVALUATOR_POLICY_COMMITMENT,
        )

    def test_cursor_does_not_advance_past_confirmation_safe_tip(self):
        api_requests = []

        def api_handler(request: httpx.Request) -> httpx.Response:
            api_requests.append(request.url.path)
            return httpx.Response(200, json={"ok": True})

        with tempfile.TemporaryDirectory() as tmpdir:
            cursor = ChainCursorStore(Path(tmpdir) / "cursor.json")
            cursor.save(
                ChainCursorState(
                    next_block=12,
                    created_deals={},
                    confirmations=2,
                    last_scanned_to_block=11,
                    contract_address="0x4444444444444444444444444444444444444444",
                )
            )
            source = _source_for_logs([_funded_log(block=12)], latest_block=13)
            dispatcher = ChainEventDispatcher(
                "https://tee.example",
                client=httpx.Client(transport=httpx.MockTransport(api_handler)),
            )

            summary = ChainWatcher(source, dispatcher).poll_once_with_cursor(
                cursor_store=cursor,
                confirmations=2,
            )

            self.assertFalse(summary["cursor_advanced"])
            self.assertEqual(summary["to_block"], 11)
            self.assertEqual(cursor.load().next_block, 12)
            self.assertEqual(api_requests, [])


class ChainWatcherApiTest(unittest.TestCase):
    def test_chain_event_endpoint_calls_control_plane_without_raw_page_state(self):
        sys.modules.setdefault("tinker", types.SimpleNamespace())

        class ControlPlane:
            calls = []

            def on_chain_event(self, *args, **kwargs):
                self.calls.append((args, kwargs))

        cp = ControlPlane()
        client = TestClient(api.app)

        with (
            patch("tinker_delegate.api._get_control_plane", return_value=cp),
            patch.object(
                api,
                "settings",
                Settings(runtime_auth_required=True, runtime_auth_token="watcher-secret"),
            ),
        ):
            response = client.post(
                "/deal/chain-event",
                json={
                    "event_name": "DealCreated",
                    "deal_id": "7",
                    "block_number": 10,
                    "tx_hash": "0x" + "12" * 32,
                    "log_index": 1,
                    "fields": {"seller": SELLER, "reserve_price": 10**15},
                },
                headers={"Authorization": "Bearer watcher-secret"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"deal_id": "7", "event": "DealCreated", "recorded": True})
        self.assertEqual(cp.calls[0][0], ("DealCreated", "7"))
        self.assertEqual(cp.calls[0][1]["block_number"], 10)
        self.assertEqual(cp.calls[0][1]["fields"]["seller"], SELLER)


def _source_for_logs(logs: list[dict], latest_block: int) -> JsonRpcLogSource:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        if payload["method"] == "eth_blockNumber":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": hex(latest_block)})
        if payload["method"] == "eth_getLogs":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": logs})
        return httpx.Response(500, json={"error": "unexpected method"})

    return JsonRpcLogSource(
        "https://rpc.example",
        "0x4444444444444444444444444444444444444444",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


if __name__ == "__main__":
    unittest.main()
