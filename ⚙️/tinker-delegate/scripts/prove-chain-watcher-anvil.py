#!/usr/bin/env python3
"""Prove the DiligenceRoom watcher against real local Anvil logs.

This script starts an ephemeral Anvil chain, deploys DiligenceRoom through an
unlocked local account, emits DealCreated and DealFunded, runs the watcher over
real JSON-RPC logs, and asserts that a bounded control-plane API stub receives
the expected state transition. It never uses or prints raw private keys.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from tinker_delegate.chain_watcher import (
    ChainEventDispatcher,
    ChainCursorStore,
    ChainWatcher,
    JsonRpcLogSource,
)


ROOT = Path(__file__).resolve().parents[3]
CONTRACTS_DIR = ROOT / "⚙️" / "tinker-delegate" / "contracts"
ANVIL_SELLER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ANVIL_BUYER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
ANVIL_TEE = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
ARTIFACT_HASH = "0x" + "ab" * 32


class ProofState:
    def __init__(self) -> None:
        self.chain_events: list[dict[str, Any]] = []
        self.funded: dict[str, dict[str, Any]] = {}
        self.resolved: list[str] = []


def main() -> int:
    anvil_port = _free_port()
    api_port = _free_port()
    rpc_url = f"http://127.0.0.1:{anvil_port}"
    api_url = f"http://127.0.0.1:{api_port}"
    state = ProofState()
    server = _start_control_plane_stub(api_port, state)
    anvil = _start_anvil(anvil_port)

    try:
        _wait_for_rpc(rpc_url)
        contract_address = _deploy_diligence_room(rpc_url)
        start_block = _block_number(rpc_url)
        create_tx = _create_deal(rpc_url, contract_address)
        created_block = _block_number(rpc_url)

        with tempfile.TemporaryDirectory() as tmpdir:
            cursor_store = ChainCursorStore(Path(tmpdir) / "chain_watcher_cursor.json")
            first_summary = _run_watcher_once(
                rpc_url,
                api_url,
                contract_address,
                cursor_store,
                start_block=start_block,
            )
            fund_tx = _fund_deal(rpc_url, contract_address)
            funded_block = _block_number(rpc_url)
            second_summary = _run_watcher_once(
                rpc_url,
                api_url,
                contract_address,
                cursor_store,
            )
            cursor_summary = cursor_store.public_summary()

        _assert_proof_state(state, first_summary, second_summary)
        print(json.dumps({
            "ok": True,
            "contract_address": contract_address,
            "from_block": start_block,
            "created_block": created_block,
            "funded_block": funded_block,
            "create_tx_hash": create_tx,
            "fund_tx_hash": fund_tx,
            "watcher_first_scan": first_summary,
            "watcher_after_restart": second_summary,
            "cursor": cursor_summary,
            "control_plane_stub": {
                "chain_event_count": len(state.chain_events),
                "funded_deal_ids": sorted(state.funded),
                "resolved_deal_ids": state.resolved,
            },
            "raw_secret_egress": False,
        }, indent=2, sort_keys=True))
        return 0
    finally:
        server.shutdown()
        server.server_close()
        anvil.terminate()
        try:
            anvil.wait(timeout=5)
        except subprocess.TimeoutExpired:
            anvil.kill()
            anvil.wait(timeout=5)


def _start_anvil(port: int) -> subprocess.Popen:
    return subprocess.Popen(
        ["anvil", "--port", str(port), "--chain-id", "31337"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=ROOT,
        text=True,
    )


def _start_control_plane_stub(port: int, state: ProofState) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            path = urlparse(self.path).path
            if path == "/deal/chain-event":
                state.chain_events.append(payload)
                self._json({"recorded": True})
                return
            if path == "/deal/notify-funded":
                state.funded[str(payload["deal_id"])] = payload
                self._json({"state": "pending_artifact", "deal_id": payload["deal_id"]})
                return
            if path.startswith("/deal/") and path.endswith("/resolve"):
                state.resolved.append(path.split("/")[2])
                self._json({"resolved": True})
                return
            self.send_response(404)
            self.end_headers()

        def _json(self, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _run_watcher_once(
    rpc_url: str,
    api_url: str,
    contract_address: str,
    cursor_store: ChainCursorStore,
    *,
    start_block: int | None = None,
) -> dict[str, Any]:
    source = JsonRpcLogSource(rpc_url, contract_address)
    dispatcher = ChainEventDispatcher(api_url, created_context=cursor_store.load().created_deals)
    try:
        return ChainWatcher(source, dispatcher).poll_once_with_cursor(
            cursor_store=cursor_store,
            start_block=start_block,
            confirmations=0,
        )
    finally:
        dispatcher.close()
        source.close()


def _deploy_diligence_room(rpc_url: str) -> str:
    output = _run_json([
        "forge",
        "create",
        "src/DiligenceRoom.sol:DiligenceRoom",
        "--rpc-url",
        rpc_url,
        "--unlocked",
        "--from",
        ANVIL_SELLER,
        "--broadcast",
        "--json",
    ], cwd=CONTRACTS_DIR)
    address = output.get("deployedTo") or output.get("contractAddress")
    if not address:
        raise RuntimeError("forge create did not return deployed contract address")
    return str(address)


def _create_deal(rpc_url: str, contract_address: str) -> str:
    expiry = int(time.time()) + 3600
    output = _run_json([
        "cast",
        "send",
        contract_address,
        "createDeal(uint256,uint256,bytes32,address)",
        "1000000000000000",
        str(expiry),
        ARTIFACT_HASH,
        ANVIL_TEE,
        "--rpc-url",
        rpc_url,
        "--unlocked",
        "--from",
        ANVIL_SELLER,
        "--json",
    ])
    return _tx_hash(output)


def _fund_deal(rpc_url: str, contract_address: str) -> str:
    output = _run_json([
        "cast",
        "send",
        contract_address,
        "fundDeal(uint256)",
        "0",
        "--value",
        "1ether",
        "--rpc-url",
        rpc_url,
        "--unlocked",
        "--from",
        ANVIL_BUYER,
        "--json",
    ])
    return _tx_hash(output)


def _assert_proof_state(state: ProofState, first_summary: dict[str, Any], second_summary: dict[str, Any]) -> None:
    names = [event["event_name"] for event in state.chain_events]
    if names != ["DealCreated", "DealFunded"]:
        raise AssertionError(f"expected DealCreated/DealFunded chain events, got {names}")
    funded = state.funded.get("0")
    if not funded:
        raise AssertionError("watcher did not notify funded deal 0")
    if funded["seller"].lower() != ANVIL_SELLER.lower():
        raise AssertionError("funded notification seller did not match created event")
    if funded["buyer"].lower() != ANVIL_BUYER.lower():
        raise AssertionError("funded notification buyer did not match funded event")
    if int(funded["budget_cap"]) != 10**18:
        raise AssertionError("funded notification budget cap mismatch")
    if int(funded["reserve_price"]) != 10**15:
        raise AssertionError("funded notification reserve price mismatch")
    if first_summary["chain_event_posts"] != 1 or first_summary["funded_notifications"] != 0:
        raise AssertionError("first watcher scan did not persist only DealCreated")
    if second_summary["funded_notifications"] != 1 or second_summary["chain_event_posts"] != 1:
        raise AssertionError("watcher summary did not match expected dispatch counts")


def _wait_for_rpc(rpc_url: str) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            _block_number(rpc_url)
            return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("Anvil RPC did not become ready")


def _block_number(rpc_url: str) -> int:
    return int(_run(["cast", "block-number", "--rpc-url", rpc_url]).strip())


def _run_json(args: list[str], *, cwd: Path | None = None) -> dict[str, Any]:
    output = _run(args, cwd=cwd)
    return json.loads(output)


def _run(args: list[str], *, cwd: Path | None = None) -> str:
    env = dict(os.environ)
    env.pop("ETH_PRIVATE_KEY", None)
    env.pop("PRIVATE_KEY", None)
    result = subprocess.run(
        args,
        cwd=cwd or ROOT,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def _tx_hash(receipt: dict[str, Any]) -> str:
    tx_hash = receipt.get("transactionHash") or receipt.get("transaction_hash")
    if not tx_hash:
        raise RuntimeError("cast receipt did not include transaction hash")
    return str(tx_hash)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


if __name__ == "__main__":
    sys.exit(main())
