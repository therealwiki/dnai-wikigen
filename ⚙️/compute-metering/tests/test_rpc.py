from __future__ import annotations

import json

import httpx
import pytest
from pydantic import SecretStr

from compute_metering.errors import PolicyRejected, UpstreamUnavailable
from compute_metering.rpc import StrictJsonRpcClient, block_reference, rpc_origin_from_url
from tests.support import PINNED_HASH, PINNED_NUMBER, VAULT


def _response(request: httpx.Request, result: object, **kwargs) -> httpx.Response:
    decoded = json.loads(request.content)
    return httpx.Response(
        200,
        headers={"Content-Type": "application/json"},
        json={"jsonrpc": "2.0", "id": decoded["id"], "result": result},
        **kwargs,
    )


async def _client(handler) -> StrictJsonRpcClient:
    client = StrictJsonRpcClient(SecretStr("https://sepolia.base.org/secret-path"), timeout_seconds=3)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


@pytest.mark.asyncio
async def test_rpc_chain_block_code_and_eip1898_contract_reads_are_strict():
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request):
        payload = json.loads(request.content)
        requests.append(payload)
        method = payload["method"]
        if method == "eth_chainId":
            return _response(request, "0x14a34")
        if method == "eth_getBlockByNumber":
            return _response(
                request,
                {"number": hex(PINNED_NUMBER), "hash": PINNED_HASH, "timestamp": "0x6b49d200"},
            )
        if method == "eth_getCode":
            return _response(request, "0x6000")
        if method == "eth_call":
            return _response(request, "0x" + "00" * 32)
        raise AssertionError(method)

    client = await _client(handler)
    try:
        assert await client.chain_id() == 84_532
        block = await client.block_by_number(PINNED_NUMBER)
        assert block.number == PINNED_NUMBER and block.hash == PINNED_HASH
        assert await client.get_code(VAULT, PINNED_HASH) == b"\x60\x00"
        assert await client.eth_call(VAULT, "0x12345678", PINNED_HASH) == "0x" + "00" * 32
    finally:
        await client.close()
    for payload in requests[-2:]:
        ref = payload["params"][-1]
        assert ref == {"blockHash": PINNED_HASH, "requireCanonical": True}


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["duplicate", "wrong_id", "error", "extra", "content_type", "status", "null"])
async def test_rpc_response_ambiguity_and_upstream_errors_are_fixed_unavailable(kind):
    def handler(request: httpx.Request):
        request_id = json.loads(request.content)["id"]
        if kind == "duplicate":
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=(f'{{"jsonrpc":"2.0","id":{request_id},"result":"0x1","result":"0x2"}}').encode(),
            )
        if kind == "wrong_id":
            return httpx.Response(200, headers={"Content-Type": "application/json"}, json={"jsonrpc": "2.0", "id": 999, "result": "0x1"})
        if kind == "error":
            return httpx.Response(200, headers={"Content-Type": "application/json"}, json={"jsonrpc": "2.0", "id": request_id, "error": {"code": -1, "message": "secret"}})
        if kind == "extra":
            return httpx.Response(200, headers={"Content-Type": "application/json"}, json={"jsonrpc": "2.0", "id": request_id, "result": "0x1", "extra": True})
        if kind == "content_type":
            return httpx.Response(200, headers={"Content-Type": "text/plain"}, content=b"{}")
        if kind == "status":
            return httpx.Response(503, headers={"Content-Type": "application/json"}, content=b"{}")
        return httpx.Response(200, headers={"Content-Type": "application/json"}, json={"jsonrpc": "2.0", "id": request_id, "result": None})

    client = await _client(handler)
    try:
        with pytest.raises(UpstreamUnavailable):
            await client.chain_id()
    finally:
        await client.close()


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("https://sepolia.base.org", "https://sepolia.base.org"),
        ("https://sepolia.base.org/path/key?token=x", "https://sepolia.base.org"),
        ("https://rpc.example.com:8443/key", "https://rpc.example.com:8443"),
        ("https://rpc.example.com:443/key", "https://rpc.example.com"),
    ],
)
def test_rpc_origin_strips_secret_path_and_default_port(url, origin):
    assert rpc_origin_from_url(url) == origin


@pytest.mark.parametrize("url", ["http://example.com", "not-a-url", "https://", "https://example.com:99999"])
def test_rpc_origin_rejects_non_https_or_invalid_urls(url):
    with pytest.raises(PolicyRejected):
        rpc_origin_from_url(url)


def test_block_reference_is_exact_and_rejects_noncanonical_hash():
    assert block_reference(PINNED_HASH) == {"blockHash": PINNED_HASH, "requireCanonical": True}
    with pytest.raises(UpstreamUnavailable):
        block_reference("0X" + "ab" * 32)
