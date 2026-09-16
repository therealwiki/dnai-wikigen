"""Secret-safe, duplicate-free Base JSON-RPC client with EIP-1898 reads."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import SecretStr

from .errors import PolicyRejected, UpstreamUnavailable
from .evm import decode_quantity
from .policy import parse_duplicate_free_json


MAX_RPC_RESPONSE_BYTES = 2 * 1024 * 1024
BYTES32_RE = re.compile(r"^0x[0-9a-f]{64}$")
CODE_RE = re.compile(r"^0x(?:[0-9a-f]{2})+$")


@dataclass(frozen=True)
class BlockSnapshot:
    number: int
    hash: str
    timestamp: int


def rpc_origin_from_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise PolicyRejected from exc
    if parsed.scheme != "https" or not parsed.hostname:
        raise PolicyRejected
    host = parsed.hostname
    if port in (None, 443):
        return f"https://{host}"
    return f"https://{host}:{port}"


@dataclass
class StrictJsonRpcClient:
    _url: SecretStr = field(repr=False)
    timeout_seconds: float
    _client: httpx.AsyncClient | None = field(default=None, init=False, repr=False)
    _next_id: int = field(default=1, init=False, repr=False)

    async def start(self) -> None:
        if self._client is not None:
            return
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=16, max_keepalive_connections=8),
            headers={"Accept": "application/json", "User-Agent": "dnai-compute-metering/0.1"},
        )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def call(self, method: str, params: list[object]) -> object:
        if self._client is None:
            raise UpstreamUnavailable
        request_id = self._next_id
        self._next_id += 1
        if self._next_id > 2**31 - 1:
            self._next_id = 1
        try:
            response = await self._client.post(
                self._url.get_secret_value(),
                json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
            )
            if response.status_code != 200 or len(response.content) > MAX_RPC_RESPONSE_BYTES:
                raise UpstreamUnavailable
            content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise UpstreamUnavailable
            decoded = parse_duplicate_free_json(response.content)
        except UpstreamUnavailable:
            raise
        except Exception as exc:
            raise UpstreamUnavailable from exc
        if not isinstance(decoded, dict):
            raise UpstreamUnavailable
        if decoded.get("jsonrpc") != "2.0" or decoded.get("id") != request_id:
            raise UpstreamUnavailable
        if set(decoded) == {"jsonrpc", "id", "error"}:
            raise UpstreamUnavailable
        if set(decoded) != {"jsonrpc", "id", "result"} or decoded["result"] is None:
            raise UpstreamUnavailable
        return decoded["result"]

    async def chain_id(self) -> int:
        return decode_quantity(await self.call("eth_chainId", []))

    async def block_by_number(self, number: int | LiteralLatest) -> BlockSnapshot:
        tag = "latest" if number is LATEST else hex(number)
        return _decode_block(await self.call("eth_getBlockByNumber", [tag, False]))

    async def block_by_hash(self, block_hash: str) -> BlockSnapshot:
        if not BYTES32_RE.fullmatch(block_hash):
            raise UpstreamUnavailable
        return _decode_block(await self.call("eth_getBlockByHash", [block_hash, False]))

    async def get_code(self, address: str, block_hash: str) -> bytes:
        result = await self.call("eth_getCode", [address, block_reference(block_hash)])
        if not isinstance(result, str) or len(result) > 512 * 1024 or not CODE_RE.fullmatch(result):
            raise UpstreamUnavailable
        return bytes.fromhex(result[2:])

    async def eth_call(self, address: str, data: str, block_hash: str) -> object:
        return await self.call(
            "eth_call",
            [{"to": address, "data": data}, block_reference(block_hash)],
        )


class LiteralLatest:
    pass


LATEST = LiteralLatest()


def block_reference(block_hash: str) -> dict[str, object]:
    if not BYTES32_RE.fullmatch(block_hash):
        raise UpstreamUnavailable
    return {"blockHash": block_hash, "requireCanonical": True}


def _decode_block(value: Any) -> BlockSnapshot:
    if not isinstance(value, dict):
        raise UpstreamUnavailable
    block_hash = value.get("hash")
    if not isinstance(block_hash, str) or not BYTES32_RE.fullmatch(block_hash):
        raise UpstreamUnavailable
    number = decode_quantity(value.get("number"))
    timestamp = decode_quantity(value.get("timestamp"))
    if number > 2**63 - 1 or timestamp > 4_102_444_800:
        raise UpstreamUnavailable
    return BlockSnapshot(number=number, hash=block_hash, timestamp=timestamp)
