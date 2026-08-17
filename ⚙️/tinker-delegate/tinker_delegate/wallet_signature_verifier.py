"""Bounded EOA and EIP-1271 verification for wallet login challenges.

The authentication services own their nonce and token domains.  This module
owns only signature verification.  Two independently configured HTTPS
JSON-RPC endpoints may be used to distinguish EOAs from contracts on Base
Sepolia; an API caller can never choose or override either endpoint.

When no RPC endpoint is configured, the verifier deliberately retains the
historical local EOA-only behavior.  Enabling EIP-1271 makes every verification
chain-aware and fail-closed: both RPCs must report Base Sepolia, agree on one
finalized block number and hash, return identical code at that block, and
return the exact EIP-1271 magic value for
``isValidSignature(bytes32,bytes)``. There is no single-provider fallback.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import math
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

import httpx
from eth_account import Account
from eth_account.messages import defunct_hash_message, encode_defunct


BASE_SEPOLIA_CHAIN_ID = 84532
EIP1271_MAGIC_VALUE = bytes.fromhex("1626ba7e")
EIP1271_SELECTOR = EIP1271_MAGIC_VALUE
EIP1271_CALL_GAS_LIMIT = 500_000
MAX_CONCURRENT_EXTERNAL_WALLET_VERIFICATIONS = 8
DEFAULT_MAX_SIGNATURE_BYTES = 4096
DEFAULT_RPC_TIMEOUT_SECONDS = 3.0
DEFAULT_RPC_MAX_RESPONSE_BYTES = 131_072

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_DATA_RE = re.compile(r"^[0-9a-fA-F]*$")
_HEX_QUANTITY_RE = re.compile(r"^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$")
_EXTERNAL_VERIFICATION_SLOTS = threading.BoundedSemaphore(
    MAX_CONCURRENT_EXTERNAL_WALLET_VERIFICATIONS
)


class WalletSignatureError(ValueError):
    """Raised when a supplied signature is invalid for the claimed wallet."""


class WalletSignatureUnavailable(RuntimeError):
    """Raised when configured chain verification cannot complete safely."""


class WalletSignatureVerifier(Protocol):
    """Injectable boundary shared by Deal, Arena, and Compute authentication."""

    def verify(
        self,
        *,
        address: str,
        message: str,
        signature: str,
    ) -> Literal["eoa", "eip1271"]:
        """Verify one exact personal-sign challenge for ``address``."""


class EthereumJsonRpc(Protocol):
    """Small injectable JSON-RPC boundary used by the EIP-1271 verifier."""

    def request(self, method: str, params: list[Any]) -> Any:
        """Return the JSON-RPC result or raise ``WalletSignatureUnavailable``."""


def _request_rpc_pair(
    executor: ThreadPoolExecutor,
    primary_rpc: EthereumJsonRpc,
    secondary_rpc: EthereumJsonRpc,
    method: str,
    params: list[Any],
) -> tuple[Any, Any]:
    """Run one phase against both providers without sequential fallback."""

    primary_future = executor.submit(primary_rpc.request, method, params)
    secondary_future = executor.submit(secondary_rpc.request, method, params)
    return primary_future.result(), secondary_future.result()


class LocalEoaWalletSignatureVerifier:
    """Historical local EOA verification used when no RPC is configured."""

    def __init__(self, *, max_signature_bytes: int = DEFAULT_MAX_SIGNATURE_BYTES):
        self.max_signature_bytes = _bounded_int(
            max_signature_bytes,
            label="wallet signature byte limit",
            minimum=65,
            maximum=DEFAULT_MAX_SIGNATURE_BYTES,
        )

    def verify(
        self,
        *,
        address: str,
        message: str,
        signature: str,
    ) -> Literal["eoa"]:
        normalized_address = _normalize_address(address)
        raw_signature = _decode_signature(
            signature,
            maximum=self.max_signature_bytes,
        )
        _verify_eoa_signature(
            address=normalized_address,
            message=message,
            signature=raw_signature,
        )
        return "eoa"


class BoundedJsonRpcClient:
    """HTTPS JSON-RPC client with fixed redirects, timeout, and body bounds."""

    def __init__(
        self,
        url: str,
        *,
        timeout_seconds: float = DEFAULT_RPC_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_RPC_MAX_RESPONSE_BYTES,
    ) -> None:
        self.url = _validated_rpc_url(url)
        self.timeout_seconds = _bounded_float(
            timeout_seconds,
            label="wallet signature RPC timeout",
            minimum=0.1,
            maximum=10.0,
        )
        self.max_response_bytes = _bounded_int(
            max_response_bytes,
            label="wallet signature RPC response limit",
            minimum=1024,
            maximum=1_048_576,
        )

    def request(self, method: str, params: list[Any]) -> Any:
        if not isinstance(method, str) or not method:
            raise WalletSignatureUnavailable("wallet signature RPC request is invalid")
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        try:
            with httpx.stream(
                "POST",
                self.url,
                json=payload,
                headers={"accept": "application/json"},
                timeout=httpx.Timeout(self.timeout_seconds),
                follow_redirects=False,
                trust_env=False,
            ) as response:
                if response.status_code != 200:
                    raise WalletSignatureUnavailable(
                        "wallet signature RPC returned an unsupported status"
                    )
                declared_length = response.headers.get("content-length")
                if declared_length is not None:
                    try:
                        normalized_length = int(declared_length)
                    except ValueError as exc:
                        raise WalletSignatureUnavailable(
                            "wallet signature RPC response length is invalid"
                        ) from exc
                    if (
                        normalized_length < 0
                        or normalized_length > self.max_response_bytes
                    ):
                        raise WalletSignatureUnavailable(
                            "wallet signature RPC response exceeds the configured limit"
                        )
                chunks: list[bytes] = []
                received = 0
                for chunk in response.iter_bytes():
                    received += len(chunk)
                    if received > self.max_response_bytes:
                        raise WalletSignatureUnavailable(
                            "wallet signature RPC response exceeds the configured limit"
                        )
                    chunks.append(chunk)
        except WalletSignatureUnavailable:
            raise
        except httpx.HTTPError as exc:
            raise WalletSignatureUnavailable(
                "wallet signature RPC request failed"
            ) from exc

        try:
            document = json.loads(b"".join(chunks))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise WalletSignatureUnavailable(
                "wallet signature RPC response is not valid JSON"
            ) from exc
        if not isinstance(document, dict):
            raise WalletSignatureUnavailable("wallet signature RPC response is invalid")
        response_id = document.get("id")
        if (
            document.get("jsonrpc") != "2.0"
            or isinstance(response_id, bool)
            or not isinstance(response_id, int)
            or response_id != 1
        ):
            raise WalletSignatureUnavailable("wallet signature RPC response is invalid")
        if document.get("error") is not None or "result" not in document:
            raise WalletSignatureUnavailable("wallet signature RPC request was rejected")
        return document["result"]


@dataclass(frozen=True)
class _FinalizedBlock:
    number: int
    block_hash: str


class BaseSepoliaWalletSignatureVerifier:
    """Verify wallets only when two Base Sepolia RPCs agree at finality."""

    def __init__(
        self,
        primary_rpc: EthereumJsonRpc,
        secondary_rpc: EthereumJsonRpc,
        *,
        max_signature_bytes: int = DEFAULT_MAX_SIGNATURE_BYTES,
    ) -> None:
        if primary_rpc is secondary_rpc:
            raise WalletSignatureUnavailable(
                "wallet signature verification requires two independent RPC providers"
            )
        self.primary_rpc = primary_rpc
        self.secondary_rpc = secondary_rpc
        self.max_signature_bytes = _bounded_int(
            max_signature_bytes,
            label="wallet signature byte limit",
            minimum=65,
            maximum=DEFAULT_MAX_SIGNATURE_BYTES,
        )

    def verify(
        self,
        *,
        address: str,
        message: str,
        signature: str,
    ) -> Literal["eoa", "eip1271"]:
        normalized_address = _normalize_address(address)
        if not isinstance(message, str):
            raise WalletSignatureError("wallet challenge message is invalid")
        raw_signature = _decode_signature(
            signature,
            maximum=self.max_signature_bytes,
        )

        if not _EXTERNAL_VERIFICATION_SLOTS.acquire(blocking=False):
            raise WalletSignatureUnavailable(
                "wallet signature verification is temporarily unavailable"
            )
        try:
            with ThreadPoolExecutor(
                max_workers=2,
                thread_name_prefix="wallet-auth-rpc",
            ) as executor:
                primary_chain, secondary_chain = _request_rpc_pair(
                    executor,
                    self.primary_rpc,
                    self.secondary_rpc,
                    "eth_chainId",
                    [],
                )
                primary_chain_id = _decode_quantity(
                    primary_chain,
                    label="primary wallet signature RPC chain id",
                )
                secondary_chain_id = _decode_quantity(
                    secondary_chain,
                    label="secondary wallet signature RPC chain id",
                )
                if (
                    primary_chain_id != BASE_SEPOLIA_CHAIN_ID
                    or secondary_chain_id != BASE_SEPOLIA_CHAIN_ID
                ):
                    raise WalletSignatureUnavailable(
                        "wallet signature RPC providers are not both connected to Base Sepolia"
                    )

                primary_head_value, secondary_head_value = _request_rpc_pair(
                    executor,
                    self.primary_rpc,
                    self.secondary_rpc,
                    "eth_getBlockByNumber",
                    ["finalized", False],
                )
                primary_head = _decode_finalized_block(
                    primary_head_value,
                    label="primary wallet signature finalized block",
                )
                secondary_head = _decode_finalized_block(
                    secondary_head_value,
                    label="secondary wallet signature finalized block",
                )
                agreed_number = min(primary_head.number, secondary_head.number)
                block_tag = hex(agreed_number)
                primary_block_value, secondary_block_value = _request_rpc_pair(
                    executor,
                    self.primary_rpc,
                    self.secondary_rpc,
                    "eth_getBlockByNumber",
                    [block_tag, False],
                )
                primary_block = _decode_finalized_block(
                    primary_block_value,
                    label="primary wallet signature agreed block",
                )
                secondary_block = _decode_finalized_block(
                    secondary_block_value,
                    label="secondary wallet signature agreed block",
                )
                if (
                    primary_block.number != agreed_number
                    or secondary_block.number != agreed_number
                    or not hmac.compare_digest(
                        primary_block.block_hash,
                        secondary_block.block_hash,
                    )
                    or (
                        primary_head.number == agreed_number
                        and not hmac.compare_digest(
                            primary_head.block_hash,
                            primary_block.block_hash,
                        )
                    )
                    or (
                        secondary_head.number == agreed_number
                        and not hmac.compare_digest(
                            secondary_head.block_hash,
                            secondary_block.block_hash,
                        )
                    )
                ):
                    raise WalletSignatureUnavailable(
                        "wallet signature RPC providers disagree on the finalized block"
                    )

                primary_code_value, secondary_code_value = _request_rpc_pair(
                    executor,
                    self.primary_rpc,
                    self.secondary_rpc,
                    "eth_getCode",
                    [normalized_address, block_tag],
                )
                primary_code = _decode_data(
                    primary_code_value,
                    label="primary wallet contract code",
                    maximum=49_152,
                )
                secondary_code = _decode_data(
                    secondary_code_value,
                    label="secondary wallet contract code",
                    maximum=49_152,
                )
                if bool(primary_code) != bool(secondary_code):
                    raise WalletSignatureUnavailable(
                        "wallet signature RPC providers disagree on wallet code classification"
                    )
                if not hmac.compare_digest(primary_code, secondary_code):
                    raise WalletSignatureUnavailable(
                        "wallet signature RPC providers disagree on wallet runtime code"
                    )
                if not primary_code:
                    _verify_eoa_signature(
                        address=normalized_address,
                        message=message,
                        signature=raw_signature,
                    )
                    return "eoa"

                digest = bytes(defunct_hash_message(text=message))
                if len(digest) != 32:  # pragma: no cover - dependency invariant
                    raise WalletSignatureUnavailable("wallet EIP-191 digest is invalid")
                calldata = _eip1271_calldata(digest, raw_signature)
                call_params = [
                    {
                        "to": normalized_address,
                        "data": "0x" + calldata.hex(),
                        "gas": hex(EIP1271_CALL_GAS_LIMIT),
                    },
                    block_tag,
                ]
                primary_result_value, secondary_result_value = _request_rpc_pair(
                    executor,
                    self.primary_rpc,
                    self.secondary_rpc,
                    "eth_call",
                    call_params,
                )
                primary_result = _decode_data(
                    primary_result_value,
                    label="primary wallet EIP-1271 response",
                    maximum=32,
                )
                secondary_result = _decode_data(
                    secondary_result_value,
                    label="secondary wallet EIP-1271 response",
                    maximum=32,
                )
                primary_valid = _is_eip1271_magic(primary_result)
                secondary_valid = _is_eip1271_magic(secondary_result)
                if primary_valid != secondary_valid:
                    raise WalletSignatureUnavailable(
                        "wallet signature RPC providers disagree on EIP-1271 validity"
                    )
                if not primary_valid:
                    raise WalletSignatureError(
                        "EIP-1271 contract wallet rejected signature"
                    )
                return "eip1271"
        finally:
            _EXTERNAL_VERIFICATION_SLOTS.release()


def wallet_signature_verifier_from_settings(settings: Any) -> WalletSignatureVerifier:
    """Build the shared verifier from server-owned settings.

    Two empty RPC URLs intentionally select EOA-only local verification.  This
    keeps development and existing EOA deployments working without silently
    claiming contract-wallet support. Contract-wallet support is active only
    when the operator supplies two endpoints on distinct provider origins.
    Partial or same-provider configuration fails closed.
    """

    max_signature_bytes = getattr(
        settings,
        "wallet_auth_max_signature_bytes",
        DEFAULT_MAX_SIGNATURE_BYTES,
    )
    primary_url = str(getattr(settings, "wallet_auth_rpc_url", "") or "").strip()
    secondary_url = str(
        getattr(settings, "wallet_auth_rpc_url_secondary", "") or ""
    ).strip()
    if not primary_url and not secondary_url:
        return LocalEoaWalletSignatureVerifier(
            max_signature_bytes=max_signature_bytes,
        )
    if not primary_url or not secondary_url:
        raise WalletSignatureUnavailable(
            "wallet signature verification requires two configured RPC providers"
        )
    primary_rpc = BoundedJsonRpcClient(
        primary_url,
        timeout_seconds=getattr(
            settings,
            "wallet_auth_rpc_timeout_seconds",
            DEFAULT_RPC_TIMEOUT_SECONDS,
        ),
        max_response_bytes=getattr(
            settings,
            "wallet_auth_rpc_max_response_bytes",
            DEFAULT_RPC_MAX_RESPONSE_BYTES,
        ),
    )
    secondary_rpc = BoundedJsonRpcClient(
        secondary_url,
        timeout_seconds=getattr(
            settings,
            "wallet_auth_rpc_timeout_seconds",
            DEFAULT_RPC_TIMEOUT_SECONDS,
        ),
        max_response_bytes=getattr(
            settings,
            "wallet_auth_rpc_max_response_bytes",
            DEFAULT_RPC_MAX_RESPONSE_BYTES,
        ),
    )
    if _rpc_origin_identity(primary_rpc.url) == _rpc_origin_identity(secondary_rpc.url):
        raise WalletSignatureUnavailable(
            "wallet signature RPC providers must use distinct origins"
        )
    return BaseSepoliaWalletSignatureVerifier(
        primary_rpc,
        secondary_rpc,
        max_signature_bytes=max_signature_bytes,
    )


def _verify_eoa_signature(*, address: str, message: str, signature: bytes) -> None:
    if len(signature) != 65:
        raise WalletSignatureError("wallet signature must be 65 bytes for an EOA")
    try:
        recovered = Account.recover_message(
            encode_defunct(text=message),
            signature=signature,
        )
        normalized_recovered = _normalize_address(recovered)
    except WalletSignatureError:
        raise
    except Exception as exc:
        raise WalletSignatureError("wallet signature recovery failed") from exc
    if not hmac.compare_digest(normalized_recovered, address):
        raise WalletSignatureError("wallet signature does not match challenge address")


def _eip1271_calldata(digest: bytes, signature: bytes) -> bytes:
    """ABI-encode ``isValidSignature(bytes32,bytes)`` without a web3 runtime."""

    padded_length = ((len(signature) + 31) // 32) * 32
    return b"".join(
        (
            EIP1271_SELECTOR,
            digest,
            (64).to_bytes(32, "big"),
            len(signature).to_bytes(32, "big"),
            signature.ljust(padded_length, b"\x00"),
        )
    )


def _normalize_address(value: Any) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value.strip()):
        raise WalletSignatureError(
            "wallet address must be a 20-byte 0x-prefixed hex address"
        )
    return value.strip().lower()


def _decode_signature(value: Any, *, maximum: int) -> bytes:
    if not isinstance(value, str):
        raise WalletSignatureError("wallet signature must be hex")
    raw_hex = value[2:] if value.startswith(("0x", "0X")) else value
    if not raw_hex:
        raise WalletSignatureError("wallet signature must not be empty")
    if len(raw_hex) % 2 != 0:
        raise WalletSignatureError("wallet signature must be even-length hex")
    if len(raw_hex) // 2 > maximum:
        raise WalletSignatureError("wallet signature exceeds the configured limit")
    if not _HEX_DATA_RE.fullmatch(raw_hex):
        raise WalletSignatureError("wallet signature must be hex")
    try:
        return bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise WalletSignatureError("wallet signature must be hex") from exc


def _decode_quantity(value: Any, *, label: str) -> int:
    if not isinstance(value, str) or not _HEX_QUANTITY_RE.fullmatch(value):
        raise WalletSignatureUnavailable(f"{label} is malformed")
    return int(value, 16)


def _decode_data(value: Any, *, label: str, maximum: int) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise WalletSignatureUnavailable(f"{label} is malformed")
    raw_hex = value[2:]
    if (
        len(raw_hex) % 2 != 0
        or len(raw_hex) // 2 > maximum
        or not _HEX_DATA_RE.fullmatch(raw_hex)
    ):
        raise WalletSignatureUnavailable(f"{label} is malformed")
    try:
        return bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise WalletSignatureUnavailable(f"{label} is malformed") from exc


def _decode_finalized_block(value: Any, *, label: str) -> _FinalizedBlock:
    if not isinstance(value, dict):
        raise WalletSignatureUnavailable(f"{label} is malformed")
    number = _decode_quantity(value.get("number"), label=f"{label} number")
    block_hash = value.get("hash")
    if (
        number <= 0
        or not isinstance(block_hash, str)
        or not re.fullmatch(r"0x[0-9a-fA-F]{64}", block_hash)
        or block_hash.lower() == "0x" + "00" * 32
    ):
        raise WalletSignatureUnavailable(f"{label} is malformed")
    return _FinalizedBlock(number=number, block_hash=block_hash.lower())


def _is_eip1271_magic(result: bytes) -> bool:
    # Standard ABI bytes4 returns are 32-byte right-padded words. A few minimal
    # clients return the raw four bytes; both represent the same exact bytes4.
    return result == EIP1271_MAGIC_VALUE or (
        len(result) == 32
        and result[:4] == EIP1271_MAGIC_VALUE
        and result[4:] == b"\x00" * 28
    )


def _validated_rpc_url(value: Any) -> str:
    if not isinstance(value, str):
        raise WalletSignatureUnavailable("wallet signature RPC URL is invalid")
    normalized = value.strip()
    if normalized != value or re.search(r"[\x00-\x20\x7f]", value):
        raise WalletSignatureUnavailable("wallet signature RPC URL is invalid")
    if len(normalized.encode("utf-8")) > 4096:
        raise WalletSignatureUnavailable("wallet signature RPC URL is invalid")
    try:
        parsed = urlsplit(normalized)
        parsed_port = parsed.port
    except ValueError as exc:
        raise WalletSignatureUnavailable("wallet signature RPC URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed_port is not None and parsed_port <= 0
    ):
        raise WalletSignatureUnavailable(
            "wallet signature RPC URL must be an operator-configured HTTPS endpoint"
        )
    return normalized


def _rpc_origin_identity(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    hostname = (parsed.hostname or "").rstrip(".")
    if not hostname:
        raise WalletSignatureUnavailable("wallet signature RPC URL is invalid")
    try:
        hostname = ipaddress.ip_address(hostname).compressed
    except ValueError:
        try:
            hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise WalletSignatureUnavailable(
                "wallet signature RPC URL is invalid"
            ) from exc
    port = parsed.port or 443
    return parsed.scheme.lower(), hostname, port


def _bounded_int(value: Any, *, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise WalletSignatureUnavailable(f"{label} is outside the supported range")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise WalletSignatureUnavailable(
            f"{label} is outside the supported range"
        ) from exc
    if normalized < minimum or normalized > maximum:
        raise WalletSignatureUnavailable(f"{label} is outside the supported range")
    return normalized


def _bounded_float(value: Any, *, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool):
        raise WalletSignatureUnavailable(f"{label} is outside the supported range")
    try:
        normalized = float(value)
    except (TypeError, ValueError) as exc:
        raise WalletSignatureUnavailable(
            f"{label} is outside the supported range"
        ) from exc
    if not math.isfinite(normalized) or normalized < minimum or normalized > maximum:
        raise WalletSignatureUnavailable(f"{label} is outside the supported range")
    return normalized
