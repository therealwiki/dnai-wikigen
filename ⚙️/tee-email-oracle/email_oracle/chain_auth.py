"""Read-only EmailOracleAuth consumer-registry checks.

This module intentionally performs only bounded public ``eth_call`` reads. It
never handles OTPs, mailbox contents, credentials, or private key material.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from email_oracle.redaction import redact_text


IS_CONSUMER_AUTHORIZED_SELECTOR = bytes.fromhex("d85e82f7")


class EmailOracleAuthError(ValueError):
    """Raised when consumer-registry policy cannot be checked safely."""


class EthCallClient(Protocol):
    def eth_call(self, tx: dict[str, Any]) -> str:
        """Return hex-encoded ABI data for an ``eth_call``."""


class JsonRpcClient:
    def __init__(self, rpc_url: str, *, timeout: float = 20.0):
        if not rpc_url:
            raise EmailOracleAuthError("EmailOracleAuth RPC URL is required")
        self.rpc_url = rpc_url
        self._client = httpx.Client(timeout=timeout)
        self._next_id = 1

    def close(self) -> None:
        self._client.close()

    def call(self, method: str, params: list[Any]) -> Any:
        request_id = self._next_id
        self._next_id += 1
        response = self._client.post(
            self.rpc_url,
            json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("error"):
            message = payload["error"].get("message", "JSON-RPC error")
            raise EmailOracleAuthError(redact_text(message))
        return payload.get("result")

    def eth_call(self, tx: dict[str, Any]) -> str:
        return str(self.call("eth_call", [tx, "latest"]))


@dataclass(frozen=True)
class ConsumerAuthorizationResult:
    checked: bool
    allowed: bool
    reason: str
    contract_address: str = ""
    consumer_app_id: str = ""
    consumer_compose_hash: str = ""
    caller_identity: str = ""
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "allowed": self.allowed,
            "reason": self.reason,
            "contract_address": self.contract_address,
            "consumer_app_id": self.consumer_app_id,
            "consumer_compose_hash": self.consumer_compose_hash,
            "caller_identity": self.caller_identity,
            "raw_secret_egress": self.raw_secret_egress,
        }


class EmailOracleAuthChecker:
    def __init__(self, rpc: EthCallClient, contract_address: str):
        self.rpc = rpc
        self.contract_address = normalize_address(contract_address)

    def is_consumer_authorized(
        self,
        *,
        consumer_app_id: str,
        consumer_compose_hash: str,
        caller_identity: str = "",
    ) -> ConsumerAuthorizationResult:
        consumer_app_id = normalize_address(consumer_app_id)
        consumer_compose_hash = normalize_bytes32(consumer_compose_hash, field="consumer compose hash")
        calldata = (
            IS_CONSUMER_AUTHORIZED_SELECTOR
            + encode_address_word(consumer_app_id)
            + bytes.fromhex(consumer_compose_hash[2:])
        )
        allowed = decode_bool(
            self.rpc.eth_call(
                {
                    "to": self.contract_address,
                    "data": "0x" + calldata.hex(),
                }
            )
        )
        return ConsumerAuthorizationResult(
            checked=True,
            allowed=allowed,
            reason="allowed" if allowed else "consumer_not_authorized",
            contract_address=self.contract_address,
            consumer_app_id=consumer_app_id,
            consumer_compose_hash=consumer_compose_hash,
            caller_identity=caller_identity,
        )


def check_consumer_authorization(
    settings,
    *,
    caller_identity: str = "",
    required: bool | None = None,
    rpc: EthCallClient | None = None,
) -> ConsumerAuthorizationResult:
    policy_required = bool(getattr(settings, "auth_required", False))
    if required is not None:
        policy_required = bool(required)

    configured_contract = getattr(settings, "auth_contract_address", "")
    if not configured_contract:
        return ConsumerAuthorizationResult(
            checked=False,
            allowed=not policy_required,
            reason="missing_contract" if policy_required else "not_configured",
            caller_identity=caller_identity,
        )

    expected_identity = getattr(settings, "auth_expected_caller_identity", "")
    if expected_identity and caller_identity and caller_identity != expected_identity:
        return ConsumerAuthorizationResult(
            checked=False,
            allowed=False,
            reason="caller_identity_mismatch",
            contract_address=normalize_address(configured_contract),
            caller_identity=caller_identity,
        )

    consumer_app_id = getattr(settings, "auth_consumer_app_id", "")
    consumer_compose_hash = getattr(settings, "auth_consumer_compose_hash", "")
    if not consumer_app_id:
        return ConsumerAuthorizationResult(
            checked=False,
            allowed=False,
            reason="missing_consumer_app_id",
            contract_address=normalize_address(configured_contract),
            caller_identity=caller_identity,
        )
    if not consumer_compose_hash:
        return ConsumerAuthorizationResult(
            checked=False,
            allowed=False,
            reason="missing_consumer_compose_hash",
            contract_address=normalize_address(configured_contract),
            consumer_app_id=normalize_address(consumer_app_id),
            caller_identity=caller_identity,
        )

    client: EthCallClient | None = rpc
    close_client = False
    try:
        if client is None:
            rpc_url = getattr(settings, "auth_rpc_url", "")
            if not rpc_url:
                return ConsumerAuthorizationResult(
                    checked=False,
                    allowed=False,
                    reason="missing_rpc_url",
                    contract_address=normalize_address(configured_contract),
                    consumer_app_id=normalize_address(consumer_app_id),
                    consumer_compose_hash=normalize_bytes32(consumer_compose_hash),
                    caller_identity=caller_identity,
                )
            client = JsonRpcClient(rpc_url)
            close_client = True
        return EmailOracleAuthChecker(client, configured_contract).is_consumer_authorized(
            consumer_app_id=consumer_app_id,
            consumer_compose_hash=consumer_compose_hash,
            caller_identity=caller_identity,
        )
    finally:
        if close_client and hasattr(client, "close"):
            client.close()  # type: ignore[attr-defined]


def normalize_address(address: str) -> str:
    raw = str(address).strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if len(raw) != 40:
        raise EmailOracleAuthError("expected 20-byte Ethereum address")
    try:
        int(raw, 16)
    except ValueError as exc:
        raise EmailOracleAuthError("Ethereum address must be hex") from exc
    return "0x" + raw


def normalize_bytes32(value: str, *, field: str = "bytes32") -> str:
    raw = str(value).strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    try:
        decoded = bytes.fromhex(raw)
    except ValueError as exc:
        raise EmailOracleAuthError(f"{field} must be hex") from exc
    if len(decoded) != 32:
        raise EmailOracleAuthError(f"{field} must be bytes32")
    if decoded == b"\x00" * 32:
        raise EmailOracleAuthError(f"{field} must be non-zero")
    return "0x" + decoded.hex()


def encode_address_word(address: str) -> bytes:
    return bytes.fromhex(normalize_address(address)[2:]).rjust(32, b"\x00")


def encode_bool(value: bool) -> str:
    return "0x" + (1 if value else 0).to_bytes(32, "big").hex()


def decode_bool(raw: str) -> bool:
    text = str(raw).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    try:
        decoded = bytes.fromhex(text)
    except ValueError as exc:
        raise EmailOracleAuthError("contract read returned non-hex data") from exc
    if len(decoded) != 32:
        raise EmailOracleAuthError("contract read returned non-word data")
    value = int.from_bytes(decoded, "big")
    if value not in (0, 1):
        raise EmailOracleAuthError("boolean contract read returned non-bool value")
    return bool(value)
