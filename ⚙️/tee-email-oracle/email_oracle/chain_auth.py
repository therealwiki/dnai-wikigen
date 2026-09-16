"""Fail-closed EmailOracleAuth reads against two Base Sepolia RPCs.

The production path never accepts a provider's unpinned ``latest`` view.  Two
independent HTTPS RPCs must agree on one common finalized block, the contract
runtime bytes, release readiness, and consumer authorization.  A durable local
checkpoint prevents a later request from moving behind a block already used by
the oracle.

Only public chain data is processed here.  OTPs, mailbox contents, credentials,
RPC URLs, and private key material never enter an error message or checkpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from typing import Any, Protocol

from eth_hash.auto import keccak
import httpx


BASE_SEPOLIA_CHAIN_ID = 84_532
CANONICAL_CALLER_IDENTITY = "tinker-delegate.signup"
IS_CONSUMER_AUTHORIZED_SELECTOR = bytes.fromhex("d85e82f7")
RELEASE_CONFIGURATION_READY_SELECTOR = bytes.fromhex("2d39d679")
FINALIZED_BLOCK_TAG = "finalized"
CHECKPOINT_SCHEMA = "dnai.email-oracle.finalized-checkpoint.v1"
ZERO_HASH = "0x" + "00" * 32
_MAX_CHECKPOINT_BYTES = 4_096
_QUANTITY = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]*)$")
_CHECKPOINT_LOCKS: dict[str, threading.Lock] = {}
_CHECKPOINT_LOCKS_GUARD = threading.Lock()


class EmailOracleAuthError(ValueError):
    """Raised when the on-chain consumer policy cannot be checked safely."""


class RpcClient(Protocol):
    def call(self, method: str, params: list[Any]) -> Any:
        """Return the JSON-RPC result for one bounded public read."""


class CheckpointStore(Protocol):
    def record(self, block_number: int, block_hash: str) -> None:
        """Persist a non-decreasing finalized block before authorization returns."""


class JsonRpcClient:
    """Small JSON-RPC client whose exceptions never include a credentialed URL."""

    def __init__(self, rpc_url: str, *, label: str, timeout: float = 20.0):
        if not rpc_url:
            raise EmailOracleAuthError(f"EmailOracleAuth {label} RPC URL is required")
        self.rpc_url = rpc_url
        self.label = label
        self._client = httpx.Client(timeout=timeout)
        self._next_id = 1

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            # Closing is best-effort and must never replace a sanitized policy
            # result with a transport object's credential-bearing exception.
            pass

    def call(self, method: str, params: list[Any]) -> Any:
        request_id = self._next_id
        self._next_id += 1
        try:
            response = self._client.post(
                self.rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": params,
                },
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError, TypeError):
            raise EmailOracleAuthError(
                f"EmailOracleAuth {self.label} RPC transport failed"
            ) from None

        if not isinstance(payload, dict):
            raise EmailOracleAuthError(
                f"EmailOracleAuth {self.label} RPC returned an invalid envelope"
            )
        if payload.get("jsonrpc") != "2.0" or payload.get("id") != request_id:
            raise EmailOracleAuthError(
                f"EmailOracleAuth {self.label} RPC response identity mismatch"
            )
        if "error" in payload:
            # A provider-controlled message can echo a credential-bearing URL.
            # Keep only our bounded provider label and method name.
            raise EmailOracleAuthError(
                f"EmailOracleAuth {self.label} RPC rejected {method}"
            )
        if "result" not in payload:
            raise EmailOracleAuthError(
                f"EmailOracleAuth {self.label} RPC omitted the result"
            )
        return payload["result"]


@dataclass(frozen=True)
class FinalizedBlock:
    number: int
    block_hash: str
    timestamp: int


@dataclass(frozen=True)
class FinalizedCheckpoint:
    block_number: int
    block_hash: str


class FinalizedBlockCheckpointStore:
    """Atomic durable monotonic checkpoint for the last accepted finalized view.

    The checkpoint contains public block metadata, so confidentiality is not
    required.  Atomic replacement plus a single-process lock protects integrity
    across crashes and concurrent requests.  Production startup calls
    :meth:`ensure_ready` so an unavailable durable volume prevents readiness.
    """

    def __init__(self, path: str):
        if not path:
            raise EmailOracleAuthError("finalized checkpoint path is required")
        self.path = Path(path)
        lock_name = str(self.path.absolute())
        with _CHECKPOINT_LOCKS_GUARD:
            self._lock = _CHECKPOINT_LOCKS.setdefault(lock_name, threading.Lock())

    def ensure_ready(self) -> FinalizedCheckpoint:
        """Load the checkpoint or durably create the zero-height sentinel."""

        with self._lock:
            current = self._load_unlocked()
            if current is not None:
                # Re-write the same checkpoint atomically to prove the mounted
                # production volume is writable, not merely readable.
                self._write_unlocked(current)
                return current
            initial = FinalizedCheckpoint(0, ZERO_HASH)
            self._write_unlocked(initial)
            return initial

    def load(self) -> FinalizedCheckpoint | None:
        with self._lock:
            return self._load_unlocked()

    def record(self, block_number: int, block_hash: str) -> None:
        if not isinstance(block_number, int) or isinstance(block_number, bool) or block_number <= 0:
            raise EmailOracleAuthError("finalized checkpoint block number is invalid")
        normalized_hash = normalize_bytes32(block_hash, field="finalized block hash")
        with self._lock:
            current = self._load_unlocked()
            if current is not None:
                if block_number < current.block_number:
                    raise EmailOracleAuthError(
                        "finalized block regressed behind the durable checkpoint"
                    )
                if (
                    block_number == current.block_number
                    and normalized_hash != current.block_hash
                ):
                    raise EmailOracleAuthError(
                        "finalized block hash conflicts with the durable checkpoint"
                    )
                if (
                    block_number == current.block_number
                    and normalized_hash == current.block_hash
                ):
                    return
            self._write_unlocked(FinalizedCheckpoint(block_number, normalized_hash))

    def _load_unlocked(self) -> FinalizedCheckpoint | None:
        try:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.path, flags)
        except FileNotFoundError:
            return None
        except OSError:
            raise EmailOracleAuthError("could not open finalized checkpoint safely") from None

        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_CHECKPOINT_BYTES:
                raise EmailOracleAuthError("finalized checkpoint is not a bounded regular file")
            chunks: list[bytes] = []
            remaining = _MAX_CHECKPOINT_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(remaining, 4_096))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
        except OSError:
            raise EmailOracleAuthError("could not read finalized checkpoint") from None
        finally:
            os.close(descriptor)

        if not raw or len(raw) > _MAX_CHECKPOINT_BYTES:
            raise EmailOracleAuthError("finalized checkpoint has invalid size")
        try:
            decoded = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise EmailOracleAuthError("finalized checkpoint is invalid JSON") from None
        if not isinstance(decoded, dict) or set(decoded) != {
            "schema",
            "block_number",
            "block_hash",
        }:
            raise EmailOracleAuthError("finalized checkpoint fields are invalid")
        if decoded["schema"] != CHECKPOINT_SCHEMA:
            raise EmailOracleAuthError("finalized checkpoint schema is invalid")
        number = decoded["block_number"]
        if not isinstance(number, int) or isinstance(number, bool) or number < 0:
            raise EmailOracleAuthError("finalized checkpoint number is invalid")
        block_hash = str(decoded["block_hash"]).lower()
        if number == 0:
            if block_hash != ZERO_HASH:
                raise EmailOracleAuthError("zero checkpoint has a nonzero block hash")
        else:
            block_hash = normalize_bytes32(block_hash, field="checkpoint block hash")
        return FinalizedCheckpoint(number, block_hash)

    def _write_unlocked(self, checkpoint: FinalizedCheckpoint) -> None:
        payload = (
            json.dumps(
                {
                    "schema": CHECKPOINT_SCHEMA,
                    "block_number": checkpoint.block_number,
                    "block_hash": checkpoint.block_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        if len(payload) > _MAX_CHECKPOINT_BYTES:
            raise EmailOracleAuthError("finalized checkpoint serialization is too large")

        temporary: Path | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(
                f".{self.path.name}.{secrets.token_hex(12)}.tmp"
            )
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary, flags, 0o600)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short checkpoint write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
            raise EmailOracleAuthError("could not persist finalized checkpoint") from None


@dataclass(frozen=True)
class ConsumerAuthorizationResult:
    checked: bool
    allowed: bool
    reason: str
    contract_address: str = ""
    consumer_app_id: str = ""
    consumer_compose_hash: str = ""
    caller_identity: str = ""
    chain_id: int = 0
    finalized_block_number: int = 0
    finalized_block_hash: str = ""
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
            "chain_id": self.chain_id,
            "finalized_block_number": self.finalized_block_number,
            "finalized_block_hash": self.finalized_block_hash,
            "raw_secret_egress": self.raw_secret_egress,
        }


class EmailOracleAuthChecker:
    """Verify one consumer decision from two matching finalized RPC views."""

    def __init__(
        self,
        primary_rpc: RpcClient,
        secondary_rpc: RpcClient,
        contract_address: str,
        *,
        expected_chain_id: int = BASE_SEPOLIA_CHAIN_ID,
        expected_runtime_code_hash: str,
        max_block_age_seconds: int = 900,
        max_future_block_skew_seconds: int = 30,
        checkpoint_store: CheckpointStore | None = None,
        now: int | None = None,
    ):
        if expected_chain_id != BASE_SEPOLIA_CHAIN_ID:
            raise EmailOracleAuthError("EmailOracleAuth requires Base Sepolia chain id 84532")
        if not 1 <= max_block_age_seconds <= 900:
            raise EmailOracleAuthError("finalized block age bound must be between 1 and 900 seconds")
        if not 0 <= max_future_block_skew_seconds <= 60:
            raise EmailOracleAuthError("future block skew bound must be between 0 and 60 seconds")
        self.primary_rpc = primary_rpc
        self.secondary_rpc = secondary_rpc
        self.contract_address = normalize_address(contract_address)
        self.expected_chain_id = expected_chain_id
        self.expected_runtime_code_hash = normalize_bytes32(
            expected_runtime_code_hash,
            field="EmailOracleAuth runtime code hash",
        )
        self.max_block_age_seconds = max_block_age_seconds
        self.max_future_block_skew_seconds = max_future_block_skew_seconds
        self.checkpoint_store = checkpoint_store
        self.now = int(time.time()) if now is None else int(now)

    def is_consumer_authorized(
        self,
        *,
        consumer_app_id: str,
        consumer_compose_hash: str,
        caller_identity: str = "",
    ) -> ConsumerAuthorizationResult:
        consumer_app_id = normalize_address(consumer_app_id)
        consumer_compose_hash = normalize_bytes32(
            consumer_compose_hash,
            field="consumer compose hash",
        )

        primary_chain = decode_quantity(
            self.primary_rpc.call("eth_chainId", []), field="primary chain id"
        )
        secondary_chain = decode_quantity(
            self.secondary_rpc.call("eth_chainId", []), field="secondary chain id"
        )
        if primary_chain != secondary_chain or primary_chain != self.expected_chain_id:
            raise EmailOracleAuthError("RPCs do not agree on exact Base Sepolia chain id")

        primary_head = parse_block(
            self.primary_rpc.call("eth_getBlockByNumber", [FINALIZED_BLOCK_TAG, False]),
            field="primary finalized head",
        )
        secondary_head = parse_block(
            self.secondary_rpc.call("eth_getBlockByNumber", [FINALIZED_BLOCK_TAG, False]),
            field="secondary finalized head",
        )
        common_number = min(primary_head.number, secondary_head.number)
        if common_number <= 0:
            raise EmailOracleAuthError("RPCs did not return a usable finalized block")
        block_tag = hex(common_number)

        primary_block = parse_block(
            self.primary_rpc.call("eth_getBlockByNumber", [block_tag, False]),
            field="primary common finalized block",
        )
        secondary_block = parse_block(
            self.secondary_rpc.call("eth_getBlockByNumber", [block_tag, False]),
            field="secondary common finalized block",
        )
        self._require_same_block(primary_block, secondary_block, common_number)
        if primary_block.timestamp > self.now + self.max_future_block_skew_seconds:
            raise EmailOracleAuthError("common finalized block timestamp is in the future")
        if self.now - primary_block.timestamp > self.max_block_age_seconds:
            raise EmailOracleAuthError("common finalized block is stale")

        primary_code = decode_hex_data(
            self.primary_rpc.call(
                "eth_getCode", [self.contract_address, block_tag]
            ),
            field="primary EmailOracleAuth runtime code",
        )
        secondary_code = decode_hex_data(
            self.secondary_rpc.call(
                "eth_getCode", [self.contract_address, block_tag]
            ),
            field="secondary EmailOracleAuth runtime code",
        )
        if not primary_code or primary_code != secondary_code:
            raise EmailOracleAuthError("RPCs disagree on EmailOracleAuth runtime code")
        actual_code_hash = "0x" + keccak(primary_code).hex()
        if actual_code_hash != self.expected_runtime_code_hash:
            raise EmailOracleAuthError("EmailOracleAuth runtime code hash mismatch")

        ready_calldata = "0x" + RELEASE_CONFIGURATION_READY_SELECTOR.hex()
        ready_primary, ready_secondary = self._matching_call(
            ready_calldata,
            block_tag,
            field="releaseConfigurationReady",
        )

        consumer_calldata = (
            IS_CONSUMER_AUTHORIZED_SELECTOR
            + encode_address_word(consumer_app_id)
            + bytes.fromhex(consumer_compose_hash[2:])
        )
        consumer_primary, consumer_secondary = self._matching_call(
            "0x" + consumer_calldata.hex(),
            block_tag,
            field="isConsumerAuthorized",
        )

        # Re-read the exact block after all contract reads.  A provider that
        # changed the block behind the numeric tag cannot pass this check.
        primary_after = parse_block(
            self.primary_rpc.call("eth_getBlockByNumber", [block_tag, False]),
            field="primary post-read finalized block",
        )
        secondary_after = parse_block(
            self.secondary_rpc.call("eth_getBlockByNumber", [block_tag, False]),
            field="secondary post-read finalized block",
        )
        self._require_same_block(primary_after, secondary_after, common_number)
        if primary_after != primary_block or secondary_after != secondary_block:
            raise EmailOracleAuthError("common finalized block changed during authorization")

        ready = decode_bool(ready_primary)
        if ready != decode_bool(ready_secondary):
            raise EmailOracleAuthError("RPCs disagree on release readiness")
        allowed = decode_bool(consumer_primary)
        if allowed != decode_bool(consumer_secondary):
            raise EmailOracleAuthError("RPCs disagree on consumer authorization")

        # Persist after fully validating the ABI responses but before returning
        # either allow or deny.  A denial observed at a newer finalized block
        # must not be rolled back to an older allowed view on the next request.
        if self.checkpoint_store is not None:
            self.checkpoint_store.record(common_number, primary_block.block_hash)

        if not ready:
            reason = "release_configuration_not_ready"
            allowed = False
        else:
            reason = "allowed" if allowed else "consumer_not_authorized"
        return ConsumerAuthorizationResult(
            checked=True,
            allowed=allowed,
            reason=reason,
            contract_address=self.contract_address,
            consumer_app_id=consumer_app_id,
            consumer_compose_hash=consumer_compose_hash,
            caller_identity=caller_identity,
            chain_id=primary_chain,
            finalized_block_number=common_number,
            finalized_block_hash=primary_block.block_hash,
        )

    def _matching_call(
        self,
        calldata: str,
        block_tag: str,
        *,
        field: str,
    ) -> tuple[str, str]:
        tx = {"to": self.contract_address, "data": calldata}
        primary = normalize_word(
            self.primary_rpc.call("eth_call", [tx, block_tag]),
            field=f"primary {field}",
        )
        secondary = normalize_word(
            self.secondary_rpc.call("eth_call", [tx, block_tag]),
            field=f"secondary {field}",
        )
        if primary != secondary:
            raise EmailOracleAuthError(f"RPCs disagree on {field}")
        return primary, secondary

    @staticmethod
    def _require_same_block(
        primary: FinalizedBlock,
        secondary: FinalizedBlock,
        expected_number: int,
    ) -> None:
        if (
            primary.number != expected_number
            or secondary.number != expected_number
            or primary != secondary
        ):
            raise EmailOracleAuthError("RPCs disagree on the common finalized block")


def check_consumer_authorization(
    settings,
    *,
    caller_identity: str = "",
    required: bool | None = None,
    rpc: RpcClient | None = None,
    rpc_secondary: RpcClient | None = None,
    checkpoint_store: CheckpointStore | None = None,
    now: int | None = None,
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

    normalized_contract = normalize_address(configured_contract)
    expected_identity = getattr(settings, "auth_expected_caller_identity", "")
    if expected_identity and caller_identity != expected_identity:
        return ConsumerAuthorizationResult(
            checked=False,
            allowed=False,
            reason="caller_identity_mismatch",
            contract_address=normalized_contract,
            caller_identity=caller_identity,
        )

    consumer_app_id = getattr(settings, "auth_consumer_app_id", "")
    consumer_compose_hash = getattr(settings, "auth_consumer_compose_hash", "")
    if not consumer_app_id:
        return ConsumerAuthorizationResult(
            checked=False,
            allowed=False,
            reason="missing_consumer_app_id",
            contract_address=normalized_contract,
            caller_identity=caller_identity,
        )
    if not consumer_compose_hash:
        return ConsumerAuthorizationResult(
            checked=False,
            allowed=False,
            reason="missing_consumer_compose_hash",
            contract_address=normalized_contract,
            consumer_app_id=normalize_address(consumer_app_id),
            caller_identity=caller_identity,
        )
    expected_code_hash = getattr(settings, "auth_contract_runtime_code_hash", "")
    if not expected_code_hash:
        return ConsumerAuthorizationResult(
            checked=False,
            allowed=False,
            reason="missing_contract_runtime_code_hash",
            contract_address=normalized_contract,
            consumer_app_id=normalize_address(consumer_app_id),
            consumer_compose_hash=normalize_bytes32(consumer_compose_hash),
            caller_identity=caller_identity,
        )

    clients: list[JsonRpcClient] = []
    primary: RpcClient | None = rpc
    secondary: RpcClient | None = rpc_secondary
    try:
        if (primary is None) != (secondary is None):
            raise EmailOracleAuthError("both independent EmailOracleAuth RPCs are required")
        if primary is None and secondary is None:
            primary_url = getattr(settings, "auth_rpc_url", "")
            secondary_url = getattr(settings, "auth_rpc_url_secondary", "")
            if not primary_url or not secondary_url:
                return ConsumerAuthorizationResult(
                    checked=False,
                    allowed=False,
                    reason="missing_rpc_quorum",
                    contract_address=normalized_contract,
                    consumer_app_id=normalize_address(consumer_app_id),
                    consumer_compose_hash=normalize_bytes32(consumer_compose_hash),
                    caller_identity=caller_identity,
                )
            if primary_url == secondary_url:
                raise EmailOracleAuthError("EmailOracleAuth RPC URLs must be distinct")
            primary_client = JsonRpcClient(primary_url, label="primary")
            secondary_client = JsonRpcClient(secondary_url, label="secondary")
            clients.extend((primary_client, secondary_client))
            primary = primary_client
            secondary = secondary_client

        store = checkpoint_store
        if store is None and bool(getattr(settings, "production_release", False)):
            store = FinalizedBlockCheckpointStore(
                getattr(settings, "auth_checkpoint_store_path", "")
            )

        checker = EmailOracleAuthChecker(
            primary,
            secondary,
            normalized_contract,
            expected_chain_id=int(
                getattr(settings, "auth_chain_id", BASE_SEPOLIA_CHAIN_ID)
            ),
            expected_runtime_code_hash=expected_code_hash,
            max_block_age_seconds=int(
                getattr(settings, "auth_max_finalized_block_age_seconds", 900)
            ),
            max_future_block_skew_seconds=int(
                getattr(settings, "auth_max_future_block_skew_seconds", 30)
            ),
            checkpoint_store=store,
            now=now,
        )
        return checker.is_consumer_authorized(
            consumer_app_id=consumer_app_id,
            consumer_compose_hash=consumer_compose_hash,
            caller_identity=caller_identity,
        )
    finally:
        for client in clients:
            client.close()


def parse_block(value: Any, *, field: str) -> FinalizedBlock:
    if not isinstance(value, dict):
        raise EmailOracleAuthError(f"{field} is missing")
    number = decode_quantity(value.get("number"), field=f"{field} number")
    timestamp = decode_quantity(value.get("timestamp"), field=f"{field} timestamp")
    block_hash = normalize_bytes32(value.get("hash", ""), field=f"{field} hash")
    return FinalizedBlock(number=number, block_hash=block_hash, timestamp=timestamp)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EmailOracleAuthError("finalized checkpoint repeats a JSON field")
        value[key] = item
    return value


def decode_quantity(value: Any, *, field: str) -> int:
    if not isinstance(value, str) or not _QUANTITY.fullmatch(value):
        raise EmailOracleAuthError(f"{field} is not a canonical JSON-RPC quantity")
    return int(value, 16)


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


def normalize_bytes32(value: Any, *, field: str = "bytes32") -> str:
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


def decode_hex_data(value: Any, *, field: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise EmailOracleAuthError(f"{field} must be hex data")
    raw = value[2:]
    if len(raw) % 2:
        raise EmailOracleAuthError(f"{field} has odd-length hex data")
    try:
        return bytes.fromhex(raw)
    except ValueError as exc:
        raise EmailOracleAuthError(f"{field} must be hex data") from exc


def normalize_word(value: Any, *, field: str) -> str:
    decoded = decode_hex_data(value, field=field)
    if len(decoded) != 32:
        raise EmailOracleAuthError(f"{field} did not return one ABI word")
    return "0x" + decoded.hex()


def encode_address_word(address: str) -> bytes:
    return bytes.fromhex(normalize_address(address)[2:]).rjust(32, b"\x00")


def encode_bool(value: bool) -> str:
    return "0x" + (1 if value else 0).to_bytes(32, "big").hex()


def decode_bool(raw: Any) -> bool:
    text = normalize_word(raw, field="boolean contract read")
    value = int(text, 16)
    if value not in (0, 1):
        raise EmailOracleAuthError("boolean contract read returned non-bool value")
    return bool(value)
