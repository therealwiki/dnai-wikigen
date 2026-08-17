"""Durable sponsor-driven Collaboration Royalty settlement control plane.

The store records requests, idempotency, plan commitments, advisory broadcast
hashes, and finalized reconciliation only.  Exact dual-authorized wallet plans
remain in the independently HMAC-authenticated execution-policy store.  A
reported transaction hash never proves settlement.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import hmac
import json
import os
from contextlib import contextmanager
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Iterator, Mapping

from tinker_delegate import dstack_utils


STATUS_SCHEMA = "dnai.collaboration.royalty-settlement-status.v2"
STORE_SCHEMA = "dnai.collaboration.royalty-settlement-store.v2"
STORE_VERSION = 2
MAX_STORE_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 4_096

STATES = frozenset(
    {
        "prepare_requested",
        "authorizing",
        "plan_ready",
        "broadcast_reported",
        "settled",
        "expired",
        "reservation_expired",
        "refunded",
        "reconciliation_hold",
    }
)

_MAC_DOMAIN = b"dnai-wikigen/collaboration-royalty-settlement-store/v2\0"
_IDEMPOTENCY_DOMAIN = b"dnai-wikigen/collaboration-royalty-settlement-idempotency/v1\0"
_EXECUTION_ID = re.compile(r"^exec_[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x(?!0{40}$)[0-9a-f]{40}$")
_BYTES32 = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_FAILURE = re.compile(r"^[a-z][a-z0-9_]{2,95}$")


class CollaborationRoyaltySettlementError(ValueError):
    """The status request or persisted state is invalid."""


class CollaborationRoyaltySettlementConflict(CollaborationRoyaltySettlementError):
    """A request conflicts with an existing generation or transition."""


class CollaborationRoyaltySettlementStoreError(RuntimeError):
    """The authenticated settlement journal is unavailable or corrupt."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except Exception:
        raise CollaborationRoyaltySettlementError(
            "royalty settlement state is not canonical JSON"
        ) from None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _integer(value: Any, label: str, *, minimum: int = 0, maximum: int = 2**256 - 1) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise CollaborationRoyaltySettlementError(f"{label} is invalid")
    return value


def _pattern(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise CollaborationRoyaltySettlementError(f"{label} is invalid")
    return value


def _idempotency_hash(execution_id: str, operation: str, key: str) -> str:
    normalized = _pattern(key, _IDEMPOTENCY, "idempotency key")
    return "sha256:" + hashlib.sha256(
        _IDEMPOTENCY_DOMAIN
        + execution_id.encode("ascii")
        + b"\0"
        + operation.encode("ascii")
        + b"\0"
        + normalized.encode("ascii")
    ).hexdigest()


def _execution_authority(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "execution_id",
        "sponsor_address",
        "funding_reservation_id",
        "settlement_id",
        "settlement_nonce",
        "refund_after",
    }:
        raise CollaborationRoyaltySettlementError(
            "settlement execution authority is invalid"
        )
    return {
        "execution_id": _pattern(value["execution_id"], _EXECUTION_ID, "execution id"),
        "sponsor_address": _pattern(value["sponsor_address"], _ADDRESS, "sponsor address"),
        "funding_reservation_id": _pattern(
            value["funding_reservation_id"], _BYTES32, "funding reservation id"
        ),
        "settlement_id": _pattern(value["settlement_id"], _BYTES32, "settlement id"),
        "settlement_nonce": _integer(
            value["settlement_nonce"], "settlement nonce", minimum=1
        ),
        "refund_after": _integer(
            value["refund_after"], "reservation refund time", minimum=1, maximum=4_102_444_800
        ),
    }


def settlement_execution_authority(execution: Mapping[str, Any]) -> dict[str, Any]:
    """Extract immutable server-authenticated authority from a public record."""

    try:
        royalty = execution["royalty"]
        reservation = royalty["funding_reservation"]
        request = reservation["request"]
        nonce = request["settlement_nonce"]
        refund_after = request["refund_after"]
        if (
            execution["state"] != "bounded_result_ready"
            or execution["bounded_result"] is None
            or not isinstance(nonce, str)
            or not nonce.isdecimal()
            or str(int(nonce)) != nonce
            or not isinstance(refund_after, str)
            or not refund_after.isdecimal()
            or str(int(refund_after)) != refund_after
        ):
            raise ValueError
        return _execution_authority(
            {
                "execution_id": execution["execution_id"],
                "sponsor_address": execution["sponsor_address"],
                "funding_reservation_id": reservation["reservation_id"],
                "settlement_id": request["settlement_id"],
                "settlement_nonce": int(nonce),
                "refund_after": int(refund_after),
            }
        )
    except Exception:
        raise CollaborationRoyaltySettlementError(
            "execution has no settlement-ready bounded result"
        ) from None


class CollaborationRoyaltySettlementStore:
    """HMAC-authenticated, process-locked settlement status journal."""

    _RECORD_FIELDS = frozenset(
        {
            "execution_id",
            "sponsor_address",
            "state",
            "generation",
            "funding_reservation_id",
            "settlement_id",
            "settlement_nonce",
            "refund_after",
            "prepare_idempotency_hash",
            "replace_expired",
            "prepare_requested_at",
            "plan_commitment",
            "authorization_expires_at",
            "broadcast_idempotency_hash",
            "broadcast_hint",
            "finalized_settlement",
            "terminal_evidence",
            "failure_code",
            "retryable",
            "updated_at",
        }
    )

    def __init__(self, path: str | Path, *, integrity_key: bytes) -> None:
        if not isinstance(path, (str, Path)) or not str(path).strip():
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement store path is required"
            )
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement store key is invalid"
            )
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self._key = bytes(integrity_key)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._locked():
            if not self.path.exists():
                self._write_unlocked(
                    {
                        "sequence": 0,
                        "authorization_cursor": 0,
                        "reconciliation_cursor": 0,
                        "records": {},
                    }
                )
            else:
                self._load_unlocked()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        descriptor = os.open(
            self.lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _envelope(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        encoded = _canonical_json(payload)
        return {
            "schema": STORE_SCHEMA,
            "schema_version": STORE_VERSION,
            "payload": copy.deepcopy(dict(payload)),
            "integrity": {
                "algorithm": "hmac-sha256",
                "value": hmac.new(
                    self._key, _MAC_DOMAIN + encoded, hashlib.sha256
                ).hexdigest(),
            },
        }

    def _write_unlocked(self, payload: Mapping[str, Any]) -> None:
        encoded = _canonical_json(self._envelope(payload))
        if len(encoded) > MAX_STORE_BYTES:
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement store exceeds its byte cap"
            )
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = -1
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _load_unlocked(self) -> dict[str, Any]:
        try:
            if self.path.is_symlink():
                raise OSError
            descriptor = os.open(
                self.path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                details = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(details.st_mode)
                    or stat.S_IMODE(details.st_mode) != 0o600
                    or details.st_nlink != 1
                    or details.st_uid != os.geteuid()
                    or details.st_size < 2
                    or details.st_size > MAX_STORE_BYTES
                ):
                    raise OSError
                raw = os.read(descriptor, MAX_STORE_BYTES + 1)
            finally:
                os.close(descriptor)
            root = json.loads(raw, object_pairs_hook=_unique_object)
            if raw != _canonical_json(root):
                raise ValueError
        except Exception:
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement store is unavailable or unsafe"
            ) from None
        if (
            not isinstance(root, Mapping)
            or set(root) != {"schema", "schema_version", "payload", "integrity"}
            or root["schema"] != STORE_SCHEMA
            or root["schema_version"] != STORE_VERSION
            or not isinstance(root["payload"], Mapping)
            or not isinstance(root["integrity"], Mapping)
            or set(root["integrity"]) != {"algorithm", "value"}
            or root["integrity"]["algorithm"] != "hmac-sha256"
        ):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement store schema is invalid"
            )
        expected = hmac.new(
            self._key,
            _MAC_DOMAIN + _canonical_json(root["payload"]),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(str(root["integrity"]["value"]), expected):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement store authentication failed"
            )
        payload = copy.deepcopy(dict(root["payload"]))
        if set(payload) != {
            "sequence",
            "authorization_cursor",
            "reconciliation_cursor",
            "records",
        } or not isinstance(
            payload["records"], Mapping
        ):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement store payload is invalid"
            )
        _integer(payload["sequence"], "store sequence", maximum=2**63 - 1)
        _integer(
            payload["authorization_cursor"],
            "authorization cursor",
            maximum=2**63 - 1,
        )
        _integer(
            payload["reconciliation_cursor"],
            "reconciliation cursor",
            maximum=2**63 - 1,
        )
        if len(payload["records"]) > MAX_RECORDS:
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement store record cap exceeded"
            )
        for execution_id, record in payload["records"].items():
            if execution_id != self._validate_record(record)["execution_id"]:
                raise CollaborationRoyaltySettlementStoreError(
                    "royalty settlement store record key changed"
                )
        return payload

    def _validate_record(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) != self._RECORD_FIELDS:
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement record schema is invalid"
            )
        record = copy.deepcopy(dict(value))
        authority = _execution_authority(
            {
                key: record[key]
                for key in (
                    "execution_id",
                    "sponsor_address",
                    "funding_reservation_id",
                    "settlement_id",
                    "settlement_nonce",
                    "refund_after",
                )
            }
        )
        if record["state"] not in STATES:
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement state is invalid"
            )
        _integer(record["generation"], "settlement generation", minimum=1, maximum=2**63 - 1)
        _pattern(record["prepare_idempotency_hash"], re.compile(r"^sha256:[0-9a-f]{64}$"), "prepare idempotency hash")
        if type(record["replace_expired"]) is not bool:
            raise CollaborationRoyaltySettlementStoreError("replacement flag is invalid")
        _integer(record["prepare_requested_at"], "prepare request time", minimum=1, maximum=4_102_444_800)
        _integer(record["updated_at"], "update time", minimum=1, maximum=4_102_444_800)
        if record["plan_commitment"] is not None:
            _pattern(record["plan_commitment"], _BYTES32, "plan commitment")
        if record["authorization_expires_at"] is not None:
            _integer(record["authorization_expires_at"], "authorization expiry", minimum=1, maximum=4_102_444_800)
        if record["broadcast_idempotency_hash"] is not None:
            _pattern(record["broadcast_idempotency_hash"], re.compile(r"^sha256:[0-9a-f]{64}$"), "broadcast idempotency hash")
        hint = record["broadcast_hint"]
        if hint is not None:
            if not isinstance(hint, Mapping) or set(hint) != {"transaction_hash", "reported_at"}:
                raise CollaborationRoyaltySettlementStoreError("broadcast hint is invalid")
            _pattern(hint["transaction_hash"], _BYTES32, "transaction hash")
            _integer(hint["reported_at"], "broadcast report time", minimum=1, maximum=4_102_444_800)
        finalized = record["finalized_settlement"]
        if finalized is not None:
            self._validate_finalized(finalized)
        terminal = record["terminal_evidence"]
        if terminal is not None:
            self._validate_terminal_evidence(terminal)
        if record["failure_code"] is not None:
            _pattern(record["failure_code"], _FAILURE, "failure code")
        if type(record["retryable"]) is not bool:
            raise CollaborationRoyaltySettlementStoreError("retryable flag is invalid")
        plan_present = record["plan_commitment"] is not None
        if plan_present != (record["authorization_expires_at"] is not None):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement plan fields are incomplete"
            )
        broadcast_present = record["broadcast_hint"] is not None
        if broadcast_present != (record["broadcast_idempotency_hash"] is not None):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement broadcast fields are incomplete"
            )
        if record["state"] in {"plan_ready", "broadcast_reported", "settled"} and not plan_present:
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement plan is missing"
            )
        if record["state"] == "broadcast_reported" and not broadcast_present:
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement broadcast hint is missing"
            )
        if (record["state"] == "settled") != (
            record["finalized_settlement"] is not None
        ):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement finality state is inconsistent"
            )
        if (record["state"] in {"reservation_expired", "refunded"}) != (
            terminal is not None
        ):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement terminal evidence is inconsistent"
            )
        if terminal is not None and (
            terminal["funding_reservation_id"]
            != record["funding_reservation_id"]
            or terminal["block_timestamp"] < record["refund_after"]
            or terminal["block_timestamp"] > record["updated_at"]
            or terminal["outcome"]
            != (
                "reservation_refunded"
                if record["state"] == "refunded"
                else "reservation_expired"
            )
        ):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement terminal authority changed"
            )
        state = record["state"]
        if state in {"prepare_requested", "authorizing"} and (
            plan_present
            or broadcast_present
            or record["failure_code"] is not None
            or record["retryable"] is not True
        ):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement preparation state is inconsistent"
            )
        if state == "plan_ready" and (
            broadcast_present
            or record["failure_code"] is not None
            or record["retryable"] is not False
        ):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement ready state is inconsistent"
            )
        if state == "broadcast_reported" and (
            record["failure_code"] is not None
            or record["retryable"] is not False
        ):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement broadcast state is inconsistent"
            )
        if state == "settled" and (
            record["failure_code"] is not None
            or record["retryable"] is not False
        ):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement finalized state is inconsistent"
            )
        if state == "expired" and (
            record["failure_code"] != "authorization_expired"
            or record["retryable"] is not True
        ):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement expiry state is inconsistent"
            )
        if state == "reservation_expired" and (
            record["failure_code"] != "reservation_expired"
            or record["retryable"] is not False
        ):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty reservation expiry state is inconsistent"
            )
        if state == "refunded" and (
            record["failure_code"] != "reservation_refunded"
            or record["retryable"] is not False
        ):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement refund state is inconsistent"
            )
        if state == "reconciliation_hold" and record["failure_code"] is None:
            raise CollaborationRoyaltySettlementStoreError(
                "royalty settlement hold state is inconsistent"
            )
        # The normalized authority comparison also rejects numeric aliases.
        for key, normalized in authority.items():
            if record[key] != normalized:
                raise CollaborationRoyaltySettlementStoreError(
                    "royalty settlement authority changed"
                )
        return record

    @staticmethod
    def _validate_finalized(value: Mapping[str, Any]) -> None:
        fields = {
            "chain_id",
            "block_number",
            "block_hash",
            "block_timestamp",
            "reservation_active",
            "reservation_consumed",
            "settlement_processed",
            "settlement_nonce_processed",
            "source_commitment",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise CollaborationRoyaltySettlementStoreError(
                "finalized settlement evidence is invalid"
            )
        if value["chain_id"] != 84_532:
            raise CollaborationRoyaltySettlementStoreError(
                "finalized settlement chain is invalid"
            )
        _integer(value["block_number"], "finalized block number", minimum=1, maximum=2**63 - 1)
        _pattern(value["block_hash"], _BYTES32, "finalized block hash")
        _integer(value["block_timestamp"], "finalized block time", minimum=1, maximum=4_102_444_800)
        for field in (
            "reservation_active",
            "reservation_consumed",
            "settlement_processed",
            "settlement_nonce_processed",
        ):
            if type(value[field]) is not bool:
                raise CollaborationRoyaltySettlementStoreError(
                    "finalized settlement flags are invalid"
                )
        _pattern(value["source_commitment"], re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$"), "finalized source commitment")

    @staticmethod
    def _validate_terminal_evidence(value: Mapping[str, Any]) -> None:
        fields = {
            "outcome",
            "chain_id",
            "block_number",
            "block_hash",
            "block_timestamp",
            "funding_reservation_id",
            "reservation_storage_status",
            "reservation_active",
            "reservation_consumed",
            "reservation_deposited_amount",
            "settlement_processed",
            "settlement_nonce_processed",
            "source_commitment",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise CollaborationRoyaltySettlementStoreError(
                "royalty terminal chain evidence is invalid"
            )
        if value["outcome"] not in {
            "reservation_expired",
            "reservation_refunded",
        } or value["chain_id"] != 84_532:
            raise CollaborationRoyaltySettlementStoreError(
                "royalty terminal outcome is invalid"
            )
        _integer(value["block_number"], "terminal block number", minimum=1, maximum=2**63 - 1)
        _pattern(value["block_hash"], _BYTES32, "terminal block hash")
        _integer(value["block_timestamp"], "terminal block time", minimum=1, maximum=4_102_444_800)
        _pattern(value["funding_reservation_id"], _BYTES32, "terminal reservation id")
        _integer(
            value["reservation_deposited_amount"],
            "terminal reservation deposit",
            minimum=(
                1 if value["outcome"] == "reservation_expired" else 0
            ),
        )
        for field in (
            "reservation_active",
            "reservation_consumed",
            "settlement_processed",
            "settlement_nonce_processed",
        ):
            if type(value[field]) is not bool:
                raise CollaborationRoyaltySettlementStoreError(
                    "royalty terminal flags are invalid"
                )
        if (
            value["reservation_active"] is not False
            or value["reservation_consumed"] is not False
            or value["settlement_processed"] is not False
            or value["settlement_nonce_processed"] is not False
            or (
                value["outcome"] == "reservation_expired"
                and value["reservation_storage_status"] != "active"
            )
            or (
                value["outcome"] == "reservation_refunded"
                and (
                    value["reservation_storage_status"] != "refunded"
                    or value["reservation_deposited_amount"] != 0
                )
            )
        ):
            raise CollaborationRoyaltySettlementStoreError(
                "royalty terminal state is not exact"
            )
        _pattern(
            value["source_commitment"],
            re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$"),
            "terminal source commitment",
        )

    def request_prepare(
        self,
        *,
        authority: Mapping[str, Any],
        sponsor_address: str,
        idempotency_key: str,
        replace_expired: bool,
        requested_at: int,
    ) -> dict[str, Any]:
        exact = _execution_authority(authority)
        sponsor = _pattern(sponsor_address, _ADDRESS, "sponsor address")
        if sponsor != exact["sponsor_address"] or type(replace_expired) is not bool:
            raise CollaborationRoyaltySettlementError(
                "only the execution sponsor may request settlement"
            )
        timestamp = _integer(requested_at, "prepare request time", minimum=1, maximum=4_102_444_800)
        request_hash = _idempotency_hash(exact["execution_id"], "prepare", idempotency_key)
        with self._locked():
            body = self._load_unlocked()
            current = body["records"].get(exact["execution_id"])
            if current is not None:
                current = self._validate_record(current)
                if any(current[key] != exact[key] for key in exact):
                    raise CollaborationRoyaltySettlementConflict(
                        "settlement execution authority changed"
                    )
                if current["prepare_idempotency_hash"] == request_hash:
                    return self._public(current, wallet_plan=None)
                if (
                    current["state"] != "expired"
                    or current["retryable"] is not True
                    or not replace_expired
                ):
                    raise CollaborationRoyaltySettlementConflict(
                        "settlement preparation already exists"
                    )
                generation = current["generation"] + 1
            else:
                if replace_expired:
                    raise CollaborationRoyaltySettlementConflict(
                        "no expired settlement exists to replace"
                    )
                generation = 1
            record = {
                **exact,
                "state": "prepare_requested",
                "generation": generation,
                "prepare_idempotency_hash": request_hash,
                "replace_expired": replace_expired,
                "prepare_requested_at": timestamp,
                "plan_commitment": None,
                "authorization_expires_at": None,
                "broadcast_idempotency_hash": None,
                "broadcast_hint": None,
                "finalized_settlement": None,
                "terminal_evidence": None,
                "failure_code": None,
                "retryable": True,
                "updated_at": timestamp,
            }
            self._validate_record(record)
            body["records"][exact["execution_id"]] = record
            body["sequence"] += 1
            self._write_unlocked(body)
            return self._public(record, wallet_plan=None)

    def claim_next(self, *, claimed_at: int) -> dict[str, Any] | None:
        timestamp = _integer(claimed_at, "settlement claim time", minimum=1, maximum=4_102_444_800)
        with self._locked():
            body = self._load_unlocked()
            candidates = sorted(
                (
                    record
                    for record in body["records"].values()
                    if record["state"] in {"prepare_requested", "authorizing"}
                ),
                key=lambda item: (item["prepare_requested_at"], item["execution_id"]),
            )
            if not candidates:
                return None
            record = self._validate_record(
                candidates[body["authorization_cursor"] % len(candidates)]
            )
            if record["state"] == "prepare_requested":
                record["state"] = "authorizing"
                record["updated_at"] = timestamp
                body["records"][record["execution_id"]] = record
                body["sequence"] += 1
                self._write_unlocked(body)
            return copy.deepcopy(record)

    def defer_authorization(
        self,
        *,
        execution_id: str,
        generation: int,
    ) -> None:
        """Rotate a temporarily unavailable authorization behind its peers."""

        execution = _pattern(execution_id, _EXECUTION_ID, "execution id")
        generation_value = _integer(
            generation,
            "settlement generation",
            minimum=1,
            maximum=2**63 - 1,
        )
        with self._locked():
            body = self._load_unlocked()
            current = body["records"].get(execution)
            if current is None:
                raise CollaborationRoyaltySettlementConflict(
                    "settlement status does not exist"
                )
            record = self._validate_record(current)
            if (
                record["generation"] != generation_value
                or record["state"] != "authorizing"
            ):
                raise CollaborationRoyaltySettlementConflict(
                    "settlement status changed concurrently"
                )
            body["authorization_cursor"] += 1
            body["sequence"] += 1
            self._write_unlocked(body)

    def mark_plan_ready(
        self,
        *,
        execution_id: str,
        generation: int,
        plan_commitment: str,
        authorization_expires_at: int,
        recorded_at: int,
    ) -> dict[str, Any]:
        return self._transition(
            execution_id=execution_id,
            generation=generation,
            expected={"authorizing", "plan_ready"},
            state="plan_ready",
            updated_at=recorded_at,
            updates={
                "plan_commitment": _pattern(plan_commitment, _BYTES32, "plan commitment"),
                "authorization_expires_at": _integer(
                    authorization_expires_at,
                    "authorization expiry",
                    minimum=1,
                    maximum=4_102_444_800,
                ),
                "failure_code": None,
                "retryable": False,
            },
        )

    def report_broadcast(
        self,
        *,
        execution_id: str,
        sponsor_address: str,
        idempotency_key: str,
        plan_commitment: str,
        transaction_hash: str,
        reported_at: int,
    ) -> dict[str, Any]:
        execution = _pattern(execution_id, _EXECUTION_ID, "execution id")
        sponsor = _pattern(sponsor_address, _ADDRESS, "sponsor address")
        plan = _pattern(plan_commitment, _BYTES32, "plan commitment")
        tx_hash = _pattern(transaction_hash, _BYTES32, "transaction hash")
        timestamp = _integer(reported_at, "broadcast report time", minimum=1, maximum=4_102_444_800)
        idem = _idempotency_hash(execution, "broadcast", idempotency_key)
        with self._locked():
            body = self._load_unlocked()
            current = body["records"].get(execution)
            if current is None:
                raise CollaborationRoyaltySettlementConflict(
                    "settlement plan does not exist"
                )
            record = self._validate_record(current)
            if sponsor != record["sponsor_address"] or plan != record["plan_commitment"]:
                raise CollaborationRoyaltySettlementConflict(
                    "broadcast report does not match the sponsor plan"
                )
            hint = {"transaction_hash": tx_hash, "reported_at": timestamp}
            if record["broadcast_idempotency_hash"] == idem:
                if record["broadcast_hint"]["transaction_hash"] != tx_hash:
                    raise CollaborationRoyaltySettlementConflict(
                        "broadcast idempotency key was reused"
                    )
                return self._public(record, wallet_plan=None)
            if record["broadcast_hint"] is not None or record["state"] not in {
                "plan_ready",
                "settled",
                "expired",
                "reservation_expired",
                "refunded",
                "reconciliation_hold",
            }:
                raise CollaborationRoyaltySettlementConflict(
                    "settlement broadcast cannot be reported in this state"
                )
            next_state = (
                "broadcast_reported"
                if record["state"] == "plan_ready"
                else record["state"]
            )
            record.update(
                {
                    "state": next_state,
                    "broadcast_idempotency_hash": idem,
                    "broadcast_hint": hint,
                    "updated_at": timestamp,
                }
            )
            self._validate_record(record)
            body["records"][execution] = record
            body["sequence"] += 1
            self._write_unlocked(body)
            return self._public(record, wallet_plan=None)

    def mark_finalized(
        self,
        *,
        execution_id: str,
        generation: int,
        finalized_settlement: Mapping[str, Any],
        recorded_at: int,
    ) -> dict[str, Any]:
        self._validate_finalized(finalized_settlement)
        if not (
            finalized_settlement["reservation_consumed"] is True
            and finalized_settlement["settlement_processed"] is True
            and finalized_settlement["settlement_nonce_processed"] is True
            and finalized_settlement["reservation_active"] is False
        ):
            raise CollaborationRoyaltySettlementError(
                "finalized chain state does not prove settlement"
            )
        return self._transition(
            execution_id=execution_id,
            generation=generation,
            expected={"plan_ready", "broadcast_reported", "settled"},
            state="settled",
            updated_at=recorded_at,
            updates={
                "finalized_settlement": copy.deepcopy(dict(finalized_settlement)),
                "failure_code": None,
                "retryable": False,
            },
        )

    def mark_expired(self, *, execution_id: str, generation: int, recorded_at: int) -> dict[str, Any]:
        return self._transition(
            execution_id=execution_id,
            generation=generation,
            expected={"authorizing", "plan_ready", "broadcast_reported", "expired"},
            state="expired",
            updated_at=recorded_at,
            updates={"failure_code": "authorization_expired", "retryable": True},
        )

    def mark_refunded(
        self,
        *,
        execution_id: str,
        generation: int,
        terminal_evidence: Mapping[str, Any],
        recorded_at: int,
    ) -> dict[str, Any]:
        self._validate_terminal_evidence(terminal_evidence)
        if terminal_evidence["outcome"] != "reservation_refunded":
            raise CollaborationRoyaltySettlementError(
                "finalized chain state does not prove a refund"
            )
        return self._transition(
            execution_id=execution_id,
            generation=generation,
            expected={
                "prepare_requested",
                "authorizing",
                "plan_ready",
                "broadcast_reported",
                "expired",
                "reservation_expired",
                "refunded",
            },
            state="refunded",
            updated_at=recorded_at,
            updates={
                "terminal_evidence": copy.deepcopy(dict(terminal_evidence)),
                "failure_code": "reservation_refunded",
                "retryable": False,
            },
        )

    def mark_reservation_expired(
        self,
        *,
        execution_id: str,
        generation: int,
        terminal_evidence: Mapping[str, Any],
        recorded_at: int,
    ) -> dict[str, Any]:
        self._validate_terminal_evidence(terminal_evidence)
        if terminal_evidence["outcome"] != "reservation_expired":
            raise CollaborationRoyaltySettlementError(
                "finalized chain state does not prove reservation expiry"
            )
        return self._transition(
            execution_id=execution_id,
            generation=generation,
            expected={
                "prepare_requested",
                "authorizing",
                "plan_ready",
                "broadcast_reported",
                "expired",
                "reservation_expired",
            },
            state="reservation_expired",
            updated_at=recorded_at,
            updates={
                "terminal_evidence": copy.deepcopy(dict(terminal_evidence)),
                "failure_code": "reservation_expired",
                "retryable": False,
            },
        )

    def mark_hold(
        self,
        *,
        execution_id: str,
        generation: int,
        failure_code: str,
        retryable: bool,
        recorded_at: int,
    ) -> dict[str, Any]:
        code = _pattern(failure_code, _FAILURE, "failure code")
        if type(retryable) is not bool:
            raise CollaborationRoyaltySettlementError("retryable flag is invalid")
        return self._transition(
            execution_id=execution_id,
            generation=generation,
            expected={
                "prepare_requested",
                "authorizing",
                "plan_ready",
                "broadcast_reported",
                "expired",
                "reconciliation_hold",
            },
            state="reconciliation_hold",
            updated_at=recorded_at,
            updates={"failure_code": code, "retryable": retryable},
        )

    def _transition(
        self,
        *,
        execution_id: str,
        generation: int,
        expected: set[str],
        state: str,
        updated_at: int,
        updates: Mapping[str, Any],
    ) -> dict[str, Any]:
        execution = _pattern(execution_id, _EXECUTION_ID, "execution id")
        generation_value = _integer(generation, "settlement generation", minimum=1, maximum=2**63 - 1)
        timestamp = _integer(updated_at, "settlement update time", minimum=1, maximum=4_102_444_800)
        with self._locked():
            body = self._load_unlocked()
            current = body["records"].get(execution)
            if current is None:
                raise CollaborationRoyaltySettlementConflict("settlement status does not exist")
            record = self._validate_record(current)
            if record["generation"] != generation_value or record["state"] not in expected:
                raise CollaborationRoyaltySettlementConflict("settlement status changed concurrently")
            if record["state"] == state:
                if any(record.get(key) != value for key, value in updates.items()):
                    raise CollaborationRoyaltySettlementConflict(
                        "settlement transition replay changed"
                    )
                return self._public(record, wallet_plan=None)
            record.update(copy.deepcopy(dict(updates)))
            record["state"] = state
            record["updated_at"] = timestamp
            self._validate_record(record)
            body["records"][execution] = record
            body["sequence"] += 1
            self._write_unlocked(body)
            return self._public(record, wallet_plan=None)

    def record(self, execution_id: str) -> dict[str, Any] | None:
        execution = _pattern(execution_id, _EXECUTION_ID, "execution id")
        with self._locked():
            body = self._load_unlocked()
            current = body["records"].get(execution)
            return None if current is None else self._validate_record(current)

    def next_reconciliation(self) -> dict[str, Any] | None:
        """Return one immutable plan state for bounded finalized polling.

        Authorization expiry does not end chain observation: a reservation can
        later become exactly refundable or permanently refunded. The durable
        store sequence is also the round-robin cursor, so one slow transaction
        cannot starve every later settlement.
        """

        with self._locked():
            body = self._load_unlocked()
            candidates = sorted(
                (
                    self._validate_record(record)
                    for record in body["records"].values()
                    if record["state"]
                    in {
                        "prepare_requested",
                        "authorizing",
                        "plan_ready",
                        "broadcast_reported",
                        "expired",
                        "reservation_expired",
                    }
                ),
                key=lambda item: (
                    item["prepare_requested_at"],
                    item["execution_id"],
                ),
            )
            if not candidates:
                return None
            return copy.deepcopy(
                candidates[body["reconciliation_cursor"] % len(candidates)]
            )

    def defer_reconciliation(
        self,
        *,
        execution_id: str,
        generation: int,
    ) -> None:
        """Advance the durable round-robin cursor after a nonterminal read."""

        execution = _pattern(execution_id, _EXECUTION_ID, "execution id")
        generation_value = _integer(
            generation,
            "settlement generation",
            minimum=1,
            maximum=2**63 - 1,
        )
        with self._locked():
            body = self._load_unlocked()
            current = body["records"].get(execution)
            if current is None:
                raise CollaborationRoyaltySettlementConflict(
                    "settlement status does not exist"
                )
            record = self._validate_record(current)
            if (
                record["generation"] != generation_value
                or record["state"]
                not in {
                    "prepare_requested",
                    "authorizing",
                    "plan_ready",
                    "broadcast_reported",
                    "expired",
                    "reservation_expired",
                }
            ):
                raise CollaborationRoyaltySettlementConflict(
                    "settlement status changed concurrently"
                )
            body["reconciliation_cursor"] += 1
            body["sequence"] += 1
            self._write_unlocked(body)

    def status(
        self,
        *,
        authority: Mapping[str, Any],
        sponsor_address: str,
        wallet_plan: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        exact = _execution_authority(authority)
        if _pattern(sponsor_address, _ADDRESS, "sponsor address") != exact["sponsor_address"]:
            raise CollaborationRoyaltySettlementError(
                "only the execution sponsor may view settlement"
            )
        with self._locked():
            body = self._load_unlocked()
            current = body["records"].get(exact["execution_id"])
            if current is None:
                return self._not_requested(exact)
            record = self._validate_record(current)
            if any(record[key] != exact[key] for key in exact):
                raise CollaborationRoyaltySettlementConflict(
                    "settlement execution authority changed"
                )
            return self._public(record, wallet_plan=wallet_plan)

    @staticmethod
    def _not_requested(authority: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema": STATUS_SCHEMA,
            **{
                key: (
                    str(value)
                    if key in {"settlement_nonce", "refund_after"}
                    else value
                )
                for key, value in authority.items()
            },
            "state": "not_requested",
            "generation": "0",
            "prepare_requested_at": None,
            "plan_commitment": None,
            "authorization_expires_at": None,
            "wallet_plan": None,
            "broadcast_hint": None,
            "finalized_settlement": None,
            "terminal_evidence": None,
            "failure_code": None,
            "retryable": True,
            "modeled": False,
            "raw_secret_egress": False,
        }

    @staticmethod
    def _public(record: Mapping[str, Any], *, wallet_plan: Mapping[str, Any] | None) -> dict[str, Any]:
        finalized = record["finalized_settlement"]
        finalized_public = None
        if finalized is not None:
            finalized_public = {
                **copy.deepcopy(dict(finalized)),
                "block_number": str(finalized["block_number"]),
                "block_timestamp": str(finalized["block_timestamp"]),
            }
        hint = record["broadcast_hint"]
        hint_public = None if hint is None else {
            "transaction_hash": hint["transaction_hash"],
            "reported_at": str(hint["reported_at"]),
        }
        terminal = record["terminal_evidence"]
        terminal_public = None if terminal is None else {
            **copy.deepcopy(dict(terminal)),
            "block_number": str(terminal["block_number"]),
            "block_timestamp": str(terminal["block_timestamp"]),
            "reservation_deposited_amount": str(
                terminal["reservation_deposited_amount"]
            ),
        }
        return {
            "schema": STATUS_SCHEMA,
            "execution_id": record["execution_id"],
            "sponsor_address": record["sponsor_address"],
            "state": record["state"],
            "generation": str(record["generation"]),
            "funding_reservation_id": record["funding_reservation_id"],
            "settlement_id": record["settlement_id"],
            "settlement_nonce": str(record["settlement_nonce"]),
            "refund_after": str(record["refund_after"]),
            "prepare_requested_at": str(record["prepare_requested_at"]),
            "plan_commitment": record["plan_commitment"],
            "authorization_expires_at": (
                None
                if record["authorization_expires_at"] is None
                else str(record["authorization_expires_at"])
            ),
            "wallet_plan": None if wallet_plan is None else copy.deepcopy(dict(wallet_plan)),
            "broadcast_hint": hint_public,
            "finalized_settlement": finalized_public,
            "terminal_evidence": terminal_public,
            "failure_code": record["failure_code"],
            "retryable": record["retryable"],
            "modeled": False,
            "raw_secret_egress": False,
        }


def collaboration_royalty_settlement_integrity_key(settings: Any) -> bytes:
    explicit = str(
        getattr(
            settings,
            "collaboration_royalty_settlement_store_integrity_key",
            "",
        )
        or ""
    )
    if dstack_utils.is_dstack_enabled():
        if dstack_utils.is_dstack_simulator() or explicit:
            raise CollaborationRoyaltySettlementStoreError(
                "real dstack derived settlement store key is required"
            )
        path = str(
            getattr(
                settings,
                "collaboration_royalty_settlement_store_integrity_key_path",
                "tinker/collaboration_royalty_settlement_store",
            )
            or ""
        ).strip()
        if not path:
            raise CollaborationRoyaltySettlementStoreError(
                "settlement store key path is unavailable"
            )
        try:
            material = dstack_utils.derive_storage_key(path)
        except Exception:
            raise CollaborationRoyaltySettlementStoreError(
                "settlement store key derivation failed"
            ) from None
        return hashlib.sha256(
            b"dnai-wikigen/collaboration-royalty-settlement-store/dstack/v1\0"
            + material
        ).digest()
    if len(explicit.encode("utf-8")) < 32:
        raise CollaborationRoyaltySettlementStoreError(
            "local settlement store key is unavailable"
        )
    return hashlib.sha256(
        b"dnai-wikigen/collaboration-royalty-settlement-store/local/v1\0"
        + explicit.encode("utf-8")
    ).digest()
