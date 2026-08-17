"""Durable, HMAC-authenticated and hash-chained metering replay decisions."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from .errors import ReplayConflict, StateUnavailable
from .models import MeteringDecision
from .policy import canonical_json_bytes, parse_duplicate_free_json


META_DOMAIN = b"dnai-wikigen/compute-metering/replay-meta/v1\x00"
ROW_DOMAIN = b"dnai-wikigen/compute-metering/replay-row/v1\x00"
CHAIN_DOMAIN = b"dnai-wikigen/compute-metering/replay-chain/v1\x00"
ZERO_HEAD = "00" * 32
MAX_DECISION_BYTES = 16 * 1024
MAX_DATABASE_BYTES = 256 * 1024 * 1024
HEX32_RE = re.compile(r"^0x[0-9a-f]{64}$")


def _mac(key: bytes, *parts: bytes) -> bytes:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _meta_mac(key: bytes, name: str, value: bytes) -> bytes:
    return _mac(key, META_DOMAIN, name.encode("ascii"), b"\x00", value)


def _row_mac(
    key: bytes,
    *,
    sequence: int,
    job_id: str,
    usage_commitment: str,
    request_hash: str,
    decision_json: bytes,
) -> bytes:
    return _mac(
        key,
        ROW_DOMAIN,
        sequence.to_bytes(8, "big"),
        bytes.fromhex(job_id[2:]),
        bytes.fromhex(usage_commitment[2:]),
        bytes.fromhex(request_hash[2:]),
        len(decision_json).to_bytes(4, "big"),
        decision_json,
    )


def _chain_mac(key: bytes, *, previous: bytes, row_mac: bytes, sequence: int) -> bytes:
    return _mac(key, CHAIN_DOMAIN, previous, row_mac, sequence.to_bytes(8, "big"))


def _state_bytes(count: int, head: str) -> bytes:
    return canonical_json_bytes({"count": count, "head": head})


def _decode_state(value: bytes) -> tuple[int, str]:
    try:
        decoded = parse_duplicate_free_json(value)
    except Exception as exc:
        raise StateUnavailable from exc
    if not isinstance(decoded, dict) or set(decoded) != {"count", "head"}:
        raise StateUnavailable
    count = decoded["count"]
    head = decoded["head"]
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or not 0 <= count <= 2**63 - 1
        or not isinstance(head, str)
        or not re.fullmatch(r"[0-9a-f]{64}", head)
    ):
        raise StateUnavailable
    if _state_bytes(count, head) != value:
        raise StateUnavailable
    return count, head


def _validate_decision_bytes(value: bytes) -> MeteringDecision:
    if not 2 <= len(value) <= MAX_DECISION_BYTES:
        raise StateUnavailable
    try:
        decoded = parse_duplicate_free_json(value)
        decision = MeteringDecision.model_validate(decoded, strict=True)
    except Exception as exc:
        raise StateUnavailable from exc
    canonical = canonical_json_bytes(decision.model_dump(mode="json", by_alias=True))
    if canonical != value:
        raise StateUnavailable
    return decision


@dataclass
class DurableReplayStore:
    path: str
    policy_set_hash: str
    _integrity_key: bytes = field(repr=False)
    _connection: sqlite3.Connection | None = field(default=None, init=False, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        if len(self._integrity_key) != 32 or not HEX32_RE.fullmatch(self.policy_set_hash):
            raise StateUnavailable
        self._open()

    def _open(self) -> None:
        path = Path(self.path)
        parent = path.parent
        if not path.is_absolute() or path.suffix != ".sqlite3":
            raise StateUnavailable
        try:
            parent_before = os.lstat(parent)
            if (
                not stat.S_ISDIR(parent_before.st_mode)
                or stat.S_ISLNK(parent_before.st_mode)
                or parent_before.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                or parent_before.st_uid != os.geteuid()
            ):
                raise StateUnavailable
            try:
                existing = os.lstat(path)
            except FileNotFoundError:
                descriptor = os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                os.close(descriptor)
                existing = os.lstat(path)
            if (
                not stat.S_ISREG(existing.st_mode)
                or stat.S_ISLNK(existing.st_mode)
                or existing.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                or existing.st_uid != os.geteuid()
                or existing.st_size > MAX_DATABASE_BYTES
            ):
                raise StateUnavailable
            connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None, check_same_thread=False)
            connection.execute("PRAGMA busy_timeout=5000")
            if connection.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
                raise StateUnavailable
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA secure_delete=ON")
            connection.execute("PRAGMA temp_store=MEMORY")
            if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise StateUnavailable
            self._connection = connection
            self._initialize_schema()
            parent_after = os.lstat(parent)
            file_after = os.lstat(path)
            if (
                parent_after.st_dev != parent_before.st_dev
                or parent_after.st_ino != parent_before.st_ino
                or not stat.S_ISREG(file_after.st_mode)
                or stat.S_ISLNK(file_after.st_mode)
            ):
                raise StateUnavailable
        except StateUnavailable:
            self.close()
            raise
        except (OSError, sqlite3.Error) as exc:
            self.close()
            raise StateUnavailable from exc

    @property
    def _db(self) -> sqlite3.Connection:
        if self._connection is None:
            raise StateUnavailable
        return self._connection

    def _initialize_schema(self) -> None:
        db = self._db
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "CREATE TABLE IF NOT EXISTS metadata ("
                "name TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL, mac BLOB NOT NULL) STRICT"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS decisions ("
                "sequence INTEGER PRIMARY KEY NOT NULL,"
                "job_id TEXT UNIQUE NOT NULL,"
                "usage_commitment TEXT UNIQUE NOT NULL,"
                "request_hash TEXT UNIQUE NOT NULL,"
                "decision_json BLOB NOT NULL,"
                "row_mac BLOB NOT NULL,"
                "chain_mac BLOB NOT NULL) STRICT"
            )
            rows = db.execute("SELECT name, value, mac FROM metadata ORDER BY name").fetchall()
            count = db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
            if not rows and count == 0:
                self._set_meta("policy_set_hash", self.policy_set_hash.encode("ascii"))
                self._set_meta("chain_state", _state_bytes(0, ZERO_HEAD))
            else:
                if len(rows) != 2 or {row[0] for row in rows} != {"chain_state", "policy_set_hash"}:
                    raise StateUnavailable
                policy_value = self._get_meta("policy_set_hash")
                if policy_value != self.policy_set_hash.encode("ascii"):
                    raise StateUnavailable
                state_value = self._get_meta("chain_state")
                expected_count, expected_head = _decode_state(state_value)
                self._verify_chain(expected_count=expected_count, expected_head=expected_head)
            db.execute("COMMIT")
        except StateUnavailable:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise StateUnavailable from exc

    def _set_meta(self, name: str, value: bytes) -> None:
        self._db.execute(
            "INSERT INTO metadata(name, value, mac) VALUES(?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET value=excluded.value, mac=excluded.mac",
            (name, value, _meta_mac(self._integrity_key, name, value)),
        )

    def _get_meta(self, name: str) -> bytes:
        row = self._db.execute("SELECT value, mac FROM metadata WHERE name = ?", (name,)).fetchone()
        if row is None or not isinstance(row[0], bytes) or not isinstance(row[1], bytes):
            raise StateUnavailable
        if not secrets.compare_digest(row[1], _meta_mac(self._integrity_key, name, row[0])):
            raise StateUnavailable
        return row[0]

    def _verify_row(self, row: tuple[object, ...]) -> bytes:
        sequence, job_id, usage_commitment, request_hash, decision_json, row_mac, chain_mac = row
        if (
            not isinstance(sequence, int)
            or not isinstance(job_id, str)
            or not HEX32_RE.fullmatch(job_id)
            or not isinstance(usage_commitment, str)
            or not HEX32_RE.fullmatch(usage_commitment)
            or not isinstance(request_hash, str)
            or not HEX32_RE.fullmatch(request_hash)
            or not isinstance(decision_json, bytes)
            or not isinstance(row_mac, bytes)
            or not isinstance(chain_mac, bytes)
            or len(row_mac) != 32
            or len(chain_mac) != 32
        ):
            raise StateUnavailable
        decision = _validate_decision_bytes(decision_json)
        if (
            decision.job_id != job_id
            or decision.usage_commitment != usage_commitment
            or decision.policy_set_hash != self.policy_set_hash
        ):
            raise StateUnavailable
        expected = _row_mac(
            self._integrity_key,
            sequence=sequence,
            job_id=job_id,
            usage_commitment=usage_commitment,
            request_hash=request_hash,
            decision_json=decision_json,
        )
        if not secrets.compare_digest(row_mac, expected):
            raise StateUnavailable
        return decision_json

    def _verify_chain(self, *, expected_count: int, expected_head: str) -> None:
        rows = self._db.execute(
            "SELECT sequence, job_id, usage_commitment, request_hash, decision_json, row_mac, chain_mac "
            "FROM decisions ORDER BY sequence"
        ).fetchall()
        if len(rows) != expected_count:
            raise StateUnavailable
        previous = bytes.fromhex(ZERO_HEAD)
        for expected_sequence, row in enumerate(rows, start=1):
            if row[0] != expected_sequence:
                raise StateUnavailable
            self._verify_row(row)
            expected_chain = _chain_mac(
                self._integrity_key,
                previous=previous,
                row_mac=row[5],
                sequence=expected_sequence,
            )
            if not secrets.compare_digest(row[6], expected_chain):
                raise StateUnavailable
            previous = row[6]
        if previous.hex() != expected_head:
            raise StateUnavailable

    def _lookup_locked(self, job_id: str, usage_commitment: str, request_hash: str) -> bytes | None:
        rows = self._db.execute(
            "SELECT sequence, job_id, usage_commitment, request_hash, decision_json, row_mac, chain_mac "
            "FROM decisions WHERE job_id = ? OR usage_commitment = ? OR request_hash = ?",
            (job_id, usage_commitment, request_hash),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise ReplayConflict
        decision_json = self._verify_row(rows[0])
        if rows[0][1] != job_id or rows[0][2] != usage_commitment or rows[0][3] != request_hash:
            raise ReplayConflict
        return decision_json

    def _verify_current_chain_locked(self) -> None:
        count, head = _decode_state(self._get_meta("chain_state"))
        self._verify_chain(expected_count=count, expected_head=head)

    def lookup(self, *, job_id: str, usage_commitment: str, request_hash: str) -> bytes | None:
        if not all(HEX32_RE.fullmatch(value) for value in (job_id, usage_commitment, request_hash)):
            raise StateUnavailable
        with self._lock:
            try:
                self._verify_current_chain_locked()
                return self._lookup_locked(job_id, usage_commitment, request_hash)
            except (ReplayConflict, StateUnavailable):
                raise
            except sqlite3.Error as exc:
                raise StateUnavailable from exc

    def record(
        self,
        *,
        job_id: str,
        usage_commitment: str,
        request_hash: str,
        decision_json: bytes,
    ) -> bytes:
        if not all(HEX32_RE.fullmatch(value) for value in (job_id, usage_commitment, request_hash)):
            raise StateUnavailable
        decision = _validate_decision_bytes(decision_json)
        if (
            decision.job_id != job_id
            or decision.usage_commitment != usage_commitment
            or decision.policy_set_hash != self.policy_set_hash
        ):
            raise StateUnavailable
        with self._lock:
            db = self._db
            try:
                db.execute("BEGIN IMMEDIATE")
                self._verify_current_chain_locked()
                prior = self._lookup_locked(job_id, usage_commitment, request_hash)
                if prior is not None:
                    db.execute("COMMIT")
                    return prior
                count, head = _decode_state(self._get_meta("chain_state"))
                sequence = count + 1
                row_mac = _row_mac(
                    self._integrity_key,
                    sequence=sequence,
                    job_id=job_id,
                    usage_commitment=usage_commitment,
                    request_hash=request_hash,
                    decision_json=decision_json,
                )
                chain_mac = _chain_mac(
                    self._integrity_key,
                    previous=bytes.fromhex(head),
                    row_mac=row_mac,
                    sequence=sequence,
                )
                db.execute(
                    "INSERT INTO decisions(sequence, job_id, usage_commitment, request_hash, decision_json, row_mac, chain_mac) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?)",
                    (sequence, job_id, usage_commitment, request_hash, decision_json, row_mac, chain_mac),
                )
                self._set_meta("chain_state", _state_bytes(sequence, chain_mac.hex()))
                db.execute("COMMIT")
                db.execute("PRAGMA wal_checkpoint(FULL)")
                return decision_json
            except (ReplayConflict, StateUnavailable):
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
            except sqlite3.IntegrityError as exc:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise ReplayConflict from exc
            except sqlite3.Error as exc:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise StateUnavailable from exc

    def close(self) -> None:
        with self._lock:
            connection = self._connection
            self._connection = None
            if connection is not None:
                try:
                    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass
                connection.close()
