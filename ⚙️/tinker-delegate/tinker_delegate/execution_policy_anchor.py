"""Base Sepolia rollback witness for execution-policy decisions.

The HMAC-authenticated policy store detects mutation but, by itself, cannot
distinguish the newest file from an older valid snapshot.  This module binds
the store's global sequence and deterministic decision chain to the
``ExecutionPolicyAnchor`` contract.  All reads are made at one canonical block
hash, every production write is signed by a purpose-separated dstack-derived
identity, and an unavailable or inconsistent witness always fails closed.

Only opaque resource and decision commitments are sent to the chain.  Raw
resource identifiers, policies, requests, artifacts, and evaluator output are
never accepted by this module.
"""

from __future__ import annotations

import hashlib
import fcntl
import ipaddress
import json
import os
import re
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import urlparse

import httpx
from eth_account import Account
from eth_hash.auto import keccak
from eth_utils import to_checksum_address

from tinker_delegate import dstack_utils


BASE_SEPOLIA_CHAIN_ID = 84_532
EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH = (
    "tinker/execution_policy_anchor_writer"
)
ZERO_BYTES32 = "0x" + "00" * 32
ZERO_ADDRESS = "0x" + "00" * 20
MAX_RPC_RESPONSE_BYTES = 512 * 1024
MAX_RUNTIME_CODE_BYTES = 512 * 1024
MAX_CALL_RESULT_BYTES = 64 * 1024
MAX_TRANSACTION_GAS = 500_000
MAX_GAS_PRICE_WEI = 10**15
MIN_CONFIRMATIONS = 2
MAX_CONFIRMATIONS = 256
MIN_MAX_BLOCK_AGE_SECONDS = 30
MAX_MAX_BLOCK_AGE_SECONDS = 3_600
MAX_CONFIRMATION_WAIT_SECONDS = 120
MAX_POLICY_LEASE_WAIT_SECONDS = 125.0

_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_BARE_HASH = re.compile(r"^[0-9a-f]{64}$")
_HEX_DATA = re.compile(r"^0x(?:[0-9a-f]{2})*$")

_OWNER = keccak(b"owner()")[:4]
_PENDING_OWNER = keccak(b"pendingOwner()")[:4]
_WRITER = keccak(b"writer()")[:4]
_WRITER_RELEASE = keccak(b"writerReleaseCommitment()")[:4]
_PENDING_WRITER = keccak(b"pendingWriter()")[:4]
_PENDING_WRITER_RELEASE = keccak(b"pendingWriterReleaseCommitment()")[:4]
_PENDING_WRITER_AT = keccak(b"pendingWriterActivatesAt()")[:4]
_WRITER_ROTATIONS_FROZEN = keccak(b"writerRotationsFrozen()")[:4]
_PAUSED = keccak(b"paused()")[:4]
_GLOBAL_SEQUENCE = keccak(b"globalSequence()")[:4]
_GLOBAL_HEAD = keccak(b"globalHead()")[:4]
_RESOURCE_DECISION_HEAD = keccak(b"resourceDecisionHead(bytes32)")[:4]
_RESOURCE_SEQUENCE = keccak(b"resourceSequence(bytes32)")[:4]
_DECISION_SEQUENCE = keccak(b"decisionSequence(bytes32)")[:4]
_ANCHOR_DECISION = keccak(
    b"anchorDecision(uint256,bytes32,bytes32,bytes32,bytes32,bytes32)"
)[:4]
_ANCHOR_TYPEHASH = keccak(
    b"ExecutionPolicyAnchor(uint256 chainId,address anchor,uint256 sequence,"
    b"bytes32 previousGlobalHead,bytes32 resourceHash,bytes32 "
    b"previousResourceHead,bytes32 decisionHash,address writer,bytes32 "
    b"writerReleaseCommitment)"
)


class ExecutionPolicyAnchorError(RuntimeError):
    """Base error for rollback-witness verification and writes."""


class ExecutionPolicyAnchorUnavailable(ExecutionPolicyAnchorError):
    """The bounded RPC or dstack writer is temporarily unavailable."""


class ExecutionPolicyAnchorMismatch(ExecutionPolicyAnchorError):
    """The chain witness, release pins, or local journal disagree."""


class ExecutionPolicyAnchorSignerUnavailable(ExecutionPolicyAnchorError):
    """A production dstack writer identity cannot be obtained."""


class ExecutionPolicyAnchorSigner(Protocol):
    address: str
    custody: str

    def sign_transaction(self, transaction: dict[str, Any]):
        """Return an eth-account compatible signed transaction."""


@dataclass(frozen=True)
class AnchorProjectionRecord:
    sequence: int
    resource_id_hash: str
    decision_hash: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AnchorProjectionRecord":
        if not isinstance(value, Mapping):
            raise ExecutionPolicyAnchorMismatch("policy projection record is invalid")
        sequence = _integer(value.get("sequence"), "local sequence", minimum=1)
        return cls(
            sequence=sequence,
            resource_id_hash=_bare_hash(
                value.get("resource_id_hash"), "resource commitment"
            ),
            decision_hash=_bare_hash(
                value.get("decision_hash"), "decision commitment"
            ),
        )


@dataclass(frozen=True)
class AnchorProjection:
    sequence: int
    global_head: str
    resource_heads: Mapping[str, tuple[str, int]]


@dataclass(frozen=True)
class ExecutionPolicyAnchorSnapshot:
    chain_id: int
    block_number: int
    block_hash: str
    block_timestamp: int
    contract_address: str
    runtime_code_hash: str
    owner: str
    pending_owner: str
    writer: str
    writer_release_commitment: str
    pending_writer: str
    pending_writer_release_commitment: str
    pending_writer_activates_at: int
    writer_rotations_frozen: bool
    paused: bool
    global_sequence: int
    global_head: str
    resource_id_hash: str = ""
    resource_decision_head: str = ""
    resource_sequence: int = 0
    decision_hash: str = ""
    decision_sequence: int = 0
    latest_block_number: int = 0
    rpc_finalized_block_number: int = 0
    rpc_finalized_block_hash: str = ZERO_BYTES32
    minimum_confirmation_depth: int = 0
    observed_confirmation_depth: int = 0

    def to_bounded_dict(self) -> dict[str, Any]:
        return {
            "schema": "dnai-wikigen/execution-policy-anchor-status/v1",
            "status": "rpc_reported_finalized_release_match",
            "verification_model": (
                "single_rpc_reported_finalized_with_confirmation_depth"
            ),
            "chain_id": self.chain_id,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "block_timestamp": self.block_timestamp,
            "contract_address": self.contract_address,
            "runtime_code_hash": self.runtime_code_hash,
            "writer": self.writer,
            "writer_release_commitment": self.writer_release_commitment,
            "writer_rotations_frozen": self.writer_rotations_frozen,
            "paused": self.paused,
            "global_sequence": self.global_sequence,
            "global_head": self.global_head,
            "resource_id_hash": self.resource_id_hash,
            "resource_decision_head": self.resource_decision_head,
            "resource_sequence": self.resource_sequence,
            "decision_hash": self.decision_hash,
            "decision_sequence": self.decision_sequence,
            "latest_block_number": self.latest_block_number,
            "rpc_finalized_block_number": self.rpc_finalized_block_number,
            "rpc_finalized_block_hash": self.rpc_finalized_block_hash,
            "minimum_confirmation_depth": self.minimum_confirmation_depth,
            "observed_confirmation_depth": self.observed_confirmation_depth,
            "independent_rpc_quorum_verified": False,
            "consensus_proof_verified": False,
            "opaque_commitments_only": True,
            "raw_resource_id_egress": False,
            "raw_policy_egress": False,
        }


@dataclass(frozen=True)
class PreparedAnchorTransaction:
    tx_hash: str
    raw_transaction: str
    expected_global_sequence: int
    expected_global_head: str
    resource_id_hash: str
    expected_resource_head: str
    decision_hash: str
    target_sequence: int
    target_global_head: str


class DstackExecutionPolicyAnchorSigner:
    """Purpose-separated secp256k1 signer derived only inside real dstack."""

    custody = "dstack_derived_execution_policy_anchor_writer"

    def __init__(self, private_key: bytes) -> None:
        self._account = Account.from_key(private_key)
        self.address = self._account.address

    @classmethod
    def from_settings(cls, settings: Any) -> "DstackExecutionPolicyAnchorSigner":
        if (
            not dstack_utils.is_dstack_enabled()
            or dstack_utils.is_dstack_simulator()
        ):
            raise ExecutionPolicyAnchorSignerUnavailable(
                "real dstack is required for execution-policy anchor signing"
            )
        path = str(
            getattr(
                settings,
                "execution_policy_anchor_writer_key_path",
                EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH,
            )
            or ""
        ).strip()
        if path != EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH:
            raise ExecutionPolicyAnchorSignerUnavailable(
                "execution-policy anchor writer key path is not release-pinned"
            )
        try:
            material = dstack_utils.derive_storage_key(path)
        except Exception:
            raise ExecutionPolicyAnchorSignerUnavailable(
                "execution-policy anchor dstack key derivation failed"
            ) from None
        if not isinstance(material, bytes) or not material:
            raise ExecutionPolicyAnchorSignerUnavailable(
                "execution-policy anchor dstack key derivation returned no material"
            )
        # A distinct domain prevents the same dstack material from becoming a
        # signer for any other chain boundary.
        order = int(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        seed = hashlib.sha256(
            b"dnai-wikigen/dstack/execution-policy-anchor-writer/v1\0"
            + path.encode("utf-8")
            + b"\0"
            + material
        ).digest()
        scalar = (int.from_bytes(seed, "big") % (order - 1)) + 1
        return cls(scalar.to_bytes(32, "big"))

    def sign_transaction(self, transaction: dict[str, Any]):
        return self._account.sign_transaction(transaction)


class _RpcRejected(ExecutionPolicyAnchorUnavailable):
    def __init__(self, message: str) -> None:
        super().__init__("bounded Base Sepolia RPC rejected request")
        self.rpc_message = message.lower()[:256]


class HttpsExecutionPolicyAnchorGateway:
    """Strict EIP-1898 reader and optional dstack-only anchor writer."""

    chain_id = BASE_SEPOLIA_CHAIN_ID

    def __init__(
        self,
        rpc_url: str,
        *,
        contract_address: str,
        runtime_code_hash: str,
        writer_address: str,
        writer_release_commitment: str,
        confirmations: int,
        max_block_age_seconds: int,
        max_future_block_skew_seconds: int,
        signer: ExecutionPolicyAnchorSigner | None = None,
        poll_interval_seconds: float = 1.0,
        confirmation_wait_seconds: float = 60.0,
        client: httpx.Client | None = None,
        allow_plain_http_for_test: bool = False,
    ) -> None:
        self.rpc_url = _bounded_url(
            rpc_url, allow_plain_http_for_test=allow_plain_http_for_test
        )
        self.contract_address = _address(contract_address, allow_zero=False)
        self.runtime_code_hash = _bytes32(runtime_code_hash, allow_zero=False)
        self.writer_address = _address(writer_address, allow_zero=False)
        self.writer_release_commitment = _bytes32(
            writer_release_commitment, allow_zero=False
        )
        self.confirmations = _integer(
            confirmations,
            "anchor confirmations",
            minimum=MIN_CONFIRMATIONS,
            maximum=MAX_CONFIRMATIONS,
        )
        self.max_block_age_seconds = _integer(
            max_block_age_seconds,
            "anchor max block age",
            minimum=MIN_MAX_BLOCK_AGE_SECONDS,
            maximum=MAX_MAX_BLOCK_AGE_SECONDS,
        )
        self.max_future_block_skew_seconds = _integer(
            max_future_block_skew_seconds,
            "anchor future block skew",
            minimum=0,
            maximum=300,
        )
        if (
            isinstance(poll_interval_seconds, bool)
            or not isinstance(poll_interval_seconds, (int, float))
            or not 0.05 <= float(poll_interval_seconds) <= 10.0
        ):
            raise ExecutionPolicyAnchorMismatch("anchor poll interval is invalid")
        if (
            isinstance(confirmation_wait_seconds, bool)
            or not isinstance(confirmation_wait_seconds, (int, float))
            or not 1.0
            <= float(confirmation_wait_seconds)
            <= MAX_CONFIRMATION_WAIT_SECONDS
        ):
            raise ExecutionPolicyAnchorMismatch(
                "anchor confirmation wait is invalid"
            )
        self.poll_interval_seconds = float(poll_interval_seconds)
        self.confirmation_wait_seconds = float(confirmation_wait_seconds)
        self.signer = signer
        if signer is not None:
            signer_address = _address(signer.address, allow_zero=False)
            if signer_address != self.writer_address:
                raise ExecutionPolicyAnchorMismatch(
                    "dstack anchor signer does not match the release writer"
                )
            if signer.custody != "dstack_derived_execution_policy_anchor_writer":
                if not allow_plain_http_for_test:
                    raise ExecutionPolicyAnchorSignerUnavailable(
                        "execution-policy anchor signer is not dstack-derived"
                    )
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(20.0, connect=10.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None
        self._next_id = 1
        observed_chain = _quantity(self._rpc("eth_chainId", []), "chain ID")
        if observed_chain != self.chain_id:
            self.close()
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy anchor is not on Base Sepolia"
            )

    @classmethod
    def from_settings(
        cls,
        settings: Any,
        *,
        read_only: bool,
        client: httpx.Client | None = None,
    ) -> "HttpsExecutionPolicyAnchorGateway":
        signer = None
        if not read_only:
            signer = DstackExecutionPolicyAnchorSigner.from_settings(settings)
        return cls(
            str(getattr(settings, "execution_policy_anchor_rpc_url", "") or ""),
            contract_address=str(
                getattr(settings, "execution_policy_anchor_address", "") or ""
            ),
            runtime_code_hash=str(
                getattr(
                    settings, "execution_policy_anchor_runtime_code_hash", ""
                )
                or ""
            ),
            writer_address=str(
                getattr(settings, "execution_policy_anchor_writer_address", "")
                or ""
            ),
            writer_release_commitment=str(
                getattr(
                    settings,
                    "execution_policy_anchor_writer_release_commitment",
                    "",
                )
                or ""
            ),
            confirmations=getattr(
                settings, "execution_policy_anchor_confirmations", 12
            ),
            max_block_age_seconds=getattr(
                settings, "execution_policy_anchor_max_block_age_seconds", 3_600
            ),
            max_future_block_skew_seconds=getattr(
                settings,
                "execution_policy_anchor_max_future_block_skew_seconds",
                30,
            ),
            poll_interval_seconds=getattr(
                settings, "execution_policy_anchor_poll_interval_seconds", 1.0
            ),
            confirmation_wait_seconds=getattr(
                settings,
                "execution_policy_anchor_confirmation_wait_seconds",
                60.0,
            ),
            signer=signer,
            client=client,
        )

    @property
    def read_only(self) -> bool:
        return self.signer is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def finalized_snapshot(
        self,
        *,
        resource_id_hash: str = "",
        decision_hash: str = "",
        now: int | None = None,
    ) -> ExecutionPolicyAnchorSnapshot:
        rpc_finalized = self._block("finalized")
        latest = self._block("latest")
        if rpc_finalized["number"] > latest["number"]:
            raise ExecutionPolicyAnchorMismatch(
                "Base Sepolia RPC finalized head is ahead of latest"
            )
        confirmation_bound = latest["number"] - self.confirmations + 1
        if confirmation_bound < 0:
            raise ExecutionPolicyAnchorUnavailable(
                "Base Sepolia has insufficient finalized history"
            )
        selected_number = min(rpc_finalized["number"], confirmation_bound)
        if selected_number == rpc_finalized["number"]:
            block = rpc_finalized
        elif selected_number == latest["number"]:
            block = latest
        else:
            block = self._block(selected_number)
        return self._snapshot_at(
            block,
            resource_id_hash=resource_id_hash,
            decision_hash=decision_hash,
            now=now,
            latest_block_number=latest["number"],
            rpc_finalized_block_number=rpc_finalized["number"],
            rpc_finalized_block_hash=rpc_finalized["hash"],
        )

    def latest_snapshot(
        self,
        *,
        resource_id_hash: str = "",
        decision_hash: str = "",
        now: int | None = None,
    ) -> ExecutionPolicyAnchorSnapshot:
        return self._snapshot_at(
            self._block("latest"),
            resource_id_hash=resource_id_hash,
            decision_hash=decision_hash,
            now=now,
        )

    def prepare_anchor(
        self,
        *,
        snapshot: ExecutionPolicyAnchorSnapshot,
        resource_id_hash: str,
        decision_hash: str,
    ) -> PreparedAnchorTransaction:
        if self.signer is None:
            raise ExecutionPolicyAnchorSignerUnavailable(
                "execution-policy anchor writer is unavailable in read-only mode"
            )
        resource = _bare_hash(resource_id_hash, "resource commitment")
        decision = _bare_hash(decision_hash, "decision commitment")
        if snapshot.resource_id_hash != resource:
            raise ExecutionPolicyAnchorMismatch(
                "anchor resource snapshot does not match the decision"
            )
        target_sequence = snapshot.global_sequence + 1
        target_head = compute_anchor_head(
            contract_address=self.contract_address,
            sequence=target_sequence,
            previous_global_head=snapshot.global_head,
            resource_id_hash=resource,
            previous_resource_head=snapshot.resource_decision_head,
            decision_hash=decision,
            writer_address=self.writer_address,
            writer_release_commitment=self.writer_release_commitment,
        )
        data = b"".join(
            (
                _ANCHOR_DECISION,
                _uint_word(snapshot.global_sequence),
                _bytes32_word(snapshot.global_head),
                _bytes32_word(resource),
                _bytes32_word(snapshot.resource_decision_head),
                _bytes32_word(decision),
                _bytes32_word(self.writer_release_commitment),
            )
        )
        nonce = _quantity(
            self._rpc(
                "eth_getTransactionCount", [self.writer_address, "latest"]
            ),
            "confirmed nonce",
        )
        gas_price = _quantity(self._rpc("eth_gasPrice", []), "gas price")
        if gas_price <= 0 or gas_price > MAX_GAS_PRICE_WEI:
            raise ExecutionPolicyAnchorMismatch(
                "Base Sepolia gas price is outside the anchor bound"
            )
        call = {
            "from": self.writer_address,
            "to": self.contract_address,
            "value": "0x0",
            "data": "0x" + data.hex(),
        }
        estimated = _quantity(
            self._rpc("eth_estimateGas", [call]), "estimated gas"
        )
        gas = max(21_000, (estimated * 12 + 9) // 10)
        if gas > MAX_TRANSACTION_GAS:
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy anchor transaction gas exceeds the bound"
            )
        transaction = {
            "chainId": self.chain_id,
            "nonce": nonce,
            "gasPrice": gas_price,
            "gas": gas,
            "to": to_checksum_address(self.contract_address),
            "value": 0,
            "data": data,
        }
        try:
            signed = self.signer.sign_transaction(transaction)
            raw_value = getattr(signed, "raw_transaction", None)
            if raw_value is None:
                raw_value = getattr(signed, "rawTransaction", None)
            raw = bytes(raw_value)
        except Exception:
            raise ExecutionPolicyAnchorSignerUnavailable(
                "dstack execution-policy anchor transaction signing failed"
            ) from None
        if not raw:
            raise ExecutionPolicyAnchorSignerUnavailable(
                "dstack execution-policy anchor signing returned no bytes"
            )
        return PreparedAnchorTransaction(
            tx_hash="0x" + keccak(raw).hex(),
            raw_transaction="0x" + raw.hex(),
            expected_global_sequence=snapshot.global_sequence,
            expected_global_head=snapshot.global_head,
            resource_id_hash=resource,
            expected_resource_head=snapshot.resource_decision_head,
            decision_hash=decision,
            target_sequence=target_sequence,
            target_global_head=target_head,
        )

    def broadcast(self, prepared: PreparedAnchorTransaction) -> None:
        if not isinstance(prepared, PreparedAnchorTransaction):
            raise ExecutionPolicyAnchorMismatch("prepared anchor transaction is invalid")
        try:
            result = self._rpc(
                "eth_sendRawTransaction", [prepared.raw_transaction]
            )
        except _RpcRejected as exc:
            if any(
                marker in exc.rpc_message
                for marker in (
                    "already known",
                    "known transaction",
                    "already imported",
                )
            ):
                return
            raise ExecutionPolicyAnchorUnavailable(
                "execution-policy anchor broadcast failed"
            ) from None
        if not isinstance(result, str) or result.lower() != prepared.tx_hash:
            raise ExecutionPolicyAnchorMismatch(
                "anchor RPC returned the wrong transaction hash"
            )

    def anchor_record(
        self,
        *,
        prefix: AnchorProjection,
        record: AnchorProjectionRecord,
        now: int | None = None,
    ) -> ExecutionPolicyAnchorSnapshot:
        """Idempotently append one exact persisted decision and finalize it."""

        clock_started = time.monotonic()

        def validation_now() -> int | None:
            return _advancing_validation_time(now, clock_started)

        if self.read_only:
            raise ExecutionPolicyAnchorSignerUnavailable(
                "read-only anchor verifier cannot reconcile a pending record"
            )
        if record.sequence != prefix.sequence + 1:
            raise ExecutionPolicyAnchorMismatch(
                "only one persisted anchor record can be reconciled"
            )
        expected_target = compute_anchor_head(
            contract_address=self.contract_address,
            sequence=record.sequence,
            previous_global_head=prefix.global_head,
            resource_id_hash=record.resource_id_hash,
            previous_resource_head=prefix.resource_heads.get(
                record.resource_id_hash, (ZERO_BYTES32, 0)
            )[0],
            decision_hash=record.decision_hash,
            writer_address=self.writer_address,
            writer_release_commitment=self.writer_release_commitment,
        )
        latest = self.latest_snapshot(
            resource_id_hash=record.resource_id_hash,
            decision_hash=record.decision_hash,
            now=validation_now(),
        )
        if latest.global_sequence == record.sequence:
            self._verify_target(latest, record, expected_target)
        elif latest.global_sequence == prefix.sequence:
            _verify_projection(prefix, latest)
            previous_resource = prefix.resource_heads.get(
                record.resource_id_hash, (ZERO_BYTES32, 0)
            )
            if (
                latest.resource_decision_head != previous_resource[0]
                or latest.resource_sequence != previous_resource[1]
                or latest.decision_sequence != 0
            ):
                raise ExecutionPolicyAnchorMismatch(
                    "anchor resource head changed before reconciliation"
                )
            prepared = self.prepare_anchor(
                snapshot=latest,
                resource_id_hash=record.resource_id_hash,
                decision_hash=record.decision_hash,
            )
            if (
                prepared.target_sequence != record.sequence
                or prepared.target_global_head != expected_target
            ):
                raise ExecutionPolicyAnchorMismatch(
                    "prepared anchor target does not match the persisted record"
                )
            try:
                self.broadcast(prepared)
            except ExecutionPolicyAnchorUnavailable:
                # A prior identical/replacement transaction may have crossed
                # the boundary between our latest-state read and broadcast.
                # Accept only the exact resulting contract state; otherwise
                # preserve the local one-record gap and fail closed for retry.
                raced = self.latest_snapshot(
                    resource_id_hash=record.resource_id_hash,
                    decision_hash=record.decision_hash,
                    now=validation_now(),
                )
                if raced.global_sequence != record.sequence:
                    raise
                self._verify_target(raced, record, expected_target)
        else:
            raise ExecutionPolicyAnchorMismatch(
                "latest anchor sequence diverges from the local store"
            )

        deadline = time.monotonic() + self.confirmation_wait_seconds
        while True:
            latest = self.latest_snapshot(
                resource_id_hash=record.resource_id_hash,
                decision_hash=record.decision_hash,
                now=validation_now(),
            )
            if latest.global_sequence == record.sequence:
                self._verify_target(latest, record, expected_target)
                finalized = self.finalized_snapshot(
                    resource_id_hash=record.resource_id_hash,
                    decision_hash=record.decision_hash,
                    now=validation_now(),
                )
                if finalized.global_sequence == record.sequence:
                    self._verify_target(finalized, record, expected_target)
                    return finalized
                if finalized.global_sequence != prefix.sequence:
                    raise ExecutionPolicyAnchorMismatch(
                        "finalized anchor sequence diverges during confirmation"
                    )
                _verify_projection(prefix, finalized)
            elif latest.global_sequence != prefix.sequence:
                raise ExecutionPolicyAnchorMismatch(
                    "anchor head changed while waiting for confirmation"
                )
            else:
                _verify_projection(prefix, latest)
            if time.monotonic() >= deadline:
                raise ExecutionPolicyAnchorUnavailable(
                    "execution-policy anchor confirmation timed out"
                )
            time.sleep(self.poll_interval_seconds)

    @staticmethod
    def _verify_target(
        snapshot: ExecutionPolicyAnchorSnapshot,
        record: AnchorProjectionRecord,
        expected_global_head: str,
    ) -> None:
        if (
            snapshot.global_sequence != record.sequence
            or snapshot.global_head != expected_global_head
            or snapshot.resource_decision_head
            != "0x" + record.decision_hash
            or snapshot.resource_sequence != record.sequence
            or snapshot.decision_sequence != record.sequence
        ):
            raise ExecutionPolicyAnchorMismatch(
                "anchored decision does not match the persisted record"
            )

    def _snapshot_at(
        self,
        block: Mapping[str, int | str],
        *,
        resource_id_hash: str,
        decision_hash: str,
        now: int | None,
        latest_block_number: int = 0,
        rpc_finalized_block_number: int = 0,
        rpc_finalized_block_hash: str = ZERO_BYTES32,
    ) -> ExecutionPolicyAnchorSnapshot:
        timestamp = int(time.time() if now is None else now)
        block_timestamp = _integer(
            block["timestamp"], "block timestamp", minimum=1
        )
        if block_timestamp > timestamp + self.max_future_block_skew_seconds:
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy anchor block is future-dated"
            )
        if timestamp - block_timestamp > self.max_block_age_seconds:
            raise ExecutionPolicyAnchorUnavailable(
                "execution-policy anchor block is stale"
            )
        block_hash = _bytes32(block["hash"], allow_zero=False)
        tag = {"blockHash": block_hash, "requireCanonical": True}
        code = _hex_bytes(
            self._rpc("eth_getCode", [self.contract_address, tag]),
            "anchor bytecode",
            MAX_RUNTIME_CODE_BYTES,
        )
        if not code or "0x" + keccak(code).hex() != self.runtime_code_hash:
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy anchor runtime code hash mismatch"
            )
        resource = (
            _bare_hash(resource_id_hash, "resource commitment")
            if resource_id_hash
            else ""
        )
        decision = (
            _bare_hash(decision_hash, "decision commitment")
            if decision_hash
            else ""
        )
        snapshot = ExecutionPolicyAnchorSnapshot(
            chain_id=self.chain_id,
            block_number=_integer(
                block["number"], "block number", minimum=0
            ),
            block_hash=block_hash,
            block_timestamp=block_timestamp,
            contract_address=self.contract_address,
            runtime_code_hash=self.runtime_code_hash,
            owner=_decode_address(self._eth_call(_OWNER, tag), allow_zero=False),
            pending_owner=_decode_address(
                self._eth_call(_PENDING_OWNER, tag), allow_zero=True
            ),
            writer=_decode_address(self._eth_call(_WRITER, tag), allow_zero=False),
            writer_release_commitment=_decode_bytes32(
                self._eth_call(_WRITER_RELEASE, tag)
            ),
            pending_writer=_decode_address(
                self._eth_call(_PENDING_WRITER, tag), allow_zero=True
            ),
            pending_writer_release_commitment=_decode_bytes32(
                self._eth_call(_PENDING_WRITER_RELEASE, tag)
            ),
            pending_writer_activates_at=_decode_uint(
                self._eth_call(_PENDING_WRITER_AT, tag)
            ),
            writer_rotations_frozen=_decode_bool(
                self._eth_call(_WRITER_ROTATIONS_FROZEN, tag)
            ),
            paused=_decode_bool(self._eth_call(_PAUSED, tag)),
            global_sequence=_decode_uint(
                self._eth_call(_GLOBAL_SEQUENCE, tag)
            ),
            global_head=_decode_bytes32(self._eth_call(_GLOBAL_HEAD, tag)),
            resource_id_hash=resource,
            resource_decision_head=(
                _decode_bytes32(
                    self._eth_call(
                        _RESOURCE_DECISION_HEAD + _bytes32_word(resource), tag
                    )
                )
                if resource
                else ""
            ),
            resource_sequence=(
                _decode_uint(
                    self._eth_call(
                        _RESOURCE_SEQUENCE + _bytes32_word(resource), tag
                    )
                )
                if resource
                else 0
            ),
            decision_hash=decision,
            decision_sequence=(
                _decode_uint(
                    self._eth_call(
                        _DECISION_SEQUENCE + _bytes32_word(decision), tag
                    )
                )
                if decision
                else 0
            ),
            latest_block_number=latest_block_number,
            rpc_finalized_block_number=rpc_finalized_block_number,
            rpc_finalized_block_hash=rpc_finalized_block_hash,
            minimum_confirmation_depth=(
                self.confirmations if latest_block_number else 0
            ),
            observed_confirmation_depth=(
                latest_block_number
                - _integer(block["number"], "block number", minimum=0)
                + 1
                if latest_block_number
                else 0
            ),
        )
        self._validate_release_state(snapshot)
        if resource and (
            (snapshot.resource_sequence == 0)
            != (snapshot.resource_decision_head == ZERO_BYTES32)
            or snapshot.resource_sequence > snapshot.global_sequence
        ):
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy anchor resource head is malformed"
            )
        if decision and snapshot.decision_sequence > snapshot.global_sequence:
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy anchor decision sequence is malformed"
            )
        return snapshot

    def _validate_release_state(
        self, snapshot: ExecutionPolicyAnchorSnapshot
    ) -> None:
        if snapshot.writer != self.writer_address:
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy anchor writer does not match the release"
            )
        if snapshot.writer_release_commitment != self.writer_release_commitment:
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy anchor writer release does not match"
            )
        if (
            snapshot.pending_writer != ZERO_ADDRESS
            or snapshot.pending_writer_release_commitment != ZERO_BYTES32
            or snapshot.pending_writer_activates_at != 0
        ):
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy anchor has a pending writer rotation"
            )
        if not snapshot.writer_rotations_frozen:
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy anchor writer rotations are not frozen"
            )
        if snapshot.paused:
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy anchor is paused"
            )
        if (snapshot.global_sequence == 0) != (
            snapshot.global_head == ZERO_BYTES32
        ):
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy anchor global head is malformed"
            )

    def _block(self, number: int | str) -> dict[str, Any]:
        if isinstance(number, str):
            if number not in {"latest", "finalized"}:
                raise ExecutionPolicyAnchorMismatch(
                    "execution-policy anchor block tag is invalid"
                )
            tag = number
        else:
            tag = hex(number)
        value = self._rpc("eth_getBlockByNumber", [tag, False])
        if not isinstance(value, Mapping):
            raise ExecutionPolicyAnchorUnavailable(
                "Base Sepolia anchor block is unavailable"
            )
        observed_number = _quantity(value.get("number"), "block number")
        if isinstance(number, int) and observed_number != number:
            raise ExecutionPolicyAnchorUnavailable(
                "anchor RPC returned a different block"
            )
        return {
            "number": observed_number,
            "timestamp": _quantity(value.get("timestamp"), "block timestamp"),
            "hash": _bytes32(value.get("hash"), allow_zero=False),
        }

    def _eth_call(self, data: bytes, block_tag: Mapping[str, Any]) -> bytes:
        try:
            value = self._rpc(
                "eth_call",
                [
                    {"to": self.contract_address, "data": "0x" + data.hex()},
                    block_tag,
                ],
            )
        except _RpcRejected as exc:
            if "revert" in exc.rpc_message:
                raise ExecutionPolicyAnchorMismatch(
                    "execution-policy anchor read reverted"
                ) from None
            raise
        return _hex_bytes(value, "anchor call result", MAX_CALL_RESULT_BYTES)

    def _rpc(self, method: str, params: list[Any]) -> Any:
        request_id = self._next_id
        self._next_id += 1
        request = self._client.build_request(
            "POST",
            self.rpc_url,
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
            content=_canonical_json(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": params,
                }
            ),
        )
        try:
            response = self._client.send(
                request, stream=True, follow_redirects=False
            )
            try:
                content_type = (
                    response.headers.get("content-type", "")
                    .split(";", 1)[0]
                    .lower()
                )
                if (
                    response.status_code != 200
                    or response.history
                    or not (
                        content_type == "application/json"
                        or content_type.endswith("+json")
                    )
                ):
                    raise ExecutionPolicyAnchorUnavailable(
                        "bounded Base Sepolia RPC is unavailable"
                    )
                raw = _bounded_response_body(response)
            finally:
                response.close()
        except ExecutionPolicyAnchorError:
            raise
        except Exception:
            raise ExecutionPolicyAnchorUnavailable(
                "bounded Base Sepolia RPC is unavailable"
            ) from None
        try:
            payload = json.loads(raw)
        except Exception:
            raise ExecutionPolicyAnchorUnavailable(
                "bounded Base Sepolia RPC returned invalid JSON"
            ) from None
        if (
            not isinstance(payload, Mapping)
            or payload.get("jsonrpc") != "2.0"
            or payload.get("id") != request_id
        ):
            raise ExecutionPolicyAnchorUnavailable(
                "bounded Base Sepolia RPC response binding failed"
            )
        if payload.get("error") is not None:
            error = payload["error"]
            message = error.get("message") if isinstance(error, Mapping) else ""
            raise _RpcRejected(message if isinstance(message, str) else "")
        if "result" not in payload:
            raise ExecutionPolicyAnchorUnavailable(
                "bounded Base Sepolia RPC result is missing"
            )
        return payload["result"]


def verify_live_execution_policy_release_binding(
    settings: Any,
    gateway: HttpsExecutionPolicyAnchorGateway,
) -> None:
    """Cross-bind the approval domain, anchor release, and live dstack app.

    This is a same-CVM consistency check, not an independent QVL verdict.  It
    prevents a running API from accepting Release-A approvals while signing
    Release-B anchors or while its live compose/app identity differs from the
    approval domain selected by the release descriptor.
    """

    from tinker_delegate.execution_policy_store import (
        ExecutionPolicyStoreError,
        execution_policy_approval_domain,
        execution_policy_approval_domain_components,
    )

    try:
        domain = execution_policy_approval_domain(settings)
        components = execution_policy_approval_domain_components(domain)
    except ExecutionPolicyStoreError as exc:
        raise ExecutionPolicyAnchorMismatch(
            "execution-policy approval domain release binding is invalid"
        ) from exc
    if (
        "0x" + components["release_manifest_commitment"]
        != gateway.writer_release_commitment
    ):
        raise ExecutionPolicyAnchorMismatch(
            "approval domain release does not match the anchor writer release"
        )
    report_data = hashlib.sha256(
        b"dnai-wikigen/execution-policy-live-release-binding/v1\0"
        + _canonical_json(
            {
                "anchor_address": gateway.contract_address,
                "approval_domain": domain,
                "chain_id": gateway.chain_id,
                "runtime_code_hash": gateway.runtime_code_hash,
                "writer_address": gateway.writer_address,
                "writer_release_commitment": (
                    gateway.writer_release_commitment
                ),
            }
        )
    ).digest()
    try:
        details = dstack_utils.get_attestation_details(report_data)
        if not isinstance(details, Mapping):
            raise ValueError("dstack details are invalid")
        compose_hash = str(details.get("compose_hash") or "").strip().lower()
        if not compose_hash.startswith("0x"):
            compose_hash = "0x" + compose_hash
        app_id = str(details.get("app_id") or "")
        if not re.fullmatch(r"[\x21-\x7e]{1,128}", app_id):
            raise ValueError("dstack app ID is invalid")
        quote_report_data = str(
            details.get("quote_report_data") or ""
        ).strip().lower()
        if quote_report_data.startswith("0x"):
            quote_report_data = quote_report_data[2:]
        if not re.fullmatch(r"(?:[0-9a-f]{64}|[0-9a-f]{128})", quote_report_data):
            raise ValueError("dstack report data is invalid")
        raw_report_data = bytes.fromhex(quote_report_data)
    except Exception:
        raise ExecutionPolicyAnchorSignerUnavailable(
            "live dstack execution-policy release evidence is unavailable"
        ) from None
    if len(raw_report_data) == 64 and raw_report_data[32:] == b"\0" * 32:
        raw_report_data = raw_report_data[:32]
    if raw_report_data != report_data:
        raise ExecutionPolicyAnchorMismatch(
            "live dstack release evidence report data does not match"
        )
    if compose_hash != components["compose_hash"]:
        raise ExecutionPolicyAnchorMismatch(
            "live dstack compose does not match the approval domain"
        )
    if hashlib.sha256(app_id.encode("utf-8")).hexdigest() != components[
        "app_id_hash"
    ]:
        raise ExecutionPolicyAnchorMismatch(
            "live dstack app ID does not match the approval domain"
        )


class ExecutionPolicyFileLease:
    """Bounded cross-process lease shared by policy writers and executors."""

    def __init__(
        self,
        store_path: str | Path,
        *,
        exclusive: bool,
        timeout_seconds: float = MAX_POLICY_LEASE_WAIT_SECONDS,
    ) -> None:
        path = Path(store_path)
        self.path = path.with_name(f".{path.name}.execution-policy.lock")
        self.exclusive = bool(exclusive)
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0.1 <= float(timeout_seconds) <= MAX_POLICY_LEASE_WAIT_SECONDS
        ):
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy lease timeout is invalid"
            )
        self.timeout_seconds = float(timeout_seconds)
        self._fd: int | None = None

    def __enter__(self) -> "ExecutionPolicyFileLease":
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd: int | None = None
        deadline = time.monotonic() + self.timeout_seconds
        try:
            fd = os.open(self.path, flags, 0o600)
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OSError("policy lease file is not an exclusive regular inode")
            os.fchmod(fd, 0o600)
            operation = fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH
            while True:
                try:
                    fcntl.flock(fd, operation | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ExecutionPolicyAnchorUnavailable(
                            "execution-policy cross-process lease timed out"
                        ) from None
                    time.sleep(0.05)
        except ExecutionPolicyAnchorError:
            if fd is not None:
                os.close(fd)
            raise
        except OSError:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise ExecutionPolicyAnchorUnavailable(
                "execution-policy cross-process lease is unavailable"
            ) from None
        self._fd = fd
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        del exc_type, exc, traceback
        fd = self._fd
        self._fd = None
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


class AnchoredExecutionPolicyCoordinator:
    """Serialize and refresh the journal against its monotonic chain witness."""

    def __init__(self, store: Any, gateway: Any) -> None:
        # Avoid importing the store at module import time and creating a cycle.
        from tinker_delegate.execution_policy_store import ExecutionPolicyStore

        if not isinstance(store, ExecutionPolicyStore):
            raise ExecutionPolicyAnchorMismatch(
                "execution-policy store is required for anchoring"
            )
        self.store = store
        self.gateway = gateway
        self._lock = threading.RLock()

    def close(self) -> None:
        close = getattr(self.gateway, "close", None)
        if callable(close):
            close()

    @contextmanager
    def _policy_lease(self, *, exclusive: bool):
        with self._lock:
            with ExecutionPolicyFileLease(
                self.store.path,
                exclusive=exclusive,
            ):
                self.store.refresh()
                yield

    def _ensure_synchronized_locked(
        self, *, now: int | None, reconcile: bool
    ) -> ExecutionPolicyAnchorSnapshot:
        records = tuple(
            AnchorProjectionRecord.from_mapping(value)
            for value in self.store.anchor_projection()
        )
        projection = compute_anchor_projection(
            records,
            contract_address=self.gateway.contract_address,
            writer_address=self.gateway.writer_address,
            writer_release_commitment=self.gateway.writer_release_commitment,
        )
        last_decision = records[-1].decision_hash if records else ""
        finalized = self.gateway.finalized_snapshot(
            decision_hash=last_decision,
            now=now,
        )
        if finalized.global_sequence > projection.sequence:
            raise ExecutionPolicyAnchorMismatch(
                "on-chain policy sequence is ahead of the local HMAC journal"
            )
        if finalized.global_sequence == projection.sequence:
            _verify_projection(projection, finalized)
            if records and finalized.decision_sequence != projection.sequence:
                raise ExecutionPolicyAnchorMismatch(
                    "latest local policy decision is not anchored at its sequence"
                )
            # Read the canonical head as well, so a pause or an unfinalized
            # foreign append fails before the selected finalized boundary.
            latest = self.gateway.latest_snapshot(
                decision_hash=last_decision,
                now=now,
            )
            _verify_projection(projection, latest)
            if records and latest.decision_sequence != projection.sequence:
                raise ExecutionPolicyAnchorMismatch(
                    "canonical anchor head does not contain the local decision"
                )
            return finalized
        if projection.sequence != finalized.global_sequence + 1:
            raise ExecutionPolicyAnchorMismatch(
                "local policy journal is more than one decision ahead of chain"
            )
        prefix = compute_anchor_projection(
            records[:-1],
            contract_address=self.gateway.contract_address,
            writer_address=self.gateway.writer_address,
            writer_release_commitment=self.gateway.writer_release_commitment,
        )
        _verify_projection(prefix, finalized)
        if not reconcile:
            raise ExecutionPolicyAnchorUnavailable(
                "one local policy decision is awaiting chain anchoring"
            )
        self.gateway.anchor_record(
            prefix=prefix,
            record=records[-1],
            now=now,
        )
        confirmed = self.gateway.finalized_snapshot(
            decision_hash=records[-1].decision_hash,
            now=now,
        )
        _verify_projection(projection, confirmed)
        if confirmed.decision_sequence != projection.sequence:
            raise ExecutionPolicyAnchorMismatch(
                "reconciled policy decision sequence is invalid"
            )
        return confirmed

    def ensure_synchronized(
        self, *, now: int | None = None, reconcile: bool
    ) -> ExecutionPolicyAnchorSnapshot:
        with self._policy_lease(exclusive=reconcile):
            return self._ensure_synchronized_locked(now=now, reconcile=reconcile)

    def append_and_anchor(
        self, *, now: int | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        with self._policy_lease(exclusive=True):
            self._ensure_synchronized_locked(now=now, reconcile=True)
            record = self.store.append(**kwargs)
            snapshot = self._ensure_resource_synchronized_locked(
                surface=kwargs["surface"],
                resource_id=kwargs["resource_id"],
                now=now,
                reconcile=True,
            )
            return {**record, "rollback_anchor": snapshot.to_bounded_dict()}

    def latest_decision_hash(
        self,
        *,
        surface: str,
        resource_id: str,
        now: int | None = None,
    ) -> str:
        reconcile = not self.gateway.read_only
        with self._policy_lease(exclusive=reconcile):
            self._ensure_synchronized_locked(now=now, reconcile=reconcile)
            return self.store.latest_decision_hash(
                surface=surface, resource_id=resource_id
            )

    def latest(
        self,
        *,
        surface: str,
        resource_id: str,
        now: int | None = None,
    ) -> tuple[dict[str, Any] | None, ExecutionPolicyAnchorSnapshot]:
        reconcile = not self.gateway.read_only
        with self._policy_lease(exclusive=reconcile):
            snapshot = self._ensure_resource_synchronized_locked(
                surface=surface,
                resource_id=resource_id,
                now=now,
                reconcile=reconcile,
            )
            return (
                self.store.latest(surface=surface, resource_id=resource_id),
                snapshot,
            )

    def ensure_resource_synchronized(
        self,
        *,
        surface: str,
        resource_id: str,
        now: int | None,
        reconcile: bool,
    ) -> ExecutionPolicyAnchorSnapshot:
        with self._policy_lease(exclusive=reconcile):
            return self._ensure_resource_synchronized_locked(
                surface=surface,
                resource_id=resource_id,
                now=now,
                reconcile=reconcile,
            )

    def _ensure_resource_synchronized_locked(
        self,
        *,
        surface: str,
        resource_id: str,
        now: int | None,
        reconcile: bool,
    ) -> ExecutionPolicyAnchorSnapshot:
        self._ensure_synchronized_locked(now=now, reconcile=reconcile)
        from tinker_delegate.execution_policy_store import execution_resource_hash

        resource_hash = execution_resource_hash(surface, resource_id)
        record = self.store.latest(surface=surface, resource_id=resource_id)
        decision_hash = record["decision_hash"] if record is not None else ""
        snapshot = self.gateway.finalized_snapshot(
            resource_id_hash=resource_hash,
            decision_hash=decision_hash,
            now=now,
        )
        records = tuple(
            AnchorProjectionRecord.from_mapping(value)
            for value in self.store.anchor_projection()
        )
        projection = compute_anchor_projection(
            records,
            contract_address=self.gateway.contract_address,
            writer_address=self.gateway.writer_address,
            writer_release_commitment=self.gateway.writer_release_commitment,
        )
        _verify_projection(projection, snapshot)
        if record is None:
            if (
                snapshot.resource_decision_head != ZERO_BYTES32
                or snapshot.resource_sequence != 0
            ):
                raise ExecutionPolicyAnchorMismatch(
                    "chain has a resource head missing from the local journal"
                )
            return snapshot
        if (
            snapshot.resource_decision_head != "0x" + record["decision_hash"]
            or snapshot.resource_sequence != record["sequence"]
            or snapshot.decision_sequence != record["sequence"]
        ):
            raise ExecutionPolicyAnchorMismatch(
                "resource policy head does not match the local journal"
            )
        return snapshot

    def _require_pass_locked(
        self,
        *,
        surface: str,
        resource_id: str,
        now: int,
        expected_approval_domain_hash: str,
        expected_approver_root_hash: str,
        approved_approver_hashes: frozenset[str] | set[str] | tuple[str, ...],
        expected_execution_context_hash: str | None,
        reconcile: bool,
    ) -> dict[str, Any]:
        snapshot = self._ensure_resource_synchronized_locked(
            surface=surface,
            resource_id=resource_id,
            now=now,
            reconcile=reconcile,
        )
        record = self.store.require_pass(
            surface=surface,
            resource_id=resource_id,
            now=now,
            expected_approval_domain_hash=expected_approval_domain_hash,
            expected_approver_root_hash=expected_approver_root_hash,
            approved_approver_hashes=approved_approver_hashes,
            expected_execution_context_hash=expected_execution_context_hash,
        )
        return {**record, "rollback_anchor": snapshot.to_bounded_dict()}

    def require_pass(
        self,
        *,
        surface: str,
        resource_id: str,
        now: int,
        expected_approval_domain_hash: str,
        expected_approver_root_hash: str,
        approved_approver_hashes: frozenset[str] | set[str] | tuple[str, ...],
        expected_execution_context_hash: str | None = None,
    ) -> dict[str, Any]:
        reconcile = not self.gateway.read_only
        with self._policy_lease(exclusive=reconcile):
            return self._require_pass_locked(
                surface=surface,
                resource_id=resource_id,
                now=now,
                expected_approval_domain_hash=expected_approval_domain_hash,
                expected_approver_root_hash=expected_approver_root_hash,
                approved_approver_hashes=approved_approver_hashes,
                expected_execution_context_hash=(
                    expected_execution_context_hash
                ),
                reconcile=reconcile,
            )

    @contextmanager
    def authorized_execution_lease(
        self,
        *,
        surface: str,
        resource_id: str,
        now: int,
        expected_approval_domain_hash: str,
        expected_approver_root_hash: str,
        approved_approver_hashes: frozenset[str] | set[str] | tuple[str, ...],
        expected_execution_context_hash: str | None = None,
    ):
        """Hold authorization stable until the caller's execution completes."""

        reconcile = not self.gateway.read_only
        with self._policy_lease(exclusive=reconcile):
            record = self._require_pass_locked(
                surface=surface,
                resource_id=resource_id,
                now=now,
                expected_approval_domain_hash=expected_approval_domain_hash,
                expected_approver_root_hash=expected_approver_root_hash,
                approved_approver_hashes=approved_approver_hashes,
                expected_execution_context_hash=(
                    expected_execution_context_hash
                ),
                reconcile=reconcile,
            )
            yield record

    def latest_with_pass_status(
        self,
        *,
        surface: str,
        resource_id: str,
        now: int,
        expected_approval_domain_hash: str,
        expected_approver_root_hash: str,
        approved_approver_hashes: frozenset[str] | set[str] | tuple[str, ...],
        expected_execution_context_hash: str | None = None,
    ) -> tuple[
        dict[str, Any] | None,
        dict[str, Any] | None,
        ExecutionPolicyAnchorSnapshot,
    ]:
        """Return one record/pass/snapshot view under one journal lease."""

        from tinker_delegate.execution_policy_store import (
            ExecutionPolicyNotPassed,
            ExecutionPolicyStoreError,
            ExecutionPolicyStoreUnavailable,
        )

        reconcile = not self.gateway.read_only
        with self._policy_lease(exclusive=reconcile):
            snapshot = self._ensure_resource_synchronized_locked(
                surface=surface,
                resource_id=resource_id,
                now=now,
                reconcile=reconcile,
            )
            record = self.store.latest(surface=surface, resource_id=resource_id)
            if record is None:
                return None, None, snapshot
            try:
                passed = self.store.require_pass(
                    surface=surface,
                    resource_id=resource_id,
                    now=now,
                    expected_approval_domain_hash=expected_approval_domain_hash,
                    expected_approver_root_hash=expected_approver_root_hash,
                    approved_approver_hashes=approved_approver_hashes,
                    expected_execution_context_hash=(
                        expected_execution_context_hash
                    ),
                )
            except (
                ExecutionPolicyNotPassed,
                ExecutionPolicyStoreError,
                ExecutionPolicyStoreUnavailable,
            ):
                passed = None
            return (
                record,
                (
                    {**passed, "rollback_anchor": snapshot.to_bounded_dict()}
                    if passed is not None
                    else None
                ),
                snapshot,
            )


def compute_anchor_projection(
    records: Sequence[AnchorProjectionRecord],
    *,
    contract_address: str,
    writer_address: str,
    writer_release_commitment: str,
) -> AnchorProjection:
    global_head = ZERO_BYTES32
    resource_heads: dict[str, tuple[str, int]] = {}
    for expected_sequence, record in enumerate(records, start=1):
        if not isinstance(record, AnchorProjectionRecord):
            raise ExecutionPolicyAnchorMismatch("policy projection is invalid")
        if record.sequence != expected_sequence:
            raise ExecutionPolicyAnchorMismatch(
                "policy projection sequence is not contiguous"
            )
        previous_resource = resource_heads.get(
            record.resource_id_hash, (ZERO_BYTES32, 0)
        )[0]
        global_head = compute_anchor_head(
            contract_address=contract_address,
            sequence=record.sequence,
            previous_global_head=global_head,
            resource_id_hash=record.resource_id_hash,
            previous_resource_head=previous_resource,
            decision_hash=record.decision_hash,
            writer_address=writer_address,
            writer_release_commitment=writer_release_commitment,
        )
        resource_heads[record.resource_id_hash] = (
            "0x" + record.decision_hash,
            record.sequence,
        )
    return AnchorProjection(
        sequence=len(records),
        global_head=global_head,
        resource_heads=resource_heads,
    )


def compute_anchor_head(
    *,
    contract_address: str,
    sequence: int,
    previous_global_head: str,
    resource_id_hash: str,
    previous_resource_head: str,
    decision_hash: str,
    writer_address: str,
    writer_release_commitment: str,
) -> str:
    encoded = (
        _ANCHOR_TYPEHASH
        + _uint_word(BASE_SEPOLIA_CHAIN_ID)
        + _address_word(_address(contract_address, allow_zero=False))
        + _uint_word(sequence)
        + _bytes32_word(previous_global_head)
        + _bytes32_word(resource_id_hash)
        + _bytes32_word(previous_resource_head)
        + _bytes32_word(decision_hash)
        + _address_word(_address(writer_address, allow_zero=False))
        + _bytes32_word(writer_release_commitment)
    )
    return "0x" + keccak(encoded).hex()


def _verify_projection(
    projection: AnchorProjection, snapshot: ExecutionPolicyAnchorSnapshot
) -> None:
    if (
        snapshot.global_sequence != projection.sequence
        or snapshot.global_head != projection.global_head
    ):
        raise ExecutionPolicyAnchorMismatch(
            "global policy anchor does not match the local HMAC journal"
        )


def _bounded_url(value: str, *, allow_plain_http_for_test: bool) -> str:
    if not isinstance(value, str) or not value or len(value) > 2_048:
        raise ExecutionPolicyAnchorMismatch("Base Sepolia anchor RPC URL is invalid")
    parsed = urlparse(value)
    allowed = {"https"}
    if allow_plain_http_for_test:
        allowed.add("http")
    if (
        parsed.scheme not in allowed
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ExecutionPolicyAnchorMismatch("Base Sepolia anchor RPC URL is invalid")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        if not allow_plain_http_for_test:
            raise ExecutionPolicyAnchorMismatch(
                "Base Sepolia anchor RPC must use DNS HTTPS"
            )
    return value


def _bounded_response_body(response: httpx.Response) -> bytes:
    content_length = response.headers.get("content-length", "")
    if content_length:
        try:
            if int(content_length) > MAX_RPC_RESPONSE_BYTES:
                raise ExecutionPolicyAnchorUnavailable(
                    "bounded Base Sepolia RPC response is too large"
                )
        except ValueError:
            raise ExecutionPolicyAnchorUnavailable(
                "bounded Base Sepolia RPC response length is invalid"
            ) from None
    body = bytearray()
    for chunk in response.iter_bytes():
        body.extend(chunk)
        if len(body) > MAX_RPC_RESPONSE_BYTES:
            raise ExecutionPolicyAnchorUnavailable(
                "bounded Base Sepolia RPC response is too large"
            )
    return bytes(body)


def _advancing_validation_time(
    initial_now: int | None,
    started_monotonic: float,
) -> int | None:
    if initial_now is None:
        return None
    elapsed = max(0, int(time.monotonic() - started_monotonic))
    return initial_now + elapsed


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _quantity(value: Any, label: str) -> int:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]*)", value)
    ):
        raise ExecutionPolicyAnchorUnavailable(f"{label} quantity is invalid")
    result = int(value, 16)
    if result >= 2**256:
        raise ExecutionPolicyAnchorUnavailable(f"{label} quantity is invalid")
    return result


def _integer(
    value: Any,
    label: str,
    *,
    minimum: int,
    maximum: int = 2**256 - 1,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExecutionPolicyAnchorMismatch(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ExecutionPolicyAnchorMismatch(f"{label} is out of range")
    return value


def _address(value: Any, *, allow_zero: bool) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"0x[0-9a-fA-F]{40}", value
    ):
        raise ExecutionPolicyAnchorMismatch("Ethereum address is invalid")
    result = value.lower()
    if not allow_zero and result == ZERO_ADDRESS:
        raise ExecutionPolicyAnchorMismatch("zero Ethereum address is forbidden")
    return result


def _bytes32(value: Any, *, allow_zero: bool) -> str:
    if not isinstance(value, str):
        raise ExecutionPolicyAnchorMismatch("bytes32 value is invalid")
    result = value.lower()
    if not _BYTES32.fullmatch(result) or (
        not allow_zero and result == ZERO_BYTES32
    ):
        raise ExecutionPolicyAnchorMismatch("bytes32 value is invalid")
    return result


def _bare_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _BARE_HASH.fullmatch(value):
        raise ExecutionPolicyAnchorMismatch(f"{label} is invalid")
    return value


def _hex_bytes(value: Any, label: str, maximum: int) -> bytes:
    if not isinstance(value, str):
        raise ExecutionPolicyAnchorUnavailable(f"{label} is invalid")
    normalized = value.lower()
    if not _HEX_DATA.fullmatch(normalized):
        raise ExecutionPolicyAnchorUnavailable(f"{label} is invalid")
    raw = bytes.fromhex(normalized[2:])
    if len(raw) > maximum:
        raise ExecutionPolicyAnchorUnavailable(f"{label} exceeds the size cap")
    return raw


def _decode_word(value: bytes) -> bytes:
    if len(value) != 32:
        raise ExecutionPolicyAnchorMismatch("anchor ABI result is invalid")
    return value


def _decode_bool(value: bytes) -> bool:
    word = _decode_word(value)
    number = int.from_bytes(word, "big")
    if number not in {0, 1}:
        raise ExecutionPolicyAnchorMismatch("anchor boolean result is invalid")
    return bool(number)


def _decode_uint(value: bytes) -> int:
    return int.from_bytes(_decode_word(value), "big")


def _decode_bytes32(value: bytes) -> str:
    return "0x" + _decode_word(value).hex()


def _decode_address(value: bytes, *, allow_zero: bool) -> str:
    word = _decode_word(value)
    if word[:12] != b"\0" * 12:
        raise ExecutionPolicyAnchorMismatch("anchor address result is invalid")
    return _address("0x" + word[12:].hex(), allow_zero=allow_zero)


def _uint_word(value: Any) -> bytes:
    number = _integer(value, "uint256", minimum=0)
    return number.to_bytes(32, "big")


def _address_word(value: str) -> bytes:
    return bytes.fromhex(_address(value, allow_zero=True)[2:]).rjust(32, b"\0")


def _bytes32_word(value: str) -> bytes:
    normalized = value
    if _BARE_HASH.fullmatch(value):
        normalized = "0x" + value
    return bytes.fromhex(_bytes32(normalized, allow_zero=True)[2:])
