"""Bounded Base Sepolia and independent-metering clients for Compute runtime.

Every vault policy read in :meth:`HttpsComputeVaultGateway.snapshot` uses the
same explicit block tag, including bytecode. Transaction preparation is kept
separate from those policy snapshots and returns exact signed bytes so the
execution journal can persist them before any broadcast attempt.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Mapping
from urllib.parse import urlparse

import httpx
from eth_hash.auto import keccak
from eth_utils import to_checksum_address

from tinker_delegate.compute_runtime import (
    BASE_SEPOLIA_CHAIN_ID,
    ComputeExecutionIdentity,
    ComputeMeteringClient,
    ComputeRuntimePolicyError,
    ComputeRuntimeRetryable,
    MeteringDecision,
    PreparedTransaction,
    SignedUsageEnvelope,
    VaultJob,
    VaultSnapshot,
)
from tinker_delegate.wallet_auth import WalletAuthError, normalize_wallet_address


MAX_RPC_RESPONSE_BYTES = 512 * 1024
MAX_METERING_RESPONSE_BYTES = 64 * 1024
MAX_RUNTIME_CODE_BYTES = 512 * 1024
MAX_TRANSACTION_GAS = 1_500_000
MAX_GAS_PRICE_WEI = 10**15

_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_HEX_DATA = re.compile(r"^0x(?:[0-9a-f]{2})*$")
_TX_HASH = re.compile(r"^0x[0-9a-f]{64}$")

_PAUSED = keccak(b"paused()")[:4]
_DEVELOPER_FEE_FROZEN = keccak(b"developerFeeFrozen()")[:4]
_ASSET_ADDITIONS_FROZEN = keccak(b"assetAdditionsFrozen()")[:4]
_RATE_POLICY_ADDITIONS_FROZEN = keccak(b"ratePolicyAdditionsFrozen()")[:4]
_COMPOSE_POLICY_FROZEN = keccak(b"composePolicyFrozen()")[:4]
_TEE_IDENTITY_ADDITIONS_FROZEN = keccak(b"teeIdentityAdditionsFrozen()")[:4]
_METERING_BINDING_FROZEN = keccak(b"meteringBindingFrozen()")[:4]
_METERING_POLICY_SET_HASH = keccak(b"meteringPolicySetHash()")[:4]
_ALLOWED_ASSET_COUNT = keccak(b"allowedAssetCount()")[:4]
_ACTIVE_RATE_POLICY_COUNT = keccak(b"activeRatePolicyCount()")[:4]
_APPROVED_COMPOSE_COUNT = keccak(b"approvedComposeCount()")[:4]
_APPROVED_TEE_IDENTITY_COUNT = keccak(b"approvedTeeIdentityCount()")[:4]
_PENDING_DEVELOPER_FEE_ACTIVATES_AT = keccak(b"pendingDeveloperFeeActivatesAt()")[:4]
_PENDING_ASSET_COUNT = keccak(b"pendingAssetCount()")[:4]
_PENDING_RATE_POLICY_COUNT = keccak(b"pendingRatePolicyCount()")[:4]
_PENDING_COMPOSE_COUNT = keccak(b"pendingComposeCount()")[:4]
_PENDING_TEE_IDENTITY_COUNT = keccak(b"pendingTeeIdentityCount()")[:4]
_PENDING_METERING_VERIFIER = keccak(b"pendingMeteringVerifier()")[:4]
_PENDING_METERING_QVL_VERIFIER = keccak(b"pendingMeteringQvlVerifier()")[:4]
_PENDING_METERING_POLICY_SET_HASH = keccak(b"pendingMeteringPolicySetHash()")[:4]
_PENDING_METERING_BINDING_ACTIVATES_AT = keccak(b"pendingMeteringBindingActivatesAt()")[:4]
_APPROVED_COMPOSE_HASHES = keccak(b"approvedComposeHashes(bytes32)")[:4]
_TEE_IDENTITY_COMPOSE_HASH = keccak(b"teeIdentityComposeHash(address)")[:4]
_METERING_VERIFIER = keccak(b"meteringVerifier()")[:4]
_METERING_QVL_VERIFIER = keccak(b"meteringQvlVerifier()")[:4]
_RATE_POLICIES = keccak(b"ratePolicies(bytes32)")[:4]
_GET_JOB = keccak(b"getJob(bytes32)")[:4]
_START_JOB = keccak(b"startJob(bytes32,bytes32)")[:4]
_SUBMIT_METERING = keccak(
    b"submitMeteringReceipt(bytes32,uint256,bytes32,uint256,uint256,uint256,bytes32,uint256,bytes,bytes)"
)[:4]
_METERING_RECEIPT_DIGEST = keccak(
    b"meteringReceiptDigest(bytes32,uint256,uint256,uint256,uint256,bytes32,uint256)"
)[:4]
_METERING_QVL_RECEIPT_DIGEST = keccak(
    b"meteringQvlReceiptDigest(bytes32,uint256,uint256,uint256,uint256,bytes32,uint256)"
)[:4]
_USAGE_COMMITMENT_FOR = keccak(
    b"usageCommitmentFor(bytes32,uint256,uint256,uint256,uint256,bytes32)"
)[:4]


class _RpcResponseError(ComputeRuntimeRetryable):
    def __init__(self, code: int, message: str):
        super().__init__("bounded RPC rejected request")
        self.code = code
        self.rpc_message = message.lower()[:256]


class HttpsComputeVaultGateway:
    """Strict single-chain gateway that signs only with injected TEE identity."""

    chain_id = BASE_SEPOLIA_CHAIN_ID

    def __init__(
        self,
        rpc_url: str,
        *,
        vault_address: str,
        runtime_code_hash: str,
        identity: ComputeExecutionIdentity,
        client: httpx.Client | None = None,
        allow_plain_http_for_test: bool = False,
    ) -> None:
        self.rpc_url = _bounded_url(
            rpc_url,
            label="Base Sepolia RPC",
            allow_plain_http_for_test=allow_plain_http_for_test,
        )
        self.vault_address = _address(vault_address, allow_zero=False)
        self.runtime_code_hash = _bytes32(runtime_code_hash, allow_zero=False)
        self.identity = identity
        self.identity_address = _address(identity.address, allow_zero=False)
        if not str(getattr(identity, "custody", "")).startswith("dstack_"):
            # Test identities are supplied only to this constructor's explicit
            # test-HTTP path. Production construction cannot use a local key.
            if not allow_plain_http_for_test:
                raise ComputeRuntimePolicyError(
                    "Compute vault signer is not dstack-derived"
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
            raise ComputeRuntimePolicyError("Compute vault is not on Base Sepolia")

    def __repr__(self) -> str:
        return (
            "HttpsComputeVaultGateway(chain_id=84532, "
            "custody='dstack_derived_compute_execution')"
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def snapshot(
        self,
        *,
        job_id: str,
        rate_policy_commitment: str,
        tee_identity: str,
        compose_hash: str,
        block_number: int | None = None,
    ) -> VaultSnapshot:
        job_id = _bytes32(job_id, allow_zero=False)
        rate_commitment = _bytes32(rate_policy_commitment, allow_zero=False)
        tee = _address(tee_identity, allow_zero=False)
        compose = _bytes32(compose_hash, allow_zero=False)
        block = self._block("latest" if block_number is None else block_number)
        number = block["number"]
        # EIP-1898 hash pinning prevents a reorg between individual policy
        # calls from silently mixing state at the same block number.
        tag = {"blockHash": block["hash"], "requireCanonical": True}

        code = _hex_bytes(
            self._rpc("eth_getCode", [self.vault_address, tag]),
            label="vault bytecode",
            maximum=MAX_RUNTIME_CODE_BYTES,
        )
        if not code or "0x" + keccak(code).hex() != self.runtime_code_hash:
            raise ComputeRuntimePolicyError("Compute vault runtime hash mismatch")

        paused = _decode_bool(self._eth_call(_PAUSED, tag))
        developer_fee_frozen = _decode_bool(
            self._eth_call(_DEVELOPER_FEE_FROZEN, tag)
        )
        asset_additions_frozen = _decode_bool(
            self._eth_call(_ASSET_ADDITIONS_FROZEN, tag)
        )
        rate_policy_additions_frozen = _decode_bool(
            self._eth_call(_RATE_POLICY_ADDITIONS_FROZEN, tag)
        )
        compose_frozen = _decode_bool(
            self._eth_call(_COMPOSE_POLICY_FROZEN, tag)
        )
        tee_identity_additions_frozen = _decode_bool(
            self._eth_call(_TEE_IDENTITY_ADDITIONS_FROZEN, tag)
        )
        metering_binding_frozen = _decode_bool(
            self._eth_call(_METERING_BINDING_FROZEN, tag)
        )
        metering_policy_set_hash = _decode_bytes32(
            self._eth_call(_METERING_POLICY_SET_HASH, tag)
        )
        allowed_asset_count = _decode_uint(
            self._eth_call(_ALLOWED_ASSET_COUNT, tag)
        )
        active_rate_policy_count = _decode_uint(
            self._eth_call(_ACTIVE_RATE_POLICY_COUNT, tag)
        )
        approved_compose_count = _decode_uint(
            self._eth_call(_APPROVED_COMPOSE_COUNT, tag)
        )
        approved_tee_identity_count = _decode_uint(
            self._eth_call(_APPROVED_TEE_IDENTITY_COUNT, tag)
        )
        pending_developer_fee_activates_at = _decode_uint(
            self._eth_call(_PENDING_DEVELOPER_FEE_ACTIVATES_AT, tag)
        )
        pending_asset_count = _decode_uint(
            self._eth_call(_PENDING_ASSET_COUNT, tag)
        )
        pending_rate_policy_count = _decode_uint(
            self._eth_call(_PENDING_RATE_POLICY_COUNT, tag)
        )
        pending_compose_count = _decode_uint(
            self._eth_call(_PENDING_COMPOSE_COUNT, tag)
        )
        pending_tee_identity_count = _decode_uint(
            self._eth_call(_PENDING_TEE_IDENTITY_COUNT, tag)
        )
        pending_metering_verifier = _decode_address(
            self._eth_call(_PENDING_METERING_VERIFIER, tag), allow_zero=True
        )
        pending_metering_qvl_verifier = _decode_address(
            self._eth_call(_PENDING_METERING_QVL_VERIFIER, tag), allow_zero=True
        )
        pending_metering_policy_set_hash = _decode_bytes32(
            self._eth_call(_PENDING_METERING_POLICY_SET_HASH, tag)
        )
        pending_metering_binding_activates_at = _decode_uint(
            self._eth_call(_PENDING_METERING_BINDING_ACTIVATES_AT, tag)
        )
        compose_approved = _decode_bool(
            self._eth_call(
                _APPROVED_COMPOSE_HASHES + _bytes32_word(compose), tag
            )
        )
        registered_compose = _decode_bytes32(
            self._eth_call(
                _TEE_IDENTITY_COMPOSE_HASH + _address_word(tee), tag
            )
        )
        metering_verifier = _decode_address(
            self._eth_call(_METERING_VERIFIER, tag), allow_zero=False
        )
        metering_qvl_verifier = _decode_address(
            self._eth_call(_METERING_QVL_VERIFIER, tag), allow_zero=False
        )
        rate_words = _decode_words(
            self._eth_call(_RATE_POLICIES + _bytes32_word(rate_commitment), tag),
            4,
            "rate policy",
        )
        job_words = _decode_words(
            self._eth_call(_GET_JOB + _bytes32_word(job_id), tag),
            21,
            "vault job",
        )
        job_state = _word_uint(job_words[20])
        if job_state > 5:
            raise ComputeRuntimePolicyError("vault job state is invalid")

        return VaultSnapshot(
            chain_id=self.chain_id,
            block_number=number,
            block_hash=block["hash"],
            block_timestamp=block["timestamp"],
            vault_address=self.vault_address,
            vault_runtime_code_hash=self.runtime_code_hash,
            paused=paused,
            developer_fee_frozen=developer_fee_frozen,
            asset_additions_frozen=asset_additions_frozen,
            rate_policy_additions_frozen=rate_policy_additions_frozen,
            compose_policy_frozen=compose_frozen,
            tee_identity_additions_frozen=tee_identity_additions_frozen,
            metering_binding_frozen=metering_binding_frozen,
            metering_policy_set_hash=metering_policy_set_hash,
            allowed_asset_count=allowed_asset_count,
            active_rate_policy_count=active_rate_policy_count,
            approved_compose_count=approved_compose_count,
            approved_tee_identity_count=approved_tee_identity_count,
            pending_developer_fee_activates_at=pending_developer_fee_activates_at,
            pending_asset_count=pending_asset_count,
            pending_rate_policy_count=pending_rate_policy_count,
            pending_compose_count=pending_compose_count,
            pending_tee_identity_count=pending_tee_identity_count,
            pending_metering_verifier=pending_metering_verifier,
            pending_metering_qvl_verifier=pending_metering_qvl_verifier,
            pending_metering_policy_set_hash=pending_metering_policy_set_hash,
            pending_metering_binding_activates_at=pending_metering_binding_activates_at,
            compose_approved=compose_approved,
            registered_tee_compose_hash=registered_compose,
            metering_verifier=metering_verifier,
            metering_qvl_verifier=metering_qvl_verifier,
            rate_policy_asset=_word_address(rate_words[0], allow_zero=True),
            rate_policy_provider=_word_address(rate_words[1], allow_zero=False),
            rate_policy_developer_fee_bps=_word_uint(rate_words[2]),
            rate_policy_active=_word_bool(rate_words[3]),
            job=VaultJob(
                project_id=_word_bytes32(job_words[0]),
                user=_word_address(job_words[1], allow_zero=False),
                asset=_word_address(job_words[2], allow_zero=True),
                authorization_nonce=_word_uint(job_words[3]),
                max_asset_debit=_word_uint(job_words[4]),
                actual_asset_debit=_word_uint(job_words[5]),
                authorization_expiry=_word_uint(job_words[6]),
                started_at=_word_uint(job_words[7]),
                usage_ended_at=_word_uint(job_words[8]),
                receipt_expiry=_word_uint(job_words[9]),
                rate_policy_commitment=_word_bytes32(job_words[10]),
                workload_commitment=_word_bytes32(job_words[11]),
                manifest_commitment=_word_bytes32(job_words[12]),
                dispatch_intent_commitment=_word_bytes32(job_words[13]),
                compose_hash=_word_bytes32(job_words[14]),
                start_commitment=_word_bytes32(job_words[15]),
                usage_commitment=_word_bytes32(job_words[16]),
                attestation_evidence_hash=_word_bytes32(job_words[17]),
                billable_compute_units=_word_uint(job_words[18]),
                tee_identity=_word_address(job_words[19], allow_zero=True),
                state=job_state,
            ),
        )

    def prepare_start(
        self,
        *,
        job_id: str,
        compose_hash: str,
    ) -> PreparedTransaction:
        data = (
            _START_JOB
            + _bytes32_word(_bytes32(job_id, allow_zero=False))
            + _bytes32_word(_bytes32(compose_hash, allow_zero=False))
        )
        return self._prepare("start", data)

    def prepare_settlement(
        self,
        *,
        job_id: str,
        actual_asset_debit: int,
        compose_hash: str,
        billable_compute_units: int,
        usage_started_at: int,
        usage_ended_at: int,
        attestation_evidence_hash: str,
        receipt_expiry: int,
        verifier_signature: str,
        qvl_signature: str,
    ) -> PreparedTransaction:
        signature = _signature_bytes(verifier_signature)
        qvl = _signature_bytes(qvl_signature)
        signature_tail = _dynamic_bytes(signature)
        qvl_tail = _dynamic_bytes(qvl)
        head = b"".join(
            (
                _bytes32_word(_bytes32(job_id, allow_zero=False)),
                _uint_word(actual_asset_debit),
                _bytes32_word(_bytes32(compose_hash, allow_zero=False)),
                _uint_word(billable_compute_units),
                _uint_word(usage_started_at),
                _uint_word(usage_ended_at),
                _bytes32_word(_bytes32(attestation_evidence_hash, allow_zero=False)),
                _uint_word(receipt_expiry),
                _uint_word(32 * 10),
                _uint_word(32 * 10 + len(signature_tail)),
            )
        )
        return self._prepare(
            "settlement", _SUBMIT_METERING + head + signature_tail + qvl_tail
        )

    def broadcast(self, transaction: PreparedTransaction) -> None:
        prepared = PreparedTransaction.from_dict(transaction.to_dict())
        try:
            result = self._rpc(
                "eth_sendRawTransaction", [prepared.raw_transaction]
            )
        except _RpcResponseError as exc:
            if any(
                marker in exc.rpc_message
                for marker in (
                    "already known",
                    "known transaction",
                    "already imported",
                )
            ):
                return
            raise ComputeRuntimeRetryable("transaction broadcast unavailable") from None
        if not isinstance(result, str) or result.lower() != prepared.tx_hash:
            raise ComputeRuntimePolicyError("RPC returned the wrong transaction hash")

    def confirmed_snapshot(
        self,
        transaction: PreparedTransaction,
        *,
        confirmations: int,
        job_id: str,
        rate_policy_commitment: str,
        tee_identity: str,
        compose_hash: str,
    ) -> VaultSnapshot | None:
        prepared = PreparedTransaction.from_dict(transaction.to_dict())
        receipt = self._rpc("eth_getTransactionReceipt", [prepared.tx_hash])
        if receipt is None:
            return None
        if not isinstance(receipt, Mapping):
            raise ComputeRuntimeRetryable("transaction receipt is unavailable")
        if (
            str(receipt.get("transactionHash", "")).lower() != prepared.tx_hash
            or _address(receipt.get("from"), allow_zero=False)
            != self.identity_address
            or _address(receipt.get("to"), allow_zero=False) != self.vault_address
        ):
            raise ComputeRuntimePolicyError("transaction receipt binding mismatch")
        status = _quantity(receipt.get("status"), "receipt status")
        if status != 1:
            raise ComputeRuntimePolicyError("Compute vault transaction reverted")
        receipt_block = _quantity(receipt.get("blockNumber"), "receipt block")
        receipt_hash = _bytes32(receipt.get("blockHash"), allow_zero=False)
        canonical_block = self._block(receipt_block)
        if canonical_block["hash"] != receipt_hash:
            return None
        latest = self._block("latest")
        if latest["number"] < receipt_block:
            raise ComputeRuntimeRetryable("latest block is behind receipt")
        if latest["number"] - receipt_block + 1 < confirmations:
            return None
        return self.snapshot(
            job_id=job_id,
            rate_policy_commitment=rate_policy_commitment,
            tee_identity=tee_identity,
            compose_hash=compose_hash,
            block_number=receipt_block,
        )

    def metering_receipt_digest(
        self,
        *,
        block_number: int,
        block_hash: str,
        job_id: str,
        actual_asset_debit: int,
        billable_compute_units: int,
        usage_started_at: int,
        usage_ended_at: int,
        attestation_evidence_hash: str,
        receipt_expiry: int,
    ) -> str:
        data = b"".join(
            (
                _METERING_RECEIPT_DIGEST,
                _bytes32_word(_bytes32(job_id, allow_zero=False)),
                _uint_word(actual_asset_debit),
                _uint_word(billable_compute_units),
                _uint_word(usage_started_at),
                _uint_word(usage_ended_at),
                _bytes32_word(_bytes32(attestation_evidence_hash, allow_zero=False)),
                _uint_word(receipt_expiry),
            )
        )
        return self._pinned_bytes32_call(
            data,
            block_number=block_number,
            block_hash=block_hash,
            label="metering digest",
        )

    def metering_qvl_receipt_digest(
        self,
        *,
        block_number: int,
        block_hash: str,
        job_id: str,
        actual_asset_debit: int,
        billable_compute_units: int,
        usage_started_at: int,
        usage_ended_at: int,
        attestation_evidence_hash: str,
        receipt_expiry: int,
    ) -> str:
        data = b"".join(
            (
                _METERING_QVL_RECEIPT_DIGEST,
                _bytes32_word(_bytes32(job_id, allow_zero=False)),
                _uint_word(actual_asset_debit),
                _uint_word(billable_compute_units),
                _uint_word(usage_started_at),
                _uint_word(usage_ended_at),
                _bytes32_word(_bytes32(attestation_evidence_hash, allow_zero=False)),
                _uint_word(receipt_expiry),
            )
        )
        return self._pinned_bytes32_call(
            data,
            block_number=block_number,
            block_hash=block_hash,
            label="metering QVL digest",
        )

    def usage_commitment(
        self,
        *,
        block_number: int,
        block_hash: str,
        job_id: str,
        actual_asset_debit: int,
        billable_compute_units: int,
        usage_started_at: int,
        usage_ended_at: int,
        attestation_evidence_hash: str,
    ) -> str:
        data = b"".join(
            (
                _USAGE_COMMITMENT_FOR,
                _bytes32_word(_bytes32(job_id, allow_zero=False)),
                _uint_word(actual_asset_debit),
                _uint_word(billable_compute_units),
                _uint_word(usage_started_at),
                _uint_word(usage_ended_at),
                _bytes32_word(_bytes32(attestation_evidence_hash, allow_zero=False)),
            )
        )
        return self._pinned_bytes32_call(
            data,
            block_number=block_number,
            block_hash=block_hash,
            label="usage commitment",
        )

    def _pinned_bytes32_call(
        self,
        data: bytes,
        *,
        block_number: int,
        block_hash: str,
        label: str,
    ) -> str:
        canonical = self._block(block_number)
        expected_hash = _bytes32(block_hash, allow_zero=False)
        if canonical["hash"] != expected_hash:
            raise ComputeRuntimePolicyError(f"{label} block is not canonical")
        return _decode_bytes32(
            self._eth_call(
                data,
                {"blockHash": expected_hash, "requireCanonical": True},
            )
        )

    def _prepare(self, purpose: str, data: bytes) -> PreparedTransaction:
        nonce = _quantity(
            self._rpc(
                "eth_getTransactionCount", [self.identity_address, "pending"]
            ),
            "pending nonce",
        )
        gas_price = _quantity(self._rpc("eth_gasPrice", []), "gas price")
        if gas_price <= 0 or gas_price > MAX_GAS_PRICE_WEI:
            raise ComputeRuntimePolicyError("Base Sepolia gas price is outside bounds")
        call = {
            "from": self.identity_address,
            "to": self.vault_address,
            "value": "0x0",
            "data": "0x" + data.hex(),
        }
        estimated = _quantity(
            self._rpc("eth_estimateGas", [call]), "estimated gas"
        )
        gas = max(21_000, (estimated * 12 + 9) // 10)
        if gas > MAX_TRANSACTION_GAS:
            raise ComputeRuntimePolicyError("Compute vault transaction gas exceeds bound")
        transaction = {
            "chainId": self.chain_id,
            "nonce": nonce,
            "gasPrice": gas_price,
            "gas": gas,
            "to": to_checksum_address(self.vault_address),
            "value": 0,
            "data": data,
        }
        try:
            signed = self.identity.sign_transaction(transaction)
            raw_value = getattr(signed, "raw_transaction", None)
            if raw_value is None:
                raw_value = getattr(signed, "rawTransaction", None)
            raw = bytes(raw_value)
        except Exception:
            raise ComputeRuntimePolicyError("dstack transaction signing failed") from None
        if not raw:
            raise ComputeRuntimePolicyError("dstack transaction signing returned no bytes")
        return PreparedTransaction(
            purpose=purpose,
            tx_hash="0x" + keccak(raw).hex(),
            raw_transaction="0x" + raw.hex(),
        )

    def _block(self, number: int | str) -> dict[str, Any]:
        tag = number if number == "latest" else _quantity_hex(number)
        value = self._rpc("eth_getBlockByNumber", [tag, False])
        if not isinstance(value, Mapping):
            raise ComputeRuntimeRetryable("Base Sepolia block is unavailable")
        observed_number = _quantity(value.get("number"), "block number")
        if number != "latest" and observed_number != number:
            raise ComputeRuntimeRetryable("RPC returned a different block")
        return {
            "number": observed_number,
            "timestamp": _quantity(value.get("timestamp"), "block timestamp"),
            "hash": _bytes32(value.get("hash"), allow_zero=False),
        }

    def _eth_call(self, data: bytes, block_tag: str | Mapping[str, Any]) -> bytes:
        try:
            result = self._rpc(
                "eth_call",
                [
                    {"to": self.vault_address, "data": "0x" + data.hex()},
                    block_tag,
                ],
            )
        except _RpcResponseError as exc:
            if "revert" in exc.rpc_message:
                raise ComputeRuntimePolicyError("Compute vault read reverted") from None
            raise
        return _hex_bytes(
            result,
            label="vault call result",
            maximum=64 * 1024,
        )

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
                    raise ComputeRuntimeRetryable("bounded RPC is unavailable")
                raw = _bounded_response_body(response, MAX_RPC_RESPONSE_BYTES)
            finally:
                response.close()
        except ComputeRuntimeRetryable:
            raise
        except Exception:
            raise ComputeRuntimeRetryable("bounded RPC is unavailable") from None
        try:
            payload = json.loads(raw)
        except Exception:
            raise ComputeRuntimeRetryable("bounded RPC returned invalid JSON") from None
        if (
            not isinstance(payload, Mapping)
            or payload.get("jsonrpc") != "2.0"
            or payload.get("id") != request_id
        ):
            raise ComputeRuntimeRetryable("bounded RPC response binding failed")
        error = payload.get("error")
        if error is not None:
            if not isinstance(error, Mapping):
                raise ComputeRuntimeRetryable("bounded RPC rejected request")
            code = error.get("code")
            message = error.get("message")
            if isinstance(code, bool) or not isinstance(code, int):
                code = -32_000
            if not isinstance(message, str):
                message = "rpc error"
            raise _RpcResponseError(code, message)
        if "result" not in payload:
            raise ComputeRuntimeRetryable("bounded RPC result is missing")
        return payload["result"]


class HttpsComputeMeteringClient(ComputeMeteringClient):
    """Replay-bound transport to the independent deterministic meter."""

    def __init__(
        self,
        url: str,
        *,
        auth_token: str,
        client: httpx.Client | None = None,
        allow_plain_http_for_test: bool = False,
    ) -> None:
        self.url = _bounded_url(
            url,
            label="independent metering service",
            allow_plain_http_for_test=allow_plain_http_for_test,
        )
        parsed_url = urlparse(self.url)
        if parsed_url.path != "/meter" or parsed_url.params or parsed_url.query:
            raise ComputeRuntimePolicyError(
                "independent metering URL must target /meter"
            )
        if (
            not isinstance(auth_token, str)
            or not 32 <= len(auth_token.encode("utf-8")) <= 4_096
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in auth_token)
        ):
            raise ComputeRuntimePolicyError(
                "independent metering authentication is unavailable"
            )
        self._auth_token = auth_token
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None

    def __repr__(self) -> str:
        return "HttpsComputeMeteringClient(authenticated=True)"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def decide(self, signed_usage: SignedUsageEnvelope) -> MeteringDecision:
        # Round-trip local parsing before egress so no caller can smuggle fields
        # outside the signed, bounded schema.
        bounded = SignedUsageEnvelope.from_dict(signed_usage.to_dict())
        request = self._client.build_request(
            "POST",
            self.url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._auth_token}",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
                "Idempotency-Key": bounded.usage_commitment,
            },
            content=_canonical_json(bounded.to_dict()),
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
                if response.status_code in {408, 425, 429} or response.status_code >= 500:
                    raise ComputeRuntimeRetryable(
                        "independent metering is unavailable"
                    )
                if (
                    response.status_code != 200
                    or response.history
                    or not (
                        content_type == "application/json"
                        or content_type.endswith("+json")
                    )
                ):
                    raise ComputeRuntimePolicyError(
                        "independent metering rejected bounded usage"
                    )
                raw = _bounded_response_body(
                    response, MAX_METERING_RESPONSE_BYTES
                )
            finally:
                response.close()
        except (ComputeRuntimePolicyError, ComputeRuntimeRetryable):
            raise
        except Exception:
            # Never chain an HTTP exception carrying the bearer/request body.
            raise ComputeRuntimeRetryable(
                "independent metering is unavailable"
            ) from None
        try:
            payload = json.loads(raw)
            if not isinstance(payload, Mapping):
                raise ValueError
            return MeteringDecision.from_dict(payload)
        except Exception:
            raise ComputeRuntimePolicyError(
                "independent metering returned an invalid decision"
            ) from None


def _bounded_url(
    value: str,
    *,
    label: str,
    allow_plain_http_for_test: bool,
) -> str:
    if not isinstance(value, str) or not value or len(value) > 2_048:
        raise ComputeRuntimePolicyError(f"{label} URL is invalid")
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
        raise ComputeRuntimePolicyError(f"{label} URL is invalid")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        if not allow_plain_http_for_test:
            raise ComputeRuntimePolicyError(f"{label} URL must use DNS HTTPS")
    return value


def _bounded_response_body(response: httpx.Response, maximum: int) -> bytes:
    content_length = response.headers.get("content-length", "")
    if content_length:
        try:
            if int(content_length) > maximum:
                raise ComputeRuntimeRetryable("bounded response is too large")
        except ValueError:
            raise ComputeRuntimeRetryable("bounded response length is invalid") from None
    body = bytearray()
    for chunk in response.iter_bytes():
        body.extend(chunk)
        if len(body) > maximum:
            raise ComputeRuntimeRetryable("bounded response is too large")
    return bytes(body)


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
        raise ComputeRuntimeRetryable(f"{label} quantity is invalid")
    result = int(value, 16)
    if result < 0 or result >= 2**256:
        raise ComputeRuntimeRetryable(f"{label} quantity is invalid")
    return result


def _quantity_hex(value: int) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ComputeRuntimePolicyError("block number is invalid")
    return hex(value)


def _address(value: Any, *, allow_zero: bool) -> str:
    try:
        result = normalize_wallet_address(str(value)).lower()
    except WalletAuthError:
        raise ComputeRuntimePolicyError("Ethereum address is invalid") from None
    if not allow_zero and result == "0x" + "00" * 20:
        raise ComputeRuntimePolicyError("zero Ethereum address is forbidden")
    return result


def _bytes32(value: Any, *, allow_zero: bool) -> str:
    if not isinstance(value, str):
        raise ComputeRuntimePolicyError("bytes32 value is invalid")
    result = value.lower()
    if not _BYTES32.fullmatch(result) or (
        not allow_zero and result == "0x" + "00" * 32
    ):
        raise ComputeRuntimePolicyError("bytes32 value is invalid")
    return result


def _hex_bytes(value: Any, *, label: str, maximum: int) -> bytes:
    if not isinstance(value, str):
        raise ComputeRuntimeRetryable(f"{label} is invalid")
    normalized = value.lower()
    if not _HEX_DATA.fullmatch(normalized) or len(normalized) > 2 + maximum * 2:
        raise ComputeRuntimeRetryable(f"{label} is invalid")
    return bytes.fromhex(normalized[2:])


def _uint_word(value: Any) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**256:
        raise ComputeRuntimePolicyError("uint256 value is invalid")
    return value.to_bytes(32, "big")


def _bytes32_word(value: str) -> bytes:
    return bytes.fromhex(_bytes32(value, allow_zero=True)[2:])


def _address_word(value: str) -> bytes:
    return b"\0" * 12 + bytes.fromhex(_address(value, allow_zero=True)[2:])


def _signature_bytes(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ComputeRuntimePolicyError("metering signature is invalid")
    normalized = value.lower()
    if not re.fullmatch(r"0x[0-9a-f]{130}", normalized):
        raise ComputeRuntimePolicyError("metering signature is invalid")
    return bytes.fromhex(normalized[2:])


def _dynamic_bytes(value: bytes) -> bytes:
    encoded = _uint_word(len(value)) + value
    return encoded + b"\0" * ((32 - len(value) % 32) % 32)


def _decode_words(value: bytes, count: int, label: str) -> tuple[bytes, ...]:
    if len(value) != count * 32:
        raise ComputeRuntimePolicyError(f"{label} ABI shape is invalid")
    return tuple(value[index : index + 32] for index in range(0, len(value), 32))


def _word_uint(value: bytes) -> int:
    if len(value) != 32:
        raise ComputeRuntimePolicyError("ABI uint256 word is invalid")
    return int.from_bytes(value, "big")


def _word_bool(value: bytes) -> bool:
    integer = _word_uint(value)
    if integer not in (0, 1):
        raise ComputeRuntimePolicyError("ABI bool word is invalid")
    return bool(integer)


def _word_address(value: bytes, *, allow_zero: bool) -> str:
    if len(value) != 32 or value[:12] != b"\0" * 12:
        raise ComputeRuntimePolicyError("ABI address word is invalid")
    return _address("0x" + value[12:].hex(), allow_zero=allow_zero)


def _word_bytes32(value: bytes) -> str:
    if len(value) != 32:
        raise ComputeRuntimePolicyError("ABI bytes32 word is invalid")
    return "0x" + value.hex()


def _decode_bool(value: bytes) -> bool:
    return _word_bool(_decode_words(value, 1, "bool result")[0])


def _decode_uint(value: bytes) -> int:
    return _word_uint(_decode_words(value, 1, "uint result")[0])


def _decode_address(value: bytes, *, allow_zero: bool) -> str:
    return _word_address(
        _decode_words(value, 1, "address result")[0], allow_zero=allow_zero
    )


def _decode_bytes32(value: bytes) -> str:
    return _word_bytes32(_decode_words(value, 1, "bytes32 result")[0])
