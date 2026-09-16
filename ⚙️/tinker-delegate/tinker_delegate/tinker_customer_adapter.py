"""Wallet-owned, fail-closed authority for the delegated Tinker customer surface.

This module is the narrow service boundary used by the release-gated FastAPI
customer routes.  It binds an already authenticated Base Sepolia wallet to one
immutable logical customer account, but it never treats a browser request as
proof that an upstream Tinker account exists.  Activation remains an internal
operation and requires an independently signed, short-lived provisioning
result whose account commitment matches the exact frozen
``TinkerAccountEncumbrance`` release.

Every state-changing method re-reads the contract at one numeric finalized
block through two independent RPC providers and obtains a fresh TDX/QVL release
lease.  The durable store is HMAC authenticated and transactionally replaced.
It contains only bounded policy records, commitments, encrypted credential
capsules, and receipts; upstream API keys, project ids, cookies, card data,
provider identifiers, prompts, examples, and outputs are not accepted.

The first release enables bounded training authority only.  Inference remains
an explicit disabled capability until a compatible bounded provider adapter is
reviewed into the same release evidence.  Reservations and settlements are
authority-accounting receipts, not provider-authoritative billing.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from eth_hash.auto import keccak

from tinker_delegate.crypto import encrypt_for_tee
from tinker_delegate.tinker_account_binding import (
    TINKER_ACCOUNT_BINDING_CHAIN_ID,
    TINKER_ACCOUNT_BINDING_SCHEMA,
    TINKER_ACCOUNT_BINDING_TYPE,
    TINKER_ACCOUNT_BINDING_TYPEHASH,
    TINKER_PROVIDER_NAMESPACE,
    TINKER_PROVIDER_NAMESPACE_LABEL,
)
from tinker_delegate.wallet_auth import normalize_wallet_address
from tinker_delegate.wallet_signature_verifier import BASE_SEPOLIA_CHAIN_ID


CUSTOMER_WALLET_SCOPE = "compute:console"
CUSTOMER_CREDENTIAL_HKDF_INFO = b"dnai-wikigen-tinker-customer-credential-v1"
CUSTOMER_CREDENTIAL_HEADER = {
    "alg": "HS256",
    "kid": "dstack-tinker-customer-v1",
    "typ": "JWT",
}
CUSTOMER_CREDENTIAL_ISSUER = "dnai-wikigen:tinker-customer"
CUSTOMER_CREDENTIAL_AUDIENCE = "dnai-wikigen:tinker-proxy"
SUPPORTED_CUSTOMER_OPERATIONS = ("training", "inference")
CUSTOMER_OPERATION_SCOPE = {
    "training": "tinker:train",
    "inference": "tinker:infer",
}
ZERO_ADDRESS = "0x" + "00" * 20
ZERO_WORD = "0x" + "00" * 32
MAX_CUSTOMER_ACCOUNTS = 10_000
MAX_CUSTOMER_CREDENTIALS = 100_000
DEFAULT_CUSTOMER_CREDENTIAL_PAGE_SIZE = 16
MAX_CUSTOMER_CREDENTIAL_PAGE_SIZE = 64
MAX_CUSTOMER_CREDENTIAL_CURSOR_BYTES = 1_024
MAX_CUSTOMER_CREDENTIAL_PAGE_BYTES = 255 * 1_024
MAX_CUSTOMER_RESERVATIONS = 1_000_000
MAX_IDEMPOTENCY_RECORDS = 1_000_000
MAX_CUSTOMER_STORE_BYTES = 64 * 1024 * 1024
TINKER_CUSTOMER_ACCOUNT_BINDING_TRUTH = (
    "independently_attested_opaque_binding_handle_not_cryptographic_proof_of_provider_internal_identity"
)
TC_WALLET_VERIFIER_UNAVAILABLE = "TC_WALLET_VERIFIER_UNAVAILABLE"
TC_RELEASE_READER_UNAVAILABLE = "TC_RELEASE_READER_UNAVAILABLE"
TC_RUNTIME_EVIDENCE_PROVIDER_UNAVAILABLE = "TC_RUNTIME_EVIDENCE_PROVIDER_UNAVAILABLE"
TC_PROVISIONING_PROVIDER_UNAVAILABLE = "TC_PROVISIONING_PROVIDER_UNAVAILABLE"
TC_SETTLEMENT_PROVIDER_UNAVAILABLE = "TC_SETTLEMENT_PROVIDER_UNAVAILABLE"
TC_STATE_ANCHOR_READ_UNAVAILABLE = "TC_STATE_ANCHOR_READ_UNAVAILABLE"
TC_STATE_ANCHOR_UPDATE_UNAVAILABLE = "TC_STATE_ANCHOR_UPDATE_UNAVAILABLE"
TC_CREDENTIAL_ENCRYPTION_UNAVAILABLE = "TC_CREDENTIAL_ENCRYPTION_UNAVAILABLE"
TC_RECIPIENT_X25519_INVALID = "TC_RECIPIENT_X25519_INVALID"

_HEX_32_RE = re.compile(r"^0x[0-9a-f]{64}$")
_HEX_20_RE = re.compile(r"^0x[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_RESOURCE_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_JWT_PART_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_CREDENTIAL_CURSOR_RE = re.compile(
    r"^tinker_credentials_v1\.([A-Za-z0-9_-]+)\.([0-9a-f]{64})$"
)
_ACCOUNT_BINDING_SCHEMA_MATCH = re.fullmatch(
    r"dnai\.tinker-account-binding\.v([1-9][0-9]*)",
    TINKER_ACCOUNT_BINDING_SCHEMA,
)
if _ACCOUNT_BINDING_SCHEMA_MATCH is None:
    raise RuntimeError("shared Tinker account-binding schema has no canonical version")
TINKER_ACCOUNT_BINDING_VERSION = int(_ACCOUNT_BINDING_SCHEMA_MATCH.group(1))
TINKER_ACCOUNT_BINDING_TYPEHASH_WORD = "0x" + TINKER_ACCOUNT_BINDING_TYPEHASH.hex()
TINKER_PROVIDER_NAMESPACE_WORD = "0x" + TINKER_PROVIDER_NAMESPACE.hex()

# No value whose key contains one of these fragments may enter durable state or
# a public response.  The check is intentionally recursive and applies to
# idempotency replay records as well.
_FORBIDDEN_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "project_id",
    "cookie",
    "card_number",
    "card_cvc",
    "card_expiry",
    "payment_method_id",
    "prompt",
    "examples",
    "dataset",
    "output_text",
    "checkpoint_path",
    "raw_run_id",
    "private_key",
    "plaintext_token",
)
_FORBIDDEN_EXACT_KEY_COMPACTS = frozenset(
    {
        "provideraccountid",
        "provideridentifier",
        "providersession",
        "providerauth",
        "bindingroot",
        "reviewershare",
        "reviewershares",
        "authorization",
        "sessioncookie",
        "tinkerapikey",
    }
)


class TinkerCustomerError(ValueError):
    """Rejected customer input, policy transition, or state."""


class TinkerCustomerUnavailable(RuntimeError):
    """Required release, attestation, or durable authority is unavailable."""


class TinkerCustomerConflict(TinkerCustomerError):
    """Idempotency or immutable customer binding conflict."""


class TinkerCustomerNotFound(TinkerCustomerError):
    """Wallet-owned customer resource does not exist."""


class TinkerCustomerStoreCorrupt(TinkerCustomerUnavailable):
    """Durable customer state failed integrity or schema validation."""


class JsonRpc(Protocol):
    """Small JSON-RPC boundary compatible with ``BoundedJsonRpcClient``."""

    def request(self, method: str, params: list[Any]) -> Any:
        """Return a JSON-RPC result or raise."""


class CustomerWalletVerifier(Protocol):
    """Compatible with ``ComputeWalletAuthService``."""

    def verify_token(
        self,
        token: str,
        *,
        required_scope: str = CUSTOMER_WALLET_SCOPE,
        now: int | None = None,
    ) -> Any:
        """Return claims containing an authenticated ``address``."""


class TinkerReleaseReader(Protocol):
    def read(self) -> "TinkerReleaseSnapshot":
        """Re-read the exact frozen release through two independent RPCs."""


class RuntimeEvidenceProvider(Protocol):
    def read(self, *, now: int) -> "RuntimeEvidence":
        """Return one fresh independent TDX/QVL/release-evidence lease."""


class ProvisioningResultProvider(Protocol):
    def consume(
        self,
        *,
        account_id: str,
        request_commitment: str,
        now: int,
    ) -> "AttestedProvisioningResult":
        """Consume a one-shot independently attested provisioning result."""


class SettlementResultProvider(Protocol):
    def consume(
        self,
        *,
        reservation_id: str,
        reservation_commitment: str,
        now: int,
    ) -> "AttestedSettlementResult":
        """Consume a one-shot attested settlement/release result."""


@dataclass(frozen=True)
class CustomerStateAnchorHead:
    """Externally monotonic head for one customer authority store.

    ``sequence`` is advisory on reads because an on-chain resource may share a
    contract-wide sequence with other opaque resources. The authenticated
    32-byte ``head_hash`` is the rollback witness. A successful compare-and-set
    must still return the exact requested local successor sequence.
    """

    sequence: int
    head_hash: str


class CustomerStateAnchor(Protocol):
    """Compare-and-set rollback witness, normally backed by ExecutionPolicyAnchor."""

    def read_head(self) -> CustomerStateAnchorHead:
        """Read the externally finalized head."""

    def compare_and_set(
        self,
        *,
        expected_sequence: int,
        expected_head_hash: str,
        new_sequence: int,
        new_head_hash: str,
    ) -> CustomerStateAnchorHead:
        """Advance exactly once or fail without accepting another predecessor."""


@dataclass(frozen=True)
class ExpectedTinkerRelease:
    contract_address: str
    runtime_code_hash: str
    owner: str
    account_commitment: str
    account_binding_ceremony_receipt_digest: str
    deployment_intent_digest: str
    release_policy_commitment: str
    approved_compose_root: str
    approved_compose_hashes: tuple[str, ...]
    manager_root: str
    managers: tuple[str, ...]
    max_add_balance_policy_units: int
    max_spend_policy_units: int
    chain_id: int = BASE_SEPOLIA_CHAIN_ID

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "contract_address",
            _exact_address(self.contract_address, "contract address"),
        )
        object.__setattr__(
            self,
            "owner",
            _exact_address(self.owner, "release owner"),
        )
        object.__setattr__(
            self,
            "runtime_code_hash",
            _exact_word(self.runtime_code_hash, "runtime code hash"),
        )
        object.__setattr__(
            self,
            "account_commitment",
            _exact_nonzero_word(self.account_commitment, "account commitment"),
        )
        ceremony_receipt = _exact_nonzero_sha256(
            self.account_binding_ceremony_receipt_digest,
            "account-binding ceremony receipt digest",
        )
        deployment_intent = _exact_nonzero_sha256(
            self.deployment_intent_digest,
            "deployment intent digest",
        )
        if hmac.compare_digest(ceremony_receipt, deployment_intent):
            raise TinkerCustomerError(
                "account-binding ceremony receipt and deployment intent must be distinct"
            )
        object.__setattr__(
            self,
            "account_binding_ceremony_receipt_digest",
            ceremony_receipt,
        )
        object.__setattr__(self, "deployment_intent_digest", deployment_intent)
        object.__setattr__(
            self,
            "release_policy_commitment",
            _exact_nonzero_word(
                self.release_policy_commitment,
                "release policy commitment",
            ),
        )
        object.__setattr__(
            self,
            "approved_compose_root",
            _exact_nonzero_word(self.approved_compose_root, "compose root"),
        )
        object.__setattr__(
            self,
            "manager_root",
            _exact_nonzero_word(self.manager_root, "manager root"),
        )
        if type(self.approved_compose_hashes) is not tuple or type(self.managers) is not tuple:
            raise TinkerCustomerError(
                "reviewed compose and manager sets must be exact tuples"
            )
        composes = tuple(
            _exact_nonzero_word(value, "approved compose hash")
            for value in self.approved_compose_hashes
        )
        managers = tuple(
            _exact_address(value, "release manager")
            for value in self.managers
        )
        if not composes or len(composes) > 16 or tuple(sorted(set(composes))) != composes:
            raise TinkerCustomerError("approved compose hashes must be a non-empty sorted unique tuple")
        if not managers or len(managers) > 16 or tuple(sorted(set(managers))) != managers:
            raise TinkerCustomerError("release managers must be a non-empty sorted unique tuple")
        if self.owner in managers:
            raise TinkerCustomerError("release owner and manager roles must be distinct")
        object.__setattr__(self, "approved_compose_hashes", composes)
        object.__setattr__(self, "managers", managers)
        if type(self.chain_id) is not int or self.chain_id != BASE_SEPOLIA_CHAIN_ID:
            raise TinkerCustomerError("Tinker customer release requires Base Sepolia chain 84532")
        max_add = _positive_uint(self.max_add_balance_policy_units, "max add-balance policy units")
        max_spend = _positive_uint(self.max_spend_policy_units, "max spend policy units")
        if max_spend > max_add:
            raise TinkerCustomerError("max spend policy units exceed add-balance policy units")

    def policy_tuple(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "contract_address": self.contract_address,
            "runtime_code_hash": self.runtime_code_hash,
            "owner": self.owner,
            "pending_owner": ZERO_ADDRESS,
            "account_commitment": self.account_commitment,
            "release_policy_commitment": self.release_policy_commitment,
            "release_policy_frozen": True,
            "emergency_halted": False,
            "approved_compose_root": self.approved_compose_root,
            "approved_compose_hashes": list(self.approved_compose_hashes),
            "approved_compose_count": len(self.approved_compose_hashes),
            "manager_root": self.manager_root,
            "managers": list(self.managers),
            "manager_count": len(self.managers),
            "max_add_balance_policy_units": str(self.max_add_balance_policy_units),
            "max_spend_policy_units": str(self.max_spend_policy_units),
            "release_max_add_balance_policy_units": str(self.max_add_balance_policy_units),
            "release_max_spend_policy_units": str(self.max_spend_policy_units),
        }

    @property
    def policy_tuple_digest(self) -> str:
        return _sha256_json("tinker_customer_release_policy", self.policy_tuple())

    @property
    def release_lineage(self) -> dict[str, Any]:
        return _release_lineage(
            account_commitment=self.account_commitment,
            account_binding_ceremony_receipt_digest=(
                self.account_binding_ceremony_receipt_digest
            ),
            deployment_intent_digest=self.deployment_intent_digest,
        )

    @property
    def release_lineage_digest(self) -> str:
        return _sha256_json(
            "tinker_customer_account_binding_release_lineage",
            self.release_lineage,
        )


@dataclass(frozen=True)
class TinkerReleaseSnapshot:
    chain_id: int
    finalized_block_number: int
    finalized_block_hash: str
    contract_address: str
    runtime_code_hash: str
    owner: str
    pending_owner: str
    account_commitment: str
    release_policy_commitment: str
    release_policy_frozen: bool
    emergency_halted: bool
    approved_compose_root: str
    approved_compose_hashes: tuple[str, ...]
    manager_root: str
    managers: tuple[str, ...]
    max_add_balance_policy_units: int
    max_spend_policy_units: int
    release_max_add_balance_policy_units: int
    release_max_spend_policy_units: int

    def policy_tuple(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "contract_address": self.contract_address,
            "runtime_code_hash": self.runtime_code_hash,
            "owner": self.owner,
            "pending_owner": self.pending_owner,
            "account_commitment": self.account_commitment,
            "release_policy_commitment": self.release_policy_commitment,
            "release_policy_frozen": self.release_policy_frozen,
            "emergency_halted": self.emergency_halted,
            "approved_compose_root": self.approved_compose_root,
            "approved_compose_hashes": list(self.approved_compose_hashes),
            "approved_compose_count": len(self.approved_compose_hashes),
            "manager_root": self.manager_root,
            "managers": list(self.managers),
            "manager_count": len(self.managers),
            "max_add_balance_policy_units": str(self.max_add_balance_policy_units),
            "max_spend_policy_units": str(self.max_spend_policy_units),
            "release_max_add_balance_policy_units": str(self.release_max_add_balance_policy_units),
            "release_max_spend_policy_units": str(self.release_max_spend_policy_units),
        }

    @property
    def policy_tuple_digest(self) -> str:
        return _sha256_json("tinker_customer_release_policy", self.policy_tuple())

    @property
    def observation_digest(self) -> str:
        return _sha256_json(
            "tinker_customer_release_observation",
            {
                **self.policy_tuple(),
                "finalized_block_number": self.finalized_block_number,
                "finalized_block_hash": self.finalized_block_hash,
            },
        )


@dataclass(frozen=True)
class RuntimeEvidencePolicy:
    cvm_id_hash: str
    measurement_hash: str
    qvl_policy_hash: str
    release_authority_digest: str
    roles_digest: str
    customer_policy_digest: str
    enabled_operations: tuple[str, ...] = ("training",)
    max_lease_seconds: int = 300

    def __post_init__(self) -> None:
        policy_commitment_error = (
            "runtime evidence policy commitments must be nonzero and "
            "pairwise distinct"
        )
        commitments: dict[str, str] | None = None
        try:
            commitments = _distinct_exact_sha256_commitments(
                {
                    "cvm_id_hash": self.cvm_id_hash,
                    "measurement_hash": self.measurement_hash,
                    "qvl_policy_hash": self.qvl_policy_hash,
                    "release_authority_digest": self.release_authority_digest,
                    "roles_digest": self.roles_digest,
                    "customer_policy_digest": self.customer_policy_digest,
                },
                error_message=policy_commitment_error,
            )
        except TinkerCustomerError:
            pass
        if commitments is None:
            raise TinkerCustomerError(policy_commitment_error)
        for name, commitment in commitments.items():
            object.__setattr__(self, name, commitment)
        operations = _operations(self.enabled_operations)
        if "inference" in operations:
            raise TinkerCustomerError("customer inference remains disabled in this release")
        object.__setattr__(self, "enabled_operations", operations)
        if type(self.max_lease_seconds) is not int or not 1 <= self.max_lease_seconds <= 300:
            raise TinkerCustomerError("runtime evidence lease must be between 1 and 300 seconds")


@dataclass(frozen=True)
class RuntimeEvidence:
    issued_at: int
    expires_at: int
    cvm_id_hash: str
    measurement_hash: str
    qvl_policy_hash: str
    release_authority_digest: str
    roles_digest: str
    customer_policy_digest: str
    release_policy_tuple_digest: str
    account_commitment: str
    compose_hash: str
    manager: str
    enabled_operations: tuple[str, ...]
    tdx_verified: bool
    qvl_pass: bool
    raw_quote_publicly_disclosed: bool = False
    raw_collateral_publicly_disclosed: bool = False
    raw_secret_egress: bool = False

    def public_digest(self) -> str:
        return _sha256_json("tinker_customer_runtime_evidence", _jsonable(asdict(self)))


@dataclass(frozen=True)
class CustomerAccountPolicy:
    allowed_operations: tuple[str, ...] = ("training",)
    max_operation_policy_units: int = 10**18
    max_outstanding_policy_units: int = 5 * 10**18
    max_lifetime_policy_units: int = 10 * 10**18
    credential_max_ttl_seconds: int = 3600
    max_active_credentials: int = 8

    def __post_init__(self) -> None:
        operations = _operations(self.allowed_operations)
        if "inference" in operations:
            raise TinkerCustomerError("customer inference remains disabled in this release")
        object.__setattr__(self, "allowed_operations", operations)
        per_operation = _positive_uint(self.max_operation_policy_units, "customer per-operation cap")
        outstanding = _positive_uint(self.max_outstanding_policy_units, "customer outstanding cap")
        lifetime = _positive_uint(self.max_lifetime_policy_units, "customer lifetime cap")
        if per_operation > outstanding or outstanding > lifetime:
            raise TinkerCustomerError("customer spend caps must be monotonic per-operation <= outstanding <= lifetime")
        if type(self.credential_max_ttl_seconds) is not int or not 60 <= self.credential_max_ttl_seconds <= 3600:
            raise TinkerCustomerError("customer credential max ttl must be between 60 and 3600 seconds")
        if type(self.max_active_credentials) is not int or not 1 <= self.max_active_credentials <= 16:
            raise TinkerCustomerError("customer active credential cap is outside the supported range")

    def public_dict(self) -> dict[str, Any]:
        return {
            "allowed_operations": list(self.allowed_operations),
            "max_operation_policy_units": str(self.max_operation_policy_units),
            "max_outstanding_policy_units": str(self.max_outstanding_policy_units),
            "max_lifetime_policy_units": str(self.max_lifetime_policy_units),
            "credential_max_ttl_seconds": self.credential_max_ttl_seconds,
            "max_active_credentials": self.max_active_credentials,
            "inference_enabled": False,
            "hosted_card_funding": "roadmap",
            "token_exchange": "roadmap",
            "raw_secret_egress": False,
        }

    @property
    def digest(self) -> str:
        return _sha256_json("tinker_customer_account_policy", self.public_dict())


@dataclass(frozen=True)
class AttestedProvisioningResult:
    account_id: str
    request_commitment: str
    owner_address_hash: str
    mode: Literal["create", "link_existing"]
    account_commitment: str
    release_policy_tuple_digest: str
    compose_hash: str
    manager: str
    provisioning_receipt_hash: str
    runtime_evidence_digest: str
    account_binding_schema: str
    account_binding_version: int
    account_binding_chain_id: int
    account_binding_type: str
    account_binding_typehash: str
    provider_namespace_label: str
    provider_namespace: str
    account_binding_receipt_digest: str
    sealed_binding_record_hash: str
    account_binding_ceremony_receipt_digest: str
    deployment_intent_digest: str
    account_binding_receipt_independently_attested: bool
    account_binding_handle_attested: bool
    provider_identity_checked: bool
    current_provider_session_rechecked: bool
    account_commitment_exact_match: bool
    provider_internal_identity_cryptographically_proven: bool
    raw_provider_account_id_egress: bool
    raw_binding_root_egress: bool
    raw_reviewer_share_egress: bool
    binding_root_or_share_digest_published: bool
    raw_provider_auth_egress: bool
    raw_provider_session_egress: bool
    issued_at: int
    expires_at: int
    success: bool
    upstream_account_exists: bool
    raw_account_identifier_returned: bool
    raw_secret_egress: bool


@dataclass(frozen=True)
class AttestedSettlementResult:
    reservation_id: str
    reservation_commitment: str
    outcome: Literal["settled", "released"]
    actual_policy_units: int
    usage_receipt_hash: str
    release_policy_tuple_digest: str
    runtime_evidence_digest: str
    issued_at: int
    expires_at: int
    provider_dispatch_performed: bool
    provider_authoritative_billing: bool = False
    raw_secret_egress: bool = False


@dataclass(frozen=True)
class _Gate:
    snapshot: TinkerReleaseSnapshot
    evidence: RuntimeEvidence

    def public_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.snapshot.chain_id,
            "finalized_block_number": self.snapshot.finalized_block_number,
            "finalized_block_hash": self.snapshot.finalized_block_hash,
            "release_observation_digest": self.snapshot.observation_digest,
            "release_policy_tuple_digest": self.snapshot.policy_tuple_digest,
            "runtime_evidence_digest": self.evidence.public_digest(),
            "tdx_verified": True,
            "qvl_pass": True,
            "raw_quote_publicly_disclosed": False,
            "raw_collateral_publicly_disclosed": False,
            "raw_secret_egress": False,
        }


class DualRpcTinkerReleaseReader:
    """Read and authenticate the exact release at one numeric finalized block."""

    _GETTERS = {
        "owner": "owner()",
        "pending_owner": "pendingOwner()",
        "account_commitment": "accountCommitment()",
        "release_policy_commitment": "releasePolicyCommitment()",
        "release_policy_frozen": "releasePolicyFrozen()",
        "emergency_halted": "emergencyHalted()",
        "approved_compose_root": "approvedComposeRoot()",
        "approved_compose_count": "approvedComposeCount()",
        "manager_root": "managerRoot()",
        "manager_count": "managerCount()",
        "max_add": "maxAddBalanceWei()",
        "max_spend": "maxSpendWei()",
        "release_max_add": "releaseMaxAddBalanceWei()",
        "release_max_spend": "releaseMaxSpendWei()",
    }

    def __init__(self, primary: JsonRpc, secondary: JsonRpc, expected: ExpectedTinkerRelease):
        if primary is secondary:
            raise TinkerCustomerUnavailable("Tinker release verification requires two independent RPC providers")
        _require_distinct_rpc_origins(primary, secondary)
        self.primary = primary
        self.secondary = secondary
        self.expected = expected

    def read(self) -> TinkerReleaseSnapshot:
        try:
            with ThreadPoolExecutor(max_workers=2, thread_name_prefix="tinker-customer-rpc") as executor:
                chain_a, chain_b = self._pair(executor, "eth_chainId", [])
                if _quantity(chain_a, "primary chain id") != BASE_SEPOLIA_CHAIN_ID or _quantity(
                    chain_b, "secondary chain id"
                ) != BASE_SEPOLIA_CHAIN_ID:
                    raise TinkerCustomerUnavailable("Tinker release RPCs are not both on Base Sepolia")

                head_a_raw, head_b_raw = self._pair(executor, "eth_getBlockByNumber", ["finalized", False])
                head_a = _block(head_a_raw, "primary finalized block")
                head_b = _block(head_b_raw, "secondary finalized block")
                if head_a != head_b:
                    raise TinkerCustomerUnavailable(
                        "Tinker release RPCs disagree on the exact finalized head"
                    )
                number = head_a[0]
                tag = hex(number)
                block_a_raw, block_b_raw = self._pair(executor, "eth_getBlockByNumber", [tag, False])
                block_a = _block(block_a_raw, "primary agreed block")
                block_b = _block(block_b_raw, "secondary agreed block")
                if block_a != block_b or block_a[0] != number:
                    raise TinkerCustomerUnavailable("Tinker release RPCs disagree on the finalized block")
                if head_a[0] == number and head_a != block_a:
                    raise TinkerCustomerUnavailable("primary finalized head changed during verification")
                if head_b[0] == number and head_b != block_b:
                    raise TinkerCustomerUnavailable("secondary finalized head changed during verification")

                code_a, code_b = self._pair(
                    executor,
                    "eth_getCode",
                    [self.expected.contract_address, tag],
                )
                code = _same_data(code_a, code_b, "Tinker encumbrance runtime code")
                if not code:
                    raise TinkerCustomerUnavailable("Tinker encumbrance runtime code is empty")
                runtime_code_hash = "0x" + keccak(code).hex()

                words: dict[str, bytes] = {}
                for name, signature in self._GETTERS.items():
                    words[name] = self._call_word(executor, _selector(signature), tag, name)

                compose_count = _word_uint(words["approved_compose_count"])
                manager_count = _word_uint(words["manager_count"])
                if compose_count > 16 or manager_count > 16:
                    raise TinkerCustomerUnavailable("Tinker release authority set exceeds contract bounds")
                composes = tuple(
                    _word_hex(
                        self._call_word(
                            executor,
                            _selector("approvedComposeHashAt(uint256)") + index.to_bytes(32, "big"),
                            tag,
                            f"approved compose {index}",
                        )
                    )
                    for index in range(compose_count)
                )
                managers = tuple(
                    _word_address(
                        self._call_word(
                            executor,
                            _selector("managerAt(uint256)") + index.to_bytes(32, "big"),
                            tag,
                            f"manager {index}",
                        )
                    )
                    for index in range(manager_count)
                )
                for compose_hash in composes:
                    approved = self._call_word(
                        executor,
                        _selector("approvedComposeHashes(bytes32)") + bytes.fromhex(compose_hash[2:]),
                        tag,
                        "compose membership",
                    )
                    if not _word_bool(approved, "compose membership"):
                        raise TinkerCustomerUnavailable("enumerated Tinker compose is not approved")
                for manager in managers:
                    approved = self._call_word(
                        executor,
                        _selector("managers(address)") + _address_word(manager),
                        tag,
                        "manager membership",
                    )
                    if not _word_bool(approved, "manager membership"):
                        raise TinkerCustomerUnavailable("enumerated Tinker manager is not approved")
                final_block_a_raw, final_block_b_raw = self._pair(
                    executor,
                    "eth_getBlockByNumber",
                    [tag, False],
                )
                final_block_a = _block(final_block_a_raw, "primary final agreed block")
                final_block_b = _block(final_block_b_raw, "secondary final agreed block")
                if final_block_a != block_a or final_block_b != block_a:
                    raise TinkerCustomerUnavailable(
                        "Tinker release finalized block changed during policy verification"
                    )
        except TinkerCustomerUnavailable:
            raise
        except Exception as exc:
            raise TinkerCustomerUnavailable("Tinker release verification is unavailable") from exc

        snapshot = TinkerReleaseSnapshot(
            chain_id=BASE_SEPOLIA_CHAIN_ID,
            finalized_block_number=number,
            finalized_block_hash=block_a[1],
            contract_address=self.expected.contract_address,
            runtime_code_hash=runtime_code_hash,
            owner=_word_address(words["owner"]),
            pending_owner=_word_address(words["pending_owner"]),
            account_commitment=_word_hex(words["account_commitment"]),
            release_policy_commitment=_word_hex(words["release_policy_commitment"]),
            release_policy_frozen=_word_bool(words["release_policy_frozen"], "release policy frozen"),
            emergency_halted=_word_bool(words["emergency_halted"], "emergency halted"),
            approved_compose_root=_word_hex(words["approved_compose_root"]),
            approved_compose_hashes=composes,
            manager_root=_word_hex(words["manager_root"]),
            managers=managers,
            max_add_balance_policy_units=_word_uint(words["max_add"]),
            max_spend_policy_units=_word_uint(words["max_spend"]),
            release_max_add_balance_policy_units=_word_uint(words["release_max_add"]),
            release_max_spend_policy_units=_word_uint(words["release_max_spend"]),
        )
        _validate_release_snapshot(snapshot, self.expected)
        return snapshot

    def _pair(
        self,
        executor: ThreadPoolExecutor,
        method: str,
        params: list[Any],
    ) -> tuple[Any, Any]:
        first = executor.submit(self.primary.request, method, params)
        second = executor.submit(self.secondary.request, method, params)
        return first.result(), second.result()

    def _call_word(
        self,
        executor: ThreadPoolExecutor,
        calldata: bytes,
        block_tag: str,
        label: str,
    ) -> bytes:
        first, second = self._pair(
            executor,
            "eth_call",
            [{"to": self.expected.contract_address, "data": "0x" + calldata.hex()}, block_tag],
        )
        data = _same_data(first, second, label)
        if len(data) != 32:
            raise TinkerCustomerUnavailable(f"{label} did not return one ABI word")
        return data


class TinkerCustomerStore:
    """Transactional, HMAC-authenticated single-process customer authority store."""

    def __init__(self, path: str | Path, integrity_key: bytes, *, anchor: CustomerStateAnchor):
        self.path = Path(path)
        if not str(self.path) or not self.path.is_absolute() or self.path.name in ("", ".", ".."):
            raise TinkerCustomerUnavailable("Tinker customer store requires an absolute file path")
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise TinkerCustomerUnavailable("Tinker customer store integrity key must be at least 32 bytes")
        if anchor is None:
            raise TinkerCustomerUnavailable("Tinker customer store requires an external monotonic anchor")
        _assert_no_symlink_components(self.path.parent)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            directory_fd = os.open(self.path.parent, flags)
            directory_stat = os.fstat(directory_fd)
        except OSError as exc:
            raise TinkerCustomerUnavailable("Tinker customer store directory is unavailable") from exc
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.geteuid()
            or (directory_stat.st_mode & 0o777) != 0o700
        ):
            os.close(directory_fd)
            raise TinkerCustomerUnavailable(
                "Tinker customer store directory must be owner-controlled mode 0700"
            )
        self._key = hashlib.sha256(b"dnai-tinker-customer-store-v1:" + integrity_key).digest()
        self._anchor = anchor
        self._pending_path = self.path.with_suffix(self.path.suffix + ".pending")
        self._directory_fd = directory_fd
        self._file_name = self.path.name
        self._pending_name = self._pending_path.name
        self._lock = threading.RLock()

    def read(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._load_and_reconcile_locked())

    def encode_credential_cursor(
        self,
        *,
        account_id: str,
        snapshot_sequence: int,
        anchor_issued_at: int,
        anchor_credential_id: str,
    ) -> str:
        """Return an opaque account/snapshot-bound credential-page cursor."""

        payload = {
            "account_id": _resource(
                account_id,
                "credential cursor account id",
                prefix="tca_",
            ),
            "snapshot_sequence": _uint(
                snapshot_sequence,
                "credential cursor snapshot sequence",
            ),
            "anchor_issued_at": _positive_uint(
                anchor_issued_at,
                "credential cursor issue time",
            ),
            "anchor_credential_id": _resource(
                anchor_credential_id,
                "credential cursor credential id",
                prefix="tcc_",
            ),
        }
        encoded = _b64url(_canonical_bytes(payload)).decode("ascii")
        signature = hmac.new(
            self._key,
            (
                b"dnai-wikigen/tinker-customer-credential-list-cursor/v1\0"
                + encoded.encode("ascii")
            ),
            hashlib.sha256,
        ).hexdigest()
        cursor = f"tinker_credentials_v1.{encoded}.{signature}"
        if len(cursor.encode("utf-8")) > MAX_CUSTOMER_CREDENTIAL_CURSOR_BYTES:
            raise TinkerCustomerUnavailable(
                "customer credential cursor exceeded its public bound"
            )
        return cursor

    def decode_credential_cursor(
        self,
        cursor: str,
        *,
        expected_account_id: str,
        expected_snapshot_sequence: int,
    ) -> tuple[int, str]:
        """Verify one cursor and return its exact descending-order anchor."""

        expected_account = _resource(
            expected_account_id,
            "credential cursor account id",
            prefix="tca_",
        )
        expected_sequence = _uint(
            expected_snapshot_sequence,
            "credential cursor snapshot sequence",
        )
        if (
            not isinstance(cursor, str)
            or len(cursor.encode("utf-8"))
            > MAX_CUSTOMER_CREDENTIAL_CURSOR_BYTES
        ):
            raise TinkerCustomerConflict(
                "credential cursor is invalid; restart listing"
            )
        match = _CREDENTIAL_CURSOR_RE.fullmatch(cursor)
        if match is None:
            raise TinkerCustomerConflict(
                "credential cursor is invalid; restart listing"
            )
        encoded, supplied_signature = match.groups()
        expected_signature = hmac.new(
            self._key,
            (
                b"dnai-wikigen/tinker-customer-credential-list-cursor/v1\0"
                + encoded.encode("ascii")
            ),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise TinkerCustomerConflict(
                "credential cursor is invalid; restart listing"
            )
        try:
            raw = _b64url_decode(encoded)
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TinkerCustomerConflict(
                "credential cursor is invalid; restart listing"
            ) from exc
        if (
            not isinstance(payload, dict)
            or set(payload) != {
                "account_id",
                "snapshot_sequence",
                "anchor_issued_at",
                "anchor_credential_id",
            }
            or _canonical_bytes(payload) != raw
        ):
            raise TinkerCustomerConflict(
                "credential cursor is invalid; restart listing"
            )
        try:
            account_id = _resource(
                payload["account_id"],
                "credential cursor account id",
                prefix="tca_",
            )
            snapshot_sequence = _uint(
                payload["snapshot_sequence"],
                "credential cursor snapshot sequence",
            )
            anchor_issued_at = _positive_uint(
                payload["anchor_issued_at"],
                "credential cursor issue time",
            )
            anchor_credential_id = _resource(
                payload["anchor_credential_id"],
                "credential cursor credential id",
                prefix="tcc_",
            )
        except TinkerCustomerError as exc:
            raise TinkerCustomerConflict(
                "credential cursor is invalid; restart listing"
            ) from exc
        if (
            account_id != expected_account
            or snapshot_sequence != expected_sequence
        ):
            raise TinkerCustomerConflict(
                "credential cursor is stale; restart listing"
            )
        return anchor_issued_at, anchor_credential_id

    def transact(self, mutation) -> Any:
        with self._lock:
            state = self._load_and_reconcile_locked()
            candidate = copy.deepcopy(state)
            result = mutation(candidate)
            _validate_customer_state(candidate)
            if candidate == state:
                if not isinstance(result, dict) or result.get("idempotent_replay") is not True:
                    raise TinkerCustomerError("customer transaction made no state change without an exact replay")
                return copy.deepcopy(result)
            if (
                candidate["sequence"] != state["sequence"] + 1
                or candidate["head_hash"] == state["head_hash"]
            ):
                raise TinkerCustomerError("customer transaction must advance exactly one event")
            self._write_path_locked(self._pending_path, candidate)
            anchored = _fixed_external_call(
                lambda: _validated_anchor_head(
                    self._anchor.compare_and_set(
                        expected_sequence=state["sequence"],
                        expected_head_hash=state["head_hash"],
                        new_sequence=candidate["sequence"],
                        new_head_hash=candidate["head_hash"],
                    )
                ),
                error_type=TinkerCustomerUnavailable,
                error_code=TC_STATE_ANCHOR_UPDATE_UNAVAILABLE,
            )
            # An external write can be ambiguous. The authenticated candidate is
            # retained so the next read can compare it with the anchor and either
            # promote or discard it without replaying the mutation.
            if anchored.sequence != candidate["sequence"] or not hmac.compare_digest(
                anchored.head_hash, candidate["head_hash"]
            ):
                raise TinkerCustomerUnavailable("customer state anchor returned an unexpected successor")
            self._promote_pending_locked()
            return copy.deepcopy(result)

    def _load_and_reconcile_locked(self) -> dict[str, Any]:
        state = self._load_path_locked(self.path) if self._entry_exists_locked(self._file_name) else _empty_state()
        if self._entry_exists_locked(self._pending_name):
            pending = self._load_path_locked(self._pending_path)
            if pending["sequence"] != state["sequence"] + 1:
                raise TinkerCustomerStoreCorrupt("customer pending state is not the next successor")
            anchored = self._read_anchor_head_locked()
            if hmac.compare_digest(anchored.head_hash, pending["head_hash"]):
                self._promote_pending_locked()
                state = pending
            elif hmac.compare_digest(anchored.head_hash, state["head_hash"]):
                try:
                    os.unlink(self._pending_name, dir_fd=self._directory_fd)
                    self._fsync_parent_locked()
                except OSError as exc:
                    raise TinkerCustomerUnavailable("unanchored customer pending state cannot be cleared") from exc
            else:
                raise TinkerCustomerStoreCorrupt("customer pending state and external anchor diverge")
        anchored = self._read_anchor_head_locked()
        if not hmac.compare_digest(anchored.head_hash, state["head_hash"]):
            raise TinkerCustomerStoreCorrupt("customer state is stale relative to its external anchor")
        return state

    def _load_path_locked(self, path: Path) -> dict[str, Any]:
        name = self._entry_name(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(name, flags, dir_fd=self._directory_fd)
            file_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_nlink != 1
                or file_stat.st_uid != os.geteuid()
                or (file_stat.st_mode & 0o777) != 0o600
                or file_stat.st_size <= 0
                or file_stat.st_size > MAX_CUSTOMER_STORE_BYTES
            ):
                raise TinkerCustomerStoreCorrupt("Tinker customer store file metadata is invalid")
            chunks: list[bytes] = []
            remaining = file_stat.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1_048_576))
                if not chunk:
                    raise TinkerCustomerStoreCorrupt("Tinker customer store ended before its declared size")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise TinkerCustomerStoreCorrupt("Tinker customer store exceeds its declared size")
            raw = b"".join(chunks)
            document = json.loads(raw)
        except TinkerCustomerStoreCorrupt:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TinkerCustomerStoreCorrupt("Tinker customer store is unreadable") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if not isinstance(document, dict) or set(document) != {"schema_version", "state", "mac"}:
            raise TinkerCustomerStoreCorrupt("Tinker customer store envelope is invalid")
        if (
            type(document.get("schema_version")) is not int
            or document.get("schema_version") != 1
            or not isinstance(document.get("state"), dict)
        ):
            raise TinkerCustomerStoreCorrupt("Tinker customer store schema is invalid")
        mac = str(document.get("mac", ""))
        expected = hmac.new(self._key, _canonical_bytes(document["state"]), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            raise TinkerCustomerStoreCorrupt("Tinker customer store integrity check failed")
        try:
            _validate_customer_state(document["state"])
        except TinkerCustomerError as exc:
            raise TinkerCustomerStoreCorrupt("Tinker customer store state is invalid") from exc
        return document["state"]

    def _write_path_locked(self, target: Path, state: dict[str, Any]) -> None:
        _assert_no_forbidden_fields(state)
        document = {
            "schema_version": 1,
            "state": state,
            "mac": hmac.new(self._key, _canonical_bytes(state), hashlib.sha256).hexdigest(),
        }
        payload = _canonical_bytes(document) + b"\n"
        if len(payload) > MAX_CUSTOMER_STORE_BYTES:
            raise TinkerCustomerUnavailable("Tinker customer store exceeds its exact byte cap")
        target_name = self._entry_name(target)
        temporary_name = f".{target_name}.{secrets.token_hex(12)}.tmp"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=self._directory_fd,
            )
            os.fchmod(descriptor, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temporary_name,
                target_name,
                src_dir_fd=self._directory_fd,
                dst_dir_fd=self._directory_fd,
            )
            self._fsync_parent_locked()
        except OSError as exc:
            raise TinkerCustomerUnavailable("Tinker customer store transaction failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=self._directory_fd)
            except FileNotFoundError:
                pass

    def _read_anchor_head_locked(self) -> CustomerStateAnchorHead:
        head = _fixed_external_call(
            lambda: _validated_anchor_head(self._anchor.read_head()),
            error_type=TinkerCustomerUnavailable,
            error_code=TC_STATE_ANCHOR_READ_UNAVAILABLE,
        )
        return head

    def _promote_pending_locked(self) -> None:
        try:
            os.replace(
                self._pending_name,
                self._file_name,
                src_dir_fd=self._directory_fd,
                dst_dir_fd=self._directory_fd,
            )
            self._fsync_parent_locked()
        except OSError as exc:
            raise TinkerCustomerUnavailable("anchored customer state cannot be promoted") from exc

    def _fsync_parent_locked(self) -> None:
        os.fsync(self._directory_fd)

    def _entry_name(self, path: Path) -> str:
        if path.parent != self.path.parent or path.name not in (self._file_name, self._pending_name):
            raise TinkerCustomerUnavailable("Tinker customer store entry is outside the pinned directory")
        return path.name

    def _entry_exists_locked(self, name: str) -> bool:
        try:
            entry_stat = os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise TinkerCustomerUnavailable("Tinker customer store entry cannot be inspected") from exc
        if stat.S_ISLNK(entry_stat.st_mode) or not stat.S_ISREG(entry_stat.st_mode):
            raise TinkerCustomerStoreCorrupt("Tinker customer store entry is not a regular file")
        return True


class TinkerCustomerAdapter:
    """Monotonic wallet-owner account, credential, and spend authority service."""

    def __init__(
        self,
        *,
        wallet_verifier: CustomerWalletVerifier,
        release_reader: TinkerReleaseReader,
        expected_release: ExpectedTinkerRelease,
        evidence_provider: RuntimeEvidenceProvider,
        evidence_policy: RuntimeEvidencePolicy,
        provisioning_provider: ProvisioningResultProvider,
        settlement_provider: SettlementResultProvider,
        store: TinkerCustomerStore,
        account_policy: CustomerAccountPolicy,
        credential_signing_key: bytes,
    ) -> None:
        if not isinstance(credential_signing_key, bytes) or len(credential_signing_key) < 32:
            raise TinkerCustomerUnavailable("customer credential signing key must be at least 32 bytes")
        if account_policy.max_operation_policy_units > expected_release.max_spend_policy_units:
            raise TinkerCustomerError("customer per-operation cap exceeds the frozen on-chain spend cap")
        if evidence_policy.customer_policy_digest != account_policy.digest:
            raise TinkerCustomerError("customer account policy is not bound by the release evidence policy")
        if any(operation not in evidence_policy.enabled_operations for operation in account_policy.allowed_operations):
            raise TinkerCustomerError("customer operations exceed the release evidence policy")
        self.wallet_verifier = wallet_verifier
        self.release_reader = release_reader
        self.expected_release = expected_release
        self.evidence_provider = evidence_provider
        self.evidence_policy = evidence_policy
        self.provisioning_provider = provisioning_provider
        self.settlement_provider = settlement_provider
        self.store = store
        self.account_policy = account_policy
        self._credential_key = hashlib.sha256(
            b"dnai-tinker-customer-credential-v1:" + credential_signing_key
        ).digest()
        self._mutation_lock = threading.RLock()
        self._audit_persisted_release_lineage()

    def request_account(
        self,
        *,
        wallet_token: str,
        mode: Literal["create", "link_existing"],
        idempotency_key: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        wallet = self._wallet(wallet_token, current)
        if type(mode) is not str or mode not in ("create", "link_existing"):
            raise TinkerCustomerError("customer account request mode is invalid")
        idempotency_key = _idempotency_key(idempotency_key)
        with self._mutation_lock:
            gate = self._gate(current)
            request = {
                "operation": "request_account",
                "owner_address": wallet,
                "mode": mode,
                "release_policy_tuple_digest": gate.snapshot.policy_tuple_digest,
                "release_lineage_digest": self.expected_release.release_lineage_digest,
                "account_policy_digest": self.account_policy.digest,
            }
            request_hash = _sha256_json("tinker_customer_idempotent_request", request)

            def mutation(state: dict[str, Any]) -> dict[str, Any]:
                replay = _idempotent_replay(state, idempotency_key, request_hash)
                if replay is not None:
                    return _replay(replay)
                existing = [record for record in state["accounts"].values() if record["owner_address"] == wallet]
                if existing:
                    raise TinkerCustomerConflict("wallet already has an immutable Tinker customer account binding")
                if len(state["accounts"]) >= MAX_CUSTOMER_ACCOUNTS:
                    raise TinkerCustomerUnavailable("Tinker customer account capacity reached")
                request_commitment = _sha256_json("tinker_customer_account_request", request)
                account_id = "tca_" + request_commitment.split(":", 1)[1][:24]
                if account_id in state["accounts"]:
                    raise TinkerCustomerUnavailable(
                        "Tinker customer account identity collision"
                    )
                created_at = current
                state["accounts"][account_id] = {
                    "account_id": account_id,
                    "owner_address": wallet,
                    "owner_address_hash": _address_hash(wallet),
                    "mode": mode,
                    "status": "requested",
                    "request_commitment": request_commitment,
                    "release_policy_tuple_digest": gate.snapshot.policy_tuple_digest,
                    "release_lineage_digest":
                        self.expected_release.release_lineage_digest,
                    "account_commitment": gate.snapshot.account_commitment,
                    "account_policy": self.account_policy.public_dict(),
                    "account_policy_digest": self.account_policy.digest,
                    "created_at": created_at,
                    "activated_at": 0,
                    "revoked_at": 0,
                    "provisioning_receipt_hash": "",
                    "account_binding_authority": {},
                    "settled_policy_units": "0",
                    "outstanding_policy_units": "0",
                }
                receipt = {
                    "surface": "tinker_customer_account_request",
                    "schema_version": 1,
                    "account_id": account_id,
                    "status": "requested",
                    "mode": mode,
                    "request_commitment": request_commitment,
                    "owner_address_hash": _address_hash(wallet),
                    "release_lineage_digest":
                        self.expected_release.release_lineage_digest,
                    "account_binding_ceremony_receipt_digest":
                        self.expected_release.account_binding_ceremony_receipt_digest,
                    "deployment_intent_digest":
                        self.expected_release.deployment_intent_digest,
                    "account_policy": self.account_policy.public_dict(),
                    "upstream_account_exists": False,
                    "provisioning_performed": False,
                    "browser_supplied_account_commitment_accepted": False,
                    "hosted_card_funding": "roadmap",
                    "token_exchange": "roadmap",
                    "gate": gate.public_dict(),
                    "idempotent_replay": False,
                    "raw_secret_egress": False,
                }
                _record_event(state, "account_requested", receipt)
                _put_idempotency(state, idempotency_key, request_hash, receipt)
                return receipt

            return self.store.transact(mutation)

    def activate_account(
        self,
        *,
        account_id: str,
        idempotency_key: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Activate only from the injected one-shot attested provisioning provider."""

        current = _now(now)
        account_id = _resource(account_id, "account id", prefix="tca_")
        idempotency_key = _idempotency_key(idempotency_key)
        with self._mutation_lock:
            gate = self._gate(current)
            state_before = self.store.read()
            account_before = _account(state_before, account_id)
            self._require_requested_account_release(account_before)
            request = {
                "operation": "activate_account",
                "account_id": account_id,
                "request_commitment": account_before["request_commitment"],
                "release_policy_tuple_digest": gate.snapshot.policy_tuple_digest,
                "release_lineage_digest": self.expected_release.release_lineage_digest,
            }
            request_hash = _sha256_json("tinker_customer_idempotent_request", request)
            replay = _idempotent_replay(state_before, idempotency_key, request_hash)
            if replay is not None:
                return _replay(replay)
            if account_before["status"] != "requested":
                raise TinkerCustomerConflict("Tinker customer account is not awaiting activation")
            result, account_binding_authority = _fixed_external_call(
                lambda: _consume_and_validate_provisioning_result(
                    self.provisioning_provider,
                    account_id=account_id,
                    request_commitment=account_before["request_commitment"],
                    account=account_before,
                    gate=gate,
                    now=current,
                    expected_release=self.expected_release,
                ),
                error_type=TinkerCustomerUnavailable,
                error_code=TC_PROVISIONING_PROVIDER_UNAVAILABLE,
            )
            account_binding_authority_digest = _account_binding_authority_digest(
                account_binding_authority
            )

            def mutation(state: dict[str, Any]) -> dict[str, Any]:
                replay_inner = _idempotent_replay(state, idempotency_key, request_hash)
                if replay_inner is not None:
                    return _replay(replay_inner)
                account = _account(state, account_id)
                if account != account_before:
                    raise TinkerCustomerConflict("Tinker customer account changed during provisioning")
                self._require_requested_account_release(account)
                account["status"] = "active"
                account["activated_at"] = current
                account["provisioning_receipt_hash"] = result.provisioning_receipt_hash
                account["account_binding_authority"] = copy.deepcopy(
                    account_binding_authority
                )
                receipt = {
                    "surface": "tinker_customer_account_activation",
                    "schema_version": 1,
                    "account_id": account_id,
                    "status": "active",
                    "mode": account["mode"],
                    "request_commitment": account["request_commitment"],
                    "owner_address_hash": account["owner_address_hash"],
                    "account_commitment": account["account_commitment"],
                    "release_lineage_digest":
                        self.expected_release.release_lineage_digest,
                    "account_binding_authority_digest":
                        account_binding_authority_digest,
                    "provisioning_receipt_hash": result.provisioning_receipt_hash,
                    "account_binding_ceremony_receipt_digest":
                        account_binding_authority[
                            "account_binding_ceremony_receipt_digest"
                        ],
                    "deployment_intent_digest": account_binding_authority[
                        "deployment_intent_digest"
                    ],
                    "provisioning_result_attested": True,
                    "account_binding_authority": copy.deepcopy(
                        account_binding_authority
                    ),
                    "upstream_account_exists": True,
                    "raw_account_identifier_returned": False,
                    "browser_supplied_account_commitment_accepted": False,
                    "gate": gate.public_dict(),
                    "idempotent_replay": False,
                    "raw_secret_egress": False,
                }
                _record_event(state, "account_activated", receipt)
                _put_idempotency(state, idempotency_key, request_hash, receipt)
                return receipt

            return self.store.transact(mutation)

    def issue_credential(
        self,
        *,
        wallet_token: str,
        account_id: str,
        recipient_public_key: str,
        operations: tuple[str, ...] | list[str],
        ttl_seconds: int,
        idempotency_key: str,
        max_operation_policy_units: int | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        wallet = self._wallet(wallet_token, current)
        account_id = _resource(account_id, "account id", prefix="tca_")
        requested_operations = _operations(tuple(operations))
        if "inference" in requested_operations:
            raise TinkerCustomerUnavailable("customer inference credential issuance is disabled in this release")
        if any(operation not in self.account_policy.allowed_operations for operation in requested_operations):
            raise TinkerCustomerError("requested customer credential operation is not allowed")
        if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= self.account_policy.credential_max_ttl_seconds:
            raise TinkerCustomerError("customer credential ttl is outside the account policy")
        credential_cap = (
            self.account_policy.max_operation_policy_units
            if max_operation_policy_units is None
            else _positive_uint(
                max_operation_policy_units,
                "customer credential operation cap",
            )
        )
        if credential_cap > self.account_policy.max_operation_policy_units:
            raise TinkerCustomerError(
                "customer credential operation cap exceeds the immutable account policy"
            )
        recipient = _x25519_public_key(recipient_public_key)
        recipient_hash = _sha256_text("tinker_customer_recipient", recipient_public_key.lower())
        idempotency_key = _idempotency_key(idempotency_key)
        with self._mutation_lock:
            gate = self._gate(current)
            request = {
                "operation": "issue_credential",
                "owner_address": wallet,
                "account_id": account_id,
                "recipient_public_key_hash": recipient_hash,
                "operations": list(requested_operations),
                "ttl_seconds": ttl_seconds,
                "max_operation_policy_units": str(credential_cap),
                "release_policy_tuple_digest": gate.snapshot.policy_tuple_digest,
                "release_lineage_digest": self.expected_release.release_lineage_digest,
                "account_policy_digest": self.account_policy.digest,
            }
            request_hash = _sha256_json("tinker_customer_idempotent_request", request)

            def mutation(state: dict[str, Any]) -> dict[str, Any]:
                replay = _idempotent_replay(state, idempotency_key, request_hash)
                if replay is not None:
                    return _replay(replay)
                account = _owned_active_account(state, account_id, wallet)
                lineage = self._require_immutable_account_authority(account)
                active = [
                    credential
                    for credential in state["credentials"].values()
                    if credential["account_id"] == account_id
                    and credential["status"] == "active"
                    and current < credential["expires_at"]
                ]
                if len(active) >= self.account_policy.max_active_credentials:
                    raise TinkerCustomerUnavailable("customer credential capacity reached")
                if len(state["credentials"]) >= MAX_CUSTOMER_CREDENTIALS:
                    raise TinkerCustomerUnavailable("global customer credential capacity reached")
                credential_id = "tcc_" + secrets.token_hex(12)
                if credential_id in state["credentials"]:
                    raise TinkerCustomerUnavailable(
                        "customer credential identity collision"
                    )
                jwt_id = secrets.token_hex(16)
                expires_at = current + ttl_seconds
                scopes = tuple(CUSTOMER_OPERATION_SCOPE[operation] for operation in requested_operations)
                payload = {
                    "iss": CUSTOMER_CREDENTIAL_ISSUER,
                    "aud": CUSTOMER_CREDENTIAL_AUDIENCE,
                    "sub": credential_id,
                    "account_id": account_id,
                    "owner_address_hash": account["owner_address_hash"],
                    "scope": " ".join(scopes),
                    "operations": " ".join(requested_operations),
                    "max_operation_policy_units": str(credential_cap),
                    "release_policy_tuple_digest": gate.snapshot.policy_tuple_digest,
                    "release_lineage_digest": lineage["release_lineage_digest"],
                    "account_binding_authority_digest":
                        lineage["account_binding_authority_digest"],
                    "account_binding_ceremony_receipt_digest":
                        lineage["account_binding_ceremony_receipt_digest"],
                    "deployment_intent_digest": lineage["deployment_intent_digest"],
                    "account_policy_digest": self.account_policy.digest,
                    "iat": current,
                    "nbf": current,
                    "exp": expires_at,
                    "jti": jwt_id,
                }
                token = _encode_jwt(payload, self._credential_key)
                jwt_id_hash = _sha256_text("tinker_customer_jti", jwt_id)
                associated_data_object = {
                    "surface": "tinker_customer_credential",
                    "credential_id": credential_id,
                    "account_id": account_id,
                    "owner_address_hash": account["owner_address_hash"],
                    "recipient_public_key_hash": recipient_hash,
                    "operations": list(requested_operations),
                    "max_operation_policy_units": str(credential_cap),
                    "jwt_id_hash": jwt_id_hash,
                    "release_policy_tuple_digest": gate.snapshot.policy_tuple_digest,
                    "release_lineage_digest": lineage["release_lineage_digest"],
                    "account_binding_authority_digest":
                        lineage["account_binding_authority_digest"],
                    "account_binding_ceremony_receipt_digest":
                        lineage["account_binding_ceremony_receipt_digest"],
                    "deployment_intent_digest": lineage["deployment_intent_digest"],
                    "account_policy_digest": self.account_policy.digest,
                    "expires_at": expires_at,
                }
                associated_data = _canonical_bytes(associated_data_object)
                envelope = _fixed_external_call(
                    lambda: encrypt_for_tee(
                        token.encode("utf-8"),
                        recipient,
                        info=CUSTOMER_CREDENTIAL_HKDF_INFO,
                        associated_data=associated_data,
                    ),
                    error_type=TinkerCustomerUnavailable,
                    error_code=TC_CREDENTIAL_ENCRYPTION_UNAVAILABLE,
                )
                capsule = {
                    "delivery": "x25519_aes_256_gcm_envelope",
                    "encrypted_token": envelope.to_hex(),
                    "associated_data": associated_data.hex(),
                    "associated_data_hash": _sha256_text("tinker_customer_credential_aad", associated_data.hex()),
                    "recipient_public_key_hash": recipient_hash,
                    "token_returned_in_plaintext": False,
                }
                state["credentials"][credential_id] = {
                    "credential_id": credential_id,
                    "account_id": account_id,
                    "owner_address_hash": account["owner_address_hash"],
                    "recipient_public_key_hash": recipient_hash,
                    "operations": list(requested_operations),
                    "scopes": list(scopes),
                    "max_operation_policy_units": str(credential_cap),
                    "release_policy_tuple_digest": gate.snapshot.policy_tuple_digest,
                    "release_lineage_digest": lineage["release_lineage_digest"],
                    "account_binding_authority_digest":
                        lineage["account_binding_authority_digest"],
                    "account_binding_ceremony_receipt_digest":
                        lineage["account_binding_ceremony_receipt_digest"],
                    "deployment_intent_digest": lineage["deployment_intent_digest"],
                    "account_policy_digest": self.account_policy.digest,
                    "jwt_id_hash": jwt_id_hash,
                    "status": "active",
                    "issued_at": current,
                    "expires_at": expires_at,
                    "revoked_at": 0,
                }
                receipt = {
                    "surface": "tinker_customer_credential_issue",
                    "schema_version": 1,
                    "credential_id": credential_id,
                    "account_id": account_id,
                    "status": "active",
                    "operations": list(requested_operations),
                    "scopes": list(scopes),
                    "max_operation_policy_units": str(credential_cap),
                    "account_policy_digest": self.account_policy.digest,
                    "release_lineage_digest": lineage["release_lineage_digest"],
                    "account_binding_authority_digest":
                        lineage["account_binding_authority_digest"],
                    "account_binding_ceremony_receipt_digest":
                        lineage["account_binding_ceremony_receipt_digest"],
                    "deployment_intent_digest": lineage["deployment_intent_digest"],
                    "issued_at": current,
                    "expires_at": expires_at,
                    "jwt_id_hash": jwt_id_hash,
                    "capsule": capsule,
                    "upstream_tinker_key_exposed": False,
                    "upstream_project_exposed": False,
                    "token_returned_in_plaintext": False,
                    "gate": gate.public_dict(),
                    "idempotent_replay": False,
                    "raw_secret_egress": False,
                }
                _record_event(state, "credential_issued", {key: value for key, value in receipt.items() if key != "capsule"})
                _put_idempotency(state, idempotency_key, request_hash, receipt)
                return receipt

            return self.store.transact(mutation)

    def revoke_credential(
        self,
        *,
        wallet_token: str,
        account_id: str,
        credential_id: str,
        idempotency_key: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        wallet = self._wallet(wallet_token, current)
        account_id = _resource(account_id, "account id", prefix="tca_")
        credential_id = _resource(credential_id, "credential id", prefix="tcc_")
        idempotency_key = _idempotency_key(idempotency_key)
        with self._mutation_lock:
            gate = self._gate(current)
            request = {
                "operation": "revoke_credential",
                "owner_address": wallet,
                "account_id": account_id,
                "credential_id": credential_id,
                "release_lineage_digest": self.expected_release.release_lineage_digest,
            }
            request_hash = _sha256_json("tinker_customer_idempotent_request", request)

            def mutation(state: dict[str, Any]) -> dict[str, Any]:
                replay = _idempotent_replay(state, idempotency_key, request_hash)
                if replay is not None:
                    return _replay(replay)
                account = _owned_account(state, account_id, wallet)
                lineage = self._require_immutable_account_authority(account)
                credential = _credential(state, credential_id, account_id)
                if credential["status"] == "revoked":
                    raise TinkerCustomerConflict("customer credential is already revoked")
                credential["status"] = "revoked"
                credential["revoked_at"] = current
                receipt = {
                    "surface": "tinker_customer_credential_revoke",
                    "schema_version": 1,
                    "credential_id": credential_id,
                    "account_id": account_id,
                    "status": "revoked",
                    "jwt_id_hash": credential["jwt_id_hash"],
                    "release_lineage_digest": lineage["release_lineage_digest"],
                    "account_binding_authority_digest":
                        lineage["account_binding_authority_digest"],
                    "account_binding_ceremony_receipt_digest":
                        lineage["account_binding_ceremony_receipt_digest"],
                    "deployment_intent_digest": lineage["deployment_intent_digest"],
                    "revoked_at": current,
                    "gate": gate.public_dict(),
                    "idempotent_replay": False,
                    "raw_secret_egress": False,
                }
                _record_event(state, "credential_revoked", receipt)
                _put_idempotency(state, idempotency_key, request_hash, receipt)
                return receipt

            return self.store.transact(mutation)

    def rotate_credential(
        self,
        *,
        wallet_token: str,
        account_id: str,
        credential_id: str,
        recipient_public_key: str,
        operations: tuple[str, ...] | list[str],
        ttl_seconds: int,
        idempotency_key: str,
        max_operation_policy_units: int | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Revoke the prior authority before issuing its bounded replacement.

        Rotation is intentionally fail-safe rather than overlap-safe: the old
        credential is terminally revoked first. If the second anchored
        transaction cannot complete, no new authority exists and an exact
        retry resumes from the two deterministic child idempotency keys.
        """

        current = _now(now)
        account_id = _resource(account_id, "account id", prefix="tca_")
        credential_id = _resource(
            credential_id,
            "credential id",
            prefix="tcc_",
        )
        base_idempotency_key = _idempotency_key(idempotency_key)
        requested_operations = _operations(tuple(operations))
        if "inference" in requested_operations:
            raise TinkerCustomerUnavailable(
                "customer inference credential issuance is disabled in this release"
            )
        if any(
            operation not in self.account_policy.allowed_operations
            for operation in requested_operations
        ):
            raise TinkerCustomerError(
                "requested customer credential operation is not allowed"
            )
        if (
            type(ttl_seconds) is not int
            or not 60
            <= ttl_seconds
            <= self.account_policy.credential_max_ttl_seconds
        ):
            raise TinkerCustomerError(
                "customer credential ttl is outside the account policy"
            )
        credential_cap = (
            self.account_policy.max_operation_policy_units
            if max_operation_policy_units is None
            else _positive_uint(
                max_operation_policy_units,
                "customer credential operation cap",
            )
        )
        if credential_cap > self.account_policy.max_operation_policy_units:
            raise TinkerCustomerError(
                "customer credential operation cap exceeds the immutable account policy"
            )
        # Reject malformed or low-order recipient keys before revoking the
        # currently usable credential.
        _x25519_public_key(recipient_public_key)
        wallet = self._wallet(wallet_token, current)
        before = self.store.read()
        _owned_active_account(before, account_id, wallet)
        prior = _credential(before, credential_id, account_id)
        if prior["status"] not in ("active", "revoked"):
            raise TinkerCustomerError(
                "customer credential has an unsupported rotation state"
            )
        rotation_digest = hashlib.sha256(
            (
                "dnai-tinker-customer-credential-rotation-v1:"
                + base_idempotency_key
            ).encode("utf-8")
        ).hexdigest()
        revoke_key = "rotate-revoke:" + rotation_digest
        issue_key = "rotate-issue:" + rotation_digest
        revoked = self.revoke_credential(
            wallet_token=wallet_token,
            account_id=account_id,
            credential_id=credential_id,
            idempotency_key=revoke_key,
            now=current,
        )
        issued = self.issue_credential(
            wallet_token=wallet_token,
            account_id=account_id,
            recipient_public_key=recipient_public_key,
            operations=list(requested_operations),
            ttl_seconds=ttl_seconds,
            idempotency_key=issue_key,
            max_operation_policy_units=credential_cap,
            now=current,
        )
        return {
            "surface": "tinker_customer_credential_rotation",
            "schema_version": 1,
            "account_id": account_id,
            "prior_credential_id": credential_id,
            "credential_id": issued["credential_id"],
            "status": issued["status"],
            "operations": issued["operations"],
            "scopes": issued["scopes"],
            "max_operation_policy_units": issued[
                "max_operation_policy_units"
            ],
            "account_policy_digest": issued["account_policy_digest"],
            "release_lineage_digest": issued["release_lineage_digest"],
            "account_binding_authority_digest": issued[
                "account_binding_authority_digest"
            ],
            "account_binding_ceremony_receipt_digest": issued[
                "account_binding_ceremony_receipt_digest"
            ],
            "deployment_intent_digest": issued["deployment_intent_digest"],
            "issued_at": issued["issued_at"],
            "expires_at": issued["expires_at"],
            "jwt_id_hash": issued["jwt_id_hash"],
            "capsule": issued["capsule"],
            "gate": issued["gate"],
            "prior_credential_revoked": revoked["status"] == "revoked",
            "rotation_order": "revoke_then_issue_no_authority_overlap",
            "idempotent_replay": (
                revoked["idempotent_replay"] is True
                and issued["idempotent_replay"] is True
            ),
            "upstream_tinker_key_exposed": False,
            "upstream_project_exposed": False,
            "token_returned_in_plaintext": False,
            "raw_secret_egress": False,
        }

    def reserve_spend(
        self,
        *,
        credential_token: str,
        operation: Literal["training", "inference"],
        amount_policy_units: int,
        workload_commitment: str,
        idempotency_key: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        amount = _positive_uint(amount_policy_units, "reservation policy units")
        workload_commitment = _sha256(workload_commitment, "workload commitment")
        if type(operation) is not str or operation not in SUPPORTED_CUSTOMER_OPERATIONS:
            raise TinkerCustomerError("customer reservation operation is invalid")
        if operation == "inference":
            raise TinkerCustomerUnavailable("customer inference is disabled in this release")
        idempotency_key = _idempotency_key(idempotency_key)
        # Authenticate the bounded local credential before performing either
        # expensive live-release read. A valid credential is still re-gated
        # immediately before the anchored mutation below.
        claims = self._decode_credential(
            credential_token,
            operation=operation,
            now=current,
        )
        with self._mutation_lock:
            gate = self._gate(current)
            request = {
                "operation": "reserve_spend",
                "credential_id": claims["credential_id"],
                "account_id": claims["account_id"],
                "customer_operation": operation,
                "amount_policy_units": str(amount),
                "workload_commitment": workload_commitment,
                "release_policy_tuple_digest": gate.snapshot.policy_tuple_digest,
                "release_lineage_digest": claims["release_lineage_digest"],
                "account_binding_authority_digest":
                    claims["account_binding_authority_digest"],
                "account_binding_ceremony_receipt_digest":
                    claims["account_binding_ceremony_receipt_digest"],
                "deployment_intent_digest": claims["deployment_intent_digest"],
                "account_policy_digest": self.account_policy.digest,
            }
            request_hash = _sha256_json("tinker_customer_idempotent_request", request)

            def mutation(state: dict[str, Any]) -> dict[str, Any]:
                replay = _idempotent_replay(state, idempotency_key, request_hash)
                if replay is not None:
                    return _replay(replay)
                account = _account(state, claims["account_id"])
                if account["status"] != "active":
                    raise TinkerCustomerError("customer account is not active")
                lineage = self._require_immutable_account_authority(account)
                if any(
                    claims[field] != lineage[field]
                    for field in (
                        "release_lineage_digest",
                        "account_binding_authority_digest",
                        "account_binding_ceremony_receipt_digest",
                        "deployment_intent_digest",
                    )
                ):
                    raise TinkerCustomerError(
                        "customer credential account-binding lineage is stale"
                    )
                credential = _credential(state, claims["credential_id"], claims["account_id"])
                _validate_live_credential_record(credential, claims, current)
                if (
                    amount > claims["max_operation_policy_units"]
                    or amount > self.account_policy.max_operation_policy_units
                    or amount > gate.snapshot.max_spend_policy_units
                ):
                    raise TinkerCustomerError("reservation exceeds the frozen per-operation spend cap")
                outstanding = int(account["outstanding_policy_units"])
                settled = int(account["settled_policy_units"])
                if outstanding + amount > self.account_policy.max_outstanding_policy_units:
                    raise TinkerCustomerError("reservation exceeds the immutable outstanding spend cap")
                if settled + outstanding + amount > self.account_policy.max_lifetime_policy_units:
                    raise TinkerCustomerError("reservation exceeds the immutable lifetime spend cap")
                if len(state["reservations"]) >= MAX_CUSTOMER_RESERVATIONS:
                    raise TinkerCustomerUnavailable("customer reservation capacity reached")
                reservation_id = "tcr_" + secrets.token_hex(12)
                if reservation_id in state["reservations"]:
                    raise TinkerCustomerUnavailable(
                        "customer reservation identity collision"
                    )
                reservation_commitment = _sha256_json(
                    "tinker_customer_reservation",
                    {
                        **request,
                        "reservation_id": reservation_id,
                        "owner_address_hash": account["owner_address_hash"],
                        "jwt_id_hash": credential["jwt_id_hash"],
                    },
                )
                state["reservations"][reservation_id] = {
                    "reservation_id": reservation_id,
                    "reservation_commitment": reservation_commitment,
                    "account_id": claims["account_id"],
                    "credential_id": claims["credential_id"],
                    "owner_address_hash": account["owner_address_hash"],
                    "operation": operation,
                    "amount_policy_units": str(amount),
                    "actual_policy_units": "0",
                    "workload_commitment": workload_commitment,
                    "release_policy_tuple_digest": gate.snapshot.policy_tuple_digest,
                    "release_lineage_digest": lineage["release_lineage_digest"],
                    "account_binding_authority_digest":
                        lineage["account_binding_authority_digest"],
                    "account_binding_ceremony_receipt_digest":
                        lineage["account_binding_ceremony_receipt_digest"],
                    "deployment_intent_digest": lineage["deployment_intent_digest"],
                    "account_policy_digest": self.account_policy.digest,
                    "status": "reserved",
                    "reserved_at": current,
                    "dispatch_claimed_at": 0,
                    "dispatch_runtime_evidence_digest": "",
                    "finalized_at": 0,
                    "usage_receipt_hash": "",
                    "provider_dispatch_performed": False,
                }
                account["outstanding_policy_units"] = str(outstanding + amount)
                receipt = {
                    "surface": "tinker_customer_spend_reservation",
                    "schema_version": 1,
                    "reservation_id": reservation_id,
                    "reservation_commitment": reservation_commitment,
                    "account_id": claims["account_id"],
                    "credential_id": claims["credential_id"],
                    "operation": operation,
                    "status": "reserved",
                    "amount_policy_units": str(amount),
                    "workload_commitment": workload_commitment,
                    "account_policy_digest": self.account_policy.digest,
                    "release_lineage_digest": lineage["release_lineage_digest"],
                    "account_binding_authority_digest":
                        lineage["account_binding_authority_digest"],
                    "account_binding_ceremony_receipt_digest":
                        lineage["account_binding_ceremony_receipt_digest"],
                    "deployment_intent_digest": lineage["deployment_intent_digest"],
                    "provider_dispatch_performed": False,
                    "provider_authoritative_billing": False,
                    "settlement_performed": False,
                    "gate": gate.public_dict(),
                    "idempotent_replay": False,
                    "raw_secret_egress": False,
                }
                _record_event(state, "spend_reserved", receipt)
                _put_idempotency(state, idempotency_key, request_hash, receipt)
                return receipt

            return self.store.transact(mutation)

    def finalize_reservation(
        self,
        *,
        reservation_id: str,
        idempotency_key: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Settle or release only from the injected one-shot attested provider."""

        current = _now(now)
        reservation_id = _resource(reservation_id, "reservation id", prefix="tcr_")
        idempotency_key = _idempotency_key(idempotency_key)
        with self._mutation_lock:
            gate = self._gate(current)
            state_before = self.store.read()
            reservation_before = _reservation(state_before, reservation_id)
            account_before = _account(
                state_before,
                reservation_before["account_id"],
            )
            lineage = self._require_immutable_account_authority(account_before)
            request = {
                "operation": "finalize_reservation",
                "reservation_id": reservation_id,
                "reservation_commitment": reservation_before["reservation_commitment"],
                "release_lineage_digest": lineage["release_lineage_digest"],
                "account_binding_authority_digest":
                    lineage["account_binding_authority_digest"],
            }
            request_hash = _sha256_json("tinker_customer_idempotent_request", request)
            replay = _idempotent_replay(state_before, idempotency_key, request_hash)
            if replay is not None:
                return _replay(replay)
            if reservation_before["status"] not in (
                "reserved",
                "dispatch_claimed",
            ):
                raise TinkerCustomerConflict("customer reservation is already final")
            result = _fixed_external_call(
                lambda: _consume_and_validate_settlement_result(
                    self.settlement_provider,
                    reservation_id=reservation_id,
                    reservation_commitment=reservation_before[
                        "reservation_commitment"
                    ],
                    reservation=reservation_before,
                    gate=gate,
                    now=current,
                ),
                error_type=TinkerCustomerUnavailable,
                error_code=TC_SETTLEMENT_PROVIDER_UNAVAILABLE,
            )

            def mutation(state: dict[str, Any]) -> dict[str, Any]:
                replay_inner = _idempotent_replay(state, idempotency_key, request_hash)
                if replay_inner is not None:
                    return _replay(replay_inner)
                reservation = _reservation(state, reservation_id)
                if reservation != reservation_before:
                    raise TinkerCustomerConflict("customer reservation changed during finalization")
                account = _account(state, reservation["account_id"])
                lineage_inner = self._require_immutable_account_authority(account)
                if lineage_inner != lineage:
                    raise TinkerCustomerConflict(
                        "customer account lineage changed during finalization"
                    )
                reserved = int(reservation["amount_policy_units"])
                outstanding = int(account["outstanding_policy_units"])
                if outstanding < reserved:
                    raise TinkerCustomerStoreCorrupt("customer outstanding balance is inconsistent")
                actual = result.actual_policy_units
                reservation["status"] = result.outcome
                reservation["actual_policy_units"] = str(actual)
                reservation["finalized_at"] = current
                reservation["usage_receipt_hash"] = result.usage_receipt_hash
                reservation["provider_dispatch_performed"] = (
                    result.provider_dispatch_performed
                )
                account["outstanding_policy_units"] = str(outstanding - reserved)
                account["settled_policy_units"] = str(int(account["settled_policy_units"]) + actual)
                receipt = {
                    "surface": "tinker_customer_spend_finalization",
                    "schema_version": 1,
                    "reservation_id": reservation_id,
                    "reservation_commitment": reservation["reservation_commitment"],
                    "account_id": reservation["account_id"],
                    "operation": reservation["operation"],
                    "status": result.outcome,
                    "reserved_policy_units": str(reserved),
                    "actual_policy_units": str(actual),
                    "released_policy_units": str(reserved - actual),
                    "usage_receipt_hash": result.usage_receipt_hash,
                    "dispatch_claimed_at": reservation[
                        "dispatch_claimed_at"
                    ],
                    "dispatch_runtime_evidence_digest": reservation[
                        "dispatch_runtime_evidence_digest"
                    ]
                    or result.runtime_evidence_digest,
                    "at_most_once_claim_committed": (
                        reservation["dispatch_claimed_at"] > 0
                    ),
                    "automatic_provider_redispatch": False,
                    "release_lineage_digest": lineage["release_lineage_digest"],
                    "account_binding_authority_digest":
                        lineage["account_binding_authority_digest"],
                    "account_binding_ceremony_receipt_digest":
                        lineage["account_binding_ceremony_receipt_digest"],
                    "deployment_intent_digest": lineage["deployment_intent_digest"],
                    "provider_dispatch_performed": result.provider_dispatch_performed,
                    "provider_authoritative_billing": False,
                    "authority_accounting_only": True,
                    "gate": gate.public_dict(),
                    "idempotent_replay": False,
                    "raw_secret_egress": False,
                }
                _record_event(state, f"spend_{result.outcome}", receipt)
                _put_idempotency(state, idempotency_key, request_hash, receipt)
                return receipt

            return self.store.transact(mutation)

    def claim_reservation_dispatch(
        self,
        *,
        reservation_id: str,
        reservation_commitment: str,
        idempotency_key: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Commit the at-most-once boundary before any provider request.

        This method is intentionally internal to the customer training wrapper.
        A replay returns the original claim but never grants permission to
        dispatch again.  A process crash after this claim therefore leaves the
        reservation reconciliation-required until independently signed
        settlement evidence is available.
        """

        current = _now(now)
        reservation_id = _resource(
            reservation_id,
            "reservation id",
            prefix="tcr_",
        )
        reservation_commitment = _exact_nonzero_sha256(
            reservation_commitment,
            "reservation commitment",
        )
        idempotency_key = _idempotency_key(idempotency_key)
        with self._mutation_lock:
            gate = self._gate(current)
            request = {
                "operation": "claim_reservation_dispatch",
                "reservation_id": reservation_id,
                "reservation_commitment": reservation_commitment,
                "release_policy_tuple_digest": gate.snapshot.policy_tuple_digest,
                "release_lineage_digest":
                    self.expected_release.release_lineage_digest,
            }
            request_hash = _sha256_json(
                "tinker_customer_idempotent_request",
                request,
            )

            def mutation(state: dict[str, Any]) -> dict[str, Any]:
                replay = _idempotent_replay(
                    state,
                    idempotency_key,
                    request_hash,
                )
                if replay is not None:
                    return _replay(replay)
                reservation = _reservation(state, reservation_id)
                if not hmac.compare_digest(
                    reservation["reservation_commitment"],
                    reservation_commitment,
                ):
                    raise TinkerCustomerConflict(
                        "customer reservation commitment differs"
                    )
                if reservation["status"] != "reserved":
                    raise TinkerCustomerConflict(
                        "customer reservation cannot be dispatched"
                    )
                account = _account(state, reservation["account_id"])
                lineage = self._require_immutable_account_authority(account)
                if (
                    reservation["release_policy_tuple_digest"]
                    != gate.snapshot.policy_tuple_digest
                    or reservation["release_lineage_digest"]
                    != lineage["release_lineage_digest"]
                    or reservation["account_binding_authority_digest"]
                    != lineage["account_binding_authority_digest"]
                ):
                    raise TinkerCustomerConflict(
                        "customer reservation release binding changed"
                    )
                reservation["status"] = "dispatch_claimed"
                reservation["dispatch_claimed_at"] = current
                reservation["dispatch_runtime_evidence_digest"] = (
                    gate.evidence.public_digest()
                )
                receipt = {
                    "surface": "tinker_customer_dispatch_claim",
                    "schema_version": 1,
                    "reservation_id": reservation_id,
                    "reservation_commitment": reservation_commitment,
                    "account_id": reservation["account_id"],
                    "credential_id": reservation["credential_id"],
                    "operation": reservation["operation"],
                    "status": "dispatch_claimed",
                    "amount_policy_units": reservation[
                        "amount_policy_units"
                    ],
                    "workload_commitment": reservation[
                        "workload_commitment"
                    ],
                    "dispatch_runtime_evidence_digest": reservation[
                        "dispatch_runtime_evidence_digest"
                    ],
                    "at_most_once_claim_committed": True,
                    "automatic_provider_redispatch": False,
                    "provider_dispatch_performed": False,
                    "gate": gate.public_dict(),
                    "idempotent_replay": False,
                    "raw_secret_egress": False,
                }
                _record_event(state, "dispatch_claimed", receipt)
                _put_idempotency(
                    state,
                    idempotency_key,
                    request_hash,
                    receipt,
                )
                return receipt

            return self.store.transact(mutation)

    def revoke_account(
        self,
        *,
        wallet_token: str,
        account_id: str,
        idempotency_key: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        wallet = self._wallet(wallet_token, current)
        account_id = _resource(account_id, "account id", prefix="tca_")
        idempotency_key = _idempotency_key(idempotency_key)
        with self._mutation_lock:
            gate = self._gate(current)
            request = {
                "operation": "revoke_account",
                "owner_address": wallet,
                "account_id": account_id,
                "release_lineage_digest":
                    self.expected_release.release_lineage_digest,
            }
            request_hash = _sha256_json("tinker_customer_idempotent_request", request)

            def mutation(state: dict[str, Any]) -> dict[str, Any]:
                replay = _idempotent_replay(state, idempotency_key, request_hash)
                if replay is not None:
                    return _replay(replay)
                account = _owned_account(state, account_id, wallet)
                if account["status"] in ("revoked", "cancelled"):
                    raise TinkerCustomerConflict("Tinker customer account is already revoked")
                was_requested = account["status"] == "requested"
                if was_requested:
                    self._require_requested_account_release(account)
                    lineage = {
                        "release_lineage_digest":
                            self.expected_release.release_lineage_digest,
                        "account_binding_authority_digest": None,
                        "account_binding_ceremony_receipt_digest":
                            self.expected_release.account_binding_ceremony_receipt_digest,
                        "deployment_intent_digest":
                            self.expected_release.deployment_intent_digest,
                    }
                    account["status"] = "cancelled"
                else:
                    lineage = self._require_immutable_account_authority(account)
                    account["status"] = "revoked"
                account["revoked_at"] = current
                revoked_credentials = 0
                for credential in state["credentials"].values():
                    if credential["account_id"] == account_id and credential["status"] == "active":
                        credential["status"] = "revoked"
                        credential["revoked_at"] = current
                        revoked_credentials += 1
                outstanding_count = sum(
                    1
                    for reservation in state["reservations"].values()
                    if (
                        reservation["account_id"] == account_id
                        and reservation["status"] in (
                            "reserved",
                            "dispatch_claimed",
                        )
                    )
                )
                receipt = {
                    "surface": "tinker_customer_account_revoke",
                    "schema_version": 1,
                    "account_id": account_id,
                    "status": account["status"],
                    "owner_address_hash": account["owner_address_hash"],
                    "release_lineage_digest": lineage["release_lineage_digest"],
                    "account_binding_authority_digest":
                        lineage["account_binding_authority_digest"],
                    "account_binding_ceremony_receipt_digest":
                        lineage["account_binding_ceremony_receipt_digest"],
                    "deployment_intent_digest": lineage["deployment_intent_digest"],
                    "provisioning_result_attested": not was_requested,
                    "revoked_credentials": revoked_credentials,
                    "outstanding_reservations": outstanding_count,
                    "new_authority_permitted": False,
                    "outstanding_reservations_require_attested_finalization": outstanding_count > 0,
                    "gate": gate.public_dict(),
                    "idempotent_replay": False,
                    "raw_secret_egress": False,
                }
                _record_event(
                    state,
                    "account_cancelled" if was_requested else "account_revoked",
                    receipt,
                )
                _put_idempotency(state, idempotency_key, request_hash, receipt)
                return receipt

            return self.store.transact(mutation)

    def account_status(self, *, wallet_token: str, account_id: str, now: int | None = None) -> dict[str, Any]:
        current = _now(now)
        wallet = self._wallet(wallet_token, current)
        account_id = _resource(account_id, "account id", prefix="tca_")
        state = self.store.read()
        account = _owned_account(state, account_id, wallet)
        if account["status"] in ("active", "revoked"):
            lineage = self._require_immutable_account_authority(account)
        else:
            self._require_requested_account_release(account)
            lineage = {
                "release_lineage_digest":
                    self.expected_release.release_lineage_digest,
                "account_binding_authority_digest": None,
            }
        credentials = [item for item in state["credentials"].values() if item["account_id"] == account_id]
        reservations = [item for item in state["reservations"].values() if item["account_id"] == account_id]
        return {
            "surface": "tinker_customer_account_status",
            "schema_version": 1,
            "account_id": account_id,
            "status": account["status"],
            "mode": account["mode"],
            "owner_address_hash": account["owner_address_hash"],
            "request_commitment": account["request_commitment"],
            "account_commitment": account["account_commitment"],
            "release_lineage_digest": lineage["release_lineage_digest"],
            "account_binding_authority_digest":
                lineage["account_binding_authority_digest"],
            "account_binding_authority": copy.deepcopy(
                account["account_binding_authority"]
            ),
            "account_policy": account["account_policy"],
            "credential_counts": _status_counts(credentials),
            "reservation_counts": _status_counts(reservations),
            "settled_policy_units": account["settled_policy_units"],
            "outstanding_policy_units": account["outstanding_policy_units"],
            "upstream_account_exists": account["status"] in ("active", "revoked") and bool(account["provisioning_receipt_hash"]),
            "raw_account_identifier_returned": False,
            "upstream_tinker_key_exposed": False,
            "upstream_project_exposed": False,
            "hosted_card_funding": "roadmap",
            "token_exchange": "roadmap",
            "raw_secret_egress": False,
        }

    def current_account_status(
        self,
        *,
        wallet_token: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Recover the one immutable logical account owned by this wallet."""

        current = _now(now)
        wallet = self._wallet(wallet_token, current)
        state = self.store.read()
        account_ids = sorted(
            account_id
            for account_id, account in state["accounts"].items()
            if account["owner_address"] == wallet
        )
        if not account_ids:
            raise TinkerCustomerNotFound("customer account was not found")
        if len(account_ids) != 1:
            raise TinkerCustomerStoreCorrupt(
                "customer wallet has more than one immutable account"
            )
        return self.account_status(
            wallet_token=wallet_token,
            account_id=account_ids[0],
            now=current,
        )

    def list_credentials(
        self,
        *,
        wallet_token: str,
        account_id: str,
        limit: int = DEFAULT_CUSTOMER_CREDENTIAL_PAGE_SIZE,
        cursor: str | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Return one snapshot-bound credential page, never a token or capsule."""

        current = _now(now)
        wallet = self._wallet(wallet_token, current)
        account_id = _resource(account_id, "account id", prefix="tca_")
        if (
            type(limit) is not int
            or not 1 <= limit <= MAX_CUSTOMER_CREDENTIAL_PAGE_SIZE
        ):
            raise TinkerCustomerError(
                "customer credential page limit is invalid"
            )
        if cursor is not None and (
            not isinstance(cursor, str)
            or not cursor
            or len(cursor.encode("utf-8"))
            > MAX_CUSTOMER_CREDENTIAL_CURSOR_BYTES
        ):
            raise TinkerCustomerConflict(
                "credential cursor is invalid; restart listing"
            )
        state = self.store.read()
        account = _owned_account(state, account_id, wallet)
        if account["status"] in ("active", "revoked"):
            lineage = self._require_immutable_account_authority(account)
        else:
            self._require_requested_account_release(account)
            lineage = {
                "release_lineage_digest":
                    self.expected_release.release_lineage_digest,
                "account_binding_authority_digest": None,
            }
        matching_records = sorted(
            (
                item
                for item in state["credentials"].values()
                if item["account_id"] == account_id
            ),
            key=lambda item: (item["issued_at"], item["credential_id"]),
            reverse=True,
        )
        start = 0
        if cursor is not None:
            anchor = self.store.decode_credential_cursor(
                cursor,
                expected_account_id=account_id,
                expected_snapshot_sequence=state["sequence"],
            )
            for index, record in enumerate(matching_records):
                if (
                    record["issued_at"],
                    record["credential_id"],
                ) == anchor:
                    start = index + 1
                    break
            else:
                raise TinkerCustomerConflict(
                    "credential cursor is stale; restart listing"
                )
        selected_records = matching_records[start : start + limit]
        has_more = start + len(selected_records) < len(matching_records)
        credentials = []
        for record in selected_records:
            effective_status = (
                "expired"
                if record["status"] == "active"
                and current >= record["expires_at"]
                else record["status"]
            )
            credentials.append(
                {
                    "credential_id": record["credential_id"],
                    "status": effective_status,
                    "persisted_status": record["status"],
                    "operations": list(record["operations"]),
                    "scopes": list(record["scopes"]),
                    "max_operation_policy_units": record[
                        "max_operation_policy_units"
                    ],
                    "recipient_public_key_hash": record[
                        "recipient_public_key_hash"
                    ],
                    "jwt_id_hash": record["jwt_id_hash"],
                    "issued_at": record["issued_at"],
                    "expires_at": record["expires_at"],
                    "revoked_at": record["revoked_at"],
                    "token_returned_in_plaintext": False,
                }
            )
        next_cursor = None
        if has_more and selected_records:
            anchor = selected_records[-1]
            next_cursor = self.store.encode_credential_cursor(
                account_id=account_id,
                snapshot_sequence=state["sequence"],
                anchor_issued_at=anchor["issued_at"],
                anchor_credential_id=anchor["credential_id"],
            )
        result = {
            "surface": "tinker_customer_credentials",
            "schema_version": 2,
            "account_id": account_id,
            "account_status": account["status"],
            "release_lineage_digest": lineage["release_lineage_digest"],
            "account_binding_authority_digest": lineage[
                "account_binding_authority_digest"
            ],
            "total_credentials": len(matching_records),
            "page_credential_count": len(credentials),
            "page_limit": limit,
            "maximum_page_size": MAX_CUSTOMER_CREDENTIAL_PAGE_SIZE,
            "has_more": has_more,
            "next_cursor": next_cursor,
            "snapshot_sequence": state["sequence"],
            "ordering": "issued_at_desc_then_credential_id_desc",
            "credentials": credentials,
            "upstream_tinker_key_exposed": False,
            "upstream_project_exposed": False,
            "credential_capsules_returned": False,
            "plaintext_token_egress": False,
            "raw_secret_egress": False,
        }
        if len(_canonical_bytes(result)) >= MAX_CUSTOMER_CREDENTIAL_PAGE_BYTES:
            raise TinkerCustomerUnavailable(
                "customer credential page exceeded its public byte bound"
            )
        return result

    def _wallet(self, token: str, now: int) -> str:
        claims = _fixed_external_call(
            lambda: self.wallet_verifier.verify_token(
                token,
                required_scope=CUSTOMER_WALLET_SCOPE,
                now=now,
            ),
            error_type=TinkerCustomerError,
            error_code=TC_WALLET_VERIFIER_UNAVAILABLE,
        )
        try:
            address = normalize_wallet_address(str(claims.address))
            scopes = tuple(str(scope) for scope in claims.scopes)
            issued_at = claims.issued_at
            expires_at = claims.expires_at
        except Exception:
            raise TinkerCustomerError("customer wallet session is invalid") from None
        if type(issued_at) is not int or type(expires_at) is not int:
            raise TinkerCustomerError("customer wallet session is invalid")
        if scopes != (CUSTOMER_WALLET_SCOPE,) or issued_at > now or expires_at <= now or expires_at - issued_at > 900:
            raise TinkerCustomerError("customer wallet session is invalid")
        return address

    def _require_immutable_account_policy(self, account: dict[str, Any]) -> None:
        if account.get("account_policy_digest") != self.account_policy.digest or account.get(
            "account_policy"
        ) != self.account_policy.public_dict():
            raise TinkerCustomerUnavailable(
                "customer account policy differs from its immutable activation binding"
            )

    def _audit_persisted_release_lineage(self) -> None:
        """Fail startup if durable accounts belong to another reviewed release."""

        state = self.store.read()
        for account in state["accounts"].values():
            if account["status"] in ("active", "revoked"):
                self._require_immutable_account_authority(account)
            else:
                self._require_requested_account_release(account)

    def _require_requested_account_release(self, account: dict[str, Any]) -> None:
        self._require_immutable_account_policy(account)
        if (
            account.get("release_policy_tuple_digest")
            != self.expected_release.policy_tuple_digest
            or account.get("account_commitment")
            != self.expected_release.account_commitment
            or account.get("release_lineage_digest")
            != self.expected_release.release_lineage_digest
        ):
            raise TinkerCustomerUnavailable(
                "customer account request differs from the exact release lineage"
            )

    def _require_immutable_account_authority(
        self,
        account: dict[str, Any],
    ) -> dict[str, Any]:
        self._require_requested_account_release(account)
        if account.get("status") not in ("active", "revoked"):
            raise TinkerCustomerUnavailable(
                "customer account has no immutable activation authority"
            )
        try:
            authority = _normalize_account_binding_authority(
                account.get("account_binding_authority"),
                expected_commitment=self.expected_release.account_commitment,
                expected_ceremony_receipt_digest=(
                    self.expected_release.account_binding_ceremony_receipt_digest
                ),
                expected_deployment_intent_digest=(
                    self.expected_release.deployment_intent_digest
                ),
            )
            provisioning_receipt = _exact_nonzero_sha256(
                account.get("provisioning_receipt_hash"),
                "provisioning receipt hash",
            )
            _distinct_exact_sha256_commitments(
                {
                    "provisioning receipt hash": provisioning_receipt,
                    "account-binding receipt digest": authority[
                        "account_binding_receipt_digest"
                    ],
                    "sealed account-binding record hash": authority[
                        "sealed_binding_record_hash"
                    ],
                    "account-binding ceremony receipt digest": authority[
                        "account_binding_ceremony_receipt_digest"
                    ],
                    "deployment intent digest": authority[
                        "deployment_intent_digest"
                    ],
                },
                error_message=(
                    "customer activation commitments must remain pairwise distinct"
                ),
            )
        except (TinkerCustomerError, TypeError, ValueError) as exc:
            raise TinkerCustomerUnavailable(
                "customer account activation authority is invalid"
            ) from exc
        return {
            "release_lineage_digest": self.expected_release.release_lineage_digest,
            "account_binding_authority_digest":
                _account_binding_authority_digest(authority),
            "account_binding_ceremony_receipt_digest": authority[
                "account_binding_ceremony_receipt_digest"
            ],
            "deployment_intent_digest": authority["deployment_intent_digest"],
        }

    def _gate(self, now: int) -> _Gate:
        snapshot = _fixed_external_call(
            lambda: _validated_release_snapshot(
                self.release_reader.read(),
                self.expected_release,
            ),
            error_type=TinkerCustomerUnavailable,
            error_code=TC_RELEASE_READER_UNAVAILABLE,
        )
        evidence = _fixed_external_call(
            lambda: _validated_runtime_evidence(
                self.evidence_provider.read(now=now),
                self.evidence_policy,
                snapshot,
                now,
            ),
            error_type=TinkerCustomerUnavailable,
            error_code=TC_RUNTIME_EVIDENCE_PROVIDER_UNAVAILABLE,
        )
        return _Gate(snapshot=snapshot, evidence=evidence)

    def _decode_credential(self, token: str, *, operation: str, now: int) -> dict[str, Any]:
        payload = _decode_jwt(token, self._credential_key)
        if payload.get("iss") != CUSTOMER_CREDENTIAL_ISSUER or payload.get("aud") != CUSTOMER_CREDENTIAL_AUDIENCE:
            raise TinkerCustomerError("customer credential domain is invalid")
        try:
            issued_at = payload["iat"]
            not_before = payload["nbf"]
            expires_at = payload["exp"]
        except KeyError:
            raise TinkerCustomerError("customer credential timestamps are invalid") from None
        if any(type(value) is not int for value in (issued_at, not_before, expires_at)):
            raise TinkerCustomerError("customer credential timestamps are invalid")
        if issued_at != not_before or issued_at > now or expires_at <= now:
            raise TinkerCustomerError("customer credential is not active")
        if expires_at - issued_at > self.account_policy.credential_max_ttl_seconds:
            raise TinkerCustomerError("customer credential lifetime exceeds policy")
        credential_id = _resource(str(payload.get("sub", "")), "credential id", prefix="tcc_")
        account_id = _resource(str(payload.get("account_id", "")), "account id", prefix="tca_")
        owner_hash = _sha256(str(payload.get("owner_address_hash", "")), "owner address hash")
        operations = _operations(tuple(str(payload.get("operations", "")).split()))
        scopes = tuple(sorted(set(str(payload.get("scope", "")).split())))
        expected_scopes = tuple(sorted(CUSTOMER_OPERATION_SCOPE[item] for item in operations))
        if scopes != expected_scopes or operation not in operations:
            raise TinkerCustomerError("customer credential is missing the required operation")
        if operation not in self.account_policy.allowed_operations:
            raise TinkerCustomerError("customer credential operation is not release enabled")
        try:
            cap = _uint_string(
                payload["max_operation_policy_units"],
                "customer credential cap",
            )
        except (KeyError, TinkerCustomerError):
            raise TinkerCustomerError("customer credential cap is invalid") from None
        if cap <= 0 or cap > self.account_policy.max_operation_policy_units:
            raise TinkerCustomerError(
                "customer credential cap exceeds immutable account policy"
            )
        release_digest = _sha256(str(payload.get("release_policy_tuple_digest", "")), "release policy tuple digest")
        if release_digest != self.expected_release.policy_tuple_digest:
            raise TinkerCustomerError("customer credential is bound to a different release")
        release_lineage_digest = _exact_nonzero_sha256(
            payload.get("release_lineage_digest"),
            "customer credential release lineage digest",
        )
        if release_lineage_digest != self.expected_release.release_lineage_digest:
            raise TinkerCustomerError(
                "customer credential is bound to a different account-binding release lineage"
            )
        account_binding_authority_digest = _exact_nonzero_sha256(
            payload.get("account_binding_authority_digest"),
            "customer credential account-binding authority digest",
        )
        ceremony_receipt_digest = _exact_nonzero_sha256(
            payload.get("account_binding_ceremony_receipt_digest"),
            "customer credential account-binding ceremony receipt digest",
        )
        if (
            ceremony_receipt_digest
            != self.expected_release.account_binding_ceremony_receipt_digest
        ):
            raise TinkerCustomerError(
                "customer credential is bound to a different account-binding ceremony"
            )
        deployment_intent_digest = _exact_nonzero_sha256(
            payload.get("deployment_intent_digest"),
            "customer credential deployment intent digest",
        )
        if deployment_intent_digest != self.expected_release.deployment_intent_digest:
            raise TinkerCustomerError(
                "customer credential is bound to a different deployment intent"
            )
        account_policy_digest = _sha256(
            str(payload.get("account_policy_digest", "")), "account policy digest"
        )
        if account_policy_digest != self.account_policy.digest:
            raise TinkerCustomerError("customer credential is bound to a different account policy")
        jwt_id = str(payload.get("jti", ""))
        if not re.fullmatch(r"[0-9a-f]{32}", jwt_id):
            raise TinkerCustomerError("customer credential id is invalid")
        return {
            "credential_id": credential_id,
            "account_id": account_id,
            "owner_address_hash": owner_hash,
            "operations": operations,
            "scopes": scopes,
            "max_operation_policy_units": cap,
            "release_policy_tuple_digest": release_digest,
            "release_lineage_digest": release_lineage_digest,
            "account_binding_authority_digest":
                account_binding_authority_digest,
            "account_binding_ceremony_receipt_digest":
                ceremony_receipt_digest,
            "deployment_intent_digest": deployment_intent_digest,
            "account_policy_digest": account_policy_digest,
            "jwt_id_hash": _sha256_text("tinker_customer_jti", jwt_id),
            "issued_at": issued_at,
            "expires_at": expires_at,
        }


def _validate_release_snapshot(snapshot: TinkerReleaseSnapshot, expected: ExpectedTinkerRelease) -> None:
    if type(snapshot) is not TinkerReleaseSnapshot:
        raise TinkerCustomerUnavailable("live Tinker release returned an unsupported value")
    if (
        type(snapshot.chain_id) is not int
        or type(snapshot.finalized_block_number) is not int
        or type(snapshot.release_policy_frozen) is not bool
        or type(snapshot.emergency_halted) is not bool
        or type(snapshot.max_add_balance_policy_units) is not int
        or type(snapshot.max_spend_policy_units) is not int
        or type(snapshot.release_max_add_balance_policy_units) is not int
        or type(snapshot.release_max_spend_policy_units) is not int
        or type(snapshot.approved_compose_hashes) is not tuple
        or type(snapshot.managers) is not tuple
    ):
        raise TinkerCustomerUnavailable("live Tinker release contains a noncanonical primitive")
    try:
        _exact_address(snapshot.contract_address, "contract address")
        _exact_word(snapshot.runtime_code_hash, "runtime code hash")
        _exact_address(snapshot.owner, "release owner")
        _exact_address(snapshot.pending_owner, "pending owner")
        _exact_nonzero_word(snapshot.account_commitment, "account commitment")
        _exact_nonzero_word(
            snapshot.release_policy_commitment,
            "release policy commitment",
        )
        _exact_nonzero_word(
            snapshot.approved_compose_root,
            "approved compose root",
        )
        tuple(
            _exact_nonzero_word(value, "approved compose hash")
            for value in snapshot.approved_compose_hashes
        )
        _exact_nonzero_word(snapshot.manager_root, "manager root")
        tuple(
            _exact_address(value, "release manager")
            for value in snapshot.managers
        )
        _exact_nonzero_word(snapshot.finalized_block_hash, "finalized block hash")
    except (TinkerCustomerError, TypeError, ValueError) as exc:
        raise TinkerCustomerUnavailable(
            "live Tinker release contains a noncanonical identity"
        ) from exc
    if snapshot.policy_tuple() != expected.policy_tuple():
        raise TinkerCustomerUnavailable("live Tinker release does not match the exact reviewed policy tuple")
    if snapshot.finalized_block_number < 0:
        raise TinkerCustomerUnavailable("live Tinker release block identity is invalid")


def _validated_release_snapshot(
    snapshot: TinkerReleaseSnapshot,
    expected: ExpectedTinkerRelease,
) -> TinkerReleaseSnapshot:
    _validate_release_snapshot(snapshot, expected)
    return snapshot


def _validate_anchor_head(head: CustomerStateAnchorHead) -> None:
    if type(head) is not CustomerStateAnchorHead:
        raise TinkerCustomerUnavailable("customer state anchor returned an unsupported value")
    if type(head.sequence) is not int or head.sequence < 0:
        raise TinkerCustomerUnavailable("customer state anchor sequence is invalid")
    try:
        _sha256(head.head_hash, "customer state anchor head")
    except TinkerCustomerError as exc:
        raise TinkerCustomerUnavailable("customer state anchor head is invalid") from exc


def _validated_anchor_head(head: CustomerStateAnchorHead) -> CustomerStateAnchorHead:
    _validate_anchor_head(head)
    return head


def _validate_runtime_evidence(
    evidence: RuntimeEvidence,
    policy: RuntimeEvidencePolicy,
    snapshot: TinkerReleaseSnapshot,
    now: int,
) -> None:
    if type(evidence) is not RuntimeEvidence:
        raise TinkerCustomerUnavailable("runtime evidence provider returned an unsupported value")
    if type(evidence.issued_at) is not int or type(evidence.expires_at) is not int:
        raise TinkerCustomerUnavailable("runtime evidence timestamps are not exact integers")
    if (
        evidence.issued_at < 0
        or evidence.issued_at > now
        or evidence.expires_at <= now
        or evidence.expires_at <= evidence.issued_at
        or evidence.expires_at - evidence.issued_at > policy.max_lease_seconds
    ):
        raise TinkerCustomerUnavailable("runtime evidence lease is not fresh")
    for field, value in (
        ("CVM id hash", evidence.cvm_id_hash),
        ("measurement hash", evidence.measurement_hash),
        ("QVL policy hash", evidence.qvl_policy_hash),
        ("release authority digest", evidence.release_authority_digest),
        ("roles digest", evidence.roles_digest),
        ("customer policy digest", evidence.customer_policy_digest),
        ("release policy tuple digest", evidence.release_policy_tuple_digest),
    ):
        try:
            _exact_sha256(value, f"runtime evidence {field}")
        except TinkerCustomerError as exc:
            raise TinkerCustomerUnavailable(
                "runtime evidence contains a noncanonical commitment"
            ) from exc
    try:
        _exact_nonzero_word(
            evidence.account_commitment,
            "runtime evidence account commitment",
        )
        _exact_nonzero_word(evidence.compose_hash, "runtime evidence compose hash")
        manager = _address(evidence.manager, "runtime evidence manager")
    except TinkerCustomerError as exc:
        raise TinkerCustomerUnavailable(
            "runtime evidence contains a noncanonical release identity"
        ) from exc
    if type(evidence.manager) is not str or manager != evidence.manager:
        raise TinkerCustomerUnavailable(
            "runtime evidence contains a noncanonical manager"
        )
    if (
        type(evidence.enabled_operations) is not tuple
        or any(type(operation) is not str for operation in evidence.enabled_operations)
    ):
        raise TinkerCustomerUnavailable(
            "runtime evidence operation set is not an exact tuple"
        )
    exact = {
        "cvm_id_hash": policy.cvm_id_hash,
        "measurement_hash": policy.measurement_hash,
        "qvl_policy_hash": policy.qvl_policy_hash,
        "release_authority_digest": policy.release_authority_digest,
        "roles_digest": policy.roles_digest,
        "customer_policy_digest": policy.customer_policy_digest,
        "release_policy_tuple_digest": snapshot.policy_tuple_digest,
        "account_commitment": snapshot.account_commitment,
        "enabled_operations": policy.enabled_operations,
    }
    actual = {
        "cvm_id_hash": evidence.cvm_id_hash,
        "measurement_hash": evidence.measurement_hash,
        "qvl_policy_hash": evidence.qvl_policy_hash,
        "release_authority_digest": evidence.release_authority_digest,
        "roles_digest": evidence.roles_digest,
        "customer_policy_digest": evidence.customer_policy_digest,
        "release_policy_tuple_digest": evidence.release_policy_tuple_digest,
        "account_commitment": evidence.account_commitment,
        "enabled_operations": evidence.enabled_operations,
    }
    if actual != exact:
        raise TinkerCustomerUnavailable("runtime evidence does not match the exact release pins")
    if evidence.compose_hash not in snapshot.approved_compose_hashes or evidence.manager not in snapshot.managers:
        raise TinkerCustomerUnavailable("runtime evidence compose or manager is not in the exact frozen release")
    if type(evidence.tdx_verified) is not bool or type(evidence.qvl_pass) is not bool:
        raise TinkerCustomerUnavailable("runtime evidence verdicts are not exact booleans")
    if evidence.tdx_verified is not True or evidence.qvl_pass is not True:
        raise TinkerCustomerUnavailable("runtime evidence did not independently pass TDX/QVL verification")
    for field, value in (
        ("raw quote disclosure", evidence.raw_quote_publicly_disclosed),
        ("raw collateral disclosure", evidence.raw_collateral_publicly_disclosed),
        ("raw secret egress", evidence.raw_secret_egress),
    ):
        if type(value) is not bool:
            raise TinkerCustomerUnavailable(f"runtime evidence {field} is not an exact boolean")
    if (
        evidence.raw_quote_publicly_disclosed is not False
        or evidence.raw_collateral_publicly_disclosed is not False
        or evidence.raw_secret_egress is not False
    ):
        raise TinkerCustomerUnavailable("runtime evidence violates the bounded public-evidence policy")


def _validated_runtime_evidence(
    evidence: RuntimeEvidence,
    policy: RuntimeEvidencePolicy,
    snapshot: TinkerReleaseSnapshot,
    now: int,
) -> RuntimeEvidence:
    _validate_runtime_evidence(evidence, policy, snapshot, now)
    return evidence


_ACCOUNT_BINDING_AUTHORITY_FIELDS = frozenset(
    {
        "truth_status",
        "account_binding_schema",
        "account_binding_version",
        "account_binding_chain_id",
        "account_binding_type",
        "account_binding_typehash",
        "provider_namespace_label",
        "provider_namespace",
        "account_commitment",
        "account_binding_receipt_digest",
        "sealed_binding_record_hash",
        "account_binding_ceremony_receipt_digest",
        "deployment_intent_digest",
        "account_binding_receipt_independently_attested",
        "account_binding_handle_attested",
        "provider_identity_checked",
        "current_provider_session_rechecked",
        "account_commitment_exact_match",
        "provider_internal_identity_cryptographically_proven",
        "raw_provider_account_id_egress",
        "raw_binding_root_egress",
        "raw_reviewer_share_egress",
        "binding_root_or_share_digest_published",
        "raw_provider_auth_egress",
        "raw_provider_session_egress",
        "raw_secret_egress",
    }
)
_ACCOUNT_BINDING_REQUIRED_TRUE_FIELDS = (
    "account_binding_receipt_independently_attested",
    "account_binding_handle_attested",
    "provider_identity_checked",
    "current_provider_session_rechecked",
    "account_commitment_exact_match",
)
_ACCOUNT_BINDING_REQUIRED_FALSE_FIELDS = (
    "provider_internal_identity_cryptographically_proven",
    "raw_provider_account_id_egress",
    "raw_binding_root_egress",
    "raw_reviewer_share_egress",
    "binding_root_or_share_digest_published",
    "raw_provider_auth_egress",
    "raw_provider_session_egress",
    "raw_secret_egress",
)


def _release_lineage(
    *,
    account_commitment: Any,
    account_binding_ceremony_receipt_digest: Any,
    deployment_intent_digest: Any,
) -> dict[str, Any]:
    return {
        "account_binding_schema": TINKER_ACCOUNT_BINDING_SCHEMA,
        "account_binding_version": TINKER_ACCOUNT_BINDING_VERSION,
        "account_binding_chain_id": TINKER_ACCOUNT_BINDING_CHAIN_ID,
        "account_binding_typehash": TINKER_ACCOUNT_BINDING_TYPEHASH_WORD,
        "provider_namespace": TINKER_PROVIDER_NAMESPACE_WORD,
        "account_commitment": _exact_nonzero_word(
            account_commitment,
            "release-lineage account commitment",
        ),
        "account_binding_ceremony_receipt_digest": _exact_nonzero_sha256(
            account_binding_ceremony_receipt_digest,
            "release-lineage account-binding ceremony receipt digest",
        ),
        "deployment_intent_digest": _exact_nonzero_sha256(
            deployment_intent_digest,
            "release-lineage deployment intent digest",
        ),
    }


def _release_lineage_digest(
    *,
    account_commitment: Any,
    account_binding_ceremony_receipt_digest: Any,
    deployment_intent_digest: Any,
) -> str:
    return _sha256_json(
        "tinker_customer_account_binding_release_lineage",
        _release_lineage(
            account_commitment=account_commitment,
            account_binding_ceremony_receipt_digest=(
                account_binding_ceremony_receipt_digest
            ),
            deployment_intent_digest=deployment_intent_digest,
        ),
    )


def _account_binding_authority_digest(authority: dict[str, Any]) -> str:
    return _sha256_json(
        "tinker_customer_account_binding_authority",
        authority,
    )


def _normalize_account_binding_authority(
    value: dict[str, Any],
    *,
    expected_commitment: str,
    expected_ceremony_receipt_digest: str | None = None,
    expected_deployment_intent_digest: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ACCOUNT_BINDING_AUTHORITY_FIELDS:
        raise TinkerCustomerError("account-binding authority fields are not exact")
    if (
        type(value["truth_status"]) is not str
        or value["truth_status"] != TINKER_CUSTOMER_ACCOUNT_BINDING_TRUTH
        or type(value["account_binding_schema"]) is not str
        or value["account_binding_schema"] != TINKER_ACCOUNT_BINDING_SCHEMA
        or type(value["account_binding_version"]) is not int
        or value["account_binding_version"] != TINKER_ACCOUNT_BINDING_VERSION
        or type(value["account_binding_chain_id"]) is not int
        or value["account_binding_chain_id"] != TINKER_ACCOUNT_BINDING_CHAIN_ID
        or type(value["account_binding_type"]) is not str
        or value["account_binding_type"] != TINKER_ACCOUNT_BINDING_TYPE
        or type(value["provider_namespace_label"]) is not str
        or value["provider_namespace_label"] != TINKER_PROVIDER_NAMESPACE_LABEL
    ):
        raise TinkerCustomerError("account-binding scheme or provider namespace drifted")
    typehash = _exact_nonzero_word(
        value["account_binding_typehash"],
        "account-binding typehash",
    )
    if typehash != TINKER_ACCOUNT_BINDING_TYPEHASH_WORD:
        raise TinkerCustomerError("account-binding typehash drifted")
    provider_namespace = _exact_nonzero_word(
        value["provider_namespace"],
        "account-binding provider namespace",
    )
    if provider_namespace != TINKER_PROVIDER_NAMESPACE_WORD:
        raise TinkerCustomerError("account-binding provider namespace drifted")
    account_commitment = _exact_nonzero_word(
        value["account_commitment"],
        "account-binding commitment",
    )
    expected_commitment = _exact_nonzero_word(
        expected_commitment,
        "expected account-binding commitment",
    )
    if account_commitment != expected_commitment:
        raise TinkerCustomerError("account-binding commitment drifted")
    semantic_digests = _distinct_exact_sha256_commitments(
        {
            "account-binding receipt digest": value[
                "account_binding_receipt_digest"
            ],
            "sealed account-binding record hash": value[
                "sealed_binding_record_hash"
            ],
            "account-binding ceremony receipt digest": value[
                "account_binding_ceremony_receipt_digest"
            ],
            "deployment intent digest": value["deployment_intent_digest"],
        },
        error_message="account-binding semantic commitments must be pairwise distinct",
    )
    if (
        expected_ceremony_receipt_digest is not None
        and semantic_digests["account-binding ceremony receipt digest"]
        != _exact_nonzero_sha256(
            expected_ceremony_receipt_digest,
            "expected account-binding ceremony receipt digest",
        )
    ):
        raise TinkerCustomerError(
            "account-binding ceremony receipt digest drifted"
        )
    if (
        expected_deployment_intent_digest is not None
        and semantic_digests["deployment intent digest"]
        != _exact_nonzero_sha256(
            expected_deployment_intent_digest,
            "expected deployment intent digest",
        )
    ):
        raise TinkerCustomerError(
            "account-binding deployment intent digest drifted"
        )
    if any(
        type(value[field]) is not bool or value[field] is not True
        for field in _ACCOUNT_BINDING_REQUIRED_TRUE_FIELDS
    ):
        raise TinkerCustomerError(
            "account-binding authority omitted an independently attested check"
        )
    if any(
        type(value[field]) is not bool or value[field] is not False
        for field in _ACCOUNT_BINDING_REQUIRED_FALSE_FIELDS
    ):
        raise TinkerCustomerError(
            "account-binding authority overclaims identity proof or permits private egress"
        )
    return {
        "truth_status": TINKER_CUSTOMER_ACCOUNT_BINDING_TRUTH,
        "account_binding_schema": TINKER_ACCOUNT_BINDING_SCHEMA,
        "account_binding_version": TINKER_ACCOUNT_BINDING_VERSION,
        "account_binding_chain_id": TINKER_ACCOUNT_BINDING_CHAIN_ID,
        "account_binding_type": TINKER_ACCOUNT_BINDING_TYPE,
        "account_binding_typehash": typehash,
        "provider_namespace_label": TINKER_PROVIDER_NAMESPACE_LABEL,
        "provider_namespace": provider_namespace,
        "account_commitment": account_commitment,
        "account_binding_receipt_digest": semantic_digests[
            "account-binding receipt digest"
        ],
        "sealed_binding_record_hash": semantic_digests[
            "sealed account-binding record hash"
        ],
        "account_binding_ceremony_receipt_digest": semantic_digests[
            "account-binding ceremony receipt digest"
        ],
        "deployment_intent_digest": semantic_digests[
            "deployment intent digest"
        ],
        **{
            field: True
            for field in _ACCOUNT_BINDING_REQUIRED_TRUE_FIELDS
        },
        **{
            field: False
            for field in _ACCOUNT_BINDING_REQUIRED_FALSE_FIELDS
        },
    }


def _account_binding_authority_from_result(
    result: AttestedProvisioningResult,
    *,
    expected_commitment: str,
    expected_ceremony_receipt_digest: str,
    expected_deployment_intent_digest: str,
) -> dict[str, Any]:
    authority = {
        "truth_status": TINKER_CUSTOMER_ACCOUNT_BINDING_TRUTH,
        "account_binding_schema": result.account_binding_schema,
        "account_binding_version": result.account_binding_version,
        "account_binding_chain_id": result.account_binding_chain_id,
        "account_binding_type": result.account_binding_type,
        "account_binding_typehash": result.account_binding_typehash,
        "provider_namespace_label": result.provider_namespace_label,
        "provider_namespace": result.provider_namespace,
        "account_commitment": result.account_commitment,
        "account_binding_receipt_digest": result.account_binding_receipt_digest,
        "sealed_binding_record_hash": result.sealed_binding_record_hash,
        "account_binding_ceremony_receipt_digest":
            result.account_binding_ceremony_receipt_digest,
        "deployment_intent_digest": result.deployment_intent_digest,
        "account_binding_receipt_independently_attested":
            result.account_binding_receipt_independently_attested,
        "account_binding_handle_attested": result.account_binding_handle_attested,
        "provider_identity_checked": result.provider_identity_checked,
        "current_provider_session_rechecked": result.current_provider_session_rechecked,
        "account_commitment_exact_match": result.account_commitment_exact_match,
        "provider_internal_identity_cryptographically_proven":
            result.provider_internal_identity_cryptographically_proven,
        "raw_provider_account_id_egress": result.raw_provider_account_id_egress,
        "raw_binding_root_egress": result.raw_binding_root_egress,
        "raw_reviewer_share_egress": result.raw_reviewer_share_egress,
        "binding_root_or_share_digest_published":
            result.binding_root_or_share_digest_published,
        "raw_provider_auth_egress": result.raw_provider_auth_egress,
        "raw_provider_session_egress": result.raw_provider_session_egress,
        "raw_secret_egress": result.raw_secret_egress,
    }
    try:
        normalized = _normalize_account_binding_authority(
            authority,
            expected_commitment=expected_commitment,
            expected_ceremony_receipt_digest=expected_ceremony_receipt_digest,
            expected_deployment_intent_digest=expected_deployment_intent_digest,
        )
        provisioning_receipt = _exact_nonzero_sha256(
            result.provisioning_receipt_hash,
            "provisioning receipt hash",
        )
        _distinct_exact_sha256_commitments(
            {
                "provisioning receipt hash": provisioning_receipt,
                "account-binding receipt digest": normalized[
                    "account_binding_receipt_digest"
                ],
                "sealed account-binding record hash": normalized[
                    "sealed_binding_record_hash"
                ],
                "account-binding ceremony receipt digest": normalized[
                    "account_binding_ceremony_receipt_digest"
                ],
                "deployment intent digest": normalized[
                    "deployment_intent_digest"
                ],
            },
            error_message=(
                "provisioning and account-binding semantic commitments "
                "must be pairwise distinct"
            ),
        )
    except (TinkerCustomerError, TypeError, ValueError) as exc:
        raise TinkerCustomerUnavailable(
            "provisioning account-binding authority is invalid"
        ) from exc
    return normalized


def _validate_provisioning_result(
    result: AttestedProvisioningResult,
    account: dict[str, Any],
    gate: _Gate,
    now: int,
    expected_release: ExpectedTinkerRelease,
) -> dict[str, Any]:
    if type(result) is not AttestedProvisioningResult:
        raise TinkerCustomerUnavailable("provisioning provider returned an unsupported result")
    if type(result.issued_at) is not int or type(result.expires_at) is not int:
        raise TinkerCustomerUnavailable(
            "attested provisioning timestamps are not exact integers"
        )
    if (
        result.issued_at < 0
        or result.issued_at > now
        or result.expires_at <= now
        or result.expires_at <= result.issued_at
        or result.expires_at - result.issued_at > 300
    ):
        raise TinkerCustomerUnavailable("attested provisioning result is not fresh")
    try:
        if type(result.account_id) is not str:
            raise TinkerCustomerError("provisioning account id is not exact")
        account_id = _resource(
            result.account_id,
            "provisioning account id",
            prefix="tca_",
        )
        request_commitment = _exact_nonzero_sha256(
            result.request_commitment,
            "provisioning request commitment",
        )
        owner_address_hash = _exact_nonzero_sha256(
            result.owner_address_hash,
            "provisioning owner-address hash",
        )
        if type(result.mode) is not str or result.mode not in (
            "create",
            "link_existing",
        ):
            raise TinkerCustomerError("provisioning mode is not exact")
        account_commitment = _exact_nonzero_word(
            result.account_commitment,
            "provisioning account commitment",
        )
        release_policy_tuple_digest = _exact_nonzero_sha256(
            result.release_policy_tuple_digest,
            "provisioning release-policy tuple digest",
        )
        runtime_evidence_digest = _exact_nonzero_sha256(
            result.runtime_evidence_digest,
            "provisioning runtime-evidence digest",
        )
        compose_hash = _exact_nonzero_word(
            result.compose_hash,
            "provisioning compose hash",
        )
        manager = _exact_address(
            result.manager,
            "provisioning manager",
        )
    except (TinkerCustomerError, TypeError, ValueError) as exc:
        raise TinkerCustomerUnavailable(
            "provisioning result contains a noncanonical identity"
        ) from exc
    expected = {
        "account_id": account["account_id"],
        "request_commitment": account["request_commitment"],
        "owner_address_hash": account["owner_address_hash"],
        "mode": account["mode"],
        "account_commitment": gate.snapshot.account_commitment,
        "release_policy_tuple_digest": gate.snapshot.policy_tuple_digest,
        "runtime_evidence_digest": gate.evidence.public_digest(),
    }
    actual = {
        "account_id": account_id,
        "request_commitment": request_commitment,
        "owner_address_hash": owner_address_hash,
        "mode": result.mode,
        "account_commitment": account_commitment,
        "release_policy_tuple_digest": release_policy_tuple_digest,
        "runtime_evidence_digest": runtime_evidence_digest,
    }
    if actual != expected:
        raise TinkerCustomerUnavailable("provisioning result does not match the wallet request and frozen release")
    if compose_hash != gate.evidence.compose_hash or manager != gate.evidence.manager:
        raise TinkerCustomerUnavailable("provisioning result compose or manager does not match runtime evidence")
    binding_authority = _account_binding_authority_from_result(
        result,
        expected_commitment=gate.snapshot.account_commitment,
        expected_ceremony_receipt_digest=(
            expected_release.account_binding_ceremony_receipt_digest
        ),
        expected_deployment_intent_digest=expected_release.deployment_intent_digest,
    )
    if type(result.success) is not bool or type(result.upstream_account_exists) is not bool:
        raise TinkerCustomerUnavailable(
            "provisioning result truth fields are not exact booleans"
        )
    if result.success is not True or result.upstream_account_exists is not True:
        raise TinkerCustomerUnavailable("provisioning did not attest an existing upstream account")
    if type(result.raw_account_identifier_returned) is not bool:
        raise TinkerCustomerUnavailable(
            "provisioning identifier-egress field is not an exact boolean"
        )
    if result.raw_account_identifier_returned is not False:
        raise TinkerCustomerUnavailable("provisioning result violates the bounded output policy")
    return binding_authority


def _validate_settlement_result(
    result: AttestedSettlementResult,
    reservation: dict[str, Any],
    gate: _Gate,
    now: int,
) -> None:
    if type(result) is not AttestedSettlementResult:
        raise TinkerCustomerUnavailable("settlement provider returned an unsupported result")
    if type(result.issued_at) is not int or type(result.expires_at) is not int:
        raise TinkerCustomerUnavailable(
            "attested settlement timestamps are not exact integers"
        )
    if (
        result.issued_at < 0
        or result.issued_at > now
        or result.expires_at <= now
        or result.expires_at <= result.issued_at
        or result.expires_at - result.issued_at > 300
    ):
        raise TinkerCustomerUnavailable("attested settlement result is not fresh")
    try:
        if type(result.reservation_id) is not str:
            raise TinkerCustomerError("settlement reservation id is not exact")
        reservation_id = _resource(
            result.reservation_id,
            "settlement reservation id",
            prefix="tcr_",
        )
        reservation_commitment = _exact_nonzero_sha256(
            result.reservation_commitment,
            "settlement reservation commitment",
        )
        release_policy_tuple_digest = _exact_nonzero_sha256(
            result.release_policy_tuple_digest,
            "settlement release-policy tuple digest",
        )
        runtime_evidence_digest = _exact_nonzero_sha256(
            result.runtime_evidence_digest,
            "settlement runtime-evidence digest",
        )
        if type(result.outcome) is not str:
            raise TinkerCustomerError("settlement outcome is not exact")
    except (TinkerCustomerError, TypeError, ValueError) as exc:
        raise TinkerCustomerUnavailable(
            "settlement result contains a noncanonical identity"
        ) from exc
    if reservation_id != reservation["reservation_id"] or reservation_commitment != reservation[
        "reservation_commitment"
    ]:
        raise TinkerCustomerUnavailable("settlement result is bound to a different reservation")
    expected_runtime_evidence_digest = (
        reservation["dispatch_runtime_evidence_digest"]
        if reservation["status"] == "dispatch_claimed"
        else gate.evidence.public_digest()
    )
    if (
        release_policy_tuple_digest != gate.snapshot.policy_tuple_digest
        or runtime_evidence_digest != expected_runtime_evidence_digest
    ):
        raise TinkerCustomerUnavailable(
            "settlement result is bound to a different release or dispatch evidence"
        )
    if result.outcome not in ("settled", "released"):
        raise TinkerCustomerUnavailable("settlement result outcome is unsupported")
    reserved = int(reservation["amount_policy_units"])
    actual = _uint(result.actual_policy_units, "actual settlement policy units")
    if actual > reserved or (result.outcome == "released" and actual != 0):
        raise TinkerCustomerUnavailable("settlement result exceeds the reservation")
    try:
        _exact_nonzero_sha256(result.usage_receipt_hash, "usage receipt hash")
    except TinkerCustomerError as exc:
        raise TinkerCustomerUnavailable(
            "settlement usage receipt hash is noncanonical"
        ) from exc
    for field, value in (
        ("provider dispatch", result.provider_dispatch_performed),
        ("provider-authoritative billing", result.provider_authoritative_billing),
        ("raw secret egress", result.raw_secret_egress),
    ):
        if type(value) is not bool:
            raise TinkerCustomerUnavailable(
                f"settlement {field} field is not an exact boolean"
            )
    if (
        result.provider_authoritative_billing is not False
        or result.raw_secret_egress is not False
    ):
        raise TinkerCustomerUnavailable("settlement result overclaims provider authority or secret egress")
    if (
        result.provider_dispatch_performed is True
        and reservation["status"] != "dispatch_claimed"
    ):
        raise TinkerCustomerUnavailable(
            "settlement claims provider dispatch without an at-most-once claim"
        )
    if (
        result.outcome == "settled"
        and result.provider_dispatch_performed is not True
    ):
        raise TinkerCustomerUnavailable(
            "settled authority accounting requires confirmed provider dispatch"
        )


def _consume_and_validate_provisioning_result(
    provider: ProvisioningResultProvider,
    *,
    account_id: str,
    request_commitment: str,
    account: dict[str, Any],
    gate: _Gate,
    now: int,
    expected_release: ExpectedTinkerRelease,
) -> tuple[AttestedProvisioningResult, dict[str, Any]]:
    result = provider.consume(
        account_id=account_id,
        request_commitment=request_commitment,
        now=now,
    )
    authority = _validate_provisioning_result(
        result,
        account,
        gate,
        now,
        expected_release,
    )
    return result, authority


def _consume_and_validate_settlement_result(
    provider: SettlementResultProvider,
    *,
    reservation_id: str,
    reservation_commitment: str,
    reservation: dict[str, Any],
    gate: _Gate,
    now: int,
) -> AttestedSettlementResult:
    result = provider.consume(
        reservation_id=reservation_id,
        reservation_commitment=reservation_commitment,
        now=now,
    )
    _validate_settlement_result(result, reservation, gate, now)
    return result


def _empty_state() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "sequence": 0,
        "head_hash": "sha256:" + "00" * 32,
        "accounts": {},
        "credentials": {},
        "reservations": {},
        "idempotency": {},
    }


def _validate_customer_state(state: dict[str, Any]) -> None:
    if not isinstance(state, dict) or set(state) != {
        "schema_version",
        "sequence",
        "head_hash",
        "accounts",
        "credentials",
        "reservations",
        "idempotency",
    }:
        raise TinkerCustomerError("customer state schema is invalid")
    if (
        type(state["schema_version"]) is not int
        or state["schema_version"] != 1
        or type(state["sequence"]) is not int
        or state["sequence"] < 0
    ):
        raise TinkerCustomerError("customer state sequence is invalid")
    _sha256(state["head_hash"], "customer state head hash")
    for key, maximum in (
        ("accounts", MAX_CUSTOMER_ACCOUNTS),
        ("credentials", MAX_CUSTOMER_CREDENTIALS),
        ("reservations", MAX_CUSTOMER_RESERVATIONS),
        ("idempotency", MAX_IDEMPOTENCY_RECORDS),
    ):
        if not isinstance(state[key], dict) or len(state[key]) > maximum:
            raise TinkerCustomerError(f"customer state {key} collection is invalid")
    _assert_no_forbidden_fields(state)
    owner_addresses: set[str] = set()
    for account_id, account in state["accounts"].items():
        _resource(account_id, "account id", prefix="tca_")
        required = {
            "account_id",
            "owner_address",
            "owner_address_hash",
            "mode",
            "status",
            "request_commitment",
            "release_policy_tuple_digest",
            "release_lineage_digest",
            "account_commitment",
            "account_policy",
            "account_policy_digest",
            "created_at",
            "activated_at",
            "revoked_at",
            "provisioning_receipt_hash",
            "account_binding_authority",
            "settled_policy_units",
            "outstanding_policy_units",
        }
        if not isinstance(account, dict) or set(account) != required or account["account_id"] != account_id:
            raise TinkerCustomerError("customer account record is invalid")
        address = _address(account["owner_address"], "customer owner address")
        if address in owner_addresses or account["owner_address_hash"] != _address_hash(address):
            raise TinkerCustomerError("customer owner binding is duplicated or invalid")
        owner_addresses.add(address)
        if account["mode"] not in ("create", "link_existing") or account["status"] not in (
            "requested",
            "active",
            "revoked",
            "cancelled",
        ):
            raise TinkerCustomerError("customer account lifecycle is invalid")
        for field in ("request_commitment", "release_policy_tuple_digest", "account_policy_digest"):
            _sha256(account[field], field)
        release_lineage_digest = _exact_nonzero_sha256(
            account["release_lineage_digest"],
            "release lineage digest",
        )
        if not isinstance(account["account_policy"], dict) or account["account_policy_digest"] != _sha256_json(
            "tinker_customer_account_policy", account["account_policy"]
        ):
            raise TinkerCustomerError("customer account policy commitment is invalid")
        _nonzero_word(account["account_commitment"], "account commitment")
        _uint_string(account["settled_policy_units"], "settled policy units")
        _uint_string(account["outstanding_policy_units"], "outstanding policy units")
        for field in ("created_at", "activated_at", "revoked_at"):
            _uint(account[field], f"customer account {field}")
        if account["created_at"] <= 0:
            raise TinkerCustomerError("customer account creation time is invalid")
        if account["status"] == "requested" and (
            account["activated_at"] != 0 or account["revoked_at"] != 0
        ):
            raise TinkerCustomerError("requested customer account has final timestamps")
        if account["status"] == "active" and (
            account["activated_at"] < account["created_at"]
            or account["revoked_at"] != 0
        ):
            raise TinkerCustomerError("active customer account timestamps are invalid")
        if account["status"] == "revoked" and (
            account["activated_at"] < account["created_at"]
            or account["revoked_at"] < account["activated_at"]
        ):
            raise TinkerCustomerError("revoked customer account timestamps are invalid")
        if account["status"] == "cancelled" and (
            account["activated_at"] != 0
            or account["revoked_at"] < account["created_at"]
        ):
            raise TinkerCustomerError("cancelled customer account timestamps are invalid")
        if (
            account["status"] in ("requested", "cancelled")
            and account["provisioning_receipt_hash"]
        ):
            raise TinkerCustomerError(
                "unactivated customer account cannot claim provisioning"
            )
        if (
            account["status"] in ("requested", "cancelled")
            and account["account_binding_authority"] != {}
        ):
            raise TinkerCustomerError(
                "unactivated customer account cannot claim account-binding authority"
            )
        if account["status"] in ("active", "revoked"):
            provisioning_receipt = _exact_nonzero_sha256(
                account["provisioning_receipt_hash"],
                "provisioning receipt hash",
            )
            binding_authority = _normalize_account_binding_authority(
                account["account_binding_authority"],
                expected_commitment=account["account_commitment"],
            )
            _distinct_exact_sha256_commitments(
                {
                    "provisioning receipt hash": provisioning_receipt,
                    "account-binding receipt digest": binding_authority[
                        "account_binding_receipt_digest"
                    ],
                    "sealed account-binding record hash": binding_authority[
                        "sealed_binding_record_hash"
                    ],
                    "account-binding ceremony receipt digest": binding_authority[
                        "account_binding_ceremony_receipt_digest"
                    ],
                    "deployment intent digest": binding_authority[
                        "deployment_intent_digest"
                    ],
                },
                error_message=(
                    "persisted provisioning and account-binding commitments "
                    "must be pairwise distinct"
                ),
            )
            expected_lineage_digest = _release_lineage_digest(
                account_commitment=account["account_commitment"],
                account_binding_ceremony_receipt_digest=binding_authority[
                    "account_binding_ceremony_receipt_digest"
                ],
                deployment_intent_digest=binding_authority[
                    "deployment_intent_digest"
                ],
            )
            if release_lineage_digest != expected_lineage_digest:
                raise TinkerCustomerError(
                    "customer account release lineage commitment is invalid"
                )
    for credential_id, credential in state["credentials"].items():
        _resource(credential_id, "credential id", prefix="tcc_")
        required = {
            "credential_id",
            "account_id",
            "owner_address_hash",
            "recipient_public_key_hash",
            "operations",
            "scopes",
            "max_operation_policy_units",
            "release_policy_tuple_digest",
            "release_lineage_digest",
            "account_binding_authority_digest",
            "account_binding_ceremony_receipt_digest",
            "deployment_intent_digest",
            "account_policy_digest",
            "jwt_id_hash",
            "status",
            "issued_at",
            "expires_at",
            "revoked_at",
        }
        if not isinstance(credential, dict) or set(credential) != required or credential["credential_id"] != credential_id:
            raise TinkerCustomerError("customer credential record is invalid")
        account = _account(state, credential["account_id"])
        if credential["owner_address_hash"] != account["owner_address_hash"]:
            raise TinkerCustomerError("customer credential owner binding is invalid")
        if credential["account_policy_digest"] != account["account_policy_digest"]:
            raise TinkerCustomerError("customer credential account-policy binding is invalid")
        if (
            credential["release_policy_tuple_digest"]
            != account["release_policy_tuple_digest"]
            or credential["release_lineage_digest"]
            != account["release_lineage_digest"]
        ):
            raise TinkerCustomerError(
                "customer credential release binding is invalid"
            )
        binding_authority = _normalize_account_binding_authority(
            account["account_binding_authority"],
            expected_commitment=account["account_commitment"],
        )
        if (
            credential["account_binding_authority_digest"]
            != _account_binding_authority_digest(binding_authority)
            or credential["account_binding_ceremony_receipt_digest"]
            != binding_authority["account_binding_ceremony_receipt_digest"]
            or credential["deployment_intent_digest"]
            != binding_authority["deployment_intent_digest"]
        ):
            raise TinkerCustomerError(
                "customer credential account-binding lineage is invalid"
            )
        _sha256(credential["recipient_public_key_hash"], "recipient public key hash")
        _sha256(credential["release_policy_tuple_digest"], "release policy tuple digest")
        for field in (
            "release_lineage_digest",
            "account_binding_authority_digest",
            "account_binding_ceremony_receipt_digest",
            "deployment_intent_digest",
        ):
            _exact_nonzero_sha256(credential[field], field)
        _sha256(credential["account_policy_digest"], "account policy digest")
        _sha256(credential["jwt_id_hash"], "jwt id hash")
        for field in ("issued_at", "expires_at", "revoked_at"):
            _uint(credential[field], f"customer credential {field}")
        if (
            credential["issued_at"] <= 0
            or credential["expires_at"] <= credential["issued_at"]
            or (
                credential["status"] == "active"
                and credential["revoked_at"] != 0
            )
            or (
                credential["status"] == "revoked"
                and credential["revoked_at"] < credential["issued_at"]
            )
        ):
            raise TinkerCustomerError("customer credential timestamps are invalid")
        operations = _operations(tuple(credential["operations"]))
        if tuple(credential["scopes"]) != tuple(CUSTOMER_OPERATION_SCOPE[item] for item in operations):
            raise TinkerCustomerError("customer credential scope binding is invalid")
        credential_cap = _uint_string(
            credential["max_operation_policy_units"],
            "credential cap",
        )
        account_cap = _uint_string(
            account["account_policy"].get("max_operation_policy_units"),
            "account policy operation cap",
        )
        if credential_cap <= 0 or credential_cap > account_cap:
            raise TinkerCustomerError(
                "customer credential cap exceeds its immutable account policy"
            )
        if credential["status"] not in ("active", "revoked"):
            raise TinkerCustomerError("customer credential lifecycle is invalid")
    computed_outstanding: dict[str, int] = {account_id: 0 for account_id in state["accounts"]}
    computed_settled: dict[str, int] = {account_id: 0 for account_id in state["accounts"]}
    for reservation_id, reservation in state["reservations"].items():
        _resource(reservation_id, "reservation id", prefix="tcr_")
        required = {
            "reservation_id",
            "reservation_commitment",
            "account_id",
            "credential_id",
            "owner_address_hash",
            "operation",
            "amount_policy_units",
            "actual_policy_units",
            "workload_commitment",
            "release_policy_tuple_digest",
            "release_lineage_digest",
            "account_binding_authority_digest",
            "account_binding_ceremony_receipt_digest",
            "deployment_intent_digest",
            "account_policy_digest",
            "status",
            "reserved_at",
            "dispatch_claimed_at",
            "dispatch_runtime_evidence_digest",
            "finalized_at",
            "usage_receipt_hash",
            "provider_dispatch_performed",
        }
        if not isinstance(reservation, dict) or set(reservation) != required or reservation["reservation_id"] != reservation_id:
            raise TinkerCustomerError("customer reservation record is invalid")
        account = _account(state, reservation["account_id"])
        _credential(state, reservation["credential_id"], reservation["account_id"])
        if reservation["owner_address_hash"] != account["owner_address_hash"]:
            raise TinkerCustomerError("customer reservation owner binding is invalid")
        if reservation["account_policy_digest"] != account["account_policy_digest"]:
            raise TinkerCustomerError("customer reservation account-policy binding is invalid")
        binding_authority = _normalize_account_binding_authority(
            account["account_binding_authority"],
            expected_commitment=account["account_commitment"],
        )
        if (
            reservation["release_policy_tuple_digest"]
            != account["release_policy_tuple_digest"]
            or reservation["release_lineage_digest"]
            != account["release_lineage_digest"]
            or reservation["account_binding_authority_digest"]
            != _account_binding_authority_digest(binding_authority)
            or reservation["account_binding_ceremony_receipt_digest"]
            != binding_authority["account_binding_ceremony_receipt_digest"]
            or reservation["deployment_intent_digest"]
            != binding_authority["deployment_intent_digest"]
        ):
            raise TinkerCustomerError(
                "customer reservation account-binding lineage is invalid"
            )
        for field in (
            "reservation_commitment",
            "workload_commitment",
            "release_policy_tuple_digest",
            "account_policy_digest",
        ):
            _sha256(reservation[field], field)
        for field in (
            "release_lineage_digest",
            "account_binding_authority_digest",
            "account_binding_ceremony_receipt_digest",
            "deployment_intent_digest",
        ):
            _exact_nonzero_sha256(reservation[field], field)
        if reservation["operation"] not in SUPPORTED_CUSTOMER_OPERATIONS or reservation["status"] not in (
            "reserved",
            "dispatch_claimed",
            "settled",
            "released",
        ):
            raise TinkerCustomerError("customer reservation lifecycle is invalid")
        _uint(reservation["reserved_at"], "reservation creation time")
        _uint(
            reservation["dispatch_claimed_at"],
            "reservation dispatch claim time",
        )
        _uint(reservation["finalized_at"], "reservation finalization time")
        if type(reservation["provider_dispatch_performed"]) is not bool:
            raise TinkerCustomerError(
                "customer reservation provider-dispatch truth is invalid"
            )
        if reservation["reserved_at"] <= 0:
            raise TinkerCustomerError("customer reservation creation time is invalid")
        if (
            reservation["status"] in ("reserved", "dispatch_claimed")
            and reservation["finalized_at"] != 0
        ):
            raise TinkerCustomerError("open reservation has a finalization time")
        if reservation["status"] == "reserved" and (
            reservation["dispatch_claimed_at"] != 0
            or reservation["dispatch_runtime_evidence_digest"]
            or reservation["provider_dispatch_performed"] is not False
        ):
            raise TinkerCustomerError(
                "unclaimed reservation contains dispatch evidence"
            )
        if reservation["status"] == "dispatch_claimed":
            if (
                reservation["dispatch_claimed_at"]
                < reservation["reserved_at"]
                or reservation["provider_dispatch_performed"] is not False
            ):
                raise TinkerCustomerError(
                    "dispatch-claimed reservation state is invalid"
                )
            _exact_nonzero_sha256(
                reservation["dispatch_runtime_evidence_digest"],
                "dispatch runtime evidence digest",
            )
        if (
            reservation["status"] in ("settled", "released")
            and reservation["finalized_at"] < reservation["reserved_at"]
        ):
            raise TinkerCustomerError("final reservation timestamp is invalid")
        reserved = _uint_string(reservation["amount_policy_units"], "reservation amount")
        actual = _uint_string(reservation["actual_policy_units"], "reservation actual amount")
        if actual > reserved:
            raise TinkerCustomerError("customer reservation actual amount exceeds reservation")
        if reservation["status"] in ("reserved", "dispatch_claimed"):
            if actual != 0 or reservation["usage_receipt_hash"]:
                raise TinkerCustomerError("open reservation contains final settlement fields")
            computed_outstanding[reservation["account_id"]] += reserved
        else:
            _exact_nonzero_sha256(
                reservation["usage_receipt_hash"],
                "usage receipt hash",
            )
            if reservation["status"] == "released" and actual != 0:
                raise TinkerCustomerError("released reservation has nonzero actual spend")
            if (
                reservation["provider_dispatch_performed"] is True
                and reservation["dispatch_claimed_at"] == 0
            ):
                raise TinkerCustomerError(
                    "final reservation claims unclaimed provider dispatch"
                )
            if reservation["status"] == "settled" and (
                reservation["provider_dispatch_performed"] is not True
                or reservation["dispatch_claimed_at"] == 0
            ):
                raise TinkerCustomerError(
                    "settled reservation lacks confirmed provider dispatch"
                )
            if reservation["dispatch_claimed_at"] > 0:
                _exact_nonzero_sha256(
                    reservation["dispatch_runtime_evidence_digest"],
                    "dispatch runtime evidence digest",
                )
            elif reservation["dispatch_runtime_evidence_digest"]:
                raise TinkerCustomerError(
                    "unclaimed final reservation contains dispatch evidence"
                )
            computed_settled[reservation["account_id"]] += actual
    for account_id, account in state["accounts"].items():
        if int(account["outstanding_policy_units"]) != computed_outstanding[account_id]:
            raise TinkerCustomerError("customer outstanding balance does not reconcile")
        if int(account["settled_policy_units"]) != computed_settled[account_id]:
            raise TinkerCustomerError("customer settled balance does not reconcile")
    for key, record in state["idempotency"].items():
        _idempotency_key(key)
        if not isinstance(record, dict) or set(record) != {"request_hash", "result"}:
            raise TinkerCustomerError("customer idempotency record is invalid")
        _sha256(record["request_hash"], "idempotency request hash")
        if not isinstance(record["result"], dict):
            raise TinkerCustomerError("customer idempotency result is invalid")


def _record_event(state: dict[str, Any], event: str, public_receipt: dict[str, Any]) -> None:
    _assert_no_forbidden_fields(public_receipt)
    sequence = state["sequence"] + 1
    state["head_hash"] = _sha256_json(
        "tinker_customer_event",
        {
            "previous_hash": state["head_hash"],
            "sequence": sequence,
            "event": event,
            "receipt_commitment": _sha256_json("tinker_customer_receipt", public_receipt),
        },
    )
    state["sequence"] = sequence


def _idempotent_replay(state: dict[str, Any], key: str, request_hash: str) -> dict[str, Any] | None:
    existing = state["idempotency"].get(key)
    if existing is None:
        return None
    if not hmac.compare_digest(existing["request_hash"], request_hash):
        raise TinkerCustomerConflict("idempotency key was already used for a different request")
    return copy.deepcopy(existing["result"])


def _put_idempotency(state: dict[str, Any], key: str, request_hash: str, result: dict[str, Any]) -> None:
    if len(state["idempotency"]) >= MAX_IDEMPOTENCY_RECORDS:
        raise TinkerCustomerUnavailable("Tinker customer idempotency capacity reached")
    _assert_no_forbidden_fields(result)
    state["idempotency"][key] = {"request_hash": request_hash, "result": copy.deepcopy(result)}


def _replay(result: dict[str, Any]) -> dict[str, Any]:
    replay = copy.deepcopy(result)
    replay["idempotent_replay"] = True
    return replay


def _account(state: dict[str, Any], account_id: str) -> dict[str, Any]:
    account = state["accounts"].get(account_id)
    if not isinstance(account, dict):
        raise TinkerCustomerNotFound("Tinker customer account was not found")
    return account


def _owned_account(state: dict[str, Any], account_id: str, wallet: str) -> dict[str, Any]:
    account = _account(state, account_id)
    if not hmac.compare_digest(account["owner_address"], wallet):
        # Missing and foreign opaque ids share one classification so an
        # authenticated wallet cannot use status/mutation routes as an account
        # existence oracle.
        raise TinkerCustomerNotFound("Tinker customer account was not found")
    return account


def _owned_active_account(state: dict[str, Any], account_id: str, wallet: str) -> dict[str, Any]:
    account = _owned_account(state, account_id, wallet)
    if account["status"] != "active":
        raise TinkerCustomerError("Tinker customer account is not active")
    return account


def _credential(state: dict[str, Any], credential_id: str, account_id: str) -> dict[str, Any]:
    credential = state["credentials"].get(credential_id)
    if not isinstance(credential, dict) or credential["account_id"] != account_id:
        raise TinkerCustomerNotFound("customer credential was not found")
    return credential


def _reservation(state: dict[str, Any], reservation_id: str) -> dict[str, Any]:
    reservation = state["reservations"].get(reservation_id)
    if not isinstance(reservation, dict):
        raise TinkerCustomerNotFound("customer reservation was not found")
    return reservation


def _validate_live_credential_record(record: dict[str, Any], claims: dict[str, Any], now: int) -> None:
    for field in (
        "credential_id",
        "account_id",
        "owner_address_hash",
        "operations",
        "scopes",
        "max_operation_policy_units",
        "release_policy_tuple_digest",
        "release_lineage_digest",
        "account_binding_authority_digest",
        "account_binding_ceremony_receipt_digest",
        "deployment_intent_digest",
        "account_policy_digest",
        "jwt_id_hash",
        "issued_at",
        "expires_at",
    ):
        if field == "max_operation_policy_units":
            comparable = str(record[field])
            claimed = str(claims[field])
        elif field in ("operations", "scopes"):
            comparable = tuple(record[field])
            claimed = tuple(claims[field])
        else:
            comparable = record[field]
            claimed = claims[field]
        if comparable != claimed:
            raise TinkerCustomerError("customer credential no longer matches its durable authority record")
    if record["status"] != "active" or now >= record["expires_at"]:
        raise TinkerCustomerError("customer credential is revoked or expired")


def _status_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        status = str(record["status"])
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def _assert_no_forbidden_fields(value: Any, path: str = "root") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TinkerCustomerError("customer state keys must be strings")
            normalized = key.lower().replace("-", "_")
            compact = re.sub(r"[^a-z0-9]", "", key.lower())
            if (
                any(fragment in normalized for fragment in _FORBIDDEN_KEY_FRAGMENTS)
                or compact in _FORBIDDEN_EXACT_KEY_COMPACTS
            ):
                raise TinkerCustomerError(f"forbidden customer field at {path}")
            _assert_no_forbidden_fields(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_no_forbidden_fields(item, f"{path}[{index}]")
    elif isinstance(value, (str, int, bool)) or value is None:
        return
    else:
        raise TinkerCustomerError(f"unsupported customer state value at {path}")


def _assert_no_symlink_components(path: Path) -> None:
    """Reject symlinked or non-directory ancestors before pinning the parent FD."""

    if not path.is_absolute():
        raise TinkerCustomerUnavailable("Tinker customer store directory must be absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        try:
            component_stat = os.lstat(current)
        except OSError as exc:
            raise TinkerCustomerUnavailable("Tinker customer store directory is unavailable") from exc
        if stat.S_ISLNK(component_stat.st_mode) or not stat.S_ISDIR(component_stat.st_mode):
            raise TinkerCustomerUnavailable("Tinker customer store directory contains a symlink component")


def _require_distinct_rpc_origins(primary: JsonRpc, secondary: JsonRpc) -> None:
    first_url = getattr(primary, "url", "")
    second_url = getattr(secondary, "url", "")
    if not isinstance(first_url, str) or not isinstance(second_url, str) or not first_url or not second_url:
        raise TinkerCustomerUnavailable(
            "Tinker release RPC implementations must expose canonical HTTPS URLs"
        )
    try:
        first = urlsplit(first_url)
        second = urlsplit(second_url)
    except ValueError as exc:
        raise TinkerCustomerUnavailable("Tinker release RPC URL is invalid") from exc
    origins = []
    for raw, parsed in ((first_url, first), (second_url, second)):
        try:
            parsed_port = parsed.port
        except ValueError as exc:
            raise TinkerCustomerUnavailable("Tinker release RPC URL port is invalid") from exc
        host = (parsed.hostname or "").lower()
        canonical_netloc = host
        if parsed_port is not None:
            canonical_netloc = f"{host}:{parsed_port}"
        if (
            raw != raw.strip()
            or len(raw.encode("utf-8")) > 4096
            or re.search(r"[\x00-\x20\x7f]", raw)
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.hostname != host
            or host.endswith(".")
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?",
                host,
            )
            or parsed.username is not None
            or parsed.password is not None
            or parsed.netloc != canonical_netloc
            or parsed.path
            or parsed.query
            or parsed.fragment
            or (parsed_port is not None and parsed_port <= 0)
            or parsed_port == 443
        ):
            raise TinkerCustomerUnavailable("Tinker release RPCs must be canonical credential-free HTTPS endpoints")
        origins.append(("https", host, parsed_port or 443))
    # Different ports or URL paths on one host are not independent providers.
    # Release safety requires two separately operated DNS origins.
    if origins[0][1] == origins[1][1]:
        raise TinkerCustomerUnavailable("Tinker release RPCs must use distinct provider origins")


def _selector(signature: str) -> bytes:
    return keccak(signature.encode("ascii"))[:4]


def _address_word(value: str) -> bytes:
    return b"\x00" * 12 + bytes.fromhex(_address(value, "address")[2:])


def _same_data(first: Any, second: Any, label: str) -> bytes:
    first_data = _data(first, f"primary {label}")
    second_data = _data(second, f"secondary {label}")
    if not hmac.compare_digest(first_data, second_data):
        raise TinkerCustomerUnavailable(f"Tinker release RPCs disagree on {label}")
    return first_data


def _data(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) % 2 != 0:
        raise TinkerCustomerUnavailable(f"{label} is not canonical hex data")
    try:
        return bytes.fromhex(value[2:])
    except ValueError as exc:
        raise TinkerCustomerUnavailable(f"{label} is not canonical hex data") from exc


def _quantity(value: Any, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]*)", value):
        raise TinkerCustomerUnavailable(f"{label} is not a canonical quantity")
    return int(value, 16)


def _block(value: Any, label: str) -> tuple[int, str]:
    if not isinstance(value, dict):
        raise TinkerCustomerUnavailable(f"{label} is unavailable")
    number = _quantity(value.get("number"), f"{label} number")
    block_hash = _word(str(value.get("hash", "")), f"{label} hash")
    return number, block_hash


def _word_hex(value: bytes) -> str:
    if len(value) != 32:
        raise TinkerCustomerUnavailable("contract value is not one ABI word")
    return "0x" + value.hex()


def _word_uint(value: bytes) -> int:
    if len(value) != 32:
        raise TinkerCustomerUnavailable("contract value is not one ABI word")
    return int.from_bytes(value, "big")


def _word_bool(value: bytes, label: str) -> bool:
    decoded = _word_uint(value)
    if decoded not in (0, 1):
        raise TinkerCustomerUnavailable(f"{label} is not an ABI boolean")
    return bool(decoded)


def _word_address(value: bytes) -> str:
    if len(value) != 32 or value[:12] != b"\x00" * 12:
        raise TinkerCustomerUnavailable("contract address value is not canonical")
    return "0x" + value[12:].hex()


def _address(value: str, label: str) -> str:
    try:
        normalized = normalize_wallet_address(value)
    except Exception as exc:
        raise TinkerCustomerError(f"{label} must be a 20-byte address") from exc
    if normalized == ZERO_ADDRESS and label not in ("pending owner", "address"):
        raise TinkerCustomerError(f"{label} must be non-zero")
    return normalized


def _exact_address(value: Any, label: str) -> str:
    if type(value) is not str:
        raise TinkerCustomerError(f"{label} must be a canonical 20-byte address")
    normalized = _address(value, label)
    if value != normalized:
        raise TinkerCustomerError(
            f"{label} must be a canonical lowercase 20-byte address"
        )
    return normalized


def _word(value: str, label: str) -> str:
    normalized = str(value).strip().lower()
    if not _HEX_32_RE.fullmatch(normalized):
        raise TinkerCustomerError(f"{label} must be bytes32")
    return normalized


def _exact_word(value: Any, label: str) -> str:
    if type(value) is not str:
        raise TinkerCustomerError(f"{label} must be canonical bytes32")
    normalized = _word(value, label)
    if value != normalized:
        raise TinkerCustomerError(f"{label} must be canonical lowercase bytes32")
    return normalized


def _nonzero_word(value: str, label: str) -> str:
    normalized = _word(value, label)
    if normalized == ZERO_WORD:
        raise TinkerCustomerError(f"{label} must be non-zero")
    return normalized


def _exact_nonzero_word(value: Any, label: str) -> str:
    normalized = _exact_word(value, label)
    if normalized == ZERO_WORD:
        raise TinkerCustomerError(f"{label} must be non-zero")
    return normalized


def _sha256(value: str, label: str) -> str:
    normalized = str(value).strip().lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise TinkerCustomerError(f"{label} must be a sha256 commitment")
    return normalized


def _exact_sha256(value: Any, label: str) -> str:
    if type(value) is not str:
        raise TinkerCustomerError(f"{label} must be a canonical sha256 commitment")
    normalized = _sha256(value, label)
    if value != normalized:
        raise TinkerCustomerError(
            f"{label} must be a canonical lowercase sha256 commitment"
        )
    return normalized


def _nonzero_sha256(value: str, label: str) -> str:
    normalized = _sha256(value, label)
    if normalized == "sha256:" + "0" * 64:
        raise TinkerCustomerError(f"{label} must be non-zero")
    return normalized


def _exact_nonzero_sha256(value: Any, label: str) -> str:
    normalized = _exact_sha256(value, label)
    if normalized == "sha256:" + "0" * 64:
        raise TinkerCustomerError(f"{label} must be non-zero")
    return normalized


def _distinct_exact_sha256_commitments(
    values: dict[str, Any],
    *,
    error_message: str,
) -> dict[str, str]:
    normalized = {
        label: _exact_nonzero_sha256(value, label)
        for label, value in values.items()
    }
    if len(set(normalized.values())) != len(normalized):
        raise TinkerCustomerError(error_message)
    return normalized


_EXTERNAL_CALL_FAILED = object()


def _fixed_external_call(operation, *, error_type, error_code: str) -> Any:
    """Call one injected boundary without retaining or reflecting its exception."""

    try:
        result = operation()
    except Exception:
        result = _EXTERNAL_CALL_FAILED
    if result is _EXTERNAL_CALL_FAILED:
        raise error_type(error_code) from None
    return result


def _address_hash(address: str) -> str:
    return _sha256_text("tinker_customer_owner", _address(address, "customer owner address"))


def _sha256_text(domain: str, value: str) -> str:
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\x00" + value.encode("utf-8")).hexdigest()


def _sha256_json(domain: str, value: Any) -> str:
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\x00" + _canonical_bytes(value)).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _jsonable(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


def _operations(value: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value or any(not isinstance(item, str) for item in value):
        raise TinkerCustomerError("customer operations must be a non-empty tuple")
    normalized = tuple(sorted(set(item.strip().lower() for item in value if item.strip())))
    if not normalized or any(item not in SUPPORTED_CUSTOMER_OPERATIONS for item in normalized):
        raise TinkerCustomerError("customer operation is unsupported")
    return normalized


def _positive_uint(value: Any, label: str) -> int:
    normalized = _uint(value, label)
    if normalized <= 0:
        raise TinkerCustomerError(f"{label} must be positive")
    return normalized


def _uint(value: Any, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 2**256:
        raise TinkerCustomerError(f"{label} must be uint256")
    return value


def _uint_string(value: Any, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        raise TinkerCustomerError(f"{label} must be a canonical uint string")
    normalized = int(value)
    if normalized >= 2**256:
        raise TinkerCustomerError(f"{label} exceeds uint256")
    return normalized


def _idempotency_key(value: str) -> str:
    if not isinstance(value, str) or not _IDEMPOTENCY_RE.fullmatch(value):
        raise TinkerCustomerError("idempotency key is malformed or too short")
    return value


def _resource(value: str, label: str, *, prefix: str) -> str:
    if not isinstance(value, str) or not value.startswith(prefix) or not _RESOURCE_RE.fullmatch(value):
        raise TinkerCustomerError(f"{label} is malformed")
    return value


def _x25519_public_key(value: str) -> bytes:
    if type(value) is not str or not _HEX_64_RE.fullmatch(value):
        raise TinkerCustomerError(TC_RECIPIENT_X25519_INVALID)
    raw = bytes.fromhex(value)
    invalid = False
    try:
        public_key = X25519PublicKey.from_public_bytes(raw)
        # Object construction alone accepts low-order points such as all-zero.
        # A deterministic local exchange rejects every key that would derive a
        # null shared secret before credential generation begins.
        X25519PrivateKey.from_private_bytes(b"\x01" + b"\x00" * 31).exchange(
            public_key
        )
    except ValueError:
        invalid = True
    if invalid:
        raise TinkerCustomerError(TC_RECIPIENT_X25519_INVALID)
    return raw


def _encode_jwt(payload: dict[str, Any], key: bytes) -> str:
    signing_input = b".".join((_b64url_json(CUSTOMER_CREDENTIAL_HEADER), _b64url_json(payload)))
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + _b64url(signature)).decode("ascii")


def _decode_jwt(token: str, key: bytes) -> dict[str, Any]:
    if not isinstance(token, str) or len(token) > 4096:
        raise TinkerCustomerError("customer credential format is invalid")
    parts = token.split(".")
    if len(parts) != 3 or any(not _JWT_PART_RE.fullmatch(part) for part in parts):
        raise TinkerCustomerError("customer credential format is invalid")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        supplied = _b64url_decode(parts[2])
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TinkerCustomerError("customer credential encoding is invalid") from exc
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied, expected):
        raise TinkerCustomerError("customer credential signature is invalid")
    if header != CUSTOMER_CREDENTIAL_HEADER or not isinstance(payload, dict):
        raise TinkerCustomerError("customer credential header or payload is invalid")
    return payload


def _b64url_json(value: dict[str, Any]) -> bytes:
    return _b64url(_canonical_bytes(value))


def _b64url(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not _JWT_PART_RE.fullmatch(value):
        raise ValueError("invalid base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _now(value: int | None) -> int:
    if value is None:
        current = int(time.time())
    elif type(value) is int:
        current = value
    else:
        raise TinkerCustomerError("time must be an exact integer")
    if current < 0:
        raise TinkerCustomerError("time must be non-negative")
    return current
