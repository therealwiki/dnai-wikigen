"""Production wiring for one-shot Collaboration execution.

The public API may supply bounded Compute and funding terms, but it can never
supply a Collaboration authority snapshot, a finalized vault observation, or
a Compute-journal projection.  Those values are reconstructed here from the
authenticated local stores and a hash-pinned, single-RPC finalized Base
Sepolia read.  Collaboration persists its handoff before invoking the shared
Compute admission service and never calls a provider.
"""

from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any, Callable, Mapping, Sequence

import httpx
from eth_hash.auto import keccak

from tinker_delegate import dstack_utils
from tinker_delegate.collaboration_execution import (
    BoundedExecutionResult,
    ClaimAuthoritySnapshot,
    CollaborationExecutionAuthorityInvalidated,
    CollaborationExecutionAuthorityUnavailable,
    CollaborationExecutionBasis,
    CollaborationExecutionError,
    CollaborationExecutionIntent,
    CollaborationExecutionJournal,
    ComputeHandoff,
    ComputeJournalProjection,
    ExecutionState,
    FinalizedComputeVaultObservation,
    FinalizedRoyaltyAuthorityObservation,
    OwnerExecutionGrant,
    RoyaltyFundingReservation,
    execution_grant_set_commitment,
)
from tinker_delegate.compute_dispatch_admission import (
    ComputeDispatchAdmissionService,
)
from tinker_delegate.compute_runtime import (
    ComputeDispatchIntent,
    ComputeExecutionJournal,
    ComputeRuntimeError,
    MeteringDecision,
    ProviderUsage,
    SignedUsageEnvelope,
)
from tinker_delegate.compute_vault_gateway import (
    MAX_RPC_RESPONSE_BYTES,
    MAX_RUNTIME_CODE_BYTES,
    _GET_JOB,
    _address,
    _bounded_url,
    _bytes32,
    _bytes32_word,
    _decode_address,
    _decode_bool,
    _decode_bytes32,
    _decode_uint,
    _decode_words,
    _hex_bytes,
    _quantity,
    _word_address,
    _word_bool,
    _word_bytes32,
    _word_uint,
)
from tinker_delegate.royalty_settlement_authorization import (
    RoyaltySettlementReleaseBinding,
)
from tinker_delegate.wallet_auth import normalize_wallet_address


PLAN_SCHEMA = "dnai.collaboration.execution-plan-token.v2"
GRANT_CHALLENGE_SCHEMA = "dnai.collaboration.execution-grant-challenge.v2"
BASE_SEPOLIA_CHAIN_ID = 84_532
MAX_TOKEN_BYTES = 48 * 1024
MAX_AUTHORIZATION_SECONDS = 3_600

_TOKEN_PART = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^(?!0{40}$)[0-9a-f]{40}$")
_CVM_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{7,127}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")

_PLAN_TOKEN_DOMAIN = b"dnai-wikigen/collaboration-execution-plan-token/v2\0"
_GRANT_TOKEN_DOMAIN = b"dnai-wikigen/collaboration-execution-grant-token/v2\0"
_GRANT_MESSAGE_DOMAIN = "wikigen collaboration one-shot execution grant v2"
_SIGNATURE_HASH_DOMAIN = (
    b"dnai-wikigen/collaboration-one-shot-execution-signature/v1\0"
)
_FINALIZED_RECEIPT_DOMAIN = (
    b"dnai-wikigen/collaboration-finalized-vault-read-receipt/v1\0"
)
_COMPUTE_RECORD_DOMAIN = (
    b"dnai-wikigen/collaboration-authenticated-compute-record/v1\0"
)
_COMPUTE_RECEIPT_DOMAIN = (
    b"dnai-wikigen/collaboration-compute-journal-read-receipt/v1\0"
)
_ROYALTY_RELEASE_BINDING_DOMAIN = (
    b"dnai-wikigen/collaboration-royalty-release-binding/v1\0"
)
_ROYALTY_RECEIPT_DOMAIN = (
    b"dnai-wikigen/collaboration-royalty-current-state-receipt/v1\0"
)
_ROYALTY_SETTLEMENT_RECEIPT_DOMAIN = (
    b"dnai-wikigen/collaboration-royalty-finalized-settlement/v1\0"
)


def _selector(signature: bytes) -> bytes:
    return keccak(signature)[:4]


_ROYALTY_PAUSED = _selector(b"paused()")
_ROYALTY_OWNER = _selector(b"owner()")
_ROYALTY_PENDING_OWNER = _selector(b"pendingOwner()")
_ROYALTY_SETTLEMENT_VERIFIER = _selector(b"settlementVerifier()")
_ROYALTY_QVL_VERIFIER = _selector(b"qvlVerifier()")
_ROYALTY_ANCHOR = _selector(b"executionPolicyAnchor()")
_ROYALTY_ANCHOR_RELEASE = _selector(b"anchorWriterReleaseCommitment()")
_ROYALTY_RELEASE_POLICY = _selector(b"releasePolicyCommitment()")
_ROYALTY_AUTHORITY_NONCE = _selector(b"authorityNonce()")
_ROYALTY_PENDING_SETTLEMENT = _selector(b"pendingSettlementVerifier()")
_ROYALTY_PENDING_QVL = _selector(b"pendingQvlVerifier()")
_ROYALTY_PENDING_ANCHOR = _selector(b"pendingExecutionPolicyAnchor()")
_ROYALTY_PENDING_ANCHOR_RELEASE = _selector(
    b"pendingAnchorWriterReleaseCommitment()"
)
_ROYALTY_PENDING_RELEASE = _selector(b"pendingReleasePolicyCommitment()")
_ROYALTY_PENDING_NONCE = _selector(b"pendingAuthorityNonce()")
_ROYALTY_PENDING_ACTIVATES = _selector(b"pendingAuthorityActivatesAt()")
_ROYALTY_PENDING_REVOCATION = _selector(b"pendingAuthorityRevocation()")
_ROYALTY_COLLABORATION_RESERVATION = _selector(
    b"collaborationFundingReservation(bytes32)"
)
_ROYALTY_FUNDING_RESERVATION_STATE = _selector(
    b"fundingReservationState(bytes32)"
)
_ROYALTY_FUNDING_SETTLEMENT_STATE = _selector(
    b"fundingReservationSettlementState(bytes32)"
)
_ANCHOR_WRITER = _selector(b"writer()")
_ANCHOR_WRITER_RELEASE = _selector(b"writerReleaseCommitment()")
_ANCHOR_ROTATIONS_FROZEN = _selector(b"writerRotationsFrozen()")
_ANCHOR_PAUSED = _selector(b"paused()")


class CollaborationExecutionServiceError(CollaborationExecutionError):
    """The API/worker integration rejected an execution operation."""


class CollaborationExecutionServiceUnavailable(RuntimeError):
    """A required authenticated store, release field, or RPC is unavailable."""


@dataclass(frozen=True)
class ExecutionPlan:
    basis: CollaborationExecutionBasis
    requester_address: str
    run_id: str
    royalty_owner_amounts: Mapping[str, int]
    plan_token: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "surface": "collaboration_execution_plan",
            "schema_version": 2,
            "run_id": self.run_id,
            "room_id": self.basis.room_id,
            "requester_address": self.requester_address,
            "basis": self.basis.to_dict(),
            "basis_commitment": self.basis.commitment,
            "owner_addresses": list(self.basis.owner_addresses),
            "royalty_owner_amounts_hash": self.basis.royalty_owner_amounts_hash,
            "royalty_release_binding_commitment": (
                self.basis.royalty_release_binding_commitment
            ),
            "royalty_distributor_address": (
                self.basis.royalty_distributor_address
            ),
            "royalty_release_policy_commitment": (
                self.basis.royalty_release_policy_commitment
            ),
            "royalty_settlement_id": self.basis.royalty_settlement_id,
            "royalty_settlement_nonce": str(
                self.basis.royalty_settlement_nonce
            ),
            "royalty_reservation_safety_seconds": (
                self.basis.royalty_reservation_safety_seconds
            ),
            "royalty_authority_server_derived": True,
            "royalty_reservation_is_derived_after_fresh_owner_grants": True,
            "royalty_reservation_must_be_deposited_onchain_after_authorization": True,
            "plan_token": self.plan_token,
            "plan_token_contains_bounded_metadata_only": True,
            "requires_fresh_execution_grant_from_every_owner": True,
            "query_grants_are_not_execution_grants": True,
            "provider_dispatch_performed": False,
            "raw_signature_retained": False,
            "raw_query_egress": False,
            "raw_artifact_egress": False,
        }


@dataclass(frozen=True)
class FinalizedObservationReceipt:
    observation: FinalizedComputeVaultObservation
    block_timestamp: int
    source_record_commitment: str
    authentication_receipt: str


@dataclass(frozen=True)
class AuthenticatedComputeProjection:
    projection: ComputeJournalProjection
    source_sequence: int
    source_record_commitment: str
    source_journal_mac_commitment: str
    authentication_receipt: str

    def to_evidence_dict(self) -> dict[str, Any]:
        return {
            "source_sequence": self.source_sequence,
            "source_record_commitment": self.source_record_commitment,
            "source_journal_mac_commitment": self.source_journal_mac_commitment,
            "source_authentication_receipt": self.authentication_receipt,
            "projection_commitment": self.projection.commitment,
            "source_authentication_proven_to_worker": True,
            "client_supplied_projection": False,
        }


def collaboration_execution_integrity_key(settings: Any) -> bytes:
    """Resolve the execution-journal key with no live explicit-key escape."""

    explicit = str(
        getattr(settings, "collaboration_execution_journal_integrity_key", "")
        or ""
    )
    if explicit:
        if dstack_utils.is_dstack_enabled():
            raise CollaborationExecutionServiceUnavailable(
                "explicit Collaboration execution keys are local-development only"
            )
        if len(explicit.encode("utf-8")) < 32:
            raise CollaborationExecutionServiceUnavailable(
                "Collaboration execution journal key is too short"
            )
        return hashlib.sha256(
            b"dnai-collaboration-execution-local-v1\0"
            + explicit.encode("utf-8")
        ).digest()
    path = str(
        getattr(
            settings,
            "collaboration_execution_journal_integrity_key_path",
            "tinker/collaboration_execution_journal_integrity",
        )
        or ""
    ).strip()
    if not path:
        raise CollaborationExecutionServiceUnavailable(
            "Collaboration execution journal key path is missing"
        )
    try:
        return dstack_utils.derive_storage_key(path)
    except Exception as exc:
        raise CollaborationExecutionServiceUnavailable(
            "Collaboration execution journal key derivation failed"
        ) from exc


def royalty_release_binding_from_settings(
    settings: Any,
) -> RoyaltySettlementReleaseBinding:
    """Construct the complete reviewed Royalty release or fail closed."""

    try:
        return RoyaltySettlementReleaseBinding(
            distributor_address=getattr(settings, "royalty_distributor_address", ""),
            distributor_runtime_code_hash=getattr(
                settings, "royalty_distributor_runtime_code_hash", ""
            ),
            owner_address=getattr(settings, "royalty_owner_address", ""),
            authority_nonce=int(getattr(settings, "royalty_authority_nonce", 0)),
            settlement_verifier_address=getattr(
                settings, "royalty_settlement_verifier", ""
            ),
            royalty_qvl_verifier_address=getattr(
                settings, "royalty_qvl_verifier", ""
            ),
            execution_policy_anchor_address=getattr(
                settings, "royalty_execution_policy_anchor", ""
            ),
            anchor_writer_release_commitment=getattr(
                settings, "royalty_anchor_writer_release_commitment", ""
            ),
            release_policy_commitment=getattr(
                settings, "royalty_release_policy_commitment", ""
            ),
            royalty_qvl_policy_commitment=getattr(
                settings, "royalty_qvl_policy_commitment", ""
            ),
            royalty_qvl_signer_key_id=getattr(
                settings, "royalty_qvl_signer_key_id", ""
            ),
            qvl_release_policy_hash=getattr(
                settings, "royalty_qvl_release_policy_hash", ""
            ),
            main_runtime_cvm_id=getattr(settings, "main_runtime_cvm_id", ""),
            deployment_intent_sha256=getattr(
                settings, "release_deployment_intent_sha256", ""
            ),
            release_authority_sha256=getattr(
                settings, "release_authority_sha256", ""
            ),
            ceremony_nonce=getattr(settings, "release_ceremony_nonce", ""),
            measurement_policy_sha256=getattr(
                settings, "royalty_measurement_policy_sha256", ""
            ),
            compose_hash=getattr(settings, "royalty_main_runtime_compose_hash", ""),
            app_id=getattr(settings, "royalty_main_runtime_app_id", ""),
            os_image_hash=getattr(
                settings, "royalty_main_runtime_os_image_hash", ""
            ),
        )
    except Exception as exc:
        raise CollaborationExecutionServiceUnavailable(
            "Royalty settlement release binding is incomplete"
        ) from exc


def royalty_release_binding_commitment(
    binding: RoyaltySettlementReleaseBinding,
) -> str:
    payload = {
        field: getattr(binding, field)
        for field in binding.__dataclass_fields__
    }
    return _sha256_commitment(
        _ROYALTY_RELEASE_BINDING_DOMAIN + _canonical_json(payload)
    )


class CollaborationExecutionCoordinator:
    """Create stateless signed plans and persist only verified grant hashes."""

    _PLAN_REQUEST_FIELDS = {
        "compute_project_id",
        "compute_job_id",
        "compute_workload_id",
        "compute_workload_commitment",
        "compute_manifest_commitment",
        "compute_rate_policy_commitment",
        "compute_workload_schema",
        "compute_workload_source_kind",
        "compute_workload_execution_binding_commitment",
        "compute_workload_recipient_release_commitment",
        "compute_user_address",
        "operation",
        "model",
        "recipe",
        "result_policy",
        "max_prefill_tokens",
        "max_sample_tokens",
        "max_train_tokens",
        "sponsor_address",
        "asset",
        "max_total_asset_debit",
        "max_compute_asset_debit",
        "authorization_nonce",
        "authorization_lifetime_seconds",
        "royalty_total",
    }

    def __init__(
        self,
        *,
        settings: Any,
        collaboration_store: Any,
        execution_journal: CollaborationExecutionJournal,
        integrity_key: bytes,
        signature_verifier: Any,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if len(integrity_key) < 32:
            raise CollaborationExecutionServiceUnavailable(
                "Collaboration execution integration key is too short"
            )
        if not callable(
            getattr(collaboration_store, "execution_authority_snapshot", None)
        ) or not callable(
            getattr(
                collaboration_store,
                "execution_authority_snapshot_by_commitment",
                None,
            )
        ):
            raise CollaborationExecutionServiceUnavailable(
                "authenticated Collaboration execution authority is unavailable"
            )
        if not isinstance(execution_journal, CollaborationExecutionJournal):
            raise CollaborationExecutionServiceUnavailable(
                "Collaboration execution journal is unavailable"
            )
        if not callable(getattr(signature_verifier, "verify", None)):
            raise CollaborationExecutionServiceUnavailable(
                "wallet signature verifier is unavailable"
            )
        self.settings = settings
        self.store = collaboration_store
        self.journal = execution_journal
        self.signature_verifier = signature_verifier
        self._token_key = hashlib.sha256(
            b"dnai-collaboration-execution-token-codec-v1\0" + integrity_key
        ).digest()
        self.clock = clock or time.time

    def create_plan(
        self,
        *,
        run_id: str,
        requester_address: str,
        request: Mapping[str, Any],
        now: int | None = None,
    ) -> ExecutionPlan:
        timestamp = self._now(now)
        requester = normalize_wallet_address(requester_address)
        snapshot = self.store.execution_authority_snapshot(run_id, requester)
        if snapshot["requester_address"] != requester:
            raise CollaborationExecutionServiceError(
                "only the joint-consent requester may fund its execution"
            )
        request_fields = self._validate_plan_request(request)
        if request_fields["compute_user_address"] != requester:
            raise CollaborationExecutionServiceError(
                "Compute funding wallet must be the joint-consent requester"
            )
        if request_fields["sponsor_address"] != requester:
            raise CollaborationExecutionServiceError(
                "execution sponsor must be the on-chain Compute funding wallet"
            )
        lifetime = request_fields.pop("authorization_lifetime_seconds")
        basis, amounts = self._basis_from_snapshot(
            snapshot,
            request_fields,
            intent_created_at=timestamp,
            authorization_expiry=timestamp + lifetime,
            royalty_settlement_id=_fresh_nonzero_bytes32(),
            royalty_settlement_nonce=_fresh_nonzero_uint256(),
        )
        body = {
            "schema": PLAN_SCHEMA,
            "run_id": snapshot["run_id"],
            "requester_address": requester,
            "basis": basis.to_dict(),
            "royalty_owner_amounts": amounts,
        }
        return ExecutionPlan(
            basis=basis,
            requester_address=requester,
            run_id=snapshot["run_id"],
            royalty_owner_amounts=amounts,
            plan_token=self._encode_token(body, domain=_PLAN_TOKEN_DOMAIN),
        )

    def issue_owner_grant_challenge(
        self,
        *,
        plan_token: str,
        owner_address: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = self._now(now)
        plan = self._decode_plan(plan_token)
        self._require_current_plan(plan)
        owner = normalize_wallet_address(owner_address)
        owner_record = self._owner_record(plan, owner)
        ttl = int(
            getattr(
                self.settings,
                "collaboration_execution_grant_ttl_seconds",
                300,
            )
        )
        if ttl < 60 or ttl > 900:
            raise CollaborationExecutionServiceUnavailable(
                "Collaboration execution grant TTL is unavailable"
            )
        expires_at = min(timestamp + ttl, plan.basis.authorization_expiry)
        if expires_at <= timestamp:
            raise CollaborationExecutionServiceError(
                "execution plan expired before grant challenge issuance"
            )
        grant_id = f"xgrant_{secrets.token_hex(16)}"
        message_payload = {
            "domain": _GRANT_MESSAGE_DOMAIN,
            "schema": GRANT_CHALLENGE_SCHEMA,
            "chain_id": BASE_SEPOLIA_CHAIN_ID,
            "scope": "one_shot_execution",
            "grant_id": grant_id,
            "owner_address": owner,
            "basis_commitment": plan.basis.commitment,
            "royalty_settlement_nonce": str(
                plan.basis.royalty_settlement_nonce
            ),
            "prospective_query_grant_authorization_hash": owner_record[
                "prospective_query_grant_authorization_hash"
            ],
            "execution_grant_generation": owner_record[
                "query_grant_generation"
            ],
            "issued_at": timestamp,
            "expires_at": expires_at,
            "query_grants_are_not_execution_grants": True,
        }
        message = json.dumps(
            message_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        token_body = {
            "schema": GRANT_CHALLENGE_SCHEMA,
            "plan_commitment": _sha256_commitment(
                _canonical_json(self._plan_token_body(plan))
            ),
            "message": message,
            "grant": {
                key: message_payload[key]
                for key in (
                    "grant_id",
                    "owner_address",
                    "basis_commitment",
                    "royalty_settlement_nonce",
                    "prospective_query_grant_authorization_hash",
                    "execution_grant_generation",
                    "issued_at",
                    "expires_at",
                )
            },
        }
        challenge_token = self._encode_token(
            token_body,
            domain=_GRANT_TOKEN_DOMAIN,
        )
        return {
            "surface": "collaboration_execution_grant_challenge",
            "schema_version": 2,
            "grant_id": grant_id,
            "owner_address": owner,
            "basis_commitment": plan.basis.commitment,
            "royalty_settlement_nonce": str(
                plan.basis.royalty_settlement_nonce
            ),
            "message": message,
            "challenge_token": challenge_token,
            "issued_at": timestamp,
            "expires_at": expires_at,
            "scope": "one_shot_execution",
            "query_grants_are_not_execution_grants": True,
            "raw_signature_retained": False,
        }

    def authorize(
        self,
        *,
        plan_token: str,
        requester_address: str,
        grant_submissions: Sequence[Mapping[str, Any]],
        idempotency_key: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = self._now(now)
        requester = normalize_wallet_address(requester_address)
        key = str(idempotency_key)
        if not _IDEMPOTENCY.fullmatch(key):
            raise CollaborationExecutionServiceError(
                "execution idempotency key is invalid"
            )
        plan = self._decode_plan(plan_token)
        if plan.requester_address != requester:
            raise CollaborationExecutionServiceError(
                "execution plan belongs to a different requester"
            )
        current_snapshot = self._require_current_plan(plan)
        if not isinstance(grant_submissions, Sequence) or isinstance(
            grant_submissions, (str, bytes)
        ):
            raise CollaborationExecutionServiceError(
                "execution grant submissions are invalid"
            )
        expected_plan_commitment = _sha256_commitment(
            _canonical_json(self._plan_token_body(plan))
        )
        grants: list[OwnerExecutionGrant] = []
        verifier_kinds: list[str] = []
        for item in grant_submissions:
            if not isinstance(item, Mapping) or set(item) != {
                "challenge_token",
                "signature",
            }:
                raise CollaborationExecutionServiceError(
                    "execution grant submission is invalid"
                )
            challenge = self._decode_token(
                str(item["challenge_token"]),
                domain=_GRANT_TOKEN_DOMAIN,
            )
            if (
                set(challenge) != {
                    "schema",
                    "plan_commitment",
                    "message",
                    "grant",
                }
                or challenge["schema"] != GRANT_CHALLENGE_SCHEMA
                or challenge["plan_commitment"] != expected_plan_commitment
                or not isinstance(challenge["grant"], Mapping)
            ):
                raise CollaborationExecutionServiceError(
                    "execution grant challenge is invalid"
                )
            template = challenge["grant"]
            if set(template) != {
                "grant_id",
                "owner_address",
                "basis_commitment",
                "royalty_settlement_nonce",
                "prospective_query_grant_authorization_hash",
                "execution_grant_generation",
                "issued_at",
                "expires_at",
            }:
                raise CollaborationExecutionServiceError(
                    "execution grant template is invalid"
                )
            owner = normalize_wallet_address(template["owner_address"])
            owner_record = self._owner_record(plan, owner, current_snapshot)
            if (
                template["basis_commitment"] != plan.basis.commitment
                or template["royalty_settlement_nonce"]
                != str(plan.basis.royalty_settlement_nonce)
                or template["prospective_query_grant_authorization_hash"]
                != owner_record["prospective_query_grant_authorization_hash"]
                or template["execution_grant_generation"]
                != owner_record["query_grant_generation"]
                or not isinstance(template["issued_at"], int)
                or isinstance(template["issued_at"], bool)
                or not isinstance(template["expires_at"], int)
                or isinstance(template["expires_at"], bool)
                or timestamp < template["issued_at"]
                or timestamp >= template["expires_at"]
            ):
                raise CollaborationExecutionServiceError(
                    "execution grant challenge is stale or changed"
                )
            signature = str(item["signature"])
            kind = self.signature_verifier.verify(
                address=owner,
                message=str(challenge["message"]),
                signature=signature,
            )
            if kind not in {"eoa", "eip1271"}:
                raise CollaborationExecutionServiceUnavailable(
                    "wallet signature verifier returned an unsupported result"
                )
            raw_signature = _signature_bytes(signature)
            execution_hash = "sha256:" + hashlib.sha256(
                _SIGNATURE_HASH_DOMAIN
                + str(challenge["message"]).encode("utf-8")
                + raw_signature
            ).hexdigest()
            grants.append(
                OwnerExecutionGrant.create(
                    grant_id=template["grant_id"],
                    owner_address=owner,
                    basis_commitment=plan.basis.commitment,
                    prospective_query_grant_authorization_hash=template[
                        "prospective_query_grant_authorization_hash"
                    ],
                    execution_authorization_hash=execution_hash,
                    execution_grant_generation=template[
                        "execution_grant_generation"
                    ],
                    granted_at=template["issued_at"],
                    expires_at=template["expires_at"],
                )
            )
            verifier_kinds.append(kind)
        intent = CollaborationExecutionIntent.finalize(
            plan.basis,
            grants,
            now=timestamp,
        )
        execution, created = self.journal.authorize(
            intent,
            grants,
            royalty_owner_amounts=plan.royalty_owner_amounts,
            idempotency_key=key,
            authorized_at=timestamp,
        )
        queued = self.journal.queue(intent.execution_id, queued_at=timestamp)
        return {
            "surface": "collaboration_execution_authorization_result",
            "schema_version": 2,
            "created": created,
            "idempotent_replay": not created,
            "verifier_kinds": sorted(set(verifier_kinds)),
            "raw_signatures_retained": False,
            "query_grants_reused_as_execution_grants": False,
            "provider_dispatch_performed": False,
            "execution": queued,
            "authorization_commitment": execution[
                "authorization_commitment"
            ],
            "royalty_reservation": execution["royalty"][
                "funding_reservation"
            ],
        }

    def current_basis_for_intent(
        self,
        intent: CollaborationExecutionIntent,
    ) -> CollaborationExecutionBasis:
        snapshot = self.store.execution_authority_snapshot_by_commitment(
            intent.joint_consent_snapshot_commitment,
            intent.compute_user_address,
        )
        request = {
            field: getattr(intent, field)
            for field in self._PLAN_REQUEST_FIELDS
            if field not in {"authorization_lifetime_seconds"}
        }
        request.pop("royalty_owner_amounts_hash", None)
        basis, _amounts = self._basis_from_snapshot(
            snapshot,
            request,
            intent_created_at=intent.intent_created_at,
            authorization_expiry=intent.authorization_expiry,
            royalty_settlement_id=intent.royalty_settlement_id,
            royalty_settlement_nonce=intent.royalty_settlement_nonce,
        )
        return basis

    def _require_current_plan(self, plan: ExecutionPlan) -> Mapping[str, Any]:
        snapshot = self.store.execution_authority_snapshot(
            plan.run_id,
            plan.requester_address,
        )
        request = {
            field: getattr(plan.basis, field)
            for field in self._PLAN_REQUEST_FIELDS
            if field != "authorization_lifetime_seconds"
        }
        current_basis, amounts = self._basis_from_snapshot(
            snapshot,
            request,
            intent_created_at=plan.basis.intent_created_at,
            authorization_expiry=plan.basis.authorization_expiry,
            royalty_settlement_id=plan.basis.royalty_settlement_id,
            royalty_settlement_nonce=plan.basis.royalty_settlement_nonce,
        )
        if (
            current_basis.commitment != plan.basis.commitment
            or dict(amounts) != dict(plan.royalty_owner_amounts)
        ):
            raise CollaborationExecutionServiceError(
                "execution plan authority is no longer current"
            )
        return snapshot

    def _basis_from_snapshot(
        self,
        snapshot: Mapping[str, Any],
        request: Mapping[str, Any],
        *,
        intent_created_at: int,
        authorization_expiry: int,
        royalty_settlement_id: str,
        royalty_settlement_nonce: int,
    ) -> tuple[CollaborationExecutionBasis, dict[str, int]]:
        owners = tuple(item["owner_address"] for item in snapshot["owners"])
        total = _strict_int(request["royalty_total"], "royalty total", minimum=1)
        amounts: dict[str, int] = {}
        running = 0
        for item in snapshot["owners"]:
            numerator = total * _strict_int(
                item["allocation_bps"],
                "owner allocation",
                minimum=1,
                maximum=10_000,
            )
            if numerator % 10_000:
                raise CollaborationExecutionServiceError(
                    "royalty total cannot be split exactly by current allocations"
                )
            amount = numerator // 10_000
            if amount <= 0:
                raise CollaborationExecutionServiceError(
                    "royalty allocation produced a zero owner payout"
                )
            amounts[item["owner_address"]] = amount
            running += amount
        if running != total:
            raise CollaborationExecutionServiceError(
                "royalty allocations do not reconstruct the exact total"
            )
        release_git_sha = str(
            getattr(
                self.settings,
                "collaboration_execution_release_git_sha",
                "",
            )
            or ""
        )
        release_verification = str(
            getattr(
                self.settings,
                "collaboration_execution_release_verification_sha256",
                "",
            )
            or ""
        )
        cvm_id = str(getattr(self.settings, "main_runtime_cvm_id", "") or "")
        if (
            not _GIT_SHA.fullmatch(release_git_sha)
            or not _SHA256.fullmatch(release_verification)
            or not _CVM_ID.fullmatch(cvm_id)
        ):
            raise CollaborationExecutionServiceUnavailable(
                "Collaboration execution release authority is incomplete"
            )
        fields = dict(request)
        fields.pop("authorization_lifetime_seconds", None)
        release_binding = royalty_release_binding_from_settings(self.settings)
        release_binding_commitment = royalty_release_binding_commitment(
            release_binding
        )
        reservation_safety_seconds = _strict_int(
            getattr(
                self.settings,
                "collaboration_execution_royalty_reservation_safety_seconds",
                900,
            ),
            "Royalty reservation safety window",
            minimum=60,
            maximum=3_600,
        )
        return (
            CollaborationExecutionBasis.create_with_royalty_owner_amounts(
                royalty_owner_amounts=amounts,
                release_git_sha=release_git_sha,
                release_verification_sha256=release_verification,
                chain_id=BASE_SEPOLIA_CHAIN_ID,
                cvm_id=cvm_id,
                compose_hash=str(
                    getattr(self.settings, "compute_vault_compose_hash", "")
                    or ""
                ),
                room_id=snapshot["room_id"],
                room_commitment=snapshot["room_commitment"],
                room_generation=snapshot["room_generation"],
                room_state_commitment=snapshot["room_state_commitment"],
                query_ref=snapshot["query_ref"],
                query_proposal_commitment=snapshot[
                    "query_proposal_commitment"
                ],
                prospective_query_grant_set_commitment=snapshot[
                    "prospective_query_grant_set_commitment"
                ],
                joint_consent_snapshot_commitment=snapshot[
                    "joint_consent_snapshot_commitment"
                ],
                allocation_commitment=snapshot["allocation_commitment"],
                owner_addresses=owners,
                compute_vault_address=str(
                    getattr(self.settings, "compute_vault_address", "") or ""
                ),
                compute_vault_runtime_code_hash=str(
                    getattr(
                        self.settings,
                        "compute_vault_runtime_code_hash",
                        "",
                    )
                    or ""
                ),
                compute_finality_model="single_rpc_reported_finalized",
                royalty_asset=fields["asset"],
                royalty_distributor_address=(
                    release_binding.distributor_address
                ),
                royalty_release_policy_commitment=(
                    release_binding.release_policy_commitment
                ),
                royalty_release_binding_commitment=(
                    release_binding_commitment
                ),
                royalty_settlement_id=royalty_settlement_id,
                royalty_settlement_nonce=royalty_settlement_nonce,
                royalty_reservation_safety_seconds=(
                    reservation_safety_seconds
                ),
                intent_created_at=intent_created_at,
                authorization_expiry=authorization_expiry,
                **fields,
            ),
            amounts,
        )

    def _validate_plan_request(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(request, Mapping) or set(request) != self._PLAN_REQUEST_FIELDS:
            raise CollaborationExecutionServiceError(
                "execution plan fields are invalid"
            )
        normalized = copy.deepcopy(dict(request))
        normalized["compute_user_address"] = normalize_wallet_address(
            normalized["compute_user_address"]
        )
        normalized["sponsor_address"] = normalize_wallet_address(
            normalized["sponsor_address"]
        )
        lifetime = _strict_int(
            normalized["authorization_lifetime_seconds"],
            "authorization lifetime",
            minimum=60,
            maximum=MAX_AUTHORIZATION_SECONDS,
        )
        normalized["authorization_lifetime_seconds"] = lifetime
        return normalized

    def _decode_plan(self, token: str) -> ExecutionPlan:
        body = self._decode_token(token, domain=_PLAN_TOKEN_DOMAIN)
        if set(body) != {
            "schema",
            "run_id",
            "requester_address",
            "basis",
            "royalty_owner_amounts",
        } or body["schema"] != PLAN_SCHEMA:
            raise CollaborationExecutionServiceError("execution plan token is invalid")
        basis = CollaborationExecutionBasis.from_dict(body["basis"])
        amounts = body["royalty_owner_amounts"]
        if not isinstance(amounts, Mapping):
            raise CollaborationExecutionServiceError("execution plan royalty split is invalid")
        normalized_amounts = {
            normalize_wallet_address(owner): _strict_int(
                amount,
                "royalty owner amount",
                minimum=1,
            )
            for owner, amount in amounts.items()
        }
        # The safe constructor is the exclusive factory even when decoding a
        # server-authenticated plan token.
        safe_basis_fields = {
            key: value
            for key, value in basis.to_dict().items()
            if key not in {"schema", "royalty_owner_amounts_hash"}
        }
        # The public/token basis uses a canonical decimal string so a full
        # uint256 cannot be rounded by JSON/JavaScript.  The in-process
        # constructor keeps its arithmetic representation as Python int.
        safe_basis_fields["royalty_settlement_nonce"] = (
            basis.royalty_settlement_nonce
        )
        safe_basis = CollaborationExecutionBasis.create_with_royalty_owner_amounts(
            royalty_owner_amounts=normalized_amounts,
            **safe_basis_fields,
        )
        if safe_basis.commitment != basis.commitment:
            raise CollaborationExecutionServiceError("execution plan royalty split changed")
        return ExecutionPlan(
            basis=basis,
            requester_address=normalize_wallet_address(body["requester_address"]),
            run_id=str(body["run_id"]),
            royalty_owner_amounts=normalized_amounts,
            plan_token=token,
        )

    def _owner_record(
        self,
        plan: ExecutionPlan,
        owner: str,
        snapshot: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        current = snapshot or self.store.execution_authority_snapshot(
            plan.run_id,
            plan.requester_address,
        )
        matches = [item for item in current["owners"] if item["owner_address"] == owner]
        if len(matches) != 1 or owner not in plan.basis.owner_addresses:
            raise CollaborationExecutionServiceError(
                "wallet is not an owner of this execution plan"
            )
        return matches[0]

    def _plan_token_body(self, plan: ExecutionPlan) -> dict[str, Any]:
        return {
            "schema": PLAN_SCHEMA,
            "run_id": plan.run_id,
            "requester_address": plan.requester_address,
            "basis": plan.basis.to_dict(),
            "royalty_owner_amounts": dict(plan.royalty_owner_amounts),
        }

    def _encode_token(self, body: Mapping[str, Any], *, domain: bytes) -> str:
        encoded = _b64url(_canonical_json(body))
        mac = hmac.new(
            self._token_key,
            domain + encoded.encode("ascii"),
            hashlib.sha256,
        ).digest()
        return encoded + "." + _b64url(mac)

    def _decode_token(self, token: str, *, domain: bytes) -> dict[str, Any]:
        if not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES * 2:
            raise CollaborationExecutionServiceError("execution authority token is invalid")
        parts = token.split(".")
        if len(parts) != 2 or any(not _TOKEN_PART.fullmatch(part) for part in parts):
            raise CollaborationExecutionServiceError("execution authority token is invalid")
        expected = hmac.new(
            self._token_key,
            domain + parts[0].encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(_b64url_decode(parts[1]), expected):
            raise CollaborationExecutionServiceError("execution authority token is invalid")
        raw = _b64url_decode(parts[0])
        if len(raw) > MAX_TOKEN_BYTES:
            raise CollaborationExecutionServiceError("execution authority token is too large")
        try:
            value = json.loads(raw, object_pairs_hook=_unique_object)
        except Exception as exc:
            raise CollaborationExecutionServiceError("execution authority token is invalid") from exc
        if not isinstance(value, dict):
            raise CollaborationExecutionServiceError("execution authority token is invalid")
        return value

    def _now(self, value: int | None) -> int:
        timestamp = int(self.clock()) if value is None else value
        return _strict_int(timestamp, "execution time", minimum=1, maximum=4_102_444_800)


class FinalizedComputeVaultReader:
    """Read one EIP-1898-pinned job at the RPC's current finalized head."""

    def __init__(
        self,
        *,
        rpc_url: str,
        vault_address: str,
        runtime_code_hash: str,
        receipt_key: bytes,
        max_block_age_seconds: int,
        max_future_block_skew_seconds: int,
        timeout_seconds: float = 5.0,
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
        if len(receipt_key) < 32:
            raise CollaborationExecutionServiceUnavailable(
                "finalized read receipt key is too short"
            )
        self.receipt_key = bytes(receipt_key)
        self.max_block_age_seconds = _strict_int(
            max_block_age_seconds,
            "maximum finalized block age",
            minimum=1,
            maximum=3_600,
        )
        self.max_future_block_skew_seconds = _strict_int(
            max_future_block_skew_seconds,
            "maximum finalized future skew",
            minimum=0,
            maximum=300,
        )
        if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0 or timeout_seconds > 20:
            raise CollaborationExecutionServiceUnavailable("finalized RPC timeout is invalid")
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(float(timeout_seconds)),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None
        self._next_id = 1

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def observe(
        self,
        intent: CollaborationExecutionIntent,
        *,
        observed_at: int,
    ) -> FinalizedObservationReceipt:
        now = _strict_int(observed_at, "vault observation time", minimum=1)
        if intent.compute_vault_address != self.vault_address or intent.compute_vault_runtime_code_hash != self.runtime_code_hash:
            raise CollaborationExecutionAuthorityInvalidated(
                "current vault release differs from the execution intent"
            )
        if intent.sponsor_address != intent.compute_user_address:
            raise CollaborationExecutionAuthorityInvalidated(
                "execution sponsor is not the on-chain Compute funding wallet"
            )
        chain_id = _quantity(self._rpc("eth_chainId", []), "chain ID")
        if chain_id != BASE_SEPOLIA_CHAIN_ID:
            raise CollaborationExecutionAuthorityInvalidated(
                "Compute vault is not on Base Sepolia"
            )
        raw_block = self._rpc("eth_getBlockByNumber", ["finalized", False])
        if not isinstance(raw_block, Mapping):
            raise CollaborationExecutionAuthorityUnavailable(
                "Base Sepolia finalized head is unavailable"
            )
        block_number = _quantity(raw_block.get("number"), "finalized block number")
        block_timestamp = _quantity(raw_block.get("timestamp"), "finalized block timestamp")
        block_hash = _bytes32(raw_block.get("hash"), allow_zero=False)
        if (
            block_timestamp < now - self.max_block_age_seconds
            or block_timestamp > now + self.max_future_block_skew_seconds
        ):
            raise CollaborationExecutionAuthorityUnavailable(
                "Base Sepolia finalized head is outside the freshness window"
            )
        tag = {"blockHash": block_hash, "requireCanonical": True}
        code = _hex_bytes(
            self._rpc("eth_getCode", [self.vault_address, tag]),
            label="vault bytecode",
            maximum=MAX_RUNTIME_CODE_BYTES,
        )
        if not code or "0x" + keccak(code).hex() != self.runtime_code_hash:
            raise CollaborationExecutionAuthorityInvalidated(
                "Compute vault runtime hash mismatch"
            )
        data = "0x" + (_GET_JOB + _bytes32_word(intent.compute_job_id)).hex()
        raw_job = self._rpc(
            "eth_call",
            [{"to": self.vault_address, "data": data}, tag],
        )
        job_words = _decode_words(
            _hex_bytes(raw_job, label="vault job", maximum=21 * 32),
            21,
            "vault job",
        )
        state_value = _word_uint(job_words[20])
        states = {
            1: "authorized",
            2: "started",
            3: "settled",
            4: "canceled",
            5: "expired",
        }
        if state_value not in states:
            raise CollaborationExecutionAuthorityInvalidated(
                "Compute vault job state is invalid"
            )
        source_payload = {
            "chain_id": chain_id,
            "vault_address": self.vault_address,
            "vault_runtime_code_hash": self.runtime_code_hash,
            "finalized_block_number": block_number,
            "finalized_block_hash": block_hash,
            "finalized_block_timestamp": block_timestamp,
            "job_id": intent.compute_job_id,
            "job_words_sha256": _sha256_commitment(b"".join(job_words)),
            "rpc_method": "eth_getBlockByNumber(finalized)+EIP-1898",
        }
        source_commitment = _sha256_commitment(_canonical_json(source_payload))
        receipt = "sha256:" + hmac.new(
            self.receipt_key,
            _FINALIZED_RECEIPT_DOMAIN + _canonical_json(source_payload),
            hashlib.sha256,
        ).hexdigest()
        observation = FinalizedComputeVaultObservation.create(
            chain_id=chain_id,
            vault_address=self.vault_address,
            vault_runtime_code_hash=self.runtime_code_hash,
            block_number=block_number,
            block_hash=block_hash,
            block_timestamp=block_timestamp,
            source_record_commitment=source_commitment,
            source_authentication_receipt=receipt,
            finality_model="single_rpc_reported_finalized",
            reported_finalized=True,
            job_state=states[state_value],
            compute_project_id=_word_bytes32(job_words[0]),
            compute_job_id=intent.compute_job_id,
            sponsor_address=intent.compute_user_address,
            compute_user_address=_word_address(job_words[1], allow_zero=False),
            asset=_word_address(job_words[2], allow_zero=True),
            authorization_nonce=_word_uint(job_words[3]),
            max_compute_asset_debit=_word_uint(job_words[4]),
            authorization_expiry=_word_uint(job_words[6]),
            compute_workload_commitment=_word_bytes32(job_words[11]),
            compute_manifest_commitment=_word_bytes32(job_words[12]),
            compute_dispatch_intent_commitment=_word_bytes32(job_words[13]),
            observed_at=now,
        )
        return FinalizedObservationReceipt(
            observation=observation,
            block_timestamp=block_timestamp,
            source_record_commitment=source_commitment,
            authentication_receipt=receipt,
        )

    def _rpc(self, method: str, params: list[Any]) -> Any:
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
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            if len(response.content) > MAX_RPC_RESPONSE_BYTES:
                raise CollaborationExecutionAuthorityUnavailable(
                    "Base Sepolia RPC response exceeds bounds"
                )
            payload = response.json()
        except CollaborationExecutionAuthorityUnavailable:
            raise
        except Exception as exc:
            raise CollaborationExecutionAuthorityUnavailable(
                "Base Sepolia finalized read is unavailable"
            ) from exc
        if (
            not isinstance(payload, Mapping)
            or payload.get("jsonrpc") != "2.0"
            or payload.get("id") != request_id
            or set(payload) not in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"})
            or "error" in payload
        ):
            raise CollaborationExecutionAuthorityUnavailable(
                "Base Sepolia RPC returned an invalid response"
            )
        return payload["result"]


class FinalizedRoyaltyAuthorityReader:
    """Validate the reviewed royalty release and funding at the Compute head."""

    def __init__(
        self,
        rpc_reader: FinalizedComputeVaultReader,
        *,
        receipt_key: bytes,
    ) -> None:
        if not isinstance(rpc_reader, FinalizedComputeVaultReader) or len(receipt_key) < 32:
            raise CollaborationExecutionServiceUnavailable(
                "Royalty current-state reader is unavailable"
            )
        self.rpc_reader = rpc_reader
        self.receipt_key = bytes(receipt_key)

    def observe(
        self,
        binding: RoyaltySettlementReleaseBinding,
        intent: CollaborationExecutionIntent,
        grants: Sequence[OwnerExecutionGrant],
        *,
        finalized: FinalizedObservationReceipt,
        observed_at: int,
        require_current_grants: bool = True,
    ) -> FinalizedRoyaltyAuthorityObservation:
        now = _strict_int(observed_at, "Royalty observation time", minimum=1)
        if finalized.observation.observed_at != now:
            raise CollaborationExecutionAuthorityUnavailable(
                "Royalty and Compute observations are not from one claim"
            )
        release_commitment = royalty_release_binding_commitment(binding)
        if (
            release_commitment != intent.royalty_release_binding_commitment
            or binding.distributor_address
            != intent.royalty_distributor_address
            or binding.release_policy_commitment
            != intent.royalty_release_policy_commitment
        ):
            raise CollaborationExecutionAuthorityInvalidated(
                "Royalty release binding differs from the owner-approved intent"
            )
        grant_set = (
            execution_grant_set_commitment(
                intent.to_basis(),
                grants,
                now=now,
            )
            if require_current_grants
            else _execution_grant_set_for_settlement(intent, grants)
        )
        expected_reservation = RoyaltyFundingReservation.derive(
            intent,
            execution_grant_set_commitment=grant_set,
        )
        tag = {
            "blockHash": finalized.observation.block_hash,
            "requireCanonical": True,
        }
        distributor = binding.distributor_address
        code = self._code(distributor, tag)
        if not code or "0x" + keccak(code).hex() != binding.distributor_runtime_code_hash:
            raise CollaborationExecutionAuthorityInvalidated(
                "RoyaltyDistributor runtime hash mismatch"
            )
        paused = self._bool(distributor, _ROYALTY_PAUSED, tag)
        owner = self._address(distributor, _ROYALTY_OWNER, tag)
        pending_owner = self._address(
            distributor,
            _ROYALTY_PENDING_OWNER,
            tag,
            allow_zero=True,
        )
        settlement = self._address(distributor, _ROYALTY_SETTLEMENT_VERIFIER, tag)
        qvl = self._address(distributor, _ROYALTY_QVL_VERIFIER, tag)
        anchor = self._address(distributor, _ROYALTY_ANCHOR, tag)
        anchor_release = self._bytes32(distributor, _ROYALTY_ANCHOR_RELEASE, tag)
        release_policy = self._bytes32(distributor, _ROYALTY_RELEASE_POLICY, tag)
        authority_nonce = self._uint(distributor, _ROYALTY_AUTHORITY_NONCE, tag)
        pending_values = {
            "settlement": self._address(
                distributor, _ROYALTY_PENDING_SETTLEMENT, tag, allow_zero=True
            ),
            "qvl": self._address(
                distributor, _ROYALTY_PENDING_QVL, tag, allow_zero=True
            ),
            "anchor": self._address(
                distributor, _ROYALTY_PENDING_ANCHOR, tag, allow_zero=True
            ),
            "anchor_release": self._bytes32(
                distributor, _ROYALTY_PENDING_ANCHOR_RELEASE, tag
            ),
            "release_policy": self._bytes32(
                distributor, _ROYALTY_PENDING_RELEASE, tag
            ),
            "nonce": self._uint(distributor, _ROYALTY_PENDING_NONCE, tag),
            "activates_at": self._uint(
                distributor, _ROYALTY_PENDING_ACTIVATES, tag
            ),
            "revocation": self._bool(
                distributor, _ROYALTY_PENDING_REVOCATION, tag
            ),
        }
        pending_empty = (
            pending_values["settlement"] == "0x" + "0" * 40
            and pending_values["qvl"] == "0x" + "0" * 40
            and pending_values["anchor"] == "0x" + "0" * 40
            and pending_values["anchor_release"] == "0x" + "0" * 64
            and pending_values["release_policy"] == "0x" + "0" * 64
            and pending_values["nonce"] == 0
            and pending_values["activates_at"] == 0
            and pending_values["revocation"] is False
        )
        if (
            owner != binding.owner_address
            or settlement != binding.settlement_verifier_address
            or qvl != binding.royalty_qvl_verifier_address
            or anchor != binding.execution_policy_anchor_address
            or anchor_release != binding.anchor_writer_release_commitment
            or release_policy != binding.release_policy_commitment
            or authority_nonce != binding.authority_nonce
        ):
            raise CollaborationExecutionAuthorityInvalidated(
                "RoyaltyDistributor active release drifted"
            )
        anchor_writer = self._address(anchor, _ANCHOR_WRITER, tag)
        anchor_writer_release = self._bytes32(anchor, _ANCHOR_WRITER_RELEASE, tag)
        anchor_frozen = self._bool(anchor, _ANCHOR_ROTATIONS_FROZEN, tag)
        anchor_paused = self._bool(anchor, _ANCHOR_PAUSED, tag)
        if anchor_writer_release != binding.anchor_writer_release_commitment:
            raise CollaborationExecutionAuthorityInvalidated(
                "Royalty anchor-writer release drifted"
            )
        reservation = self._reservation(
            distributor,
            expected_reservation.reservation_id,
            tag,
        )
        execution_intent_commitment = (
            "sha256:"
            + reservation["execution_intent_commitment"][2:]
        )
        source_payload = {
            "schema": "dnai.collaboration.royalty-current-state-source.v2",
            "chain_id": binding.chain_id,
            "block_number": finalized.observation.block_number,
            "block_hash": finalized.observation.block_hash,
            "block_timestamp": finalized.block_timestamp,
            "distributor": distributor,
            "runtime_code_hash": binding.distributor_runtime_code_hash,
            "owner": owner,
            "pending_owner": pending_owner,
            "release_binding_commitment": release_commitment,
            "release_policy_commitment": release_policy,
            "authority_nonce": authority_nonce,
            "settlement_verifier": settlement,
            "qvl_verifier": qvl,
            "execution_policy_anchor": anchor,
            "anchor_writer": anchor_writer,
            "anchor_writer_release_commitment": anchor_writer_release,
            "distributor_paused": paused,
            "pending_authority": pending_values,
            "anchor_paused": anchor_paused,
            "anchor_writer_rotations_frozen": anchor_frozen,
            "reservation_getter": (
                "collaborationFundingReservation(bytes32)"
            ),
            "reservation": {
                **reservation,
                "reservation_id": expected_reservation.reservation_id,
                "execution_intent_commitment": (
                    execution_intent_commitment
                ),
            },
            "derived_funding_request": expected_reservation.to_dict(),
            "balance_or_allowance_used_as_authority": False,
        }
        source_commitment = _sha256_commitment(_canonical_json(source_payload))
        receipt = "sha256:" + hmac.new(
            self.receipt_key,
            _ROYALTY_RECEIPT_DOMAIN + _canonical_json(source_payload),
            hashlib.sha256,
        ).hexdigest()
        observation = FinalizedRoyaltyAuthorityObservation.create(
            chain_id=binding.chain_id,
            block_number=finalized.observation.block_number,
            block_hash=finalized.observation.block_hash,
            block_timestamp=finalized.block_timestamp,
            distributor_address=distributor,
            distributor_runtime_code_hash=binding.distributor_runtime_code_hash,
            owner_address=owner,
            pending_owner_address=pending_owner,
            release_binding_commitment=release_commitment,
            release_policy_commitment=release_policy,
            authority_nonce=authority_nonce,
            settlement_verifier_address=settlement,
            qvl_verifier_address=qvl,
            execution_policy_anchor_address=anchor,
            anchor_writer_address=anchor_writer,
            anchor_writer_release_commitment=anchor_writer_release,
            distributor_paused=paused,
            pending_authority_empty=pending_empty,
            anchor_paused=anchor_paused,
            anchor_writer_rotations_frozen=anchor_frozen,
            reservation_id=expected_reservation.reservation_id,
            reservation_active=reservation["active"],
            reservation_consumed=reservation["consumed"],
            reservation_sponsor_address=reservation["sponsor"],
            reservation_asset=reservation["asset"],
            reservation_total=reservation["total"],
            reservation_owner_amounts_hash=reservation[
                "owner_amounts_hash"
            ],
            reservation_release_policy_commitment=reservation[
                "release_policy_commitment"
            ],
            reservation_execution_intent_commitment=(
                execution_intent_commitment
            ),
            reservation_refund_after=reservation["refund_after"],
            reservation_deposited_amount=reservation["deposited_amount"],
            source_record_commitment=source_commitment,
            source_authentication_receipt=receipt,
            observed_at=now,
        )
        observation.validate_for(
            intent,
            expected_reservation,
            claimed_at=now,
        )
        return observation

    def settlement_precondition(
        self,
        binding: RoyaltySettlementReleaseBinding,
        intent: CollaborationExecutionIntent,
        grants: Sequence[OwnerExecutionGrant],
        *,
        finalized: FinalizedObservationReceipt,
        observed_at: int,
    ) -> dict[str, Any]:
        """Prove the reservation and both replay markers are unused."""

        observation = self.observe(
            binding,
            intent,
            grants,
            finalized=finalized,
            observed_at=observed_at,
            require_current_grants=False,
        )
        tag = {
            "blockHash": finalized.observation.block_hash,
            "requireCanonical": True,
        }
        state = self._settlement_state(
            binding.distributor_address,
            observation.reservation_id,
            tag,
        )
        self._validate_settlement_state(intent, state)
        if (
            state["consumed"]
            or state["settlement_processed"]
            or state["nonce_processed"]
        ):
            raise CollaborationExecutionAuthorityInvalidated(
                "Royalty settlement authority was already consumed"
            )
        return {
            "royalty_observation": observation,
            "settlement_state": state,
        }

    def reconcile_settlement(
        self,
        intent: CollaborationExecutionIntent,
        grants: Sequence[OwnerExecutionGrant],
        historical_observation: FinalizedRoyaltyAuthorityObservation,
        *,
        observed_at: int,
    ) -> dict[str, Any]:
        """Read exact post-settlement state at one fresh finalized head."""

        now = _strict_int(
            observed_at,
            "Royalty settlement reconciliation time",
            minimum=1,
        )
        finalized = self.rpc_reader.observe(intent, observed_at=now)
        vault = finalized.observation
        if (
            vault.job_state != "settled"
            or vault.chain_id != intent.chain_id
            or vault.vault_address != intent.compute_vault_address
            or vault.vault_runtime_code_hash
            != intent.compute_vault_runtime_code_hash
            or vault.compute_project_id != intent.compute_project_id
            or vault.compute_job_id != intent.compute_job_id
            or vault.sponsor_address != intent.sponsor_address
            or vault.compute_user_address != intent.compute_user_address
            or vault.asset != intent.asset
            or vault.authorization_nonce != intent.authorization_nonce
            or vault.max_compute_asset_debit
            != intent.max_compute_asset_debit
            or vault.authorization_expiry != intent.authorization_expiry
            or vault.compute_workload_commitment
            != intent.compute_workload_commitment
            or vault.compute_manifest_commitment
            != intent.compute_manifest_commitment
            or vault.compute_dispatch_intent_commitment
            != intent.compute_dispatch_intent_commitment
        ):
            raise CollaborationExecutionAuthorityInvalidated(
                "finalized Compute result differs from the settlement execution"
            )
        if (
            not isinstance(
                historical_observation,
                FinalizedRoyaltyAuthorityObservation,
            )
            or historical_observation.chain_id != intent.chain_id
            or historical_observation.distributor_address
            != intent.royalty_distributor_address
            or historical_observation.release_binding_commitment
            != intent.royalty_release_binding_commitment
            or historical_observation.release_policy_commitment
            != intent.royalty_release_policy_commitment
        ):
            raise CollaborationExecutionAuthorityInvalidated(
                "persisted Royalty release evidence differs from the execution"
            )
        tag = {"blockHash": vault.block_hash, "requireCanonical": True}
        distributor = intent.royalty_distributor_address
        code = self._code(distributor, tag)
        if (
            not code
            or "0x" + keccak(code).hex()
            != historical_observation.distributor_runtime_code_hash
        ):
            raise CollaborationExecutionAuthorityInvalidated(
                "RoyaltyDistributor runtime hash mismatch"
            )
        grant_set = _execution_grant_set_for_settlement(intent, grants)
        expected = RoyaltyFundingReservation.derive(
            intent,
            execution_grant_set_commitment=grant_set,
        )
        historical_observation.validate_for(
            intent,
            expected,
            claimed_at=historical_observation.observed_at,
        )
        reservation = self._reservation(
            distributor,
            expected.reservation_id,
            tag,
        )
        state = self._settlement_state(
            distributor,
            expected.reservation_id,
            tag,
        )
        storage_state = self._reservation_storage_state(
            distributor,
            expected.reservation_id,
            tag,
        )
        self._validate_settlement_state(intent, state)
        exact_reservation = (
            reservation["sponsor"] == expected.sponsor_address
            and reservation["asset"] == expected.asset
            and reservation["total"] == expected.total
            and reservation["owner_amounts_hash"]
            == expected.owners_amounts_hash
            and reservation["release_policy_commitment"]
            == expected.release_policy_commitment
            and "sha256:" + reservation["execution_intent_commitment"][2:]
            == intent.commitment
            and reservation["refund_after"] == expected.refund_after
        )
        pending = (
            exact_reservation
            and reservation["active"]
            and not reservation["consumed"]
            and reservation["deposited_amount"] == expected.total
            and not state["consumed"]
            and not state["settlement_processed"]
            and not state["nonce_processed"]
        )
        settled = (
            exact_reservation
            and not reservation["active"]
            and reservation["consumed"]
            and reservation["deposited_amount"] == 0
            and state["consumed"]
            and state["settlement_processed"]
            and state["nonce_processed"]
        )
        expired_unconsumed = (
            exact_reservation
            and not reservation["active"]
            and not reservation["consumed"]
            and reservation["deposited_amount"] == expected.total
            and finalized.block_timestamp >= expected.refund_after
            and not state["consumed"]
            and not state["settlement_processed"]
            and not state["nonce_processed"]
        )
        refunded = (
            exact_reservation
            and not reservation["active"]
            and not reservation["consumed"]
            and reservation["deposited_amount"] == 0
            and finalized.block_timestamp >= expected.refund_after
            and not state["consumed"]
            and not state["settlement_processed"]
            and not state["nonce_processed"]
        )
        expected_storage_status = (
            2
            if settled
            else 3
            if refunded
            else 1
            if pending or expired_unconsumed
            else -1
        )
        storage_exact = (
            storage_state["intent_commitment"] == expected.reservation_id
            and storage_state["settlement_id"] == expected.settlement_id
            and storage_state["settlement_nonce"]
            == expected.settlement_nonce
            and storage_state["release_policy_commitment"]
            == expected.release_policy_commitment
            and storage_state["owner_amounts_hash"]
            == expected.owners_amounts_hash
            and storage_state["execution_commitment"]
            == expected.execution_commitment
            and storage_state["sponsor"] == expected.sponsor_address
            and storage_state["asset"] == expected.asset
            and storage_state["total"] == expected.total
            and storage_state["refund_after"] == expected.refund_after
            and storage_state["status"] == expected_storage_status
            and storage_state["active"] == pending
        )
        if (
            not (pending or expired_unconsumed or settled or refunded)
            or not storage_exact
        ):
            raise CollaborationExecutionAuthorityInvalidated(
                "finalized chain state does not prove exact Royalty settlement"
            )
        source_payload = {
            "schema": "dnai.collaboration.royalty-finalized-settlement-source.v1",
            "chain_id": intent.chain_id,
            "block_number": vault.block_number,
            "block_hash": vault.block_hash,
            "block_timestamp": finalized.block_timestamp,
            "distributor": distributor,
            "historical_release_binding_commitment": (
                historical_observation.release_binding_commitment
            ),
            "historical_distributor_runtime_code_hash": (
                historical_observation.distributor_runtime_code_hash
            ),
            "historical_observation_commitment": (
                historical_observation.commitment
            ),
            "reservation_id": expected.reservation_id,
            "reservation": reservation,
            "reservation_storage_state": storage_state,
            "settlement_state": state,
        }
        source_commitment = _sha256_commitment(
            _ROYALTY_SETTLEMENT_RECEIPT_DOMAIN
            + _canonical_json(source_payload)
        )
        finalized_settlement = (
            {
                "chain_id": intent.chain_id,
                "block_number": vault.block_number,
                "block_hash": vault.block_hash,
                "block_timestamp": finalized.block_timestamp,
                "reservation_active": reservation["active"],
                "reservation_consumed": reservation["consumed"],
                "settlement_processed": state["settlement_processed"],
                "settlement_nonce_processed": state["nonce_processed"],
                "source_commitment": source_commitment,
            }
            if settled
            else None
        )
        terminal_evidence = (
            {
                "outcome": (
                    "reservation_refunded"
                    if refunded
                    else "reservation_expired"
                ),
                "chain_id": intent.chain_id,
                "block_number": vault.block_number,
                "block_hash": vault.block_hash,
                "block_timestamp": finalized.block_timestamp,
                "funding_reservation_id": expected.reservation_id,
                "reservation_storage_status": (
                    "refunded" if refunded else "active"
                ),
                "reservation_active": reservation["active"],
                "reservation_consumed": reservation["consumed"],
                "reservation_deposited_amount": reservation[
                    "deposited_amount"
                ],
                "settlement_processed": state["settlement_processed"],
                "settlement_nonce_processed": state["nonce_processed"],
                "source_commitment": source_commitment,
            }
            if refunded or expired_unconsumed
            else None
        )
        return {
            "state": (
                "settled"
                if settled
                else "refunded"
                if refunded
                else "expired_unconsumed"
                if expired_unconsumed
                else "pending"
            ),
            "block_timestamp": finalized.block_timestamp,
            "source_commitment": source_commitment,
            "finalized_settlement": finalized_settlement,
            "terminal_evidence": terminal_evidence,
        }

    @staticmethod
    def _validate_settlement_state(
        intent: CollaborationExecutionIntent,
        state: Mapping[str, Any],
    ) -> None:
        if (
            state["settlement_id"] != intent.royalty_settlement_id
            or state["settlement_nonce"]
            != intent.royalty_settlement_nonce
            or state["asset"] != intent.royalty_asset
            or state["total"] != intent.royalty_total
            or state["owner_amounts_hash"]
            != intent.royalty_owner_amounts_hash
        ):
            raise CollaborationExecutionAuthorityInvalidated(
                "Royalty settlement replay state differs from the execution"
            )

    def _call(self, address: str, selector: bytes, tag: Mapping[str, Any]) -> bytes:
        raw = self.rpc_reader._rpc(
            "eth_call",
            [{"to": address, "data": "0x" + selector.hex()}, tag],
        )
        return _hex_bytes(raw, label="Royalty authority result", maximum=32)

    def _code(self, address: str, tag: Mapping[str, Any]) -> bytes:
        return _hex_bytes(
            self.rpc_reader._rpc("eth_getCode", [address, tag]),
            label="Royalty authority bytecode",
            maximum=MAX_RUNTIME_CODE_BYTES,
        )

    def _address(
        self,
        address: str,
        selector: bytes,
        tag: Mapping[str, Any],
        *,
        allow_zero: bool = False,
    ) -> str:
        return _decode_address(
            self._call(address, selector, tag), allow_zero=allow_zero
        )

    def _bytes32(self, address: str, selector: bytes, tag: Mapping[str, Any]) -> str:
        return _decode_bytes32(self._call(address, selector, tag))

    def _uint(self, address: str, selector: bytes, tag: Mapping[str, Any]) -> int:
        return _decode_uint(self._call(address, selector, tag))

    def _bool(self, address: str, selector: bytes, tag: Mapping[str, Any]) -> bool:
        return _decode_bool(self._call(address, selector, tag))

    def _reservation(
        self,
        distributor: str,
        reservation_id: str,
        tag: Mapping[str, Any],
    ) -> dict[str, Any]:
        calldata = (
            _ROYALTY_COLLABORATION_RESERVATION
            + bytes.fromhex(reservation_id[2:])
        )
        raw = self.rpc_reader._rpc(
            "eth_call",
            [{"to": distributor, "data": "0x" + calldata.hex()}, tag],
        )
        encoded = _hex_bytes(
            raw,
            label="Royalty funding reservation result",
            maximum=10 * 32,
        )
        words = _decode_words(
            encoded,
            10,
            "Royalty funding reservation result",
        )
        return {
            "active": _word_bool(words[0]),
            "consumed": _word_bool(words[1]),
            "sponsor": _word_address(words[2], allow_zero=True),
            "asset": _word_address(words[3], allow_zero=True),
            "total": _word_uint(words[4]),
            "owner_amounts_hash": _word_bytes32(words[5]),
            "release_policy_commitment": _word_bytes32(words[6]),
            "execution_intent_commitment": _word_bytes32(words[7]),
            "refund_after": _word_uint(words[8]),
            "deposited_amount": _word_uint(words[9]),
        }

    def _reservation_storage_state(
        self,
        distributor: str,
        reservation_id: str,
        tag: Mapping[str, Any],
    ) -> dict[str, Any]:
        calldata = (
            _ROYALTY_FUNDING_RESERVATION_STATE
            + bytes.fromhex(reservation_id[2:])
        )
        raw = self.rpc_reader._rpc(
            "eth_call",
            [{"to": distributor, "data": "0x" + calldata.hex()}, tag],
        )
        words = _decode_words(
            _hex_bytes(
                raw,
                label="Royalty reservation storage state result",
                maximum=12 * 32,
            ),
            12,
            "Royalty reservation storage state result",
        )
        status = _word_uint(words[10])
        if status not in {0, 1, 2, 3}:
            raise CollaborationExecutionAuthorityInvalidated(
                "Royalty reservation storage status is invalid"
            )
        return {
            "intent_commitment": _word_bytes32(words[0]),
            "settlement_id": _word_bytes32(words[1]),
            "settlement_nonce": _word_uint(words[2]),
            "release_policy_commitment": _word_bytes32(words[3]),
            "owner_amounts_hash": _word_bytes32(words[4]),
            "execution_commitment": _word_bytes32(words[5]),
            "sponsor": _word_address(words[6], allow_zero=True),
            "asset": _word_address(words[7], allow_zero=True),
            "total": _word_uint(words[8]),
            "refund_after": _word_uint(words[9]),
            "status": status,
            "active": _word_bool(words[11]),
        }

    def _settlement_state(
        self,
        distributor: str,
        reservation_id: str,
        tag: Mapping[str, Any],
    ) -> dict[str, Any]:
        calldata = (
            _ROYALTY_FUNDING_SETTLEMENT_STATE
            + bytes.fromhex(reservation_id[2:])
        )
        raw = self.rpc_reader._rpc(
            "eth_call",
            [{"to": distributor, "data": "0x" + calldata.hex()}, tag],
        )
        words = _decode_words(
            _hex_bytes(
                raw,
                label="Royalty settlement state result",
                maximum=8 * 32,
            ),
            8,
            "Royalty settlement state result",
        )
        return {
            "consumed": _word_bool(words[0]),
            "settlement_processed": _word_bool(words[1]),
            "nonce_processed": _word_bool(words[2]),
            "settlement_id": _word_bytes32(words[3]),
            "settlement_nonce": _word_uint(words[4]),
            "asset": _word_address(words[5], allow_zero=True),
            "total": _word_uint(words[6]),
            "owner_amounts_hash": _word_bytes32(words[7]),
        }

class AuthenticatedComputeJournalReader:
    """Build projections only after authenticating the local Compute journal."""

    def __init__(
        self,
        journal: ComputeExecutionJournal,
        *,
        integrity_key: bytes,
    ) -> None:
        if not isinstance(journal, ComputeExecutionJournal) or len(integrity_key) < 32:
            raise CollaborationExecutionServiceUnavailable(
                "authenticated Compute journal reader is unavailable"
            )
        if not hmac.compare_digest(journal._integrity_key, integrity_key):
            raise CollaborationExecutionServiceUnavailable(
                "Compute journal reader key does not match the journal"
            )
        self.journal = journal
        self.integrity_key = bytes(integrity_key)

    def read(
        self,
        handoff: ComputeHandoff,
        *,
        observed_at: int,
    ) -> AuthenticatedComputeProjection:
        now = _strict_int(observed_at, "Compute projection time", minimum=1)
        with self.journal._exclusive_lock():
            body = self.journal._load_unlocked()
            record = body["records"].get(handoff.compute_job_id)
            if record is None:
                raise CollaborationExecutionAuthorityUnavailable(
                    "Compute journal handoff is not admitted"
                )
            parsed = self.journal._validate_record(record)
            root = json.loads(
                self.journal.path.read_bytes(),
                object_pairs_hook=_unique_object,
            )
            source_mac = root.get("mac") if isinstance(root, Mapping) else None
            if not isinstance(source_mac, str) or not re.fullmatch(r"[0-9a-f]{64}", source_mac):
                raise CollaborationExecutionServiceUnavailable(
                    "Compute journal authentication envelope is invalid"
                )
            sequence = body["sequence"]
        compute_intent = ComputeDispatchIntent.from_dict(parsed["intent"])
        if (
            compute_intent.commitment != handoff.compute_dispatch_intent_commitment
            or compute_intent.job_id != handoff.compute_job_id
            or compute_intent.authorization_kind != "collaboration_one_shot"
        ):
            raise CollaborationExecutionAuthorityInvalidated(
                "Compute journal record does not match the Collaboration handoff"
            )
        bounded_result = self._bounded_result(handoff, parsed)
        public = self.journal._public_record(parsed)
        source_record_payload = {
            "source_schema": body["schema"],
            "source_schema_version": body["schema_version"],
            "source_sequence": sequence,
            "job_id": handoff.compute_job_id,
            "record": parsed,
        }
        source_record_commitment = _sha256_commitment(
            _COMPUTE_RECORD_DOMAIN + _canonical_json(source_record_payload)
        )
        source_mac_commitment = _sha256_commitment(source_mac.encode("ascii"))
        receipt_payload = {
            "source_sequence": sequence,
            "source_record_commitment": source_record_commitment,
            "source_journal_mac_commitment": source_mac_commitment,
            "handoff_commitment": handoff.commitment,
            "observed_at": now,
        }
        receipt = "sha256:" + hmac.new(
            self.integrity_key,
            _COMPUTE_RECEIPT_DOMAIN + _canonical_json(receipt_payload),
            hashlib.sha256,
        ).hexdigest()
        projection = ComputeJournalProjection.create(
            handoff=handoff,
            source_sequence=sequence,
            source_record_commitment=source_record_commitment,
            source_journal_mac_commitment=source_mac_commitment,
            source_authentication_receipt=receipt,
            compute_stage=parsed["stage"],
            provider_dispatch_may_have_occurred=public[
                "provider_dispatch_may_have_occurred"
            ],
            automatic_provider_redispatch=False,
            bounded_result=bounded_result,
            observed_at=now,
        )
        return AuthenticatedComputeProjection(
            projection=projection,
            source_sequence=sequence,
            source_record_commitment=source_record_commitment,
            source_journal_mac_commitment=source_mac_commitment,
            authentication_receipt=receipt,
        )

    def _bounded_result(
        self,
        handoff: ComputeHandoff,
        record: Mapping[str, Any],
    ) -> BoundedExecutionResult | None:
        if record["stage"] != "settled":
            return None
        usage = ProviderUsage.from_dict(record["usage"])
        signed = SignedUsageEnvelope.from_dict(record["signed_usage"])
        metering = MeteringDecision.from_dict(record["metering_decision"])
        return BoundedExecutionResult.create(
            execution_id=handoff.execution_id,
            intent_commitment=handoff.intent_commitment,
            authorization_commitment=handoff.authorization_commitment,
            outcome=usage.outcome,
            result_class=(
                "completed_within_authorized_caps"
                if usage.outcome == "succeeded"
                else "provider_failed_without_raw_detail"
            ),
            result_policy=handoff.compute_dispatch_intent.result_policy,
            result_commitment=usage.result_commitment,
            usage_commitment=signed.usage_commitment,
            actual_compute_asset_debit=metering.actual_asset_debit,
            billable_compute_units=metering.billable_compute_units,
            score_band="not_released",
        )


class CollaborationExecutionWorkerService:
    """Claim, admit, and reconcile without ever invoking a provider."""

    def __init__(
        self,
        *,
        coordinator: CollaborationExecutionCoordinator,
        journal: CollaborationExecutionJournal,
        vault_reader: FinalizedComputeVaultReader,
        royalty_reader: FinalizedRoyaltyAuthorityReader,
        admission: ComputeDispatchAdmissionService,
        compute_reader: AuthenticatedComputeJournalReader,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.coordinator = coordinator
        self.journal = journal
        self.vault_reader = vault_reader
        self.royalty_reader = royalty_reader
        self.admission = admission
        self.compute_reader = compute_reader
        self.clock = clock or time.time
        self._last_vault_receipt: FinalizedObservationReceipt | None = None

    def run_once(self, *, now: int | None = None) -> dict[str, Any]:
        timestamp = int(self.clock()) if now is None else now
        timestamp = _strict_int(timestamp, "worker time", minimum=1)
        claimed = self.journal.claim_next(
            self._claim_validator,
            claimed_at=timestamp,
        )
        actions = self.journal.recover_incomplete(recovered_at=timestamp)
        results: list[dict[str, Any]] = []
        for action in actions:
            if action["state"] == ExecutionState.RECONCILIATION_HOLD.value:
                results.append(
                    {
                        "execution_id": action["execution_id"],
                        "action": "manual_reconciliation_hold",
                        "automatic_redispatch": False,
                    }
                )
                continue
            results.append(self._recover_action(action, now=timestamp))
        return {
            "surface": "collaboration_execution_worker_cycle",
            "schema_version": 1,
            "claimed_execution_id": (
                None
                if claimed is None
                else CollaborationExecutionIntent.from_dict(
                    claimed["intent"]
                ).execution_id
            ),
            "actions": results,
            "provider_call_performed_by_collaboration": False,
            "automatic_provider_redispatch": False,
            "client_supplied_vault_observation": False,
            "client_supplied_compute_projection": False,
        }

    def _claim_validator(
        self,
        intent: CollaborationExecutionIntent,
        grants: Sequence[OwnerExecutionGrant],
        claimed_at: int,
    ) -> ClaimAuthoritySnapshot:
        try:
            current_basis = self.coordinator.current_basis_for_intent(intent)
            current_intent = CollaborationExecutionIntent.finalize(
                current_basis,
                grants,
                now=claimed_at,
            )
            receipt = self.vault_reader.observe(intent, observed_at=claimed_at)
            self._last_vault_receipt = receipt
            royalty_observation = self.royalty_reader.observe(
                royalty_release_binding_from_settings(
                    self.coordinator.settings
                ),
                intent,
                grants,
                finalized=receipt,
                observed_at=claimed_at,
            )
            return ClaimAuthoritySnapshot.create(
                current_intent=current_intent,
                current_execution_grants=grants,
                finalized_vault_observation=receipt.observation,
                finalized_royalty_observation=royalty_observation,
                observed_at=claimed_at,
            )
        except CollaborationExecutionAuthorityInvalidated:
            raise
        except CollaborationExecutionAuthorityUnavailable:
            raise
        except CollaborationExecutionError as exc:
            raise CollaborationExecutionAuthorityInvalidated(str(exc)) from exc
        except Exception as exc:
            raise CollaborationExecutionAuthorityUnavailable(
                "current Collaboration execution authority is unavailable"
            ) from exc

    def _recover_action(self, action: Mapping[str, Any], *, now: int) -> dict[str, Any]:
        execution_id = action["execution_id"]
        if action["recovery_action"] == "prepare_compute_handoff":
            handoff_dict = self.journal.prepare_compute_handoff(
                execution_id,
                prepared_at=now,
            )
        else:
            handoff_dict = action["compute_handoff"]
        handoff = ComputeHandoff.from_dict(handoff_dict)
        admission_invoked = action["recovery_action"] in {
            "prepare_compute_handoff",
            "lookup_or_resubmit_exact_idempotent_compute_handoff",
        }
        if admission_invoked:
            self.admission.enqueue_collaboration_one_shot(
                handoff.compute_dispatch_intent,
                idempotency_key=handoff.handoff_id,
                created_at=now,
            )
        authenticated = self.compute_reader.read(handoff, observed_at=now)
        execution = self.journal.confirm_compute_handoff(
            execution_id,
            authenticated.projection,
            confirmed_at=now,
        )
        return {
            "execution_id": execution_id,
            "action": (
                "compute_admitted_and_reconciled"
                if admission_invoked
                else "compute_polled_and_reconciled"
            ),
            "compute_admission_invoked": admission_invoked,
            "execution_state": execution["state"],
            "source_evidence": authenticated.to_evidence_dict(),
            "provider_call_performed_by_collaboration": False,
            "automatic_provider_redispatch": False,
        }


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise CollaborationExecutionServiceError(
            "execution authority token is invalid"
        ) from exc


def _sha256_commitment(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _fresh_nonzero_bytes32() -> str:
    while True:
        value = "0x" + secrets.token_hex(32)
        if value != "0x" + "0" * 64:
            return value


def _fresh_nonzero_uint256() -> int:
    while True:
        value = secrets.randbits(256)
        if value != 0:
            return value


def _execution_grant_set_for_settlement(
    intent: CollaborationExecutionIntent,
    grants: Sequence[OwnerExecutionGrant],
) -> str:
    """Recompute the already-authorized grant set without renewing grants."""

    if not grants:
        raise CollaborationExecutionAuthorityInvalidated(
            "Royalty settlement execution grants are unavailable"
        )
    validation_time = max(grant.granted_at for grant in grants)
    if validation_time >= min(grant.expires_at for grant in grants):
        raise CollaborationExecutionAuthorityInvalidated(
            "Royalty settlement execution grants are inconsistent"
        )
    try:
        return execution_grant_set_commitment(
            intent.to_basis(),
            grants,
            now=validation_time,
        )
    except CollaborationExecutionError as exc:
        raise CollaborationExecutionAuthorityInvalidated(
            "Royalty settlement execution grants changed"
        ) from exc


def _signature_bytes(value: str) -> bytes:
    if not isinstance(value, str):
        raise CollaborationExecutionServiceError("wallet signature is invalid")
    normalized = value[2:] if value.startswith(("0x", "0X")) else value
    try:
        raw = bytes.fromhex(normalized)
    except ValueError as exc:
        raise CollaborationExecutionServiceError("wallet signature must be hex") from exc
    if len(raw) == 0 or len(raw) > 4_096:
        raise CollaborationExecutionServiceError("wallet signature is invalid")
    return raw


def _strict_int(
    value: Any,
    label: str,
    *,
    minimum: int,
    maximum: int = 2**256 - 1,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise CollaborationExecutionServiceError(f"{label} is invalid")
    return value
