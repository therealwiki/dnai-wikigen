"""Release-gated Human Review expiry and notification scheduler.

The worker has two deliberately narrow capabilities:

* call the delegate's runtime-authenticated, conservative expiry endpoint; and
* ask the internal email-oracle boundary to notify a role about one hash-only
  pending ticket.

It never receives the private reviewer roster, raw review reason, artifact
content, submitter identity, or a reviewer identity.  The email oracle owns
recipient resolution and durable idempotency receipts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import signal
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings

from tinker_delegate import dstack_utils


BASE_SEPOLIA_CHAIN_ID = 84_532
REVIEW_RELEASE_CONTEXT_SCHEMA = "dnai.review-release-context.v1"
REVIEW_NOTIFICATION_REQUEST_SCHEMA = "dnai.review-notification-request.v1"
REVIEW_NOTIFICATION_IDEMPOTENCY_DOMAIN = (
    b"dnai-wikigen/review-notification-idempotency/v1\0"
)
REVIEW_OPERATION_ROLES = frozenset(
    {
        "access-review-officer",
        "expert-in-the-loop",
        "biosecurity-review",
        "ethics-legal-reviewer",
    }
)
_SHA256_PREFIX = "sha256:"
_MAX_RESPONSE_BYTES = 1_048_576
_DELEGATE_RUNTIME_PREFIX = b"tinker-delegate-runtime-auth:"
_ORACLE_RUNTIME_PREFIX = b"email-oracle-runtime-auth:"
_PUBLIC_REVIEW_TICKET_FIELDS = frozenset(
    {
        "ticket_ref_hash",
        "turn_ref_hash",
        "corpus_ref_hash",
        "routed_role",
        "reason_hash",
        "opened_at",
        "expires_at",
        "status",
        "reviewer_ref_hash",
        "submitter_ref_hash",
        "required_approvals",
        "approvals_count",
        "approval_reviewer_hashes",
        "approval_authorization_hashes",
        "reviewer_authorization_hash",
        "authority_context_hash",
        "decision_hash",
        "updated_at",
        "raw_secret_egress",
    }
)
_NOTIFICATION_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "idempotency_key",
        "receipt_sha256",
        "status",
        "idempotent",
        "raw_review_reason_egress",
        "raw_artifact_egress",
        "raw_reviewer_identity_egress",
    }
)
_AMBIGUOUS_NOTIFICATION_RESPONSE = {
    "detail": "Review notification delivery is ambiguous; automatic retry is held"
}


class ReviewOperationsError(ValueError):
    """A response or configuration crossed the reviewed worker boundary."""


class ReviewOperationsRetryable(RuntimeError):
    """A safe, idempotent operation may be attempted on a later scheduler tick."""


@dataclass(frozen=True)
class ReviewReleaseBinding:
    main_runtime_cvm_id: str
    deployment_intent_sha256: str
    release_authority_sha256: str
    ceremony_nonce: str
    policy_sha256: str
    active_reviewers_sha256: str
    genesis_acceptance_sha256: str
    current_status_epoch: int
    current_status_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": BASE_SEPOLIA_CHAIN_ID,
            "wallet_domain": "www.wikigen.me",
            "wallet_uri": "https://www.wikigen.me",
            "main_runtime_cvm_id": self.main_runtime_cvm_id,
            "deployment_intent_sha256": self.deployment_intent_sha256,
            "release_authority_sha256": self.release_authority_sha256,
            "ceremony_nonce": self.ceremony_nonce,
            "policy_sha256": self.policy_sha256,
            "active_reviewers_sha256": self.active_reviewers_sha256,
            "genesis_acceptance_sha256": self.genesis_acceptance_sha256,
            "current_status_epoch": self.current_status_epoch,
            "current_status_sha256": self.current_status_sha256,
        }


class ReviewOperationsSettings(BaseSettings):
    """Purpose-separated scheduler configuration.

    Production never accepts bearer tokens from environment variables. Both
    service tokens are independently derived from their exact dstack key paths.
    """

    enabled: bool = False
    production_release: bool = False
    delegate_url: str = ""
    oracle_url: str = ""
    poll_interval_seconds: float = 60.0
    request_timeout_seconds: float = 10.0
    maximum_queue_pages: int = 8
    maximum_notifications_per_tick: int = 64
    notifications_enabled: bool = False

    runtime_auth_token: str = ""
    runtime_auth_key_path: str = "tinker/runtime-auth"
    oracle_auth_token: str = ""
    oracle_auth_key_path: str = "oracle/runtime-auth"

    main_runtime_cvm_id: str = ""
    deployment_intent_sha256: str = ""
    release_authority_sha256: str = ""
    ceremony_nonce: str = ""
    policy_sha256: str = ""
    active_reviewers_sha256: str = ""
    genesis_acceptance_sha256: str = ""
    current_status_epoch: int = 0
    current_status_sha256: str = ""

    @model_validator(mode="after")
    def validate_reviewed_configuration(self) -> "ReviewOperationsSettings":
        if not self.enabled:
            return self
        if not 15 <= self.poll_interval_seconds <= 300:
            raise ValueError("review operations poll interval must be 15-300 seconds")
        if not 1 <= self.request_timeout_seconds <= 30:
            raise ValueError("review operations request timeout must be 1-30 seconds")
        if not 1 <= self.maximum_queue_pages <= 32:
            raise ValueError("review operations queue page bound must be 1-32")
        if not 1 <= self.maximum_notifications_per_tick <= 256:
            raise ValueError("review operations notification bound must be 1-256")

        _require_http_service_url(self.delegate_url, "delegate URL")
        _require_http_service_url(self.oracle_url, "oracle URL")
        _require_release_identifier(self.main_runtime_cvm_id, "main runtime CVM ID")
        _require_sha256(self.deployment_intent_sha256, "deployment intent")
        _require_sha256(self.release_authority_sha256, "release authority")
        _require_bytes32(self.ceremony_nonce, "ceremony nonce")
        _require_sha256(self.policy_sha256, "review policy")
        _require_sha256(self.active_reviewers_sha256, "active reviewers")
        _require_sha256(self.genesis_acceptance_sha256, "reviewer genesis acceptance")
        _require_positive_int(self.current_status_epoch, "reviewer status epoch")
        _require_sha256(self.current_status_sha256, "reviewer current status")

        if self.production_release:
            if not dstack_utils.is_dstack_enabled():
                raise ValueError("production review operations require dstack")
            if self.delegate_url != "http://delegate:8080":
                raise ValueError("production review operations require the internal delegate URL")
            if self.oracle_url != "http://oracle:8000":
                raise ValueError("production review operations require the internal oracle URL")
            if self.runtime_auth_token or self.oracle_auth_token:
                raise ValueError("production review operations forbid static bearer tokens")
            if self.runtime_auth_key_path != "tinker/runtime-auth":
                raise ValueError("production review operations require the delegate runtime key path")
            if self.oracle_auth_key_path != "oracle/runtime-auth":
                raise ValueError("production review operations require the oracle runtime key path")
        elif not self.runtime_auth_token or (
            self.notifications_enabled and not self.oracle_auth_token
        ):
            raise ValueError(
                "local review operations require explicit purpose-separated bearer tokens"
            )
        return self

    def release_binding(self) -> ReviewReleaseBinding:
        return ReviewReleaseBinding(
            main_runtime_cvm_id=self.main_runtime_cvm_id,
            deployment_intent_sha256=self.deployment_intent_sha256,
            release_authority_sha256=self.release_authority_sha256,
            ceremony_nonce=self.ceremony_nonce,
            policy_sha256=self.policy_sha256,
            active_reviewers_sha256=self.active_reviewers_sha256,
            genesis_acceptance_sha256=self.genesis_acceptance_sha256,
            current_status_epoch=self.current_status_epoch,
            current_status_sha256=self.current_status_sha256,
        )

    model_config = {
        "env_prefix": "TINKER_REVIEW_OPERATIONS_",
        "hide_input_in_errors": True,
    }


class ReviewNotificationRequest(BaseModel):
    schema_value: str = Field(
        alias="schema",
        pattern=r"^dnai\.review-notification-request\.v1$",
    )
    event: str = Field(pattern=r"^pending$")
    ticket_ref_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    routed_role: str = Field(min_length=2, max_length=64)
    opened_at: int = Field(ge=1)
    expires_at: int = Field(ge=1)
    authority_context_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_binding: dict[str, Any]
    idempotency_key: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_bounded_request(self) -> "ReviewNotificationRequest":
        if self.routed_role not in REVIEW_OPERATION_ROLES:
            raise ValueError("review notification role is not supported")
        if self.expires_at <= self.opened_at:
            raise ValueError("review notification expiry must follow opening")
        expected = review_notification_idempotency_key(
            {
                "schema": self.schema_value,
                "event": self.event,
                "ticket_ref_hash": self.ticket_ref_hash,
                "routed_role": self.routed_role,
                "opened_at": self.opened_at,
                "expires_at": self.expires_at,
                "authority_context_hash": self.authority_context_hash,
                "release_binding": self.release_binding,
            }
        )
        if not hmac.compare_digest(self.idempotency_key, expected):
            raise ValueError("review notification idempotency key is invalid")
        return self

    model_config = {"extra": "forbid", "populate_by_name": True}


@dataclass(frozen=True)
class PendingReviewNotification:
    ticket_ref_hash: str
    routed_role: str
    opened_at: int
    expires_at: int
    authority_context_hash: str


@dataclass(frozen=True)
class ReviewOperationsTick:
    expired_sweep_completed: bool
    observed_pending: int
    notification_delivered: int
    notification_idempotent: int
    notification_ambiguous: int
    notification_retryable: int
    notification_skipped: int
    page_limit_reached: bool

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "surface": "human_review_operations",
            "schema_version": 1,
            "expired_sweep_completed": self.expired_sweep_completed,
            "observed_pending": self.observed_pending,
            "notification_delivered": self.notification_delivered,
            "notification_idempotent": self.notification_idempotent,
            "notification_ambiguous": self.notification_ambiguous,
            "notification_retryable": self.notification_retryable,
            "notification_skipped": self.notification_skipped,
            "page_limit_reached": self.page_limit_reached,
            "raw_review_reason_egress": False,
            "raw_artifact_egress": False,
            "raw_reviewer_identity_egress": False,
        }


class ReviewOperationsWorker:
    """Run one bounded expiry-and-notification cycle."""

    def __init__(
        self,
        settings: ReviewOperationsSettings,
        *,
        client: httpx.Client | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not settings.enabled:
            raise ReviewOperationsError("review operations are disabled")
        self.settings = settings
        self.release_binding = settings.release_binding()
        self.clock = clock
        self._owns_client = client is None
        self.client = client or httpx.Client(
            timeout=settings.request_timeout_seconds,
            follow_redirects=False,
        )
        self.delegate_token = _resolve_runtime_token(
            settings.runtime_auth_token,
            settings.runtime_auth_key_path,
            _DELEGATE_RUNTIME_PREFIX,
            label="delegate",
        )
        self.oracle_token = (
            _resolve_runtime_token(
                settings.oracle_auth_token,
                settings.oracle_auth_key_path,
                _ORACLE_RUNTIME_PREFIX,
                label="oracle",
            )
            if settings.notifications_enabled
            else ""
        )

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def run_once(self) -> ReviewOperationsTick:
        queue = self._expire_and_read()
        pending, page_limit_reached = self._collect_pending(queue)
        delivered = 0
        idempotent = 0
        ambiguous = 0
        retryable = 0
        skipped = 0
        if not self.settings.notifications_enabled:
            skipped = len(pending)
        else:
            for item in pending[: self.settings.maximum_notifications_per_tick]:
                outcome = self._notify(item)
                if outcome == "delivered":
                    delivered += 1
                elif outcome == "idempotent":
                    idempotent += 1
                elif outcome == "ambiguous":
                    ambiguous += 1
                else:
                    retryable += 1
            skipped = max(
                0,
                len(pending) - self.settings.maximum_notifications_per_tick,
            )
        return ReviewOperationsTick(
            expired_sweep_completed=True,
            observed_pending=len(pending),
            notification_delivered=delivered,
            notification_idempotent=idempotent,
            notification_ambiguous=ambiguous,
            notification_retryable=retryable,
            notification_skipped=skipped,
            page_limit_reached=page_limit_reached,
        )

    def _expire_and_read(self) -> dict[str, Any]:
        try:
            response = self.client.post(
                f"{self.settings.delegate_url}/review/expire",
                headers={
                    "Authorization": f"Bearer {self.delegate_token}",
                    "Cache-Control": "no-store",
                },
            )
        except httpx.HTTPError as exc:
            raise ReviewOperationsRetryable("review expiry transport unavailable") from exc
        return self._decode_queue_response(response, operation="review expiry")

    def _collect_pending(
        self, initial: dict[str, Any]
    ) -> tuple[list[PendingReviewNotification], bool]:
        pending: list[PendingReviewNotification] = []
        seen: set[str] = set()
        page = initial
        page_number = 1
        now = int(self.clock())
        while True:
            authority_context_hash = _validate_release_authority(
                page,
                self.release_binding,
                production_release=self.settings.production_release,
            )
            raw_tickets = page.get("tickets")
            if not isinstance(raw_tickets, list) or len(raw_tickets) > 100:
                raise ReviewOperationsError("review queue page is invalid")
            for raw in raw_tickets:
                ticket = _pending_notification(
                    raw,
                    authority_context_hash=authority_context_hash,
                    now=now,
                )
                if ticket is None or ticket.ticket_ref_hash in seen:
                    continue
                seen.add(ticket.ticket_ref_hash)
                pending.append(ticket)

            pagination = page.get("page")
            if not isinstance(pagination, dict):
                raise ReviewOperationsError("review queue pagination is unavailable")
            has_more = pagination.get("has_more")
            next_cursor = pagination.get("next_cursor")
            if not isinstance(has_more, bool) or not isinstance(next_cursor, str):
                raise ReviewOperationsError("review queue pagination is invalid")
            if not has_more:
                return pending, False
            if page_number >= self.settings.maximum_queue_pages:
                return pending, True
            _require_hex_hash(next_cursor, "review queue cursor")
            try:
                response = self.client.get(
                    f"{self.settings.delegate_url}/review/queue",
                    params={"cursor": next_cursor, "limit": 100},
                    headers={"Cache-Control": "no-store"},
                )
            except httpx.HTTPError as exc:
                raise ReviewOperationsRetryable(
                    "review queue pagination transport unavailable"
                ) from exc
            page = self._decode_queue_response(
                response,
                operation="review queue pagination",
            )
            page_number += 1

    def _decode_queue_response(
        self,
        response: httpx.Response,
        *,
        operation: str,
    ) -> dict[str, Any]:
        if response.status_code != 200:
            if response.status_code == 429 or response.status_code >= 500:
                raise ReviewOperationsRetryable(f"{operation} is temporarily unavailable")
            raise ReviewOperationsError(f"{operation} was rejected")
        raw = response.content
        if not raw or len(raw) > _MAX_RESPONSE_BYTES:
            raise ReviewOperationsError(f"{operation} response is not bounded")
        return _decode_json_object(
            raw,
            operation=f"{operation} response",
            maximum_bytes=_MAX_RESPONSE_BYTES,
        )

    def _notify(self, pending: PendingReviewNotification) -> str:
        request = build_review_notification_request(
            pending,
            self.release_binding,
        )
        try:
            response = self.client.post(
                f"{self.settings.oracle_url}/review/notifications",
                headers={
                    "Authorization": f"Bearer {self.oracle_token}",
                    "Cache-Control": "no-store",
                },
                json=request.model_dump(by_alias=True),
            )
        except httpx.HTTPError:
            return "retryable"
        if response.status_code == 409:
            # The oracle reserved the key before an SMTP attempt and cannot
            # prove delivery. A release/request rejection also uses 409, so
            # only this exact bounded response is an ambiguity hold. Never
            # downgrade any other rejection into an automatic retry outcome.
            if _decode_json_object(
                response.content,
                operation="review notification conflict",
                maximum_bytes=16_384,
            ) == _AMBIGUOUS_NOTIFICATION_RESPONSE:
                return "ambiguous"
            raise ReviewOperationsError("review notification was rejected")
        if response.status_code >= 500 or response.status_code == 429:
            return "retryable"
        if response.status_code != 200:
            raise ReviewOperationsError("review notification was rejected")
        raw = response.content
        if not raw or len(raw) > 16_384:
            raise ReviewOperationsError("review notification receipt is not bounded")
        receipt = _decode_json_object(
            raw,
            operation="review notification receipt",
            maximum_bytes=16_384,
        )
        if (
            set(receipt) != _NOTIFICATION_RECEIPT_FIELDS
            or receipt.get("schema") != "dnai.review-notification-receipt.v1"
            or receipt.get("idempotency_key") != request.idempotency_key
            or receipt.get("status") != "delivered"
            or not isinstance(receipt.get("idempotent"), bool)
            or receipt.get("raw_review_reason_egress") is not False
            or receipt.get("raw_artifact_egress") is not False
            or receipt.get("raw_reviewer_identity_egress") is not False
        ):
            raise ReviewOperationsError("review notification receipt is invalid")
        _require_hex_hash(receipt.get("receipt_sha256"), "notification receipt")
        return "idempotent" if receipt["idempotent"] else "delivered"


def build_review_notification_request(
    pending: PendingReviewNotification,
    release_binding: ReviewReleaseBinding,
) -> ReviewNotificationRequest:
    payload = {
        "schema": REVIEW_NOTIFICATION_REQUEST_SCHEMA,
        "event": "pending",
        "ticket_ref_hash": pending.ticket_ref_hash,
        "routed_role": pending.routed_role,
        "opened_at": pending.opened_at,
        "expires_at": pending.expires_at,
        "authority_context_hash": pending.authority_context_hash,
        "release_binding": release_binding.to_dict(),
    }
    return ReviewNotificationRequest(
        **payload,
        idempotency_key=review_notification_idempotency_key(payload),
    )


def review_notification_idempotency_key(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        REVIEW_NOTIFICATION_IDEMPOTENCY_DOMAIN + _canonical_json(payload)
    ).hexdigest()


def _validate_release_authority(
    queue: dict[str, Any],
    expected: ReviewReleaseBinding,
    *,
    production_release: bool,
) -> str:
    if (
        queue.get("surface") != "human_review_queue"
        or queue.get("schema_version") != 2
        or queue.get("raw_secret_egress") is not False
    ):
        raise ReviewOperationsError("review queue boundary metadata is invalid")
    authority = queue.get("authority")
    if not isinstance(authority, dict) or authority.get("enabled") is not True:
        raise ReviewOperationsError("review authority is unavailable")
    if authority.get("chain_id") != BASE_SEPOLIA_CHAIN_ID:
        raise ReviewOperationsError("review authority chain is invalid")
    authority_context_hash = authority.get("authority_context_hash")
    _require_hex_hash(authority_context_hash, "review authority context")

    release_context = authority.get("release_context")
    expected_context = {
        "schema": REVIEW_RELEASE_CONTEXT_SCHEMA,
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "wallet_domain": "www.wikigen.me",
        "wallet_uri": "https://www.wikigen.me",
        "main_runtime_cvm_id": expected.main_runtime_cvm_id,
        "deployment_intent_sha256": expected.deployment_intent_sha256,
        "release_authority_sha256": expected.release_authority_sha256,
        "ceremony_nonce": expected.ceremony_nonce,
    }
    if release_context != expected_context:
        raise ReviewOperationsError("review authority release context changed")
    if authority.get("policy_sha256") != expected.policy_sha256:
        raise ReviewOperationsError("review authority policy changed")

    provenance = authority.get("release_provenance")
    expected_provenance = {
        "reviewer_authority_genesis_acceptance_sha256": (
            expected.genesis_acceptance_sha256
        ),
        "reviewer_authority_current_status_epoch": expected.current_status_epoch,
        "reviewer_authority_current_status_sha256": expected.current_status_sha256,
        "reviewer_authority_active_reviewers_sha256": (
            expected.active_reviewers_sha256
        ),
    }
    if provenance != expected_provenance:
        raise ReviewOperationsError("reviewer release provenance changed")
    active = authority.get("active_reviewers")
    if (
        not isinstance(active, dict)
        or active.get("active_reviewers_sha256") != expected.active_reviewers_sha256
        or active.get("raw_reviewer_identity_egress") is not False
    ):
        raise ReviewOperationsError("active reviewer binding changed")
    if production_release and (
        authority.get("rollback_protection")
        != "base_sepolia_execution_policy_anchor"
        or not isinstance(authority.get("rollback_anchor"), dict)
    ):
        raise ReviewOperationsError("production review rollback witness is unavailable")
    if production_release:
        _validate_production_rollback_anchor(authority["rollback_anchor"])
    return authority_context_hash


def _pending_notification(
    raw: Any,
    *,
    authority_context_hash: str,
    now: int,
) -> PendingReviewNotification | None:
    if not isinstance(raw, dict):
        raise ReviewOperationsError("review queue ticket is invalid")
    forbidden = {
        "ticket_id",
        "turn_id",
        "corpus_ref",
        "review_reason",
        "artifact",
        "artifact_content",
        "reviewer_identity",
        "reviewer_email",
    }
    if forbidden.intersection(raw):
        raise ReviewOperationsError("review queue exposed a private ticket field")
    if set(raw) != _PUBLIC_REVIEW_TICKET_FIELDS:
        raise ReviewOperationsError("review queue ticket shape is invalid")
    if raw.get("raw_secret_egress") is not False:
        raise ReviewOperationsError("review queue ticket egress marker is invalid")
    status = raw.get("status")
    if status != "pending":
        return None
    ticket_ref_hash = raw.get("ticket_ref_hash")
    routed_role = raw.get("routed_role")
    opened_at = raw.get("opened_at")
    expires_at = raw.get("expires_at")
    _require_hex_hash(ticket_ref_hash, "review ticket reference")
    if routed_role not in REVIEW_OPERATION_ROLES:
        raise ReviewOperationsError("review queue ticket role is invalid")
    if (
        not isinstance(opened_at, int)
        or isinstance(opened_at, bool)
        or opened_at <= 0
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= opened_at
    ):
        raise ReviewOperationsError("review queue ticket time bounds are invalid")
    if expires_at <= now:
        # The expiry call is authoritative; a stale pending projection is held
        # and never emailed until the next successful sweep proves otherwise.
        return None
    return PendingReviewNotification(
        ticket_ref_hash=ticket_ref_hash,
        routed_role=routed_role,
        opened_at=opened_at,
        expires_at=expires_at,
        authority_context_hash=authority_context_hash,
    )


def _resolve_runtime_token(
    explicit: str,
    key_path: str,
    prefix: bytes,
    *,
    label: str,
) -> str:
    if explicit:
        return explicit
    if not dstack_utils.is_dstack_enabled():
        raise ReviewOperationsError(f"{label} runtime auth is unavailable")
    try:
        key = dstack_utils.derive_storage_key(key_path)
    except Exception as exc:
        raise ReviewOperationsError(f"{label} runtime auth is unavailable") from exc
    if not isinstance(key, bytes) or len(key) < 32:
        raise ReviewOperationsError(f"{label} runtime auth is unavailable")
    return hashlib.sha256(prefix + key).hexdigest()


def _validate_production_rollback_anchor(value: dict[str, Any]) -> None:
    """Require the queue's bounded on-chain witness, not a status-shaped dict."""

    state_hash = value.get("state_hash")
    decision_hash = value.get("decision_hash")
    sequence = value.get("sequence")
    witness = value.get("rollback_anchor")
    if (
        value.get("schema") != "dnai.review-queue-rollback-anchor.v1"
        or not isinstance(state_hash, str)
        or not isinstance(decision_hash, str)
        or value.get("opaque_commitments_only") is not True
        or value.get("raw_ticket_egress") is not False
        or value.get("raw_reviewer_identity_egress") is not False
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 0
        or not isinstance(witness, dict)
    ):
        raise ReviewOperationsError("production review rollback witness is invalid")
    _require_hex_hash(state_hash, "review rollback state")
    _require_hex_hash(decision_hash, "review rollback decision")
    if (
        witness.get("schema")
        != "dnai-wikigen/execution-policy-anchor-status/v1"
        or witness.get("status") != "rpc_reported_finalized_release_match"
        or witness.get("verification_model")
        != "single_rpc_reported_finalized_with_confirmation_depth"
        or witness.get("chain_id") != BASE_SEPOLIA_CHAIN_ID
        or witness.get("independent_rpc_quorum_verified") is not False
        or witness.get("consensus_proof_verified") is not False
        or witness.get("opaque_commitments_only") is not True
        or witness.get("raw_resource_id_egress") is not False
        or witness.get("raw_policy_egress") is not False
    ):
        raise ReviewOperationsError("production review rollback witness is invalid")


def _decode_json_object(
    raw: bytes,
    *,
    operation: str,
    maximum_bytes: int,
) -> dict[str, Any]:
    if not raw or len(raw) > maximum_bytes:
        raise ReviewOperationsError(f"{operation} is not bounded")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ReviewOperationsError,
    ) as exc:
        raise ReviewOperationsError(f"{operation} is invalid") from exc
    if not isinstance(value, dict):
        raise ReviewOperationsError(f"{operation} is invalid")
    return value


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReviewOperationsError("JSON repeats a field")
        value[key] = item
    return value


def _require_http_service_url(value: str, label: str) -> None:
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ValueError(f"{label} is invalid") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} is invalid")


def _require_release_identifier(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or not 3 <= len(value) <= 128
        or not all(character.isalnum() or character in "_.:-" for character in value)
    ):
        raise ValueError(f"{label} is invalid")


def _require_sha256(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value.startswith(_SHA256_PREFIX)
        or len(value) != 71
    ):
        raise ValueError(f"{label} must be a nonzero SHA-256 digest")
    _require_hex_hash(value[len(_SHA256_PREFIX) :], label)
    if int(value[len(_SHA256_PREFIX) :], 16) == 0:
        raise ValueError(f"{label} must be a nonzero SHA-256 digest")


def _require_bytes32(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 66:
        raise ValueError(f"{label} must be nonzero bytes32")
    _require_hex_hash(value[2:], label)
    if int(value[2:], 16) == 0:
        raise ValueError(f"{label} must be nonzero bytes32")


def _require_hex_hash(value: Any, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ReviewOperationsError(f"{label} must be lowercase SHA-256 hex")


def _require_positive_int(value: Any, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{label} must be positive")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def main() -> None:
    try:
        settings = ReviewOperationsSettings()
        if not settings.enabled:
            raise ReviewOperationsError("review operations are disabled")
        worker = ReviewOperationsWorker(settings)
    except Exception:
        print(
            json.dumps(
                {
                    "surface": "human_review_operations",
                    "status": "configuration_unavailable",
                    "raw_secret_egress": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(78) from None

    stopping = False

    def stop(_signum: int, _frame: Any) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    consecutive_failures = 0
    try:
        while not stopping:
            started = time.monotonic()
            try:
                tick = worker.run_once()
                consecutive_failures = 0
                print(json.dumps(tick.to_public_dict(), sort_keys=True), flush=True)
            except ReviewOperationsRetryable:
                consecutive_failures = min(consecutive_failures + 1, 4)
                print(
                    json.dumps(
                        {
                            "surface": "human_review_operations",
                            "status": "retryable_unavailable",
                            "retry_count": consecutive_failures,
                            "raw_secret_egress": False,
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
            except ReviewOperationsError:
                print(
                    json.dumps(
                        {
                            "surface": "human_review_operations",
                            "status": "release_or_response_rejected",
                            "raw_secret_egress": False,
                        },
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                    flush=True,
                )
                raise SystemExit(78) from None

            delay = settings.poll_interval_seconds * (2**consecutive_failures)
            remaining = max(0.0, min(300.0, delay) - (time.monotonic() - started))
            # Short waits keep SIGTERM responsive without busy looping.
            while remaining > 0 and not stopping:
                step = min(1.0, remaining)
                time.sleep(step)
                remaining -= step
    finally:
        worker.close()


if __name__ == "__main__":
    main()
