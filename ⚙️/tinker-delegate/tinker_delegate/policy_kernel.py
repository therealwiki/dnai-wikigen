"""Deterministic fail-closed access policy kernel.

The policy kernel is intentionally pure: it reads an ``AccessRequest`` and a
``CorpusPolicy`` and returns a bounded ``PolicyGateResult``. It performs no
network, browser, Tinker, chain, or LLM calls. Policy authoring may use LLMs
elsewhere, but enforcement is a closed deterministic function here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


SUPPORTED_POLICY_VERSION = "policy-kernel/v1"
# This pins the byte-level hashing contract shared by the CVM and browser.
# Changing JSON ordering, escaping, default fields, or hash domains requires a
# new value and a coordinated release; it must never be inferred from an API
# response controlled by the runtime being approved.
POLICY_CANONICALIZATION_VERSION = "policy-kernel-canonicalization/v2"
ZERO_EXECUTION_CONTEXT_HASH = "0" * 64
PUBLIC_REVIEW_ROLES = frozenset(
    {
        "access-review-officer",
        "expert-in-the-loop",
        "ethics-legal-reviewer",
    }
)
MAX_POLICY_KERNEL_PAYLOAD_BYTES = 32_768
MAX_POLICY_STRING_BYTES = 256
MAX_POLICY_LIST_ITEMS = 64
MAX_POLICY_MAP_ITEMS = 64

_REQUEST_FIELDS = {
    "request_id",
    "requester_ref",
    "purpose",
    "pipeline",
    "data_classes",
    "output_schema",
    "operations",
    "risk_tags",
}

_POLICY_FIELDS = {
    "policy_id",
    "version",
    "corpus_ref",
    "allowed_purposes",
    "denied_purposes",
    "allowed_pipelines",
    "allowed_output_schemas",
    "allowed_operations",
    "known_data_classes",
    "restricted_categories",
    "hold_categories",
    "ambiguous_categories",
    "hold_routes",
}


class PolicyKernelError(ValueError):
    """Raised when a policy-kernel payload is malformed."""


class PolicyDecision(str, Enum):
    PASS = "pass"
    HOLD = "hold"
    DENY = "deny"


@dataclass(frozen=True)
class AccessRequest:
    request_id: str
    requester_ref: str
    purpose: str
    pipeline: str
    data_classes: tuple[str, ...]
    output_schema: str
    operations: tuple[str, ...] = ("score",)
    risk_tags: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AccessRequest":
        _reject_unknown_fields(payload, _REQUEST_FIELDS, "access request")
        return cls(
            request_id=_require_string(payload, "request_id"),
            requester_ref=_require_string(payload, "requester_ref"),
            purpose=_require_string(payload, "purpose"),
            pipeline=_require_string(payload, "pipeline"),
            data_classes=_require_string_tuple(payload, "data_classes"),
            output_schema=_require_string(payload, "output_schema"),
            operations=_optional_string_tuple(payload, "operations", ("score",)),
            risk_tags=_optional_string_tuple(payload, "risk_tags", ()),
        )


@dataclass(frozen=True)
class CorpusPolicy:
    policy_id: str
    corpus_ref: str
    allowed_purposes: tuple[str, ...]
    allowed_pipelines: tuple[str, ...]
    allowed_output_schemas: tuple[str, ...]
    allowed_operations: tuple[str, ...]
    known_data_classes: tuple[str, ...]
    restricted_categories: tuple[str, ...] = ()
    hold_categories: tuple[str, ...] = ()
    ambiguous_categories: tuple[str, ...] = ()
    denied_purposes: tuple[str, ...] = ()
    hold_routes: dict[str, str] | None = None
    version: str = SUPPORTED_POLICY_VERSION

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CorpusPolicy":
        _reject_unknown_fields(payload, _POLICY_FIELDS, "corpus policy")
        return cls(
            policy_id=_require_string(payload, "policy_id"),
            version=(
                _require_string(payload, "version")
                if "version" in payload
                else SUPPORTED_POLICY_VERSION
            ),
            corpus_ref=_require_string(payload, "corpus_ref"),
            allowed_purposes=_require_string_tuple(payload, "allowed_purposes"),
            denied_purposes=_optional_string_tuple(payload, "denied_purposes", ()),
            allowed_pipelines=_require_string_tuple(payload, "allowed_pipelines"),
            allowed_output_schemas=_require_string_tuple(payload, "allowed_output_schemas"),
            allowed_operations=_require_string_tuple(payload, "allowed_operations"),
            known_data_classes=_require_string_tuple(payload, "known_data_classes"),
            restricted_categories=_optional_string_tuple(payload, "restricted_categories", ()),
            hold_categories=_optional_string_tuple(payload, "hold_categories", ()),
            ambiguous_categories=_optional_string_tuple(payload, "ambiguous_categories", ()),
            hold_routes=_optional_string_map(payload, "hold_routes"),
        )

    @property
    def policy_hash(self) -> str:
        return _stable_hash(
            {
                "version": self.version,
                "policy_id": self.policy_id,
                "corpus_ref": self.corpus_ref,
                "allowed_purposes": sorted(self.allowed_purposes),
                "denied_purposes": sorted(self.denied_purposes),
                "allowed_pipelines": sorted(self.allowed_pipelines),
                "allowed_output_schemas": sorted(self.allowed_output_schemas),
                "allowed_operations": sorted(self.allowed_operations),
                "known_data_classes": sorted(self.known_data_classes),
                "restricted_categories": sorted(self.restricted_categories),
                "hold_categories": sorted(self.hold_categories),
                "ambiguous_categories": sorted(self.ambiguous_categories),
                "hold_routes": self.hold_routes or {},
            },
            prefix="corpus_policy",
        )


@dataclass(frozen=True)
class PolicyStageOutcome:
    stage: int
    decision: PolicyDecision
    reason_code: str
    routed_role: str = ""
    matched_category_hashes: tuple[str, ...] = ()

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "decision": self.decision.value,
            "reason_code": self.reason_code,
            "routed_role": self.routed_role,
            "matched_category_count": len(self.matched_category_hashes),
            "matched_category_hashes": list(self.matched_category_hashes),
        }


@dataclass(frozen=True)
class PolicyGateResult:
    decision: PolicyDecision
    corpus_ref: str
    stage: int
    reason_code: str
    routed_role: str = ""
    request_hash: str = ""
    policy_hash: str = ""
    # Populated by the execution-binding layer after the pure kernel runs.
    # Zero means that the surface has no additional immutable execution
    # context beyond its resource identity in this release.
    execution_context_hash: str = ZERO_EXECUTION_CONTEXT_HASH
    purpose_hash: str = ""
    pipeline_hash: str = ""
    output_schema_hash: str = ""
    outcomes: tuple[PolicyStageOutcome, ...] = ()
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "corpus_ref": self.corpus_ref,
            "stage": self.stage,
            "reason_code": self.reason_code,
            "routed_role": self.routed_role,
            "request_hash": self.request_hash,
            "policy_hash": self.policy_hash,
            "execution_context_hash": self.execution_context_hash,
            "purpose_hash": self.purpose_hash,
            "pipeline_hash": self.pipeline_hash,
            "output_schema_hash": self.output_schema_hash,
            "outcomes": [outcome.to_public_dict() for outcome in self.outcomes],
            "raw_secret_egress": self.raw_secret_egress,
        }

    def to_bounded_api_dict(self) -> dict[str, Any]:
        """Return the HTTP-safe view without the raw corpus reference."""

        public = self.to_public_dict()
        public.pop("corpus_ref", None)
        public["corpus_ref_hash"] = _stable_hash(
            self.corpus_ref, prefix="corpus_ref"
        )
        public["raw_policy_egress"] = False
        return public

    def to_gated_query(self):
        """Convert a policy result into the coordination reducer query shape."""

        from tinker_delegate.coordination import GateDecision, GatedQuery

        return GatedQuery(
            corpus_ref=self.corpus_ref,
            decision=GateDecision(self.decision.value),
            stage=self.stage,
            reason=self.reason_code,
            routed_role=self.routed_role,
        )


def gate_access_request(request: AccessRequest, policy: CorpusPolicy) -> PolicyGateResult:
    """Evaluate an access request against a corpus policy.

    This function is deterministic and fail-closed. The first deny wins; holds
    are returned only when no deny is present and at least one review route is
    required.
    """

    outcomes: list[PolicyStageOutcome] = []
    if policy.version != SUPPORTED_POLICY_VERSION:
        outcomes.append(_deny(0, "unsupported_policy_version"))
        return _result(request, policy, outcomes)

    if request.purpose in policy.denied_purposes:
        outcomes.append(_deny(1, "denied_purpose"))
        return _result(request, policy, outcomes)
    if request.purpose not in policy.allowed_purposes:
        outcomes.append(_deny(1, "unknown_or_unallowed_purpose"))
        return _result(request, policy, outcomes)
    outcomes.append(_pass(1, "purpose_allowed"))

    if request.pipeline not in policy.allowed_pipelines:
        outcomes.append(_deny(2, "unsupported_pipeline"))
        return _result(request, policy, outcomes)
    if request.output_schema not in policy.allowed_output_schemas:
        outcomes.append(_deny(2, "unsupported_output_schema"))
        return _result(request, policy, outcomes)
    unsupported_operations = tuple(operation for operation in request.operations if operation not in policy.allowed_operations)
    if unsupported_operations:
        outcomes.append(_deny(2, "unsupported_operation"))
        return _result(request, policy, outcomes)
    outcomes.append(_pass(2, "pipeline_output_allowed"))

    data_classes = set(request.data_classes)
    known_classes = set(policy.known_data_classes)
    if unknown := sorted(data_classes - known_classes):
        outcomes.append(_deny(3, "unknown_data_class", matched=tuple(unknown)))
        return _result(request, policy, outcomes)

    if restricted := tuple(sorted(data_classes & set(policy.restricted_categories))):
        outcomes.append(_deny(3, "restricted_category", matched=restricted))
        return _result(request, policy, outcomes)

    review_categories = tuple(sorted(data_classes & (set(policy.hold_categories) | set(policy.ambiguous_categories))))
    if review_categories:
        outcomes.append(
            PolicyStageOutcome(
                stage=3,
                decision=PolicyDecision.HOLD,
                reason_code="review_required",
                routed_role=_route_review(review_categories, policy),
                matched_category_hashes=_category_hashes(review_categories),
            )
        )
        return _result(request, policy, outcomes)

    outcomes.append(_pass(3, "categories_allowed"))
    outcomes.append(_pass(4, "policy_passed"))
    return _result(request, policy, outcomes)


def gate_access_request_payload(request_payload: dict[str, Any], policy_payload: dict[str, Any]) -> PolicyGateResult:
    """Strict dict entrypoint that fails closed on malformed or unknown fields."""

    try:
        _require_bounded_payload(request_payload, "access request")
        _require_bounded_payload(policy_payload, "corpus policy")
        request = AccessRequest.from_dict(request_payload)
        policy = CorpusPolicy.from_dict(policy_payload)
    except PolicyKernelError as exc:
        request_hash = _malformed_payload_hash(
            request_payload, prefix="malformed_request"
        )
        policy_hash = _malformed_payload_hash(
            policy_payload, prefix="malformed_policy"
        )
        reason = _parse_error_reason(str(exc))
        candidate_corpus_ref = (
            policy_payload.get("corpus_ref")
            if isinstance(policy_payload, dict)
            else ""
        )
        return PolicyGateResult(
            decision=PolicyDecision.DENY,
            corpus_ref=(
                candidate_corpus_ref
                if _is_bounded_string(candidate_corpus_ref)
                else ""
            ),
            stage=0,
            reason_code=reason,
            request_hash=request_hash,
            policy_hash=policy_hash,
            outcomes=(PolicyStageOutcome(stage=0, decision=PolicyDecision.DENY, reason_code=reason),),
            raw_secret_egress=False,
        )
    return gate_access_request(request, policy)


def gate_turn_requests(turn, policies_by_corpus: dict[str, CorpusPolicy]):
    """Fan out a coordination turn into deterministic per-corpus gate results.

    The coordination reducer stays event-driven: this helper is the explicit
    boundary that turns raw per-corpus request payloads into ``GateResults``.
    """

    from tinker_delegate.coordination import GateResults

    expected = set(turn.corpora)
    actual_requests = set(turn.requests)
    actual_policies = set(policies_by_corpus)
    if actual_requests != expected:
        raise PolicyKernelError("turn requests must cover exactly the turn corpora")
    if actual_policies != expected:
        raise PolicyKernelError("policies must cover exactly the turn corpora")

    queries = []
    for corpus_ref in turn.corpora:
        request_payload = dict(turn.requests[corpus_ref])
        request_payload.setdefault("request_id", f"{turn.turn_id}:{corpus_ref}")
        request_payload.setdefault("requester_ref", turn.requester_ref)
        request_payload.setdefault("purpose", turn.purpose)
        request_payload.setdefault("pipeline", turn.pipeline)
        if request_payload.get("purpose") != turn.purpose or request_payload.get("pipeline") != turn.pipeline:
            raise PolicyKernelError("turn request purpose and pipeline must match the parent turn")
        result = gate_access_request_payload(request_payload, _policy_payload(policies_by_corpus[corpus_ref]))
        queries.append(result.to_gated_query())
    return GateResults(turn_id=turn.turn_id, queries=tuple(queries))


def _result(
    request: AccessRequest,
    policy: CorpusPolicy,
    outcomes: list[PolicyStageOutcome],
) -> PolicyGateResult:
    final = outcomes[-1]
    return PolicyGateResult(
        decision=final.decision,
        corpus_ref=policy.corpus_ref,
        stage=final.stage,
        reason_code=final.reason_code,
        routed_role=final.routed_role,
        request_hash=_stable_hash(_bounded_request_shape(request), prefix="access_request"),
        policy_hash=policy.policy_hash,
        purpose_hash=_stable_hash(request.purpose, prefix="purpose"),
        pipeline_hash=_stable_hash(request.pipeline, prefix="pipeline"),
        output_schema_hash=_stable_hash(request.output_schema, prefix="output_schema"),
        outcomes=tuple(outcomes),
        raw_secret_egress=False,
    )


def _bounded_request_shape(request: AccessRequest) -> dict[str, Any]:
    return {
        "request_id": request.request_id,
        "requester_ref": request.requester_ref,
        "purpose_hash": _stable_hash(request.purpose, prefix="purpose"),
        "pipeline_hash": _stable_hash(request.pipeline, prefix="pipeline"),
        "data_class_hashes": _category_hashes(request.data_classes),
        "output_schema_hash": _stable_hash(request.output_schema, prefix="output_schema"),
        "operation_hashes": [_stable_hash(operation, prefix="operation") for operation in request.operations],
        "risk_tag_hashes": tuple(
            _stable_hash(risk_tag, prefix="risk_tag")
            for risk_tag in sorted(request.risk_tags)
        ),
        "risk_tag_count": len(request.risk_tags),
    }


def _policy_payload(policy: CorpusPolicy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "version": policy.version,
        "corpus_ref": policy.corpus_ref,
        "allowed_purposes": list(policy.allowed_purposes),
        "denied_purposes": list(policy.denied_purposes),
        "allowed_pipelines": list(policy.allowed_pipelines),
        "allowed_output_schemas": list(policy.allowed_output_schemas),
        "allowed_operations": list(policy.allowed_operations),
        "known_data_classes": list(policy.known_data_classes),
        "restricted_categories": list(policy.restricted_categories),
        "hold_categories": list(policy.hold_categories),
        "ambiguous_categories": list(policy.ambiguous_categories),
        "hold_routes": policy.hold_routes or {},
    }


def _pass(stage: int, reason: str) -> PolicyStageOutcome:
    return PolicyStageOutcome(stage=stage, decision=PolicyDecision.PASS, reason_code=reason)


def _deny(stage: int, reason: str, *, matched: tuple[str, ...] = ()) -> PolicyStageOutcome:
    return PolicyStageOutcome(
        stage=stage,
        decision=PolicyDecision.DENY,
        reason_code=reason,
        matched_category_hashes=_category_hashes(matched),
    )


def _route_review(categories: tuple[str, ...], policy: CorpusPolicy) -> str:
    routes = policy.hold_routes or {}
    for category in categories:
        if category in routes:
            return routes[category]
    if any("clinical" in category or "bio" in category for category in categories):
        return "expert-in-the-loop"
    return "access-review-officer"


def _category_hashes(categories: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(_stable_hash(category, prefix="category") for category in sorted(categories))


def _reject_unknown_fields(payload: dict[str, Any], allowed: set[str], label: str) -> None:
    if not isinstance(payload, dict):
        raise PolicyKernelError(f"invalid {label} payload")
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise PolicyKernelError(f"unknown {label} field")


def _require_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not _is_bounded_string(value):
        raise PolicyKernelError(f"missing or invalid {key}")
    return value


def _require_string_tuple(payload: dict[str, Any], key: str) -> tuple[str, ...]:
    if key not in payload:
        raise PolicyKernelError(f"missing {key}")
    return _string_tuple(payload[key], key)


def _optional_string_tuple(payload: dict[str, Any], key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    if key not in payload:
        return default
    if payload[key] == [] or payload[key] == ():
        return ()
    return _string_tuple(payload[key], key)


def _string_tuple(value: Any, key: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list | tuple)
        or not value
        or len(value) > MAX_POLICY_LIST_ITEMS
    ):
        raise PolicyKernelError(f"missing or invalid {key}")
    if not all(
        _is_bounded_string(item)
        for item in value
    ):
        raise PolicyKernelError(f"invalid {key}")
    normalized = tuple(value)
    if len(set(normalized)) != len(normalized):
        raise PolicyKernelError(f"invalid {key}")
    return normalized


def _optional_string_map(payload: dict[str, Any], key: str) -> dict[str, str] | None:
    if key not in payload:
        return None
    value = payload[key]
    if not isinstance(value, dict) or len(value) > MAX_POLICY_MAP_ITEMS:
        raise PolicyKernelError(f"invalid {key}")
    if not all(
        _is_bounded_string(k)
        and isinstance(v, str)
        and v in PUBLIC_REVIEW_ROLES
        for k, v in value.items()
    ):
        raise PolicyKernelError(f"invalid {key}")
    return dict(value)


def _require_bounded_payload(payload: Any, label: str) -> None:
    """Reject malformed or oversized policy inputs before detailed parsing."""

    if not isinstance(payload, dict):
        raise PolicyKernelError(f"invalid {label} payload")
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise PolicyKernelError(f"invalid {label} payload") from exc
    if len(encoded) > MAX_POLICY_KERNEL_PAYLOAD_BYTES:
        raise PolicyKernelError(f"oversized {label} payload")


def _is_bounded_string(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return len(value.encode("utf-8")) <= MAX_POLICY_STRING_BYTES
    except UnicodeEncodeError:
        return False


def _malformed_payload_hash(payload: Any, *, prefix: str) -> str:
    """Hash malformed input without reflecting it or requiring it to be JSON."""

    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        encoded = f"non-json:{type(payload).__name__}".encode("ascii", "replace")
    return hashlib.sha256(prefix.encode("utf-8") + b"\0" + encoded).hexdigest()


def _parse_error_reason(message: str) -> str:
    if "unknown corpus policy field" in message:
        return "unknown_policy_field"
    if "unknown access request field" in message:
        return "unknown_request_field"
    return "malformed_policy_payload"


def _stable_hash(value: Any, *, prefix: str) -> str:
    if isinstance(value, str):
        payload = value
    else:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(prefix.encode("utf-8") + b"\0" + payload.encode("utf-8")).hexdigest()
