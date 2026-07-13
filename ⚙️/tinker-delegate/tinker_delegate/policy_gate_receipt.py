"""Bounded receipts for deterministic corpus policy gates."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from tinker_delegate.coordination import GateResults, Turn
from tinker_delegate.policy_kernel import (
    CorpusPolicy,
    PolicyDecision,
    PolicyGateResult,
    PolicyKernelError,
    gate_access_request_payload,
    gate_turn_requests,
)


def build_policy_gate_receipt(request_payload: dict[str, Any], policy_payload: dict[str, Any]) -> dict[str, Any]:
    result = gate_access_request_payload(request_payload, policy_payload)
    return {
        "surface": "conseca_policy_gate",
        "schema_version": 1,
        "mode": "single_corpus",
        "evaluated": True,
        "decision": result.decision.value,
        "action": _action_for_decision(result.decision),
        "gate": result.to_public_dict(),
        "raw_artifact_egress": False,
        "raw_policy_egress": False,
        "raw_private_data_egress": False,
        "raw_secret_egress": False,
    }


def build_policy_turn_gate_receipt(turn_payload: dict[str, Any], policies_payload: dict[str, Any]) -> dict[str, Any]:
    turn = _turn_from_payload(turn_payload)
    policies = _policies_from_payload(policies_payload)
    gate_results = gate_turn_requests(turn, policies)
    per_corpus = tuple(
        gate_access_request_payload(
            _request_payload_for_turn(turn, corpus_ref),
            _policy_payload(policies[corpus_ref]),
        )
        for corpus_ref in turn.corpora
    )
    decision = _aggregate_decision(per_corpus)
    return {
        "surface": "conseca_policy_gate",
        "schema_version": 1,
        "mode": "coordination_turn_fanout",
        "evaluated": True,
        "decision": decision.value,
        "action": _action_for_decision(decision),
        "turn": {
            "turn_id": turn.turn_id,
            "requester_ref": turn.requester_ref,
            "purpose_hash": _stable_hash(turn.purpose, prefix="purpose"),
            "pipeline_hash": _stable_hash(turn.pipeline, prefix="pipeline"),
            "corpus_count": len(turn.corpora),
        },
        "gate_results": _gate_results_public(gate_results),
        "gates": [result.to_public_dict() for result in per_corpus],
        "raw_artifact_egress": False,
        "raw_policy_egress": False,
        "raw_private_data_egress": False,
        "raw_secret_egress": False,
    }


def _turn_from_payload(payload: dict[str, Any]) -> Turn:
    allowed = {"turn_id", "by", "requester_ref", "purpose", "pipeline", "corpora", "requests"}
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise PolicyKernelError("unknown turn field")
    corpora = payload.get("corpora")
    requests = payload.get("requests")
    if not isinstance(corpora, list | tuple) or not all(isinstance(item, str) and item for item in corpora):
        raise PolicyKernelError("invalid turn corpora")
    if not isinstance(requests, dict):
        raise PolicyKernelError("invalid turn requests")
    if not all(isinstance(value, dict) for value in requests.values()):
        raise PolicyKernelError("invalid turn request payload")
    return Turn(
        turn_id=_require_string(payload, "turn_id"),
        by=_require_string(payload, "by"),
        requester_ref=_require_string(payload, "requester_ref"),
        purpose=_require_string(payload, "purpose"),
        pipeline=_require_string(payload, "pipeline"),
        corpora=tuple(corpora),
        requests={str(key): dict(value) for key, value in requests.items()},
    )


def _policies_from_payload(payload: dict[str, Any]) -> dict[str, CorpusPolicy]:
    if not isinstance(payload, dict):
        raise PolicyKernelError("invalid policies payload")
    policies: dict[str, CorpusPolicy] = {}
    for corpus_ref, policy_payload in payload.items():
        if not isinstance(corpus_ref, str) or not corpus_ref:
            raise PolicyKernelError("invalid policy corpus ref")
        if not isinstance(policy_payload, dict):
            raise PolicyKernelError("invalid policy payload")
        policy = CorpusPolicy.from_dict(policy_payload)
        if policy.corpus_ref != corpus_ref:
            raise PolicyKernelError("policy corpus ref mismatch")
        policies[corpus_ref] = policy
    return policies


def _request_payload_for_turn(turn: Turn, corpus_ref: str) -> dict[str, Any]:
    try:
        payload = dict(turn.requests[corpus_ref])
    except KeyError as exc:
        raise PolicyKernelError("turn request missing") from exc
    payload.setdefault("request_id", f"{turn.turn_id}:{corpus_ref}")
    payload.setdefault("requester_ref", turn.requester_ref)
    payload.setdefault("purpose", turn.purpose)
    payload.setdefault("pipeline", turn.pipeline)
    return payload


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


def _gate_results_public(gate_results: GateResults) -> dict[str, Any]:
    return {
        "turn_id": gate_results.turn_id,
        "query_count": len(gate_results.queries),
        "queries": [
            {
                "corpus_ref": query.corpus_ref,
                "decision": query.decision.value,
                "stage": query.stage,
                "reason_code": query.reason,
                "routed_role": query.routed_role,
            }
            for query in gate_results.queries
        ],
    }


def _aggregate_decision(results: tuple[PolicyGateResult, ...]) -> PolicyDecision:
    if any(result.decision == PolicyDecision.DENY for result in results):
        return PolicyDecision.DENY
    if any(result.decision == PolicyDecision.HOLD for result in results):
        return PolicyDecision.HOLD
    return PolicyDecision.PASS


def _action_for_decision(decision: PolicyDecision) -> str:
    if decision == PolicyDecision.PASS:
        return "surface_bounded_result"
    if decision == PolicyDecision.HOLD:
        return "route_to_review"
    return "deny"


def _require_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise PolicyKernelError(f"missing or invalid {key}")
    return value


def _stable_hash(value: Any, *, prefix: str) -> str:
    if isinstance(value, str):
        payload = value
    else:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(prefix.encode("utf-8") + b"\0" + payload.encode("utf-8")).hexdigest()
