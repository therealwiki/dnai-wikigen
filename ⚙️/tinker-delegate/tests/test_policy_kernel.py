import json
import unittest
from pathlib import Path

from tinker_delegate.execution_policy_store import execution_resource_hash

from tinker_delegate.policy_kernel import (
    AccessRequest,
    CorpusPolicy,
    MAX_POLICY_KERNEL_PAYLOAD_BYTES,
    POLICY_CANONICALIZATION_VERSION,
    PolicyKernelError,
    PolicyDecision,
    gate_access_request,
    gate_access_request_payload,
    gate_turn_requests,
)
from tinker_delegate.coordination import (
    CollabSession,
    ConsentGrant,
    CoordinationState,
    Corpus,
    DelegationGrant,
    GateDecision,
    Participant,
    ParticipantRole,
    SubmitTurn,
    Turn,
    TurnStatus,
    coordinate,
)


def _request(**overrides):
    payload = {
        "request_id": "request-1",
        "requester_ref": "agent://sponsor",
        "purpose": "rank-candidates",
        "pipeline": "sft-rerank",
        "data_classes": ["assay-summary"],
        "output_schema": "score-band-v1",
        "operations": ["score"],
    }
    payload.update(overrides)
    return payload


def _policy(**overrides):
    payload = {
        "policy_id": "policy-atlas",
        "version": "policy-kernel/v1",
        "corpus_ref": "corpus://atlas",
        "allowed_purposes": ["rank-candidates"],
        "denied_purposes": ["publish-raw-records"],
        "allowed_pipelines": ["sft-rerank"],
        "allowed_output_schemas": ["score-band-v1"],
        "allowed_operations": ["score"],
        "known_data_classes": [
            "assay-summary",
            "clinical-summary",
            "dual-use-uncertain",
            "de-novo-binder-design",
        ],
        "restricted_categories": ["de-novo-binder-design"],
        "hold_categories": ["clinical-summary"],
        "ambiguous_categories": ["dual-use-uncertain"],
        "hold_routes": {
            "clinical-summary": "expert-in-the-loop",
            "dual-use-uncertain": "ethics-legal-reviewer",
        },
    }
    payload.update(overrides)
    return payload


class PolicyKernelTest(unittest.TestCase):
    def test_shared_browser_commitment_vectors_match_exactly(self):
        path = (
            Path(__file__).resolve().parents[3]
            / "web"
            / "src"
            / "lib"
            / "policyCommitmentVectors.json"
        )
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            document["schema"],
            "dnai.execution-policy-commitment-vectors.v1",
        )
        for vector in document["vectors"]:
            result = gate_access_request_payload(
                vector["bundle"]["request"], vector["bundle"]["policy"]
            )
            bounded = result.to_bounded_api_dict()
            actual = {
                "canonicalization_version": POLICY_CANONICALIZATION_VERSION,
                "request_hash": result.request_hash,
                "policy_hash": result.policy_hash,
                "resource_id_hash": execution_resource_hash(
                    vector["surface"], vector["resource_id"]
                ),
                "purpose_hash": result.purpose_hash,
                "pipeline_hash": result.pipeline_hash,
                "output_schema_hash": result.output_schema_hash,
                "corpus_ref_hash": bounded["corpus_ref_hash"],
                "local_evaluation": {
                    "decision": result.decision.value,
                    "stage": result.stage,
                    "reason_code": result.reason_code,
                    "routed_role": result.routed_role,
                    "outcomes": [
                        outcome.to_public_dict()
                        for outcome in result.outcomes
                    ],
                },
            }
            self.assertEqual(actual, vector["expected"], vector["name"])

    def test_gate_is_pure_and_passes_allowed_request(self):
        request = AccessRequest.from_dict(_request())
        policy = CorpusPolicy.from_dict(_policy())

        first = gate_access_request(request, policy)
        second = gate_access_request(request, policy)

        self.assertEqual(first, second)
        self.assertEqual(first.decision, PolicyDecision.PASS)
        public = first.to_public_dict()
        self.assertEqual(public["raw_secret_egress"], False)
        self.assertEqual(public["reason_code"], "policy_passed")
        rendered = json.dumps(public, sort_keys=True)
        self.assertNotIn("rank-candidates", rendered)
        self.assertNotIn("assay-summary", rendered)
        self.assertIn("purpose_hash", public)

        api_public = first.to_bounded_api_dict()
        self.assertNotIn("corpus_ref", api_public)
        self.assertEqual(len(api_public["corpus_ref_hash"]), 64)
        self.assertFalse(api_public["raw_policy_egress"])

    def test_denied_purpose_fails_closed(self):
        result = gate_access_request_payload(
            _request(purpose="publish-raw-records"),
            _policy(),
        )

        self.assertEqual(result.decision, PolicyDecision.DENY)
        self.assertEqual(result.reason_code, "denied_purpose")
        self.assertEqual(result.stage, 1)

    def test_unknown_purpose_fails_closed(self):
        result = gate_access_request_payload(
            _request(purpose="novel-purpose"),
            _policy(),
        )

        self.assertEqual(result.decision, PolicyDecision.DENY)
        self.assertEqual(result.reason_code, "unknown_or_unallowed_purpose")

    def test_deny_list_overrides_allow_list_for_same_purpose(self):
        # Load-bearing conflict resolution: a purpose in BOTH allowed_purposes and
        # denied_purposes must DENY — the deny check runs first, so deny wins. This
        # guards against a future reorder that would let a denied-but-also-allowed
        # purpose (an authoring mistake or an adversarial policy) slip through.
        result = gate_access_request_payload(
            _request(purpose="rank-candidates"),
            _policy(denied_purposes=["publish-raw-records", "rank-candidates"]),
        )

        self.assertEqual(result.decision, PolicyDecision.DENY)
        self.assertEqual(result.reason_code, "denied_purpose")
        self.assertEqual(result.stage, 1)

    def test_unsupported_pipeline_and_output_fail_closed(self):
        pipeline = gate_access_request_payload(
            _request(pipeline="raw-export"),
            _policy(),
        )
        output = gate_access_request_payload(
            _request(output_schema="raw-records-v1"),
            _policy(),
        )

        self.assertEqual(pipeline.decision, PolicyDecision.DENY)
        self.assertEqual(pipeline.reason_code, "unsupported_pipeline")
        self.assertEqual(output.decision, PolicyDecision.DENY)
        self.assertEqual(output.reason_code, "unsupported_output_schema")

    def test_unknown_request_and_policy_fields_fail_closed(self):
        request_payload = _request()
        request_payload["raw_prompt"] = "private corpus text"
        policy_payload = _policy()
        policy_payload["llm_verdict"] = "allow everything"

        request_result = gate_access_request_payload(request_payload, _policy())
        policy_result = gate_access_request_payload(_request(), policy_payload)

        self.assertEqual(request_result.decision, PolicyDecision.DENY)
        self.assertEqual(request_result.reason_code, "unknown_request_field")
        self.assertEqual(policy_result.decision, PolicyDecision.DENY)
        self.assertEqual(policy_result.reason_code, "unknown_policy_field")
        rendered = json.dumps(policy_result.to_public_dict(), sort_keys=True)
        self.assertNotIn("allow everything", rendered)

    def test_oversized_and_duplicate_inputs_fail_closed(self):
        oversized = _request(requester_ref="x" * (MAX_POLICY_KERNEL_PAYLOAD_BYTES + 1))
        oversized_result = gate_access_request_payload(oversized, _policy())
        duplicate_result = gate_access_request_payload(
            _request(data_classes=["assay-summary", "assay-summary"]),
            _policy(),
        )

        self.assertEqual(oversized_result.decision, PolicyDecision.DENY)
        self.assertEqual(oversized_result.reason_code, "malformed_policy_payload")
        self.assertEqual(duplicate_result.decision, PolicyDecision.DENY)
        self.assertEqual(duplicate_result.reason_code, "malformed_policy_payload")
        self.assertNotIn("x" * 128, json.dumps(oversized_result.to_bounded_api_dict()))

    def test_non_mapping_inputs_fail_closed_without_secondary_exception(self):
        result = gate_access_request_payload([], _policy())  # type: ignore[arg-type]

        self.assertEqual(result.decision, PolicyDecision.DENY)
        self.assertEqual(result.corpus_ref, "corpus://atlas")
        self.assertEqual(result.reason_code, "malformed_policy_payload")

    def test_unknown_data_class_fails_closed(self):
        result = gate_access_request_payload(
            _request(data_classes=["assay-summary", "unreviewed-private-category"]),
            _policy(),
        )

        self.assertEqual(result.decision, PolicyDecision.DENY)
        self.assertEqual(result.reason_code, "unknown_data_class")
        rendered = json.dumps(result.to_public_dict(), sort_keys=True)
        self.assertNotIn("unreviewed-private-category", rendered)
        self.assertEqual(result.outcomes[-1].to_public_dict()["matched_category_count"], 1)

    def test_restricted_category_denies_at_stage_three(self):
        result = gate_access_request_payload(
            _request(data_classes=["de-novo-binder-design"]),
            _policy(),
        )

        self.assertEqual(result.decision, PolicyDecision.DENY)
        self.assertEqual(result.reason_code, "restricted_category")
        self.assertEqual(result.stage, 3)
        self.assertEqual(result.routed_role, "")

    def test_hold_route_for_review_category(self):
        result = gate_access_request_payload(
            _request(data_classes=["clinical-summary"]),
            _policy(),
        )

        self.assertEqual(result.decision, PolicyDecision.HOLD)
        self.assertEqual(result.reason_code, "review_required")
        self.assertEqual(result.stage, 3)
        self.assertEqual(result.routed_role, "expert-in-the-loop")

    def test_ambiguous_category_fails_closed_to_review_hold(self):
        result = gate_access_request_payload(
            _request(data_classes=["dual-use-uncertain"]),
            _policy(),
        )

        self.assertEqual(result.decision, PolicyDecision.HOLD)
        self.assertEqual(result.reason_code, "review_required")
        self.assertEqual(result.routed_role, "ethics-legal-reviewer")

    def test_unsupported_policy_version_fails_closed(self):
        result = gate_access_request_payload(
            _request(),
            _policy(version="policy-kernel/v999"),
        )

        self.assertEqual(result.decision, PolicyDecision.DENY)
        self.assertEqual(result.reason_code, "unsupported_policy_version")

    def test_explicit_falsy_versions_and_invalid_routes_are_bounded_denies(self):
        for value in (False, 0, "", None, [], {}):
            result = gate_access_request_payload(
                _request(), _policy(version=value)
            )
            self.assertEqual(result.decision, PolicyDecision.DENY, repr(value))
            self.assertEqual(result.reason_code, "malformed_policy_payload")

        for value in ([], {}, None, False, "private-reviewer-not-public"):
            result = gate_access_request_payload(
                _request(data_classes=["clinical-summary"]),
                _policy(hold_routes={"clinical-summary": value}),
            )
            self.assertEqual(result.decision, PolicyDecision.DENY, repr(value))
            self.assertEqual(result.reason_code, "malformed_policy_payload")

    def test_risk_tag_identities_are_bound_with_set_semantics(self):
        first = gate_access_request_payload(
            _request(risk_tags=["novel-biology", "manual-review"]),
            _policy(),
        )
        reordered = gate_access_request_payload(
            _request(risk_tags=["manual-review", "novel-biology"]),
            _policy(),
        )
        changed = gate_access_request_payload(
            _request(risk_tags=["different-risk", "manual-review"]),
            _policy(),
        )
        self.assertEqual(first.request_hash, reordered.request_hash)
        self.assertNotEqual(first.request_hash, changed.request_hash)

    def test_astral_unicode_expansion_respects_canonical_payload_limit(self):
        classes = ["🧬" * 60 + f"-{index}" for index in range(64)]
        result = gate_access_request_payload(
            _request(data_classes=[classes[0]]),
            _policy(known_data_classes=classes),
        )
        self.assertEqual(result.decision, PolicyDecision.DENY)
        self.assertEqual(result.reason_code, "malformed_policy_payload")
        self.assertEqual(result.stage, 0)

    def test_policy_result_normalizes_to_coordination_query(self):
        result = gate_access_request_payload(_request(), _policy())

        query = result.to_gated_query()

        self.assertEqual(query.decision, GateDecision.PASS)
        self.assertEqual(query.corpus_ref, "corpus://atlas")
        self.assertEqual(query.reason, "policy_passed")

    def test_gate_turn_requests_fans_out_to_coordination_gate_results(self):
        turn = Turn(
            turn_id="turn-1",
            by="agent",
            requester_ref="sponsor",
            purpose="rank-candidates",
            pipeline="sft-rerank",
            corpora=("corpus://atlas",),
            requests={
                "corpus://atlas": {
                    "data_classes": ["assay-summary"],
                    "output_schema": "score-band-v1",
                    "operations": ["score"],
                }
            },
        )
        policy = CorpusPolicy.from_dict(_policy())

        gate_results = gate_turn_requests(turn, {"corpus://atlas": policy})

        self.assertEqual(gate_results.turn_id, "turn-1")
        self.assertEqual(len(gate_results.queries), 1)
        self.assertEqual(gate_results.queries[0].decision, GateDecision.PASS)

    def test_gate_turn_requests_rejects_missing_or_extra_corpus_requests(self):
        turn = Turn(
            turn_id="turn-1",
            by="agent",
            requester_ref="sponsor",
            purpose="rank-candidates",
            pipeline="sft-rerank",
            corpora=("corpus://atlas",),
            requests={},
        )
        policy = CorpusPolicy.from_dict(_policy())

        with self.assertRaisesRegex(PolicyKernelError, "cover exactly"):
            gate_turn_requests(turn, {"corpus://atlas": policy})

    def test_policy_deny_beats_coordination_consent(self):
        participants = (
            Participant("owner-atlas", ParticipantRole.OWNER),
            Participant("sponsor", ParticipantRole.REQUESTER),
            Participant("agent", ParticipantRole.AGENT, owner_ref="sponsor"),
        )
        session = CollabSession(
            participants=participants,
            corpora=(Corpus("corpus://atlas", "owner-atlas", policy_hash="atlas-policy"),),
            consent_grants=(
                ConsentGrant("corpus://atlas", "owner-atlas", "sponsor", "rank-candidates", "sft-rerank"),
            ),
            delegation_grants=(
                DelegationGrant("agent", "sponsor", ("corpus://atlas",), ("rank-candidates",), ("sft-rerank",)),
            ),
        )
        turn = Turn(
            turn_id="turn-1",
            by="agent",
            requester_ref="sponsor",
            purpose="rank-candidates",
            pipeline="sft-rerank",
            corpora=("corpus://atlas",),
            requests={
                "corpus://atlas": {
                    "data_classes": ["de-novo-binder-design"],
                    "output_schema": "score-band-v1",
                    "operations": ["score"],
                }
            },
        )
        state = coordinate(CoordinationState(session), SubmitTurn(turn))
        gate_results = gate_turn_requests(turn, {"corpus://atlas": CorpusPolicy.from_dict(_policy())})

        state = coordinate(state, gate_results)

        self.assertEqual(state.turns["turn-1"].status, TurnStatus.DENIED)
        self.assertEqual(state.turns["turn-1"].status_reason, "restricted_denied")


if __name__ == "__main__":
    unittest.main()
