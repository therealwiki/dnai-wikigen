import json
import unittest

from tinker_delegate.policy_gate_receipt import (
    build_policy_gate_receipt,
    build_policy_turn_gate_receipt,
)


def _request(**overrides):
    payload = {
        "request_id": "request-1",
        "requester_ref": "agent://buyer",
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
        "known_data_classes": ["assay-summary", "clinical-summary", "de-novo-binder-design"],
        "restricted_categories": ["de-novo-binder-design"],
        "hold_categories": ["clinical-summary"],
        "ambiguous_categories": [],
        "hold_routes": {"clinical-summary": "expert-in-the-loop"},
    }
    payload.update(overrides)
    return payload


class PolicyGateReceiptTest(unittest.TestCase):
    def test_single_policy_gate_receipt_is_bounded(self):
        receipt = build_policy_gate_receipt(
            _request(data_classes=["clinical-summary"]),
            _policy(),
        )

        self.assertEqual(receipt["surface"], "conseca_policy_gate")
        self.assertEqual(receipt["mode"], "single_corpus")
        self.assertTrue(receipt["evaluated"])
        self.assertEqual(receipt["decision"], "hold")
        self.assertEqual(receipt["action"], "route_to_review")
        self.assertFalse(receipt["raw_policy_egress"])
        rendered = json.dumps(receipt, sort_keys=True)
        self.assertNotIn("clinical-summary", rendered)
        self.assertNotIn("rank-candidates", rendered)
        self.assertIn("expert-in-the-loop", rendered)

    def test_turn_policy_gate_receipt_aggregates_deny(self):
        turn = {
            "turn_id": "turn-1",
            "by": "agent",
            "requester_ref": "agent://buyer",
            "purpose": "rank-candidates",
            "pipeline": "sft-rerank",
            "corpora": ["corpus://atlas", "corpus://halcyon"],
            "requests": {
                "corpus://atlas": {
                    "data_classes": ["assay-summary"],
                    "output_schema": "score-band-v1",
                    "operations": ["score"],
                },
                "corpus://halcyon": {
                    "data_classes": ["de-novo-binder-design"],
                    "output_schema": "score-band-v1",
                    "operations": ["score"],
                },
            },
        }
        policies = {
            "corpus://atlas": _policy(corpus_ref="corpus://atlas", policy_id="policy-atlas"),
            "corpus://halcyon": _policy(corpus_ref="corpus://halcyon", policy_id="policy-halcyon"),
        }

        receipt = build_policy_turn_gate_receipt(turn, policies)

        self.assertEqual(receipt["mode"], "coordination_turn_fanout")
        self.assertEqual(receipt["decision"], "deny")
        self.assertEqual(receipt["action"], "deny")
        self.assertEqual(receipt["gate_results"]["query_count"], 2)
        self.assertEqual(receipt["gate_results"]["queries"][1]["decision"], "deny")
        rendered = json.dumps(receipt, sort_keys=True)
        self.assertNotIn("de-novo-binder-design", rendered)
        self.assertNotIn("rank-candidates", rendered)
        self.assertFalse(receipt["raw_secret_egress"])


if __name__ == "__main__":
    unittest.main()
