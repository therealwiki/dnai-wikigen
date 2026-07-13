import json
import unittest

from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.consent_receipt import (
    ConsentReceiptError,
    build_consent_decision_receipt,
    consent_decision_signature_hash,
)


def _state_payload(*, grants=None, status="awaiting-consent"):
    grants = grants or []
    return {
        "session": {
            "participants": [
                {"ref": "owner-atlas", "role": "owner"},
                {"ref": "owner-halcyon", "role": "owner"},
                {"ref": "sponsor", "role": "requester"},
                {"ref": "cro-agent", "role": "agent", "owner_ref": "sponsor"},
            ],
            "corpora": [
                {
                    "ref": "corpus://atlas",
                    "owner_ref": "owner-atlas",
                    "policy_hash": "atlas-policy",
                    "royalty_per_query": 1000,
                },
                {
                    "ref": "corpus://halcyon",
                    "owner_ref": "owner-halcyon",
                    "policy_hash": "halcyon-policy",
                    "royalty_per_query": 2000,
                },
            ],
            "consent_grants": grants,
            "delegation_grants": [
                {
                    "agent_ref": "cro-agent",
                    "grantor_ref": "sponsor",
                    "corpora": ["corpus://atlas", "corpus://halcyon"],
                    "purposes": ["rank-candidates"],
                    "pipelines": ["sft-rerank"],
                }
            ],
            "consent_quorum": "unanimous",
        },
        "turns": {
            "turn-1": {
                "turn": {
                    "turn_id": "turn-1",
                    "by": "cro-agent",
                    "requester_ref": "sponsor",
                    "purpose": "rank-candidates",
                    "pipeline": "sft-rerank",
                    "corpora": ["corpus://atlas", "corpus://halcyon"],
                    "requests": {
                        "corpus://atlas": {"purpose": "rank-candidates"},
                        "corpus://halcyon": {"purpose": "rank-candidates"},
                    },
                },
                "status": status,
                "queries": [
                    {"corpus_ref": "corpus://atlas", "decision": "pass", "stage": 4, "reason": "ok"},
                    {"corpus_ref": "corpus://halcyon", "decision": "pass", "stage": 4, "reason": "ok"},
                ],
                "status_reason": "missing_consent",
            }
        },
        "revoked_corpora": [],
    }


def _grant(corpus_ref, owner_ref):
    return {
        "corpus_ref": corpus_ref,
        "owner_ref": owner_ref,
        "requester_ref": "sponsor",
        "purpose": "rank-candidates",
        "pipeline": "sft-rerank",
    }


def _signed_decision(state, decision, account):
    decision_hash = consent_decision_signature_hash(state, decision)
    signed = account.sign_message(encode_defunct(hexstr="0x" + decision_hash))
    return {
        **decision,
        "signature": {
            "kind": "ethereum_signed_message",
            "signer": account.address,
            "decision_hash": "0x" + decision_hash,
            "signature": "0x" + bytes(signed.signature).hex(),
        },
    }


class ConsentReceiptTest(unittest.TestCase):
    def test_grant_receipt_settles_when_quorum_is_met(self):
        receipt = build_consent_decision_receipt(
            _state_payload(grants=[_grant("corpus://atlas", "owner-atlas")]),
            {
                "turn_id": "turn-1",
                "corpus_ref": "corpus://halcyon",
                "owner_ref": "owner-halcyon",
                "decision": "grant",
                "expires_at": 100,
            },
        )

        self.assertEqual(receipt["surface"], "coordination_consent_decision")
        self.assertEqual(receipt["action"], "settle_bounded_result")
        self.assertEqual(receipt["turn"]["status_before"], "awaiting-consent")
        self.assertEqual(receipt["turn"]["status_after"], "settled")
        self.assertEqual(receipt["quorum"]["grant_count_before"], 1)
        self.assertEqual(receipt["quorum"]["grant_count_after"], 2)
        self.assertTrue(receipt["quorum"]["settled"])
        self.assertFalse(receipt["raw_secret_egress"])
        rendered = json.dumps(receipt, sort_keys=True)
        self.assertNotIn("rank-candidates", rendered)
        self.assertNotIn("sft-rerank", rendered)
        self.assertNotIn("owner-halcyon", rendered)
        self.assertNotIn("ok", rendered)

    def test_grant_receipt_waits_below_quorum(self):
        receipt = build_consent_decision_receipt(
            _state_payload(),
            {
                "turn_id": "turn-1",
                "corpus_ref": "corpus://atlas",
                "owner_ref": "owner-atlas",
                "decision": "grant",
            },
        )

        self.assertEqual(receipt["action"], "await_more_consent")
        self.assertEqual(receipt["turn"]["status_after"], "awaiting-consent")
        self.assertEqual(receipt["quorum"]["grant_count_after"], 1)
        self.assertFalse(receipt["quorum"]["settled"])

    def test_deny_receipt_is_terminal(self):
        receipt = build_consent_decision_receipt(
            _state_payload(),
            {
                "turn_id": "turn-1",
                "corpus_ref": "corpus://atlas",
                "owner_ref": "owner-atlas",
                "decision": "deny",
            },
        )

        self.assertEqual(receipt["action"], "deny")
        self.assertEqual(receipt["turn"]["status_after"], "denied")
        self.assertEqual(receipt["turn"]["status_reason_after"], "consent_denied")
        self.assertEqual(receipt["quorum"]["grant_count_after"], 0)

    def test_unknown_state_fields_fail_closed(self):
        state = _state_payload()
        state["session"]["raw_private_note"] = "do not leak"

        with self.assertRaisesRegex(ConsentReceiptError, "unknown session field"):
            build_consent_decision_receipt(
                state,
                {
                    "turn_id": "turn-1",
                    "corpus_ref": "corpus://atlas",
                    "owner_ref": "owner-atlas",
                    "decision": "grant",
                },
            )

    def test_required_owner_signature_verifies_without_raw_signature_egress(self):
        account = Account.from_key("0x" + "11" * 32)
        decision = _signed_decision(
            _state_payload(grants=[_grant("corpus://atlas", "owner-atlas")]),
            {
                "turn_id": "turn-1",
                "corpus_ref": "corpus://halcyon",
                "owner_ref": "owner-halcyon",
                "decision": "grant",
                "expires_at": 100,
            },
            account,
        )

        receipt = build_consent_decision_receipt(
            _state_payload(grants=[_grant("corpus://atlas", "owner-atlas")]),
            decision,
            require_signature=True,
            expected_signer=account.address,
        )

        binding = receipt["signature_binding"]
        self.assertTrue(binding["required"])
        self.assertTrue(binding["provided"])
        self.assertTrue(binding["verified"])
        self.assertTrue(binding["signer_matches_expected"])
        self.assertFalse(binding["signature_returned"])
        self.assertFalse(binding["signer_address_returned"])
        self.assertFalse(binding["raw_secret_egress"])
        self.assertEqual(receipt["action"], "settle_bounded_result")
        rendered = json.dumps(receipt, sort_keys=True)
        self.assertNotIn(account.address, rendered)
        self.assertNotIn(account.address.lower(), rendered)
        self.assertNotIn(decision["signature"]["signature"], rendered)
        self.assertNotIn("owner-halcyon", rendered)

    def test_required_owner_signature_missing_fails_closed(self):
        with self.assertRaisesRegex(ConsentReceiptError, "signature is required"):
            build_consent_decision_receipt(
                _state_payload(),
                {
                    "turn_id": "turn-1",
                    "corpus_ref": "corpus://atlas",
                    "owner_ref": "owner-atlas",
                    "decision": "grant",
                },
                require_signature=True,
            )

    def test_owner_signature_wrong_expected_signer_fails_closed(self):
        signer = Account.from_key("0x" + "11" * 32)
        other = Account.from_key("0x" + "22" * 32)
        decision = _signed_decision(
            _state_payload(),
            {
                "turn_id": "turn-1",
                "corpus_ref": "corpus://atlas",
                "owner_ref": "owner-atlas",
                "decision": "grant",
            },
            signer,
        )

        with self.assertRaisesRegex(ConsentReceiptError, "not expected owner"):
            build_consent_decision_receipt(
                _state_payload(),
                decision,
                require_signature=True,
                expected_signer=other.address,
            )

    def test_owner_signature_hash_mismatch_fails_closed(self):
        signer = Account.from_key("0x" + "11" * 32)
        decision = _signed_decision(
            _state_payload(),
            {
                "turn_id": "turn-1",
                "corpus_ref": "corpus://atlas",
                "owner_ref": "owner-atlas",
                "decision": "grant",
            },
            signer,
        )
        decision["signature"]["decision_hash"] = "0x" + "00" * 32

        with self.assertRaisesRegex(ConsentReceiptError, "hash mismatch"):
            build_consent_decision_receipt(
                _state_payload(),
                decision,
                require_signature=True,
                expected_signer=signer.address,
            )


if __name__ == "__main__":
    unittest.main()
