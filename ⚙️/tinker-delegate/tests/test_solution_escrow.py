import json
import unittest

from tinker_delegate.disclosure_policy import DisclosureMode, decide_disclosure
from tinker_delegate.solution_escrow import (
    SolutionEscrowError,
    SolutionEscrowStore,
)

_CANDIDATE = b"def solve(x):\n    return sorted(x)[1:-1]\n"
_AUTH = b"release-authorization-secret-xyz"


class SolutionEscrowStoreTest(unittest.TestCase):
    def test_seal_and_authorized_release_roundtrip(self):
        store = SolutionEscrowStore()
        receipt = store.seal(
            "escrow-1", _CANDIDATE, disclosure_mode=DisclosureMode.ESCROW, authorization=_AUTH
        )
        self.assertTrue(receipt.sealed)
        self.assertTrue(store.is_sealed("escrow-1"))
        self.assertEqual(store.release("escrow-1", authorization=_AUTH), _CANDIDATE)

    def test_wrong_authorization_fails_closed(self):
        store = SolutionEscrowStore()
        store.seal("escrow-1", _CANDIDATE, disclosure_mode=DisclosureMode.ESCROW, authorization=_AUTH)
        with self.assertRaises(SolutionEscrowError):
            store.release("escrow-1", authorization=b"wrong-secret")

    def test_only_escrow_mode_may_be_sealed(self):
        store = SolutionEscrowStore()
        for mode in (DisclosureMode.PUBLIC, DisclosureMode.HASH_ONLY, DisclosureMode.BLOCKED):
            with self.subTest(mode=mode):
                with self.assertRaises(SolutionEscrowError):
                    store.seal("e", _CANDIDATE, disclosure_mode=mode, authorization=_AUTH)

    def test_double_seal_rejected(self):
        store = SolutionEscrowStore()
        store.seal("escrow-1", _CANDIDATE, disclosure_mode=DisclosureMode.ESCROW, authorization=_AUTH)
        with self.assertRaises(SolutionEscrowError):
            store.seal("escrow-1", _CANDIDATE, disclosure_mode="escrow", authorization=_AUTH)

    def test_missing_inputs_rejected(self):
        store = SolutionEscrowStore()
        with self.assertRaises(SolutionEscrowError):
            store.seal("", _CANDIDATE, disclosure_mode=DisclosureMode.ESCROW, authorization=_AUTH)
        with self.assertRaises(SolutionEscrowError):
            store.seal("e", _CANDIDATE, disclosure_mode=DisclosureMode.ESCROW, authorization=b"")

    def test_release_unknown_escrow_fails(self):
        store = SolutionEscrowStore()
        with self.assertRaises(SolutionEscrowError):
            store.release("nope", authorization=_AUTH)

    def test_distinct_escrows_use_distinct_keys(self):
        store = SolutionEscrowStore()
        store.seal("a", _CANDIDATE, disclosure_mode=DisclosureMode.ESCROW, authorization=_AUTH)
        store.seal("b", _CANDIDATE, disclosure_mode=DisclosureMode.ESCROW, authorization=_AUTH)
        # Same plaintext + same authorization, but per-escrow keys/nonces differ.
        self.assertNotEqual(store._entries["a"].ciphertext, store._entries["b"].ciphertext)

    def test_receipt_and_manifest_are_bounded(self):
        store = SolutionEscrowStore()
        receipt = store.seal(
            "escrow-secret-ref", _CANDIDATE, disclosure_mode=DisclosureMode.ESCROW, authorization=_AUTH
        )
        public = receipt.to_public_dict()
        self.assertFalse(public["raw_secret_egress"])
        blob = json.dumps(public) + json.dumps(store.public_manifest())
        self.assertNotIn("escrow-secret-ref", blob)
        self.assertNotIn("def solve", blob)
        self.assertNotIn("release-authorization", blob)
        self.assertRegex(public["candidate_hash"], r"^0x[0-9a-f]{64}$")


class DisclosureToEscrowTest(unittest.TestCase):
    def test_escrow_decision_drives_a_real_seal(self):
        # A clean candidate without public permission -> ESCROW; the store then
        # physically seals it and only authorized release returns it.
        decision = decide_disclosure(_CANDIDATE)  # allow_public defaults False
        self.assertEqual(decision.mode, DisclosureMode.ESCROW)
        self.assertIsNone(decision.disclosable_payload(_CANDIDATE))  # not public

        store = SolutionEscrowStore()
        store.seal("deal-42", _CANDIDATE, disclosure_mode=decision.mode, authorization=_AUTH)
        self.assertEqual(store.release("deal-42", authorization=_AUTH), _CANDIDATE)


if __name__ == "__main__":
    unittest.main()
