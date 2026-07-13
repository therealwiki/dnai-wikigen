import dataclasses
import json
import unittest

from tinker_delegate.private_reward import assert_bounded_egress
from tinker_delegate.transcript_log import (
    _GENESIS_PREV,
    TranscriptEntry,
    TranscriptLogger,
    event_hash,
    verify_chain,
)


def _events(n: int) -> list[dict]:
    return [
        {"candidate_hash": f"{i:064x}", "decision": "pass", "reward_band": "medium"}
        for i in range(n)
    ]


class TranscriptLoggerTest(unittest.TestCase):
    def test_empty_log_head_is_genesis(self):
        logger = TranscriptLogger()
        self.assertEqual(logger.head, _GENESIS_PREV)
        self.assertEqual(len(logger), 0)
        self.assertTrue(logger.verify())

    def test_append_chains_and_verifies(self):
        logger = TranscriptLogger()
        for event in _events(5):
            logger.append(event)
        self.assertEqual(len(logger), 5)
        self.assertTrue(logger.verify())
        # First entry links to genesis; each links to the previous chain hash.
        entries = logger.entries
        self.assertEqual(entries[0].prev_hash, _GENESIS_PREV)
        for i in range(1, 5):
            self.assertEqual(entries[i].prev_hash, entries[i - 1].chain_hash)
        self.assertEqual(logger.head, entries[-1].chain_hash)

    def test_head_advances_with_each_append(self):
        logger = TranscriptLogger()
        heads = []
        for event in _events(3):
            logger.append(event)
            heads.append(logger.head)
        self.assertEqual(len(set(heads)), 3)  # all distinct

    def test_chain_is_deterministic(self):
        a, b = TranscriptLogger(), TranscriptLogger()
        for event in _events(4):
            a.append(event)
            b.append(event)
        self.assertEqual(a.head, b.head)

    def test_order_sensitive(self):
        events = _events(3)
        a, b = TranscriptLogger(), TranscriptLogger()
        for event in events:
            a.append(event)
        for event in reversed(events):
            b.append(event)
        self.assertNotEqual(a.head, b.head)

    def test_tampered_event_breaks_verification(self):
        logger = TranscriptLogger()
        for event in _events(4):
            logger.append(event)
        tampered = list(logger.entries)
        # Forge entry 1's event hash but keep its chain hash: chain no longer holds.
        tampered[1] = dataclasses.replace(tampered[1], event_hash=event_hash({"forged": True}))
        self.assertFalse(verify_chain(tampered))

    def test_deleted_entry_breaks_verification(self):
        logger = TranscriptLogger()
        for event in _events(4):
            logger.append(event)
        without_middle = list(logger.entries)
        del without_middle[2]  # index gap + broken prev link
        self.assertFalse(verify_chain(without_middle))

    def test_reordered_entries_break_verification(self):
        logger = TranscriptLogger()
        for event in _events(4):
            logger.append(event)
        swapped = list(logger.entries)
        swapped[1], swapped[2] = swapped[2], swapped[1]
        self.assertFalse(verify_chain(swapped))

    def test_public_dict_is_bounded(self):
        logger = TranscriptLogger()
        for event in _events(3):
            logger.append(event)
        public = logger.to_public_dict()
        assert_bounded_egress(public)
        self.assertFalse(public["raw_secret_egress"])
        self.assertEqual(public["length"], 3)
        # Only hashes/indices — no candidate payloads.
        blob = json.dumps(public)
        self.assertNotIn("payload", blob)

    def test_verify_chain_rejects_bad_index(self):
        entry = TranscriptEntry(index=5, event_hash="ab" * 32, prev_hash="00" * 32, chain_hash="cd" * 32)
        self.assertFalse(verify_chain([entry]))


if __name__ == "__main__":
    unittest.main()
