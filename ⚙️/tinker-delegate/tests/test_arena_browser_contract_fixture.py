"""Keep the default browser parser fixture tied to the current API generator."""

import json
from pathlib import Path
import unittest

from tinker_delegate.arena_ingress import (
    ArenaIngressRecipient,
    arena_candidate_browser_contract,
)
from tinker_delegate.crypto import TEEKeyPair


class ArenaBrowserContractFixtureTest(unittest.TestCase):
    def test_public_contract_matches_shared_browser_fixture(self):
        # Public interoperability vector only; no persisted key or live recipient.
        recipient = ArenaIngressRecipient.from_keypair(
            TEEKeyPair.from_private_key_hex(bytes(range(1, 33)).hex())
        )
        fixture_path = (
            Path(__file__).resolve().parents[3]
            / "web/src/lib/fixtures/arena-candidate-encryption-contract.v1.json"
        )
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.assertEqual(arena_candidate_browser_contract(recipient), fixture)


if __name__ == "__main__":
    unittest.main()
