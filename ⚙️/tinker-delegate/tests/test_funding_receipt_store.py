import json
import os
import tempfile
import unittest
from pathlib import Path

from tinker_delegate.automation_receipts import (
    AutomationOutcome,
    AutomationStage,
    AutomationSurface,
    make_receipt,
)
from tinker_delegate.funding_receipt_store import FundingReceiptStore


def _receipt():
    return make_receipt(
        surface=AutomationSurface.PAYMENT_METHOD,
        outcome=AutomationOutcome.CARD_DECLINED,
        furthest_stage=AutomationStage.PAYMENT_SUBMITTED,
        evidence="card_number=4242424242424242 cvc=123",
        bounded_message="Your card was declined.",
        card_payload_destroyed=True,
    ).to_public_dict()


class FundingReceiptStoreTest(unittest.TestCase):
    def test_round_trips_encrypted_bounded_receipts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "funding_receipts.enc"
            key = "33" * 32
            receipt = _receipt()

            store = FundingReceiptStore(str(path), key_hex=key)
            persisted = store.append(receipt)

            self.assertEqual(persisted["outcome"], "card_declined")
            self.assertTrue(path.exists())
            self.assertNotIn(b"card_declined", path.read_bytes())
            self.assertNotIn(b"4242424242424242", path.read_bytes())

            reloaded = FundingReceiptStore(str(path), key_hex=key)
            self.assertEqual(reloaded.load(), [persisted])

    def test_rejects_forbidden_receipt_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "funding_receipts.enc"
            store = FundingReceiptStore(str(path), key_hex="44" * 32)
            receipt = _receipt()
            receipt["raw_page_text"] = "do not persist this"

            with self.assertRaisesRegex(ValueError, "forbidden fields"):
                store.append(receipt)

    def test_rejects_raw_secret_egress_true(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "funding_receipts.enc"
            store = FundingReceiptStore(str(path), key_hex="55" * 32)
            receipt = _receipt()
            receipt["raw_secret_egress"] = True

            with self.assertRaisesRegex(ValueError, "raw_secret_egress=false"):
                store.append(receipt)

    def test_rejects_private_sentence_as_bounded_message(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FundingReceiptStore(
                str(Path(tmpdir) / "funding_receipts.enc"), key_hex="66" * 32
            )
            receipt = _receipt()
            receipt["bounded_message"] = (
                "Your card 4242424242424242 failed at https://stripe.example/private"
            )

            with self.assertRaisesRegex(ValueError, "must equal its outcome code"):
                store.append(receipt)

    def test_rejects_hash_that_does_not_match_bounded_projection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FundingReceiptStore(
                str(Path(tmpdir) / "funding_receipts.enc"), key_hex="77" * 32
            )
            receipt = _receipt()
            receipt["amount_band"] = "5_25_usd"

            with self.assertRaisesRegex(ValueError, "does not match"):
                store.append(receipt)

    def test_load_fails_closed_on_encrypted_legacy_private_message(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "funding_receipts.enc"
            store = FundingReceiptStore(str(path), key_hex="88" * 32)
            receipt = _receipt()
            receipt["bounded_message"] = "secret page sentence from a browser"
            plaintext = json.dumps({"funding_receipts": [receipt]}).encode()
            nonce = os.urandom(12)
            path.write_bytes(nonce + store._aesgcm.encrypt(nonce, plaintext, None))

            with self.assertRaisesRegex(ValueError, "must equal its outcome code"):
                store.load()


if __name__ == "__main__":
    unittest.main()
