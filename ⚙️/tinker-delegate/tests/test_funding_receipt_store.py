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


if __name__ == "__main__":
    unittest.main()
