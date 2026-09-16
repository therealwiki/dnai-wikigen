import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tinker_delegate.active_deal_recovery import (
    ActiveDealRecoveryError,
    ActiveDealRecoveryStore,
)
from tinker_delegate.artifacts import artifact_commitment
from tinker_delegate.control_plane import ControlPlane, DealState, ScoreBand


BUYER = "0x" + "22" * 20
SELLER = "0x" + "11" * 20
POLICY = "0x" + "44" * 32


async def _deterministic_evaluator(**_kwargs):
    return {"quality_delta": 0.12, "private_note": "must never persist publicly"}


_deterministic_evaluator.requires_tinker_session = False


class ActiveDealRecoveryTest(unittest.TestCase):
    def _funded(self, store, *, deal_id="7"):
        artifact = b"seller-private restart-recovery payload"
        secret = bytes(range(32))
        commitment = artifact_commitment(artifact, secret)
        cp = ControlPlane(
            "",
            enable_tinker_session=False,
            active_deal_store=store,
        )
        cp.on_deal_funded(
            deal_id,
            buyer=BUYER,
            seller=SELLER,
            budget_cap=10**18,
            reserve_price=10**16,
            committed_artifact_hash=commitment,
            evaluator_policy_commitment=POLICY,
        )
        cp.receive_artifact(deal_id, artifact, commitment, secret)
        return cp, artifact, secret

    def test_restart_recovers_sealed_artifact_and_interrupted_run_as_fresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "active.sealed"
            key = b"k" * 32
            cp, artifact, _secret = self._funded(
                ActiveDealRecoveryStore(path, key=key)
            )
            cp._deals["7"].state = DealState.EVALUATING
            cp._persist_active_deals()

            encoded = path.read_text(encoding="ascii")
            self.assertNotIn(artifact.decode("ascii"), encoded)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

            restarted = ControlPlane(
                "",
                enable_tinker_session=False,
                active_deal_store=ActiveDealRecoveryStore(path, key=key),
            )
            recovered = restarted.get_deal_context("7")
            self.assertEqual(recovered.state, DealState.PENDING_ARTIFACT)
            self.assertEqual(bytes(recovered.artifact), artifact)
            self.assertEqual(
                recovered.recovery_status,
                "interrupted_evaluation_recovered_fresh_run_required",
            )

    def test_bounded_result_survives_restart_but_reorg_destroys_private_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "active.sealed"
            key = b"r" * 32
            cp, artifact, _secret = self._funded(
                ActiveDealRecoveryStore(path, key=key)
            )
            original_buffer = cp._deals["7"].artifact
            with patch.object(
                cp,
                "_get_tdx_quote",
                return_value=b"test-only-modeled-quote",
            ):
                result = asyncio.run(
                    cp.evaluate("7", _deterministic_evaluator)
                )
            self.assertEqual(result.score_band, ScoreBand.HIGH)

            restarted = ControlPlane(
                "",
                enable_tinker_session=False,
                active_deal_store=ActiveDealRecoveryStore(path, key=key),
            )
            self.assertEqual(
                restarted.get_result("7").score_band,
                ScoreBand.HIGH,
            )
            restarted_buffer = restarted.get_deal_context("7").artifact
            restarted.on_chain_reorg("7")
            self.assertEqual(
                restarted_buffer,
                bytearray(len(artifact)),
            )
            self.assertNotIn("7", restarted.active_deals)
            after = ControlPlane(
                "",
                enable_tinker_session=False,
                active_deal_store=ActiveDealRecoveryStore(path, key=key),
            )
            self.assertEqual(after.active_deals, [])
            # The prior process buffer is separate and remains owned by that
            # process; this assertion ensures the reorg path zeroed its own.
            self.assertEqual(bytes(original_buffer), artifact)

    def test_wrong_key_tamper_and_unsafe_mode_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "active.sealed"
            store = ActiveDealRecoveryStore(path, key=b"a" * 32)
            store.save({"7": {"opaque_test_entry": True}})

            with self.assertRaises(ActiveDealRecoveryError):
                ActiveDealRecoveryStore(path, key=b"b" * 32).load()

            blob = bytearray(path.read_bytes())
            blob[-8] ^= 1
            path.write_bytes(blob)
            os.chmod(path, 0o600)
            with self.assertRaises(ActiveDealRecoveryError):
                ActiveDealRecoveryStore(path, key=b"a" * 32).load()

            path.write_bytes(b"{}")
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(
                ActiveDealRecoveryError,
                "safety",
            ):
                ActiveDealRecoveryStore(path, key=b"a" * 32).load()


if __name__ == "__main__":
    unittest.main()
