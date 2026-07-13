import tempfile
import unittest
from pathlib import Path

from email_oracle.replay_store import OtpReplayStore


class OtpReplayStoreTest(unittest.TestCase):
    def test_round_trips_encrypted_replay_hashes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "otp_replay.enc"
            key = "00" * 32

            store = OtpReplayStore(str(path), key_hex=key)
            store.save({"hash-b", "hash-a"})

            self.assertNotIn(b"hash-a", path.read_bytes())
            self.assertNotIn(b"hash-b", path.read_bytes())

            reloaded = OtpReplayStore(str(path), key_hex=key)
            self.assertEqual(reloaded.load(), {"hash-a", "hash-b"})

    def test_missing_replay_file_loads_empty_set(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "missing.enc"
            store = OtpReplayStore(str(path), key_hex="11" * 32)

            self.assertEqual(store.load(), set())


if __name__ == "__main__":
    unittest.main()
