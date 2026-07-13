import tempfile
import unittest
from pathlib import Path

from tinker_delegate.api_key_store import ApiKeyStore


class ApiKeyStoreTest(unittest.TestCase):
    def test_round_trips_encrypted_api_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "tinker_api_key.enc"
            key = "22" * 32
            api_key = "tml-secret-key-material"

            store = ApiKeyStore(str(path), key_hex=key)
            store.save(api_key)

            self.assertTrue(path.exists())
            self.assertNotIn(api_key.encode(), path.read_bytes())

            reloaded = ApiKeyStore(str(path), key_hex=key)
            self.assertEqual(reloaded.load(), api_key)

    def test_fresh_nonce_per_save_no_reuse_under_fixed_key(self):
        # The store encrypts under a FIXED key, so a fresh AES-GCM nonce per save
        # is load-bearing: re-saving the same key MUST produce different bytes
        # (fresh nonce), or a future fixed-nonce regression would be a catastrophic
        # nonce-reuse break for the most sensitive secret. The nonce is prepended,
        # so the leading 12 bytes and the whole file must differ across saves.
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "tinker_api_key.enc"
            key = "22" * 32
            api_key = "tml-secret-key-material"

            store = ApiKeyStore(str(path), key_hex=key)
            store.save(api_key)
            first = path.read_bytes()
            store.save(api_key)
            second = path.read_bytes()

            self.assertNotEqual(first[:12], second[:12], "nonce was reused across saves")
            self.assertNotEqual(first, second)
            # Still decrypts correctly after re-save.
            self.assertEqual(ApiKeyStore(str(path), key_hex=key).load(), api_key)


if __name__ == "__main__":
    unittest.main()
