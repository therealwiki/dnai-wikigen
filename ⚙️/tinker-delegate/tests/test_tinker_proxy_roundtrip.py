"""Full proxy round-trip: issue -> encrypt -> decrypt -> verify -> revoke.

Complements the unit-level proxy tests with an end-to-end exercise of the
issuance/verification path using an explicit HS256 key (no dstack), locking in
scope enforcement, forgery/expiry rejection, revocation, and the bounded
(hash-only) issuance surface.
"""
from __future__ import annotations

import os
import tempfile
import time
import unittest

from tinker_delegate.config import Settings
from tinker_delegate.tinker_proxy import (
    decrypt_encrypted_proxy_token,
    generate_proxy_recipient_keypair,
    issue_encrypted_proxy_token,
    issue_proxy_token,
    verify_proxy_token,
)
from tinker_delegate.tinker_proxy_store import build_proxy_token_store


def _settings(tmp: str, jwt_key: str = "11" * 32) -> Settings:
    return Settings(
        proxy_jwt_key=jwt_key,
        proxy_approved_subjects="",
        proxy_token_store_path=os.path.join(tmp, f"proxy_tokens_{jwt_key[:4]}.enc"),
        proxy_token_store_key="22" * 32,
        proxy_jwt_default_ttl_seconds=900,
        proxy_jwt_max_ttl_seconds=3600,
    )


class TestProxyRoundTrip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.settings = _settings(self.tmp)
        self.priv, self.pub = generate_proxy_recipient_keypair()
        self.resp = issue_encrypted_proxy_token(
            self.settings,
            subject="downstream-user-1",
            scopes=["tinker:train"],
            recipient_public_key_hex=self.pub,
            ttl_seconds=900,
        )

    def test_issuance_is_bounded(self):
        self.assertTrue(self.resp.get("success"))
        self.assertTrue(self.resp.get("encrypted_token"))
        # Public token metadata is hashes only — no raw subject or JWT.
        tok = self.resp["token"]
        self.assertIn("subject_hash", tok)
        self.assertNotIn("subject", tok)
        self.assertFalse(self.resp.get("plaintext_token_returned"))

    def test_decrypt_and_verify_correct_scope(self):
        jwt = decrypt_encrypted_proxy_token(self.resp, self.priv)
        self.assertEqual(jwt.count("."), 2)
        v = verify_proxy_token(self.settings, jwt, required_scope="tinker:train")
        self.assertTrue(v["valid"])
        self.assertIn("subject_hash", v)
        self.assertNotIn("sub", {k for k in v})  # no raw subject key

    def test_wrong_scope_rejected(self):
        jwt = decrypt_encrypted_proxy_token(self.resp, self.priv)
        with self.assertRaises(ValueError):
            verify_proxy_token(self.settings, jwt, required_scope="billing:add-balance")

    def test_forged_signature_rejected(self):
        jwt = decrypt_encrypted_proxy_token(self.resp, self.priv)
        other = _settings(self.tmp, jwt_key="33" * 32)
        with self.assertRaises(ValueError):
            verify_proxy_token(other, jwt, required_scope="tinker:train")

    def test_expired_rejected(self):
        _, jwt_exp = issue_proxy_token(
            self.settings, subject="u", scopes=["tinker:train"],
            ttl_seconds=1, now=int(time.time()) - 10,
        )
        with self.assertRaises(ValueError):
            verify_proxy_token(self.settings, jwt_exp, required_scope="tinker:train")

    def test_revocation_rejected(self):
        jwt = decrypt_encrypted_proxy_token(self.resp, self.priv)
        # sanity: valid before revoke
        verify_proxy_token(self.settings, jwt, required_scope="tinker:train")
        build_proxy_token_store(self.settings).revoke(
            self.resp["token"]["jwt_id_hash"], reason="test"
        )
        with self.assertRaises(ValueError):
            verify_proxy_token(self.settings, jwt, required_scope="tinker:train")


if __name__ == "__main__":
    unittest.main()
