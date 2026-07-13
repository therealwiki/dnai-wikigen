"""Adversarial tests against the Tinker proxy JWT verification.

These do not trust the happy-path issuance tests: they hand-craft hostile tokens
(alg confusion, payload tampering, cross-key forgery, issuer/audience/nbf
spoofing, ttl inflation, scope escalation) and assert verification fails closed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import tempfile
import time
import unittest

from tinker_delegate.config import Settings
from tinker_delegate.tinker_proxy import (
    _proxy_signing_key,
    issue_proxy_token,
    verify_proxy_token,
)

ISS = "dnai-wikigen:tinker-proxy"
AUD = "dnai-wikigen:tinker-delegate"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _craft(payload: dict, key: bytes, *, alg: str = "HS256", sig: bytes | None = None) -> str:
    header = {"alg": alg, "typ": "JWT"}
    signing_input = (_b64(json.dumps(header).encode()) + "." + _b64(json.dumps(payload).encode())).encode()
    if sig is None:
        sig = b"" if alg == "none" else hmac.new(key, signing_input, hashlib.sha256).digest()
    return signing_input.decode() + "." + _b64(sig)


class TestProxyAdversarial(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.s = Settings(
            proxy_jwt_key="11" * 32,
            proxy_approved_subjects="",
            proxy_token_store_path=tmp + "/p.enc",
            proxy_token_store_key="22" * 32,
            proxy_jwt_max_ttl_seconds=3600,
        )
        self.key = _proxy_signing_key(self.s)
        self.now = int(time.time())
        self.good = {
            "iss": ISS, "aud": AUD, "sub": "u", "scope": "tinker:train",
            "iat": self.now, "nbf": self.now, "exp": self.now + 900, "jti": "jti-1",
        }

    def _expect_reject(self, token, scope="tinker:train"):
        with self.assertRaises(ValueError):
            verify_proxy_token(self.s, token, required_scope=scope)

    # sanity: a correctly-crafted token verifies (so rejections below are meaningful)
    def test_baseline_valid(self):
        v = verify_proxy_token(self.s, _craft(self.good, self.key), required_scope="tinker:train")
        self.assertTrue(v["valid"])

    def test_alg_none_rejected(self):
        self._expect_reject(_craft(self.good, self.key, alg="none"))

    def test_alg_confusion_rejected(self):
        # valid HMAC sig but header claims RS256 -> must be refused
        self._expect_reject(_craft(self.good, self.key, alg="RS256"))

    def test_empty_signature_rejected(self):
        self._expect_reject(_craft(self.good, self.key, sig=b""))

    def test_cross_key_forgery_rejected(self):
        attacker = hashlib.sha256(b"attacker-key").digest()
        self._expect_reject(_craft(self.good, attacker))

    def test_scope_escalation_tamper_rejected(self):
        # sign a low-priv token, then swap payload to add a spend scope, keep sig
        low = _craft(dict(self.good, scope="proxy:status"), self.key)
        h, _p, sig = low.split(".")
        hostile = dict(self.good, scope="proxy:status billing:add-balance")
        forged = f"{h}.{_b64(json.dumps(hostile).encode())}.{sig}"
        self._expect_reject(forged, scope="billing:add-balance")

    def test_wrong_issuer_rejected(self):
        self._expect_reject(_craft(dict(self.good, iss="evil"), self.key))

    def test_wrong_audience_rejected(self):
        self._expect_reject(_craft(dict(self.good, aud="evil"), self.key))

    def test_not_yet_valid_rejected(self):
        self._expect_reject(_craft(dict(self.good, nbf=self.now + 600, exp=self.now + 900), self.key))

    def test_expired_rejected(self):
        self._expect_reject(_craft(dict(self.good, iat=self.now - 1000, nbf=self.now - 1000, exp=self.now - 1), self.key))

    def test_missing_required_scope_rejected(self):
        self._expect_reject(_craft(self.good, self.key), scope="billing:add-balance")

    def test_malformed_token_rejected(self):
        for bad in ("", "a.b", "a.b.c.d", "not-a-jwt", "..", "a..c"):
            self._expect_reject(bad)

    # issuance-side guards
    def test_ttl_inflation_clamped(self):
        claims, _tok = issue_proxy_token(self.s, subject="u", scopes=["tinker:train"], ttl_seconds=10 ** 9)
        self.assertLessEqual(claims.expires_at - claims.issued_at, self.s.proxy_jwt_max_ttl_seconds)

    def test_unknown_scope_rejected_at_issue(self):
        with self.assertRaises(ValueError):
            issue_proxy_token(self.s, subject="u", scopes=["admin:everything"])

    def test_empty_subject_rejected_at_issue(self):
        with self.assertRaises(ValueError):
            issue_proxy_token(self.s, subject="   ", scopes=["tinker:train"])


if __name__ == "__main__":
    unittest.main()
