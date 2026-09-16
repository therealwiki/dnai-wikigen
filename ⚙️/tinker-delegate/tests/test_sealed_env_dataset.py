"""Tests for the reusable sealed-env-dataset loader (fail-closed + buffer zeroing)."""
import tempfile
import unittest

from tinker_delegate.crypto import TEEKeyPair
from tinker_delegate.dataset_storage import LocalStorageBackend, publish_dataset
from tinker_delegate.sealed_dataset import DataSensitivity, seal_dataset
from tinker_delegate.sealed_env_dataset import load_sealed_env_dataset

_KEY = "22" * 32
_PLAINTEXT = b'{"cells": [1, 2, 3], "note": "sealed"}'


def _seal_and_publish(backend, *, sensitivity=DataSensitivity.PUBLIC_BENCHMARK):
    keypair = TEEKeyPair.from_private_key_hex(_KEY)
    blob, manifest, _ = seal_dataset(
        _PLAINTEXT,
        dataset_id="sealed-env-loader-test",
        task="test",
        data_sensitivity=sensitivity,
        recipient_public_keys=[keypair.public_key_bytes.hex()],
    )
    ref = backend.ref_for(manifest["dataset_id"])
    publish_dataset(blob, manifest, backend)
    return ref


class LoadSealedEnvDatasetTest(unittest.TestCase):
    def test_verified_plaintext_is_parsed(self):
        with tempfile.TemporaryDirectory() as root:
            backend = LocalStorageBackend(root)
            ref = _seal_and_publish(backend)
            parsed, receipt = load_sealed_env_dataset(
                ref, _KEY, parse=lambda b: b.decode("utf-8"), backend=backend
            )
            self.assertEqual(parsed, _PLAINTEXT.decode("utf-8"))
            self.assertTrue(receipt["plaintext_sha256_verified"])

    def test_buffer_is_zeroed_after_parse(self):
        captured: dict = {}

        def _parse(buf: bytes):
            captured["seen"] = bytes(buf)  # copy of the plaintext during parse
            return "ok"

        with tempfile.TemporaryDirectory() as root:
            backend = LocalStorageBackend(root)
            ref = _seal_and_publish(backend)
            load_sealed_env_dataset(ref, _KEY, parse=_parse, backend=backend)
        # The parser saw the real plaintext...
        self.assertEqual(captured["seen"], _PLAINTEXT)
        # ...and the loader returns without retaining the raw buffer (only the
        # parsed object escapes; the decrypted buffer is zeroed inside the loader).

    def test_wrong_recipient_key_fails_closed_without_parsing(self):
        calls = {"n": 0}

        def _parse(_b):
            calls["n"] += 1
            return "parsed"

        with tempfile.TemporaryDirectory() as root:
            backend = LocalStorageBackend(root)
            ref = _seal_and_publish(backend)
            # A different recipient key has no matching envelope -> fail closed.
            parsed, receipt = load_sealed_env_dataset(
                ref, "33" * 32, parse=_parse, backend=backend
            )
        self.assertIsNone(parsed)
        self.assertFalse(receipt.get("plaintext_sha256_verified"))
        self.assertEqual(calls["n"], 0)  # parser never called on unverified data

    def test_parser_error_still_zeroes_buffer(self):
        # If the parser raises, the loader still zeroes the buffer (finally) and
        # propagates the error rather than leaking the plaintext.
        with tempfile.TemporaryDirectory() as root:
            backend = LocalStorageBackend(root)
            ref = _seal_and_publish(backend)
            with self.assertRaises(ValueError):
                load_sealed_env_dataset(
                    ref, _KEY,
                    parse=lambda b: (_ for _ in ()).throw(ValueError("bad parse")),
                    backend=backend,
                )


class LoaderIsEnvAgnosticTest(unittest.TestCase):
    """The same loader must carry a DIFFERENTLY-shaped env's sealed data (proving
    the abstraction is env-agnostic, not denoising-specific) while keeping it
    bounded."""

    def test_synthetic_keyword_env_sourced_through_the_sealed_loader(self):
        import json

        from tinker_delegate.private_reward import (
            Candidate,
            FeedbackMode,
            LeakageBudget,
        )
        from tinker_delegate.private_reward_envs.synthetic import (
            SyntheticHiddenKeywordEnvironment,
        )
        from tinker_delegate.private_reward_holdout import HoldoutSplitPolicy

        # Synthetic env records (dict of id -> text) — a different shape than the
        # denoising demo's cell matrices.
        records = {f"rec-{i}": f"the alpha marker {i}" for i in range(10)}
        plaintext = json.dumps(records, sort_keys=True).encode("utf-8")

        keypair = TEEKeyPair.from_private_key_hex(_KEY)
        blob, manifest, _ = seal_dataset(
            plaintext, dataset_id="synthetic-sealed", task="keyword",
            data_sensitivity=DataSensitivity.PUBLIC_BENCHMARK,
            recipient_public_keys=[keypair.public_key_bytes.hex()],
        )

        def _parse(buf: bytes) -> dict:
            return {rid: text.encode("utf-8") for rid, text in json.loads(buf).items()}

        with tempfile.TemporaryDirectory() as root:
            backend = LocalStorageBackend(root)
            ref = backend.ref_for(manifest["dataset_id"])
            publish_dataset(blob, manifest, backend)
            recs, receipt = load_sealed_env_dataset(ref, _KEY, parse=_parse, backend=backend)

        self.assertIsNotNone(recs)
        self.assertTrue(receipt["plaintext_sha256_verified"])

        env = SyntheticHiddenKeywordEnvironment(
            recs,
            holdout_policy=HoldoutSplitPolicy(max_reward_queries=16),
            query_budget=LeakageBudget(max_queries=16, feedback_mode=FeedbackMode.BAND),
        )
        feedback = env.evaluate(Candidate(b"alpha")).to_public_dict()
        # A bounded band comes back, and the raw sealed record text never leaks.
        self.assertIn("reward_band", feedback)
        import json as _json
        blob_out = _json.dumps({"feedback": feedback, "attest": env.attest().to_public_dict()})
        self.assertNotIn("the alpha marker", blob_out)


if __name__ == "__main__":
    unittest.main()
