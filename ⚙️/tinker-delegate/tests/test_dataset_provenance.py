"""Seal-time attested provenance: a signed distribution claim bound to the commitment.

A distribution claim ("representative of benchmark X") is only trustworthy if it
was committed at seal time and signed — not asserted afterward. Because the
provenance lives inside the manifest before it is hashed and signed, any tampering
breaks the signature.
"""
import copy
import unittest

from eth_account import Account

from tinker_delegate.sealed_dataset import (
    DataSensitivity,
    SealedDatasetError,
    build_provenance,
    generate_recipient_keypair,
    manifest_hash,
    seal_dataset,
    sign_manifest,
    verify_dataset_provenance,
    verify_manifest,
)

_KEY = "11" * 32
_ADDR = Account.from_key(_KEY).address


def _prov(benchmark="openproblems-denoising-v1"):
    return build_provenance(
        source_pipeline="openproblems-etl",
        upstream_id="op-denoising-2024",
        license="CC-BY-4.0",
        distribution_claim="representative_of_benchmark",
        benchmark_ref=benchmark,
    )


def _sealed(provenance=None, dataset_id="d1"):
    _priv, pub = generate_recipient_keypair()
    _blob, manifest, _rcpt = seal_dataset(
        b'{"x":1}',
        dataset_id=dataset_id,
        task="denoise",
        data_sensitivity=DataSensitivity.PUBLIC_BENCHMARK,
        recipient_public_keys=[pub],
        provenance=provenance,
    )
    return manifest


class BuildProvenanceTest(unittest.TestCase):
    def test_requires_all_core_fields(self):
        with self.assertRaises(SealedDatasetError):
            build_provenance(
                source_pipeline="", upstream_id="u", license="l",
                distribution_claim="c", benchmark_ref="b",
            )

    def test_extra_must_be_scalar(self):
        with self.assertRaises(SealedDatasetError):
            build_provenance(
                source_pipeline="p", upstream_id="u", license="l",
                distribution_claim="c", benchmark_ref="b",
                extra={"nested": {"not": "scalar"}},
            )


class DatasetProvenanceTest(unittest.TestCase):
    def test_unsigned_provenance_is_not_attested(self):
        manifest = _sealed(_prov())
        verdict = verify_dataset_provenance(manifest)
        self.assertFalse(verdict["ok"])
        self.assertIn("provenance_not_signed", verdict["problems"])

    def test_signed_provenance_binds_and_matches_benchmark(self):
        signed, _ = sign_manifest(_sealed(_prov()), _KEY)
        verdict = verify_dataset_provenance(
            signed, expected_signer=_ADDR, expected_benchmark="openproblems-denoising-v1"
        )
        self.assertTrue(verdict["ok"])
        self.assertTrue(verdict["provenance_signed"])
        self.assertTrue(verdict["benchmark_match"])
        self.assertFalse(verdict["raw_secret_egress"])

    def test_benchmark_mismatch_fails(self):
        signed, _ = sign_manifest(_sealed(_prov()), _KEY)
        verdict = verify_dataset_provenance(signed, expected_benchmark="other-benchmark")
        self.assertFalse(verdict["ok"])
        self.assertIn("benchmark_claim_mismatch", verdict["problems"])

    def test_tampering_claim_after_signing_breaks_binding(self):
        signed, _ = sign_manifest(_sealed(_prov()), _KEY)
        tampered = copy.deepcopy(signed)
        tampered["provenance"]["benchmark_ref"] = "faked-benchmark"
        verdict = verify_dataset_provenance(tampered, expected_signer=_ADDR)
        self.assertFalse(verdict["ok"])
        # The signature no longer recovers over the (changed) manifest hash.
        self.assertIn("owner_signature_hash_mismatch", verdict["problems"])

    def test_missing_provenance_fails_closed(self):
        signed, _ = sign_manifest(_sealed(provenance=None), _KEY)
        verdict = verify_dataset_provenance(signed)
        self.assertFalse(verdict["ok"])
        self.assertIn("missing_provenance", verdict["problems"])

    def test_incomplete_provenance_fails_closed(self):
        manifest = _sealed(_prov())
        del manifest["provenance"]["license"]
        signed, _ = sign_manifest(manifest, _KEY)
        verdict = verify_dataset_provenance(signed)
        self.assertFalse(verdict["ok"])
        self.assertIn("incomplete_provenance", verdict["problems"])

    def test_provenance_does_not_change_when_absent_backward_compat(self):
        # A manifest sealed without provenance hashes as before (no `provenance`
        # key), so existing signatures/commitments are unaffected.
        manifest = _sealed(provenance=None)
        self.assertNotIn("provenance", manifest)
        # verify_manifest still works over a provenance-bearing manifest too.
        report = verify_manifest(_sealed(_prov()))
        self.assertTrue(report["ok"])

    def test_provenance_is_covered_by_manifest_hash(self):
        without = _sealed(provenance=None, dataset_id="same")
        with_prov = _sealed(_prov(), dataset_id="same")
        # Same dataset id but the provenance-bearing manifest commits to a
        # different hash — the claim is part of the commitment.
        self.assertNotEqual(manifest_hash(without), manifest_hash(with_prov))


if __name__ == "__main__":
    unittest.main()
