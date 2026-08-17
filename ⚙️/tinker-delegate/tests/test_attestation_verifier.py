import time
import unittest

import httpx

from tinker_delegate.attestation_verifier import (
    AttestationPolicy,
    AttestationVerificationError,
    fetch_and_verify_attestation,
    verify_attestation_envelope,
)
from tinker_delegate.card_channel import get_attestation


def _tdx_attestation() -> dict:
    attestation = get_attestation("artifact")
    attestation.update({
        "mode": "tdx",
        "verified": True,
        "quote": "aa",
        "compose_hash": "compose-ok",
        "app_id": "app-ok",
        "os_image_hash": "os-ok",
    })
    return attestation


class AttestationVerifierTest(unittest.TestCase):
    def test_rejects_service_evidence_without_independent_verification_verdict(self):
        attestation = _tdx_attestation()
        attestation["verified"] = False

        with self.assertRaisesRegex(
            AttestationVerificationError,
            "cryptographic attestation verdict is unavailable",
        ):
            verify_attestation_envelope(
                attestation,
                AttestationPolicy(expected_compose_hash="compose-ok"),
            )

    def test_simulator_evidence_cannot_pass_a_production_policy(self):
        attestation = _tdx_attestation()
        attestation["mode"] = "simulator"
        # Even a malicious/self-asserted flag cannot upgrade modeled evidence.
        attestation["verified"] = True

        with self.assertRaisesRegex(
            AttestationVerificationError,
            "attestation mode must be tdx",
        ):
            verify_attestation_envelope(
                attestation,
                AttestationPolicy(expected_compose_hash="compose-ok"),
            )

    def test_rejects_forbidden_or_unexpected_public_fields(self):
        attestation = _tdx_attestation()
        sentinel = "sentinel-runtime-auth-secret"
        attestation["tcb_info"] = {
            "app_compose": {
                "docker_compose_file": f"TINKER_RUNTIME_AUTH_TOKEN={sentinel}",
            },
        }

        with self.assertRaisesRegex(
            AttestationVerificationError,
            "forbidden or unexpected fields: tcb_info",
        ):
            verify_attestation_envelope(
                attestation,
                AttestationPolicy(expected_compose_hash="compose-ok"),
            )

    def test_tdx_requires_expected_compose_hash(self):
        with self.assertRaisesRegex(AttestationVerificationError, "expected compose hash"):
            verify_attestation_envelope(_tdx_attestation(), AttestationPolicy())

    def test_rejects_os_image_hash_mismatch(self):
        with self.assertRaisesRegex(AttestationVerificationError, "OS image hash mismatch"):
            verify_attestation_envelope(
                _tdx_attestation(),
                AttestationPolicy(
                    expected_compose_hash="compose-ok",
                    expected_os_image_hash="os-other",
                ),
            )

    def test_rejects_stale_fetched_evidence(self):
        with self.assertRaisesRegex(AttestationVerificationError, "stale"):
            verify_attestation_envelope(
                _tdx_attestation(),
                AttestationPolicy(expected_compose_hash="compose-ok", max_age_seconds=5),
                fetched_at=100,
                now=106,
            )

    def test_accepts_matching_quote_report_data_when_exposed(self):
        attestation = _tdx_attestation()
        attestation["quote_report_data"] = attestation["report_data"]

        result = verify_attestation_envelope(
            attestation,
            AttestationPolicy(expected_compose_hash="compose-ok"),
        )

        self.assertEqual(result.report_data, attestation["report_data"])

    def test_accepts_matching_64_byte_quote_report_data_when_exposed(self):
        attestation = _tdx_attestation()
        attestation["quote_report_data"] = attestation["report_data"] + ("00" * 32)

        result = verify_attestation_envelope(
            attestation,
            AttestationPolicy(expected_compose_hash="compose-ok"),
        )

        self.assertEqual(result.report_data, attestation["report_data"])

    def test_rejects_quote_report_data_mismatch_when_exposed(self):
        attestation = _tdx_attestation()
        attestation["quote_report_data"] = "00" * 32

        with self.assertRaisesRegex(AttestationVerificationError, "quote report data mismatch"):
            verify_attestation_envelope(
                attestation,
                AttestationPolicy(expected_compose_hash="compose-ok"),
            )

    def test_rejects_malformed_quote_report_data_when_exposed(self):
        attestation = _tdx_attestation()
        attestation["quote_report_data"] = "aa"

        with self.assertRaisesRegex(AttestationVerificationError, "quote_report_data must be 32 or 64 bytes"):
            verify_attestation_envelope(
                attestation,
                AttestationPolicy(expected_compose_hash="compose-ok"),
            )

    def test_fetch_and_verify_returns_bounded_evidence(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.method, "GET")
            self.assertEqual(request.url.path, "/attestation")
            self.assertEqual(request.url.params["context"], "artifact")
            return httpx.Response(200, json=_tdx_attestation())

        before = time.time()
        result = fetch_and_verify_attestation(
            "https://tee.example",
            AttestationPolicy(
                expected_compose_hash="compose-ok",
                expected_app_id="app-ok",
                expected_os_image_hash="os-ok",
            ),
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        self.assertEqual(result.mode, "tdx")
        self.assertEqual(result.compose_hash, "compose-ok")
        self.assertEqual(result.app_id, "app-ok")
        self.assertEqual(result.os_image_hash, "os-ok")
        self.assertEqual(result.quote_size, 1)
        self.assertGreaterEqual(result.fetched_at, before)
        self.assertEqual(len(bytes.fromhex(result.encryption_public_key)), 32)


if __name__ == "__main__":
    unittest.main()
