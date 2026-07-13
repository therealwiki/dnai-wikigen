from pathlib import Path
import unittest
from unittest.mock import patch

from tinker_delegate.attestation_verifier import AttestationVerificationResult
from tinker_delegate.compose_hash import ComposeHashResult, ImageDigest
from tinker_delegate.cvm_attestation import (
    CvmAttestationError,
    CvmAttestationPolicy,
    verify_cvm_attestation,
)


def _compose_result() -> ComposeHashResult:
    return ComposeHashResult(
        compose_hash="c" * 64,
        rendered_compose_sha256="d" * 64,
        images=(
            ImageDigest(
                service="delegate",
                image="ghcr.io/example/delegate@sha256:" + "e" * 64,
            ),
        ),
        app_compose={
            "runner": "docker-compose",
            "docker_compose_file": "services:\n  delegate:\n    image: hidden\n",
        },
    )


def _attestation_result() -> AttestationVerificationResult:
    return AttestationVerificationResult(
        mode="tdx",
        report_context="artifact",
        encryption_public_key="a" * 64,
        report_data="b" * 64,
        quote_size=256,
        compose_hash="c" * 64,
        app_id="app-ok",
        os_image_hash="os-ok",
        fetched_at=123.0,
    )


class CvmAttestationTest(unittest.TestCase):
    def test_verifies_compose_images_before_live_attestation(self):
        with (
            patch(
                "tinker_delegate.cvm_attestation.verify_compose_hash",
                return_value=_compose_result(),
            ) as verify_compose,
            patch(
                "tinker_delegate.cvm_attestation.fetch_and_verify_attestation",
                return_value=_attestation_result(),
            ) as fetch_attestation,
        ):
            bundle = verify_cvm_attestation(
                CvmAttestationPolicy(
                    api_url="https://tee.example",
                    compose_path=Path("docker-compose.all.phala.yaml"),
                    env_files=(Path(".env.phala"),),
                    allowed_env_file=Path("runtime.env"),
                    allowed_envs=("TINKER_ORACLE_IMAGE",),
                    expected_compose_hash="c" * 64,
                    expected_attested_compose_hash="c" * 64,
                    expected_app_id="app-ok",
                    expected_os_image_hash="os-ok",
                    required_image_digests=("sha256:" + "e" * 64,),
                    phala_raw_compose=True,
                )
            )

        verify_compose.assert_called_once()
        _, kwargs = verify_compose.call_args
        self.assertEqual(kwargs["expected_hash"], "c" * 64)
        self.assertEqual(kwargs["env_files"], [Path(".env.phala")])
        self.assertEqual(kwargs["allowed_env_file"], Path("runtime.env"))
        self.assertEqual(kwargs["allowed_envs"], ["TINKER_ORACLE_IMAGE"])
        self.assertTrue(kwargs["phala_raw_compose"])

        fetch_attestation.assert_called_once()
        _, attestation_args = fetch_attestation.call_args[0]
        self.assertEqual(attestation_args.expected_compose_hash, "c" * 64)
        self.assertEqual(attestation_args.expected_app_id, "app-ok")
        self.assertFalse(attestation_args.allow_local)

        public = bundle.to_public_dict()
        self.assertEqual(public["mode"], "tdx")
        self.assertEqual(public["attested_compose_hash"], "c" * 64)
        self.assertEqual(public["quote_size"], 256)
        self.assertEqual(public["images"][0]["service"], "delegate")
        self.assertNotIn("app_compose", public)
        self.assertNotIn("quote", public)
        self.assertIn("Intel TDX quote internals not parsed", public["quote_verification"])

    def test_rejects_missing_required_image_digest(self):
        with patch(
            "tinker_delegate.cvm_attestation.verify_compose_hash",
            return_value=_compose_result(),
        ):
            with self.assertRaisesRegex(CvmAttestationError, "missing required image digest"):
                verify_cvm_attestation(
                    CvmAttestationPolicy(
                        api_url="https://tee.example",
                        compose_path=Path("compose.yaml"),
                        required_image_digests=("f" * 64,),
                    )
                )

    def test_rejects_invalid_required_image_digest(self):
        with patch(
            "tinker_delegate.cvm_attestation.verify_compose_hash",
            return_value=_compose_result(),
        ):
            with self.assertRaisesRegex(CvmAttestationError, "invalid sha256 digest"):
                verify_cvm_attestation(
                    CvmAttestationPolicy(
                        api_url="https://tee.example",
                        compose_path=Path("compose.yaml"),
                        required_image_digests=("not-a-digest",),
                    )
                )

    def test_operator_script_wraps_fail_closed_cli(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "verify-cvm-attestation.sh"
        source = script.read_text(encoding="utf-8")

        self.assertIn("set -euo pipefail", source)
        self.assertIn("verify-cvm-attestation", source)
        self.assertIn("Use --allow-local-attestation only for local development", source)
        self.assertNotIn("--allow-local-attestation \"$@\"", source)


if __name__ == "__main__":
    unittest.main()
