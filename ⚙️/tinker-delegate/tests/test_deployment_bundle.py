from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from tinker_delegate.compose_hash import ImageDigest
from tinker_delegate.cvm_attestation import CvmAttestationBundle
from tinker_delegate.deployment_bundle import (
    DeploymentBundleError,
    DeploymentBundlePolicy,
    GithubImageAttestation,
    GithubImagePolicy,
    PROVENANCE_PREDICATE,
    SBOM_PREDICATE,
    image_digest,
    verify_deployment_bundle,
    verify_github_image,
)


IMAGE = "ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:" + "a" * 64
ORACLE_IMAGE = "ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:" + "b" * 64
SOURCE_DIGEST = "c" * 40


def _cvm_bundle() -> CvmAttestationBundle:
    return CvmAttestationBundle(
        api_url="https://tee.example",
        context="artifact",
        mode="tdx",
        compose_hash="d" * 64,
        attested_compose_hash="e" * 64,
        rendered_compose_sha256="f" * 64,
        images=(
            ImageDigest(service="delegate", image=IMAGE),
            ImageDigest(service="oracle", image=ORACLE_IMAGE),
        ),
        app_id="app-ok",
        os_image_hash="os-ok",
        report_data="1" * 64,
        encryption_public_key="2" * 64,
        quote_size=5010,
        fetched_at=123.0,
        quote_verification="public-envelope-only; Intel TDX quote internals not parsed",
    )


class DeploymentBundleTest(unittest.TestCase):
    def test_verify_github_image_requires_digest_pinned_refs(self):
        with self.assertRaisesRegex(DeploymentBundleError, "digest-pinned"):
            image_digest("ghcr.io/example/image:latest")

    def test_verify_github_image_checks_provenance_and_sbom_predicates(self):
        with patch("tinker_delegate.deployment_bundle.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

            result = verify_github_image(
                GithubImagePolicy(
                    image=IMAGE,
                    source_digest=SOURCE_DIGEST,
                    source_ref="refs/heads/main",
                )
            )

        self.assertEqual(run.call_count, 2)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertTrue(all(command[:3] == ["gh", "attestation", "verify"] for command in commands))
        self.assertIn(PROVENANCE_PREDICATE, commands[0])
        self.assertIn(SBOM_PREDICATE, commands[1])
        self.assertTrue(all("--bundle-from-oci" in command for command in commands))
        self.assertTrue(all("--deny-self-hosted-runners" in command for command in commands))
        self.assertTrue(all("--source-ref" in command for command in commands))
        self.assertEqual(result.provenance_attestation, "verified")
        self.assertEqual(result.sbom_attestation, "verified")

    def test_verify_github_image_fails_closed_on_attestation_error(self):
        with patch("tinker_delegate.deployment_bundle.subprocess.run") as run:
            run.side_effect = subprocess.CalledProcessError(
                1,
                ["gh"],
                stderr="attestation failed",
            )
            with self.assertRaisesRegex(DeploymentBundleError, "GitHub attestation"):
                verify_github_image(
                    GithubImagePolicy(image=IMAGE, source_digest=SOURCE_DIGEST)
                )

    def test_deployment_bundle_requires_github_images_in_cvm_policy(self):
        with (
            patch(
                "tinker_delegate.deployment_bundle.verify_github_image",
                side_effect=lambda policy: GithubImageAttestation(
                    image=policy.image,
                    repo=policy.repo,
                    signer_workflow=policy.signer_workflow,
                    source_digest=policy.source_digest,
                    source_ref=policy.source_ref,
                    provenance_attestation="verified",
                    sbom_attestation="verified",
                ),
            ),
            patch(
                "tinker_delegate.deployment_bundle.verify_cvm_attestation",
                return_value=_cvm_bundle(),
            ) as verify_cvm,
        ):
            bundle = verify_deployment_bundle(
                DeploymentBundlePolicy(
                    api_url="https://tee.example",
                    compose_path=Path("docker-compose.all.phala.yaml"),
                    images=(
                        GithubImagePolicy(image=IMAGE, source_digest=SOURCE_DIGEST),
                        GithubImagePolicy(image=ORACLE_IMAGE, source_digest=SOURCE_DIGEST),
                    ),
                    allowed_envs=("TINKER_DELEGATE_IMAGE", "TINKER_ORACLE_IMAGE"),
                    expected_attested_compose_hash="e" * 64,
                    expected_app_id="app-ok",
                    expected_os_image_hash="os-ok",
                    phala_raw_compose=True,
                )
            )

        verify_cvm.assert_called_once()
        cvm_policy = verify_cvm.call_args.args[0]
        self.assertEqual(cvm_policy.required_images, (IMAGE, ORACLE_IMAGE))
        self.assertEqual(
            cvm_policy.required_image_digests,
            ("sha256:" + "a" * 64, "sha256:" + "b" * 64),
        )
        self.assertEqual(cvm_policy.allowed_envs, ("TINKER_DELEGATE_IMAGE", "TINKER_ORACLE_IMAGE"))
        public = bundle.to_public_dict()
        self.assertEqual(public["schema"], "dnai.deployment.verification.v1")
        self.assertEqual(public["status"], "verified")
        self.assertEqual(public["checks"]["github_provenance_attestations"], "verified")
        self.assertFalse(public["checks"]["raw_secret_egress"])
        self.assertNotIn("app_compose", public["cvm"])
        self.assertNotIn("quote", public["cvm"])


if __name__ == "__main__":
    unittest.main()
