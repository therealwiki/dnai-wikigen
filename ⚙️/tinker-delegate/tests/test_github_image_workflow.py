from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]


class GithubImageWorkflowTest(unittest.TestCase):
    def test_tee_image_workflow_builds_registry_attested_images(self):
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "build-tee-images.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("packages: write", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("artifact-metadata: write", workflow)
        self.assertIn("docker/login-action@v3", workflow)
        self.assertIn("docker/build-push-action@v6", workflow)
        self.assertIn("anchore/sbom-action@v0", workflow)
        self.assertIn("actions/attest@v4", workflow)
        self.assertIn("platforms: linux/amd64", workflow)
        self.assertIn("push: true", workflow)
        self.assertIn("provenance: mode=max", workflow)
        self.assertIn("sbom: true", workflow)
        self.assertIn("push-to-registry: true", workflow)
        self.assertIn("sbom-path: ${{ matrix.name }}.spdx.json", workflow)
        self.assertIn("context: ./⚙️/tinker-delegate", workflow)
        self.assertIn("context: ./⚙️/tee-email-oracle", workflow)
        self.assertIn("context: ./⚙️/tee-email-oracle/neko-chrome", workflow)
        self.assertIn("image_suffix: neko-chrome", workflow)
        self.assertIn("ghcr.io", workflow)

    def test_neko_chrome_base_image_is_digest_pinned(self):
        dockerfile = (
            REPO_ROOT / "⚙️" / "tee-email-oracle" / "neko-chrome" / "Dockerfile"
        ).read_text(encoding="utf-8")

        self.assertIn("FROM ghcr.io/m1k1o/neko/base@sha256:", dockerfile)
        self.assertNotIn("FROM ghcr.io/m1k1o/neko/base:latest", dockerfile)

    def test_attestation_verifier_script_enforces_signed_digest_policy(self):
        script = (
            REPO_ROOT
            / "⚙️"
            / "tinker-delegate"
            / "scripts"
            / "verify-ghcr-image-attestation.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("set -euo pipefail", script)
        self.assertIn("IMAGE_REF must be digest-pinned", script)
        self.assertIn("--bundle-from-oci", script)
        self.assertIn("--signer-workflow", script)
        self.assertIn("--source-digest", script)
        self.assertIn("--deny-self-hosted-runners", script)
        self.assertIn("https://slsa.dev/provenance/v1", script)
        self.assertIn("https://spdx.dev/Document/v2.3", script)


if __name__ == "__main__":
    unittest.main()
