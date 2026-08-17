from pathlib import Path
import re
import unittest

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]


class GithubImageWorkflowTest(unittest.TestCase):
    def test_publication_graph_is_structurally_main_only_and_source_gated(self):
        workflow_path = REPO_ROOT / ".github" / "workflows" / "build-tee-images.yml"
        workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        triggers = workflow.get("on", workflow.get(True))

        self.assertEqual(triggers, {"push": {"branches": ["main"]}})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(
            workflow["jobs"]["source-gate"],
            {
                "name": "Verify exact release source",
                "uses": "./.github/workflows/ci.yml",
                "permissions": {"contents": "read"},
            },
        )
        self.assertEqual(workflow["jobs"]["build"]["needs"], "source-gate")
        self.assertEqual(workflow["jobs"]["release"]["needs"], "build")
        self.assertEqual(
            workflow["jobs"]["release"]["if"],
            "github.event_name == 'push' && github.ref == 'refs/heads/main'",
        )

        publication_actions = (
            "docker/login-action@",
            "docker/build-push-action@",
            "actions/attest@",
        )
        for job_name, job in workflow["jobs"].items():
            action_uses = [
                step.get("uses", "")
                for step in job.get("steps", [])
                if isinstance(step, dict)
            ]
            if any(
                action.startswith(prefix)
                for action in action_uses
                for prefix in publication_actions
            ):
                self.assertIn(job_name, {"build", "release"})
                expected_dependency = "source-gate" if job_name == "build" else "build"
                self.assertEqual(job["needs"], expected_dependency)

    def test_tee_image_publication_requires_the_complete_exact_source_ci_gate(self):
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "build-tee-images.yml"
        ).read_text(encoding="utf-8")
        ci_workflow = (
            REPO_ROOT / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("workflow_call:", ci_workflow)
        self.assertIn("run: node --test scripts/*.test.mjs", ci_workflow)
        self.assertIn("source-gate:", workflow)
        self.assertIn("name: Verify exact release source", workflow)
        self.assertIn("uses: ./.github/workflows/ci.yml", workflow)
        self.assertRegex(
            workflow,
            r"(?ms)^  build:\n    name: Build \$\{\{ matrix\.name \}\}\n"
            r"    needs: source-gate\n",
        )

    def test_tee_image_workflow_builds_registry_attested_images(self):
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "build-tee-images.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("packages: write", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("artifact-metadata: write", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn('      - "codex/**"', workflow)
        self.assertNotIn('      - "tinker-*"', workflow)
        self.assertNotIn('      - "v*"', workflow)
        self.assertRegex(workflow, r"docker/login-action@[0-9a-f]{40} # v3")
        self.assertRegex(workflow, r"docker/build-push-action@[0-9a-f]{40} # v6")
        self.assertRegex(workflow, r"anchore/sbom-action@[0-9a-f]{40} # v0")
        self.assertRegex(workflow, r"actions/attest@[0-9a-f]{40} # v4")
        self.assertNotRegex(workflow, r"uses: [^\n]+@v[0-9]+(?:\s|$)")
        self.assertIn("platforms: linux/amd64", workflow)
        self.assertIn("version: v0.29.1", workflow)
        self.assertIn(
            "driver-opts: image=moby/buildkit:v0.25.2@sha256:"
            "0f63d66f8d2de0bd16438284831a3e9ee6ca7cd57b6eb3ed6e38a7a456590fa7",
            workflow,
        )
        self.assertIn('SOURCE_DATE_EPOCH: "1735689600"', workflow)
        self.assertIn('SOURCE_DATE_RFC3339: "2025-01-01T00:00:00Z"', workflow)
        self.assertIn(
            "org.opencontainers.image.created=${{ env.SOURCE_DATE_RFC3339 }}",
            workflow,
        )
        self.assertIn("SOURCE_DATE_EPOCH=${{ env.SOURCE_DATE_EPOCH }}", workflow)
        self.assertIn("outputs: type=image,push=true,rewrite-timestamp=true", workflow)
        self.assertNotIn("type=ref,event=branch", workflow)
        self.assertNotIn("type=raw,value=latest", workflow)
        self.assertNotRegex(workflow, r"(?m)^\s+push: true\s*$")
        self.assertIn("provenance: false", workflow)
        self.assertIn("sbom: false", workflow)
        self.assertNotIn("provenance: mode=max", workflow)
        self.assertNotRegex(workflow, r"(?m)^\s+sbom: true\s*$")
        self.assertIn(
            "buildkit-inline-sbom: disabled-for-reproducible-subject", workflow
        )
        self.assertIn(
            "buildkit-inline-provenance: disabled-for-reproducible-subject",
            workflow,
        )
        self.assertNotIn("buildkit-sbom: registry-attached", workflow)
        self.assertNotIn("buildkit-provenance: registry-attached", workflow)
        self.assertIn("push-to-registry: true", workflow)
        self.assertEqual(workflow.count("create-storage-record: false"), 2)
        self.assertIn("sbom-path: ${{ matrix.name }}.spdx.json", workflow)
        self.assertIn("syft-version: v1.44.0", workflow)
        self.assertIn("context: ./⚙️/tinker-delegate", workflow)
        self.assertIn("context: ./⚙️/tee-email-oracle", workflow)
        self.assertIn("context: ./⚙️/tee-email-oracle/neko-chrome", workflow)
        self.assertIn("image_suffix: neko-chrome", workflow)
        self.assertIn("context: ./⚙️/attestation-qvl", workflow)
        self.assertIn("image_suffix: attestation-qvl", workflow)
        self.assertIn("context: ./⚙️/compute-metering", workflow)
        self.assertIn("image_suffix: compute-metering", workflow)
        matrix_names = re.findall(r"^\s{10}- name: ([a-z0-9-]+)$", workflow, re.MULTILINE)
        self.assertEqual(
            matrix_names,
            [
                "tinker-delegate",
                "tee-email-oracle",
                "neko-chrome",
                "attestation-qvl",
                "compute-metering",
            ],
        )
        self.assertIn("ghcr.io", workflow)

    def test_release_job_verifies_and_aggregates_exact_image_evidence(self):
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "build-tee-images.yml"
        ).read_text(encoding="utf-8")

        self.assertNotRegex(workflow, r"(?m)^\s{4}paths:\s*$")
        self.assertIn("name: Assemble verified TEE image release", workflow)
        self.assertIn("needs: build", workflow)
        self.assertIn(
            "if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
            workflow,
        )
        self.assertNotIn("startsWith(github.ref, 'refs/tags/v')", workflow)
        self.assertIn("packages: read", workflow)
        self.assertIn("actions: read", workflow)
        self.assertIn("verification-plan", workflow)
        self.assertIn("verify-ghcr-image-attestation.sh", workflow)
        self.assertIn("--source-digest", workflow)
        self.assertIn("--source-ref", workflow)
        self.assertIn("--signer-workflow", workflow)
        self.assertIn("--deny-self-hosted-runners", (
            REPO_ROOT
            / "⚙️"
            / "tinker-delegate"
            / "scripts"
            / "verify-ghcr-image-attestation.sh"
        ).read_text(encoding="utf-8"))
        self.assertIn("dnai-tee-image-release.json", workflow)
        self.assertIn("--sboms release-sboms", workflow)
        self.assertIn("release-sboms/*.spdx.json", workflow)
        self.assertIn("verified-images/*.json", workflow)
        self.assertIn("subject-path: dnai-tee-image-release.json", workflow)
        self.assertIn(
            "RELEASE_BUNDLE_PATH: ${{ steps.release_provenance.outputs.bundle-path }}",
            workflow,
        )
        self.assertIn("dnai-tee-image-release.bundle.json", workflow)
        self.assertIn("name: dnai-tee-image-release-${{ github.sha }}", workflow)

    def test_neko_chrome_base_image_is_digest_pinned(self):
        dockerfile = (
            REPO_ROOT / "⚙️" / "tee-email-oracle" / "neko-chrome" / "Dockerfile"
        ).read_text(encoding="utf-8")

        self.assertIn("FROM ghcr.io/m1k1o/neko/base@sha256:", dockerfile)
        self.assertNotIn("FROM ghcr.io/m1k1o/neko/base:latest", dockerfile)
        self.assertIn("google-chrome-stable_150.0.7871.114-1_amd64.deb", dockerfile)
        self.assertIn(
            "0f19e68dca574849632e25229f15853d2beac33fa06498feed43f34628bc2d53",
            dockerfile,
        )
        self.assertIn("sha256sum -c -", dockerfile)
        self.assertNotIn("google-chrome-stable_current_amd64.deb", dockerfile)

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
        self.assertIn('REPO="therealwiki/dnai-wikigen"', script)
        self.assertIn(
            'WORKFLOW="therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml"',
            script,
        )
        self.assertNotIn("G-structure/dnai-wikigen", script)


if __name__ == "__main__":
    unittest.main()
