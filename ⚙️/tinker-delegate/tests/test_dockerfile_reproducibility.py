from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
EPOCH = "1735689600"

DOCKERFILES = {
    "tinker-delegate": REPO_ROOT / "⚙️" / "tinker-delegate" / "Dockerfile",
    "tee-email-oracle": REPO_ROOT / "⚙️" / "tee-email-oracle" / "Dockerfile",
    "neko-chrome": (
        REPO_ROOT / "⚙️" / "tee-email-oracle" / "neko-chrome" / "Dockerfile"
    ),
    "attestation-qvl": REPO_ROOT / "⚙️" / "attestation-qvl" / "Dockerfile",
    "compute-metering": REPO_ROOT / "⚙️" / "compute-metering" / "Dockerfile",
}


class DockerfileReproducibilityTest(unittest.TestCase):
    def test_every_production_stage_and_tool_image_is_digest_pinned(self):
        for name, path in DOCKERFILES.items():
            with self.subTest(image=name):
                dockerfile = path.read_text(encoding="utf-8")
                epoch_declaration = f"ARG SOURCE_DATE_EPOCH={EPOCH}"
                self.assertIn(epoch_declaration, dockerfile)
                self.assertLess(dockerfile.index(epoch_declaration), dockerfile.index("FROM "))
                image_references = re.findall(
                    r"^(?:FROM\s+|COPY --from=)(\S+)", dockerfile, re.MULTILINE
                )
                self.assertGreater(len(image_references), 0)
                for image in image_references:
                    if image in {"builder", "runtime"}:
                        continue
                    self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")

    def test_python_images_use_frozen_noneditable_normalized_venvs(self):
        for name in (
            "tinker-delegate",
            "tee-email-oracle",
            "attestation-qvl",
            "compute-metering",
        ):
            with self.subTest(image=name):
                dockerfile = DOCKERFILES[name].read_text(encoding="utf-8")
                self.assertIn("UV_PROJECT_ENVIRONMENT=/.venv", dockerfile)
                self.assertIn("UV_COMPILE_BYTECODE=0", dockerfile)
                self.assertIn("UV_LINK_MODE=copy", dockerfile)
                self.assertRegex(
                    dockerfile,
                    r"uv sync --frozen --no-dev(?: --extra agent)? --no-editable",
                )
                self.assertIn("--sort=name --format=gnu", dockerfile)
                self.assertIn('--mtime="@${SOURCE_DATE_EPOCH}"', dockerfile)
                self.assertIn("find /.venv -type d -name __pycache__", dockerfile)

    def test_live_debian_indexes_are_replaced_before_install(self):
        expectations = {
            "tinker-delegate": (
                "20260623T000000Z",
                ("curl=8.14.1-2+deb13u3",),
            ),
            "tee-email-oracle": (
                "20260623T000000Z",
                ("tesseract-ocr=5.5.0-1+b1", "curl=8.14.1-2+deb13u3"),
            ),
            "neko-chrome": (
                "20260406T000000Z",
                ("openbox=3.6.1-12+b2", "nginx=1.26.3-3+deb13u2"),
            ),
        }
        for name, (snapshot, packages) in expectations.items():
            with self.subTest(image=name):
                dockerfile = DOCKERFILES[name].read_text(encoding="utf-8")
                snapshot_url = f"https://snapshot.debian.org/archive/debian/{snapshot}"
                security_url = (
                    f"https://snapshot.debian.org/archive/debian-security/{snapshot}"
                )
                self.assertIn(snapshot_url, dockerfile)
                self.assertIn(security_url, dockerfile)
                self.assertIn("Acquire::Check-Valid-Until=false", dockerfile)
                self.assertLess(dockerfile.index(snapshot_url), dockerfile.index("apt-get install"))
                for package in packages:
                    self.assertIn(package, dockerfile)
                self.assertIn(
                    "rm -rf /var/lib/apt/lists/* /var/cache/apt/* "
                    "/var/cache/ldconfig/* /var/log/apt/*",
                    dockerfile,
                )
                self.assertIn("rm -f /var/log/dpkg.log", dockerfile)
                if name == "neko-chrome":
                    self.assertIn("/var/log/alternatives.log", dockerfile)

    def test_chrome_download_is_exact_and_checksum_gated(self):
        dockerfile = DOCKERFILES["neko-chrome"].read_text(encoding="utf-8")
        self.assertIn("google-chrome-stable_150.0.7871.114-1_amd64.deb", dockerfile)
        self.assertIn(
            "0f19e68dca574849632e25229f15853d2beac33fa06498feed43f34628bc2d53",
            dockerfile,
        )
        self.assertIn("sha256sum -c -", dockerfile)
        self.assertNotIn("google-chrome-stable_current_amd64.deb", dockerfile)

    def test_sensitive_or_unrelated_files_are_not_in_release_contexts(self):
        expected = {
            REPO_ROOT / "⚙️" / "tinker-delegate" / ".dockerignore": [
                "**",
                "!Dockerfile",
                "!pyproject.toml",
                "!uv.lock",
                "!tinker_delegate/",
                "!tinker_delegate/**",
                "tinker_delegate/**/__pycache__/",
                "tinker_delegate/**/*.pyc",
            ],
            REPO_ROOT / "⚙️" / "tee-email-oracle" / ".dockerignore": [
                "**",
                "!Dockerfile",
                "!pyproject.toml",
                "!uv.lock",
                "!email_oracle/",
                "!email_oracle/**",
                "!captcha-solver/",
                "!captcha-solver/pyproject.toml",
                "!captcha-solver/captcha_solver/",
                "!captcha-solver/captcha_solver/**",
                "email_oracle/**/__pycache__/",
                "email_oracle/**/*.pyc",
                "captcha-solver/captcha_solver/**/__pycache__/",
                "captcha-solver/captcha_solver/**/*.pyc",
            ],
            REPO_ROOT
            / "⚙️"
            / "tee-email-oracle"
            / "neko-chrome"
            / ".dockerignore": [
                "**",
                "!Dockerfile",
                "!supervisord.conf",
                "!preferences.json",
                "!policies.json",
                "!openbox.xml",
                "!nginx-cdp.conf",
            ],
            REPO_ROOT / "⚙️" / "attestation-qvl" / ".dockerignore": [
                "**",
                "!Dockerfile",
                "!pyproject.toml",
                "!uv.lock",
                "!README.md",
                "!src/",
                "!src/**",
                "src/**/__pycache__/",
                "src/**/*.pyc",
            ],
            REPO_ROOT / "⚙️" / "compute-metering" / ".dockerignore": [
                "**",
                "!Dockerfile",
                "!pyproject.toml",
                "!uv.lock",
                "!README.md",
                "!src/",
                "!src/**",
                "src/**/__pycache__/",
                "src/**/*.pyc",
            ],
        }
        for path, entries in expected.items():
            with self.subTest(context=path.parent.name):
                ignore = [
                    line
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line and not line.startswith("#")
                ]
                self.assertEqual(ignore, entries)

    def test_external_attestations_bind_the_reproducible_subject_digest(self):
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "build-tee-images.yml"
        ).read_text(encoding="utf-8")
        exact_digest = "${{ steps.build.outputs.digest }}"
        self.assertIn(
            "image: ${{ steps.image.outputs.name }}@" + exact_digest,
            workflow,
        )
        self.assertEqual(workflow.count("subject-digest: " + exact_digest), 2)
        self.assertEqual(workflow.count("push-to-registry: true"), 2)
        self.assertIn("syft-version: v1.44.0", workflow)


if __name__ == "__main__":
    unittest.main()
