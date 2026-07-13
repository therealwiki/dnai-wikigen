from pathlib import Path
import re
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DockerfileAgentExtraTest(unittest.TestCase):
    def test_delegate_image_base_and_uv_are_digest_pinned(self):
        dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

        self.assertIn(
            "FROM python:3.12.13-slim-trixie@sha256:"
            "423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf",
            dockerfile,
        )
        self.assertIn(
            "COPY --from=ghcr.io/astral-sh/uv:0.11.28@sha256:"
            "0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa",
            dockerfile,
        )
        self.assertNotIn("python:3.12-slim", dockerfile)
        self.assertNotIn("ghcr.io/astral-sh/uv:latest", dockerfile)

    def test_delegate_image_installs_tinker_agent_extra_from_lockfile(self):
        dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

        self.assertRegex(dockerfile, r"COPY\s+pyproject\.toml\s+uv\.lock\s+\./")
        self.assertRegex(dockerfile, r"uv\s+sync\b")
        self.assertIn("--frozen", dockerfile)
        self.assertIn("--extra agent", dockerfile)

    def test_delegate_image_does_not_install_base_package_only(self):
        dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
        base_only_install = re.compile(r"uv\s+pip\s+install\s+\.(?:\s|&&)")

        self.assertIsNone(base_only_install.search(dockerfile))

    def test_agent_image_verifier_builds_and_runs_import_check(self):
        verifier = (PROJECT_ROOT / "scripts" / "verify-agent-image.sh").read_text(encoding="utf-8")

        self.assertIn("docker build", verifier)
        self.assertIn("docker run --rm -i", verifier)
        self.assertIn("import tinker", verifier)
        self.assertIn("agent_stack_available", verifier)
        self.assertIn("raw_secret_egress", verifier)


if __name__ == "__main__":
    unittest.main()
