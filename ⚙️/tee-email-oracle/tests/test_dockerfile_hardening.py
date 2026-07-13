from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DockerfileHardeningTest(unittest.TestCase):
    def test_oracle_image_base_and_uv_are_digest_pinned(self):
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

    def test_oracle_image_installs_from_lockfile(self):
        dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

        self.assertRegex(dockerfile, r"COPY\s+pyproject\.toml\s+uv\.lock\s+\./")
        self.assertIn("uv sync --frozen --no-dev", dockerfile)
        self.assertNotIn('uv pip install "./captcha-solver"', dockerfile)
        self.assertNotIn('uv pip install "."', dockerfile)


if __name__ == "__main__":
    unittest.main()
