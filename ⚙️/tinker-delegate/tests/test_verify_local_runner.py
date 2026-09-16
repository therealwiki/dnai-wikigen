from pathlib import Path
import tomllib
import unittest


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PACKAGE_ROOT.parents[1]


class VerifyLocalRunnerContractTest(unittest.TestCase):
    def test_delegate_dev_dependencies_are_exactly_pinned(self):
        project = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text())

        self.assertEqual(
            project["dependency-groups"]["dev"],
            ["dcap-qvl==0.5.2", "pytest==9.0.2"],
        )

    def test_delegate_verifier_preserves_agent_extra_and_runs_pytest_module(self):
        script = (REPOSITORY_ROOT / "scripts" / "verify-local.sh").read_text()

        self.assertIn("forge test --threads 1", script)
        self.assertIn("uv sync --frozen --extra agent --group dev", script)
        self.assertIn(
            'if [ "$package_dir" = "⚙️/tinker-delegate" ]; then\n'
            '      uv run --frozen python -m pytest "$test_dir"\n'
            "    else\n"
            '      uv run python -m unittest discover -s "$test_dir"',
            script,
        )
        self.assertIn("uv run --frozen python -m pytest", script)
        self.assertNotIn("uv run pytest", script)


if __name__ == "__main__":
    unittest.main()
