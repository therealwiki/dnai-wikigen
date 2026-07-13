import unittest
from unittest.mock import patch

from email_oracle.config import Settings
from email_oracle.main import cmd_serve


class FakeStore:
    def __init__(self, exists: bool):
        self._exists = exists

    def exists(self) -> bool:
        return self._exists


class MainEntrypointTest(unittest.TestCase):
    def test_serve_starts_degraded_when_auto_genesis_disabled_without_credentials(self):
        settings = Settings(auto_genesis=False, api_host="127.0.0.1", api_port=18000)

        with patch("uvicorn.run") as run:
            cmd_serve(settings, FakeStore(exists=False))

        run.assert_called_once_with(
            "email_oracle.api:app",
            host="127.0.0.1",
            port=18000,
            log_level="info",
        )

    def test_serve_exits_when_auto_genesis_enabled_and_genesis_fails(self):
        settings = Settings(auto_genesis=True, api_host="127.0.0.1", api_port=18000)

        with (
            patch("email_oracle.main.cmd_genesis", return_value=None),
            self.assertRaises(SystemExit),
        ):
            cmd_serve(settings, FakeStore(exists=False))


if __name__ == "__main__":
    unittest.main()
