import unittest
from unittest.mock import patch

from tinker_delegate.runtime_hardening import disable_core_dumps


class RuntimeHardeningTest(unittest.TestCase):
    def test_disable_core_dumps_sets_zero_rlimit_when_supported(self):
        with patch("resource.setrlimit") as setrlimit:
            self.assertTrue(disable_core_dumps())

        import resource

        setrlimit.assert_called_once_with(resource.RLIMIT_CORE, (0, 0))

    def test_disable_core_dumps_fails_closed_when_host_rejects_policy(self):
        with patch("resource.setrlimit", side_effect=OSError("denied")):
            self.assertFalse(disable_core_dumps())


if __name__ == "__main__":
    unittest.main()
