import unittest

from tinker_delegate.private_reward import Candidate
from tinker_delegate.private_reward_sandbox import (
    PythonCandidateSandbox,
    SandboxFailureCode,
    SandboxOutcome,
    SandboxPolicy,
)


class PythonCandidateSandboxTest(unittest.TestCase):
    def test_runs_candidate_with_bounded_public_result(self):
        sandbox = PythonCandidateSandbox()

        result = sandbox.run(Candidate(b"print(sum([1, 2, 3]))"))

        self.assertTrue(result.accepted)
        self.assertEqual(result.outcome, SandboxOutcome.PASS)
        self.assertEqual(result.failure_code, SandboxFailureCode.NONE)
        self.assertEqual(result.stdout, "6\n")
        self.assertGreaterEqual(result.elapsed_band_seconds, 0)
        public = result.to_public_dict()
        self.assertIn("candidate_hash", public)
        self.assertIn("failure_code", public)
        self.assertIn("elapsed_band_seconds", public)
        self.assertNotIn("sum([1, 2, 3])", str(public))

    def test_rejects_network_file_and_process_escape_attempts(self):
        sandbox = PythonCandidateSandbox()

        cases = [
            b"import socket\nprint(socket.socket())",
            b"print(open('/etc/passwd').read())",
            b"import subprocess\nsubprocess.run(['echo', 'x'])",
            b"__builtins__",
            b"().__class__",
        ]

        for payload in cases:
            with self.subTest(payload=payload):
                result = sandbox.run(Candidate(payload))
                self.assertEqual(result.outcome, SandboxOutcome.POLICY_REJECTED)
                self.assertEqual(result.failure_code, SandboxFailureCode.POLICY_REJECTED)
                self.assertFalse(result.accepted)
                self.assertEqual(result.stdout, "")

    def test_runtime_layer_blocks_ast_passing_escapes(self):
        # These escapes pass the AST preflight (getattr/type are Name calls, not
        # banned; a class def has no banned node) but must fail closed at the
        # restricted-builtins runtime — no stdout, not accepted. Guards against a
        # future refactor re-adding getattr/type/__build_class__ to safe_builtins.
        sandbox = PythonCandidateSandbox()
        escapes = [
            b'print(getattr((), chr(95)*2 + "class" + chr(95)*2))',  # dynamic dunder via getattr
            b"print(type(()))",                                       # type() -> class object
            b"print(vars())",                                         # vars() namespace access
            b"class X:\n    pass\nprint(X)",                          # needs __build_class__
        ]
        for payload in escapes:
            with self.subTest(payload=payload):
                result = sandbox.run(Candidate(payload))
                self.assertFalse(result.accepted, payload)
                self.assertEqual(result.stdout, "")
                self.assertIn(
                    result.failure_code,
                    (SandboxFailureCode.RUNTIME_ERROR, SandboxFailureCode.POLICY_REJECTED),
                )

    def test_policy_rejections_are_bucketed_not_detailed(self):
        sandbox = PythonCandidateSandbox()

        result = sandbox.run(Candidate(b"mod = __import__('socket')\nprint(mod)"))

        self.assertEqual(result.outcome, SandboxOutcome.POLICY_REJECTED)
        self.assertEqual(result.failure_code, SandboxFailureCode.POLICY_REJECTED)
        self.assertEqual(result.stderr, "sandbox failure: policy_rejected")
        self.assertNotIn("socket", result.stderr)

    def test_stdout_is_capped(self):
        sandbox = PythonCandidateSandbox(SandboxPolicy(max_stdout_bytes=12))

        result = sandbox.run(Candidate(b"print('x' * 100)"))

        self.assertEqual(result.outcome, SandboxOutcome.PASS)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 12)
        self.assertTrue(result.stdout_truncated)

    def test_stderr_is_capped_and_bucketed(self):
        sandbox = PythonCandidateSandbox(SandboxPolicy(max_stderr_bytes=15))

        result = sandbox.run(Candidate(b"raise ValueError('x' * 100)"))

        self.assertEqual(result.outcome, SandboxOutcome.RUNTIME_ERROR)
        self.assertEqual(result.failure_code, SandboxFailureCode.RUNTIME_ERROR)
        self.assertLessEqual(len(result.stderr.encode("utf-8")), 15)
        self.assertTrue(result.stderr_truncated)
        self.assertNotIn("ValueError", result.stderr)
        self.assertNotIn("100", result.stderr)

    def test_timeout_is_bounded(self):
        sandbox = PythonCandidateSandbox(SandboxPolicy(timeout_seconds=0.1, cpu_seconds=5))

        result = sandbox.run(Candidate(b"while True:\n    pass"))

        self.assertEqual(result.outcome, SandboxOutcome.TIMEOUT)
        self.assertEqual(result.failure_code, SandboxFailureCode.TIMEOUT)
        self.assertTrue(result.timed_out)
        self.assertIsNone(result.exit_code)
        self.assertEqual(result.stderr, "sandbox failure: timeout")

    def test_memory_bomb_fails_closed_bounded(self):
        # A candidate that attempts a huge allocation must fail closed to a
        # bounded runtime_error (RLIMIT_AS / allocation failure), never OOM the
        # host, hang, or leak a raw MemoryError traceback. This pins the memory-
        # DoS defense for the untrusted-code boundary (previously only the
        # wall-clock timeout was tested).
        sandbox = PythonCandidateSandbox(SandboxPolicy(timeout_seconds=3.0, memory_megabytes=64))

        result = sandbox.run(Candidate(b"x = bytearray(10**11)\nprint(len(x))"))

        self.assertEqual(result.outcome, SandboxOutcome.RUNTIME_ERROR)
        self.assertEqual(result.failure_code, SandboxFailureCode.RUNTIME_ERROR)
        self.assertFalse(result.timed_out)
        # Bucketed stderr: no raw MemoryError traceback / candidate internals.
        self.assertEqual(result.stderr, "sandbox failure: runtime_error")

    def test_random_seed_is_deterministic(self):
        sandbox = PythonCandidateSandbox(SandboxPolicy(deterministic_seed=42))
        candidate = Candidate(b"print(random.random())")

        first = sandbox.run(candidate)
        second = sandbox.run(candidate)

        self.assertEqual(first.outcome, SandboxOutcome.PASS)
        self.assertEqual(first.stdout, second.stdout)

    def test_policy_rejects_unsupported_escape_flags(self):
        with self.assertRaisesRegex(ValueError, "network"):
            SandboxPolicy(allow_network=True)
        with self.assertRaisesRegex(ValueError, "process"):
            SandboxPolicy(allow_process_spawn=True)
        with self.assertRaisesRegex(ValueError, "filesystem"):
            SandboxPolicy(allow_filesystem=True)
        with self.assertRaisesRegex(ValueError, "timing_band"):
            SandboxPolicy(timing_band_seconds=0)

    def test_rejects_non_utf8_and_oversized_source(self):
        sandbox = PythonCandidateSandbox(SandboxPolicy(max_source_bytes=8))

        non_utf8 = sandbox.run(Candidate(b"\xff"))
        oversized = sandbox.run(Candidate(b"print(12345)"))

        self.assertEqual(non_utf8.outcome, SandboxOutcome.POLICY_REJECTED)
        self.assertEqual(oversized.outcome, SandboxOutcome.POLICY_REJECTED)
        self.assertEqual(non_utf8.failure_code, SandboxFailureCode.POLICY_REJECTED)
        self.assertEqual(oversized.failure_code, SandboxFailureCode.POLICY_REJECTED)

    def test_syntax_errors_are_bucketed(self):
        sandbox = PythonCandidateSandbox()

        result = sandbox.run(Candidate(b"def nope(:\n    pass"))

        self.assertEqual(result.outcome, SandboxOutcome.POLICY_REJECTED)
        self.assertEqual(result.failure_code, SandboxFailureCode.SYNTAX_ERROR)
        self.assertEqual(result.stderr, "sandbox failure: syntax_error")

    def test_elapsed_time_is_banded(self):
        sandbox = PythonCandidateSandbox(SandboxPolicy(timing_band_seconds=60))

        result = sandbox.run(Candidate(b"print('fast')"))

        self.assertEqual(result.elapsed_band_seconds, 0)


if __name__ == "__main__":
    unittest.main()
