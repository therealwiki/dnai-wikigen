import json
import os
import subprocess
import sys
import types
import unittest


sys.modules.setdefault(
    "tinker",
    types.SimpleNamespace(ServiceClient=object, TrainingClient=object, SamplingClient=object),
)

from tinker_delegate.evaluator_sandbox import (  # noqa: E402
    EvaluatorSandboxOutcome,
    EvaluatorSandboxPolicy,
    SandboxedEvaluatorRunner,
    _rlimit_preexec,
    _rlimit_specs,
)
from tinker_delegate.fake_tinker_backend import FakeTinkerServiceClient  # noqa: E402
from tinker_delegate.private_reward_sandbox import SandboxFailureCode  # noqa: E402
from tinker_delegate.session import IsolatedTinkerSession  # noqa: E402


class SandboxedEvaluatorRunnerTest(unittest.TestCase):
    def test_process_bound_evaluator_executes_allowlisted_capability_plan(self):
        private_artifact = b"sealed evaluator artifact must stay parent-side"
        service_client = FakeTinkerServiceClient(api_key="sealed-upstream-key")
        session = IsolatedTinkerSession(service_client, "deal-sandbox")
        source = b"""
emit(
    [
        {"op": "create_training", "base_model": "meta-llama/Llama-3.1-8B", "rank": 4},
        {"op": "train", "token_count": 12},
        {"op": "optim_step"},
        {"op": "sample", "prompt_tokens": 8, "max_tokens": 4},
    ],
    {
        "quality_delta": 0.08,
        "benchmark": "sandbox-local",
        "confidence": "high",
        "methodology": "capability plan only",
    },
)
"""

        result = SandboxedEvaluatorRunner().run(
            evaluator_source=source,
            artifact=private_artifact,
            artifact_type="dataset",
            session=session,
            budget_cap=10**18,
            reserve_price=10**17,
        )

        self.assertEqual(result.outcome, EvaluatorSandboxOutcome.PASS)
        self.assertEqual(result.failure_code, SandboxFailureCode.NONE)
        self.assertEqual(result.metrics["quality_delta"], 0.08)
        self.assertEqual(result.metrics["benchmark"], "sandbox-local")
        self.assertEqual(result.operation_counts["create_training"], 1)
        self.assertEqual(result.operation_counts["train"], 1)
        self.assertEqual(result.operation_counts["sample"], 1)
        self.assertEqual(len(service_client.created_training_clients), 1)
        train_kwargs, training_client = service_client.created_training_clients[0]
        self.assertEqual(train_kwargs["user_metadata"]["deal_id"], "deal-sandbox")
        self.assertEqual(train_kwargs["user_metadata"]["surface"], "sandboxed_evaluator")
        self.assertEqual(train_kwargs["user_metadata"]["mode"], "capability_plan")
        self.assertEqual(len(training_client.forward_backward_calls), 1)
        self.assertEqual(len(service_client.samplers), 1)
        self.assertEqual(len(service_client.samplers[0].sample_calls), 1)

        public = json.dumps(result.to_public_dict(), sort_keys=True)
        forbidden_values = (
            private_artifact.decode("utf-8"),
            "sealed-upstream-key",
            "fake-run-1",
            "tinker://fake-run-1",
            "fake-sample-derived-from-sealed-artifact",
        )
        for forbidden in forbidden_values:
            self.assertNotIn(forbidden, public)
        self.assertFalse(result.to_public_dict()["raw_session_returned"])
        self.assertFalse(result.to_public_dict()["raw_artifact_returned"])
        self.assertFalse(result.to_public_dict()["raw_checkpoint_path_returned"])
        self.assertFalse(result.to_public_dict()["raw_secret_egress"])

    def test_evaluator_process_has_no_session_or_service_client_object(self):
        service_client = FakeTinkerServiceClient(api_key="sealed-upstream-key")
        session = IsolatedTinkerSession(service_client, "deal-sandbox")
        source = b"""
session_visible = 0
try:
    session
except Exception:
    session_visible = 0
else:
    session_visible = 1
emit(
    [{"op": "create_training", "base_model": "meta-llama/Llama-3.1-8B", "rank": 4}],
    {"quality_delta": 0.1 if session_visible else 0.0, "benchmark": "scope", "confidence": "high"},
)
"""

        result = SandboxedEvaluatorRunner().run(
            evaluator_source=source,
            artifact=b"private",
            artifact_type="dataset",
            session=session,
            budget_cap=10**18,
            reserve_price=10**17,
        )

        self.assertEqual(result.outcome, EvaluatorSandboxOutcome.PASS)
        self.assertEqual(result.metrics["quality_delta"], 0.0)
        self.assertNotIn("session", result.to_public_dict())
        self.assertNotIn("service_client", json.dumps(result.to_public_dict()))

    def test_rejects_escape_attempts_and_out_of_policy_plan(self):
        service_client = FakeTinkerServiceClient(api_key="sealed-upstream-key")

        rejected = SandboxedEvaluatorRunner().run(
            evaluator_source=b"print(open('/etc/passwd').read())",
            artifact=b"private",
            artifact_type="dataset",
            session=IsolatedTinkerSession(service_client, "deal-1"),
            budget_cap=10**18,
            reserve_price=10**17,
        )
        self.assertEqual(rejected.outcome, EvaluatorSandboxOutcome.POLICY_REJECTED)
        self.assertEqual(rejected.failure_code, SandboxFailureCode.POLICY_REJECTED)

        oversized_plan = b"""
emit(
    [{"op": "create_training", "base_model": "meta-llama/Llama-3.1-8B", "rank": 4},
     {"op": "train", "token_count": 999999}],
    {"quality_delta": 0.2, "benchmark": "bad", "confidence": "high"},
)
"""
        rejected_plan = SandboxedEvaluatorRunner(EvaluatorSandboxPolicy(max_train_tokens=32)).run(
            evaluator_source=oversized_plan,
            artifact=b"private",
            artifact_type="dataset",
            session=IsolatedTinkerSession(service_client, "deal-2"),
            budget_cap=10**18,
            reserve_price=10**17,
        )
        self.assertEqual(rejected_plan.outcome, EvaluatorSandboxOutcome.POLICY_REJECTED)
        self.assertEqual(rejected_plan.failure_code, SandboxFailureCode.POLICY_REJECTED)

    def test_timeout_is_bucketed_without_child_trace(self):
        result = SandboxedEvaluatorRunner(EvaluatorSandboxPolicy(timeout_seconds=0.1)).run(
            evaluator_source=b"while True:\n    pass",
            artifact=b"private",
            artifact_type="dataset",
            session=IsolatedTinkerSession(FakeTinkerServiceClient(), "deal-timeout"),
            budget_cap=10**18,
            reserve_price=10**17,
        )

        self.assertEqual(result.outcome, EvaluatorSandboxOutcome.TIMEOUT)
        self.assertEqual(result.failure_code, SandboxFailureCode.TIMEOUT)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.to_public_dict()["metrics"], {})


@unittest.skipUnless(os.name == "posix", "resource limits are POSIX-only")
class EvaluatorSandboxResourceLimitTest(unittest.TestCase):
    def test_rlimit_specs_reflect_policy(self):
        import resource

        policy = EvaluatorSandboxPolicy(
            cpu_seconds=3, max_file_bytes=0, max_open_files=32, disable_core_dumps=True
        )
        specs = dict(_rlimit_specs(policy))
        self.assertEqual(specs[resource.RLIMIT_CPU], (3, 3))
        self.assertEqual(specs[resource.RLIMIT_FSIZE], (0, 0))
        self.assertEqual(specs[resource.RLIMIT_NOFILE], (32, 32))
        self.assertEqual(specs[resource.RLIMIT_CORE], (0, 0))
        # AS is left unset by default (0) because a low cap breaks CPython start.
        self.assertNotIn(resource.RLIMIT_AS, specs)

    def test_address_space_limit_included_when_requested(self):
        import resource

        specs = dict(_rlimit_specs(EvaluatorSandboxPolicy(max_address_space_bytes=2**30)))
        self.assertEqual(specs[resource.RLIMIT_AS], (2**30, 2**30))

    def test_preexec_actually_applies_limits_in_a_child(self):
        # Prove the limits take effect in a real child on this host, not just in
        # the intended-spec table: spawn a subprocess under the same preexec_fn
        # and have it report its own soft limits.
        import resource

        policy = EvaluatorSandboxPolicy(cpu_seconds=5, max_file_bytes=4096, max_open_files=48)
        probe = (
            "import json, resource;"
            "print(json.dumps([resource.getrlimit(resource.RLIMIT_CPU)[0],"
            "resource.getrlimit(resource.RLIMIT_FSIZE)[0],"
            "resource.getrlimit(resource.RLIMIT_NOFILE)[0]]))"
        )
        proc = subprocess.run(
            [sys.executable, "-S", "-c", probe],
            capture_output=True,
            text=True,
            preexec_fn=_rlimit_preexec(policy),
            timeout=5,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        cpu, fsize, nofile = json.loads(proc.stdout)
        self.assertEqual(cpu, 5)
        self.assertEqual(fsize, 4096)
        self.assertEqual(nofile, 48)

    def test_preexec_never_raises_an_existing_hard_cap(self):
        # If the policy nominally allows more open files than the host's hard
        # cap, the applied soft limit must stay within the hard cap.
        import resource

        _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard == resource.RLIM_INFINITY:
            self.skipTest("host has no finite NOFILE hard cap to test against")
        policy = EvaluatorSandboxPolicy(max_open_files=hard + 10_000)
        probe = (
            "import json, resource;"
            "print(json.dumps(list(resource.getrlimit(resource.RLIMIT_NOFILE))))"
        )
        proc = subprocess.run(
            [sys.executable, "-S", "-c", probe],
            capture_output=True,
            text=True,
            preexec_fn=_rlimit_preexec(policy),
            timeout=5,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        soft_applied, hard_applied = json.loads(proc.stdout)
        self.assertLessEqual(soft_applied, hard)
        self.assertLessEqual(hard_applied, hard)


if __name__ == "__main__":
    unittest.main()
