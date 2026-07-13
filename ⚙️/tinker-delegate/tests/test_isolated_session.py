import sys
import types
import unittest
from dataclasses import dataclass


sys.modules.setdefault(
    "tinker",
    types.SimpleNamespace(ServiceClient=object, TrainingClient=object, SamplingClient=object),
)

from tinker_delegate.session import (  # noqa: E402
    DEFAULT_TTL,
    MAX_TTL,
    MIN_TTL,
    IsolatedTinkerSession,
)


@dataclass
class Info:
    training_run_id: str


@dataclass
class PathResponse:
    path: str


@dataclass
class Checkpoint:
    checkpoint_id: str


class Future:
    def __init__(self, value):
        self.value = value

    def result(self):
        return self.value


class Prompt:
    def __init__(self, token_count: int):
        self.length = token_count


class Datum:
    def __init__(self, token_count: int):
        self.model_input = Prompt(token_count)


class FakeSampler:
    def __init__(self):
        self.sample_calls = []
        self.logprob_calls = []

    def sample(self, prompt, sampling_params, num_samples=1):
        self.sample_calls.append((prompt, sampling_params, num_samples))
        return {"bounded": True, "num_samples": num_samples}

    def compute_logprobs(self, prompt):
        self.logprob_calls.append(prompt)
        return [None, -0.1]


class FakeTrainingClient:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.forward_backward_calls = []
        self.optim_step_calls = []
        self.save_weights_for_sampler_calls = []
        self.save_state_calls = []
        self.save_and_get_sampler_calls = []
        self.tokenizer = object()

    def get_info(self):
        return Info(training_run_id=self.run_id)

    def forward_backward(self, data, loss_fn, loss_fn_config=None):
        self.forward_backward_calls.append((data, loss_fn, loss_fn_config))
        return Future({"loss": 0.1})

    def optim_step(self, adam_params):
        self.optim_step_calls.append(adam_params)
        return Future({"ok": True})

    def save_weights_for_sampler(self, name, ttl_seconds):
        self.save_weights_for_sampler_calls.append((name, ttl_seconds))
        return Future(PathResponse(f"tinker://{self.run_id}/sampler/{name}"))

    def save_state(self, name, ttl_seconds):
        self.save_state_calls.append((name, ttl_seconds))
        return Future(PathResponse(f"tinker://{self.run_id}/state/{name}"))

    def save_weights_and_get_sampling_client(self, name, ttl_seconds):
        self.save_and_get_sampler_calls.append((name, ttl_seconds))
        return FakeSampler()

    def get_tokenizer(self):
        return self.tokenizer


class FakeRestClient:
    def __init__(self):
        self.checkpoints_by_run = {}
        self.deleted = []
        self.delete_failures = {}
        self.list_error = None

    def list_checkpoints(self, run_id):
        if self.list_error:
            raise self.list_error
        return Future(self.checkpoints_by_run.get(run_id, []))

    def delete_checkpoint(self, run_id, checkpoint_id):
        remaining_failures = self.delete_failures.get(checkpoint_id, 0)
        if remaining_failures:
            self.delete_failures[checkpoint_id] = remaining_failures - 1
            raise RuntimeError("delete failed")
        self.deleted.append((run_id, checkpoint_id))
        return Future({"deleted": True})


class FakeServiceClient:
    def __init__(self):
        self.created_training_clients = []
        self.sampling_paths = []
        self.base_sampling_models = []
        self.rest_client = FakeRestClient()

    def create_lora_training_client(self, **kwargs):
        run_id = f"run-{len(self.created_training_clients) + 1}"
        client = FakeTrainingClient(run_id)
        self.created_training_clients.append((kwargs, client))
        return client

    def create_sampling_client(self, model_path=None, base_model=None):
        if base_model:
            self.base_sampling_models.append(base_model)
            return FakeSampler()
        self.sampling_paths.append(model_path)
        return FakeSampler()

    def create_rest_client(self):
        return self.rest_client


class IsolatedTinkerSessionTest(unittest.TestCase):
    def make_session(self):
        service_client = FakeServiceClient()
        session = IsolatedTinkerSession(service_client, "deal-123")
        training_client = session.create_training(
            "meta-llama/Llama-3.1-8B",
            user_metadata={
                "buyer_agent": "agent-1",
                "surface": "unit-test",
            },
        )
        return session, service_client, training_client

    def test_create_training_scopes_metadata_and_allows_only_one_run(self):
        session, service_client, _training_client = self.make_session()

        kwargs, _client = service_client.created_training_clients[0]
        self.assertEqual(kwargs["base_model"], "meta-llama/Llama-3.1-8B")
        self.assertEqual(kwargs["rank"], 32)
        self.assertEqual(kwargs["user_metadata"]["deal_id"], "deal-123")
        self.assertEqual(kwargs["user_metadata"]["metadata_policy"], "bounded-v1")
        self.assertEqual(kwargs["user_metadata"]["surface"], "unit-test")
        self.assertIn("user_metadata_hash", kwargs["user_metadata"])
        self.assertEqual(kwargs["user_metadata"]["user_metadata_dropped_count"], 1)
        self.assertNotIn("buyer_agent", kwargs["user_metadata"])
        self.assertNotIn("agent-1", str(kwargs["user_metadata"]))
        self.assertEqual(session.training_run_id, "run-1")

        with self.assertRaisesRegex(RuntimeError, "Only one training run per deal"):
            session.create_training("meta-llama/Llama-3.1-8B")

        self.assertEqual(len(service_client.created_training_clients), 1)

    def test_user_metadata_is_bounded_before_tinker_egress(self):
        service_client = FakeServiceClient()
        session = IsolatedTinkerSession(service_client, "deal-private")

        session.create_training(
            "meta-llama/Llama-3.1-8B",
            user_metadata={
                "surface": "local_synthetic_room",
                "artifact_type": "dataset",
                "private_note": "secret private artifact text",
                "deal_id": "attacker-overridden-deal",
            },
        )

        kwargs, _client = service_client.created_training_clients[0]
        metadata = kwargs["user_metadata"]
        self.assertEqual(metadata["deal_id"], "deal-private")
        self.assertEqual(metadata["surface"], "local_synthetic_room")
        self.assertEqual(metadata["artifact_type"], "dataset")
        self.assertEqual(metadata["metadata_policy"], "bounded-v1")
        self.assertIn("user_metadata_hash", metadata)
        self.assertEqual(metadata["user_metadata_dropped_count"], 2)
        rendered = str(metadata)
        self.assertNotIn("private_note", rendered)
        self.assertNotIn("secret private artifact text", rendered)
        self.assertNotIn("attacker-overridden-deal", rendered)

    def test_user_metadata_fails_closed_for_unbounded_shapes(self):
        with self.assertRaisesRegex(ValueError, "JSON-serializable"):
            IsolatedTinkerSession(FakeServiceClient(), "deal-1").create_training(
                "meta-llama/Llama-3.1-8B",
                user_metadata={"unsafe": object()},
            )

        with self.assertRaisesRegex(ValueError, "exceeds"):
            IsolatedTinkerSession(FakeServiceClient(), "deal-1").create_training(
                "meta-llama/Llama-3.1-8B",
                user_metadata={"unsafe": "x" * 3000},
            )

    def test_checkpoint_ttl_is_clamped_on_every_save_path(self):
        session, service_client, training_client = self.make_session()

        sampler_path = session.save_for_sampling("too-short", ttl_seconds=1)
        state_path = session.save_state("too-long", ttl_seconds=MAX_TTL + 1000)
        sampler = session.save_and_get_sampler("default")

        self.assertEqual(sampler_path, "tinker://run-1/sampler/too-short")
        self.assertEqual(state_path, "tinker://run-1/state/too-long")
        self.assertIsInstance(sampler, FakeSampler)
        self.assertEqual(
            training_client.save_weights_for_sampler_calls,
            [("too-short", MIN_TTL), ("default", DEFAULT_TTL)],
        )
        self.assertEqual(training_client.save_state_calls, [("too-long", MAX_TTL)])
        self.assertEqual(training_client.save_and_get_sampler_calls, [])
        self.assertEqual(service_client.sampling_paths, ["tinker://run-1/sampler/default"])

    def test_sampling_is_path_checked_to_this_session(self):
        session, service_client, _training_client = self.make_session()
        allowed_path = session.save_for_sampling("allowed")

        sampler = session.create_sampler(allowed_path)

        self.assertIsInstance(sampler, FakeSampler)
        self.assertEqual(service_client.sampling_paths, [allowed_path])
        with self.assertRaisesRegex(PermissionError, "only models trained in deal deal-123"):
            session.create_sampler("tinker://other-run/sampler/secret")

    def test_base_sampler_is_scoped_to_training_model(self):
        session, service_client, _training_client = self.make_session()

        sampler = session.create_base_sampler("meta-llama/Llama-3.1-8B")

        self.assertIsInstance(sampler, FakeSampler)
        self.assertEqual(service_client.base_sampling_models, ["meta-llama/Llama-3.1-8B"])
        with self.assertRaisesRegex(PermissionError, "scoped to meta-llama/Llama-3.1-8B"):
            session.create_base_sampler("meta-llama/Llama-3.3-70B-Instruct")

    def test_state_checkpoint_is_not_sampleable(self):
        session, _service_client, _training_client = self.make_session()
        state_path = session.save_state("state-only")

        with self.assertRaises(PermissionError):
            session.create_sampler(state_path)

    def test_cleanup_deletes_all_checkpoints_and_closes_session(self):
        session, service_client, _training_client = self.make_session()
        service_client.rest_client.checkpoints_by_run["run-1"] = [
            Checkpoint("cp-1"),
            Checkpoint("cp-2"),
        ]

        attestation = session.cleanup()
        second_attestation = session.cleanup()

        self.assertEqual(
            service_client.rest_client.deleted,
            [("run-1", "cp-1"), ("run-1", "cp-2")],
        )
        self.assertIs(attestation, second_attestation)
        self.assertTrue(attestation.success)
        self.assertEqual(attestation.deal_id, "deal-123")
        self.assertEqual(attestation.training_run_id, "run-1")
        self.assertEqual(attestation.listed_checkpoint_count, 2)
        self.assertEqual(attestation.deleted_checkpoint_count, 2)
        self.assertEqual(attestation.failed_checkpoint_count, 0)
        self.assertEqual(attestation.delete_attempts, 2)
        self.assertEqual(len(attestation.checkpoint_ids_hash), 64)
        public = attestation.to_public_dict()
        self.assertNotIn("cp-1", str(public))
        self.assertNotIn("cp-2", str(public))
        with self.assertRaisesRegex(RuntimeError, "Session closed"):
            session.save_for_sampling("after-close")

    def test_cleanup_retries_transient_delete_failures(self):
        session, service_client, _training_client = self.make_session()
        service_client.rest_client.checkpoints_by_run["run-1"] = [Checkpoint("cp-retry")]
        service_client.rest_client.delete_failures["cp-retry"] = 2

        attestation = session.cleanup(delete_retries=3)

        self.assertTrue(attestation.success)
        self.assertEqual(attestation.deleted_checkpoint_count, 1)
        self.assertEqual(attestation.failed_checkpoint_count, 0)
        self.assertEqual(attestation.delete_attempts, 3)
        self.assertEqual(service_client.rest_client.deleted, [("run-1", "cp-retry")])

    def test_cleanup_attests_permanent_delete_failures(self):
        session, service_client, _training_client = self.make_session()
        service_client.rest_client.checkpoints_by_run["run-1"] = [Checkpoint("cp-fail")]
        service_client.rest_client.delete_failures["cp-fail"] = 10

        attestation = session.cleanup(delete_retries=3)

        self.assertFalse(attestation.success)
        self.assertEqual(attestation.deleted_checkpoint_count, 0)
        self.assertEqual(attestation.failed_checkpoint_count, 1)
        self.assertEqual(attestation.delete_attempts, 3)
        self.assertEqual(service_client.rest_client.deleted, [])
        self.assertNotIn("cp-fail", str(attestation.to_public_dict()))

    def test_cleanup_attests_checkpoint_listing_failure(self):
        session, service_client, _training_client = self.make_session()
        service_client.rest_client.list_error = RuntimeError("list failed")

        attestation = session.cleanup()

        self.assertFalse(attestation.success)
        self.assertEqual(attestation.error_type, "RuntimeError")
        self.assertEqual(attestation.listed_checkpoint_count, 0)
        self.assertEqual(attestation.delete_attempts, 0)

    def test_training_and_sampling_are_metered(self):
        session, _service_client, _training_client = self.make_session()
        session.forward_backward([Datum(5), Datum(7)])
        sampler = session.save_and_get_sampler("metered")
        session.sample(sampler, Prompt(3), sampling_params={"max_tokens": 2}, num_samples=2)
        session.compute_logprobs(sampler, Prompt(4))

        self.assertEqual(session.meter.train_tokens, 12)
        self.assertEqual(session.meter.prefill_tokens, 7)
        self.assertGreater(session.compute_cost_wei, 0)

    def test_wrapper_does_not_expose_download_publish_or_list_operations(self):
        session, _service_client, _training_client = self.make_session()

        forbidden = (
            "create_rest_client",
            "list_training_runs",
            "list_checkpoints",
            "list_user_checkpoints",
            "get_checkpoint_archive_url",
            "get_checkpoint_archive_url_from_tinker_path",
            "publish_checkpoint",
            "publish_checkpoint_from_tinker_path",
            "set_checkpoint_ttl_from_tinker_path",
        )
        for method_name in forbidden:
            self.assertFalse(hasattr(session, method_name), method_name)


if __name__ == "__main__":
    unittest.main()
