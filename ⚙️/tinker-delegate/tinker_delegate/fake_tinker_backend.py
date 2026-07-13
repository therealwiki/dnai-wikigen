"""Deterministic fake Tinker backend for local diligence-room tests.

This module models the SDK surface used by :class:`IsolatedTinkerSession`
without contacting Tinker or requiring upstream credentials. It is not a
security boundary; it exists so local tests can exercise the real TEE-side
control-plane restrictions around artifact handling, bounded output, and
cleanup.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class FakeTokenizer:
    """Deterministic stand-in tokenizer supporting the training data path."""

    def encode(self, text: str, add_special_tokens: bool = False) -> list[int]:
        toks = [(ord(c) % 4096) + 1 for c in (text or "")]
        if add_special_tokens:
            toks = [1] + toks
        return toks or [1, 2, 3]


@dataclass(frozen=True)
class FakeTinkerInfo:
    training_run_id: str


@dataclass(frozen=True)
class FakeTinkerPathResponse:
    path: str


@dataclass(frozen=True)
class FakeTinkerCheckpoint:
    checkpoint_id: str


class FakeTinkerFuture:
    def __init__(self, value: Any):
        self._value = value

    def result(self) -> Any:
        return self._value


class FakeTinkerPrompt:
    def __init__(self, token_count: int):
        self.length = token_count

    def to_ints(self) -> list[int]:
        return [0] * self.length


class FakeTinkerDatum:
    def __init__(self, token_count: int):
        self.model_input = FakeTinkerPrompt(token_count)


class FakeTinkerSampler:
    def __init__(self, *, model_path: str = "", base_model: str = ""):
        self.model_path = model_path
        self.base_model = base_model
        self.sample_calls: list[dict[str, Any]] = []
        self.logprob_calls: list[Any] = []

    def sample(self, prompt, sampling_params, num_samples=1):
        self.sample_calls.append(
            {
                "prompt_tokens": getattr(prompt, "length", 0),
                "sampling_params": sampling_params,
                "num_samples": num_samples,
            }
        )
        return {
            "private_sample_text": "fake-sample-derived-from-sealed-artifact",
            "num_samples": num_samples,
        }

    def compute_logprobs(self, prompt):
        self.logprob_calls.append(prompt)
        return [None, -0.1]


class FakeTinkerRestClient:
    def __init__(self):
        self.checkpoints_by_run: dict[str, list[FakeTinkerCheckpoint]] = {}
        self.deleted: list[tuple[str, str]] = []
        self.training_runs: list[Any] = []

    def add_checkpoint(self, run_id: str, checkpoint_id: str) -> None:
        self.checkpoints_by_run.setdefault(run_id, []).append(
            FakeTinkerCheckpoint(checkpoint_id=checkpoint_id)
        )

    def list_checkpoints(self, run_id: str):
        return FakeTinkerFuture(list(self.checkpoints_by_run.get(run_id, [])))

    def delete_checkpoint(self, run_id: str, checkpoint_id: str):
        self.deleted.append((run_id, checkpoint_id))
        remaining = [
            cp
            for cp in self.checkpoints_by_run.get(run_id, [])
            if cp.checkpoint_id != checkpoint_id
        ]
        self.checkpoints_by_run[run_id] = remaining
        return FakeTinkerFuture({"deleted": True})

    def list_training_runs(self, limit: int = 100):
        return FakeTinkerFuture(self.training_runs[:limit])


class FakeTinkerTrainingClient:
    def __init__(self, *, run_id: str, rest_client: FakeTinkerRestClient):
        self.run_id = run_id
        self._rest_client = rest_client
        self.forward_backward_calls: list[dict[str, Any]] = []
        self.optim_step_calls: list[Any] = []
        self.save_weights_for_sampler_calls: list[tuple[str, int]] = []
        self.save_state_calls: list[tuple[str, int]] = []
        self.tokenizer = FakeTokenizer()

    def get_info(self):
        return FakeTinkerInfo(training_run_id=self.run_id)

    def forward_backward(self, data, loss_fn, loss_fn_config=None):
        self.forward_backward_calls.append(
            {
                "data_len": len(data),
                "loss_fn": loss_fn,
                "loss_fn_config": loss_fn_config,
            }
        )
        return FakeTinkerFuture({"loss": 0.1})

    def optim_step(self, adam_params):
        self.optim_step_calls.append(adam_params)
        return FakeTinkerFuture({"ok": True})

    def save_weights_for_sampler(self, name: str, ttl_seconds: int):
        self.save_weights_for_sampler_calls.append((name, ttl_seconds))
        checkpoint_id = f"{self.run_id}:sampler:{name}"
        self._rest_client.add_checkpoint(self.run_id, checkpoint_id)
        return FakeTinkerFuture(
            FakeTinkerPathResponse(path=f"tinker://{self.run_id}/sampler/{name}")
        )

    def save_state(self, name: str, ttl_seconds: int):
        self.save_state_calls.append((name, ttl_seconds))
        checkpoint_id = f"{self.run_id}:state:{name}"
        self._rest_client.add_checkpoint(self.run_id, checkpoint_id)
        return FakeTinkerFuture(
            FakeTinkerPathResponse(path=f"tinker://{self.run_id}/state/{name}")
        )

    def get_tokenizer(self):
        return self.tokenizer


class FakeTinkerServiceClient:
    """Small fake of the Tinker ServiceClient used by local tests."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.rest_client = FakeTinkerRestClient()
        self.created_training_clients: list[tuple[dict[str, Any], FakeTinkerTrainingClient]] = []
        self.sampling_paths: list[str] = []
        self.base_sampling_models: list[str] = []
        self.samplers: list[FakeTinkerSampler] = []

    def create_lora_training_client(self, **kwargs):
        run_id = f"fake-run-{len(self.created_training_clients) + 1}"
        client = FakeTinkerTrainingClient(run_id=run_id, rest_client=self.rest_client)
        self.created_training_clients.append((kwargs, client))
        return client

    def create_sampling_client(self, model_path=None, base_model=None):
        if base_model:
            self.base_sampling_models.append(base_model)
            sampler = FakeTinkerSampler(base_model=base_model)
        else:
            self.sampling_paths.append(model_path)
            sampler = FakeTinkerSampler(model_path=model_path)
        self.samplers.append(sampler)
        return sampler

    def create_rest_client(self):
        return self.rest_client
