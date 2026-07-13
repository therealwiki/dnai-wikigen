import json
import sys
import tempfile
import types
import unittest
from dataclasses import dataclass
from unittest.mock import patch


class Future:
    def __init__(self, value):
        self.value = value

    def result(self):
        return self.value


@dataclass
class Info:
    training_run_id: str


@dataclass
class PathResponse:
    path: str


@dataclass
class Checkpoint:
    checkpoint_id: str


class ModelInput:
    def __init__(self, token_ids):
        self.token_ids = list(token_ids)
        self.length = len(self.token_ids)

    @classmethod
    def from_ints(cls, token_ids):
        return cls(token_ids)


class TensorData:
    def __init__(self, data, dtype, shape):
        self.data = data
        self.dtype = dtype
        self.shape = shape


class Datum:
    def __init__(self, model_input, loss_fn_inputs):
        self.model_input = model_input
        self.loss_fn_inputs = loss_fn_inputs


@dataclass
class AdamParams:
    learning_rate: float


@dataclass
class SamplingParams:
    max_tokens: int
    temperature: float


class FakeTokenizer:
    def encode(self, text, add_special_tokens=False):
        base = [ord(ch) % 251 for ch in text]
        return ([1] if add_special_tokens else []) + base


class FakeTrainingClient:
    def __init__(self, run_id):
        self.run_id = run_id
        self.forward_backward_calls = []
        self.optim_step_calls = []
        self.save_calls = []

    def get_info(self):
        return Info(training_run_id=self.run_id)

    def get_tokenizer(self):
        return FakeTokenizer()

    def forward_backward(self, data, loss_fn, loss_fn_config=None):
        self.forward_backward_calls.append((data, loss_fn, loss_fn_config))
        return Future({"ok": True})

    def optim_step(self, adam_params):
        self.optim_step_calls.append(adam_params)
        return Future({"ok": True})

    def save_weights_for_sampler(self, name, ttl_seconds):
        self.save_calls.append((name, ttl_seconds))
        return Future(PathResponse(f"tinker://{self.run_id}/sampler/{name}"))


class FakeSampler:
    def __init__(self):
        self.sample_calls = []

    def sample(self, prompt, sampling_params, num_samples=1):
        self.sample_calls.append((prompt, sampling_params, num_samples))
        return Future({"raw_text": "this sample must never leave"})


class FakeRestClient:
    def __init__(self):
        self.deleted = []

    def list_checkpoints(self, run_id):
        return Future([Checkpoint("cp-secret")])

    def delete_checkpoint(self, run_id, checkpoint_id):
        self.deleted.append((run_id, checkpoint_id))
        return Future({"deleted": True})


class FakeServiceClient:
    last_instance = None

    def __init__(self, api_key, project_id=None, base_url=None):
        self.api_key = api_key
        self.project_id = project_id
        self.base_url = base_url
        self.training_client = FakeTrainingClient("run-secret")
        self.sampling_paths = []
        self.rest_client = FakeRestClient()
        FakeServiceClient.last_instance = self

    def create_lora_training_client(self, **kwargs):
        self.training_kwargs = kwargs
        return self.training_client

    def create_sampling_client(self, model_path=None, base_model=None):
        self.sampling_paths.append(model_path or base_model)
        return FakeSampler()

    def create_rest_client(self):
        return self.rest_client


class BadRequestError(Exception):
    pass


class ProviderBadRequestError(BadRequestError):
    def __init__(self, message, *, body, status_code=400):
        super().__init__(message)
        self.body = body
        self.status_code = status_code


FAKE_PROVIDER_KEY = "tml-" + ("A" * 24)
FAKE_PROVIDER_EMAIL = "luc@example.com"
FAKE_PROVIDER_CARD = "4242 4242 4242 4242"


class FailingServiceClient(FakeServiceClient):
    def get_server_capabilities(self):
        return {
            "supported_models": [
                "Qwen/Qwen3-8B",
                "Qwen/Qwen3-32B",
            ],
            "max_batch_size": 16,
        }

    def create_lora_training_client(self, **kwargs):
        self.training_kwargs = kwargs
        raise BadRequestError(
            "Bad request for model meta-llama/Llama-3.2-1B rank 4 "
            f"using key {FAKE_PROVIDER_KEY}, "
            f"operator {FAKE_PROVIDER_EMAIL}, card {FAKE_PROVIDER_CARD}, "
            "request 123e4567-e89b-12d3-a456-426614174000"
        )


class CapabilityServiceClient(FakeServiceClient):
    def get_server_capabilities(self):
        return {
            "supported_models": [
                "meta-llama/Llama-3.2-1B",
                "Qwen/Qwen3-8B",
            ],
            "max_batch_size": 8,
        }


class CapabilityProbeFailingServiceClient(FakeServiceClient):
    def get_server_capabilities(self):
        raise PermissionError(
            f"provider body with {FAKE_PROVIDER_KEY} and {FAKE_PROVIDER_EMAIL}"
        )


class ServiceClientCreateFailingServiceClient(FakeServiceClient):
    def __init__(self, api_key, project_id=None, base_url=None):
        raise BadRequestError(
            "Bad request creating session "
            f"with key {FAKE_PROVIDER_KEY}, project {project_id}, base {base_url}"
        )


class ProviderClassifiedServiceClient(FakeServiceClient):
    def __init__(self, api_key, project_id=None, base_url=None):
        raise ProviderBadRequestError(
            f"provider request failed for {api_key}",
            body={
                "error": {
                    "code": "api_key_revoked",
                    "message": f"API key revoked for {FAKE_PROVIDER_EMAIL}",
                    "request_id": "123e4567-e89b-12d3-a456-426614174000",
                }
            },
        )


import time as _time  # noqa: E402


class HangingConnectServiceClient(FakeServiceClient):
    """Mimics a blocked account whose ServiceClient connect never returns."""

    def __init__(self, api_key, project_id=None, base_url=None):
        _time.sleep(30)  # abandoned by the smoke deadline; test stays fast
        super().__init__(api_key, project_id, base_url)


class HangingTrainingServiceClient(FakeServiceClient):
    """Connects fine, then hangs on the first training-creation call."""

    def create_lora_training_client(self, **kwargs):
        _time.sleep(30)
        return super().create_lora_training_client(**kwargs)


FAKE_TINKER = types.SimpleNamespace(
    ServiceClient=FakeServiceClient,
    TrainingClient=object,
    SamplingClient=object,
    Datum=Datum,
    ModelInput=ModelInput,
    TensorData=TensorData,
    AdamParams=AdamParams,
    SamplingParams=SamplingParams,
)
sys.modules["tinker"] = FAKE_TINKER


def _hanging_tinker(service_client_cls):
    ns = types.SimpleNamespace(**vars(FAKE_TINKER))
    ns.ServiceClient = service_client_cls
    return ns

from tinker_delegate.config import Settings  # noqa: E402
from tinker_delegate import session as session_module  # noqa: E402
from tinker_delegate.tinker_client_config_store import save_tinker_client_config  # noqa: E402
from tinker_delegate.tinker_encumbrance import TinkerEncumbrancePolicyResult  # noqa: E402
from tinker_delegate.tinker_smoke import (  # noqa: E402
    TinkerSmokeRequest,
    run_tinker_sdk_smoke,
)


def _allowed_policy():
    return TinkerEncumbrancePolicyResult(
        checked=True,
        allowed=True,
        reason="allowed",
        operation="spend_tinker_compute",
        operation_kind=2,
        compose_hash="0x" + "11" * 32,
        compose_approved=True,
        amount_wei=50_000_000_000_000_000,
        max_amount_wei=10_000_000_000_000_000_000,
        limit_kind="spend",
    )


class TinkerSmokeTest(unittest.TestCase):
    def test_smoke_runs_tiny_training_sampling_and_cleanup_with_bounded_output(self):
        with (
            patch.object(session_module, "tinker", FAKE_TINKER),
            patch("tinker_delegate.tinker_smoke.resolve_api_key", return_value="tml-secret-value"),
            patch("tinker_delegate.tinker_smoke.preflight_tinker_operation", return_value=_allowed_policy()),
        ):
            result = run_tinker_sdk_smoke(
                Settings(real_sdk_max_usd=0.05),
                TinkerSmokeRequest(deal_id="deal-secret", max_usd=0.05, ttl_seconds=3600),
            )

        rendered = json.dumps(result)
        self.assertTrue(result["success"])
        self.assertEqual(result["outcome"], "success")
        self.assertEqual(result["furthest_stage"], "cleanup_completed")
        self.assertTrue(result["sample_observed"])
        self.assertFalse(result["sample_output_returned"])
        self.assertTrue(result["cleanup"]["success"])
        self.assertEqual(result["cleanup"]["listed_checkpoint_count"], 1)
        self.assertEqual(result["cleanup"]["deleted_checkpoint_count"], 1)
        self.assertFalse(result["raw_secret_egress"])
        self.assertEqual(result["sdk_error"]["bucket"], "")
        self.assertEqual(result["sdk_diagnostics"]["capabilities"]["checked"], False)
        self.assertNotIn("tml-secret-value", rendered)
        self.assertNotIn("deal-secret", rendered)
        self.assertNotIn("run-secret", rendered)
        self.assertNotIn("cp-secret", rendered)
        self.assertNotIn("tinker://", rendered)
        self.assertNotIn("this sample must never leave", rendered)

        service_client = FakeServiceClient.last_instance
        self.assertEqual(service_client.training_kwargs["base_model"], "Qwen/Qwen3-8B")
        self.assertEqual(service_client.training_kwargs["rank"], 32)
        self.assertEqual(service_client.training_client.save_calls, [("budgeted-smoke", 3600)])
        self.assertEqual(service_client.rest_client.deleted, [("run-secret", "cp-secret")])

    def test_smoke_passes_project_id_without_leaking_it(self):
        with (
            patch.object(session_module, "tinker", FAKE_TINKER),
            patch("tinker_delegate.tinker_smoke.resolve_api_key", return_value="tml-secret-value"),
            patch("tinker_delegate.tinker_smoke.preflight_tinker_operation", return_value=_allowed_policy()),
        ):
            result = run_tinker_sdk_smoke(
                Settings(
                    real_sdk_max_usd=0.05,
                    project_id="proj-secret",
                    base_url="https://custom.thinkingmachines.dev/services/tinker-prod",
                ),
                TinkerSmokeRequest(deal_id="deal-secret", max_usd=0.05),
            )

        rendered = json.dumps(result)
        self.assertTrue(result["success"])
        self.assertEqual(FakeServiceClient.last_instance.project_id, "proj-secret")
        self.assertEqual(
            FakeServiceClient.last_instance.base_url,
            "https://custom.thinkingmachines.dev/services/tinker-prod",
        )
        self.assertTrue(result["sdk_diagnostics"]["project"]["configured"])
        self.assertRegex(result["sdk_diagnostics"]["project"]["project_hash"], r"^[0-9a-f]{64}$")
        client_config = result["sdk_diagnostics"]["client_config"]
        self.assertEqual(client_config["api_key_argument"], "provided")
        self.assertEqual(client_config["project_id_argument"], "provided")
        self.assertEqual(client_config["base_url_argument"], "provided")
        self.assertEqual(client_config["base_url_host_family"], "thinkingmachines")
        self.assertRegex(client_config["base_url_hash"], r"^[0-9a-f]{64}$")
        self.assertNotIn("proj-secret", rendered)
        self.assertNotIn("custom.thinkingmachines.dev", rendered)

    def test_blocked_account_connect_fails_fast_with_timeout_verdict(self):
        hanging = _hanging_tinker(HangingConnectServiceClient)
        started = _time.monotonic()
        with (
            patch.dict(sys.modules, {"tinker": hanging}),
            patch.object(session_module, "tinker", hanging),
            patch("tinker_delegate.tinker_smoke.resolve_api_key", return_value="tml-secret-value"),
            patch("tinker_delegate.tinker_smoke.preflight_tinker_operation", return_value=_allowed_policy()),
        ):
            result = run_tinker_sdk_smoke(
                Settings(real_sdk_max_usd=0.05, smoke_connect_timeout=1.0),
                TinkerSmokeRequest(deal_id="deal-secret", max_usd=0.05),
            )
        elapsed = _time.monotonic() - started
        # Fast fail: returns within a few seconds, not the 30s hang.
        self.assertLess(elapsed, 10.0)
        self.assertFalse(result["success"])
        self.assertEqual(result["outcome"], "smoke_failed")
        self.assertEqual(result["furthest_stage"], "api_key_loaded")
        self.assertEqual(result["sdk_error"]["bucket"], "transient_timeout")
        self.assertEqual(result["sdk_error"]["failure_site"], "service_client_create")
        self.assertEqual(
            result["sdk_error"]["operator_action"],
            "retry_or_check_tinker_account_activation",
        )
        self.assertFalse(result["raw_secret_egress"])
        self.assertNotIn("tml-secret-value", json.dumps(result))

    def test_blocked_account_training_creation_fails_fast_with_timeout_verdict(self):
        hanging = _hanging_tinker(HangingTrainingServiceClient)
        started = _time.monotonic()
        with (
            patch.dict(sys.modules, {"tinker": hanging}),
            patch.object(session_module, "tinker", hanging),
            patch("tinker_delegate.tinker_smoke.resolve_api_key", return_value="tml-secret-value"),
            patch("tinker_delegate.tinker_smoke.preflight_tinker_operation", return_value=_allowed_policy()),
        ):
            result = run_tinker_sdk_smoke(
                Settings(real_sdk_max_usd=0.05, smoke_connect_timeout=1.0),
                TinkerSmokeRequest(deal_id="deal-secret", max_usd=0.05),
            )
        elapsed = _time.monotonic() - started
        self.assertLess(elapsed, 10.0)
        self.assertFalse(result["success"])
        self.assertEqual(result["sdk_error"]["bucket"], "transient_timeout")
        self.assertEqual(result["sdk_error"]["failure_site"], "create_training_client")
        self.assertEqual(result["sdk_error"]["operator_action"], "retry_later")

    def test_smoke_uses_stored_project_id_without_leaking_it(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = Settings(
                real_sdk_max_usd=0.05,
                project_id="",
                base_url="",
                client_config_store_path=f"{tmpdir}/client_config.enc",
                client_config_store_key="88" * 32,
            )
            save_tinker_client_config(
                settings,
                project_id="proj-secret",
                base_url="https://custom.thinkingmachines.dev/services/tinker-prod",
            )
            with (
                patch.object(session_module, "tinker", FAKE_TINKER),
                patch("tinker_delegate.tinker_smoke.resolve_api_key", return_value="tml-secret-value"),
                patch("tinker_delegate.tinker_smoke.preflight_tinker_operation", return_value=_allowed_policy()),
            ):
                result = run_tinker_sdk_smoke(
                    settings,
                    TinkerSmokeRequest(deal_id="deal-secret", max_usd=0.05),
                )

        rendered = json.dumps(result)
        self.assertTrue(result["success"])
        self.assertEqual(FakeServiceClient.last_instance.project_id, "proj-secret")
        self.assertEqual(
            FakeServiceClient.last_instance.base_url,
            "https://custom.thinkingmachines.dev/services/tinker-prod",
        )
        self.assertEqual(result["sdk_diagnostics"]["client_config"]["project_id_argument"], "provided")
        self.assertEqual(result["sdk_diagnostics"]["client_config"]["base_url_argument"], "provided")
        self.assertNotIn("proj-secret", rendered)
        self.assertNotIn("custom.thinkingmachines.dev", rendered)

    def test_smoke_fails_closed_when_encumbrance_denies(self):
        denied = TinkerEncumbrancePolicyResult(
            checked=True,
            allowed=False,
            reason="compose_hash_not_approved",
            operation="spend_tinker_compute",
            operation_kind=2,
        )
        with (
            patch("tinker_delegate.tinker_smoke.resolve_api_key", return_value="tml-secret-value") as resolve_key,
            patch("tinker_delegate.tinker_smoke.preflight_tinker_operation", return_value=denied),
        ):
            result = run_tinker_sdk_smoke(
                Settings(),
                TinkerSmokeRequest(max_usd=0.05, require_encumbrance=True),
            )

        self.assertFalse(result["success"])
        self.assertEqual(result["outcome"], "policy_denied")
        self.assertEqual(result["furthest_stage"], "policy_checked")
        self.assertEqual(result["error_kind"], "compose_hash_not_approved")
        resolve_key.assert_not_called()

    def test_smoke_fails_closed_when_policy_check_raises(self):
        with (
            patch("tinker_delegate.tinker_smoke.resolve_api_key", return_value="tml-secret-value") as resolve_key,
            patch("tinker_delegate.tinker_smoke.preflight_tinker_operation", side_effect=RuntimeError("rpc exploded")),
        ):
            result = run_tinker_sdk_smoke(
                Settings(),
                TinkerSmokeRequest(max_usd=0.05, require_encumbrance=True),
            )

        self.assertFalse(result["success"])
        self.assertEqual(result["outcome"], "policy_check_failed")
        self.assertEqual(result["furthest_stage"], "policy_checked")
        self.assertEqual(result["policy"]["reason"], "policy_check_exception")
        self.assertEqual(result["error_kind"], "RuntimeError")
        self.assertNotIn("rpc exploded", json.dumps(result))
        self.assertFalse(result["raw_secret_egress"])
        resolve_key.assert_not_called()

    def test_smoke_sdk_failure_has_bounded_diagnostics_without_raw_message(self):
        with (
            patch.object(FAKE_TINKER, "ServiceClient", FailingServiceClient),
            patch.object(session_module, "tinker", FAKE_TINKER),
            patch("tinker_delegate.tinker_smoke.resolve_api_key", return_value="tml-secret-value"),
            patch("tinker_delegate.tinker_smoke.preflight_tinker_operation", return_value=_allowed_policy()),
        ):
            result = run_tinker_sdk_smoke(
                Settings(real_sdk_max_usd=0.05),
                TinkerSmokeRequest(deal_id="deal-secret", max_usd=0.05),
            )

        rendered = json.dumps(result)
        self.assertFalse(result["success"])
        self.assertEqual(result["outcome"], "smoke_failed")
        self.assertEqual(result["furthest_stage"], "api_key_loaded")
        self.assertEqual(result["error_kind"], "BadRequestError")
        self.assertEqual(result["sdk_error"]["bucket"], "model_or_rank")
        self.assertEqual(result["sdk_error"]["http_status_class"], "4xx")
        self.assertEqual(result["sdk_error"]["failure_site"], "create_training_client")
        self.assertEqual(result["sdk_error"]["operator_action"], "check_project_or_account_entitlement")
        self.assertRegex(result["sdk_error"]["message_hash"], r"^[0-9a-f]{64}$")
        self.assertIn(result["sdk_error"]["message_length_band"], {"<=64", "<=256", "<=512"})
        diagnostics = result["sdk_diagnostics"]
        self.assertEqual(diagnostics["training_create"]["method"], "ServiceClient.create_lora_training_client")
        self.assertEqual(diagnostics["training_create"]["explicit_kwargs"], ["base_model", "rank"])
        self.assertEqual(diagnostics["training_create"]["injected_user_metadata_keys"], ["deal_id"])
        self.assertEqual(diagnostics["training_create"]["model_family"], "qwen")
        self.assertEqual(diagnostics["training_create"]["rank_band"], "<=32")
        self.assertEqual(
            diagnostics["training_create"]["request_shape"],
            {
                "has_base_model": True,
                "has_rank": True,
                "has_user_metadata_deal_id": True,
                "extra_kwargs_count": 0,
            },
        )
        self.assertFalse(diagnostics["project"]["configured"])
        self.assertEqual(diagnostics["client_config"]["api_key_argument"], "provided")
        self.assertEqual(diagnostics["client_config"]["project_id_argument"], "omitted")
        self.assertEqual(diagnostics["client_config"]["base_url_argument"], "sdk_default")
        self.assertEqual(diagnostics["client_config"]["base_url_host_family"], "sdk_default")
        self.assertEqual(diagnostics["capabilities"]["checked"], True)
        self.assertEqual(diagnostics["capabilities"]["attempted_model_supported"], True)
        self.assertEqual(diagnostics["capabilities"]["supported_model_count_band"], "1-10")
        self.assertEqual(diagnostics["capabilities"]["max_batch_size_band"], "<=32")
        self.assertRegex(diagnostics["capabilities"]["supported_models_hash"], r"^[0-9a-f]{64}$")
        self.assertNotIn("Bad request for model", rendered)
        self.assertNotIn("Qwen/Qwen3-8B", rendered)
        self.assertNotIn("Qwen/Qwen3-32B", rendered)
        self.assertNotIn("meta-llama/Llama-3.2-1B", rendered)
        self.assertNotIn(FAKE_PROVIDER_KEY, rendered)
        self.assertNotIn(FAKE_PROVIDER_EMAIL, rendered)
        self.assertNotIn(FAKE_PROVIDER_CARD, rendered)
        self.assertNotIn("123e4567-e89b-12d3-a456-426614174000", rendered)
        self.assertNotIn("deal-secret", rendered)
        self.assertFalse(result["raw_secret_egress"])

    def test_smoke_service_client_create_failure_keeps_bounded_client_config(self):
        with (
            patch.object(FAKE_TINKER, "ServiceClient", ServiceClientCreateFailingServiceClient),
            patch.object(session_module, "tinker", FAKE_TINKER),
            patch("tinker_delegate.tinker_smoke.resolve_api_key", return_value="tml-secret-value"),
            patch("tinker_delegate.tinker_smoke.preflight_tinker_operation", return_value=_allowed_policy()),
        ):
            result = run_tinker_sdk_smoke(
                Settings(
                    real_sdk_max_usd=0.05,
                    project_id="proj-secret",
                    base_url="https://custom.thinkingmachines.dev/services/tinker-prod",
                ),
                TinkerSmokeRequest(deal_id="deal-secret", max_usd=0.05),
            )

        rendered = json.dumps(result)
        self.assertFalse(result["success"])
        self.assertEqual(result["furthest_stage"], "api_key_loaded")
        self.assertEqual(result["sdk_error"]["failure_site"], "service_client_create")
        self.assertEqual(result["sdk_error"]["operator_action"], "check_sdk_client_configuration")
        diagnostics = result["sdk_diagnostics"]
        self.assertTrue(diagnostics["project"]["configured"])
        self.assertRegex(diagnostics["project"]["project_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(diagnostics["client_config"]["api_key_argument"], "provided")
        self.assertEqual(diagnostics["client_config"]["project_id_argument"], "provided")
        self.assertEqual(diagnostics["client_config"]["base_url_argument"], "provided")
        self.assertEqual(diagnostics["client_config"]["base_url_host_family"], "thinkingmachines")
        self.assertRegex(diagnostics["client_config"]["base_url_hash"], r"^[0-9a-f]{64}$")
        self.assertFalse(diagnostics["capabilities"]["checked"])
        self.assertNotIn("proj-secret", rendered)
        self.assertNotIn("custom.thinkingmachines.dev", rendered)
        self.assertNotIn(FAKE_PROVIDER_KEY, rendered)

    def test_smoke_provider_error_is_allowlisted_without_raw_body(self):
        with (
            patch.object(FAKE_TINKER, "ServiceClient", ProviderClassifiedServiceClient),
            patch.object(session_module, "tinker", FAKE_TINKER),
            patch("tinker_delegate.tinker_smoke.resolve_api_key", return_value=FAKE_PROVIDER_KEY),
            patch("tinker_delegate.tinker_smoke.preflight_tinker_operation", return_value=_allowed_policy()),
        ):
            result = run_tinker_sdk_smoke(
                Settings(real_sdk_max_usd=0.05),
                TinkerSmokeRequest(deal_id="deal-secret", max_usd=0.05),
            )

        rendered = json.dumps(result)
        self.assertFalse(result["success"])
        self.assertEqual(result["sdk_error"]["provider_error_category"], "inactive_api_key")
        self.assertEqual(result["sdk_error"]["http_status"], 400)
        self.assertEqual(result["sdk_error"]["http_status_class"], "4xx")
        self.assertEqual(result["sdk_error"]["operator_action"], "refresh_or_reseal_api_key")
        self.assertNotIn("api_key_revoked", rendered)
        self.assertNotIn("API key revoked", rendered)
        self.assertNotIn(FAKE_PROVIDER_EMAIL, rendered)
        self.assertNotIn(FAKE_PROVIDER_KEY, rendered)
        self.assertNotIn("123e4567", rendered)
        self.assertFalse(result["raw_secret_egress"])

    def test_smoke_capabilities_probe_success_does_not_leak_model_list(self):
        with (
            patch.object(FAKE_TINKER, "ServiceClient", CapabilityServiceClient),
            patch.object(session_module, "tinker", FAKE_TINKER),
            patch("tinker_delegate.tinker_smoke.resolve_api_key", return_value="tml-secret-value"),
            patch("tinker_delegate.tinker_smoke.preflight_tinker_operation", return_value=_allowed_policy()),
        ):
            result = run_tinker_sdk_smoke(
                Settings(real_sdk_max_usd=0.05),
                TinkerSmokeRequest(deal_id="deal-secret", max_usd=0.05),
            )

        rendered = json.dumps(result)
        self.assertTrue(result["success"])
        diagnostics = result["sdk_diagnostics"]
        self.assertEqual(diagnostics["capabilities"]["checked"], True)
        self.assertEqual(diagnostics["capabilities"]["attempted_model_supported"], True)
        self.assertEqual(diagnostics["capabilities"]["supported_model_count_band"], "1-10")
        self.assertEqual(diagnostics["capabilities"]["max_batch_size_band"], "<=8")
        self.assertRegex(diagnostics["capabilities"]["supported_models_hash"], r"^[0-9a-f]{64}$")
        self.assertNotIn("meta-llama/Llama-3.2-1B", rendered)
        self.assertNotIn("Qwen/Qwen3-8B", rendered)
        self.assertNotIn("tml-secret-value", rendered)
        self.assertNotIn("deal-secret", rendered)

    def test_smoke_capabilities_probe_failure_is_bounded_and_non_blocking(self):
        with (
            patch.object(FAKE_TINKER, "ServiceClient", CapabilityProbeFailingServiceClient),
            patch.object(session_module, "tinker", FAKE_TINKER),
            patch("tinker_delegate.tinker_smoke.resolve_api_key", return_value="tml-secret-value"),
            patch("tinker_delegate.tinker_smoke.preflight_tinker_operation", return_value=_allowed_policy()),
        ):
            result = run_tinker_sdk_smoke(
                Settings(real_sdk_max_usd=0.05),
                TinkerSmokeRequest(deal_id="deal-secret", max_usd=0.05),
            )

        rendered = json.dumps(result)
        self.assertTrue(result["success"])
        diagnostics = result["sdk_diagnostics"]
        self.assertEqual(diagnostics["capabilities"]["checked"], True)
        self.assertEqual(diagnostics["capabilities"]["error_kind"], "PermissionError")
        self.assertEqual(diagnostics["capabilities"]["http_status_class"], "4xx")
        self.assertNotIn("provider body", rendered)
        self.assertNotIn(FAKE_PROVIDER_KEY, rendered)
        self.assertNotIn(FAKE_PROVIDER_EMAIL, rendered)

    def test_smoke_rejects_overlarge_budget_before_sdk_call(self):
        with self.assertRaisesRegex(ValueError, "<= 0.5"):
            run_tinker_sdk_smoke(Settings(), TinkerSmokeRequest(max_usd=0.51))


if __name__ == "__main__":
    unittest.main()
