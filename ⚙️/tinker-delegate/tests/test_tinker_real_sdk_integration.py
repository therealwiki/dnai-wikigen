import os
import sys
import types
import unittest
import uuid
from decimal import Decimal, InvalidOperation
from unittest.mock import patch


ENABLE_ENV = "TINKER_RUN_REAL_SDK_TESTS"
API_KEY_ENV = "TINKER_API_KEY"
BUDGET_ENV = "TINKER_REAL_SDK_MAX_USD"
MODEL_ENV = "TINKER_REAL_SDK_MODEL"
RANK_ENV = "TINKER_REAL_SDK_RANK"
PROJECT_ID_ENV = "TINKER_PROJECT_ID"
BASE_URL_ENV = "TINKER_BASE_URL"
HARD_MAX_USD = Decimal("0.50")
DEFAULT_MODEL = "Qwen/Qwen3-8B"


def _enabled() -> bool:
    return os.environ.get(ENABLE_ENV, "").strip().lower() in {"1", "true", "yes"}


_TINKER_IMPORT_ERROR = None
try:
    import tinker as _real_tinker  # noqa: F401
except Exception as exc:  # pragma: no cover - exercised when optional extra is absent.
    _TINKER_IMPORT_ERROR = exc
    sys.modules.setdefault(
        "tinker",
        types.SimpleNamespace(ServiceClient=object, TrainingClient=object, SamplingClient=object),
    )

from tinker_delegate.session import DEFAULT_TTL, IsolatedTinkerSession  # noqa: E402


def _budget_cap_usd() -> Decimal:
    raw_budget = os.environ.get(BUDGET_ENV, "").strip()
    if not raw_budget:
        raise AssertionError(f"{BUDGET_ENV} is required when {ENABLE_ENV}=1")
    try:
        budget = Decimal(raw_budget)
    except InvalidOperation as exc:
        raise AssertionError(f"{BUDGET_ENV} must be a decimal USD amount") from exc
    if budget <= 0:
        raise AssertionError(f"{BUDGET_ENV} must be positive")
    if budget > HARD_MAX_USD:
        raise AssertionError(f"{BUDGET_ENV} must be <= {HARD_MAX_USD} for this smoke test")
    return budget


def _wait(value):
    if hasattr(value, "result"):
        return value.result()
    return value


def _service_client_kwargs(api_key: str) -> dict[str, str]:
    kwargs = {"api_key": api_key}
    project_id = os.environ.get(PROJECT_ID_ENV, "").strip()
    base_url = os.environ.get(BASE_URL_ENV, "").strip()
    if project_id:
        kwargs["project_id"] = project_id
    if base_url:
        kwargs["base_url"] = base_url
    return kwargs


class TinkerRealSdkGateTest(unittest.TestCase):
    def test_budget_cap_requires_decimal_value(self):
        with patch.dict(os.environ, {BUDGET_ENV: ""}, clear=False):
            with self.assertRaisesRegex(AssertionError, "required"):
                _budget_cap_usd()
        with patch.dict(os.environ, {BUDGET_ENV: "not-money"}, clear=False):
            with self.assertRaisesRegex(AssertionError, "decimal"):
                _budget_cap_usd()

    def test_budget_cap_rejects_non_positive_or_high_values(self):
        with patch.dict(os.environ, {BUDGET_ENV: "0"}, clear=False):
            with self.assertRaisesRegex(AssertionError, "positive"):
                _budget_cap_usd()
        with patch.dict(os.environ, {BUDGET_ENV: "0.51"}, clear=False):
            with self.assertRaisesRegex(AssertionError, "<= 0.50"):
                _budget_cap_usd()

    def test_budget_cap_accepts_low_value(self):
        with patch.dict(os.environ, {BUDGET_ENV: "0.05"}, clear=False):
            self.assertEqual(_budget_cap_usd(), Decimal("0.05"))

    def test_service_client_kwargs_include_optional_project_and_base_url(self):
        env = {
            PROJECT_ID_ENV: "proj-secret",
            BASE_URL_ENV: "https://custom.thinkingmachines.dev/services/tinker-prod",
        }
        with patch.dict(os.environ, env, clear=False):
            self.assertEqual(
                _service_client_kwargs("tml-secret-value"),
                {
                    "api_key": "tml-secret-value",
                    "project_id": "proj-secret",
                    "base_url": "https://custom.thinkingmachines.dev/services/tinker-prod",
                },
            )

    def test_service_client_kwargs_omit_blank_optional_values(self):
        env = {
            PROJECT_ID_ENV: "",
            BASE_URL_ENV: "  ",
        }
        with patch.dict(os.environ, env, clear=False):
            self.assertEqual(_service_client_kwargs("tml-secret-value"), {"api_key": "tml-secret-value"})


@unittest.skipUnless(_enabled(), f"set {ENABLE_ENV}=1 to run real Tinker SDK tests")
class TinkerRealSdkIntegrationTest(unittest.TestCase):
    """Real Tinker smoke tests.

    These tests intentionally do not run during normal CI or local unit-test
    discovery. Enabling them makes live Tinker API calls and may consume paid
    credits, so the caller must opt in and provide an explicit low USD cap.
    """

    def setUp(self):
        api_key = os.environ.get(API_KEY_ENV, "").strip()
        if not api_key:
            self.fail(f"{API_KEY_ENV} is required when {ENABLE_ENV}=1")
        self.budget_cap_usd = _budget_cap_usd()
        if _TINKER_IMPORT_ERROR is not None:
            self.fail(
                "The optional `tinker` package is required when "
                f"{ENABLE_ENV}=1; install with `uv sync --extra agent`"
            )
        try:
            import tinker  # noqa: PLC0415
        except Exception as exc:
            raise AssertionError(
                "The optional `tinker` package is required when "
                f"{ENABLE_ENV}=1; install with `uv sync --extra agent`"
            ) from exc
        self.tinker = tinker

    def _assert_meter_within_cap(self, session: IsolatedTinkerSession) -> None:
        spent = Decimal(str(session.meter.total_cost_usd))
        self.assertLessEqual(
            spent,
            self.budget_cap_usd,
            f"metered Tinker cost {spent} exceeded {BUDGET_ENV}={self.budget_cap_usd}",
        )

    def test_tiny_training_sampling_and_cleanup(self):
        model = os.environ.get(MODEL_ENV, DEFAULT_MODEL)
        rank = int(os.environ.get(RANK_ENV, "4"))
        deal_id = f"real-sdk-smoke-{uuid.uuid4()}"
        service_client = self.tinker.ServiceClient(**_service_client_kwargs(os.environ[API_KEY_ENV]))
        session = IsolatedTinkerSession(service_client, deal_id)
        run_id = None

        try:
            session.create_training(base_model=model, rank=rank)
            run_id = session.training_run_id
            tokenizer = session.get_tokenizer()

            prompt_tokens = tokenizer.encode("Question: What is 2 + 2?\nAnswer:", add_special_tokens=True)
            completion_tokens = tokenizer.encode(" 4", add_special_tokens=False)
            all_tokens = prompt_tokens + completion_tokens
            self.assertGreaterEqual(len(all_tokens), 4)

            input_tokens = all_tokens[:-1]
            target_tokens = all_tokens[1:]
            weights = [0.0] * max(0, len(prompt_tokens) - 1) + [1.0] * len(completion_tokens)
            weights = weights[: len(target_tokens)]

            datum = self.tinker.Datum(
                model_input=self.tinker.ModelInput.from_ints(input_tokens),
                loss_fn_inputs={
                    "weights": self.tinker.TensorData(
                        data=weights,
                        dtype="float32",
                        shape=[len(weights)],
                    ),
                    "target_tokens": self.tinker.TensorData(
                        data=target_tokens,
                        dtype="int64",
                        shape=[len(target_tokens)],
                    ),
                },
            )

            _wait(session.forward_backward([datum], loss_fn="cross_entropy"))
            self._assert_meter_within_cap(session)
            _wait(session.optim_step(self.tinker.AdamParams(learning_rate=1e-4)))

            checkpoint_path = session.save_for_sampling("budgeted-smoke", ttl_seconds=DEFAULT_TTL)
            self.assertIn(str(run_id), checkpoint_path)
            sampler = session.create_sampler(checkpoint_path)

            sampling_params = self.tinker.SamplingParams(max_tokens=1, temperature=0)
            sample_result = _wait(
                session.sample(
                    sampler,
                    self.tinker.ModelInput.from_ints(prompt_tokens),
                    sampling_params=sampling_params,
                    num_samples=1,
                )
            )
            self.assertIsNotNone(sample_result)
            self._assert_meter_within_cap(session)
        finally:
            session.cleanup()

        if run_id:
            checkpoints = _wait(service_client.create_rest_client().list_checkpoints(run_id))
            self.assertEqual(checkpoints, [])


if __name__ == "__main__":
    unittest.main()
