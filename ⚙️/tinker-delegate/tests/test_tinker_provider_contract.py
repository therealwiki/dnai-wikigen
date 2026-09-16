"""Executable audit of the pinned Tinker SDK's public recovery surface.

These tests deliberately make no network requests and use no provider
credential.  They record why the exact-asset worker must remain fail-closed:
the generated transport has an idempotency header hook, but the supported
public training workflow does not bind a caller-stable dispatch identifier to
model creation and every paid operation, or expose an exact recovery lookup by
that identifier.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import inspect
import json
import sys
import unittest
from pathlib import Path

import httpx


try:
    importlib.metadata.version("tinker")
except importlib.metadata.PackageNotFoundError:
    TINKER_INSTALLED = False
else:
    TINKER_INSTALLED = True


@unittest.skipUnless(TINKER_INSTALLED, "install the locked agent extra to audit Tinker")
class TinkerProviderContractAuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Isolate the real SDK from legacy tests' process-global fake module.

        Several older no-SDK unit tests deliberately install a minimal
        ``sys.modules['tinker']`` stub during discovery.  The capability audit
        must inspect the installed distribution instead, then restore the
        exact prior module table so it cannot perturb neighboring tests.
        """

        super().setUpClass()
        cls._saved_tinker_modules = {
            name: module
            for name, module in list(sys.modules.items())
            if name == "tinker" or name.startswith("tinker.")
        }
        for name in cls._saved_tinker_modules:
            sys.modules.pop(name, None)

    @classmethod
    def tearDownClass(cls):
        for name in list(sys.modules):
            if name == "tinker" or name.startswith("tinker."):
                sys.modules.pop(name, None)
        sys.modules.update(cls._saved_tinker_modules)
        super().tearDownClass()

    def test_audit_is_pinned_to_locked_sdk_release(self):
        self.assertEqual(importlib.metadata.version("tinker"), "0.22.7")
        lock = (Path(__file__).resolve().parents[1] / "uv.lock").read_text()
        self.assertIn('name = "tinker"\nversion = "0.22.7"', lock)

    def test_public_model_creation_cannot_accept_worker_dispatch_id(self):
        from tinker import ServiceClient

        parameters = inspect.signature(
            ServiceClient.create_lora_training_client
        ).parameters
        self.assertIn("user_metadata", parameters)
        self.assertNotIn("dispatch_id", parameters)
        self.assertNotIn("idempotency_key", parameters)
        self.assertNotIn("request_id", parameters)

    def test_public_paid_training_steps_cannot_accept_stable_replay_key(self):
        from tinker.lib.public_interfaces.training_client import TrainingClient

        for method_name in (
            "forward",
            "forward_backward",
            "optim_step",
            "save_state",
            "save_weights_for_sampler",
        ):
            with self.subTest(method=method_name):
                parameters = inspect.signature(
                    getattr(TrainingClient, method_name)
                ).parameters
                self.assertNotIn("dispatch_id", parameters)
                self.assertNotIn("idempotency_key", parameters)
                self.assertNotIn("request_id", parameters)

    def test_public_paid_sampling_cannot_accept_stable_replay_key(self):
        from tinker.lib.public_interfaces.sampling_client import SamplingClient

        for method_name in ("sample", "compute_logprobs"):
            with self.subTest(method=method_name):
                parameters = inspect.signature(
                    getattr(SamplingClient, method_name)
                ).parameters
                self.assertNotIn("dispatch_id", parameters)
                self.assertNotIn("idempotency_key", parameters)
                self.assertNotIn("request_id", parameters)

    def test_training_run_listing_is_not_an_exact_dispatch_lookup(self):
        from tinker.lib.public_interfaces.rest_client import RestClient

        parameters = inspect.signature(RestClient.list_training_runs).parameters
        self.assertEqual(
            set(parameters),
            {"self", "limit", "offset", "access_scope", "project_id"},
        )
        self.assertNotIn("user_metadata", parameters)
        self.assertNotIn("dispatch_id", parameters)
        self.assertNotIn("idempotency_key", parameters)

    def test_low_level_header_hook_is_random_without_explicit_plumbing(self):
        from tinker._client import AsyncTinker
        from tinker.resources.models import AsyncModelsResource
        from tinker.resources.sampling import AsyncSamplingResource
        from tinker.resources.service import AsyncServiceResource
        from tinker.resources.training import AsyncTrainingResource
        from tinker.resources.weights import AsyncWeightsResource

        # The generated transport does have a useful primitive.  This test
        # prevents the audit from incorrectly claiming otherwise.  The public
        # workflow above simply does not accept or durably recover our key.
        self.assertIn(
            "idempotency_key",
            inspect.signature(AsyncModelsResource.create).parameters,
        )
        self.assertIn(
            "idempotency_key",
            inspect.signature(AsyncServiceResource.create_session).parameters,
        )
        for method_name in ("forward_backward", "optim_step"):
            self.assertIn(
                "idempotency_key",
                inspect.signature(
                    getattr(AsyncTrainingResource, method_name)
                ).parameters,
            )
        self.assertIn(
            "idempotency_key",
            inspect.signature(AsyncSamplingResource.asample).parameters,
        )
        for method_name in ("load", "save", "save_for_sampler"):
            self.assertIn(
                "idempotency_key",
                inspect.signature(
                    getattr(AsyncWeightsResource, method_name)
                ).parameters,
            )

        sampling_session_parameters = inspect.signature(
            AsyncServiceResource.create_sampling_session
        ).parameters
        self.assertNotIn("idempotency_key", sampling_session_parameters)
        self.assertIn("extra_headers", sampling_session_parameters)

        client = object.__new__(AsyncTinker)
        first = client._idempotency_key()
        second = client._idempotency_key()
        self.assertRegex(first, r"^stainless-python-retry-[0-9a-f-]+$")
        self.assertNotEqual(first, second)

    def test_sampling_session_extra_header_reaches_transport_but_proves_no_server_contract(self):
        """Pin the 0.22.7 workaround without treating it as conformance.

        ``create_sampling_session`` omits the generated ``idempotency_key``
        argument.  Its documented escape hatch still lets an adapter send the
        same header, and the base client does not overwrite it with its random
        retry key.  A mock transport can prove only those local bytes.  It
        cannot prove retention, conflict rejection, one mutation, or replayed
        response semantics at Tinker's authenticated server boundary.
        """

        from tinker._client import AsyncTinker
        from tinker.types.create_sampling_session_request import (
            CreateSamplingSessionRequest,
        )

        observed: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            observed.append(request)
            return httpx.Response(
                200,
                json={"sampling_session_id": "sampling-session-test-only"},
            )

        async def exercise() -> None:
            transport = httpx.MockTransport(handler)
            async with httpx.AsyncClient(transport=transport) as http_client:
                client = AsyncTinker(
                    api_key="".join(("tml-", "test-only-no-network-credential")),
                    base_url="https://tinker.invalid",
                    http_client=http_client,
                    max_retries=0,
                )
                await client.service.create_sampling_session(
                    request=CreateSamplingSessionRequest(
                        session_id="session-test-only",
                        sampling_session_seq_id=0,
                        base_model="Qwen/Qwen3-8B",
                    ),
                    extra_headers={
                        "X-Idempotency-Key": "dnai-test/sampling-session/00000001"
                    },
                    max_retries=0,
                )

        asyncio.run(exercise())
        self.assertEqual(len(observed), 1)
        request = observed[0]
        self.assertEqual(
            request.headers["X-Idempotency-Key"],
            "dnai-test/sampling-session/00000001",
        )
        self.assertEqual(request.url.path, "/api/v1/create_sampling_session")
        self.assertEqual(
            json.loads(request.content),
            {
                "base_model": "Qwen/Qwen3-8B",
                "sampling_session_seq_id": 0,
                "session_id": "session-test-only",
                "type": "create_sampling_session",
            },
        )


if __name__ == "__main__":
    unittest.main()
