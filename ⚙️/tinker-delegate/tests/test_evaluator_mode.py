"""Trust-boundary tests for explicit deal evaluator activation."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.config import Settings
from tinker_delegate.evaluator import (
    EvaluatorUnavailable,
    resolve_deal_evaluator,
    stub_evaluate,
)


ROOT = Path(__file__).resolve().parents[1]


class EvaluatorModeResolutionTests(unittest.TestCase):
    def test_disabled_is_fail_closed_everywhere(self):
        for dstack_enabled in (False, True):
            with self.subTest(dstack_enabled=dstack_enabled):
                with self.assertRaises(EvaluatorUnavailable):
                    resolve_deal_evaluator(
                        Settings(evaluator_mode="disabled"),
                        dstack_enabled=dstack_enabled,
                        simulator_endpoint="",
                    )

    def test_stub_is_local_only(self):
        selected = resolve_deal_evaluator(
            Settings(evaluator_mode="stub"),
            dstack_enabled=False,
            simulator_endpoint="",
        )
        self.assertIs(selected, stub_evaluate)

        with self.assertRaises(EvaluatorUnavailable):
            resolve_deal_evaluator(
                Settings(evaluator_mode="stub"),
                dstack_enabled=True,
                simulator_endpoint="",
            )

    def test_sft_is_unavailable_in_every_custody_mode(self):
        for dstack_enabled, simulator_endpoint in (
            (False, ""),
            (True, ""),
            (True, "http://127.0.0.1:8090"),
        ):
            with self.subTest(
                dstack_enabled=dstack_enabled,
                simulator_endpoint=simulator_endpoint,
            ):
                with self.assertRaisesRegex(
                    EvaluatorUnavailable,
                    "^deal evaluator is unavailable$",
                ):
                    resolve_deal_evaluator(
                        Settings(evaluator_mode="sft"),
                        dstack_enabled=dstack_enabled,
                        simulator_endpoint=simulator_endpoint,
                    )

    def test_environment_simulator_cannot_enable_sft(self):
        with patch.dict(
            os.environ,
            {"DSTACK_SIMULATOR_ENDPOINT": "http://127.0.0.1:8090"},
            clear=False,
        ):
            with self.assertRaisesRegex(
                EvaluatorUnavailable,
                "^deal evaluator is unavailable$",
            ):
                resolve_deal_evaluator(
                    Settings(evaluator_mode="sft"),
                    dstack_enabled=True,
                )

    def test_compose_profiles_label_local_and_real_evaluation_explicitly(self):
        local = (ROOT / "docker-compose.all.yaml").read_text()
        dstack = (ROOT / "docker-compose.all.dstack.yaml").read_text()
        phala = (ROOT / "docker-compose.all.phala.yaml").read_text()

        self.assertIn("TINKER_EVALUATOR_MODE: ${TINKER_EVALUATOR_MODE:-stub}", local)
        self.assertIn('TINKER_EVALUATOR_MODE: "deterministic"', dstack)
        self.assertIn('TINKER_EVALUATOR_MODE: "deterministic"', phala)
        self.assertNotIn('TINKER_EVALUATOR_MODE: "sft"', dstack)
        self.assertNotIn('TINKER_EVALUATOR_MODE: "sft"', phala)
        for key in (
            "TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_PATH",
            "TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_SHA256",
            "TINKER_DILIGENCE_EVALUATOR_POLICY_SET_ROOT",
            "TINKER_DILIGENCE_CHAIN_ID",
            "TINKER_DILIGENCE_ROOM_ADDRESS",
        ):
            with self.subTest(key=key):
                self.assertRegex(dstack, rf"{key}: \$\{{{key}:\?[^\n]+\}}")
                self.assertRegex(phala, rf"{key}: \$\{{{key}:\?[^\n]+\}}")
        for compose in (dstack, phala):
            self.assertIn('command: ["tinker-diligence-evaluator-provision"]', compose)
            self.assertIn("network_mode: none", compose)
            self.assertIn(
                "TINKER_DILIGENCE_EVALUATOR_RELEASE_B64: ${TINKER_DILIGENCE_EVALUATOR_RELEASE_B64:?",
                compose,
            )
            self.assertIn("diligence-evaluator-policy:/sealed/diligence:ro", compose)
            self.assertIn("condition: service_completed_successfully", compose)


class EvaluatorApiTests(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings
        self.original_control_plane = api._control_plane
        api._control_plane = None

    def tearDown(self):
        api.settings = self.original_settings
        api._control_plane = self.original_control_plane

    def test_disabled_mode_returns_bounded_503_before_control_plane_init(self):
        api.settings = Settings(
            evaluator_mode="disabled",
            runtime_auth_required=True,
            runtime_auth_token="operator-test-token",
        )
        client = TestClient(api.app)
        response = client.post(
            "/deal/7/evaluate",
            headers={"Authorization": "Bearer operator-test-token"},
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json(),
            {"detail": "Deal evaluator is unavailable for this runtime"},
        )
        self.assertIsNone(api._control_plane)

    def test_stub_cannot_run_when_dstack_is_enabled(self):
        api.settings = Settings(
            evaluator_mode="stub",
            runtime_auth_required=True,
            runtime_auth_token="operator-test-token",
        )
        client = TestClient(api.app)
        with patch.dict(os.environ, {"DSTACK_ENABLED": "true"}, clear=False):
            response = client.post(
                "/deal/7/evaluate",
                headers={"Authorization": "Bearer operator-test-token"},
            )

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("synthetic", response.text.lower())
        self.assertIsNone(api._control_plane)

    def test_real_dstack_rejects_sft_before_control_plane_init(self):
        api.settings = Settings(
            evaluator_mode="sft",
            runtime_auth_required=True,
            runtime_auth_token="operator-test-token",
        )
        client = TestClient(api.app)
        with (
            patch.dict(
                os.environ,
                {
                    "DSTACK_ENABLED": "true",
                    "DSTACK_SIMULATOR_ENDPOINT": "",
                },
                clear=False,
            ),
            patch.object(api, "_get_control_plane") as get_control_plane,
        ):
            response = client.post(
                "/deal/7/evaluate",
                headers={"Authorization": "Bearer operator-test-token"},
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json(),
            {"detail": "Deal evaluator is unavailable for this runtime"},
        )
        get_control_plane.assert_not_called()
        self.assertIsNone(api._control_plane)


if __name__ == "__main__":
    unittest.main()
