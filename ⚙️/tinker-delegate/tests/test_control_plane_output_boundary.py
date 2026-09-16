import asyncio
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch

from pydantic import ValidationError


sys.modules.setdefault(
    "tinker",
    types.SimpleNamespace(ServiceClient=object, TrainingClient=object, SamplingClient=object),
)

from tinker_delegate.api import EvaluationResultResponse  # noqa: E402
from tinker_delegate.artifacts import artifact_commitment  # noqa: E402
from tinker_delegate.control_plane import (  # noqa: E402
    ControlPlane,
    DealContext,
    DealState,
    ScoreBand,
    compute_offer,
    derive_public_settlement,
    evaluation_attestation_report_data,
)


PRIVATE_ARTIFACT = b"private artifact sentinel that must never leave the boundary"
COMMITMENT_SECRET = bytes(range(32))
COMMITMENT = artifact_commitment(PRIVATE_ARTIFACT, COMMITMENT_SECRET)


class _Session:
    training_run_id = "private-run-id"

    def __init__(self, compute_cost_wei: int = 7, fee_wei: int = 1):
        self.compute_cost_wei = compute_cost_wei
        self.fee_wei = fee_wei

    def cleanup(self):
        return None


def _control_plane(
    *, compute_cost_wei: int = 7, fee_wei: int = 1
) -> tuple[ControlPlane, DealContext, bytearray]:
    cp = ControlPlane.__new__(ControlPlane)
    ctx = DealContext(
        "deal-output-boundary",
        "buyer",
        "seller",
        1_000,
        100,
        COMMITMENT,
        session=_Session(compute_cost_wei, fee_wei),
    )
    ctx.artifact = bytearray(PRIVATE_ARTIFACT)
    ctx.artifact_commitment_secret = bytearray(COMMITMENT_SECRET)
    ctx.artifact_hash = COMMITMENT
    stored_artifact = ctx.artifact
    cp._deals = {ctx.deal_id: ctx}
    return cp, ctx, stored_artifact


def _public_response(result) -> EvaluationResultResponse:
    return EvaluationResultResponse(
        deal_id=result.deal_id,
        score_band=result.score_band.value,
        quality_delta=result.quality_delta,
        offer_price=result.offer_price,
        recommendation=result.recommendation,
        confidence=result.confidence,
        methodology_summary=result.methodology_summary,
        compute_cost_wei=result.compute_cost_wei,
        fee_wei=result.fee_wei,
    )


class ControlPlaneOutputBoundaryTest(unittest.TestCase):
    def test_evaluator_strings_numbers_and_nested_values_cannot_become_public(self):
        secret_text = PRIVATE_ARTIFACT.decode("utf-8")
        secret_number = 987_654_321_987_654_321
        evaluator = AsyncMock(
            return_value={
                "quality_delta": 0.12,
                "benchmark": secret_text,
                "confidence": secret_text,
                "methodology": secret_text,
                "arbitrary_number": secret_number,
                "nested": {"artifact": secret_text, "number": secret_number},
            }
        )
        cp, ctx, _ = _control_plane()

        with patch.object(cp, "_get_tdx_quote", return_value=b"test-only-attestation"):
            result = asyncio.run(cp.evaluate(ctx.deal_id, evaluator))

        self.assertEqual(ctx.state, DealState.EVALUATED)
        self.assertEqual(result.score_band.value, "high")
        self.assertEqual(result.quality_delta, "10-20% quality-improvement band")
        self.assertEqual(result.confidence, "withheld")
        self.assertEqual(result.methodology_summary, "private_evaluator_details_withheld")
        self.assertEqual((result.compute_cost_wei, result.fee_wei), (10, 0))
        rendered = _public_response(result).model_dump_json()
        self.assertNotIn(secret_text, rendered)
        self.assertNotIn(str(secret_number), rendered)

    def test_nonfinite_non_numeric_or_out_of_range_delta_fails_closed(self):
        invalid_values = (None, True, "0.2", float("nan"), float("inf"), -0.01, 1.01)
        for invalid in invalid_values:
            with self.subTest(invalid=invalid):
                cp, ctx, stored_artifact = _control_plane()
                evaluator = AsyncMock(return_value={"quality_delta": invalid})
                with (
                    patch.object(cp, "_get_tdx_quote", return_value=b"test-only-attestation"),
                    self.assertRaisesRegex(ValueError, "quality_delta"),
                ):
                    asyncio.run(cp.evaluate(ctx.deal_id, evaluator))
                self.assertEqual(ctx.state, DealState.RESOLVED)
                self.assertIsNone(ctx.result)
                self.assertIsNone(ctx.artifact)
                self.assertEqual(stored_artifact, bytearray(len(PRIVATE_ARTIFACT)))

    def test_missing_tdx_quote_cannot_mark_deal_evaluated(self):
        cp, ctx, stored_artifact = _control_plane()
        evaluator = AsyncMock(return_value={"quality_delta": 0.21})

        with (
            patch.object(cp, "_get_tdx_quote", return_value=b""),
            self.assertRaisesRegex(RuntimeError, "TDX result attestation quote is required"),
        ):
            asyncio.run(cp.evaluate(ctx.deal_id, evaluator))

        self.assertEqual(ctx.state, DealState.RESOLVED)
        self.assertIsNone(ctx.result)
        self.assertIsNone(ctx.artifact)
        self.assertEqual(stored_artifact, bytearray(len(PRIVATE_ARTIFACT)))

    def test_private_meter_variation_cannot_modulate_public_settlement_or_quote_input(self):
        async def malicious_evaluator(
            *, artifact, artifact_type, session, budget_cap, reserve_price
        ):
            # A buyer evaluator can vary calls/tokens after seeing the artifact.
            # These exact private values must not become a public numeric channel.
            session.compute_cost_wei = artifact[0]
            session.fee_wei = artifact[1]
            return {
                "quality_delta": 0.12,
                "benchmark": artifact.decode("utf-8", errors="ignore"),
            }

        public_projections = []
        report_data_values = []
        for private_cost, private_fee in ((1, 0), (250, 25)):
            cp, ctx, _ = _control_plane()
            ctx.artifact[0] = private_cost
            ctx.artifact[1] = private_fee
            # Keep commitment verification focused on the malicious meter channel:
            # the evaluator receives distinct private bytes, while the test patches
            # only the commitment check that would otherwise reject this mutation.
            with (
                patch(
                    "tinker_delegate.control_plane.verify_artifact_commitment",
                    return_value=COMMITMENT,
                ),
                patch.object(cp, "_get_tdx_quote", return_value=b"test-only-attestation"),
            ):
                result = asyncio.run(cp.evaluate(ctx.deal_id, malicious_evaluator))
            public_projections.append(
                (
                    result.score_band,
                    result.offer_price,
                    result.compute_cost_wei,
                    result.fee_wei,
                    result.recommendation,
                )
            )
            report_data_values.append(
                evaluation_attestation_report_data(ctx.deal_id, result)
            )

        self.assertEqual(public_projections[0], public_projections[1])
        self.assertEqual(report_data_values[0], report_data_values[1])
        self.assertEqual(
            public_projections[0][2:4],
            derive_public_settlement(budget_cap=1_000, reserve_price=100),
        )

    def test_offer_has_no_artifact_influence_beyond_the_five_way_score_band(self):
        offers = {
            compute_offer(band, budget_cap=987_654_321, reserve_price=123_456)
            for band in ScoreBand
        }
        self.assertLessEqual(len(offers), len(ScoreBand))
        self.assertEqual(
            compute_offer(ScoreBand.HIGH, 987_654_321, 123_456),
            691_358_024,
        )

    def test_private_meter_over_budget_emits_no_evaluated_result(self):
        cp, ctx, stored_artifact = _control_plane(compute_cost_wei=301, fee_wei=0)
        evaluator = AsyncMock(return_value={"quality_delta": 0.12})

        with (
            patch.object(cp, "_get_tdx_quote", return_value=b"test-only-attestation"),
            self.assertRaisesRegex(RuntimeError, "private metered evaluation cost"),
        ):
            asyncio.run(cp.evaluate(ctx.deal_id, evaluator))

        self.assertEqual(ctx.state, DealState.RESOLVED)
        self.assertIsNone(ctx.result)
        self.assertEqual(stored_artifact, bytearray(len(PRIVATE_ARTIFACT)))

    def test_public_response_model_rejects_new_evaluator_channels(self):
        valid = {
            "deal_id": "deal-output-boundary",
            "score_band": "medium",
            "quality_delta": "5-10% quality-improvement band",
            "offer_price": 500,
            "recommendation": "accept",
            "confidence": "withheld",
            "methodology_summary": "private_evaluator_details_withheld",
            "compute_cost_wei": 7,
            "fee_wei": 1,
        }
        EvaluationResultResponse(**valid)
        for field, value in (
            ("quality_delta", "5-10% on private-benchmark"),
            ("confidence", "artifact-derived-high"),
            ("methodology_summary", PRIVATE_ARTIFACT.decode("utf-8")),
            ("compute_cost_wei", -1),
        ):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                EvaluationResultResponse(**{**valid, field: value})


if __name__ == "__main__":
    unittest.main()
