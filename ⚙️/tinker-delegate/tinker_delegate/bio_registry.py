"""Registry of bio-validation evaluators, for discoverability and orchestration.

The bio layer now has several deterministic pieces: an evaluator that produces a
bounded `BioResultCandidate` (`bio_evaluators`), a fail-closed release gate
(`bio_validation`), and three risk axes that plug into it (`bio_dual_use`,
`bio_reid`, `bio_data_quality`). This registry ties them together so a caller can
*discover* which use cases exist and fetch the runner for one, without importing
each module by hand.

Bounded by construction: the registry only exposes use-case metadata (ids,
methodology classes, descriptions, input schema summaries) — never raw data, and
the runners it returns are the same fail-closed functions that hold unless every
readiness capability is enabled.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from tinker_delegate.bio_evaluators import (
    METHODOLOGY_CLASS as ASSAY_METHODOLOGY_CLASS,
    USE_CASE_ID as ASSAY_USE_CASE_ID,
    run_synthetic_assay_qc,
)
from tinker_delegate.bio_validation import BioReleaseReceipt


class BioRegistryError(KeyError):
    """Raised when a requested bio use case is not registered."""


@dataclass(frozen=True)
class BioEvaluatorEntry:
    """Bounded, egress-safe metadata about a registered bio evaluator."""

    use_case_id: str
    methodology_class: str
    description: str
    input_schema: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "use_case_id": self.use_case_id,
            "methodology_class": self.methodology_class,
            "description": self.description,
            "input_schema": self.input_schema,
        }


# A runner takes an evaluator-specific input plus the standard gate keyword
# assessments and returns a bounded BioReleaseReceipt.
BioRunner = Callable[..., BioReleaseReceipt]


class BioEvaluatorRegistry:
    """Discoverable set of bio evaluators keyed by use-case id."""

    def __init__(self) -> None:
        self._entries: dict[str, BioEvaluatorEntry] = {}
        self._runners: dict[str, BioRunner] = {}

    def register(self, entry: BioEvaluatorEntry, runner: BioRunner) -> None:
        if entry.use_case_id in self._entries:
            raise BioRegistryError(f"use case '{entry.use_case_id}' is already registered")
        self._entries[entry.use_case_id] = entry
        self._runners[entry.use_case_id] = runner

    def has(self, use_case_id: str) -> bool:
        return use_case_id in self._entries

    def get_entry(self, use_case_id: str) -> BioEvaluatorEntry:
        try:
            return self._entries[use_case_id]
        except KeyError as exc:
            raise BioRegistryError(f"unknown bio use case '{use_case_id}'") from exc

    def get_runner(self, use_case_id: str) -> BioRunner:
        try:
            return self._runners[use_case_id]
        except KeyError as exc:
            raise BioRegistryError(f"unknown bio use case '{use_case_id}'") from exc

    def list_use_cases(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            self._entries[key].to_public_dict() for key in sorted(self._entries)
        )


def default_registry() -> BioEvaluatorRegistry:
    """Build a registry pre-populated with the shipped evaluators."""

    registry = BioEvaluatorRegistry()
    registry.register(
        BioEvaluatorEntry(
            use_case_id=ASSAY_USE_CASE_ID,
            methodology_class=ASSAY_METHODOLOGY_CLASS,
            description=(
                "Synthetic screening-assay QC scoring via the Z'-factor; emits "
                "only coarse bands and passes through the fail-closed release gate."
            ),
            input_schema="SyntheticAssay(positive_controls, negative_controls, replicates)",
        ),
        run_synthetic_assay_qc,
    )
    return registry
