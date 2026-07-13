"""Bounded "explain why denied/held" layer over the system's reason codes.

Every gate in the system emits a bounded `reason_code` (leakage guard, budget,
biosecurity, verification, funding, governance, ...). A buyer/operator whose deal
was denied or held deserves to know WHY — the policy reason — without any private
content leaking. This module is that explanation surface (the data layer behind an
"explain why denied/held" UI).

Leak-free by construction: `explain_decision` maps a reason code to a FIXED
registry entry (category, disposition, plain-language summary, remediation). It
never interpolates the input code or any suffix into the output, so even a code
carrying an injected private-looking suffix cannot leak — only curated vocabulary
is emitted. Unknown codes fall back to a generic, safe explanation.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class DecisionCategory(str, Enum):
    LEAKAGE = "leakage"
    BUDGET = "budget"
    BIOSECURITY = "biosecurity"
    PRIVACY = "privacy"
    DATA_QUALITY = "data_quality"
    GOVERNANCE = "governance"
    VERIFICATION = "verification"
    FUNDING = "funding"
    LIFECYCLE = "lifecycle"
    OK = "ok"
    UNKNOWN = "unknown"


class Disposition(str, Enum):
    DENIED = "denied"
    HELD = "held"
    ALLOWED = "allowed"
    INFO = "info"


@dataclass(frozen=True)
class DecisionExplanation:
    category: DecisionCategory
    disposition: Disposition
    summary: str
    remediation: str
    reveals_private_content: bool = False  # always False by construction

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "decision_explanation",
            "category": self.category.value,
            "disposition": self.disposition.value,
            "summary": self.summary,
            "remediation": self.remediation,
            "reveals_private_content": self.reveals_private_content,
            "raw_secret_egress": False,
        }


_C, _D = DecisionCategory, Disposition


def _e(cat, disp, summary, remediation) -> DecisionExplanation:
    return DecisionExplanation(cat, disp, summary, remediation)


# Exact reason-code registry. Summaries/remediations are FIXED strings — the input
# code is never echoed into them.
_EXACT: dict[str, DecisionExplanation] = {
    # Leakage / bounded egress
    "float_value": _e(_C.LEAKAGE, _D.DENIED, "Output blocked: it contained an exact numeric value where only a score band is allowed.", "Publish only bounded bands/decisions/hashes, not raw values."),
    "numeric_array": _e(_C.LEAKAGE, _D.DENIED, "Output blocked: it contained a numeric array (e.g. a gradient) that could leak sealed data.", "Reduce to a bounded band before publishing."),
    "oversized_int": _e(_C.LEAKAGE, _D.DENIED, "Output blocked: a single oversized integer could encode sealed data.", "Emit bounded counts/bands only."),
    "aggregate_int_payload": _e(_C.LEAKAGE, _D.DENIED, "Output blocked: many integer fields summed to a bulk payload.", "Reduce the number/size of numeric fields to bounded values."),
    "oversized_blob": _e(_C.LEAKAGE, _D.DENIED, "Output blocked: an oversized blob could carry raw sealed data rather than a hash.", "Publish a hash, not the raw bytes."),
    "structure_too_deep": _e(_C.LEAKAGE, _D.DENIED, "Output blocked: the structure was too deeply nested to bound safely.", "Flatten the bounded output."),
    "packet_leaks": _e(_C.LEAKAGE, _D.DENIED, "Verification failed: the run packet's feedback carried un-bounded (leaky) content.", "Re-emit the run with bounded per-round feedback."),
    # Budget / economics
    "exceeds_cap": _e(_C.BUDGET, _D.DENIED, "Spend blocked: the charge would exceed an authorized spend cap.", "Lower the amount or raise the relevant cap."),
    "over_budget": _e(_C.BUDGET, _D.DENIED, "Settlement blocked: the charge exceeds the buyer's authorized budget.", "Re-quote within the budget cap."),
    "dp_budget_exhausted": _e(_C.PRIVACY, _D.DENIED, "Release blocked: the differential-privacy budget for this data is exhausted.", "No further private releases are possible under the current (epsilon, delta) budget."),
    # Biosecurity / dual-use
    "dual_use_screen_required": _e(_C.BIOSECURITY, _D.HELD, "Held for biosecurity review: a required dual-use screen was not supplied.", "Run the structured dual-use screen and resubmit."),
    "forbidden_output_detected": _e(_C.BIOSECURITY, _D.DENIED, "Denied: the output matched a forbidden-content category.", "This content cannot be released; revise the task scope."),
    "reidentification_risk": _e(_C.PRIVACY, _D.HELD, "Held for review: the cohort is small enough to risk re-identifying individuals.", "Increase the cohort/subgroup size or suppress small cells."),
    "data_quality_invalid": _e(_C.DATA_QUALITY, _D.HELD, "Held for expert review: the dataset has an invalidating quality issue.", "Fix the flagged data-quality issue (e.g. contamination, too few samples)."),
    "readiness_incomplete": _e(_C.BIOSECURITY, _D.HELD, "Held: not all required safety-readiness capabilities are enabled.", "Enable the missing readiness controls before release."),
    "cleared_bounded_release": _e(_C.OK, _D.ALLOWED, "Released: all safety and bounded-output checks passed.", "No action needed."),
    # Governance
    "self_approval_denied": _e(_C.GOVERNANCE, _D.DENIED, "Denied: the requester cannot approve its own action (non-self-approval).", "Obtain approval from a different party."),
    "no_valid_confirmation": _e(_C.GOVERNANCE, _D.HELD, "Held: a high-risk action needs an out-of-band second confirmation.", "Confirm via an approved channel from a party other than the requester."),
    "insufficient_confirmations": _e(_C.GOVERNANCE, _D.HELD, "Held: not enough distinct approvals for this high-risk action.", "Obtain the required number of distinct out-of-band confirmations."),
    # Verification
    "run_verified": _e(_C.OK, _D.ALLOWED, "Verified: the run's certificate and transcript chain check out.", "No action needed."),
    "code_binding_verified": _e(_C.OK, _D.ALLOWED, "Verified: the attested code hash matches the reward source you read.", "No action needed."),
    "code_hash_mismatch": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the attested code hash does not match the reward source you provided.", "The run may have used different code; obtain the exact source that was attested."),
    "missing_code_hash": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the packet has no attested code hash to bind.", "Include a reproducibility certificate with a code_hash."),
    "code_source_unreadable": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the provided reward source could not be read to recompute its hash.", "Provide the readable source modules/paths the boundary attested."),
    "dataset_binding_verified": _e(_C.OK, _D.ALLOWED, "Verified: the run committed to the exact sealed dataset in the manifest you hold.", "No action needed."),
    "missing_dataset_commitment": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the run packet carries no sealed-dataset commitment to bind.", "Use a run whose provenance records the sealed-dataset manifest hash."),
    "dataset_manifest_invalid": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the sealed-dataset manifest did not verify (schema, ciphertext, or signature).", "Obtain a valid, correctly-signed manifest from the publisher."),
    "dataset_commitment_mismatch": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the manifest hash does not match the run's dataset commitment.", "The run used a different dataset; obtain the manifest the run committed to."),
    "dataset_provenance_mismatch": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the run's declared dataset id / ciphertext does not match the manifest.", "A manifest for a different dataset was supplied; use the matching one."),
    "dataset_witness_quorum_unmet": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: fewer than the required neutral witnesses co-signed the sealed dataset.", "Obtain the required M-of-N witness co-signatures on the commitment."),
    "dataset_provenance_verified": _e(_C.OK, _D.ALLOWED, "Verified: the sealed dataset carries signed, seal-time provenance bound to the commitment.", "No action needed."),
    "missing_dataset_provenance": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the sealed dataset has no provenance block.", "Seal the dataset with an attested provenance block."),
    "dataset_provenance_incomplete": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the dataset provenance block is missing required fields.", "Provide a complete provenance block (pipeline, upstream id, license, claim, benchmark)."),
    "dataset_provenance_unsigned": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the dataset provenance is not bound by a valid signature.", "Sign the manifest so the provenance claim is attested at seal time."),
    "dataset_benchmark_mismatch": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the provenance benchmark claim does not match the expected benchmark.", "Use a dataset whose provenance references the required benchmark."),
    "dataset_provenance_invalid": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the dataset provenance did not verify.", "Re-obtain a correctly signed provenance manifest."),
    "canary_calibration_verified": _e(_C.OK, _D.ALLOWED, "Verified: the oracle's known-answer canaries are calibrated and none tripped.", "No action needed."),
    "mechanism_verified": _e(_C.OK, _D.ALLOWED, "Verified: every requested mechanism-audit check passed (run, code, dataset, canaries).", "No action needed."),
    "no_canaries": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the calibration report has no canaries to check.", "Publish a canary report with known-good and known-bad probes."),
    "canary_report_inconsistent": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: a canary's claimed outcome does not follow from its bands.", "The calibration report may be forged; re-obtain it from the boundary."),
    "canary_tripped": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: a known-answer canary scored outside its allowed band — the oracle is gamed or leaking.", "Do not trust this oracle's scores; investigate the tripped canary."),
    "certificate_hash_mismatch": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the reproducibility certificate did not recompute.", "The packet may be tampered; re-obtain it from the source."),
    "commitment_hash_mismatch": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the transcript commitment did not recompute.", "The packet may be tampered; re-obtain it from the source."),
    "binding_mismatch": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the certificate and transcript are not bound to each other.", "The artifacts may be spliced; re-obtain a consistent packet."),
    "packet_inconsistent": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the certificate/transcript do not match the packet body.", "The packet may be spliced or tampered; re-obtain it."),
    "mechanism_accounting_violation": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: the enforced query/ladder accounting exceeds the declared policy caps.", "The boundary ran more than its stated policy allows; reject the packet."),
    "missing_artifact": _e(_C.VERIFICATION, _D.DENIED, "Verification failed: a required verification artifact is missing.", "Include the certificate and transcript commitment."),
    # Funding
    "negative_amount": _e(_C.FUNDING, _D.DENIED, "Denied: a negative amount is not a valid charge.", "Submit a non-negative amount."),
    "auto_reload_off": _e(_C.FUNDING, _D.INFO, "No top-up: auto-reload is disabled by policy.", "Enable auto-reload only via an approved operator action."),
    "emergency_disabled": _e(_C.FUNDING, _D.DENIED, "Blocked: the funding emergency kill switch is engaged.", "Resolve the triggering failure before re-enabling auto-reload."),
    "balance_sufficient": _e(_C.FUNDING, _D.INFO, "No top-up needed: the balance is above the minimum.", "No action needed."),
    # Lifecycle
    "settled": _e(_C.LIFECYCLE, _D.INFO, "Settled: the deal reached final settlement.", "No action needed."),
    "destroyed": _e(_C.LIFECYCLE, _D.INFO, "Destroyed: the sealed artifact was destroyed per retention policy.", "No action needed."),
}

# Prefix registry for dynamic codes (matched after exact lookup fails). The
# suffix after the prefix (which may carry policy vocabulary) is NEVER emitted.
_PREFIX: tuple[tuple[str, DecisionExplanation], ...] = (
    ("dual_use_prohibited", _e(_C.BIOSECURITY, _D.DENIED, "Denied: the task is a prohibited dual-use category.", "This class of task cannot be released.")),
    ("dual_use_review", _e(_C.BIOSECURITY, _D.HELD, "Held for biosecurity review: the dual-use tier requires human sign-off.", "Await biosecurity reviewer approval.")),
    ("dual_use", _e(_C.BIOSECURITY, _D.HELD, "Held for biosecurity review of a dual-use concern.", "Await biosecurity reviewer approval.")),
    ("exceeds_", _e(_C.BUDGET, _D.DENIED, "Spend blocked: the charge would exceed an authorized spend cap.", "Lower the amount or raise the relevant cap.")),
    ("funding_failure_", _e(_C.FUNDING, _D.HELD, "Funding attempt failed and was routed for handling.", "Follow the disposition (retry, escalate, or disable auto-reload).")),
    ("disclosure_", _e(_C.GOVERNANCE, _D.HELD, "Disclosure restricted by policy.", "Release only through the permitted disclosure channel.")),
    ("reidentification", _e(_C.PRIVACY, _D.HELD, "Held for review: re-identification risk.", "Increase cohort size or suppress small cells.")),
    ("data_quality", _e(_C.DATA_QUALITY, _D.HELD, "Held for review: a data-quality concern.", "Address the flagged data-quality issue.")),
    ("individual_level_data", _e(_C.PRIVACY, _D.HELD, "Held: individual-level data requires a satisfied privacy budget.", "Provide a satisfied differential-privacy charge.")),
)

_FALLBACK = _e(
    _C.UNKNOWN, _D.HELD,
    "Held: a policy check was not satisfied.",
    "Contact the operator for the specific policy reason.",
)


def explain_decision(reason_code: str) -> DecisionExplanation:
    """Map a bounded reason code to a leak-free policy explanation.

    Only fixed registry vocabulary is emitted — the input code (and any suffix it
    carries) is never echoed, so private content cannot leak through this surface.
    """
    if not isinstance(reason_code, str) or not reason_code:
        return _FALLBACK
    # Normalize: drop any ":suffix" (which may carry per-decision detail).
    base = reason_code.split(":", 1)[0].strip()
    if base in _EXACT:
        return _EXACT[base]
    for prefix, explanation in _PREFIX:
        if base.startswith(prefix):
            return explanation
    return _FALLBACK
