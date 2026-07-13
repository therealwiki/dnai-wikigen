"""One-call verifier for an emitted private-reward run packet.

A demo / run packet publishes two run-level verification artifacts: a
``reproducibility_certificate`` (config + data + code + result + quote, and — when
bound — the transcript commitment hash) and a ``reward_transcript_commitment``
(per-round Merkle root + env chain head). This module re-checks that whole chain
from the bounded public bytes alone, with no access to sealed data:

1. the reproducibility certificate's ``certificate_hash`` recomputes (untampered);
2. the transcript commitment's ``commitment_hash`` recomputes from its fields;
3. the certificate's ``transcript_commitment_hash`` equals the commitment's own
   ``commitment_hash`` — i.e. the two artifacts are genuinely bound;
4. the per-round ``feedback`` is leakage-bounded — the sealed-data-derived records
   carry no smuggled reward value / gradient / sealed blob (``packet_leaks``), so
   "verified" means both cryptographically consistent AND leakage-safe.

It is fail-closed: any missing/mismatched/leaky piece yields ``verified=false``.
The verdict is bounded (booleans + reason), never echoing sealed content.
"""
from __future__ import annotations

from typing import Any

from tinker_delegate.reproducibility import (
    ReproducibilityCertificate,
    verify_reproducibility_certificate,
)
from tinker_delegate.reward_transcript import RewardTranscriptCommitment


def _certificate_from_dict(data: dict[str, Any]) -> ReproducibilityCertificate:
    return ReproducibilityCertificate(
        run_config_hash=str(data.get("run_config_hash", "")),
        data_commitment=str(data.get("data_commitment", "")),
        code_hash=str(data.get("code_hash", "")),
        model_base=str(data.get("model_base", "")),
        result_hash=str(data.get("result_hash", "")),
        attestation_quote_hash=str(data.get("attestation_quote_hash", "")),
        certificate_hash=str(data.get("certificate_hash", "")),
        transcript_commitment_hash=str(data.get("transcript_commitment_hash", "")),
    )


def _dp_status_consistent(dp: dict[str, Any]) -> bool:
    """True iff an attested dp_status is internally consistent (bounded floats)."""

    try:
        max_e = float(dp.get("max_epsilon", 0.0))
        spent_e = float(dp.get("spent_epsilon", 0.0))
        rem_e = float(dp.get("remaining_epsilon", 0.0))
        max_d = float(dp.get("max_delta", 0.0))
        spent_d = float(dp.get("spent_delta", 0.0))
        rem_d = float(dp.get("remaining_delta", 0.0))
    except (TypeError, ValueError):
        return False
    tol = 1e-6  # dp_status floats are rounded to 9 decimals on egress
    if abs(rem_e - max(0.0, max_e - spent_e)) > tol:
        return False
    if abs(rem_d - max(0.0, max_d - spent_d)) > tol:
        return False
    if dp.get("mode") == "differential_privacy":
        expected_exhausted = spent_e >= max_e - tol
        if bool(dp.get("exhausted")) != bool(expected_exhausted):
            return False
    return True


def _one_attestation_consistent(attestation: Any) -> bool:
    """True iff one attestation dict's holdout/ladder manifests respect their caps."""

    if not isinstance(attestation, dict):
        return True

    def _within(container: Any, count_key: str, cap_container: Any, cap_key: str) -> bool:
        # True unless BOTH count and cap are present and count > cap (or malformed).
        if not isinstance(container, dict) or not isinstance(cap_container, dict):
            return True
        if count_key not in container or cap_key not in cap_container:
            return True
        try:
            count = int(container[count_key])
            cap = int(cap_container[cap_key])
        except (TypeError, ValueError):
            return False
        return count <= cap

    holdout = attestation.get("holdout")
    if isinstance(holdout, dict):
        policy = holdout.get("policy")
        if not _within(holdout, "reward_query_count", policy, "max_reward_queries"):
            return False
        if not _within(
            holdout, "max_reward_queries_for_single_candidate", policy, "max_reward_queries_per_candidate"
        ):
            return False
        if not _within(holdout, "final_validation_count", policy, "max_final_validations"):
            return False
        # A completed final validation must have closed reward queries and met the
        # minimum-unique-candidates gate the policy declared.
        try:
            final_count = int(holdout.get("final_validation_count", 0))
        except (TypeError, ValueError):
            return False
        if final_count > 0:
            if holdout.get("closed_to_reward_queries") is not True:
                return False
            if isinstance(policy, dict) and "min_unique_reward_candidates_before_final" in policy:
                if not _within(
                    policy, "min_unique_reward_candidates_before_final", holdout, "unique_reward_candidates"
                ):
                    return False

    ladder = attestation.get("ladder")
    if isinstance(ladder, dict):
        if ladder.get("variant") == "paired_t":
            # Released numerator lives on the 1/n grid; improvements <= submissions.
            if not _within(ladder, "leaderboard_numerator", ladder, "denominator"):
                return False
            if not _within(ladder, "improvement_count", ladder, "submission_count"):
                return False
        else:
            policy = ladder.get("policy")
            # Core Ladder guarantee: at most D genuine improvement steps, and the
            # leaderboard index never exceeds the grid.
            if not _within(ladder, "improvement_count", policy, "max_improvement_steps"):
                return False
            if not _within(ladder, "leaderboard_step_index", ladder, "step_denominator"):
                return False
            if isinstance(policy, dict) and policy.get("max_submissions") is not None:
                if not _within(ladder, "submission_count", policy, "max_submissions"):
                    return False

    return True


def _mechanism_accounting_consistent(packet: dict[str, Any]) -> bool:
    """True iff the packet's holdout/ladder manifests respect their own caps.

    A third party auditing the *mechanism* must be able to confirm the boundary
    enforced the policy it declared: each manifest's enforced counts must not
    exceed the manifest's own declared caps. This catches a boundary (or a
    tampered packet) that ran more reward queries, more per-candidate probes, more
    final validations, or more Ladder improvement steps than its stated policy
    permits — a violation the hash/egress checks do not see. Lenient on absent
    fields (that dimension is simply not checkable), strict on a present-but-
    exceeded cap or an unparseable count (fail closed).

    The holdout/ladder manifests are attached in ``finalize()`` under
    ``final_result.attestation``; the top-level ``attestation`` is also checked in
    case a producer surfaces them there. Both must be consistent.
    """

    final_result = packet.get("final_result")
    final_attestation = (
        final_result.get("attestation") if isinstance(final_result, dict) else None
    )
    return _one_attestation_consistent(packet.get("attestation")) and (
        _one_attestation_consistent(final_attestation)
    )


def verify_reward_run(packet: dict[str, Any]) -> dict[str, Any]:
    """Verify a run packet's certificate + transcript chain; bounded verdict."""

    cert_dict = packet.get("reproducibility_certificate")
    commitment_dict = packet.get("reward_transcript_commitment")

    certificate_present = isinstance(cert_dict, dict)
    commitment_present = isinstance(commitment_dict, dict)

    certificate_verified = False
    if certificate_present:
        try:
            certificate_verified = verify_reproducibility_certificate(
                _certificate_from_dict(cert_dict)
            )
        except Exception:
            certificate_verified = False

    commitment_recomputed = False
    if commitment_present:
        try:
            rebuilt = RewardTranscriptCommitment.from_public_dict(commitment_dict)
            commitment_recomputed = (
                rebuilt.commitment_hash == str(commitment_dict.get("commitment_hash", ""))
            )
        except Exception:
            commitment_recomputed = False

    # Independent leakage bound: a third party accepting this packet must also be
    # sure it carries no smuggled reward value or sealed data — not just that the
    # hashes bind. The per-round `feedback` records are the sealed-data-derived
    # surface (bands / decisions / candidate hashes); they must contain no float
    # (an exact reward), numeric array (a gradient), oversized/aggregate int, or
    # blob. Public env config (holdout split fractions, DP epsilon/delta budget)
    # legitimately carries floats and lives in `attestation` / `optimizer_view`,
    # so only `feedback` is checked here.
    feedback_bounded = True
    feedback = packet.get("feedback")
    if isinstance(feedback, list):
        from tinker_delegate.private_reward import (
            RewardLeakageError,
            assert_bounded_egress,
        )

        try:
            assert_bounded_egress({"feedback": feedback})
        except RewardLeakageError:
            feedback_bounded = False

    # The binding only holds if BOTH artifacts are present and the certificate's
    # bound hash equals the commitment's own hash.
    binding_matches = False
    if certificate_present and commitment_present:
        binding_matches = (
            str(cert_dict.get("transcript_commitment_hash", "")) != ""
            and str(cert_dict.get("transcript_commitment_hash", ""))
            == str(commitment_dict.get("commitment_hash", ""))
        )

    # Cross-consistency: the (verified, mutually-bound) certificate + commitment
    # must also agree with the REST of the packet, so a valid cert+commitment from
    # one run cannot be re-attached to another run's final_result/attestation.
    packet_consistent = True
    if certificate_present and commitment_present:
        def _eq(a: Any, b: Any) -> bool:
            return str(a) == str(b)

        # Certificate <-> commitment: env commitment and result hash must match.
        if not _eq(cert_dict.get("data_commitment"), commitment_dict.get("environment_hash")):
            packet_consistent = False
        if not _eq(cert_dict.get("result_hash"), commitment_dict.get("final_result_hash")):
            packet_consistent = False
        # Commitment <-> packet body (when present).
        final_result = packet.get("final_result")
        if isinstance(final_result, dict) and not _eq(
            commitment_dict.get("final_result_hash"), final_result.get("transcript_hash")
        ):
            packet_consistent = False
        attestation = packet.get("attestation")
        if isinstance(attestation, dict):
            if not _eq(commitment_dict.get("environment_hash"), attestation.get("environment_hash")):
                packet_consistent = False
            att_head = str(attestation.get("transcript_chain_head", ""))
            com_head = str(commitment_dict.get("transcript_chain_head", ""))
            if att_head and com_head and att_head != com_head:
                packet_consistent = False
            # If a DP budget was attested, its accounting must be internally
            # consistent — remaining == max - spent, and exhausted matches the
            # epsilon ledger — so a tampered privacy claim is caught.
            if isinstance(attestation.get("dp_status"), dict):
                if not _dp_status_consistent(attestation["dp_status"]):
                    packet_consistent = False
        # The published per-round feedback must actually hash to the committed
        # Merkle root, so tampering a round record (with an otherwise-valid
        # commitment) is caught.
        feedback = packet.get("feedback")
        if isinstance(feedback, list):
            from tinker_delegate.reward_transcript import leaf_hash, merkle_root

            if int(commitment_dict.get("round_count", -1)) != len(feedback):
                packet_consistent = False
            else:
                try:
                    recomputed_root = merkle_root([leaf_hash(f) for f in feedback])
                except Exception:
                    recomputed_root = None
                if recomputed_root != str(commitment_dict.get("transcript_root", "")):
                    packet_consistent = False

    # Mechanism-audit dimension: did the boundary respect the policy it declared?
    # The enforced holdout/ladder accounting must not exceed its own stated caps.
    mechanism_accounting_consistent = _mechanism_accounting_consistent(packet)

    verified = (
        certificate_verified
        and commitment_recomputed
        and binding_matches
        and packet_consistent
        and feedback_bounded
        and mechanism_accounting_consistent
    )
    if verified:
        reason = "run_verified"
    elif not certificate_present or not commitment_present:
        reason = "missing_artifact"
    elif not feedback_bounded:
        # Leakage is a hard reject regardless of any binding outcome.
        reason = "packet_leaks"
    elif not mechanism_accounting_consistent:
        # The boundary enforced more than its declared policy allows.
        reason = "mechanism_accounting_violation"
    elif not certificate_verified:
        reason = "certificate_hash_mismatch"
    elif not commitment_recomputed:
        reason = "commitment_hash_mismatch"
    elif not binding_matches:
        reason = "binding_mismatch"
    else:
        reason = "packet_inconsistent"

    from tinker_delegate.decision_explainer import explain_decision

    return {
        "kind": "reward_run_verification",
        "verified": verified,
        "certificate_present": certificate_present,
        "commitment_present": commitment_present,
        "certificate_verified": certificate_verified,
        "commitment_recomputed": commitment_recomputed,
        "binding_matches": binding_matches,
        "packet_consistent": packet_consistent,
        "feedback_bounded": feedback_bounded,
        "mechanism_accounting_consistent": mechanism_accounting_consistent,
        "reason_code": reason,
        # Self-explaining verdict: a bounded, leak-free policy explanation of the
        # reason code (category / disposition / summary / remediation).
        "explanation": explain_decision(reason).to_public_dict(),
        "raw_secret_egress": False,
    }


def verify_reward_code_binding(
    packet: dict[str, Any], source_targets: Any
) -> dict[str, Any]:
    """Bind the attested code hash to the reward source a third party read.

    Point (1) of the third-party mechanism audit ("audit the mechanism, not the
    data"): a buyer/sponsor who has independently read the open reward-environment
    source must be able to confirm *that exact code* produced the run. Given the
    published packet and the source the reader obtained (module objects or
    filesystem paths), this recomputes `hash_source_files(...)` over that source
    and checks it equals the packet's reproducibility-certificate `code_hash`.

    This is a SEPARATE check from `verify_reward_run` because it takes an external
    input — the source the reader independently holds — that the packet alone does
    not carry. Both hashes are SHA-256 digests, so the verdict is bounded. Fails
    closed on a missing attested hash, unreadable source, or mismatch.
    """

    from tinker_delegate.decision_explainer import explain_decision
    from tinker_delegate.reproducibility import hash_source_files

    certificate = packet.get("reproducibility_certificate")
    attested = (
        str(certificate.get("code_hash", "")) if isinstance(certificate, dict) else ""
    )

    targets: tuple[Any, ...]
    if source_targets is None:
        targets = ()
    elif isinstance(source_targets, (list, tuple)):
        targets = tuple(source_targets)
    else:
        targets = (source_targets,)

    recomputed = ""
    if targets:
        try:
            recomputed = hash_source_files(*targets)
        except (OSError, TypeError, ValueError):
            recomputed = ""

    matches = bool(attested) and bool(recomputed) and attested == recomputed
    if matches:
        reason = "code_binding_verified"
    elif not attested:
        reason = "missing_code_hash"
    elif not recomputed:
        reason = "code_source_unreadable"
    else:
        reason = "code_hash_mismatch"

    return {
        "kind": "reward_code_binding",
        "code_binding_verified": matches,
        "attested_code_hash": attested,
        "recomputed_code_hash": recomputed,
        "reason_code": reason,
        "explanation": explain_decision(reason).to_public_dict(),
        "raw_secret_egress": False,
    }


def verify_reward_dataset_binding(
    packet: dict[str, Any],
    manifest: dict[str, Any],
    *,
    expected_signer: str | None = None,
    witness_quorum: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Bind a run packet to the published sealed-dataset manifest it committed to.

    Point (2) of the third-party mechanism audit: a buyer/sponsor who holds the
    published dataset manifest must be able to confirm the run consumed *that
    exact committed dataset*, without any plaintext. This checks three things:

    1. the manifest's own integrity + owner/notary signature (`verify_manifest`,
       requiring `expected_signer` when given);
    2. the manifest's `manifest_hash` equals the commitment the run published in
       `sealed_dataset_provenance.manifest_hash`;
    3. the run's declared `dataset_id` and `publish_ciphertext_sha256` match the
       manifest, so a valid manifest for a *different* dataset cannot be swapped
       in.

    Fails closed on a missing provenance/commitment, an invalid manifest, or any
    mismatch. The verdict is bounded (hashes + booleans only).

    When ``witness_quorum`` is supplied (``{"authorized_witnesses": [...],
    "threshold": M}``), the binding additionally requires that M distinct
    authorized neutral witnesses co-signed the commitment — the anti-collusion
    layer for adversarial buyer/seller pairs — else ``dataset_witness_quorum_unmet``.
    """

    from tinker_delegate.decision_explainer import explain_decision
    from tinker_delegate.sealed_dataset import manifest_hash, verify_manifest

    provenance = packet.get("sealed_dataset_provenance")
    committed_hash = (
        str(provenance.get("manifest_hash", "")) if isinstance(provenance, dict) else ""
    )

    manifest_report: dict[str, Any] | None = None
    manifest_ok = False
    computed_hash = ""
    if isinstance(manifest, dict):
        try:
            manifest_report = verify_manifest(manifest, expected_signer=expected_signer)
            manifest_ok = bool(manifest_report.get("ok"))
            computed_hash = str(manifest_report.get("manifest_hash", ""))
        except Exception:
            manifest_report = None
            manifest_ok = False

    hash_matches = bool(committed_hash) and bool(computed_hash) and committed_hash == computed_hash

    # Cross-field: the run's declared provenance must agree with the manifest, so a
    # valid manifest for another dataset cannot be substituted.
    fields_match = True
    if isinstance(provenance, dict) and isinstance(manifest, dict):
        if str(provenance.get("dataset_id", "")) != str(manifest.get("dataset_id", "")):
            fields_match = False
        pub_ct = str(provenance.get("publish_ciphertext_sha256", ""))
        man_ct = str(manifest.get("ciphertext_sha256", ""))
        if pub_ct and man_ct and pub_ct != man_ct:
            fields_match = False

    # Optional neutral-witness quorum: for adversarial buyer/seller pairs, require
    # that an M-of-N set of authorized notaries co-signed this commitment, so
    # neither side can dispute what was sealed. Only enforced when requested.
    quorum_requested = witness_quorum is not None
    quorum_met = True
    quorum_count = 0
    if quorum_requested:
        quorum_met = False
        if isinstance(manifest, dict):
            from tinker_delegate.sealed_dataset import verify_witness_quorum

            try:
                quorum_result = verify_witness_quorum(
                    manifest,
                    authorized_witnesses=witness_quorum.get("authorized_witnesses", []),
                    threshold=int(witness_quorum.get("threshold", 1)),
                )
                quorum_met = bool(quorum_result.get("threshold_met"))
                quorum_count = int(quorum_result.get("valid_witness_count", 0))
            except Exception:
                quorum_met = False

    verified = manifest_ok and hash_matches and fields_match and quorum_met
    if verified:
        reason = "dataset_binding_verified"
    elif not committed_hash:
        reason = "missing_dataset_commitment"
    elif not manifest_ok:
        reason = "dataset_manifest_invalid"
    elif not hash_matches:
        reason = "dataset_commitment_mismatch"
    elif not fields_match:
        reason = "dataset_provenance_mismatch"
    else:
        reason = "dataset_witness_quorum_unmet"

    return {
        "kind": "reward_dataset_binding",
        "dataset_binding_verified": verified,
        "manifest_verified": manifest_ok,
        "commitment_hash_matches": hash_matches,
        "provenance_fields_match": fields_match,
        "witness_quorum_requested": quorum_requested,
        "witness_quorum_met": quorum_met,
        "valid_witness_count": quorum_count,
        "committed_manifest_hash": committed_hash,
        "computed_manifest_hash": computed_hash,
        "owner_signature_verified": bool(manifest_report.get("owner_signature_verified"))
        if isinstance(manifest_report, dict)
        else False,
        "reason_code": reason,
        "explanation": explain_decision(reason).to_public_dict(),
        "raw_secret_egress": False,
    }


def verify_canary_calibration(report: dict[str, Any]) -> dict[str, Any]:
    """Verify a published canary calibration report (point (3) of the audit).

    A third party trusts the oracle's private scores only if known-answer probes
    behave: known-junk canaries must not score above their ceiling and known-good
    ones must not score below their floor. This re-derives each canary's outcome
    from its published bands (an outcome is a pure function of
    observed/min/max band ranks; INCONCLUSIVE coincides with a WITHHELD band on
    budget exhaustion) and confirms the *claimed* outcome matches — so a report
    that forges a "pass" over an out-of-range observation, or hides a trip, is
    caught. Calibrated iff every result is self-consistent, the aggregate
    clear/tripped fields agree, there is at least one canary, and none tripped.
    Bounded verdict; fails closed on a missing/empty/inconsistent report.
    """

    from tinker_delegate.canary import CanaryOutcome
    from tinker_delegate.decision_explainer import explain_decision
    from tinker_delegate.private_reward import RewardBand
    from tinker_delegate.private_reward_loop import band_rank

    results = report.get("results") if isinstance(report, dict) else None
    canary_count = len(results) if isinstance(results, list) else 0

    consistent = True
    tripped = 0
    if not isinstance(results, list) or not results:
        consistent = False
    else:
        for result in results:
            try:
                observed = RewardBand(result["observed_band"])
                min_band = RewardBand(result["min_band"])
                max_band = RewardBand(result["max_band"])
                claimed = str(result["outcome"])
            except (KeyError, ValueError, TypeError):
                consistent = False
                break
            if observed == RewardBand.WITHHELD:
                expected = CanaryOutcome.INCONCLUSIVE.value
            elif band_rank(observed) > band_rank(max_band):
                expected = CanaryOutcome.TRIPPED_HIGH.value
            elif band_rank(observed) < band_rank(min_band):
                expected = CanaryOutcome.TRIPPED_LOW.value
            else:
                expected = CanaryOutcome.PASS.value
            if claimed != expected:
                consistent = False
                break
            if claimed in (CanaryOutcome.TRIPPED_HIGH.value, CanaryOutcome.TRIPPED_LOW.value):
                tripped += 1

    # The report's own aggregate fields must agree with the recomputation.
    if consistent and isinstance(report.get("tripped_count"), int):
        if report["tripped_count"] != tripped:
            consistent = False
    if consistent and isinstance(report.get("clear"), bool):
        if report["clear"] != (tripped == 0):
            consistent = False

    calibrated = consistent and canary_count > 0 and tripped == 0
    if calibrated:
        reason = "canary_calibration_verified"
    elif canary_count == 0:
        reason = "no_canaries"
    elif not consistent:
        reason = "canary_report_inconsistent"
    else:
        reason = "canary_tripped"

    return {
        "kind": "canary_calibration",
        "canary_calibrated": calibrated,
        "canary_count": canary_count,
        "tripped_count": tripped,
        "report_consistent": consistent,
        "reason_code": reason,
        "explanation": explain_decision(reason).to_public_dict(),
        "raw_secret_egress": False,
    }


def verify_reward_mechanism(
    packet: dict[str, Any],
    *,
    source_targets: Any = None,
    manifest: dict[str, Any] | None = None,
    canary_report: dict[str, Any] | None = None,
    expected_signer: str | None = None,
    witness_quorum: dict[str, Any] | None = None,
    expected_benchmark: str | None = None,
    require_provenance: bool = False,
) -> dict[str, Any]:
    """Aggregate third-party mechanism audit: run every applicable check.

    Composes the "audit the mechanism, not the data" checks into one bounded
    verdict: the run packet itself (`verify_reward_run` — hashes, binding, leakage,
    and declared-vs-enforced policy accounting), plus the external-input checks a
    reader supplies — reward-code source binding (1), sealed-dataset binding (2,
    optionally requiring an M-of-N ``witness_quorum``), canary calibration (3), and
    seal-time provenance (run when ``require_provenance`` or ``expected_benchmark``
    is set). Each sub-check runs only when its input is present; a check that is
    not requested is reported ``skipped`` and does not fail the aggregate.
    ``verified`` is true iff every *run* check passes and every *requested*
    external check passes. The verdict nests each sub-verdict and is itself bounded
    (booleans + hashes only).
    """

    from tinker_delegate.decision_explainer import explain_decision

    run = verify_reward_run(packet)
    checks: dict[str, Any] = {"run": run}
    all_pass = bool(run.get("verified"))

    if source_targets is not None:
        code = verify_reward_code_binding(packet, source_targets)
        checks["code_binding"] = code
        all_pass = all_pass and bool(code.get("code_binding_verified"))
    else:
        checks["code_binding"] = {"skipped": True}

    if manifest is not None:
        dataset = verify_reward_dataset_binding(
            packet, manifest, expected_signer=expected_signer, witness_quorum=witness_quorum
        )
        checks["dataset_binding"] = dataset
        all_pass = all_pass and bool(dataset.get("dataset_binding_verified"))
    else:
        checks["dataset_binding"] = {"skipped": True}

    if canary_report is not None:
        canary = verify_canary_calibration(canary_report)
        checks["canary_calibration"] = canary
        all_pass = all_pass and bool(canary.get("canary_calibrated"))
    else:
        checks["canary_calibration"] = {"skipped": True}

    if manifest is not None and (require_provenance or expected_benchmark is not None):
        from tinker_delegate.sealed_dataset import verify_dataset_provenance

        provenance = verify_dataset_provenance(
            manifest, expected_signer=expected_signer, expected_benchmark=expected_benchmark
        )
        checks["provenance"] = provenance
        all_pass = all_pass and bool(provenance.get("ok"))
    else:
        checks["provenance"] = {"skipped": True}

    reason = "mechanism_verified" if all_pass else str(run.get("reason_code", "mechanism_unverified"))
    if not all_pass and run.get("verified"):
        # The run itself passed; surface the first failing external check's reason.
        _verified_reasons = {
            "code_binding_verified",
            "dataset_binding_verified",
            "canary_calibration_verified",
            "dataset_provenance_verified",
        }
        for key in ("code_binding", "dataset_binding", "canary_calibration", "provenance"):
            sub = checks[key]
            if not sub.get("skipped") and sub.get("reason_code", "").split(":")[0] not in _verified_reasons:
                reason = sub["reason_code"]
                break

    return {
        "kind": "reward_mechanism_verification",
        "verified": all_pass,
        "checks": checks,
        "reason_code": reason,
        "explanation": explain_decision(reason).to_public_dict(),
        "raw_secret_egress": False,
    }
