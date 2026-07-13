# Bio-Validation Target

Status: `[partial]` — target defined and a fail-closed bounded release gate is
`[real]` in code (`⚙️/tinker-delegate/tinker_delegate/bio_validation.py`,
`tests/test_bio_validation.py`). Real evaluators, risk screens, reviewer
workflow wiring, and DP accounting are still `[planned]`.

This document defines the first bio-validation use of the private
verified-reward substrate (see `PROJECT.md`) and the invariants any bio or
dual-use output must satisfy before release. The governing rule from `TODO.md`:

> Bio/dual-use outputs must fail closed until the risk screen, reviewer queue,
> and bounded result schema are real.

## Method Is Not The Claim

`TTT` (test-time training) is treated as **method-agnostic**. The central
primitive is a *private verified reward*: measured code scores a candidate
against sealed data and returns only a bounded reward. The optimization method
around it can be reinforcement learning, test-time training, evolutionary
search, or an LLM repair loop. Nothing in this target depends on which
optimizer is used, and product docs must not imply that TTT specifically is
required.

## First Safe Use Case

The first demo is **synthetic assay QC scoring**: candidate computational-bio
code (or a small adapted model) is scored on how well it flags quality problems
in an assay dataset. It is chosen because it is useful, non-dual-use, and can
run entirely over synthetic or public toy data.

Explicitly *not* first: anything touching real patient records, real pathogen
data, or wetlab-actionable design. Those require the reviewer path and DP
accounting to be real first.

Acceptable alternative first use cases (same safety class): de-identified
expression classifier scoring, method-validation reproducibility, private
reward for computational-bio code correctness, or non-dual-use model-utility
scoring.

## Allowed Data For The First Demo

Synthetic or public toy data only (e.g. OpenProblems-like single-cell data or
generated assay tables). No individual-level records, no PHI, no real pathogen
sequences. The release gate treats `individual_level_data=True` without a
`differential_privacy_marked=True` flag as a fail-closed **hold** routed to
biosecurity review.

## Forbidden Outputs

The bounded result must never carry, and the gate denies on detecting, any of:

- wetlab protocol details (steps, reagents, culture/PCR conditions)
- pathogen enhancement guidance (gain-of-function, virulence/transmissibility)
- de novo harmful design (novel toxins, pathogens, agents)
- identifiable patient-level outputs (patient id, MRN, per-record labels)
- raw records or samples (FASTQ/VCF rows, raw reads, genotypes)
- model weights / checkpoints (state dicts, checkpoint bytes/paths)
- reconstruction-prone statistics (per-record values, exact rewards/losses,
  full confusion matrices, membership-inference-enabling detail)

These map to `_FORBIDDEN_PATTERNS` in `bio_validation.py`. A match on any
operator-supplied free-text field forces `decision=deny`,
`safety_band=blocked`, and a `biosecurity-review` route; the free-text is
hashed, never returned.

## Bounded Result Schema

The only fields that may leave (all coarse, all in
`BioReleaseReceipt.result_schema`):

| Field | Meaning |
| --- | --- |
| `use_case_id` | Public identifier of the validation task |
| `methodology_class` | Public class of method used (e.g. `sft_lora_scorer`) |
| `score_band` | `high` / `medium` / `low` / `withheld` |
| `confidence_band` | `high` / `medium` / `low` / `withheld` |
| `safety_band` | `cleared` / `review` / `blocked` |
| `utility_band` | `high` / `medium` / `low` / `withheld` |
| `compute_cost_band` | coarse cost band, `withheld` unless released |
| `data_quality_flags` | small allowlist of public flags |
| `free_text_screen` | per-field hash + forbidden-match verdict, no raw text |
| `result_hash` | stable hash binding the bounded result |

Bands are emitted as `withheld` on any non-release decision, so a held or
denied result reveals only that it was held/denied plus the safety band and
screen verdict.

## Benchmark Tasks

A real evaluator (still `[planned]`) must report, over synthetic data:

- baseline model score band
- adapted model score band
- held-out evaluation score band (separate from the reward split)
- statistical confidence band
- enumerated failure modes as public `data_quality_flags`

Hidden-holdout separation and adaptive-query defenses come from
`private_reward_holdout.py`; this target reuses them rather than redefining them.

## When Results Must Hold For Human Review

Release is the exception, not the default. The gate holds (never releases) when:

- any readiness capability is missing (`risk_screen`, `reviewer_queue`,
  `bounded_schema`, `data_policy`) — routed to `expert-in-the-loop`;
- individual-level data is used without a DP marking — routed to
  `biosecurity-review`;
- and denies outright on any forbidden-output match.

Held tickets are intended to flow into the existing bounded review queue
(`review_queue.py`) once wired; this target does not auto-release held results
under any condition.

## Readiness Ledger

`BioReadiness` defaults every capability flag to `false` so a fresh or
misconfigured deployment cannot release. Flipping a flag to `true` is a claim
that the corresponding capability is actually real:

- `risk_screen_enabled` — a real risk/biosecurity screen runs on candidates.
- `reviewer_queue_enabled` — held results reach a durable human review queue.
- `bounded_schema_enabled` — outputs are constrained to the schema above.
- `synthetic_or_approved_data_only` — data policy is enforced upstream.

Until all four are independently real, keep them false and let the gate hold.
