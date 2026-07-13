# IsolatedTinkerSession -- Comprehensive Scoping Document

**Date:** 2026-03-10
**Status:** Draft
**Author:** Automated research from SDK source, docs, cookbook, and NDAI paper

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Full SDK API Inventory](#2-full-sdk-api-inventory)
3. [Data Flow Diagrams](#3-data-flow-diagrams)
4. [Security Boundary Analysis](#4-security-boundary-analysis)
5. [TTL and Checkpoint Lifecycle](#5-ttl-and-checkpoint-lifecycle)
6. [Cost Metering Strategy](#6-cost-metering-strategy)
7. [Evaluation Protocol Options](#7-evaluation-protocol-options)
8. [Testing Strategy](#8-testing-strategy)
9. [NDAI Paper Alignment](#9-ndai-paper-alignment)
10. [Open Questions and Risks](#10-open-questions-and-risks)

---

## 1. Executive Summary

`IsolatedTinkerSession` is the sandboxed wrapper that sits between the NDAI evaluator agent (the buyer's agent A_B) and the Tinker fine-tuning SDK. Its purpose is to enforce the TEE's security boundary: the evaluator can train and sample models to assess a seller's artifact, but it must not be able to exfiltrate model weights, access other deals' data, accumulate persistent state, or bypass cost controls.

The current implementation (`session.py`) covers the critical path -- single training run enforcement, path-checked sampling, mandatory TTL on checkpoints, cost metering, and cleanup. This document maps the *full* Tinker SDK surface against what is exposed, identifies gaps, and defines the spec for a production-grade implementation.

---

## 2. Full SDK API Inventory

### 2.1 ServiceClient Methods

| Method | Exposed | Wrapped As | Rationale |
|--------|---------|------------|-----------|
| `__init__(**kwargs)` | NO | Internal only | Session constructs this; agent never sees raw client |
| `get_server_capabilities()` | NO | Not needed | Leaks model lineup info; evaluator uses fixed config |
| `create_lora_training_client(base_model, rank, seed, train_mlp, train_attn, train_unembed, user_metadata)` | YES | `create_training(base_model, rank, **kwargs)` | One-per-deal enforced; deal_id injected into metadata |
| `create_training_client_from_state(path, user_metadata)` | BLOCKED | -- | Could load weights from other deals/users |
| `create_training_client_from_state_with_optimizer(path, user_metadata)` | BLOCKED | -- | Same risk as above |
| `create_sampling_client(model_path, base_model, retry_config)` | PARTIAL | `create_sampler(model_path)` | Path-checked: only paths from this session allowed |
| `create_rest_client()` | BLOCKED | -- | Gateway to download, publish, list, delete operations |

**Gap identified:** The current `create_training()` passes `**kwargs` through to `create_lora_training_client`. This could allow smuggling `seed`, `train_mlp`, `train_attn`, `train_unembed` parameters. These should be either explicitly whitelisted or fixed.

### 2.2 TrainingClient Methods

| Method | Exposed | Wrapped As | Rationale |
|--------|---------|------------|-----------|
| `forward(data, loss_fn, loss_fn_config)` | NO | -- | Forward-only pass; useful for eval but not currently wrapped. **Consider adding.** |
| `forward_backward(data, loss_fn, loss_fn_config)` | YES | `forward_backward(data, loss_fn, loss_fn_config)` | Core training operation; cost metered |
| `forward_backward_custom(data, loss_fn)` | NO | -- | Requires PyTorch on client side + custom callable. **Security concern:** callable runs locally, not on server. See Section 4. |
| `optim_step(adam_params)` | YES | `optim_step(adam_params)` | No token cost, but counts as API usage |
| `save_state(name, ttl_seconds)` | YES | `save_state(name, ttl_seconds)` | TTL clamped to [1h, 24h]; path NOT added to allowed sampling paths |
| `save_weights_for_sampler(name, ttl_seconds)` | YES | `save_for_sampling(name, ttl_seconds)` | TTL enforced; path added to allowed set |
| `save_weights_and_get_sampling_client(name, retry_config)` | NO | -- | Direct ephemeral save bypasses explicit TTL policy |
| explicit save + sampling client | YES | `save_and_get_sampler(name, ttl_seconds)` | Convenience wrapper calls `save_for_sampling()` with clamped TTL, then path-checked `create_sampler()` |
| `load_state(path)` | NO | -- | Could load weights from other deals. **BLOCKED.** |
| `load_state_with_optimizer(path)` | NO | -- | Same risk. **BLOCKED.** |
| `get_info()` | NO | -- | Returns training_run_id, model metadata. Low risk but not needed. |
| `get_tokenizer()` | YES | `get_tokenizer()` | Safe -- returns HuggingFace tokenizer, no secrets |
| `create_sampling_client(model_path, retry_config)` | NO | -- | Bypasses session path checking. Use `create_sampler()` instead. |
| `create_sampling_client(base_model=...)` | YES | `create_base_sampler(base_model)` | Scoped to this deal's training model for tuned-vs-base evaluation |

**Gaps identified:**
- `forward()` (inference-only pass) is not exposed. Evaluator might need this for computing eval loss without gradients. Should be added with metering.
- `forward_backward_custom()` is not exposed. This is the DPO/custom-loss entry point. See Section 7 for whether we need it.
- `get_info()` could be useful for the evaluator to confirm model configuration. Low security risk. Consider exposing a sanitized version.

### 2.3 SamplingClient Methods

| Method | Exposed | Wrapped As | Rationale |
|--------|---------|------------|-----------|
| `sample(prompt, num_samples, sampling_params, include_prompt_logprobs, topk_prompt_logprobs)` | YES | `sample(sampler, prompt, sampling_params, num_samples)` | Metered (prefill + generation tokens) |
| `compute_logprobs(prompt)` | YES | `compute_logprobs(sampler, prompt)` | Metered (prefill tokens) |
| `get_tokenizer()` | NO | -- | Available through TrainingClient wrapper instead |
| `sample_async(...)` | NO | -- | Async variants not yet supported in session |

**Gaps identified:**
- `include_prompt_logprobs` and `topk_prompt_logprobs` parameters are not passed through in the current `sample()` wrapper. The evaluator may need prompt logprobs for DPO/PPO evaluation.
- Sample token metering: current implementation meters prefill tokens but does NOT meter generated output tokens. The `SampleResponse.sequences[].tokens` length should be counted after the result is obtained.

### 2.4 RestClient Methods (ALL BLOCKED)

| Method | Status | Rationale |
|--------|--------|-----------|
| `get_training_run(id)` | BLOCKED | Reveals other training runs |
| `get_training_run_by_tinker_path(path)` | BLOCKED | Same |
| `list_training_runs(limit, offset)` | BLOCKED | Enumerates all user's runs |
| `list_checkpoints(training_run_id)` | BLOCKED | Internal to cleanup only |
| `list_user_checkpoints(limit, offset)` | BLOCKED | Cross-deal visibility |
| `get_checkpoint_archive_url(id, cp_id)` | BLOCKED | **Weight exfiltration** |
| `get_checkpoint_archive_url_from_tinker_path(path)` | BLOCKED | **Weight exfiltration** |
| `delete_checkpoint(id, cp_id)` | BLOCKED | Internal to cleanup only |
| `delete_checkpoint_from_tinker_path(path)` | BLOCKED | Internal to cleanup only |
| `publish_checkpoint_from_tinker_path(path)` | BLOCKED | **Makes weights globally accessible** |
| `unpublish_checkpoint_from_tinker_path(path)` | BLOCKED | N/A |
| `set_checkpoint_ttl_from_tinker_path(path, ttl)` | BLOCKED | Could extend TTL to defeat dead man's switch |
| `get_weights_info_by_tinker_path(path)` | BLOCKED | Reveals checkpoint metadata |
| `get_session(session_id)` | BLOCKED | Cross-session visibility |
| `list_sessions(limit, offset)` | BLOCKED | Cross-session visibility |
| `get_sampler(sampler_id)` | BLOCKED | Cross-session visibility |

**These are all correctly blocked.** The RestClient is the primary attack surface for weight exfiltration (via `get_checkpoint_archive_url`) and information leakage (via listing operations).

### 2.5 APIFuture Interface

| Method | Notes |
|--------|-------|
| `result(timeout)` | Sync wait -- currently used throughout |
| `result_async(timeout)` | Async wait -- not exposed in session |
| `__await__` | Async await syntax -- not exposed |
| `future()` | Returns `concurrent.futures.Future` -- not exposed |

The session currently returns raw `APIFuture` objects from `forward_backward()` and `optim_step()`, meaning the evaluator calls `.result()` on them directly. This is acceptable but means we rely on the evaluator not holding references to the underlying client through the future object.

---

## 3. Data Flow Diagrams

### 3.1 Training Flow

```
Seller's Artifact (bytes)
    |
    v
[Control Plane] -- decrypts artifact, holds in TEE memory
    |
    v
[Evaluator Agent (A_B)] -- receives artifact + IsolatedTinkerSession
    |
    +--> session.create_training(base_model, rank)
    |        |
    |        +--> ServiceClient.create_lora_training_client()
    |        |        |
    |        |        +--> Tinker API: CreateModel (allocates GPU resources)
    |        |        +--> Returns: TrainingClient + model_id
    |        |
    |        +--> TrainingClient.get_info() --> captures training_run_id
    |        +--> CostMeter.set_model(base_model)
    |
    +--> session.forward_backward(data, loss_fn)
    |        |
    |        +--> CostMeter.record_train(token_count)
    |        +--> TrainingClient.forward_backward(data, loss_fn)
    |        |        |
    |        |        +--> Tinker API: ForwardBackward (GPU compute)
    |        |        +--> Returns: APIFuture[ForwardBackwardOutput]
    |        |                 Contains: loss_fn_outputs, metrics
    |        |
    |        +--> Returns: APIFuture (evaluator calls .result())
    |
    +--> session.optim_step(adam_params)
    |        |
    |        +--> TrainingClient.optim_step(adam_params)
    |        +--> Returns: APIFuture[OptimStepResponse]
    |
    +--> session.save_and_get_sampler("eval")
    |        |
    |        +--> TrainingClient.save_weights_and_get_sampling_client()
    |        |        |
    |        |        +--> Tinker API: SaveWeightsForSampler (ephemeral)
    |        |        +--> Tinker API: CreateSamplingSession
    |        |        +--> Returns: SamplingClient
    |        |
    |        +--> Returns: SamplingClient (path implicitly allowed)
    |
    +--> session.sample(sampler, prompt, params)
    |        |
    |        +--> CostMeter.record_prefill(prompt_tokens)
    |        +--> SamplingClient.sample(prompt, params, num_samples)
    |        +--> [MISSING: record_sample(generated_tokens)]
    |        +--> Returns: Future[SampleResponse]
    |
    +--> Evaluator returns raw metrics dict
    |
    v
[Control Plane] -- bound_output(raw_delta) --> ScoreBand
    |
    +--> compute_offer(band, budget_cap, reserve_price) --> offer_price
    +--> _get_tdx_quote(deal_id, result) --> TDX attestation
    +--> session.cleanup() --> deletes all checkpoints
    +--> Zero artifact from memory
    |
    v
[EvaluationResult] -- the ONLY thing that leaves the TEE
    Contains: score_band, offer_price, recommendation,
              confidence, methodology_summary,
              compute_cost_wei, fee_wei, tdx_quote
```

### 3.2 Data Boundary Summary

```
OUTSIDE TEE                      TEE BOUNDARY                    TINKER API (OUTSIDE TEE)
=============                    ============                    ========================

Seller's encrypted     --[TLS]--> Decrypted artifact
artifact                          (in-memory only)

                                  Evaluator code +
                                  IsolatedTinkerSession -------> Training requests (data batches)
                                                        <------- Loss values, metrics (scalars)
                                                        -------> Sampling requests (prompts)
                                                        <------- Generated tokens
                                                        -------> Save/load checkpoint commands
                                                        <------- Checkpoint paths (strings)

EvaluationResult       <--[TLS]-- Bounded output
(score band only)                 (control plane creates)

Escrow contract        <--[TLS]-- TDX-attested result
(on-chain)                        (offer price in wei)
```

### 3.3 What CAN Leak (Information Channels)

| Channel | Data | Risk Level | Mitigation |
|---------|------|------------|------------|
| Tinker API traffic | Training data batches (tokens + weights) | LOW | Data is from seller's artifact; Tinker sees it but is a service provider, not an adversary |
| Tinker API traffic | Checkpoint paths | LOW | Opaque IDs, not meaningful |
| Tinker API traffic | Loss values, metrics | LOW | Scalars only; bounded before leaving TEE |
| Tinker checkpoint storage | LoRA adapter weights | **HIGH** | TTL dead man's switch + explicit cleanup |
| EvaluationResult | Score band | BY DESIGN | Coarse banding prevents exact quality leakage |
| EvaluationResult | Methodology summary | MEDIUM | Free-text from evaluator; could encode info. See Section 4. |
| Timing side channel | Duration of training/eval | LOW | Not easily actionable |

---

## 4. Security Boundary Analysis

### 4.1 Threat Model

The IsolatedTinkerSession defends against a **malicious evaluator agent** (or compromised evaluator code) that attempts to:

1. **Exfiltrate model weights** -- Download or publish trained checkpoints
2. **Access other deals** -- Read training runs, checkpoints, or sessions from other deals
3. **Persist state across deals** -- Load weights from a previous deal into a new one
4. **Bypass cost controls** -- Train without metering, or accumulate unbounded costs
5. **Leak exact quality metrics** -- Encode precise delta values in bounded output
6. **Extend checkpoint lifetime** -- Modify TTL to keep weights accessible indefinitely

### 4.2 Defense Matrix

| Threat | Defense | Status | Notes |
|--------|---------|--------|-------|
| Weight download | `get_checkpoint_archive_url` blocked | IMPLEMENTED | No SDK path to download |
| Weight publish | `publish_checkpoint` blocked | IMPLEMENTED | No SDK path to publish |
| Cross-deal access | `list_training_runs`, `list_sessions` blocked | IMPLEMENTED | |
| State loading | `load_state`, `create_training_client_from_state` blocked | IMPLEMENTED | |
| Path traversal | `create_sampler` path-checked against `_allowed_paths` | IMPLEMENTED | |
| Raw client bypass in first-party evaluator | `sft_evaluate()` uses wrapper methods only | IMPLEMENTED | Source regression test blocks `_sc`, REST, list, download, publish, delete |
| Unbounded cost | `CostMeter` tracks all operations | PARTIAL | **Generation tokens not metered** |
| Unbounded training | One training run per deal | IMPLEMENTED | |
| Checkpoint persistence | Mandatory TTL on all saves (1h-24h) | IMPLEMENTED | |
| Checkpoint persistence | `cleanup()` deletes all checkpoints on deal resolution | IMPLEMENTED | Retry-backed; emits bounded cleanup attestation |
| Exact quality leakage | `bound_output()` maps to coarse score bands | IMPLEMENTED | In control_plane.py |
| TTL extension | `set_checkpoint_ttl` blocked | IMPLEMENTED | Cannot call RestClient |

### 4.3 Known Gaps

**GAP 1: Generated token metering.** The `sample()` method meters prefill tokens but not generated tokens. After `sampler.sample()` returns, the output tokens in `result.sequences[i].tokens` are not counted toward cost. Fix: await the result inside the wrapper and count output tokens before returning.

**RESOLVED: `save_and_get_sampler()` TTL enforcement.** The wrapper no longer
calls `save_weights_and_get_sampling_client()` directly. It uses explicit
`save_for_sampling()` with clamped TTL, then path-checked `create_sampler()`.
Mocked-SDK tests verify that the convenience path uses the same TTL policy as
named sampler checkpoints.

**RESOLVED: cleanup retry and attestation.** `cleanup()` retries checkpoint
deletions, closes the session idempotently, and returns a bounded
`CleanupAttestation` containing counts, attempts, success/error status, and a
hash of checkpoint IDs rather than raw IDs. `ControlPlane.on_deal_resolved()`
stores that attestation on the deal context.

**GAP 2: `forward_backward_custom()` security.** This method executes a user-provided Python callable locally (in the TEE), receiving logprob tensors from the server. The callable itself never leaves the TEE, but it has access to the `TrainingClient` internals through the closure. If exposed, it should be wrapped to prevent the callable from accessing `self._training_client` or `self._sc` directly.

**GAP 3: `**kwargs` passthrough in `create_training()`.** Currently, `**kwargs` is passed to `create_lora_training_client`, which could allow injecting unexpected parameters. The session should explicitly whitelist: `seed`, `train_mlp`, `train_attn`, `train_unembed`.

**GAP 5: Methodology summary free-text.** The evaluator's returned `methodology` string passes through to `EvaluationResult.methodology_summary`. A malicious evaluator could steganographically encode exact quality values in this text. Fix: validate/truncate the methodology string, or generate it from structured data in the control plane.

**RESOLVED: base model sampler in evaluator.** `sft_evaluate()` now calls
`session.create_base_sampler(base_model)`, which only creates a base sampler for
the model scoped to the current deal. Source regression tests fail if the
first-party evaluator reaches `session._sc`, REST/list/download/publish/delete
APIs, or arbitrary sampling paths.

**GAP 6: In-process Python introspection.** The wrapper blocks the first-party
evaluator path and ordinary method access, but an arbitrary malicious evaluator
running in the same Python process could still attempt object introspection.
Before accepting third-party evaluator code, move evaluator execution behind a
process or sandbox capability boundary.

**GAP 7: No budget cap enforcement.** The session meters costs but does not enforce a maximum spend. If `compute_cost_wei` exceeds the deal's `budget_cap`, training should be halted. The control plane passes `budget_cap` to the evaluator but the session does not enforce it.

---

## 5. TTL and Checkpoint Lifecycle

### 5.1 What We Know (from SDK + Docs)

**Checkpoint types:**
- `training` -- weights + optimizer state, saved via `save_state(name, ttl_seconds)`
- `sampler` -- weights only, saved via `save_weights_for_sampler(name, ttl_seconds)`

**TTL support:**
- Both `save_state()` and `save_weights_for_sampler()` accept `ttl_seconds: int | None`
- `None` means the checkpoint never expires
- The `Checkpoint` type has an `expires_at: datetime | None` field
- `RestClient.set_checkpoint_ttl_from_tinker_path(path, ttl_seconds)` can modify TTL after creation
- TTL of `None` removes expiration

**Checkpoint paths:**
- Format: `tinker://<training_run_id>/weights/<checkpoint_id>` (training)
- Format: `tinker://<training_run_id>/sampler_weights/<checkpoint_id>` (sampler)

**Checkpoint storage pricing:**
- $0.10 per GB per month

**Checkpoint size:**
- The `Checkpoint.size_bytes` field exists but may be `None`
- LoRA adapter size depends on rank and model size (e.g., rank-32 on 8B model is ~100-200MB)

### 5.2 Current Session TTL Policy

```python
MIN_TTL = 3600       # 1 hour floor
MAX_TTL = 86400      # 24 hour cap
DEFAULT_TTL = 3600   # 1 hour default
```

The session clamps TTL to [1h, 24h]. This serves as a "dead man's switch" -- even if `cleanup()` is never called (CVM crash, network failure), checkpoints auto-delete within 24 hours.

### 5.3 What We Need to Verify

| Question | Impact | How to Verify |
|----------|--------|---------------|
| Are ephemeral sampler weights (from `save_weights_and_get_sampling_client`) cleaned up when the sampling session ends? | If not, weights persist indefinitely | Test: create ephemeral sampler, check if checkpoint appears in `list_checkpoints` |
| Does `ttl_seconds` countdown start at creation time or last-access time? | Affects whether active evaluation can outlive TTL | Test: create checkpoint with 1h TTL, access after 50min, check if it extends |
| Can a checkpoint be accessed (sampled from) after its TTL expires? | If yes, TTL only affects storage, not access | Test: create 1h TTL checkpoint, try sampling at 61min |
| What happens to an active SamplingClient when its underlying checkpoint expires? | Could crash mid-evaluation | Test: create sampler from TTL checkpoint, let TTL expire, try sampling |
| Is there a maximum checkpoint count per training run? | Could be used to DoS storage | Test: create 1000 checkpoints rapidly |
| Is there a rate limit on save operations? | Affects evaluation speed if saving many checkpoints | Test: rapid save_state calls |

### 5.4 Recommended TTL Strategy

```
Deal lifecycle:
  T=0:  Deal funded, session created
  T+5m: Artifact received, evaluation starts
  T+1h: Typical evaluation completes (200 SFT steps + sampling)
  T+2h: Extended evaluation (RL loop, DPO, multiple checkpoints)
  T+4h: Maximum reasonable evaluation time
  T+24h: Dead man's switch -- all checkpoints expire

Recommended:
  - Evaluation checkpoints (mid-training): TTL = 2h (7200s)
  - Evaluation checkpoints (for sampling): TTL = 4h (14400s)
  - Maximum session duration: 6h, enforced by control plane
  - Dead man's switch: MAX_TTL = 24h (86400s), unchanged
```

---

## 6. Cost Metering Strategy

### 6.1 Current Pricing Table (from thinkingmachines.ai, as of 2026-03-10)

All prices in USD per million tokens:

| Model | Prefill | Sample | Train |
|-------|---------|--------|-------|
| Qwen3.5-397B-A17B | $2.00 | $5.00 | $6.00 |
| Qwen3.5-35B-A3B | $0.36 | $0.89 | $1.07 |
| Qwen3.5-27B | $1.24 | $3.73 | $3.73 |
| Qwen3.5-4B | $0.22 | $0.67 | $0.67 |
| Qwen3-8B | $0.13 | $0.40 | $0.40 |
| Qwen3-30B-A3B | $0.12 | $0.30 | $0.36 |
| Qwen3-32B | $0.49 | $1.47 | $1.47 |
| Qwen3-235B-Instruct | $0.68 | $1.70 | $2.04 |
| Qwen3-VL-30B-A3B-Instruct | $0.18 | $0.44 | $0.53 |
| Qwen3-VL-235B-A22B-Instruct | $1.02 | $2.56 | $3.07 |
| Llama-3.2-1B | $0.03 | $0.09 | $0.09 |
| Llama-3.2-3B | $0.06 | $0.18 | $0.18 |
| Llama-3.1-8B / 8B-Instruct | $0.13 | $0.40 | $0.40 |
| Llama-3.1-70B | $1.05 | $3.16 | $3.16 |
| DeepSeek-V3.1 | $1.13 | $2.81 | $3.38 |
| GPT-OSS-120B | $0.18 | $0.44 | $0.52 |
| GPT-OSS-20B | $0.12 | $0.30 | $0.36 |
| Kimi-K2-Thinking | $0.98 | $2.44 | $2.93 |
| Kimi-K2.5 | $1.47 | $3.66 | $4.40 |

Storage: $0.10/GB-month

### 6.2 Current CostMeter Implementation

The `CostMeter` tracks three token categories:
- `train_tokens` -- from `forward_backward()` data batches
- `sample_tokens` -- **NOT CURRENTLY POPULATED** (gap)
- `prefill_tokens` -- from `sample()` and `compute_logprobs()` prompt inputs

Cost is computed as:
```
total_cost_usd = train * price_train/1M + sample * price_sample/1M + prefill * price_prefill/1M
total_cost_wei = (total_cost_usd / ETH_USD) * 10^18
fee_wei = total_cost_wei / 100  (1% protocol fee)
```

### 6.3 Metering Gaps and Fixes

**Fix 1: Meter generated tokens.**
```python
def sample(self, sampler, prompt, sampling_params, num_samples=1):
    # ... existing prefill metering ...
    future = sampler.sample(prompt, sampling_params, num_samples)
    result = future.result()  # Must await to count output tokens
    for seq in result.sequences:
        self._meter.record_sample(len(seq.tokens))
    return result  # Return resolved result, not future
```

Note: This changes the return type from `Future` to resolved `SampleResponse`. Evaluate whether the evaluator needs the `Future` pattern.

**Fix 2: Update pricing table.** The hardcoded `PRICING` dict in `session.py` only covers 5 models. It should be expanded to match the full pricing table above. Consider fetching pricing dynamically from the Tinker homepage or maintaining a versioned lookup.

**Fix 3: Enforce budget cap.**
```python
def _check_budget(self):
    if self._budget_cap and self._meter.total_cost_wei > self._budget_cap:
        raise BudgetExceededError(
            f"Compute cost {self._meter.total_cost_wei} exceeds budget {self._budget_cap}"
        )
```

Call `_check_budget()` before every metered operation.

**Fix 4: ETH/USD price.** The current hardcoded `ETH_USD = 2000.0` is a placeholder. For production, this should be set at deal creation time from a price oracle (e.g., Chainlink) and stored in the `DealContext`.

### 6.4 Cost Estimation Examples

Typical SFT evaluation on Llama-3.1-8B-Instruct:
- 200 training steps, batch_size=4, ~200 tokens/example = 160,000 train tokens
- 20 eval samples, ~500 tokens/prompt = 10,000 prefill tokens
- 20 eval samples, ~100 tokens generated = 2,000 sample tokens
- **Total cost: ~$0.068 USD** (160K * $0.40/M + 10K * $0.13/M + 2K * $0.40/M)

Larger RL evaluation on Qwen3-235B:
- 50 RL iterations, 16 samples/iter, ~1000 tokens/sample = 800,000 sample tokens
- 50 training steps, 16 examples, ~500 tokens = 400,000 train tokens
- **Total cost: ~$2.18 USD** (800K * $1.70/M + 400K * $2.04/M)

---

## 7. Evaluation Protocol Options

### 7.1 SFT Evaluation (Currently Implemented)

**Loss function:** `cross_entropy`
**Protocol:**
1. Parse JSONL dataset from artifact
2. Tokenize with prompt/completion weighting (train on completions only)
3. LoRA fine-tune on Llama-3.1-8B-Instruct (rank=32, 200 steps, batch_size=4, lr=1e-4)
4. Save checkpoint, create sampling client
5. Compute perplexity on held-out set
6. Compare against base model perplexity
7. Return `quality_delta = (base_ppl - tuned_ppl) / base_ppl`

**Strengths:** Simple, fast, deterministic metric. Well-understood baseline.
**Weaknesses:** Only measures next-token prediction improvement. Does not evaluate generation quality, instruction following, or task-specific performance.

### 7.2 DPO Evaluation (Not Yet Implemented)

**Loss function:** `forward_backward_custom()` with DPO loss, OR direct `cross_entropy` with the DPO dataset rendering used by tinker-cookbook.

**Requires:**
- `forward_backward_custom()` to be exposed in session (currently blocked)
- OR: use the cookbook's DPO implementation which renders chosen/rejected pairs into `cross_entropy`-compatible format using logprob differences

**Protocol:**
1. Parse preference dataset (chosen/rejected pairs per prompt)
2. Compute reference logprobs on base model (via `compute_logprobs`)
3. Fine-tune with DPO loss: `L = -log sigma(beta * (log(pi/pi_ref)(chosen) - log(pi/pi_ref)(rejected)))`
4. Evaluate: accuracy on held-out preferences, margin between chosen/rejected rewards
5. Return quality_delta based on accuracy improvement

**Session changes needed:**
- Expose `forward_backward_custom()` or implement DPO as a server-side loss function
- Expose `forward()` for computing eval-only logprobs without gradient computation
- Allow base-model sampler creation for reference policy

### 7.3 RL/PPO Evaluation (Not Yet Implemented)

**Loss functions:** `importance_sampling`, `ppo`, `cispo`

**Protocol:**
1. Parse environment/reward function from artifact
2. Create training run + sampling client
3. RL loop: sample -> evaluate rewards -> compute advantages -> train with PPO
4. Evaluate final policy against base model on held-out prompts
5. Return quality_delta based on reward improvement

**Session changes needed:**
- All loss functions are already string-passable to `forward_backward()`, so no new SDK methods needed
- The evaluator needs `sample()` + `forward_backward()` interleaving, which is already supported
- May need `loss_fn_config` for PPO clip thresholds (already supported)
- May need `forward()` for computing KL divergence without training

**Additional loss functions available:**
- `importance_sampling` -- REINFORCE-style policy gradient
- `ppo` -- PPO with configurable clip thresholds (default 0.2)
- `cispo` -- Clipped importance sampling (Chen et al., 2024)
- `dro` -- Direct Reward Optimization with quadratic penalty (Richemond et al., 2024)

### 7.4 Custom Loss Evaluation

**Loss function:** `forward_backward_custom()` with arbitrary PyTorch callable

**Security considerations:**
- The custom loss function runs *inside* the TEE, not on the Tinker server
- It receives logprob tensors and returns gradients
- The function has access to whatever Python environment exists in the TEE
- If the evaluator provides a malicious loss function, it could access `self._training_client` internals

**Recommendation:** Do NOT expose `forward_backward_custom()` in v1. Instead, support DPO via the cookbook's approach (rendering DPO as a custom training loop using `forward()` + `forward_backward()`).

### 7.5 Recommended Evaluation Protocol Matrix

| Artifact Type | Evaluation Method | Loss Function | Session Methods Needed |
|---------------|-------------------|---------------|------------------------|
| SFT dataset (JSONL) | Perplexity comparison | `cross_entropy` | `create_training`, `forward_backward`, `optim_step`, `save_and_get_sampler`, `sample`, `compute_logprobs` |
| Preference dataset | DPO training + accuracy | `cross_entropy` (rendered) | Same + `forward` (for ref logprobs) |
| RL environment | PPO training + reward | `ppo` or `importance_sampling` | Same + `forward_backward` with RL loss config |
| Code dataset | RL with code execution | `ppo` | Same + sandboxed code execution (separate from Tinker) |
| Vision dataset | VLM fine-tuning | `cross_entropy` | Same, but with `ImageChunk` in `ModelInput` |

---

## 8. Testing Strategy

### 8.1 Unit Tests

**Test the session wrapper in isolation (mock Tinker SDK):**

| Test | Mock | Asserts |
|------|------|---------|
| `test_single_training_run` | Mock `ServiceClient.create_lora_training_client` | Second call raises `AssertionError` |
| `test_closed_session_rejects` | N/A | All methods raise after `cleanup()` |
| `test_ttl_clamping` | Mock `TrainingClient.save_weights_for_sampler` | TTL arg is clamped to [3600, 86400] |
| `test_path_checking` | N/A | `create_sampler("tinker://other/...")` raises `PermissionError` |
| `test_base_sampler_is_scoped_to_training_model` | Mock `ServiceClient.create_sampling_client` | Base sampler must match the training model |
| `test_allowed_path_tracking` | Mock save response with path | Path added to `_allowed_paths`; `create_sampler` succeeds |
| `test_sft_evaluator_does_not_reach_raw_tinker_client_or_admin_apis` | Source inspection | Evaluator does not use raw client/admin APIs |
| `test_cost_metering_train` | Mock `forward_backward` | `meter.train_tokens` incremented by datum token count |
| `test_cost_metering_prefill` | Mock `sample` | `meter.prefill_tokens` incremented by prompt length |
| `test_cost_metering_sample` | Mock `sample` result | `meter.sample_tokens` incremented by generated token count |
| `test_cost_calculation` | Set known token counts | `total_cost_usd` matches manual calculation |
| `test_deal_id_in_metadata` | Mock `create_lora_training_client` | `user_metadata["deal_id"]` is set |
| `test_cleanup_idempotent` | Mock `RestClient` | Double `cleanup()` does not raise |
| `test_cleanup_retries_transient_delete_failures` | Mock transient delete failures | Retries and succeeds |
| `test_cleanup_attests_permanent_delete_failures` | Mock persistent delete failure | Returns bounded failed cleanup attestation |
| `test_cleanup_attests_checkpoint_listing_failure` | Mock list failure | Returns bounded failed cleanup attestation |
| `test_kwargs_whitelist` | N/A | Unexpected kwargs rejected |
| `test_budget_cap_enforcement` | Set low budget, meter tokens | Operation raises `BudgetExceededError` |

### 8.2 Integration Tests (Against Tinker API)

**Requires `TINKER_API_KEY` and real API calls. Disabled by default. Run only
with `TINKER_RUN_REAL_SDK_TESTS=1` and a low `TINKER_REAL_SDK_MAX_USD` cap.**

| Test | Steps | Asserts |
|------|-------|---------|
| `test_tiny_training_sampling_and_cleanup` | Tiny real SDK smoke with explicit budget gate | Creates run, saves TTL checkpoint, samples, cleans up |
| `test_e2e_sft_evaluation` | Full SFT eval with 10 training examples | Returns quality_delta > 0, compute_cost_wei > 0 |
| `test_checkpoint_ttl_expiry` | Save with TTL=3600, wait, check expiry | Checkpoint `expires_at` is set correctly |
| `test_cleanup_deletes_all` | Create run, save 3 checkpoints, cleanup | `list_checkpoints` returns empty |
| `test_ephemeral_sampler_cleanup` | `save_and_get_sampler`, check what persists | Verify no lingering checkpoints |
| `test_cross_deal_isolation` | Two sessions, try cross-access | `PermissionError` on path mismatch |
| `test_large_batch_metering` | 100 training examples in one forward_backward | Token count matches expected |

### 8.3 Mock Strategy

**What to mock:**

| Component | Mock Type | Rationale |
|-----------|-----------|-----------|
| `tinker.ServiceClient` | Full mock | Avoid API calls in unit tests |
| `tinker.TrainingClient` | Full mock | Training operations return predictable results |
| `tinker.SamplingClient` | Full mock | Sampling returns deterministic sequences |
| `tinker.RestClient` | Full mock | List/delete operations for cleanup testing |
| `tinker.types.ForwardBackwardOutput` | Data fixture | Realistic loss_fn_outputs with logprobs |
| `tinker.types.SampleResponse` | Data fixture | Realistic sequences with token lists |
| `tinker.types.GetInfoResponse` | Data fixture | Returns training_run_id, model metadata |

**Mock factory pattern:**
```python
def make_mock_session(deal_id="test-deal-001", base_model="meta-llama/Llama-3.1-8B"):
    """Create an IsolatedTinkerSession with fully mocked Tinker SDK."""
    mock_sc = MagicMock(spec=tinker.ServiceClient)
    mock_tc = MagicMock(spec=tinker.TrainingClient)
    mock_sc.create_lora_training_client.return_value = mock_tc
    mock_tc.get_info.return_value = GetInfoResponse(
        training_run_id="mock-run-123", ...
    )
    session = IsolatedTinkerSession(mock_sc, deal_id)
    return session, mock_sc, mock_tc
```

### 8.4 Stub Evaluator

The existing `stub_evaluate()` in `evaluator.py` is a deterministic evaluator that returns synthetic metrics based on artifact hash. It does not make any Tinker API calls. This should be used for:
- CI pipeline tests
- Control plane lifecycle testing
- Front-end integration testing

---

## 9. NDAI Paper Alignment

### 9.1 Paper Concepts Mapped to Implementation

| NDAI Paper Concept | Implementation | Status |
|-------------------|----------------|--------|
| **Seller (S)** | Entity uploading artifact (dataset/recipe) | N/A (off-chain) |
| **Buyer (B)** | Entity funding the deal with budget cap P-bar | N/A (on-chain escrow) |
| **Agent A_S (seller's agent)** | Not implemented -- seller discloses artifact passively | N/A |
| **Agent A_B (buyer's agent)** | `evaluator.py` -- runs inside TEE | IMPLEMENTED |
| **TEE (T)** | Phala Cloud CVM (Intel TDX) running tinker-delegate | IMPLEMENTED |
| **Private input x_S (seller)** | Encrypted artifact (dataset, training recipe) | IMPLEMENTED |
| **Private input x_B (buyer)** | Budget cap P-bar, reserve price | IMPLEMENTED (on-chain) |
| **Disclosed value omega-hat** | `quality_delta` from evaluator, bounded to `ScoreBand` | IMPLEMENTED |
| **Payment P** | `offer_price` computed from score band + budget constraints | IMPLEMENTED |
| **Budget cap P-bar** | `budget_cap` in `DealContext` | IMPLEMENTED |
| **Reserve price** | `reserve_price` in `DealContext` | IMPLEMENTED |
| **Security threshold Phi** | Not directly modeled -- we assume TEE is secure | OPEN QUESTION |
| **Agent error epsilon_B** | Not modeled -- evaluator is deterministic code, not stochastic | SEE BELOW |
| **Nash bargaining solution** | Simplified: band-based multiplier on budget cap | IMPLEMENTED (approximation) |
| **TDX attestation** | `_get_tdx_quote()` binding result to enclave | IMPLEMENTED (stub) |

### 9.2 Section 5 Analysis: Robustness to Agent Errors

The NDAI paper's Section 5 analyzes robustness when agents make random errors. In our implementation:

**Sources of "agent error" in the evaluator:**
1. **Training variance** -- Different random seeds produce different quality_delta values
2. **Dataset sensitivity** -- Small datasets produce noisy perplexity estimates
3. **Hyperparameter sensitivity** -- Fixed lr=1e-4, rank=32 may not be optimal for all datasets
4. **Evaluation noise** -- 20-sample eval set has high variance

**Paper's mitigation mechanisms and our implementation:**

| Mechanism | Paper | Our Implementation |
|-----------|-------|-------------------|
| **Budget cap** (prevents overpayment) | P-bar caps buyer's maximum payment | `budget_cap` in `DealContext`; `offer_price <= budget_cap` enforced |
| **Acceptance threshold** (prevents underpayment) | Seller rejects offers below alpha_0 * omega | `reserve_price` acts as floor; offer clamped to >= reserve_price for non-negligible bands |
| **Score banding** (reduces error impact) | Not in paper | Our addition: coarse bands (<1%, 1-5%, 5-10%, 10-20%, >20%) reduce the impact of evaluation noise on offer price |

**Paper's Corollary 1 (error tolerance):** The paper shows that positive error thresholds exist below which each player's payoff exceeds their baseline. Our score banding effectively *quantizes* the error, making the mechanism more robust than the paper's continuous model. A quality_delta of 0.08 vs 0.09 does not change the offer (both map to MEDIUM band = 50% of budget).

### 9.3 Alignment Gaps

**GAP A: No information-theoretic analysis of score bands.** The paper proves that budget caps extend error tolerance by 50%. We have not analyzed whether our 5-band system provides comparable or better error tolerance. The band boundaries (1%, 5%, 10%, 20%) should be justified or made configurable.

**GAP B: No repeated interaction model.** The paper assumes one-shot bargaining. If the same seller/buyer pair enters multiple deals, the buyer accumulates information across evaluations. Score banding mitigates this but does not eliminate it.

**GAP C: Collusion between evaluator and seller.** The paper models the evaluator as aligned with the buyer. If the evaluator code itself is compromised (e.g., seller provides a malicious evaluation script), the evaluator could always return "exceptional" regardless of artifact quality. Mitigation: the evaluator code should be pinned by hash in the escrow contract, and the TDX quote should include the code hash.

**GAP D: Tinker as a third party.** The paper's TEE model assumes all computation happens inside the enclave. In our architecture, Tinker's API is *outside* the TEE -- training data (tokens) flows to Tinker's GPUs, and model weights are stored on Tinker's servers. Tinker could theoretically observe the training data (which is the seller's artifact). Mitigation: the artifact's value is in its *curation*, not individual tokens. Also, Tinker is a service provider with reputational skin in the game, not an adversarial party.

---

## 10. Open Questions and Risks

### 10.1 Must Resolve Before Production

| # | Question | Owner | Impact |
|---|----------|-------|--------|
| 1 | **What is the checkpoint count limit per training run?** Can an evaluator create unlimited checkpoints, exhausting storage? | Tinker team | DoS vector if unlimited |
| 2 | **Rate limits on training API?** Are there per-user or per-model concurrency limits? | Tinker team | Could affect evaluation speed and timeout behavior |
| 3 | **How is the Tinker API key scoped?** Can we create a key that is limited to create + train + sample but cannot list/download/publish? | Tinker team | Would provide defense-in-depth beyond session wrapper |
| 4 | **ETH/USD price oracle integration** | Smart contract team | Needed for accurate cost-to-wei conversion |
| 5 | **Evaluator code pinning** | Control plane team | TDX quote must include evaluator code hash |

### 10.2 Should Resolve Before Production

| # | Question | Impact |
|---|----------|--------|
| 7 | Should we support vision model evaluation (ImageChunk)? | Expands artifact types but increases complexity |
| 8 | Should we support MoE models (Qwen3-235B, DeepSeek-V3.1)? | Higher cost per evaluation, but potentially better quality assessment |
| 9 | How do we handle evaluator timeout? If the evaluator runs for >6h, what happens? | Need session max-duration enforcement + graceful cleanup |
| 10 | Should the evaluator be allowed to choose the base model, or should it be fixed? | Flexibility vs. cost predictability |
| 11 | How do we handle Tinker API outages during evaluation? | Need retry strategy + partial result handling |
| 12 | Should we expose `get_server_capabilities()` so the evaluator can check which models are available? | Useful but leaks model lineup info |

### 10.3 Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Tinker API key leaked from TEE | Low (TDX enclave) | Critical -- full account access | Scope key to minimum permissions; rotate per-CVM |
| Checkpoint weights accessed after TTL but before GC | Low | High -- model weights exposed | Verify Tinker's TTL enforcement is immediate, not eventual |
| Evaluator encodes artifact content in bounded output | Medium | Medium -- partial information leakage | Validate methodology string; limit to 500 chars |
| Cost metering underestimates actual Tinker bill | Medium | Low -- protocol loses money | Add reconciliation: compare metered cost vs. Tinker dashboard |
| Model training produces NaN/diverged loss | Medium | Low -- evaluation fails | Detect NaN in loss, abort early with "low" confidence |
| Tinker pricing changes without updating CostMeter | High | Medium -- incorrect cost calculation | Fetch pricing at session creation, or version-pin |
| Concurrent deals exhaust Tinker account balance | Medium | High -- all evaluations fail | Pre-fund account per-deal; or check balance before starting |

---

## Appendix A: Complete Type Reference

### Key Tinker Types Used by the Session

```python
# Training data
tinker.Datum(
    model_input: ModelInput,        # Input tokens
    loss_fn_inputs: LossFnInputs,   # Dict[str, TensorData]
)

tinker.ModelInput.from_ints(tokens: List[int]) -> ModelInput
tinker.ModelInput(chunks: List[ModelInputChunk])  # For vision inputs

tinker.TensorData(data: list, dtype: str, shape: list)
# dtypes: "int64" (target_tokens), "float32" (weights, advantages, logprobs)

# Loss functions
LossFnType = Literal["cross_entropy", "importance_sampling", "ppo", "cispo", "dro"]

# Optimizer
tinker.AdamParams(
    learning_rate: float = 0.0001,
    beta1: float = 0.9,
    beta2: float = 0.95,
    eps: float = 1e-12,
    weight_decay: float = 0.0,
    grad_clip_norm: float = 0.0,
)

# Sampling
tinker.SamplingParams(
    max_tokens: int | None = None,
    seed: int | None = None,
    stop: str | Sequence[str] | Sequence[int] | None = None,
    temperature: float = 1.0,
    top_k: int = -1,
    top_p: float = 1.0,
)

# Results
ForwardBackwardOutput(
    loss_fn_output_type: str,
    loss_fn_outputs: List[LossFnOutput],  # Dict[str, TensorData] per datum
    metrics: Dict[str, float],
)

SampleResponse(
    sequences: Sequence[SampledSequence],  # Generated text
    prompt_logprobs: List[float | None] | None,
    topk_prompt_logprobs: list | None,
)

SampledSequence(
    stop_reason: StopReason,
    tokens: List[int],
    logprobs: List[float] | None,
)

# Checkpoints
Checkpoint(
    checkpoint_id: str,
    checkpoint_type: "training" | "sampler",
    time: datetime,
    tinker_path: str,
    size_bytes: int | None,
    public: bool = False,
    expires_at: datetime | None,
)

# LoRA config (set at training creation)
LoraConfig(
    rank: int,
    seed: int | None,
    train_mlp: bool,
    train_attn: bool,
    train_unembed: bool,
)
```

### Appendix B: Supported Models (as of 2026-03-10)

**Qwen 3.5 Series:** 397B-A17B, 35B-A3B, 27B, 4B
**Qwen 3 Series:** VL-235B, VL-30B, 235B, 30B, 32B, 8B, 30B-A3B, 8B-Base, 30B-A3B-Base, 4B-Instruct-2507
**OpenAI:** gpt-oss-120b, gpt-oss-20b
**DeepSeek:** V3.1
**Meta Llama:** 3.1-70B, 3.3-70B-Instruct, 3.1-8B, 3.1-8B-Instruct, 3.2-3B, 3.2-1B
**Moonshot:** Kimi-K2-Thinking, Kimi-K2.5

### Appendix C: File Inventory

| File | Role |
|------|------|
| `session.py` | IsolatedTinkerSession -- this document's subject |
| `control_plane.py` | Deal lifecycle orchestration, output bounding, TDX attestation |
| `evaluator.py` | Evaluator agents (stub + real SFT) |
| `billing.py` | Tinker account payment automation (Stripe) |
| `config.py` | Environment configuration |
| `signup.py` | Tinker account signup automation |
| `api.py` | HTTP API for the TEE service |
| `main.py` | Entry point |
| `oracle_client.py` | Email OTP oracle client |
| `crypto.py` | Encryption utilities |
| `card_channel.py` | Secure card detail channel |
