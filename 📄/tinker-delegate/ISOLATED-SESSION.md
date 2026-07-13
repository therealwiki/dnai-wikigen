# IsolatedTinkerSession Spec

**Status**: Implemented
**Location**: `tinker_delegate/session.py` (372 lines)

## Purpose

The `IsolatedTinkerSession` is the security boundary between the evaluator agent (untrusted code) and the Tinker API (credentialed resource). It wraps `tinker.ServiceClient` and enforces:

- **One training run per deal** — prevents resource squatting
- **Path-checked sampling** — can only sample models trained in this session
- **Mandatory TTL on checkpoints** — dead man's switch if cleanup fails
- **No downloads, publishing, or listing** — prevents weight exfiltration
- **Cost metering** — tracks every API call in USD and wei

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Evaluator Agent (untrusted)                     │
│  - Receives IsolatedTinkerSession                │
│  - Can: train, sample, compute logprobs          │
│  - Cannot: download, publish, list, access key   │
├─────────────────────────────────────────────────┤
│  IsolatedTinkerSession (trust boundary)          │
│  - Wraps tinker.ServiceClient                    │
│  - Enforces: 1 run, path check, TTL, metering   │
├─────────────────────────────────────────────────┤
│  tinker.ServiceClient (credentialed)             │
│  - API key sealed in TEE memory                  │
│  - Full Tinker SDK access                        │
├─────────────────────────────────────────────────┤
│  Tinker API (external)                           │
│  - Training, sampling, checkpoint management     │
└─────────────────────────────────────────────────┘
```

## What's Implemented

### CostMeter (`session.py:44-91`)

Tracks token usage across three operation types:

| Operation | Models Priced | Price (USD/M tokens) |
|---|---|---|
| Prefill | Llama-3.2-1B through Qwen3-235B | $0.03 - $0.68 |
| Sample | Same | $0.09 - $1.70 |
| Train | Same | $0.09 - $2.04 |

Conversion: `total_cost_usd / ETH_USD (2000) * 10^18 = wei`
Fee: 1% of compute cost (`total_cost_wei // 100`)

### Session Lifecycle

1. **Create**: `ControlPlane.on_deal_funded()` → `IsolatedTinkerSession(sc, deal_id)`
2. **Train**: `session.create_training(base_model, rank)` → returns `TrainingClient`
3. **Forward/backward**: `session.forward_backward(data, loss_fn)` — metered
4. **Optimize**: `session.optim_step(adam_params)`
5. **Checkpoint**: `session.save_for_sampling(name, ttl)` — TTL enforced (1h-24h)
6. **Sample**: `session.save_and_get_sampler(name)` → `SamplingClient`
7. **Cleanup**: `session.cleanup()` — deletes all checkpoints, closes session

### Security Enforcements

| Rule | Implementation | Location |
|---|---|---|
| One training run | `assert self._training_run_id is None` | `create_training()` |
| Path-checked sampling | `if model_path not in self._allowed_paths` | `create_sampler()` |
| TTL floor/ceiling | `max(MIN_TTL, min(ttl_seconds, MAX_TTL))` | `save_for_sampling()` |
| Cost metering | `self._meter.record_train(tokens)` on every op | `forward_backward()` |
| Mandatory cleanup | Called by control plane on resolution | `cleanup()` |
| Session closed check | `assert not self._closed` on every op | All methods |

### Blocked Operations

These Tinker SDK methods are intentionally NOT exposed:

- `create_rest_client()` — no raw REST access
- `list_training_runs()` — no visibility into other deals
- `get_checkpoint_archive_url()` — no weight downloads
- `publish_checkpoint()` — no public weight sharing
- `create_sampling_client()` with arbitrary path — path-checked above
- `create_training_client_from_state()` — no loading other runs

## Known Issues

### 1. Base Model Sampling Leak (`evaluator.py:253`)

```python
base_sampler = session._sc.create_sampling_client(base_model=base_model)
```

The `sft_evaluate()` function directly accesses `session._sc` to create a base model sampler for comparison. This bypasses the session isolation boundary.

**Fix**: Add a `create_base_sampler(base_model)` method to `IsolatedTinkerSession` that allows sampling from the base model (no fine-tuned weights) without exposing the raw `ServiceClient`. This is safe because base model weights are public.

```python
def create_base_sampler(self, base_model: str) -> tinker.SamplingClient:
    """Create sampler for the base model (public weights, not fine-tuned)."""
    assert not self._closed, "Session closed"
    return self._sc.create_sampling_client(base_model=base_model)
```

### 2. ETH_USD Price Staleness

`ETH_USD = 2000.0` is hardcoded. In production, this should be fetched from a price oracle at deal creation time and locked for the deal's duration.

### 3. Python String Immutability

`CardDetails.zero()` sets attributes to `""` but Python strings are immutable — the original string objects remain in memory until GC. True memory zeroing requires `ctypes` or `mmap`.

The `IsolatedTinkerSession` doesn't handle card data, but the same concern applies to API keys in `ServiceClient`.

### 4. No Rate Limiting

Nothing prevents an evaluator from making thousands of API calls within the budget. The cost meter tracks but doesn't enforce. The control plane should check `session.compute_cost_wei` against the deal's `budget_cap` during evaluation.

**Fix**: Add budget enforcement to metered operations:

```python
def forward_backward(self, data, loss_fn="cross_entropy", loss_fn_config=None):
    # ... existing code ...
    if self._meter.total_cost_wei > self._budget_cap:
        raise BudgetExceeded(f"Compute cost {self._meter.total_cost_wei} exceeds budget {self._budget_cap}")
```

### 5. Tokenizer Access

`get_tokenizer()` returns the raw tokenizer object. This is safe (tokenizers don't contain secrets and base model tokenizers are public), but worth noting as a surface area consideration.

## Remaining Work

| Task | Priority | Effort |
|---|---|---|
| Fix base model sampler leak | High | 10 min |
| Add budget enforcement to metered ops | High | 30 min |
| Add ETH price oracle integration | Medium | 2 hours |
| Add rate limiting (calls/min) | Low | 1 hour |
| Integration tests with mock Tinker SDK | Medium | 4 hours |
| Document Tinker SDK version requirements | Low | 30 min |

## Tinker SDK Surface Area

Based on `📄/thinking-machines/` docs, the SDK provides:

```
tinker.ServiceClient(api_key="tml-...")
  ├── create_lora_training_client(base_model, rank, ...) → TrainingClient
  │     ├── forward_backward(data, loss_fn, ...) → Future[FwdBwdResult]
  │     ├── optim_step(adam_params) → Future
  │     ├── save_weights_for_sampler(name, ttl) → Future[SaveResp]
  │     ├── save_state(name, ttl) → Future[SaveResp]
  │     ├── save_weights_and_get_sampling_client(name) → SamplingClient
  │     ├── get_tokenizer() → Tokenizer
  │     └── get_info() → TrainingInfo
  ├── create_sampling_client(model_path=..., base_model=...) → SamplingClient
  │     ├── sample(prompt, sampling_params, num_samples) → SampleResult
  │     └── compute_logprobs(prompt) → Future[list[float]]
  └── create_rest_client() → RestClient
        ├── list_training_runs() → list
        ├── list_checkpoints(run_id) → list
        ├── delete_checkpoint(run_id, cp_id) → Future
        ├── get_checkpoint_archive_url(run_id, cp_id) → str
        └── publish_checkpoint(...) / unpublish_checkpoint(...)

tinker.Datum(model_input, loss_fn_inputs)
tinker.ModelInput.from_ints(token_ids)
tinker.TensorData(data, dtype, shape)
tinker.AdamParams(learning_rate, beta1, beta2, ...)
tinker.SamplingParams(max_tokens, temperature, ...)
```

The session exposes: `create_training`, `forward_backward`, `optim_step`, `save_for_sampling`, `save_state`, `save_and_get_sampler`, `create_sampler` (path-checked), `sample`, `compute_logprobs`, `get_tokenizer`, `cleanup`.

The session blocks: `create_rest_client`, `list_training_runs`, `get_checkpoint_archive_url`, `publish_checkpoint`, arbitrary `create_sampling_client`.
