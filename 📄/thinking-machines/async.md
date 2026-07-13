---
source: https://tinker-docs.thinkingmachines.ai/async
scraped: 2026-03-08
---

# Async and Futures

## Sync and Async APIs

Every method in the Tinker Python library offers both synchronous and asynchronous versions, with async variants appended with `_async`:

| Client | Sync method | Async method |
|--------|------------|--------------|
| ServiceClient | `create_lora_training_client()` | `create_lora_training_client_async()` |
| TrainingClient | `forward()` | `forward_async()` |
| SamplingClient | `sample()` | `sample_async()` |
| RestClient | `list_training_run_ids()` | `list_training_run_ids_async()` |

The async functionality requires an `asyncio` event loop, typically executed as `asyncio.run(main())`.

**Usage guidance:**
- **Async:** Optimal for high-performance workflows requiring concurrent operations, particularly with multiple network requests
- **Sync:** Simpler for scripts and educational examples; easier to follow but blocks during each operation

## Understanding Futures

Most Tinker API methods are non-blocking and return immediately with a `Future` object confirming submission. Retrieve actual results by explicitly waiting:

**Sync Python:**

```python
future = client.forward_backward(data, loss_fn)
result = future.result()  # Blocks until complete
```

**Async Python (note the double await):**

```python
future = await client.forward_backward_async(data, loss_fn)
result = await future
```

The first `await` confirms request submission and ordering. The second `await` waits for computation completion and numerical outputs. For `forward_backward`, this guarantees gradient accumulation in optimizer state.

## Performance tips: overlap requests

Submit your next request while the current one processes for optimal performance. This is particularly critical with Tinker because training operates on discrete clock cycles (~10 seconds each). Missing a queued request at cycle start means missing that entire cycle.

**Example pattern for overlapping forward_backward and optim_step:**

```python
# Submit forward_backward
fwd_bwd_future = await client.forward_backward_async(batch, loss_fn)

# Submit optim_step immediately (don't wait for forward_backward to finish)
optim_future = await client.optim_step_async(adam_params)

# Now retrieve results
fwd_bwd_result = await fwd_bwd_future
optim_result = await optim_future
```

This approach queues both operations for potential same-cycle processing. Waiting for `forward_backward` completion before submitting `optim_step` risks missing the next cycle.
