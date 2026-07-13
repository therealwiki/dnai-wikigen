---
source: https://tinker-docs.thinkingmachines.ai/api-reference/samplingclient
scraped: 2026-03-08
---

# SamplingClient

The `SamplingClient` is a client for text generation and inference from trained or base models.

```python
class SamplingClient(TelemetryProvider, QueueStateObserver)
```

Typically obtained via:
- `service_client.create_sampling_client()`
- `training_client.save_weights_and_get_sampling_client()`

## Methods

### `sample()`

```python
def sample(
        prompt: types.ModelInput,
        num_samples: int,
        sampling_params: types.SamplingParams,
        include_prompt_logprobs: bool = False,
        topk_prompt_logprobs: int = 0
) -> ConcurrentFuture[types.SampleResponse]
```

Generates text completions from the model.

**Parameters:**
- `prompt`: Input tokens as ModelInput
- `num_samples`: Number of independent samples to generate
- `sampling_params`: Generation parameters (temperature, max_tokens, etc.)
- `include_prompt_logprobs`: Whether to include log probabilities for prompt tokens
- `topk_prompt_logprobs`: Number of top token log probabilities per position

```python
prompt = types.ModelInput.from_ints(tokenizer.encode("The weather today is"))
params = types.SamplingParams(max_tokens=20, temperature=0.7)
future = sampling_client.sample(prompt=prompt, sampling_params=params, num_samples=1)
result = future.result()
for sample in result.samples:
    print(tokenizer.decode(sample.tokens))
```

### `compute_logprobs()`

```python
def compute_logprobs(
        prompt: types.ModelInput) -> ConcurrentFuture[list[float | None]]
```

Computes log probabilities for prompt tokens. None values indicate tokens where computation failed.

```python
prompt = types.ModelInput.from_ints(tokenizer.encode("Hello world"))
future = sampling_client.compute_logprobs(prompt)
logprobs = future.result()
for i, logprob in enumerate(logprobs):
    if logprob is not None:
        print(f"Token {i}: logprob = {logprob:.4f}")
```

### `get_tokenizer()`

```python
def get_tokenizer() -> PreTrainedTokenizer
```

Retrieves the tokenizer for the current model.

All methods have corresponding `_async` variants.
