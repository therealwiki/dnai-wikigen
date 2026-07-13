---
source: https://tinker-docs.thinkingmachines.ai/api-reference/trainingclient
scraped: 2026-03-08
---

# TrainingClient

The `TrainingClient` is a class for training ML models with forward/backward passes and optimization. It corresponds to a fine-tuned model you can train and sample from, typically obtained via `service_client.create_lora_training_client()`.

```python
class TrainingClient(TelemetryProvider, QueueStateObserver)
```

## Forward Pass Methods

### `forward()`

```python
def forward(
    data: List[types.Datum],
    loss_fn: types.LossFnType,
    loss_fn_config: Dict[str, float] | None = None
) -> APIFuture[types.ForwardBackwardOutput]
```

Compute forward pass without gradients.

### `forward_backward()`

```python
def forward_backward(
    data: List[types.Datum],
    loss_fn: types.LossFnType,
    loss_fn_config: Dict[str, float] | None = None
) -> APIFuture[types.ForwardBackwardOutput]
```

Compute forward pass and backward pass to calculate gradients.

### `forward_backward_custom()`

```python
def forward_backward_custom(
    data: List[types.Datum],
    loss_fn: CustomLossFnV1
) -> APIFuture[types.ForwardBackwardOutput]
```

Compute forward/backward with a custom loss function that operates on log probabilities.

## Optimization Methods

### `optim_step()`

```python
def optim_step(
    adam_params: types.AdamParams
) -> APIFuture[types.OptimStepResponse]
```

Update model parameters using Adam optimizer. The implementation matches `torch.optim.AdamW` with a default weight decay of 0.0.

## State Management Methods

### `save_state()`

```python
def save_state(
    name: str,
    ttl_seconds: int | None = None
) -> APIFuture[types.SaveWeightsResponse]
```

Save model weights to persistent storage.

### `load_state()`

```python
def load_state(path: str) -> APIFuture[types.LoadWeightsResponse]
```

Load model weights only (optimizer state is not restored).

### `load_state_with_optimizer()`

```python
def load_state_with_optimizer(path: str) -> APIFuture[types.LoadWeightsResponse]
```

Load model weights and optimizer state from a checkpoint.

## Sampling-Related Methods

### `save_weights_for_sampler()`

```python
def save_weights_for_sampler(
    name: str,
    ttl_seconds: int | None = None
) -> APIFuture[types.SaveWeightsForSamplerResponse]
```

Save model weights for use with a SamplingClient.

### `save_weights_and_get_sampling_client()`

```python
def save_weights_and_get_sampling_client(
    name: str | None = None,
    retry_config: RetryConfig | None = None
) -> SamplingClient
```

Save current weights and immediately create a SamplingClient for inference.

## Information Methods

### `get_info()`

```python
def get_info() -> types.GetInfoResponse
```

Retrieve model configuration and metadata.

### `get_tokenizer()`

```python
def get_tokenizer() -> PreTrainedTokenizer
```

Get the tokenizer compatible with the current model.

## Usage Example

```python
training_client = service_client.create_lora_training_client(
    base_model="Qwen/Qwen3-8B"
)

fwdbwd_future = training_client.forward_backward(training_data, "cross_entropy")
optim_future = training_client.optim_step(types.AdamParams(learning_rate=1e-4))

fwdbwd_result = fwdbwd_future.result()
optim_result = optim_future.result()

sampling_client = training_client.save_weights_and_get_sampling_client("my-model")
```

All methods have corresponding `_async` variants.
