---
source: https://tinker-docs.thinkingmachines.ai/api-reference/serviceclient
scraped: 2026-03-08
---

# ServiceClient

The `ServiceClient` serves as the primary entry point for the Tinker API. It enables developers to query server capabilities, instantiate training clients for model fine-tuning workflows, create sampling clients for text generation, and generate REST clients for API operations.

## ServiceClient Objects

```python
class ServiceClient(TelemetryProvider)
```

**Constructor Arguments:**
- `**kwargs`: Advanced options for the underlying HTTP client, including API keys, headers, and connection settings

**Basic Usage:**

```python
client = ServiceClient()
training_client = client.create_lora_training_client(base_model="Qwen/Qwen3-8B")
sampling_client = client.create_sampling_client(base_model="Qwen/Qwen3-8B")
rest_client = client.create_rest_client()
```

## Methods

### get_server_capabilities

```python
def get_server_capabilities() -> types.GetServerCapabilitiesResponse
```

Queries the server's supported features and capabilities.

```python
capabilities = service_client.get_server_capabilities()
print(f"Supported models: {capabilities.supported_models}")
print(f"Max batch size: {capabilities.max_batch_size}")
```

### create_lora_training_client

```python
def create_lora_training_client(
        base_model: str,
        rank: int = 32,
        seed: int | None = None,
        train_mlp: bool = True,
        train_attn: bool = True,
        train_unembed: bool = True,
        user_metadata: dict[str, str] | None = None) -> TrainingClient
```

Creates a TrainingClient configured for LoRA fine-tuning.

**Parameters:**
- `base_model`: Name of the base model to fine-tune (e.g., "Qwen/Qwen3-8B")
- `rank`: LoRA rank controlling the size of adaptation matrices (default: 32)
- `seed`: Random seed for initialization (None means random seed)
- `train_mlp`: Whether to train MLP layers (default: True)
- `train_attn`: Whether to train attention layers (default: True)
- `train_unembed`: Whether to train unembedding layers (default: True)
- `user_metadata`: Optional metadata to attach to the training run

```python
training_client = service_client.create_lora_training_client(
    base_model="Qwen/Qwen3-8B",
    rank=16,
    train_mlp=True,
    train_attn=True
)
```

### create_training_client_from_state

```python
def create_training_client_from_state(
        path: str,
        user_metadata: dict[str, str] | None = None) -> TrainingClient
```

Creates a TrainingClient from saved model weights (weights only, optimizer state is not restored).

### create_training_client_from_state_with_optimizer

```python
def create_training_client_from_state_with_optimizer(
        path: str,
        user_metadata: dict[str, str] | None = None) -> TrainingClient
```

Creates a TrainingClient from saved model weights and optimizer state (e.g., Adam momentum).

### create_sampling_client

```python
def create_sampling_client(
        model_path: str | None = None,
        base_model: str | None = None,
        retry_config: RetryConfig | None = None) -> SamplingClient
```

Creates a SamplingClient for text generation and inference.

**Parameters:**
- `model_path`: Path to saved model weights (e.g., "tinker://run-id/weights/checkpoint-001")
- `base_model`: Name of base model to use (e.g., "Qwen/Qwen3-8B")
- `retry_config`: Optional configuration for retrying failed requests

**Raises:** `ValueError` if neither `model_path` nor `base_model` is provided

```python
# Using a base model
sampling_client = service_client.create_sampling_client(
    base_model="Qwen/Qwen3-8B"
)

# Using saved weights
sampling_client = service_client.create_sampling_client(
    model_path="tinker://run-id/weights/checkpoint-001"
)
```

### create_rest_client

```python
def create_rest_client() -> RestClient
```

Creates a RestClient for REST API operations including querying model information, checkpoints, sessions, and managing checkpoint visibility.

```python
rest_client = service_client.create_rest_client()
checkpoints = rest_client.list_checkpoints("run-id").result()
training_run = rest_client.get_training_run("run-id").result()
rest_client.publish_checkpoint_from_tinker_path(
    "tinker://run-id/weights/checkpoint-001"
).result()
```

All methods have corresponding `_async` variants.
