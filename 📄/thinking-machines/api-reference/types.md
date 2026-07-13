---
source: https://tinker-docs.thinkingmachines.ai/api-reference/types
scraped: 2026-03-08
---

# Parameters (Types)

## Optimizer Configuration

**AdamParams** -- Configures the Adam optimizer:
- `learning_rate`: Optimizer learning rate
- `beta1`, `beta2`: Gradient averaging coefficients
- `eps`: Numerical stability term
- `weight_decay`: Decoupled weight decay setting
- `grad_clip_norm`: Maximum gradient norm threshold (0.0 disables clipping)

## Model Information

- **SupportedModel** -- Model metadata
- **ModelData** -- Architecture, name, and tokenizer identification
- **GetInfoResponse** -- Training client model information including LoRA status

## Training & Checkpoints

**TrainingRun** -- Represents a training session:
- `training_run_id`: Unique identifier
- `base_model`: Source model name
- `is_lora`: LoRA adapter flag
- `last_checkpoint`, `last_sampler_checkpoint`: Most recent checkpoints
- `user_metadata`: Custom training metadata

**Checkpoint** -- Checkpoint metadata including ID, type, creation time, size, and expiration

**ParsedCheckpointTinkerPath** -- Parses tinker paths to extract training run and checkpoint information

## Input/Output Data

**ModelInput** -- Represents model inputs with chunking support:
- `from_ints()`: Create from token lists
- `to_ints()`: Convert to token arrays
- `append()`, `append_int()`: Add content
- `length()`: Get context length

**TensorData** -- Flattened tensor representation with shape metadata; includes `to_numpy()` and `to_torch()` conversion methods

**EncodedTextChunk** -- Token ID arrays

**ImageChunk** -- Image data in bytes with format specification

**ImageAssetPointerChunk** -- Image references with expected token counts

## Sampling

**SampleRequest** -- Sampling configuration:
- `num_samples`: Generation count
- `model_path`: Optional LoRA/weight path
- `prompt_logprobs`, `topk_prompt_logprobs`: Probability computation flags
- `sampling_session_id`: Multi-turn conversation support

**SamplingParams** -- Generation parameters (temperature, top-k, top-p, max tokens, seed, stop sequences)

**SampledSequence** -- Generated output with tokens, log probabilities, and stop reason

**CreateSamplingSessionRequest/Response** -- Multi-turn conversation session management

## Training Operations

- **ForwardBackwardInput** -- Training data with loss function specification
- **ForwardBackwardOutput** -- Training results containing loss outputs and metrics
- **OptimStepResponse** -- Optimization step metrics
- **Datum** -- Training data wrapper with tensor conversion support

## Weights Management

- **SaveWeightsRequest** -- Checkpoint saving with TTL specification
- **LoadWeightsRequest** -- Weight loading with optimizer state option
- **SaveWeightsForSamplerRequest/Response** -- Sampler-specific checkpoint operations

## LoRA Configuration

**LoraConfig** -- Low-rank adaptation settings:
- `rank`: Matrix dimension
- `seed`: Initialization seed
- `train_unembed`, `train_mlp`, `train_attn`: Layer-specific training flags

## Server & Telemetry

- **GetServerCapabilitiesResponse** -- Lists supported models
- **Cursor** -- Pagination information (offset, limit, total count)
- **TelemetrySendRequest**, **TelemetryBatch** -- SDK telemetry data
- **GenericEvent**, **SessionStartEvent**, **SessionEndEvent**, **UnhandledExceptionEvent** -- Telemetry event types
