---
source: https://tinker-docs.thinkingmachines.ai/save-load
scraped: 2026-03-08
---

# Saving and Loading Weights and Optimizer State

## Overview

The Tinker API provides checkpoint management through the `TrainingClient` for two primary use cases: model sampling and training resumption. Three key methods:

1. **`save_weights_for_sampler()`** -- saves a copy of the model weights that can be used for sampling
2. **`save_state()`** -- saves the weights and the optimizer state
3. **`load_state()`** -- load the weights and the optimizer state

Both save functions require a `name` parameter to identify checkpoints and return a `path` field containing a fully-qualified path like `tinker://<model_id>/<name>`.

## Sampling Setup

```python
# Setup
import tinker
service_client = tinker.ServiceClient()
training_client = service_client.create_lora_training_client(
    base_model="meta-llama/Llama-3.2-1B", rank=32
)

# Save a checkpoint that you can use for sampling
sampling_path = training_client.save_weights_for_sampler(name="0000").result().path

# Create a sampling client with that checkpoint
sampling_client = service_client.create_sampling_client(model_path=sampling_path)
```

**Shortcut:** Combine these steps with: `sampling_client = training_client.save_weights_and_get_sampling_client(name="0000")`

## Training Resumption

```python
# Save a checkpoint that you can resume from
resume_path = training_client.save_state(name="0010").result().path

# Load that checkpoint
training_client.load_state(resume_path)
```

## When to Use `save_state()` and `load_state()`

- Multi-step training pipelines (supervised learning followed by reinforcement learning)
- Adjusting hyperparameters or data mid-run
- Recovery from interruptions or failures
- Scenarios requiring preservation of exact optimizer state
