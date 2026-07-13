---
source: https://tinker-docs.thinkingmachines.ai/training-sampling
scraped: 2026-03-08
---

# Training and Sampling

## Creating the Training Client

Users must first set the `TINKER_API_KEY` environment variable. The process involves:

1. Creating a `ServiceClient` to discover available base models
2. Retrieving supported models via `get_server_capabilities()`

Available models include options from Qwen3, Qwen3-VL, and Llama3 series.

Creating the training client:

```python
training_client = service_client.create_lora_training_client(
    base_model=base_model
)
```

## Preparing Training Data

Training examples follow a simple format. Examples are converted to the Tinker format using:

- Tokenizer encoding of prompts and completions
- Weight assignment (0 for prompts, 1 for completions)
- Token shifting for next-token prediction
- `types.Datum` objects containing model inputs and loss function inputs

## Vision Inputs

The `ModelInput` type accepts mixed content chunks:

- `EncodedTextChunk` for tokenized text
- `ImageChunk` for image data

Example structure:

```python
model_input = tinker.ModelInput(chunks=[
    types.EncodedTextChunk(tokens=...),
    types.ImageChunk(data=image_data, format="png"),
    types.EncodedTextChunk(tokens=...),
])
```

Special tokens like `<|vision_start|>` and `<|vision_end|>` are required for Qwen3-VL models.

## Performing Training Updates

Training involves forward-backward passes and optimizer steps:

```python
fwdbwd_future = training_client.forward_backward(
    processed_examples, "cross_entropy"
)
optim_future = training_client.optim_step(
    types.AdamParams(learning_rate=1e-4)
)
```

Both operations return futures that must be resolved with `.result()`. Loss computation uses weighted average logprobs across tokens.

## Sampling from the Model

After training, weights are saved and a sampling client is created:

```python
sampling_client = training_client.save_weights_and_get_sampling_client(
    name='pig-latin-model'
)
```

Sampling uses:

```python
params = types.SamplingParams(
    max_tokens=20, temperature=0.0, stop=["\n"]
)
future = sampling_client.sample(
    prompt=prompt, sampling_params=params, num_samples=8
)
```

## Computing Logprobs

Two approaches exist for logprob computation:

**Prompt logprobs** via sampling with `include_prompt_logprobs=True` returns logprobs for each token in the prompt.

**Top-k logprobs** with `topk_prompt_logprobs=5` returns lists of `(token_id, logprob)` pairs for the most likely tokens at each position.

Helper function:

```python
sampling_client.compute_logprobs(prompt).result()
```

## Related Resources

- [Rendering](/rendering) -- Template handling and special tokens
- [Supervised Fine-tuning](/supervised-learning) -- Best practices for LLM training
- [Model Lineup](/model-lineup) -- Complete list of supported models
