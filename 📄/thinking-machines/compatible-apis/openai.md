---
source: https://tinker-docs.thinkingmachines.ai/compatible-apis/openai
scraped: 2026-03-08
---

# OpenAI API Compatible Inference (beta)

## Overview

The Tinker API provides OpenAI-compatible inference capabilities (currently in beta) that allow users to interact with model checkpoints using an endpoint compatible with the OpenAI Completions API.

## Use Cases

- Fast feedback while training from sampler checkpoints
- Sampling capability while training continues on an experiment
- Developer and internal workflow testing and evaluation

**Important Limitations:** The service is designed for testing and internal use with low traffic. It is not suitable for large-scale, high-throughput user-facing deployments. Latency and throughput may vary by model and may change without notice during the beta.

## Implementation Steps

1. Set the base URL to: `https://tinker.thinkingmachines.dev/services/tinker-prod/oai/api/v1`
2. Use a Tinker sampler weight path as the model name
3. Authenticate using your Tinker API key

**Supported Endpoints:** Both `/completions` and `/chat/completions` endpoints are available. Chat requests use the model's default Hugging Face chat template.

## Code Example

```python
from os import getenv
from openai import OpenAI

BASE_URL = "https://tinker.thinkingmachines.dev/services/tinker-prod/oai/api/v1"
MODEL_PATH = "tinker://0034d8c9-0a88-52a9-b2b7-bce7cb1e6fef:train:0/sampler_weights/000080"

api_key = getenv("TINKER_API_KEY")

client = OpenAI(
    base_url=BASE_URL,
    api_key=api_key,
)

response = client.completions.create(
    model=MODEL_PATH,
    prompt="The capital of France is",
    max_tokens=50,
    temperature=0.7,
    top_p=0.9,
)

print(f"{response.choices[0].text}")
```
