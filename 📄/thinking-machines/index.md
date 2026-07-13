---
source: https://tinker-docs.thinkingmachines.ai/
scraped: 2026-03-08
---

# What is Tinker?

> Tinker lets you focus on what matters in LLM fine-tuning -- your data and algorithms -- while we handle the heavy lifting of distributed training.

The platform enables users to develop training scripts on CPU-only machines while the service manages GPU distribution. Users can switch models by changing a single configuration string.

## Design Philosophy

> Tinker gives you full control over the training loop and all the algorithmic details. It's not a magic black box that makes fine-tuning "easy". It's a clean abstraction that shields you from the complexity of distributed training while preserving your control.

## Responsibility Division

| Focus Area | User Responsibility | Platform Responsibility |
|---|---|---|
| Data and Environments | Custom training datasets | Distributed GPU training at scale |
| Training Implementation | Loss functions, training loops, evaluations | Hardware reliability & failure handling |
| Development Process | Python scripts (CPU-based) | Llama 70B, Qwen 235B support |

## Key API Functions

- `forward_backward`: Compute and accumulate gradients from data and loss functions
- `optim_step`: Update model weights using accumulated gradients
- `sample`: Generate outputs from trained models
- Additional functions for weights and optimizer state management

## Features

**Currently Supported:**
- Fine-tuning of open-weight models including Qwen and Llama series
- Large mixture-of-experts models like Qwen3-235B-A22B
- Vision-language models (VLMs) such as Qwen3-VL for image understanding
- LoRA (low-rank adaptation) fine-tuning implementation
- Model weight download capability for external inference services

**Notable Implementation Details:**
LoRA fine-tuning is the current standard. The platform references research suggesting "LoRA gives the same performance as full fine-tuning for many important use cases, especially in RL" (citing "LoRA Without Regret").

**Planned Future Features:**
- Full fine-tuning support
