---
source: https://tinker-docs.thinkingmachines.ai/docs-outline
scraped: 2026-03-08
---

# Navigating these docs

The Tinker API documentation is organized into two main sections:

## Using the Tinker API

This section covers foundational concepts:

- **Installation** -- Setup instructions for `tinker` and `tinker-cookbook` packages, plus API key retrieval from the Tinker Console
- **Training and Sampling** -- Guidance on preparing training data, executing training runs, and testing model outputs
- **Loss Functions** -- Coverage of built-in loss functions and custom differentiable loss options
- **Saving and Loading** -- Information about checkpoint types and resuming from checkpoints
- **Async and Futures** -- Explanation of synchronous and asynchronous API variants and request structures
- **Model Lineup** -- Updated listing of available models for fine-tuning

## The Tinker Cookbook

This section provides practical recipes for research and applications:

- **Rendering** -- Converting conversation data structures to token lists
- **Supervised Learning** -- Basic SL workflows, training loops, hyperparameter selection, and prompt distillation
- **Reinforcement Learning** -- RL fundamentals, custom environments, training loops, and hyperparameter guidance
- **Preferences** -- Learning from pairwise feedback using DPO and RLHF approaches
- **Evaluations** -- Running inline and offline evaluations
- **Completers** -- Policy implementation and training examples
- **LoRA Primer** -- Background on LoRA and hyperparameter selection

The documentation also includes API reference materials for ServiceClient, TrainingClient, SamplingClient, RestClient, APIFuture, Parameters, and Exceptions, plus OpenAI-compatible API information.
