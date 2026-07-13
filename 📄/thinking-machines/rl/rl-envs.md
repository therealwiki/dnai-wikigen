---
source: https://tinker-docs.thinkingmachines.ai/rl/rl-envs
scraped: 2026-03-08
---

# RL Environments

How to create and implement custom RL environments for the Tinker API framework.

## Core Classes

Three primary classes from `tinker_cookbook.rl.types`:

### Env Interface

The foundational class requires implementing two async methods:

- `initial_observation()` -- returns an Observation and StopCondition tuple
- `step(action: Action)` -- processes an action and returns a StepResult

Key design decision: this `Env` operates on _tokens_, rather than strings or messages, to align with training code requirements for exact token sampling and logprob tracking.

### EnvGroupBuilder

Instantiates groups of environments via `make_envs()`, enabling multi-agent training or objectives comparing multiple samples.

### RLDataset

Provides batches of EnvGroupBuilders through `get_batch(index: int)`, creating a modular data loading architecture separate from environment logic.

## Practical Example

The "Twenty Questions" example implementation:

- A question-asking agent interacts with a fixed answerer (Llama-3.1-8B-Instruct)
- The player model undergoes fine-tuning during training
- Run training via: `python -m tinker_cookbook.recipes.twenty_questions.train`

## Design Philosophy

This three-class structure offers modularity and control compared to traditional frameworks like OpenAI Gym, where datasets are typically embedded within environments.
