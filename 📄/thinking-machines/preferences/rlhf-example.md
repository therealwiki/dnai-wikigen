---
source: https://tinker-docs.thinkingmachines.ai/preferences/rlhf-example
scraped: 2026-03-08
---

# RLHF Worked Example

A standard reinforcement learning from human feedback pipeline, with a reference implementation available as `rlhf_pipeline.py`.

## Three-Stage Training Process

### 1. Initial Policy Training via Supervised Learning

Trains a policy model using the no_robots dataset from Huggingface, which is a basic instruction following dataset with human-written answers, designed to match the methodology from InstructGPT.

### 2. Preference Model Training via Supervised Learning

Trains a preference model on the HHH dataset from Anthropic, which is a dataset of pairwise comparisons of completions. This model learns to evaluate pairs of completions and determine which is preferred.

### 3. Policy Refinement via Reinforcement Learning

The policy is trained via reinforcement learning. This RL is a form of self-play, where the preference model grades match-ups between the policy and itself. The process involves sampling multiple completions per prompt, evaluating all pairwise comparisons through the preference model, and rewarding the policy based on its win fraction.

## Running the Pipeline

```
python -m recipes.preference.rlhf.rlhf_pipeline
```
