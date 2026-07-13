---
source: https://tinker-docs.thinkingmachines.ai/rl/rl-basic
scraped: 2026-03-08
---

# Your First RL Run

A minimal script for running reinforcement learning on the GSM8K dataset:

```
python -m tinker_cookbook.recipes.rl_basic
```

## Training Details

Fine-tunes the Llama-3.1-8B base model using a reward function combining correctness scoring and format validation, with format weighted at 0.1x relative to correctness.

### Expected Performance

Training requires approximately one minute per iteration and should reach around 63% accuracy after 15 iterations, as measured by the `env/all/correct` metric.

## Key Metrics

- **`ac_tokens_per_turn`**: Token count per generated completion
- **`env/all/format`**: Fraction of correctly formatted completions
- **`env/all/reward/total`**: Mean combined reward score
- **`entropy`**: Per-token entropy measurement
- **`kl_sample_train_{v1,v2}`**: Two KL divergence approximations between sampler and learner distributions
- **`progress/done_frac`**: Training completion percentage
- **`time/...`**: Duration metrics for training loop components

The `log_path` directory contains detailed metrics comparable to those available in supervised learning documentation sections.
