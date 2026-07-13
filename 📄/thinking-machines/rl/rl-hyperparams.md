---
source: https://tinker-docs.thinkingmachines.ai/rl/rl-hyperparams
scraped: 2026-03-08
---

# RL Hyperparameters

## Learning Rate

The most important hyperparameter. See the supervised learning guidance as a foundation for RL experiments.

## Batch and Group Sizes

- **`batch_size`**: The number of unique environments or problems used for training
- **`group_size`**: The number of rollouts performed per unique environment

When training environments are scarce, increasing `group_size` generates additional training data. Scale learning rates according to: LR proportional to sqrt(batch_size).

## Multiple Updates per Sampling Iteration

The `num_substeps` parameter determines how many policy updates occur on sampled data from the current policy iteration.

### How It Works

- **`num_substeps = 1`** (default): Each trajectory batch receives one optimizer update
- **`num_substeps > 1`**: The batch divides into mini-batches, with each environment's rollouts grouped together for a single update step

### Usage Guidelines

- Batch size must divide evenly by `num_substeps`
- Starting values of 2-4 are recommended for experimentation with the PPO objective
- Higher values risk out-of-distribution policy updates; learning rate reduction may be necessary

## Advanced Training Configurations

These experimental features carry potential instabilities and remain disabled by default.

### Streaming Minibatch Training

Overlaps sampling and training phases to enhance throughput by submitting training requests incrementally rather than awaiting all sampling completion.

**Parameters:**
- **`groups_per_batch`**: Equivalent to batch size
- **`num_minibatches`**: Controls workload distribution across forward-backward requests

This remains on-policy training focused on pipeline efficiency.

### Async Off-Policy Training

Trains on trajectories from slightly older model versions, enabling higher throughput with some off-policy drift.

**Parameters:**
- **`max_steps_off_policy`**: Maximum age (in training steps) of trajectories before they're discarded
- **`groups_per_batch`**: New trajectory groups accumulated before model updates

**Guidelines:**
- Suited for long, heterogeneous rollouts like extended chain-of-thought, multi-step tool use, or agentic systems
- Begin with `max_steps_off_policy` values below 5

## Monitoring and Run Health

### KL Divergence Monitoring

The system logs KL divergence between the sampling and learning policies using two estimators: `kl_sample_train_v1` and `kl_sample_train_v2`.

- Even with full on-policy training, the divergence will not be exactly zero due to implementation specifics
- Stable training typically occurs when KL divergence remains below 0.01
- Values exceeding recommended thresholds suggest numerical instability or training issues
