---
source: https://tinker-docs.thinkingmachines.ai/losses
scraped: 2026-03-08
---

# Loss Functions

Tinker provides built-in loss functions accessible via the `forward_backward` method using string identifiers. For advanced use cases requiring custom logic, `forward_backward_custom` enables arbitrary differentiable loss functions with an additional forward pass.

## Basic Loss Functions

All losses operate at the token level on tensors with shape `(N,)`, accepting numpy arrays or torch tensors.

### Supervised Learning: `cross_entropy`

Implements standard negative log-likelihood optimization.

**Formula:** L(theta) = -E_x[log p_theta(x)]

**Implementation:**

```python
elementwise_loss = -target_logprobs * weights
loss = elementwise_loss.sum()
```

**Inputs:**
- `target_tokens: array[(N,), int]` -- Target token IDs
- `weights: array[(N,), float]` -- Token-level loss weights

**Outputs:**
- `logprobs: array[(N,), float]` -- Log probabilities of predicted tokens
- `loss:sum` (scalar) -- Sum of weighted cross-entropy losses

### Policy Gradient: `importance_sampling`

Addresses distribution mismatch between learner policy p_theta and sampling policy q.

**Formula:** L_IS(theta) = E_x~q[p_theta(x)/q(x) * A(x)]

**Implementation:**

```python
prob_ratio = torch.exp(target_logprobs - sampling_logprobs)
loss = -(prob_ratio * advantages).sum()
```

**Inputs:**
- `target_tokens: array[(N,), int]`
- `logprobs: array[(N,), float]` -- Sampling logprobs
- `advantages: array[(N,), float]` -- RL advantage values

**Outputs:**
- `logprobs: array[(N,), float]` -- Target logprobs
- `loss:sum` (scalar)

### Proximal Policy Optimization: `ppo`

Clips importance ratios to prevent excessive policy updates (Schulman et al., 2017).

**Implementation:**

```python
prob_ratio = torch.exp(target_logprobs - sampling_logprobs)
clipped_ratio = torch.clamp(prob_ratio, clip_low_threshold, clip_high_threshold)
unclipped_objective = prob_ratio * advantages
clipped_objective = clipped_ratio * advantages
ppo_objective = torch.min(unclipped_objective, clipped_objective)
loss = -ppo_objective.sum()
```

**Custom Configuration:**

```python
fwd_bwd_result = await training_client.forward_backward_async(
    data=data,
    loss_fn="ppo",
    loss_fn_config={"clip_low_threshold": 0.9, "clip_high_threshold": 1.1}
)
```

Default clipping thresholds are fixed at 0.2 in Tinker.

### Clipped Importance Sampling Policy Optimization: `cispo`

Uses clipped ratios as coefficients for policy gradient (Chen et al., 2024).

**Implementation:**

```python
prob_ratio = torch.exp(target_logprobs - sampling_logprobs)
clipped_ratio = torch.clamp(prob_ratio, clip_low_threshold, clip_high_threshold)
cispo_objective = clipped_ratio.detach() * target_logprobs * advantages
loss = -cispo_objective.sum()
```

**Custom Configuration:**

```python
fwd_bwd_result = await training_client.forward_backward_async(
    data=data,
    loss_fn="cispo",
    loss_fn_config={"clip_low_threshold": 0.8, "clip_high_threshold": 1.2}
)
```

### Direct Reward Optimization: `dro`

Off-policy/offline RL method with quadratic penalty constraint (Richemond et al., 2024).

**Implementation:**

```python
quadratic_term = (target_logprobs - sampling_logprobs) ** 2
dro_objective = target_logprobs * advantages - 0.5 * beta * quadratic_term
loss = -dro_objective.sum()
```

**Custom Configuration:**

```python
fwd_bwd_result = await training_client.forward_backward_async(
    data=data,
    loss_fn="dro",
    loss_fn_config={"beta": 0.05}
)
```

## Flexible Loss Functions: `forward_backward_custom`

For cases outside built-in options, use `forward_backward_custom` or `forward_backward_custom_async` for custom differentiable losses.

### Usage

**Basic Example:**

```python
def logprob_squared_loss(data: list[Datum], logprobs: list[torch.Tensor]) -> tuple[torch.Tensor, dict[str, float]]:
    loss = (logprobs ** 2).sum()
    return loss, {"logprob_squared_loss": loss.item()}

loss, metrics = training_client.forward_backward_custom(data, logprob_squared_loss)
```

**Multi-Sequence Example:**

```python
def variance_loss(data: list[Datum], logprobs: list[torch.Tensor]) -> tuple[torch.Tensor, dict[str, float]]:
    flat_logprobs = torch.cat(logprobs)
    variance = torch.var(flat_logprobs)
    return variance, {"variance_loss": variance.item()}
```

**Practical Applications:**
- Bradley-Terry loss for pairwise comparison data
- Direct Preference Optimization (DPO) -- see DPO guide

### How `forward_backward_custom` Works

The system decomposes gradient computation into a forward pass followed by a weighted cross-entropy loss computation, without transmitting user functions to the server.

**Process:**
1. Compute target logprobs via forward pass
2. Calculate gradients with respect to logprobs
3. Construct surrogate loss: `surrogate_loss = (logprobs * logprob_grads).sum()`

**Performance:** Requires 1.5x FLOPs and up to 3x wall-time compared to single `forward_backward` call.

## Example Usage

```python
import tinker
import torch
from tinker import TensorData

datum = tinker.Datum(
    model_input=input_tokens,
    loss_fn_inputs={
        "target_tokens": TensorData.from_torch(torch.tensor(target_tokens)),
        "logprobs": TensorData.from_torch(torch.tensor(sampling_logprobs)),
        "advantages": TensorData.from_torch(torch.tensor(advantages)),
    }
)

# Importance sampling REINFORCE
fwd_bwd_result = await training_client.forward_backward_async(
    [datum], loss_fn="importance_sampling"
)

# PPO with clipping
fwd_bwd_result = await training_client.forward_backward_async(
    [datum], loss_fn="ppo"
)
```
