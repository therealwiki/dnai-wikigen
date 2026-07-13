---
source: https://tinker-docs.thinkingmachines.ai/supervised-learning/sweep-case-study
scraped: 2026-03-08
---

# Sweep Case Study

Demonstrates how to conduct a hyperparameter sweep for learning rate optimization in supervised learning tasks.

## Why Sweep the Learning Rate?

Learning rate is typically the most impactful hyperparameter. While default recommendations achieve good results (under 0.5% regret), task-specific optimization can yield further improvements.

## Setup

The guide uses a supervised learning training loop to train a Llama-3.1-8B model. The default learning rate:

```python
from tinker_cookbook.hyperparam_utils import get_lr
print(get_lr("meta-llama/Llama-3.1-8B"))
# Outputs approximately 2.8e-4
```

The recommended sweep range extends one order of magnitude above and below: `[1e-5, 3e-5, 1e-4, 3e-4, 1e-3, 3e-3]`

## Running Experiments

Multiple experiments launch in parallel using separate terminal windows with varying learning rate parameters and logging paths.

## Results Collection

Read `metrics.jsonl` files from completed experiments, extracting learning rate values and final loss metrics.

## Visualization

A matplotlib script plots final loss against learning rate on a logarithmic scale, producing a U-shaped curve.

## Optimal Learning Rate Determination

The optimal value minimizes loss. In this example, `3e-4` emerged as optimal, closely matching the default `2.8e-4`.

## Next Steps

- Retrain with optimal parameters
- Sweep additional hyperparameters
- Use results as baselines for similar future tasks
