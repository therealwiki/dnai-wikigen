---
source: https://tinker-docs.thinkingmachines.ai/supervised-learning/sl-hyperparams
scraped: 2026-03-08
---

# Supervised Learning Hyperparameters

Starting recommendations for the most important hyperparameters, rather than exhaustive sweeps.

## Learning Rate

The most important hyperparameter. Recommended formula:

**LR(m) = lr_base * M_LoRA * (2000/H_m)^P_m**

Where:
- **lr_base** = 5e-5 (constant base learning rate)
- **M_LoRA** = 10 (multiplier for LoRA; 1 for full fine-tuning)
- **H_m** = model hidden size
- **P_m** = model-specific exponent (0.0775 for Qwen; 0.781 for Llama)

This function is independent of the LoRA rank.

### Getting the Recommended Learning Rate

```python
from tinker_cookbook.hyperparam_utils import get_lr
model_name = "meta-llama/Llama-3.2-1B"
recommended_lr = get_lr(model_name)
print(f"Recommended LR: {recommended_lr}")
```

### Validation Results

The formula achieved less than 0.5% regret compared to exhaustive hyperparameter sweeps across diverse experiments with varying datasets, sizes, batch sizes, and LoRA ranks.

## Batch Size

The second-most important hyperparameter.

- **Smaller batch sizes** (around 128) are recommended for fine-tuning, despite longer training duration
- **Minimum training steps**: At least 100 steps recommended; 1000+ steps typically yields better results
- The scaling relationship LR proportional to sqrt(B) doesn't always hold during LLM fine-tuning

**Note**: Batch size recommendations are preliminary findings and ongoing research with low confidence.
