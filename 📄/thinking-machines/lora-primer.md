---
source: https://tinker-docs.thinkingmachines.ai/lora-primer
scraped: 2026-03-08
---

# LoRA Primer

Tinker supports LoRA fine-tuning, which adjusts a small number of parameters rather than performing full fine-tuning on all model parameters.

## Performance Characteristics

- **Small-to-medium datasets**: LoRA performs the same as full fine-tuning for supervised instruction-tuning and reasoning tasks
- **Large datasets**: LoRA underperforms full fine-tuning with reduced training efficiency
- **Batch size sensitivity**: LoRA may be less tolerant of large batch sizes than full fine-tuning
- **Layer coverage**: LoRA works best when applied to all weight matrices, including MLP and MoE layers
- **Reinforcement learning**: LoRA performs equivalently to full fine-tuning even with small ranks

## Hyperparameters

**Learning Rate**: The most critical hyperparameter. LoRA requires a much larger LR than full fine-tuning -- typically 20-100x larger, depending on model size.

```python
from tinker_cookbook.hyperparam_utils import get_lora_lr_over_full_finetune_lr

model_name = "meta-llama/Llama-3.1-8B"
print(get_lora_lr_over_full_finetune_lr(model_name))
```

Examples: Llama-3.2-1B requires a 32x factor; Llama-3.1-70B requires 128x.

## What is LoRA?

LoRA (Low-Rank Adaptation) replaces a weight matrix W with W' = W + BA, where B and A are low-rank matrices with rank r. The default rank is 32. LoRA is a random projection of the parameter space that happens to be efficient to implement.

## Rank Selection

- **Default rank**: 32
- **For large supervised learning datasets**: Use larger ranks where the number of LoRA parameters is at least as large as the number of completion tokens

```python
from tinker_cookbook.hyperparam_utils import get_lora_param_count

model_name = "meta-llama/Llama-3.1-8B"
print(get_lora_param_count(model_name, lora_rank=32))
```

- **For reinforcement learning**: Small ranks provide equivalent performance to larger ranks and full fine-tuning

The optimal learning rate does not depend on LoRA rank.
