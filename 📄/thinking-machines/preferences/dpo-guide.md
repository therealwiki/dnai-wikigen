---
source: https://tinker-docs.thinkingmachines.ai/preferences/dpo-guide
scraped: 2026-03-08
---

# Direct Preference Optimization (DPO)

DPO aligns language models with human preferences without requiring a separate reward model. It directly optimizes models to favor chosen responses over rejected alternatives through a classification loss approach.

## DPO Loss

L_theta = -E[log sigma(beta * log(pi_theta(y_chosen|x)/pi_ref(y_chosen|x)) - beta * log(pi_theta(y_rejected|x)/pi_ref(y_rejected|x)))]

Key components:
- pi_theta: the current policy being trained
- pi_ref: the reference model (initial model before optimization)
- beta: the DPO beta parameter controlling preference learning strength
- D: dataset containing prompts, chosen responses, and rejected responses

## Running DPO Training

```
python -m tinker_cookbook.recipes.preference.train \
    log_path=/tmp/dpo-hhh-experiment \
    model_name=meta-llama/Llama-3.2-1B \
    dataset=hhh \
    renderer_name=role_colon \
    learning_rate=1e-5 \
    dpo_beta=0.1
```

## Key Parameters

- **log_relpath**: Output directory for results and checkpoints
- **model_name**: Base model serving as initialization and reference policy
- **dataset**: Choice of `hhh`, `helpsteer3`, or `ultrafeedback`
- **renderer_name**: Conversation formatting style
- **learning_rate**: Optimization learning rate
- **dpo_beta**: Controls preference learning intensity

## Available Datasets

- **hhh**: Anthropic's Helpful-Harmless-Honest collection
- **helpsteer3**: NVIDIA's HelpSteer3 preference dataset
- **ultrafeedback**: UltraFeedback binarized preferences

Custom datasets can be implemented following the `DPODatasetBuilder` interface pattern.

## Training Metrics

- **dpo_loss**: Classification loss value
- **accuracy**: Implicit reward model performance on preference data
- **margin**: Average difference between chosen and rejected reward scores
- **chosen_reward/rejected_reward**: Mean rewards for each response category
- **num_tokens**: Total tokens processed in batch

## Evaluating DPO Models

```
MODEL_PATH=tinker://YOUR_MODEL_PATH_HERE
python -m tinker_cookbook.eval.run_inspect_evals \
    model_path=$MODEL_PATH \
    model_name=meta-llama/Llama-3.2-1B \
    tasks=inspect_evals/ifeval \
    renderer_name=role_colon
```

## Tips

1. **Beta Parameter**: Begin with `dpo_beta=0.1`, adjusting based on dataset characteristics
2. **Learning Rate**: Apply lower rates than supervised fine-tuning (typically 1e-5 to 1e-6)
3. **Base Model Selection**: Start with models already aligned with preference data distribution
