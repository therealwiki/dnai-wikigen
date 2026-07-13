---
source: https://tinker-docs.thinkingmachines.ai/supervised-learning/prompt-distillation
scraped: 2026-03-08
---

# Prompt Distillation

A training technique in which a model is optimized to behave as though it had been provided with a long and complex prompt, without requiring access to that prompt during inference.

## Process

1. **Creation of distillation data**: A detailed teacher prompt generates responses using a teacher model across a set of queries
2. **Training the student model**: A student model learns from the distilled dataset to reproduce the teacher's behaviors

## Mathematical Framework

- Teacher model generates responses: ri = fT([P, qi])
- For a dataset of queries Q = {qi | 1 <= i <= D}, corresponding teacher responses R = {ri | 1 <= i <= D}
- The distillation training dataset excludes the original prompt: T = {(qi, ri) | 1 <= i <= D}
- Student model training minimizes cross-entropy loss between student predictions and teacher outputs

## Example Implementation

The Tinker Cookbook provides a language classification recipe where models predict two-character language codes from input text.

**Supported languages**: Arabic, German, Greek, English, Spanish, French, Hindi, Russian, Turkish, Urdu, Vietnamese, Simplified Chinese, and Other/Unknown.

### Step 1: Generate Training Data

```
python -m tinker_cookbook.recipes.prompt_distillation.create_data \
  output_file=/tmp/tinker-datasets/prompt_distillation_lang.jsonl
```

### Step 2: Train the Student Model

```
python -m tinker_cookbook.recipes.prompt_distillation.train
```

### Step 3: Test Your Model

After training, sample from the model to verify language classification performance.

## Advanced Configuration Options

- Teacher model selection based on specific requirements
- Sampling strategy adjustments (temperature and generation parameters)
- Data volume scaling based on needs
- Training hyperparameter customization (learning rates, etc.)
