---
source: https://tinker-docs.thinkingmachines.ai/evals
scraped: 2026-03-08
---

# Evaluations

## Inline Evaluations

### Supervised Fine-Tuning

For `supervised.train`, configure:

- **`evaluator_builders`**: Runs evaluations every `eval_every` steps
- **`infrequent_evaluator_builders`**: Runs evaluations every `infrequent_eval_every` steps

### RL Training

For `rl.train`, add:

- **`evaluator_builders`**: Runs evaluations every `eval_every` steps

## Offline Evaluations

### Inspect AI Integration

Standard evaluations via the Inspect AI library:

```
MODEL_PATH=tinker://FIXME # YOUR MODEL PATH HERE
python -m tinker_cookbook.eval.run_inspect_evals \
    model_path=$MODEL_PATH \
    model_name=MODEL_NAME \
    tasks=inspect_evals/ifeval,inspect_evals/mmlu_0_shot \
    renderer_name=RENDERER_NAME
```

### Custom Sampling Evaluations

Two primary approaches:

1. **Inspect AI Tasks**: Create custom tasks using Inspect AI's framework with custom LLM-as-judge scoring
2. **SamplingClientEvaluator**: Lower-level abstraction providing finer-grain control over running your evaluations

Both approaches include QA datasets, grading functions, and async evaluation patterns.
