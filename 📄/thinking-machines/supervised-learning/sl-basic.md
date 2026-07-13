---
source: https://tinker-docs.thinkingmachines.ai/supervised-learning/sl-basic
scraped: 2026-03-08
---

# Basic Supervised Learning

## Quick Start

The Tinker API provides a ready-to-run supervised learning example:

```
python -m tinker_cookbook.recipes.sl_basic
```

This fine-tunes Llama-3.1-8B on the NoRobots dataset from Hugging Face, a small instruction-following collection.

## Training Output

During execution, you'll observe:

- Training and test loss metrics printed at each step with timing information
- Visual representation of data, showing predicted tokens in green and context tokens in yellow
- Logs and checkpoint files written to `/tmp/tinker-examples/sl_basic`

## Output Files Reference

**metrics.jsonl** -- Training metrics you can visualize:

```python
import pandas
import matplotlib.pyplot as plt
df = pandas.read_json("/tmp/tinker-examples/sl_basic/metrics.jsonl", lines=True)
plt.plot(df['train_mean_nll'], label='train_loss')
plt.plot(df['test/nll'].dropna(), label='test_loss')
plt.legend()
plt.show()
```

**checkpoints.jsonl** -- Two checkpoint types: sampler weights (for generation) and full weights (for resuming training)

**config.json** -- Your training configuration settings

## Custom Datasets

The example includes disabled code demonstrating how to use custom JSONL datasets formatted like the provided conversations.jsonl file.
