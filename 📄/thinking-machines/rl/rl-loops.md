---
source: https://tinker-docs.thinkingmachines.ai/rl/rl-loops
scraped: 2026-03-08
---

# RL Training Loop

A self-contained RL training loop available in `rl_loop.py`, designed for those who prefer writing custom training loops or understanding underlying mechanisms. An optimized version exists in `rl/train.py` with performance enhancements and additional features like periodic evaluations.

## Running the Training Loop

```
python -m tinker_cookbook.recipes.rl_loop
```

Default configuration outputs results to `/tmp/tinker-examples/rl-loop`. Training completes after 57 steps.

## Visualization

```python
import pandas
import matplotlib.pyplot as plt

metrics_path = "/tmp/tinker-examples/rl-loop/metrics.jsonl"
df = pandas.read_json(metrics_path, lines=True)
plt.plot(df["reward/total"], label="reward/total")
plt.legend()
plt.show()
```
