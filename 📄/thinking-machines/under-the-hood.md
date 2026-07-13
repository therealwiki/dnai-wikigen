---
source: https://tinker-docs.thinkingmachines.ai/under-the-hood
scraped: 2026-03-08
---

# Under the Hood

Implementation details crucial for optimizing code performance.

## Clock Cycles

The platform assigns training jobs to a shared worker pool that operates in synchronized steps called "clock cycles." Within each cycle, the system performs forward-backward operations and optimizer steps, potentially handling multiple LoRA models simultaneously.

This multi-tenant architecture enables:
- High compute efficiency even with small batch sizes
- Improved sample efficiency through smaller batches
- Resource optimization across multiple users

However, there are tradeoffs: even if training with a small batch, you'll still see the same step time as a large batch.

## Request Overlapping Strategy

Rather than sequentially awaiting operations, submit `forward_backward` and `optim_step` requests together before waiting for results.

**Inefficient approach**: Submitting forward_backward, waiting for completion, then submitting optim_step uses approximately 3 clock cycles.

**Optimized approach**: Submitting both requests immediately allows them to execute within the same clock cycle, reducing overhead significantly.

## Pipelining for Maximum Efficiency

Submit subsequent batches before current batch completion finishes. This technique:
- Eliminates gaps between submissions
- Reduces wasted clock cycles
- Typically achieves 1 clock cycle per training step
- Ensures requests are queued when new cycles begin
