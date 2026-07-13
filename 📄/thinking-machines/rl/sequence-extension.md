---
source: https://tinker-docs.thinkingmachines.ai/rl/sequence-extension
scraped: 2026-03-08
---

# Sequence Extension Property in Multi-Turn RL

## What is the Extension Property?

The extension property occurs when each successive observation contains all previous observations and actions as a prefix. This enables efficient training through sequence merging and KV-cache reuse, achieving O(T) compute scaling rather than O(T^2) for trajectories of length T.

## Two Key Examples

1. **With Thinking Visible** (`strip_thinking_from_history=False`): Complete conversation history including `<think>` blocks remains at each timestep. Multiple timesteps can merge into a single training datum because each observation extends the previous one by appending new tokens.

2. **With Thinking Hidden** (`strip_thinking_from_history=True`): The `<think>` blocks are removed from previous messages. This breaks the extension property since the prefix no longer matches, requiring separate data objects and O(T^2) compute scaling.

## The Tradeoff

Keeping thinking visible provides computational efficiency and faster context growth but increases context length. Stripping thinking maintains smaller context but sacrifices efficiency gains.

## Implementation Details

The RL code in `data_processing.py` includes a `trajectory_to_data` function that automatically detects whether consecutive timesteps satisfy the extension property. Renderers can be checked via `renderer.has_extension_property`.

## Advanced: Periodic Compaction

A hybrid approach periodically strips old thinking blocks every N turns, balancing efficiency with bounded context size while limiting recomputation costs.

The recommendation depends on trajectory length and compute priorities, with periodic compaction offered as an optimal middle ground for long conversations with context constraints.
