---
source: https://tinker-docs.thinkingmachines.ai/supervised-learning/sl-loop
scraped: 2026-03-08
---

# SL Training Loop

A simplified SL training loop implementation found in `sl_loop.py`. This is for people who like to write their own training loops or learn about how things work under the hood.

Two training implementations:

1. **sl_loop.py** -- A simplified version that avoids dataset classes and uses self-contained data loading
2. **supervised/train.py** -- A more optimized implementation with performance enhancements and additional functionality like periodic evaluations

Both implementations accomplish similar core functionality, with the latter adding performance optimizations and extra features.
