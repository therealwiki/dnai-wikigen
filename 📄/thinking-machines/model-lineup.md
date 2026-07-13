---
source: https://tinker-docs.thinkingmachines.ai/model-lineup
scraped: 2026-03-08
---

# Model Lineup

## What model should I use?

- **Cost efficiency**: In general, use MoE models, which are more cost effective than the dense models.
- **Research**: Base models are suggested for those conducting research or implementing full post-training pipelines
- **Task-specific needs**: Fine-tune existing post-trained models on your data or environment
- **Latency concerns**: Instruction models output tokens without chain-of-thought reasoning
- **Intelligence priority**: Hybrid or Reasoning models support extended chain-of-thought processing

## Full Model Listing

**Qwen 3.5 Series** (Hybrid + Vision)
- 397B-A17B (MoE, Large)
- 35B-A3B (MoE, Medium)
- 27B (Dense, Medium)
- 4B (Dense, Compact)

**Qwen 3 Series** (various types)
- Vision models (VL-235B, VL-30B)
- Instruction models (235B, 30B)
- Hybrid models (30B-A3B)
- Base models (30B-A3B-Base, 8B-Base)
- Dense models (32B, 8B)

**Other Providers**
- OpenAI: gpt-oss-120b and gpt-oss-20b (Reasoning)
- DeepSeek: V3.1 variants (Hybrid/Base)
- Meta Llama: 3.1-70B, 3.3-70B-Instruct, 3.1-8B variants, 3.2-3B, 3.2-1B
- Moonshot: Kimi-K2-Thinking and Kimi-K2.5

## Legend

**Training Types:**
- Base, Instruction, Reasoning, Hybrid, Vision

**Architecture:**
- Dense (standard transformer) or MoE (Mixture of Experts with sparse activation)

**Sizes:**
- Compact (1B-4B), Small (8B), Medium (30B-32B), Large (70B+)

Note: MoE models are much more cost effective than the dense models because costs scale with active parameters rather than total parameters.
