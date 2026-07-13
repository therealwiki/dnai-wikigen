---
source: https://thinkingmachines.ai/blog/tinker-general-availability/
scraped: 2026-03-08
date: 2025-12-12
---

# Tinker: General Availability and Vision Input

**Thinking Machines Lab** | Dec 12, 2025

## Four Major Updates

### General Availability

The waitlist is over. Everybody can use Tinker now through signup at the authentication portal. The Tinker homepage displays available models and pricing information.

### Kimi K2 Thinking Model

Users can now fine-tune Kimi K2 Thinking, the largest model in the lineup so far with a trillion parameters, designed for extended reasoning chains and tool use.

### OpenAI API Compatibility

Tinker added OpenAI-compatible sampling interfaces allowing developers to specify model paths during training and integrate with OpenAI API-compatible platforms. The implementation enables quick model sampling without requiring custom infrastructure.

### Vision Model Support

Two Qwen3-VL models were added: the 30B and 235B parameter variants. These support image processing through interleaved ImageChunk and text data structures, enabling applications like classification and visual understanding tasks.

## Image Classifier Benchmarks

The team fine-tuned Qwen3-VL on four datasets (Caltech 101, Stanford Cars, Oxford Flowers, Oxford Pets) and compared results against DINOv2-base. The VLM demonstrated superior performance in limited-data scenarios, outperforming the vision-only baseline.
