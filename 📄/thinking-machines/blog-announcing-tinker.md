---
source: https://thinkingmachines.ai/blog/announcing-tinker/
scraped: 2026-03-08
date: 2025-10-01
---

# Announcing Tinker

**Thinking Machines Lab** | October 1, 2025

Thinking Machines Lab has launched **Tinker**, a flexible API for fine-tuning language models that enables researchers to experiment with model customization while the platform handles distributed training infrastructure.

## Key Features

The platform supports fine-tuning various open-weight models, including large mixture-of-experts models like Qwen-235B-A22B. Users can switch between model sizes by changing a single parameter in Python code.

Tinker operates as a managed service handling scheduling, resource allocation, and failure recovery. The system employs LoRA technology to share compute resources across multiple training runs, reducing costs.

## Technical Capabilities

The API provides low-level primitives such as `forward_backward` and `sample` for implementing post-training methods. To assist users in achieving quality results, the team released an accompanying open-source library called the Tinker Cookbook with implementations of modern post-training techniques.

## Early Adoption

Research groups at Princeton, Stanford, Berkeley, and Redwood Research have already utilized Tinker for various applications -- ranging from mathematical theorem provers to chemistry reasoning tasks and reinforcement learning experiments.

## Availability & Pricing

Tinker is currently in private beta with a waitlist for researchers and developers. The service will launch free initially, with usage-based pricing coming in the following weeks.
