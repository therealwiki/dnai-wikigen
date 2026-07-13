---
source: https://tinker-docs.thinkingmachines.ai/completers
scraped: 2026-03-08
---

# Completers

Policies are crucial to the RL training process and are implemented as `Completers`. These are abstractions representing models or policies that can be sampled from with varying levels of structure.

## Completer Types

### TokenCompleter

Foundational interface operating at the token level for RL algorithms:

```python
async def __call__(
    self, model_input: types.ModelInput, stop: StopCondition
) -> TokensWithLogprobs
```

Accepts model input and stop conditions, returning a `TokensWithLogprobs` object containing tokens and optional log probabilities. This is the interface used during RL training since the algorithms work directly with tokens.

### MessageCompleter

Higher abstraction level working with structured messages:

```python
async def __call__(self, messages: list[renderers.Message]) -> renderers.Message
```

Takes a message list and returns an assistant message response, similar to standard chat APIs.

## Implementation

Concrete implementations -- `TinkerTokenCompleter` and `TinkerMessageCompleter` -- wrap a `tinker.SamplingClient`. The `TinkerMessageCompleter` requires instantiation with a renderer for compatibility with the sampling client's expected inputs.
