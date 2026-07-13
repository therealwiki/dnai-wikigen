---
source: https://tinker-docs.thinkingmachines.ai/rendering
scraped: 2026-03-08
---

# Rendering to Tokens

## The Renderer Class

The Renderer class serves as the primary interface for rendering, located in `tinker_cookbook/renderers/`. It converts message lists into token representations for both training and inference workflows.

### Example Conversation

```python
messages = [
    {'role': 'system', 'content': 'Answer concisely; at most one sentence per response'},
    {'role': 'user', 'content': 'What is the longest-lived rodent species?'},
    {'role': 'assistant', 'content': 'The naked mole rat, which can live over 30 years.'},
    {'role': 'user', 'content': 'How do they live so long?'},
    {'role': 'assistant', 'content': 'They evolved multiple protective mechanisms including special hyaluronic acid that prevents cancer, extremely stable proteins, and efficient DNA repair systems that work together to prevent aging.'}
]
```

## Inference: Generating Messages

Three key methods for message-to-message sampling:

- `build_generation_prompt` -- Converts a conversation into a prompt for sampling
- `get_stop_sequences` -- Returns token sequences that signal completion
- `parse_response` -- Converts sampled tokens back into structured messages

### Generate an Alternative Response

```python
from tinker_cookbook import renderers, tokenizer_utils

tokenizer = tokenizer_utils.get_tokenizer('Qwen/Qwen3-30B-A3B')
renderer = renderers.get_renderer('qwen3', tokenizer)
prompt = renderer.build_generation_prompt(messages[:-1])
```

### Sampling and Parsing

```python
import tinker
from tinker.types import SamplingParams

service_client = tinker.ServiceClient()
sampling_client = service_client.create_sampling_client(base_model='Qwen/Qwen3-30B-A3B')
stop_sequences = renderer.get_stop_sequences()
sampling_params = SamplingParams(max_tokens=100, temperature=0.5, stop=stop_sequences)
output = sampling_client.sample(prompt, sampling_params=sampling_params, num_samples=1).result()
sampled_message, parse_success = renderer.parse_response(output.sequences[0].tokens)
```

The stop sequence for Qwen models is `151645`, representing the `<|im_end|>` token.

## Training: Supervised Learning

For supervised learning and preference-based methods like DPO, the renderer distinguishes between prompt tokens (context, weight=0) and completion tokens (learning target, weight=1).

```python
model_input, weights = renderer.build_supervised_example(messages)

from tinker_cookbook.utils.format_colorized import format_colorized
print(format_colorized(model_input.to_ints(), weights, tokenizer))
```

Only the final assistant message counts as the completion; earlier context remains part of the prompt. This design trains models to continue conversations rather than answer isolated questions.

## Vision Inputs

### Multimodal Messages

```python
from tinker_cookbook.renderers import Message, TextPart, ImagePart

# Text-only message
text_message = Message(role='user', content='What is this?')

# Multimodal message
multimodal_message = Message(
    role='user',
    content=[
        ImagePart(type='image', image='https://example.com/image.png'),
        TextPart(type='text', text='What is in this image?'),
    ]
)
```

### Using Qwen3VLRenderer

```python
from tinker_cookbook import renderers, tokenizer_utils
from tinker_cookbook.image_processing_utils import get_image_processor

model_name = "Qwen/Qwen3-VL-235B-A22B-Instruct"
tokenizer = tokenizer_utils.get_tokenizer(model_name)
image_processor = get_image_processor(model_name)

renderer = renderers.Qwen3VLInstructRenderer(tokenizer, image_processor)
```

The `Qwen3VLRenderer` and `Qwen3VLInstructRenderer` automatically handle Qwen's vision special tokens (`<|vision_start|>`, `<|vision_end|>`).

## HuggingFace Compatibility

Tinker's default renderers produce identical tokens to HuggingFace's `apply_chat_template`.

| Renderer | HF Equivalent |
|----------|---------------|
| `qwen3` | `apply_chat_template(..., enable_thinking=True)` |
| `qwen3_disable_thinking` | `apply_chat_template(..., enable_thinking=False)` |
| `llama3` | `apply_chat_template(...)` * |
| `deepseekv3` | `apply_chat_template(...)` |

*The Llama3 renderer omits the knowledge cutoff preamble that HuggingFace adds to system messages.

Use default renderers with default options for OpenAI endpoint compatibility.

## Multi-turn RL and the Extension Property

In multi-turn RL, the extension property determines whether each observation is a prefix extension of the previous observation plus action. This affects compute efficiency (O(T) vs O(T^2)) and KV-cache reuse.

The `strip_thinking_from_history` parameter on renderers like `Qwen3Renderer` controls whether `<think>` blocks remain in conversation history.

## Appendix: Why Not Jinja Templates?

HuggingFace chat templates handle inference-only conversion. Tinker's renderers support the complete training lifecycle with capabilities templates lack:

1. **Per-token loss weights** -- Templates produce flat sequences without prompt/completion distinction.
2. **Message parsing** -- Templates provide no reverse conversion from tokens to structured messages.
3. **Tool calling** -- Each model family uses different formats. Renderers encode and parse these correctly.
4. **Precise tokenization control** -- Renderers directly construct token sequences rather than strings, giving precise control over the sequence.
