"""Evaluator agents — stub for testing + real SFT evaluator using Tinker SDK.

The evaluator is the buyer's agent (A_B from the NDAI paper). It receives
the seller's artifact and an IsolatedTinkerSession, then:
1. Parses the artifact (dataset, training recipe, etc.)
2. Fine-tunes a model using the session
3. Benchmarks the fine-tuned model against the base model
4. Returns raw metrics (the control plane bounds the output)

The control plane calls bound_output() on the raw metrics before they
leave the TEE — the evaluator never decides what leaves the boundary.
"""
from __future__ import annotations

import hashlib
import json
import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tinker_delegate.session import IsolatedTinkerSession


# ---------------------------------------------------------------------------
# Stub evaluator — deterministic, no real API calls
# ---------------------------------------------------------------------------

async def stub_evaluate(
    artifact: bytes,
    artifact_type: str,
    session: IsolatedTinkerSession,
    budget_cap: int,
    reserve_price: int,
) -> dict:
    """Stub evaluator — returns synthetic metrics based on artifact hash.

    Deterministic: same artifact always produces the same score.
    Useful for testing the full pipeline without consuming API credits.
    """
    h = hashlib.sha256(artifact).hexdigest()
    seed = int(h[:8], 16)
    rng = random.Random(seed)

    quality_delta = rng.uniform(0.0, 0.30)
    compute_fraction = rng.uniform(0.01, 0.10)
    simulated_compute = int(budget_cap * compute_fraction)

    if len(artifact) > 10000:
        confidence = "high"
    elif len(artifact) > 1000:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "quality_delta": quality_delta,
        "benchmark": "stub-perplexity",
        "confidence": confidence,
        "methodology": (
            f"Stub evaluation on {len(artifact)} byte artifact. "
            f"Simulated {artifact_type} assessment with seed {h[:8]}. "
            f"No Tinker API calls made."
        ),
    }


# ---------------------------------------------------------------------------
# SFT evaluator — real LoRA fine-tuning via Tinker SDK
# ---------------------------------------------------------------------------

def _parse_sft_dataset(artifact: bytes) -> list[dict]:
    """Parse JSONL artifact into instruction/response pairs."""
    text = artifact.decode("utf-8", errors="replace")
    records = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            # Support common SFT formats
            if "instruction" in record or "input" in record or "prompt" in record:
                records.append(record)
            elif "messages" in record:
                # ChatML format: extract last assistant message as response
                msgs = record["messages"]
                prompt_parts = []
                response = ""
                for msg in msgs:
                    if msg.get("role") == "assistant":
                        response = msg.get("content", "")
                    else:
                        prompt_parts.append(msg.get("content", ""))
                records.append({
                    "instruction": "\n".join(prompt_parts),
                    "response": response,
                })
        except json.JSONDecodeError:
            continue
    return records


def _tokenize_sft_example(tokenizer, record: dict) -> tuple[list[int], list[float]]:
    """Tokenize an SFT example into input tokens + loss weights.

    Returns (tokens, weights) where weights=0 for prompt, weights=1 for completion.
    This follows the standard SFT pattern: train on completions only.
    """
    instruction = record.get("instruction", record.get("input", record.get("prompt", "")))
    response = record.get("response", record.get("output", record.get("completion", "")))

    prompt_text = f"### Instruction:\n{instruction}\n\n### Response:\n"
    completion_text = f"{response}\n\n"

    prompt_tokens = tokenizer.encode(prompt_text, add_special_tokens=True)
    completion_tokens = tokenizer.encode(completion_text, add_special_tokens=False)

    # Combine and create weights (0 for prompt, 1 for completion)
    all_tokens = prompt_tokens + completion_tokens
    weights = [0.0] * len(prompt_tokens) + [1.0] * len(completion_tokens)

    # Truncate to model context length
    max_len = 2048
    if len(all_tokens) > max_len:
        all_tokens = all_tokens[:max_len]
        weights = weights[:max_len]

    return all_tokens, weights


async def sft_evaluate(
    artifact: bytes,
    artifact_type: str,
    session: IsolatedTinkerSession,
    budget_cap: int,
    reserve_price: int,
) -> dict:
    """Real SFT evaluation — LoRA fine-tune on artifact, benchmark against base.

    Protocol:
    1. Parse JSONL dataset from artifact
    2. Tokenize examples with prompt/completion weighting
    3. Create LoRA training run on Llama-3.1-8B-Instruct
    4. Train for up to 200 steps (cross_entropy, completion-only loss)
    5. Save checkpoint, create sampling client
    6. Benchmark: compute perplexity on held-out eval set
    7. Compare against base model perplexity
    8. Return quality_delta = (base_ppl - tuned_ppl) / base_ppl
    """
    import numpy as np
    import tinker

    # 1. Parse dataset
    records = _parse_sft_dataset(artifact)
    if not records:
        return {
            "quality_delta": 0.0,
            "benchmark": "sft-perplexity",
            "confidence": "low",
            "methodology": "Empty or unparseable dataset.",
        }

    # 2. Split train/eval (90/10)
    split_idx = max(1, len(records) * 9 // 10)
    train_records = records[:split_idx]
    eval_records = records[split_idx:] or records[:1]

    # 3. Create training run
    base_model = "meta-llama/Llama-3.1-8B-Instruct"
    tc = session.create_training(base_model=base_model, rank=32)
    tokenizer = session.get_tokenizer()

    # 4. Tokenize training data into Datum objects
    train_data = []
    for record in train_records:
        tokens, weights = _tokenize_sft_example(tokenizer, record)
        if len(tokens) < 4:
            continue

        # Shift for next-token prediction
        input_tokens = tokens[:-1]
        target_tokens = tokens[1:]
        loss_weights = weights[1:]  # align weights with targets

        datum = tinker.Datum(
            model_input=tinker.ModelInput.from_ints(input_tokens),
            loss_fn_inputs={
                "weights": tinker.TensorData(
                    data=loss_weights,
                    dtype="float32",
                    shape=[len(loss_weights)],
                ),
                "target_tokens": tinker.TensorData(
                    data=target_tokens,
                    dtype="int64",
                    shape=[len(target_tokens)],
                ),
            },
        )
        train_data.append(datum)

    if not train_data:
        return {
            "quality_delta": 0.0,
            "benchmark": "sft-perplexity",
            "confidence": "low",
            "methodology": "No valid training examples after tokenization.",
        }

    # 5. Training loop — batch size 4, up to 200 steps
    max_steps = min(200, len(train_data))
    batch_size = 4
    losses = []

    adam_params = tinker.AdamParams(learning_rate=1e-4)

    for step in range(0, max_steps, batch_size):
        batch = train_data[step:step + batch_size]
        if not batch:
            break

        # Pipeline: submit fwd/bwd and optim step before waiting
        fwdbwd_future = session.forward_backward(batch, loss_fn="cross_entropy")
        optim_future = session.optim_step(adam_params)

        # Wait for results
        fwdbwd_result = fwdbwd_future.result()
        optim_future.result()

        # Compute batch loss from logprobs
        batch_logprobs = []
        batch_weights = []
        for i, output_dict in enumerate(fwdbwd_result.loss_fn_outputs):
            logprobs = output_dict["logprobs"].to_numpy()
            w = batch[i].loss_fn_inputs["weights"].to_numpy()
            batch_logprobs.append(logprobs)
            batch_weights.append(w)

        all_logprobs = np.concatenate(batch_logprobs)
        all_weights = np.concatenate(batch_weights)
        if all_weights.sum() > 0:
            loss = -np.dot(all_logprobs, all_weights) / all_weights.sum()
            losses.append(float(loss))

    # 6. Save checkpoint and create sampling client
    sampler = session.save_and_get_sampler(name="eval-checkpoint")

    # 7. Benchmark: perplexity on eval set
    eval_losses_tuned = []
    eval_losses_base = []

    # Also create a scoped base model sampler for comparison.
    base_sampler = session.create_base_sampler(base_model=base_model)

    for record in eval_records[:20]:  # cap eval at 20 examples
        tokens, weights = _tokenize_sft_example(tokenizer, record)
        if len(tokens) < 4:
            continue

        prompt = tinker.ModelInput.from_ints(tokens)

        # Tuned model logprobs
        tuned_lp = session.compute_logprobs(sampler, prompt).result()
        completion_lps = [
            lp for lp, w in zip(tuned_lp, weights)
            if w > 0 and lp is not None
        ]
        if completion_lps:
            eval_losses_tuned.append(-sum(completion_lps) / len(completion_lps))

        # Base model logprobs
        base_lp = base_sampler.compute_logprobs(prompt).result()
        base_completion_lps = [
            lp for lp, w in zip(base_lp, weights)
            if w > 0 and lp is not None
        ]
        if base_completion_lps:
            eval_losses_base.append(-sum(base_completion_lps) / len(base_completion_lps))

    # 8. Compute quality delta
    if eval_losses_tuned and eval_losses_base:
        tuned_ppl = sum(eval_losses_tuned) / len(eval_losses_tuned)
        base_ppl = sum(eval_losses_base) / len(eval_losses_base)
        if base_ppl > 0:
            quality_delta = (base_ppl - tuned_ppl) / base_ppl
        else:
            quality_delta = 0.0
    else:
        tuned_ppl = 0.0
        base_ppl = 0.0
        quality_delta = 0.0

    # Determine confidence
    if len(train_data) >= 100 and len(eval_losses_tuned) >= 10:
        confidence = "high"
    elif len(train_data) >= 20:
        confidence = "medium"
    else:
        confidence = "low"

    actual_steps = max_steps // batch_size

    return {
        "quality_delta": max(0.0, quality_delta),
        "benchmark": "sft-perplexity",
        "confidence": confidence,
        "methodology": (
            f"LoRA fine-tune on {base_model} (rank=32, {actual_steps} steps, "
            f"batch_size={batch_size}, lr=1e-4, cross_entropy completion-only). "
            f"Dataset: {len(records)} examples ({len(train_data)} after tokenization). "
            f"Eval: perplexity on {len(eval_losses_tuned)} held-out samples. "
            f"Base avg NLL: {base_ppl:.3f}, Tuned avg NLL: {tuned_ppl:.3f}, "
            f"Delta: {max(0, quality_delta):.1%}. "
            f"Training loss trend: {losses[0]:.3f} → {losses[-1]:.3f}."
            if losses else
            f"LoRA fine-tune on {base_model}. No training loss recorded."
        ),
    }
