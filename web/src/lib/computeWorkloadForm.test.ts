import { describe, expect, it } from "vitest";
import {
  buildComputeWorkloadDraft,
  computeWorkloadExampleCountClass,
  minimumComputeWorkloadPayloadClass,
  parseComputeSftJsonl,
} from "./computeWorkloadForm";

describe("Compute workload form projection", () => {
  it("builds the exact inference manifest and measures canonical private bytes locally", () => {
    const draft = buildComputeWorkloadDraft({
      operation: "inference",
      prompt: "summarize DNA β",
      sftJsonl: "",
      payloadSizeClass: "4k",
      maxPrefillTokens: 4_096,
      maxSampleTokens: 512,
      maxTrainTokens: 0,
    });
    expect(draft.manifest).toEqual({
      schema: "dnai.compute.workload.inference.v1",
      operation: "inference",
      model: "qwen3_8b",
      recipe: "qwen3_8b_bounded",
      payload_size_class: "4k",
      example_count_class: "none",
      max_prefill_tokens: 4_096,
      max_sample_tokens: 512,
      max_train_tokens: 0,
    });
    expect(draft.workload).toEqual({ kind: "inference", prompt: "summarize DNA β" });
    expect(draft.minimumPayloadSizeClass).toBe("4k");
    expect(draft.privatePayloadBytes).toBeGreaterThan(0);
  });

  it("strictly parses and canonicalizes SFT JSONL without retaining extra fields", () => {
    const input = '{"prompt":"p1","completion":"c1"}\n{"completion":"c2","prompt":"p2"}\n';
    const examples = parseComputeSftJsonl(input);
    expect(examples).toEqual([
      { prompt: "p1", completion: "c1" },
      { prompt: "p2", completion: "c2" },
    ]);
    const draft = buildComputeWorkloadDraft({
      operation: "training",
      prompt: "",
      sftJsonl: input,
      payloadSizeClass: "4k",
      maxPrefillTokens: 0,
      maxSampleTokens: 0,
      maxTrainTokens: 50_000,
    });
    expect(draft.manifest.schema).toBe("dnai.compute.workload.sft-jsonl.v1");
    expect(draft.manifest.example_count_class).toBe("1_8");
    expect(draft.exampleCount).toBe(2);
  });

  it.each([
    ['{"prompt":"p"}', /only prompt and completion/],
    ['{"prompt":"p","completion":"c","secret":"x"}', /only prompt and completion/],
    ['{"prompt":1,"completion":"c"}', /prompt must be a non-empty string/],
    ['not-json', /not valid JSON/],
    ['{"prompt":"p","completion":"c"}\n\n{"prompt":"p2","completion":"c2"}', /line 2 is blank/],
  ])("rejects malformed JSONL without returning submitted content", (value, message) => {
    expect(() => parseComputeSftJsonl(value)).toThrow(message);
    try {
      parseComputeSftJsonl(value);
    } catch (cause) {
      expect(String(cause)).not.toContain("secret");
      expect(String(cause)).not.toContain("not-json");
    }
  });

  it("maps exact example-count and padded payload classes", () => {
    expect(computeWorkloadExampleCountClass(1)).toBe("1_8");
    expect(computeWorkloadExampleCountClass(9)).toBe("9_32");
    expect(computeWorkloadExampleCountClass(33)).toBe("33_128");
    expect(computeWorkloadExampleCountClass(129)).toBe("129_256");
    expect(minimumComputeWorkloadPayloadClass(4_052)).toBe("4k");
    expect(minimumComputeWorkloadPayloadClass(4_053)).toBe("16k");
    expect(minimumComputeWorkloadPayloadClass(1_048_516)).toBe("1m");
    expect(() => minimumComputeWorkloadPayloadClass(1_048_517)).toThrow(/exceeds/);
  });

  it("rejects public caps or a selected size class that do not fit the private payload", () => {
    expect(() => buildComputeWorkloadDraft({
      operation: "inference",
      prompt: "A".repeat(4_100),
      sftJsonl: "",
      payloadSizeClass: "4k",
      maxPrefillTokens: 4_096,
      maxSampleTokens: 512,
      maxTrainTokens: 0,
    })).toThrow(/16k payload class/);
    expect(() => buildComputeWorkloadDraft({
      operation: "inference",
      prompt: "valid",
      sftJsonl: "",
      payloadSizeClass: "4k",
      maxPrefillTokens: 32_769,
      maxSampleTokens: 512,
      maxTrainTokens: 0,
    })).toThrow(/Prefill token cap/);
  });
});
