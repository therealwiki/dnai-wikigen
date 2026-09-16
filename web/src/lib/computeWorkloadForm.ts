import {
  canonicalAsciiJson,
  COMPUTE_WORKLOAD_EXAMPLE_COUNT_CLASSES,
  COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES,
  type ComputePrivateWorkload,
  type ComputeWorkloadExampleCountClass,
  type ComputeWorkloadManifest,
  type ComputeWorkloadPayloadSizeClass,
} from "./computeWorkload";

const encoder = new TextEncoder();
const SEALED_HEADER_BYTES = 44;
const MAX_INFERENCE_PROMPT_BYTES = 262_144;
const MAX_SFT_FIELD_BYTES = 32_768;
const MAX_SFT_EXAMPLES = 256;

export const COMPUTE_WORKLOAD_PAYLOAD_CLASS_ORDER = Object.freeze([
  "4k",
  "16k",
  "64k",
  "256k",
  "1m",
] as const satisfies readonly ComputeWorkloadPayloadSizeClass[]);

export interface ComputeWorkloadDraft {
  manifest: ComputeWorkloadManifest;
  workload: ComputePrivateWorkload;
  privatePayloadBytes: number;
  selectedPayloadClassBytes: number;
  minimumPayloadSizeClass: ComputeWorkloadPayloadSizeClass;
  exampleCount: number;
}

function exactRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be one JSON object`);
  }
  return value as Record<string, unknown>;
}

function scalarString(
  value: unknown,
  label: string,
  maximumBytes = MAX_SFT_FIELD_BYTES,
): string {
  if (typeof value !== "string" || encoder.encode(value).length < 1) {
    throw new Error(`${label} must be a non-empty string`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const low = value.charCodeAt(index + 1);
      if (!(low >= 0xdc00 && low <= 0xdfff)) throw new Error(`${label} contains invalid Unicode`);
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error(`${label} contains invalid Unicode`);
    }
  }
  if (encoder.encode(value).length > maximumBytes) {
    throw new Error(`${label} exceeds its byte limit`);
  }
  return value;
}

export function parseComputeSftJsonl(value: string): readonly { prompt: string; completion: string }[] {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error("Add at least one JSONL training example");
  }
  const normalized = value.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
  const lines = normalized.endsWith("\n") ? normalized.slice(0, -1).split("\n") : normalized.split("\n");
  if (lines.length < 1 || lines.length > MAX_SFT_EXAMPLES) {
    throw new Error("SFT JSONL must contain 1 through 256 examples");
  }
  return Object.freeze(lines.map((line, index) => {
    if (!line.trim()) throw new Error(`SFT JSONL line ${index + 1} is blank`);
    let decoded: unknown;
    try {
      decoded = JSON.parse(line);
    } catch {
      throw new Error(`SFT JSONL line ${index + 1} is not valid JSON`);
    }
    const record = exactRecord(decoded, `SFT JSONL line ${index + 1}`);
    if (Object.keys(record).sort().join(",") !== "completion,prompt") {
      throw new Error(`SFT JSONL line ${index + 1} must contain only prompt and completion`);
    }
    return Object.freeze({
      prompt: scalarString(record.prompt, `SFT JSONL line ${index + 1} prompt`),
      completion: scalarString(record.completion, `SFT JSONL line ${index + 1} completion`),
    });
  }));
}

export function computeWorkloadExampleCountClass(count: number): ComputeWorkloadExampleCountClass {
  if (!Number.isInteger(count) || count < 1 || count > MAX_SFT_EXAMPLES) {
    throw new Error("SFT example count is outside its supported privacy classes");
  }
  const match = Object.entries(COMPUTE_WORKLOAD_EXAMPLE_COUNT_CLASSES).find(
    ([key, [minimum, maximum]]) => key !== "none" && count >= minimum && count <= maximum,
  );
  if (!match) throw new Error("SFT example count class is unavailable");
  return match[0] as ComputeWorkloadExampleCountClass;
}

export function minimumComputeWorkloadPayloadClass(
  privatePayloadBytes: number,
): ComputeWorkloadPayloadSizeClass {
  if (!Number.isInteger(privatePayloadBytes) || privatePayloadBytes < 1) {
    throw new Error("Private workload is empty");
  }
  const match = COMPUTE_WORKLOAD_PAYLOAD_CLASS_ORDER.find(
    (key) => privatePayloadBytes <= COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES[key] - SEALED_HEADER_BYTES,
  );
  if (!match) throw new Error("Private workload exceeds the 1 MiB sealed frame");
  return match;
}

export function computeWorkloadClassCanFit(
  payloadSizeClass: ComputeWorkloadPayloadSizeClass,
  privatePayloadBytes: number,
): boolean {
  return privatePayloadBytes <= COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES[payloadSizeClass] - SEALED_HEADER_BYTES;
}

function boundedInteger(value: number, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} is outside its compiled bound`);
  }
  return value;
}

export function buildComputeWorkloadDraft(input: {
  operation: "inference" | "training";
  prompt: string;
  sftJsonl: string;
  payloadSizeClass: ComputeWorkloadPayloadSizeClass;
  maxPrefillTokens: number;
  maxSampleTokens: number;
  maxTrainTokens: number;
}): ComputeWorkloadDraft {
  if (input.operation === "inference") {
    const prompt = input.prompt;
    const promptBytes = encoder.encode(prompt).length;
    if (promptBytes < 1) throw new Error("Enter a private inference prompt");
    if (promptBytes > MAX_INFERENCE_PROMPT_BYTES) throw new Error("Inference prompt exceeds 256 KiB");
    scalarString(prompt, "Inference prompt", MAX_INFERENCE_PROMPT_BYTES);
    const privatePayloadBytes = encoder.encode(canonicalAsciiJson({
      prompt,
      schema: "dnai.compute.inference-prompt.v1",
    })).length;
    const minimumPayloadSizeClass = minimumComputeWorkloadPayloadClass(privatePayloadBytes);
    if (!computeWorkloadClassCanFit(input.payloadSizeClass, privatePayloadBytes)) {
      throw new Error(`Choose the ${minimumPayloadSizeClass} payload class or larger`);
    }
    const manifest: ComputeWorkloadManifest = {
      schema: "dnai.compute.workload.inference.v1",
      operation: "inference",
      model: "qwen3_8b",
      recipe: "qwen3_8b_bounded",
      payload_size_class: input.payloadSizeClass,
      example_count_class: "none",
      max_prefill_tokens: boundedInteger(input.maxPrefillTokens, 1, 32_768, "Prefill token cap"),
      max_sample_tokens: boundedInteger(input.maxSampleTokens, 1, 4_096, "Sample token cap"),
      max_train_tokens: boundedInteger(input.maxTrainTokens, 0, 0, "Training token cap"),
    };
    return {
      manifest,
      workload: { kind: "inference", prompt },
      privatePayloadBytes,
      selectedPayloadClassBytes: COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES[input.payloadSizeClass],
      minimumPayloadSizeClass,
      exampleCount: 0,
    };
  }

  const examples = parseComputeSftJsonl(input.sftJsonl);
  const canonicalJsonl = `${examples.map((example) => canonicalAsciiJson({
    completion: example.completion,
    prompt: example.prompt,
  })).join("\n")}\n`;
  const privatePayloadBytes = encoder.encode(canonicalJsonl).length;
  const minimumPayloadSizeClass = minimumComputeWorkloadPayloadClass(privatePayloadBytes);
  if (!computeWorkloadClassCanFit(input.payloadSizeClass, privatePayloadBytes)) {
    throw new Error(`Choose the ${minimumPayloadSizeClass} payload class or larger`);
  }
  const manifest: ComputeWorkloadManifest = {
    schema: "dnai.compute.workload.sft-jsonl.v1",
    operation: "training",
    model: "qwen3_8b",
    recipe: "qwen3_8b_lora_r32",
    payload_size_class: input.payloadSizeClass,
    example_count_class: computeWorkloadExampleCountClass(examples.length),
    max_prefill_tokens: boundedInteger(input.maxPrefillTokens, 0, 0, "Prefill token cap"),
    max_sample_tokens: boundedInteger(input.maxSampleTokens, 0, 0, "Sample token cap"),
    max_train_tokens: boundedInteger(input.maxTrainTokens, 1, 10_000_000, "Training token cap"),
  };
  return {
    manifest,
    workload: { kind: "training", examples },
    privatePayloadBytes,
    selectedPayloadClassBytes: COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES[input.payloadSizeClass],
    minimumPayloadSizeClass,
    exampleCount: examples.length,
  };
}
