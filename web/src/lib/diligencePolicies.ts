import { encodeAbiParameters, keccak256, toHex, type Hex } from "viem";

type EnvLike = Record<string, unknown>;

export const DILIGENCE_EVALUATOR_DESCRIPTOR_SCHEMA =
  "dnai.diligence-evaluator-policy-descriptor.v1" as const;
export const DILIGENCE_EVALUATOR_POLICY_SET_TYPE =
  "DiligenceRoomEvaluatorPolicySet(bytes32[3] evaluatorPolicies)" as const;
export const DILIGENCE_MAX_ARTIFACT_BYTES = 1_048_576 as const;

export const DILIGENCE_RECIPES = [
  "csv_table_integrity_v1",
  "sft_jsonl_integrity_v1",
  "vcf_structural_qc_v1",
] as const;

export type DiligenceRecipe = (typeof DILIGENCE_RECIPES)[number];

export interface DiligenceEvaluatorPolicyDescriptor {
  recipe: DiligenceRecipe;
  policy_commitment: Hex;
  display_schema: string;
  max_artifact_bytes: typeof DILIGENCE_MAX_ARTIFACT_BYTES;
  policy_document_sha256: `sha256:${string}`;
}

export interface DiligenceEvaluatorDeploymentConfig {
  descriptors: readonly DiligenceEvaluatorPolicyDescriptor[];
  policySetRoot?: Hex;
  configured: boolean;
  issues: readonly string[];
}

const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const SHA256_PIN = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const DESCRIPTOR_KEYS = new Set([
  "recipe",
  "policy_commitment",
  "display_schema",
  "max_artifact_bytes",
  "policy_document_sha256",
]);
const DISPLAY_SCHEMAS: Readonly<Record<DiligenceRecipe, string>> = Object.freeze({
  csv_table_integrity_v1: "dnai.diligence-artifact.csv-table.v1",
  sft_jsonl_integrity_v1: "dnai.diligence-artifact.sft-jsonl.v1",
  vcf_structural_qc_v1: "dnai.diligence-artifact.vcf.v1",
});

export const DILIGENCE_RECIPE_COPY: Readonly<Record<DiligenceRecipe, {
  label: string;
  summary: string;
  accepts: string;
}>> = Object.freeze({
  csv_table_integrity_v1: {
    label: "CSV table integrity",
    summary: "Bounded structural checks for columns, row shape, missingness, and parse consistency.",
    accepts: "UTF-8 CSV",
  },
  sft_jsonl_integrity_v1: {
    label: "SFT JSONL integrity",
    summary: "Bounded record, role, and content-shape checks for supervised fine-tuning corpora.",
    accepts: "UTF-8 JSONL",
  },
  vcf_structural_qc_v1: {
    label: "VCF structural QC",
    summary: "Bounded header, sample, allele, and sorted-variant checks; never a clinical interpretation.",
    accepts: "UTF-8 VCF",
  },
});

function clean(value: unknown): string {
  if (typeof value !== "string") return "";
  const normalized = value.trim();
  return normalized === "undefined" || normalized === "null" ? "" : normalized;
}

function bytes32(value: unknown): Hex | undefined {
  const normalized = clean(value);
  return BYTES32.test(normalized) ? normalized as Hex : undefined;
}

export function computeDiligenceEvaluatorPolicySetRoot(
  commitments: readonly [Hex, Hex, Hex],
): Hex {
  const normalized = commitments.map((value) => value.toLowerCase() as Hex)
    .sort((left, right) => left.localeCompare(right)) as [Hex, Hex, Hex];
  if (new Set(normalized).size !== 3 || normalized.some((value) => !BYTES32.test(value))) {
    throw new Error("Diligence evaluator commitments must be three distinct nonzero bytes32 values");
  }
  const typehash = keccak256(toHex(DILIGENCE_EVALUATOR_POLICY_SET_TYPE));
  return keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes32[3]" }],
    [typehash, normalized],
  ));
}

function parseDescriptor(value: unknown, index: number, issues: string[]): DiligenceEvaluatorPolicyDescriptor | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    issues.push(`Diligence evaluator descriptor ${index + 1} must be an object`);
    return undefined;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== DESCRIPTOR_KEYS.size || keys.some((key) => !DESCRIPTOR_KEYS.has(key))) {
    issues.push(`Diligence evaluator descriptor ${index + 1} has undeclared or missing fields`);
    return undefined;
  }
  const expectedRecipe = DILIGENCE_RECIPES[index];
  if (record.recipe !== expectedRecipe) {
    issues.push(`Diligence evaluator descriptor ${index + 1} must be ${expectedRecipe}`);
    return undefined;
  }
  const commitment = bytes32(record.policy_commitment);
  if (!commitment) {
    issues.push(`Diligence evaluator descriptor ${index + 1} has an invalid policy commitment`);
    return undefined;
  }
  if (record.display_schema !== DISPLAY_SCHEMAS[expectedRecipe]) {
    issues.push(`Diligence evaluator descriptor ${index + 1} has the wrong display schema`);
    return undefined;
  }
  if (record.max_artifact_bytes !== DILIGENCE_MAX_ARTIFACT_BYTES) {
    issues.push(`Diligence evaluator descriptor ${index + 1} must use the exact 1 MiB artifact cap`);
    return undefined;
  }
  if (typeof record.policy_document_sha256 !== "string" || !SHA256_PIN.test(record.policy_document_sha256)) {
    issues.push(`Diligence evaluator descriptor ${index + 1} has an invalid policy document digest`);
    return undefined;
  }
  return Object.freeze({
    recipe: expectedRecipe,
    policy_commitment: commitment,
    display_schema: record.display_schema,
    max_artifact_bytes: DILIGENCE_MAX_ARTIFACT_BYTES,
    policy_document_sha256: record.policy_document_sha256 as `sha256:${string}`,
  });
}

export function parseDiligenceEvaluatorConfig(env: EnvLike): DiligenceEvaluatorDeploymentConfig {
  const issues: string[] = [];
  const rawDescriptors = clean(env.VITE_DILIGENCE_EVALUATOR_POLICIES_JSON);
  const rawRoot = clean(env.VITE_DILIGENCE_EVALUATOR_POLICY_SET_ROOT);
  if (!rawDescriptors && !rawRoot) {
    return Object.freeze({ descriptors: Object.freeze([]), configured: false, issues: Object.freeze([]) });
  }

  let decoded: unknown;
  try {
    decoded = JSON.parse(rawDescriptors);
  } catch {
    issues.push("VITE_DILIGENCE_EVALUATOR_POLICIES_JSON must be valid JSON");
  }
  if (!Array.isArray(decoded) || decoded.length !== 3) {
    issues.push("The Diligence evaluator release must contain exactly three descriptors");
  }
  const descriptors = Array.isArray(decoded) && decoded.length === 3
    ? decoded.flatMap((value, index) => {
        const descriptor = parseDescriptor(value, index, issues);
        return descriptor ? [descriptor] : [];
      })
    : [];
  if (new Set(descriptors.map((descriptor) => descriptor.policy_commitment)).size !== descriptors.length) {
    issues.push("Diligence evaluator policy commitments must be unique");
  }

  const policySetRoot = bytes32(rawRoot);
  if (!policySetRoot) issues.push("VITE_DILIGENCE_EVALUATOR_POLICY_SET_ROOT must be a nonzero lowercase bytes32 value");
  if (descriptors.length === 3 && policySetRoot) {
    try {
      const calculated = computeDiligenceEvaluatorPolicySetRoot([
        descriptors[0].policy_commitment,
        descriptors[1].policy_commitment,
        descriptors[2].policy_commitment,
      ]);
      if (calculated !== policySetRoot) {
        issues.push("Diligence evaluator descriptor commitments do not match the configured policy-set root");
      }
    } catch {
      issues.push("Diligence evaluator descriptor commitments cannot form the exact three-policy root");
    }
  }

  return Object.freeze({
    descriptors: Object.freeze(descriptors),
    policySetRoot,
    configured: descriptors.length === 3 && Boolean(policySetRoot) && issues.length === 0,
    issues: Object.freeze(issues),
  });
}
