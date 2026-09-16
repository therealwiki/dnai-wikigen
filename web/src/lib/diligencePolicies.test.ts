import { describe, expect, it } from "vitest";
import {
  DILIGENCE_MAX_ARTIFACT_BYTES,
  computeDiligenceEvaluatorPolicySetRoot,
  parseDiligenceEvaluatorConfig,
} from "./diligencePolicies";

const commitments = [
  `0x${"11".repeat(32)}`,
  `0x${"22".repeat(32)}`,
  `0x${"33".repeat(32)}`,
] as const;

const descriptors = [
  {
    recipe: "csv_table_integrity_v1",
    policy_commitment: commitments[0],
    display_schema: "dnai.diligence-artifact.csv-table.v1",
    max_artifact_bytes: DILIGENCE_MAX_ARTIFACT_BYTES,
    policy_document_sha256: `sha256:${"41".repeat(32)}`,
  },
  {
    recipe: "sft_jsonl_integrity_v1",
    policy_commitment: commitments[1],
    display_schema: "dnai.diligence-artifact.sft-jsonl.v1",
    max_artifact_bytes: DILIGENCE_MAX_ARTIFACT_BYTES,
    policy_document_sha256: `sha256:${"42".repeat(32)}`,
  },
  {
    recipe: "vcf_structural_qc_v1",
    policy_commitment: commitments[2],
    display_schema: "dnai.diligence-artifact.vcf.v1",
    max_artifact_bytes: DILIGENCE_MAX_ARTIFACT_BYTES,
    policy_document_sha256: `sha256:${"43".repeat(32)}`,
  },
];

describe("Diligence evaluator release configuration", () => {
  it("stays inert without a release descriptor set", () => {
    expect(parseDiligenceEvaluatorConfig({})).toEqual({
      descriptors: [],
      configured: false,
      issues: [],
    });
  });

  it("computes the Solidity policy-set root independent of input order", () => {
    const ordered = computeDiligenceEvaluatorPolicySetRoot(commitments);
    const reversed = computeDiligenceEvaluatorPolicySetRoot([
      commitments[2],
      commitments[1],
      commitments[0],
    ]);
    expect(ordered).toBe(reversed);
    expect(ordered).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("accepts only the exact three-descriptor release and matching root", () => {
    const policySetRoot = computeDiligenceEvaluatorPolicySetRoot(commitments);
    const config = parseDiligenceEvaluatorConfig({
      VITE_DILIGENCE_EVALUATOR_POLICIES_JSON: JSON.stringify(descriptors),
      VITE_DILIGENCE_EVALUATOR_POLICY_SET_ROOT: policySetRoot,
    });
    expect(config.configured).toBe(true);
    expect(config.issues).toEqual([]);
    expect(config.descriptors.map((descriptor) => descriptor.recipe)).toEqual([
      "csv_table_integrity_v1",
      "sft_jsonl_integrity_v1",
      "vcf_structural_qc_v1",
    ]);
  });

  it("rejects reordered, widened, duplicate, zero, and root-mismatched descriptors", () => {
    const root = computeDiligenceEvaluatorPolicySetRoot(commitments);
    const cases = [
      [descriptors.slice().reverse(), root],
      [[{ ...descriptors[0], max_artifact_bytes: DILIGENCE_MAX_ARTIFACT_BYTES + 1 }, descriptors[1], descriptors[2]], root],
      [[descriptors[0], { ...descriptors[1], policy_commitment: commitments[0] }, descriptors[2]], root],
      [[{ ...descriptors[0], policy_commitment: `0x${"00".repeat(32)}` }, descriptors[1], descriptors[2]], root],
      [[{ ...descriptors[0], policy_commitment: commitments[0].toUpperCase() }, descriptors[1], descriptors[2]], root],
      [descriptors, `0x${"ff".repeat(32)}`],
      [descriptors, root.toUpperCase()],
    ] as const;
    for (const [candidate, candidateRoot] of cases) {
      const config = parseDiligenceEvaluatorConfig({
        VITE_DILIGENCE_EVALUATOR_POLICIES_JSON: JSON.stringify(candidate),
        VITE_DILIGENCE_EVALUATOR_POLICY_SET_ROOT: candidateRoot,
      });
      expect(config.configured).toBe(false);
      expect(config.issues.length).toBeGreaterThan(0);
    }
  });

  it("rejects missing, unknown, or malformed public descriptor fields", () => {
    const root = computeDiligenceEvaluatorPolicySetRoot(commitments);
    const malformed = [
      { ...descriptors[0], raw_policy_document: "private" },
      descriptors[1],
      { ...descriptors[2], policy_document_sha256: "sha256:not-a-digest" },
    ];
    const config = parseDiligenceEvaluatorConfig({
      VITE_DILIGENCE_EVALUATOR_POLICIES_JSON: JSON.stringify(malformed),
      VITE_DILIGENCE_EVALUATOR_POLICY_SET_ROOT: root,
    });
    expect(config.configured).toBe(false);
    expect(config.issues.join(" ")).toMatch(/undeclared|invalid/i);
  });
});
