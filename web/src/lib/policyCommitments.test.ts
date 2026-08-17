import { describe, expect, it } from "vitest";
import vectorsDocument from "./policyCommitmentVectors.json";
import type { ExecutionPolicySurface, PolicyBundle } from "./policy";
import {
  computePolicyCommitments,
  pythonCanonicalJson,
} from "./policyCommitments";

interface CommitmentVector {
  name: string;
  surface: ExecutionPolicySurface;
  resource_id: string;
  bundle: PolicyBundle;
  expected: Awaited<ReturnType<typeof computePolicyCommitments>>;
}

const vectors = vectorsDocument.vectors as CommitmentVector[];

describe("browser policy commitments", () => {
  it("matches the Python policy kernel's checked-in pass, hold, deny, defaults, and Unicode vectors", async () => {
    expect(vectorsDocument.schema).toBe("dnai.execution-policy-commitment-vectors.v1");
    for (const vector of vectors) {
      expect(
        await computePolicyCommitments(vector.bundle, vector.surface, vector.resource_id),
        vector.name,
      ).toEqual(vector.expected);
    }
  });

  it("matches Python JSON key ordering and ensure_ascii escaping", () => {
    expect(pythonCanonicalJson({ "🧬": "é", z: 1, "β": true })).toBe(
      "{\"z\":1,\"\\u03b2\":true,\"\\ud83e\\uddec\":\"\\u00e9\"}",
    );
    expect(() => pythonCanonicalJson({ unsafe: undefined })).toThrow(/undefined/);
    expect(() => pythonCanonicalJson(0.5)).toThrow(/non-JSON/);
  });

  it("sorts policy sets while preserving request operation order", async () => {
    const source = vectors.find((vector) => vector.name === "hold-explicit-route");
    expect(source).toBeDefined();
    const original = await computePolicyCommitments(source!.bundle, source!.surface, source!.resource_id);
    const reorderedPolicy: PolicyBundle = {
      request: { ...source!.bundle.request },
      policy: {
        ...source!.bundle.policy,
        allowed_operations: [...(source!.bundle.policy.allowed_operations as string[])].reverse(),
        known_data_classes: [...(source!.bundle.policy.known_data_classes as string[])].reverse(),
      },
    };
    const reordered = await computePolicyCommitments(reorderedPolicy, source!.surface, source!.resource_id);
    expect(reordered.policy_hash).toBe(original.policy_hash);
    expect(reordered.request_hash).toBe(original.request_hash);

    const reorderedRequest: PolicyBundle = {
      request: {
        ...source!.bundle.request,
        operations: [...(source!.bundle.request.operations as string[])].reverse(),
      },
      policy: { ...source!.bundle.policy },
    };
    const requestChanged = await computePolicyCommitments(reorderedRequest, source!.surface, source!.resource_id);
    expect(requestChanged.request_hash).not.toBe(original.request_hash);
    expect(requestChanged.policy_hash).toBe(original.policy_hash);
  });
});
