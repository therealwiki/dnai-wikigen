import { describe, expect, it } from "vitest";
import {
  assertPinnedComputeProviderResultPolicy,
  isPinnedComputeProviderResultPolicy,
  PINNED_COMPUTE_PROVIDER_RESULT_POLICIES,
} from "./computeProviderPolicy";

describe("pinned Compute provider result policies", () => {
  it("exposes only the immutable policy implemented by the sealed Tinker worker", () => {
    expect(PINNED_COMPUTE_PROVIDER_RESULT_POLICIES).toEqual(["bounded_summary_receipt"]);
    expect(Object.isFrozen(PINNED_COMPUTE_PROVIDER_RESULT_POLICIES)).toBe(true);
    expect(isPinnedComputeProviderResultPolicy("bounded_summary_receipt")).toBe(true);
    expect(() => assertPinnedComputeProviderResultPolicy("bounded_summary_receipt")).not.toThrow();
  });

  it.each([
    ["generic score-band policy", "score_band_hash"],
    ["raw output", "raw_output"],
    ["empty string", ""],
    ["leading whitespace", " bounded_summary_receipt"],
    ["trailing whitespace", "bounded_summary_receipt "],
    ["case drift", "BOUNDED_SUMMARY_RECEIPT"],
    ["missing value", undefined],
    ["null", null],
    ["boolean", true],
    ["number", 1],
    ["array", ["bounded_summary_receipt"]],
    ["coercible object", { toString: () => "bounded_summary_receipt" }],
  ])("rejects %s without coercing untrusted input", (_label, value) => {
    expect(isPinnedComputeProviderResultPolicy(value)).toBe(false);
    expect(() => assertPinnedComputeProviderResultPolicy(value)).toThrow(
      /not supported by the pinned Tinker provider/,
    );
  });
});
