// This is a provider-release constraint, not the generic Compute protocol's
// result-policy schema. Score-band commitments remain a protocol-level option,
// but the pinned sealed Tinker worker does not implement their execution.
export const PINNED_COMPUTE_PROVIDER_RESULT_POLICIES = Object.freeze([
  "bounded_summary_receipt",
] as const);

export type PinnedComputeProviderResultPolicy =
  typeof PINNED_COMPUTE_PROVIDER_RESULT_POLICIES[number];

export function isPinnedComputeProviderResultPolicy(
  value: unknown,
): value is PinnedComputeProviderResultPolicy {
  return typeof value === "string"
    && PINNED_COMPUTE_PROVIDER_RESULT_POLICIES.some((policy) => policy === value);
}

export function assertPinnedComputeProviderResultPolicy(
  value: unknown,
): asserts value is PinnedComputeProviderResultPolicy {
  if (!isPinnedComputeProviderResultPolicy(value)) {
    throw new Error(
      "Result policy is not supported by the pinned Tinker provider; use bounded_summary_receipt",
    );
  }
}
