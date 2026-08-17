import { describe, expect, it } from "vitest";
import type {
  ComputeProviderCapabilityRelease,
  ComputeProviderCapabilityUnavailable,
} from "./compute";
import { computeProviderPresentation } from "./computeProviderPresentation";

const unavailableCapability: ComputeProviderCapabilityUnavailable = {
  schema: "dnai.compute.provider-capability.v1",
  source_present: true,
  release_configured: false,
  provider_dispatch: false,
  reason: "provider_capability_unavailable",
};

const liveCapability: ComputeProviderCapabilityRelease = {
  schema: "dnai.compute.provider-capability.v1",
  source_present: true,
  release_configured: true,
  provider_dispatch: true,
  allowed_operations: ["inference", "training"],
  allowed_result_policies: ["bounded_summary_receipt"],
  adapter_id: "tinker_sdk_0_22_7_at_most_once_v1",
  sdk_version: "0.22.7",
  sdk_source_sha256: "sha256:3ab30e85f4d1ae21ab4a8b415d382e719decd3abb31e61f6e481e8e5296dac62",
  request_contract_sha256: "sha256:15f112c2e285ba2463d36fe32a47f78eda40f7ca81d7b49f6d51dc4378feef0d",
  base_url_sha256: "sha256:e3ae09c22c856fa175bfbeded8819e1665f39c235869a15e3e0729bfb4f39533",
  provider_release_sha256: "sha256:4264a2226ac9c850d8f053c98ac90d0f6dcbc58702919899384a9b2442b35631",
  idempotency_header_role: "request_commitment_only",
  idempotent_provider_replay_claimed: false,
  automatic_provider_redispatch: false,
  adapter_contract: {
    at_most_once_attempt_checkpoint: true,
    terminal_ambiguity_hold: true,
    ambiguous_outcome_ciphertext_retained: true,
  },
  runtime_guarantees: {
    at_most_once_attempt_checkpoint: true,
    terminal_ambiguity_hold: true,
    ambiguous_outcome_ciphertext_retained: true,
  },
  runtime: {
    authenticated: true,
    fresh: true,
    process_presence_only: true,
    tdx_evidence: false,
    observed_at: 1_900_000_000,
  },
  reason: "ready_at_most_once_ambiguity_hold",
};

describe("Compute provider overview presentation", () => {
  it("labels an explicitly non-live build as modeled", () => {
    expect(computeProviderPresentation(false, liveCapability)).toMatchObject({
      state: "modeled",
      label: "MODELED",
    });
  });

  it("fails closed when a live release returns no exact provider capability", () => {
    const result = computeProviderPresentation(true, undefined);

    expect(result).toMatchObject({
      state: "unavailable",
      label: "UNAVAILABLE",
    });
    expect(result.detail).toContain("Service reachability is not treated as provider readiness");
  });

  it("surfaces the exact unavailable capability reason", () => {
    const result = computeProviderPresentation(true, unavailableCapability);

    expect(result.state).toBe("unavailable");
    expect(result.detail).toContain("provider capability unavailable");
  });

  it("requires the fresh authenticated at-most-once runtime before reporting live", () => {
    expect(computeProviderPresentation(true, liveCapability)).toMatchObject({
      state: "live",
      label: "LIVE · HEARTBEAT FRESH",
    });

    expect(computeProviderPresentation(true, {
      ...liveCapability,
      runtime: undefined,
    }).state).toBe("unavailable");
    expect(computeProviderPresentation(true, {
      ...liveCapability,
      runtime_guarantees: {
        ...liveCapability.runtime_guarantees,
        terminal_ambiguity_hold: false,
      },
    }).state).toBe("unavailable");
  });
});
