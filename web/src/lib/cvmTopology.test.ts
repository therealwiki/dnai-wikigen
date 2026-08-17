import { describe, expect, it } from "vitest";
import {
  buildCvmTopologyInventory,
  CVM_RELEASE_TOPOLOGY,
  type CvmTopologyInput,
} from "./cvmTopology";

const completeMainIdentity = Object.freeze({
  cvmId: "main-runtime-cvm-0001",
  appId: "a".repeat(40),
  composeHash: `0x${"b".repeat(64)}`,
  osImageHash: "c".repeat(64),
});

function input(
  overrides: Partial<CvmTopologyInput> = {},
): CvmTopologyInput {
  return {
    releaseBound: false,
    endpointConfigured: false,
    mainRuntimeConfig: {},
    mainRuntimeObservation: "not_checked",
    ...overrides,
  };
}

describe("seven-CVM topology inventory", () => {
  it("keeps the exact seven release roles distinct and ordered", () => {
    expect(CVM_RELEASE_TOPOLOGY.map(({ key }) => key)).toEqual([
      "main_runtime_cvm",
      "diligence_qvl_cvm",
      "arena_qvl_cvm",
      "anchor_writer_qvl_cvm",
      "compute_workload_qvl_cvm",
      "compute_metering_qvl_cvm",
      "independent_metering_cvm",
    ]);
    expect(new Set(CVM_RELEASE_TOPOLOGY.map(({ key }) => key)).size).toBe(7);
  });

  it("labels the current unconfigured build as not deployed without inventing observations", () => {
    const inventory = buildCvmTopologyInventory(input());
    expect(inventory).toMatchObject({
      plannedCount: 7,
      configuredCount: 0,
      runtimeObservedCount: 0,
      qvlVerifiedCount: 0,
      hasLiveInventorySource: false,
      currentBuildNotDeployed: true,
    });
    expect(inventory.rows).toHaveLength(7);
    expect(inventory.rows.every((row) => row.deployment.state === "not_deployed")).toBe(true);
    expect(inventory.rows.every((row) => row.verification.state === "unavailable")).toBe(true);
  });

  it("counts only a complete identity tuple as configured and never as deployed or verified", () => {
    const inventory = buildCvmTopologyInventory(input({
      releaseBound: true,
      endpointConfigured: true,
      mainRuntimeConfig: completeMainIdentity,
    }));
    expect(inventory.configuredCount).toBe(1);
    expect(inventory.runtimeObservedCount).toBe(0);
    expect(inventory.qvlVerifiedCount).toBe(0);
    expect(inventory.currentBuildNotDeployed).toBe(false);
    expect(inventory.rows[0].configuration.state).toBe("configured");
    expect(inventory.rows[0].deployment.state).toBe("not_established");
    expect(inventory.rows.slice(1).every((row) => row.configuration.state === "unavailable")).toBe(true);
  });

  it("treats an invalid purpose-specific projection as partial config, not proof of absence", () => {
    const inventory = buildCvmTopologyInventory(input({
      additionalConfigurationPresent: true,
    }));
    expect(inventory.currentBuildNotDeployed).toBe(false);
    expect(inventory.configuredCount).toBe(0);
    expect(inventory.rows[0].configuration.state).toBe("partial");
    expect(inventory.rows[0].deployment.state).toBe("not_established");
  });

  it("rejects disagreement between main-runtime and purpose-specific projections", () => {
    const inventory = buildCvmTopologyInventory(input({
      releaseBound: true,
      mainRuntimeConfig: completeMainIdentity,
      computeWorkloadProjection: {
        ...completeMainIdentity,
        cvmId: "main-runtime-cvm-substitution",
      },
    }));
    expect(inventory.configuredCount).toBe(0);
    expect(inventory.rows[0].configuration).toMatchObject({
      state: "conflict",
      label: "Configuration conflict",
    });
  });

  it("limits a bounded TDX response observation to the main runtime", () => {
    const inventory = buildCvmTopologyInventory(input({
      releaseBound: true,
      endpointConfigured: true,
      mainRuntimeConfig: completeMainIdentity,
      mainRuntimeObservation: "tdx_envelope_observed",
    }));
    expect(inventory.runtimeObservedCount).toBe(1);
    expect(inventory.rows[0].runtime.state).toBe("observed");
    expect(inventory.rows[0].runtime.detail).toContain("not health or independent QVL verification");
    expect(inventory.rows.slice(1).every((row) => row.runtime.state === "not_observable")).toBe(true);
    expect(inventory.qvlVerifiedCount).toBe(0);
  });

  it.each([
    ["tdx_envelope_incomplete", "incomplete", 1],
    ["local_modeled", "modeled", 0],
    ["rejected", "rejected", 0],
  ] as const)(
    "keeps %s distinct from a verified runtime",
    (observation, expectedState, observedCount) => {
      const inventory = buildCvmTopologyInventory(input({
        endpointConfigured: true,
        mainRuntimeObservation: observation,
      }));
      expect(inventory.rows[0].runtime.state).toBe(expectedState);
      expect(inventory.runtimeObservedCount).toBe(observedCount);
      expect(inventory.qvlVerifiedCount).toBe(0);
    },
  );
});
