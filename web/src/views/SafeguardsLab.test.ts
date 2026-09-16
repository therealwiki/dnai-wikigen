import { describe, expect, it } from "vitest";
import safeguardsSource from "./SafeguardsLab.tsx?raw";
import {
  executionPolicyOperatorReady,
  executionPolicyStatusReadAuthorityIsCurrent,
  executionPolicyUiAuthorityIsCurrent,
  runExecutionPolicyStatusRead,
  type ExecutionPolicyStatusReadAuthorityContext,
  type ExecutionPolicyUiAuthorityContext,
} from "./SafeguardsLab";

const READY = {
  delegateConfigured: true,
  approvalDomainPinned: true,
  approverSetPinned: true,
  monotonicAnchorPinned: true,
  walletConnected: true,
  walletOnBaseSepolia: true,
} as const;

const STATUS_AUTHORITY: ExecutionPolicyStatusReadAuthorityContext = {
  walletAddress: "0x1111111111111111111111111111111111111111",
  walletProvider: {},
  walletAuthorizationVersion: 11,
  chainId: 84_532,
  runtimeBearer: "runtime-status-session-a",
  surface: "compute_dispatch",
  statusReference: "job-private-11",
  computeStatusProjectReference: "prj_private_11",
  releaseFingerprint: "release-status-a",
};

const STATUS_AUTHORITY_DRIFTS: ReadonlyArray<readonly [
  label: string,
  change: (
    authority: ExecutionPolicyStatusReadAuthorityContext,
  ) => ExecutionPolicyStatusReadAuthorityContext,
]> = [
  ["wallet address", (authority) => ({
    ...authority,
    walletAddress: "0x2222222222222222222222222222222222222222",
  })],
  ["wallet provider", (authority) => ({ ...authority, walletProvider: {} })],
  ["wallet authorization generation", (authority) => ({
    ...authority,
    walletAuthorizationVersion: 12,
  })],
  ["chain", (authority) => ({ ...authority, chainId: 1 })],
  ["runtime bearer", (authority) => ({
    ...authority,
    runtimeBearer: "runtime-status-session-b",
  })],
  ["surface", (authority) => ({ ...authority, surface: "arena_execution" })],
  ["status reference", (authority) => ({
    ...authority,
    statusReference: "job-private-12",
  })],
  ["Compute project reference", (authority) => ({
    ...authority,
    computeStatusProjectReference: "prj_private_12",
  })],
  ["release fingerprint", (authority) => ({
    ...authority,
    releaseFingerprint: "release-status-b",
  })],
];

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe("execution-policy operator readiness", () => {
  it("requires the connected wallet to already be on Base Sepolia", () => {
    expect(executionPolicyOperatorReady(READY)).toBe(true);
    expect(executionPolicyOperatorReady({
      ...READY,
      walletOnBaseSepolia: false,
    })).toBe(false);
  });

  it("keeps both delegate mutations and reads behind the explicit chain check", () => {
    expect(safeguardsSource).toContain(
      "Switch the connected wallet to Base Sepolia before sending a policy bundle to the delegate.",
    );
    expect(safeguardsSource).toContain(
      "Switch the connected wallet to Base Sepolia before reading execution-policy status.",
    );
    expect(safeguardsSource).toContain('"Switch wallet to Base Sepolia"');
  });

  it("pins recovery to the exact wallet, provider session, chain, bearer, draft, and release", () => {
    const provider = {};
    const expected: ExecutionPolicyUiAuthorityContext = {
      walletAddress: "0x1111111111111111111111111111111111111111",
      walletProvider: provider,
      walletAuthorizationVersion: 7,
      chainId: 84_532,
      runtimeBearer: "runtime-session-a",
      surface: "compute_dispatch",
      resourceReference: "job-private-7",
      computeProjectReference: "prj_private_7",
      releaseFingerprint: "release-a",
    };

    expect(executionPolicyUiAuthorityIsCurrent(expected, { ...expected })).toBe(true);
    for (const current of [
      { ...expected, walletAddress: "0x2222222222222222222222222222222222222222" },
      { ...expected, walletProvider: {} },
      { ...expected, walletAuthorizationVersion: 8 },
      { ...expected, chainId: 1 },
      { ...expected, runtimeBearer: "runtime-session-b" },
      { ...expected, surface: "arena_execution" as const },
      { ...expected, resourceReference: "job-private-8" },
      { ...expected, computeProjectReference: "prj_private_8" },
      { ...expected, releaseFingerprint: "release-b" },
    ]) {
      expect(executionPolicyUiAuthorityIsCurrent(expected, current)).toBe(false);
    }
  });

  it("retains and locks the exact private intent until status reconciliation succeeds", () => {
    expect(safeguardsSource).toContain("onPreparedIntent: (intent)");
    expect(safeguardsSource).toContain("recoverExecutionPolicyWorkflow({");
    expect(safeguardsSource).toContain("setPendingPolicyRecovery(preparedThisAttempt)");
    expect(safeguardsSource).toContain(
      "Retry performs a status read before any byte-identical replay.",
    );
    expect(safeguardsSource).toContain("disabled={draftLocked()}");
    expect(safeguardsSource).toContain("if (completed) {");
    expect(safeguardsSource).toContain("clearTransientBundle();");
    expect(safeguardsSource).toContain(
      "No new expiry, signature, prior head, or policy append was created.",
    );
  });

  it("pins status reads to the exact wallet, release, surface, and private references", () => {
    expect(executionPolicyStatusReadAuthorityIsCurrent(
      STATUS_AUTHORITY,
      { ...STATUS_AUTHORITY },
    )).toBe(true);

    for (const [, change] of STATUS_AUTHORITY_DRIFTS) {
      expect(executionPolicyStatusReadAuthorityIsCurrent(
        STATUS_AUTHORITY,
        change(STATUS_AUTHORITY),
      )).toBe(false);
    }
  });

  it("rejects authority drift after deferred target resolution before reading status", async () => {
    const target = deferred<{ resourceId: string; executionContextHash: string }>();
    let current = STATUS_AUTHORITY;
    let statusReadStarted = false;
    const result = runExecutionPolicyStatusRead(STATUS_AUTHORITY, {
      currentAuthority: () => current,
      resolveTarget: async () => target.promise,
      readStatus: async () => {
        statusReadStarted = true;
        return "unexpected";
      },
    });

    current = { ...STATUS_AUTHORITY, walletProvider: {} };
    target.resolve({
      resourceId: "policy-resource-11",
      executionContextHash: "1".repeat(64),
    });

    await expect(result).rejects.toThrow(/changed during this lookup/);
    expect(statusReadStarted).toBe(false);
  });

  it("rejects every captured authority drift while the status response is deferred", async () => {
    for (const [label, change] of STATUS_AUTHORITY_DRIFTS) {
      let current = STATUS_AUTHORITY;
      const enteredStatusRead = deferred<void>();
      const statusResponse = deferred<string>();
      let assertCurrent: (() => void) | undefined;
      const result = runExecutionPolicyStatusRead(STATUS_AUTHORITY, {
        currentAuthority: () => current,
        resolveTarget: async (captured) => ({
          resourceId: captured.statusReference,
          executionContextHash: "2".repeat(64),
        }),
        readStatus: async (captured, target, assertAuthorityCurrent) => {
          expect(captured).toBe(STATUS_AUTHORITY);
          expect(target.resourceId).toBe(STATUS_AUTHORITY.statusReference);
          assertCurrent = assertAuthorityCurrent;
          enteredStatusRead.resolve();
          return statusResponse.promise;
        },
      });

      await enteredStatusRead.promise;
      current = change(STATUS_AUTHORITY);
      expect(
        () => assertCurrent?.(),
        `${label} must invalidate the in-flight transport authority`,
      ).toThrow(/changed during this lookup/);
      statusResponse.resolve("stale-status");
      await expect(
        result,
        `${label} must prevent a stale status from being published`,
      ).rejects.toThrow(/changed during this lookup/);
    }
  });

  it("locks status inputs and never clears a newer private reference", () => {
    expect(safeguardsSource).toContain(
      '<form aria-busy={busy() === "status"}',
    );
    expect(safeguardsSource).toMatch(
      /value=\{computeStatusProjectReference\(\)\}\s+disabled=\{Boolean\(busy\(\)\)\}/,
    );
    expect(safeguardsSource).toMatch(
      /value=\{statusReference\(\)\}\s+disabled=\{Boolean\(busy\(\)\)\}/,
    );
    expect(safeguardsSource).toContain(
      "if (statusReference() === authority.statusReference)",
    );
    expect(safeguardsSource).toContain(
      "=== authority.computeStatusProjectReference",
    );
  });
});
