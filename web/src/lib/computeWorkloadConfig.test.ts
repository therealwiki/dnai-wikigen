import { describe, expect, it } from "vitest";
import { parseComputeWorkloadConfig } from "./computeWorkloadConfig";

const hash = `0x${"11".repeat(32)}`;
const env = {
  VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD: "true",
  VITE_COMPUTE_WORKLOAD_QVL_VERIFIER: `0x${"22".repeat(20)}`,
  VITE_COMPUTE_WORKLOAD_CVM_ID: "main-runtime-cvm-0001",
  VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256: `sha256:${"23".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256: `sha256:${"24".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE: `0x${"25".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256: `sha256:${"26".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256: `sha256:${"27".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256: `sha256:${"28".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH: hash,
  VITE_COMPUTE_WORKLOAD_COMPOSE_HASH: `0x${"33".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_APP_ID: "aa".repeat(20),
  VITE_COMPUTE_WORKLOAD_OS_IMAGE_HASH: "44".repeat(32),
  VITE_COMPUTE_WORKLOAD_ACTIVATION_SIGNER: `0x${"55".repeat(20)}`,
  VITE_COMPUTE_WORKLOAD_CHAIN_ID: "84532",
  VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS: `0x${"66".repeat(20)}`,
  VITE_COMPUTE_WORKLOAD_VAULT_RUNTIME_CODE_HASH: `0x${"67".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256: `0x${"68".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MAX_VERDICT_AGE_SECONDS: "120",
  VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON: JSON.stringify([
    `0x${"77".repeat(32)}`,
    `0x${"88".repeat(32)}`,
  ]),
};

describe("Compute workload release configuration", () => {
  it("builds one exact Base Sepolia trust policy only from the complete dedicated group", () => {
    const parsed = parseComputeWorkloadConfig(env);
    expect(parsed.configured).toBe(true);
    expect(parsed.issues).toEqual([]);
    expect(parsed.trustPolicy).toEqual({
      trustedVerifierAddresses: [env.VITE_COMPUTE_WORKLOAD_QVL_VERIFIER],
      cvmId: env.VITE_COMPUTE_WORKLOAD_CVM_ID,
      deploymentIntentSha256: env.VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256,
      releaseAuthoritySha256: env.VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256,
      ceremonyNonce: env.VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE,
      measurementPolicySetSha256: env.VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256,
      measurementPolicySha256: env.VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256,
      mainRuntimeEvidenceSha256: env.VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256,
      releasePolicyHash: env.VITE_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH,
      composeHash: env.VITE_COMPUTE_WORKLOAD_COMPOSE_HASH,
      appId: env.VITE_COMPUTE_WORKLOAD_APP_ID,
      osImageHash: env.VITE_COMPUTE_WORKLOAD_OS_IMAGE_HASH,
      activationSignerAddress: env.VITE_COMPUTE_WORKLOAD_ACTIVATION_SIGNER,
      chainId: 84_532,
      contractAddress: env.VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS,
      vaultRuntimeCodeHash: env.VITE_COMPUTE_WORKLOAD_VAULT_RUNTIME_CODE_HASH,
      freshDeploymentReceiptSha256: env.VITE_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256,
      maxVerdictAgeSeconds: 120,
      revokedQuoteHashes: JSON.parse(env.VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON),
    });
  });

  it("keeps the surface modeled when its explicit upload gate is off", () => {
    const parsed = parseComputeWorkloadConfig({});
    expect(parsed).toEqual({
      enabled: false,
      configured: false,
      trustPolicy: undefined,
      issues: [],
    });
  });

  it("fails closed on partial trust material even when the enable flag is absent", () => {
    const parsed = parseComputeWorkloadConfig({
      VITE_COMPUTE_WORKLOAD_QVL_VERIFIER: env.VITE_COMPUTE_WORKLOAD_QVL_VERIFIER,
    });
    expect(parsed.configured).toBe(false);
    expect(parsed.issues).toContain(
      "VITE_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH is required by the enabled Compute workload gate",
    );
  });

  it.each([
    ["wrong chain", { VITE_COMPUTE_WORKLOAD_CHAIN_ID: "8453" }, /exactly 84532/],
    ["noncanonical CVM id", { VITE_COMPUTE_WORKLOAD_CVM_ID: "Main-Runtime-CVM-0001" }, /canonical lowercase CVM id/],
    ["zero deployment intent", { VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256: `sha256:${"00".repeat(32)}` }, /nonzero canonical lowercase sha256 pin/],
    ["uppercase release authority", { VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256: `sha256:${"AB".repeat(32)}` }, /canonical lowercase sha256 pin/],
    ["uppercase ceremony nonce", { VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE: `0x${"AB".repeat(32)}` }, /canonical lowercase 32-byte/],
    ["zero verifier", { VITE_COMPUTE_WORKLOAD_QVL_VERIFIER: `0x${"00".repeat(20)}` }, /nonzero/],
    ["zero policy", { VITE_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH: `0x${"00".repeat(32)}` }, /nonzero/],
    ["arbitrary printable app id", { VITE_COMPUTE_WORKLOAD_APP_ID: "workload-recipient-production" }, /bare 40-hex/],
    ["prefixed OS hash", { VITE_COMPUTE_WORKLOAD_OS_IMAGE_HASH: hash }, /without 0x/],
    ["long freshness", { VITE_COMPUTE_WORKLOAD_MAX_VERDICT_AGE_SECONDS: "301" }, /1 through 300/],
    [
      "unsorted revocations",
      { VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON: JSON.stringify([`0x${"88".repeat(32)}`, `0x${"77".repeat(32)}`]) },
      /strictly sorted/,
    ],
  ])("rejects %s instead of weakening the workload release gate", (_label, mutation, message) => {
    const parsed = parseComputeWorkloadConfig({ ...env, ...mutation });
    expect(parsed.configured).toBe(false);
    expect(parsed.issues.join(" ")).toMatch(message);
  });

  it("requires every O-derived ceremony-lineage pin as one indivisible group", () => {
    for (const key of [
      "VITE_COMPUTE_WORKLOAD_CVM_ID",
      "VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256",
      "VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
      "VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE",
      "VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256",
      "VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256",
      "VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256",
    ] as const) {
      const partial = { ...env } as Record<string, string>;
      delete partial[key];
      const parsed = parseComputeWorkloadConfig(partial);
      expect(parsed.configured, key).toBe(false);
      expect(parsed.issues.join(" "), key).toContain(`${key} is required`);
    }
  });

  it("does not reuse a metering or diligence trust root", () => {
    const parsed = parseComputeWorkloadConfig({
      VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD: "true",
      VITE_COMPUTE_VAULT_METERING_VERIFIER: env.VITE_COMPUTE_WORKLOAD_QVL_VERIFIER,
      VITE_DILIGENCE_ATTESTATION_VERIFIER: env.VITE_COMPUTE_WORKLOAD_QVL_VERIFIER,
    });
    expect(parsed.configured).toBe(false);
    expect(parsed.trustPolicy).toBeUndefined();
    expect(parsed.issues).toContain(
      "VITE_COMPUTE_WORKLOAD_QVL_VERIFIER is required by the enabled Compute workload gate",
    );
  });

  it("rejects the ambiguous legacy execution-signer key without an alias", () => {
    const parsed = parseComputeWorkloadConfig({
      ...env,
      VITE_COMPUTE_WORKLOAD_EXECUTION_SIGNER: env.VITE_COMPUTE_WORKLOAD_ACTIVATION_SIGNER,
    });
    expect(parsed.configured).toBe(false);
    expect(parsed.issues).toContain(
      "VITE_COMPUTE_WORKLOAD_EXECUTION_SIGNER is rejected legacy; use the C-projected workload activation signer only",
    );
    expect(parseComputeWorkloadConfig({
      ...env,
      VITE_COMPUTE_WORKLOAD_EXECUTION_SIGNER: "",
    }).configured).toBe(false);
  });

  it("keeps an explicit empty revocation list inert while the feature gate is off", () => {
    expect(parseComputeWorkloadConfig({
      VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD: "false",
      VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON: "[]",
    })).toEqual({
      enabled: false,
      configured: false,
      trustPolicy: undefined,
      issues: [],
    });
  });

  it("requires the QVL verifier and activation signer to be purpose-separated", () => {
    const parsed = parseComputeWorkloadConfig({
      ...env,
      VITE_COMPUTE_WORKLOAD_ACTIVATION_SIGNER: env.VITE_COMPUTE_WORKLOAD_QVL_VERIFIER,
    });
    expect(parsed.configured).toBe(false);
    expect(parsed.issues.join(" ")).toMatch(/must be distinct/);
  });
});
