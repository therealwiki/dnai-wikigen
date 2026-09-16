import { describe, expect, it } from "vitest";
import {
  COLLABORATION_EXECUTION_RELEASE_PROFILE,
  COLLABORATION_EXECUTION_RELEASE_SERVICE,
  parseCollaborationExecutionReleaseConfig,
} from "./collaborationExecutionReleaseConfig";
import {
  parseRoyaltyReleaseConfiguration,
  royaltyReleasePolicyCommitment,
  ROYALTY_RELEASE_ZERO_ADDRESS,
  ROYALTY_RELEASE_ZERO_BYTES32,
  type RoyaltyReleaseActiveState,
  type RoyaltyReleaseAuthority,
} from "./royaltyReleaseAuthority";

const address = (byte: string) => `0x${byte.repeat(40)}` as const;
const bytes32 = (byte: string) => `0x${byte.repeat(64)}` as const;
const pin = (byte: string) => `sha256:${byte.repeat(64)}` as const;
const RELEASE_SHA = "1".repeat(40);
const CVM_ID = "cvm-main-runtime-0001";

function fixture() {
  const authority = {
    schema: "dnai.royalty-release-authority.v1",
    chain_id: 84532,
    distributor_address: address("1"),
    owner: address("2"),
    settlement_verifier: address("3"),
    qvl_verifier: address("4"),
    execution_policy_anchor: address("5"),
    anchor_writer: address("6"),
    anchor_writer_release_commitment: bytes32("7"),
    authority_nonce: 1,
    authority_timelock_seconds: 172800,
    release_policy_commitment: "" as `0x${string}`,
  } satisfies RoyaltyReleaseAuthority;
  authority.release_policy_commitment = royaltyReleasePolicyCommitment({
    chainId: authority.chain_id,
    distributorAddress: authority.distributor_address,
    authorityNonce: authority.authority_nonce,
    settlementVerifier: authority.settlement_verifier,
    qvlVerifier: authority.qvl_verifier,
    executionPolicyAnchor: authority.execution_policy_anchor,
    anchorWriterReleaseCommitment: authority.anchor_writer_release_commitment,
  });
  const activeState = {
    schema: "dnai.royalty-release-state.v1",
    chain_id: 84532,
    contract_address: authority.distributor_address,
    block_number: 123456,
    block_hash: bytes32("8"),
    block_timestamp: 1785000000,
    owner: authority.owner,
    pending_owner: ROYALTY_RELEASE_ZERO_ADDRESS,
    paused: false,
    settlement_verifier: authority.settlement_verifier,
    qvl_verifier: authority.qvl_verifier,
    execution_policy_anchor: authority.execution_policy_anchor,
    anchor_writer_release_commitment: authority.anchor_writer_release_commitment,
    release_policy_commitment: authority.release_policy_commitment,
    authority_nonce: 1,
    pending_settlement_verifier: ROYALTY_RELEASE_ZERO_ADDRESS,
    pending_qvl_verifier: ROYALTY_RELEASE_ZERO_ADDRESS,
    pending_execution_policy_anchor: ROYALTY_RELEASE_ZERO_ADDRESS,
    pending_anchor_writer_release_commitment: ROYALTY_RELEASE_ZERO_BYTES32,
    pending_release_policy_commitment: ROYALTY_RELEASE_ZERO_BYTES32,
    pending_authority_nonce: 0,
    pending_authority_activates_at: 0,
    pending_authority_revocation: false,
    settlement_verifier_ever_configured: true,
    qvl_verifier_ever_configured: true,
    anchor_writer_ever_configured: true,
    computed_release_policy_commitment: authority.release_policy_commitment,
  } satisfies RoyaltyReleaseActiveState;
  const env: Record<string, string> = {
    VITE_FINAL_RELEASE_AUTHORITY_SHA256: pin("a"),
    VITE_COLLABORATION_EXECUTION_RELEASE_VERIFICATION_SHA256: pin("b"),
    VITE_COLLABORATION_EXECUTION_SERVICE:
      COLLABORATION_EXECUTION_RELEASE_SERVICE,
    VITE_COLLABORATION_EXECUTION_PROFILE:
      COLLABORATION_EXECUTION_RELEASE_PROFILE,
    VITE_COLLABORATION_EXECUTION_RELEASE_SHA: RELEASE_SHA,
    VITE_COLLABORATION_EXECUTION_MAIN_RUNTIME_CVM_ID: CVM_ID,
    VITE_COLLABORATION_EXECUTION_ENABLED: "true",
    VITE_ROYALTY_RELEASE_ACTIVE_STATE_SHA256: pin("c"),
    VITE_ROYALTY_RELEASE_HISTORY_SHA256: pin("d"),
    VITE_ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256: pin("e"),
    VITE_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED: "true",
    VITE_ROYALTY_RELEASE_AUTHORITY_JSON: JSON.stringify(authority),
    VITE_ROYALTY_RELEASE_ACTIVE_STATE_JSON: JSON.stringify(activeState),
  };
  const royaltyRelease = parseRoyaltyReleaseConfiguration(env);
  return { env, royaltyRelease };
}

describe("Collaboration execution current release config", () => {
  it("accepts only the complete v4 release projection and makes no runtime proof claim", () => {
    const value = fixture();
    expect(parseCollaborationExecutionReleaseConfig(value.env, {
      releaseSha: RELEASE_SHA,
      mainRuntimeCvmId: CVM_ID,
      collaborationEnabled: true,
      royaltyRelease: value.royaltyRelease,
    })).toEqual(expect.objectContaining({
      configured: true,
      service: COLLABORATION_EXECUTION_RELEASE_SERVICE,
      profile: COLLABORATION_EXECUTION_RELEASE_PROFILE,
      walletAdoptionEnabled: true,
      executionEnabled: true,
      workerPresenceProven: false,
      tdxAttestationClaimed: false,
      qvlVerified: false,
      truthStatus: "release-configured",
    }));
  });

  it.each([
    ["partial", (env: Record<string, string>) => { delete env.VITE_FINAL_RELEASE_AUTHORITY_SHA256; }],
    ["service", (env: Record<string, string>) => { env.VITE_COLLABORATION_EXECUTION_SERVICE = "other"; }],
    ["wallet decision", (env: Record<string, string>) => { env.VITE_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED = "invalid"; }],
    ["H drift", (env: Record<string, string>) => { env.VITE_ROYALTY_RELEASE_HISTORY_SHA256 = pin("f"); }],
    ["digest collapse", (env: Record<string, string>) => { env.VITE_FINAL_RELEASE_AUTHORITY_SHA256 = pin("b"); }],
  ])("fails closed for %s", (_label, mutate) => {
    const value = fixture();
    mutate(value.env);
    expect(parseCollaborationExecutionReleaseConfig(value.env, {
      releaseSha: RELEASE_SHA,
      mainRuntimeCvmId: CVM_ID,
      collaborationEnabled: true,
      royaltyRelease: value.royaltyRelease,
    }).configured).toBe(false);
  });

  it("keeps signed false execution and wallet-adoption decisions valid but disabled", () => {
    const value = fixture();
    value.env.VITE_COLLABORATION_EXECUTION_ENABLED = "false";
    value.env.VITE_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED = "false";
    expect(parseCollaborationExecutionReleaseConfig(value.env, {
      releaseSha: RELEASE_SHA,
      mainRuntimeCvmId: CVM_ID,
      collaborationEnabled: false,
      royaltyRelease: value.royaltyRelease,
    })).toMatchObject({
      configured: true,
      executionEnabled: false,
      walletAdoptionEnabled: false,
    });
  });

  it("keeps rooms configured while the independent execution decision is disabled", () => {
    const value = fixture();
    value.env.VITE_COLLABORATION_EXECUTION_ENABLED = "false";
    expect(parseCollaborationExecutionReleaseConfig(value.env, {
      releaseSha: RELEASE_SHA,
      mainRuntimeCvmId: CVM_ID,
      collaborationEnabled: true,
      royaltyRelease: value.royaltyRelease,
    })).toMatchObject({
      configured: true,
      executionEnabled: false,
    });
  });

  it("rejects enabled execution when the broader Collaboration dependency is disabled", () => {
    const value = fixture();
    expect(parseCollaborationExecutionReleaseConfig(value.env, {
      releaseSha: RELEASE_SHA,
      mainRuntimeCvmId: CVM_ID,
      collaborationEnabled: false,
      royaltyRelease: value.royaltyRelease,
    })).toMatchObject({
      configured: false,
      executionEnabled: true,
    });
  });

  it("keeps wallet-origin control-plane release valid when credential adoption is disabled", () => {
    const value = fixture();
    value.env.VITE_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED = "false";
    expect(parseCollaborationExecutionReleaseConfig(value.env, {
      releaseSha: RELEASE_SHA,
      mainRuntimeCvmId: CVM_ID,
      collaborationEnabled: true,
      royaltyRelease: value.royaltyRelease,
    })).toMatchObject({
      configured: true,
      executionEnabled: true,
      walletAdoptionEnabled: false,
      workerPresenceProven: false,
      tdxAttestationClaimed: false,
      qvlVerified: false,
    });
  });

  it("keeps historical or absent builds closed", () => {
    expect(parseCollaborationExecutionReleaseConfig({}, {
      collaborationEnabled: true,
      royaltyRelease: parseRoyaltyReleaseConfiguration({}),
    })).toMatchObject({
      configured: false,
      workerPresenceProven: false,
      tdxAttestationClaimed: false,
      qvlVerified: false,
    });
  });
});
