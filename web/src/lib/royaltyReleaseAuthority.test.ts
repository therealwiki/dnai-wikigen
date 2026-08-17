import { describe, expect, it } from "vitest";
import {
  normalizeRoyaltyReleaseActiveStateBrowser,
  normalizeRoyaltyReleaseAuthorityBrowser,
  parseRoyaltyReleaseConfiguration,
  royaltyReleasePolicyCommitment,
  ROYALTY_RELEASE_ZERO_ADDRESS,
  ROYALTY_RELEASE_ZERO_BYTES32,
  type RoyaltyReleaseActiveState,
  type RoyaltyReleaseAuthority,
} from "./royaltyReleaseAuthority";

const address = (byte: string) => `0x${byte.repeat(40)}` as const;
const bytes32 = (byte: string) => `0x${byte.repeat(64)}` as const;

function fixture(): {
  authority: RoyaltyReleaseAuthority;
  activeState: RoyaltyReleaseActiveState;
  env: Record<string, string>;
} {
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
  return {
    authority,
    activeState,
    env: {
      VITE_ROYALTY_RELEASE_AUTHORITY_JSON: JSON.stringify(authority),
      VITE_ROYALTY_RELEASE_ACTIVE_STATE_JSON: JSON.stringify(activeState),
      VITE_ROYALTY_RELEASE_HISTORY_SHA256: `sha256:${"9".repeat(64)}`,
      VITE_ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256: `sha256:${"a".repeat(64)}`,
    },
  };
}

describe("Royalty release browser authority", () => {
  it("accepts the exact phase-two authority and clear-pending poststate", () => {
    const value = fixture();
    expect(normalizeRoyaltyReleaseAuthorityBrowser(value.authority)).toEqual(value.authority);
    expect(normalizeRoyaltyReleaseActiveStateBrowser(
      value.activeState,
      value.authority,
    )).toEqual(value.activeState);
    expect(parseRoyaltyReleaseConfiguration(value.env)).toMatchObject({
      configured: true,
      authority: value.authority,
      activeState: value.activeState,
      releaseEvidenceModel: "dual_rpc_history_H",
    });
  });

  it("fails closed for absent or partial release evidence", () => {
    expect(parseRoyaltyReleaseConfiguration({})).toMatchObject({
      configured: false,
      issues: ["Royalty dual-RPC release history is not configured"],
    });
    const { env } = fixture();
    delete env.VITE_ROYALTY_RELEASE_ACTIVE_STATE_JSON;
    expect(parseRoyaltyReleaseConfiguration(env)).toMatchObject({
      configured: false,
      issues: ["Royalty release authority, active state, history digest, and H receipt digest must be configured together"],
    });
  });

  it.each([
    ["paused", (value: ReturnType<typeof fixture>) => { Object.assign(value.activeState, { paused: true }); }],
    ["pending owner", (value: ReturnType<typeof fixture>) => { Object.assign(value.activeState, { pending_owner: address("a") }); }],
    ["pending verifier", (value: ReturnType<typeof fixture>) => { Object.assign(value.activeState, { pending_settlement_verifier: address("a") }); }],
    ["pending nonce", (value: ReturnType<typeof fixture>) => { Object.assign(value.activeState, { pending_authority_nonce: 2 }); }],
    ["authority mismatch", (value: ReturnType<typeof fixture>) => { Object.assign(value.activeState, { qvl_verifier: address("a") }); }],
    ["computed policy mismatch", (value: ReturnType<typeof fixture>) => { Object.assign(value.activeState, { computed_release_policy_commitment: bytes32("a") }); }],
    ["history absent", (value: ReturnType<typeof fixture>) => { value.env.VITE_ROYALTY_RELEASE_HISTORY_SHA256 = ""; }],
  ])("rejects %s mutation", (_label, mutate) => {
    const value = fixture();
    mutate(value);
    value.env.VITE_ROYALTY_RELEASE_AUTHORITY_JSON = JSON.stringify(value.authority);
    value.env.VITE_ROYALTY_RELEASE_ACTIVE_STATE_JSON = JSON.stringify(value.activeState);
    expect(parseRoyaltyReleaseConfiguration(value.env).configured).toBe(false);
  });

  it("rejects extra fields and a typed release-policy mutation", () => {
    const value = fixture();
    const extra = { ...value.authority, attacker: true };
    expect(() => normalizeRoyaltyReleaseAuthorityBrowser(extra)).toThrow(/exact schema/);
    const changed = { ...value.authority, release_policy_commitment: bytes32("f") };
    expect(() => normalizeRoyaltyReleaseAuthorityBrowser(changed)).toThrow(/does not recompute/);
  });
});
