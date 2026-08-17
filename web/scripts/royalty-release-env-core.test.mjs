import assert from "node:assert/strict";
import test from "node:test";

import {
  royaltyReleasePolicyCommitment,
} from "../../scripts/royalty-release-authority-core.mjs";
import {
  normalizeRoyaltyReleaseBrowserEnv,
  projectRoyaltyReleaseBrowserEnv,
} from "./royalty-release-env-core.mjs";

function fixture() {
  const royalty = "0x1111111111111111111111111111111111111111";
  const owner = "0x2222222222222222222222222222222222222222";
  const settlement = "0x3333333333333333333333333333333333333333";
  const qvl = "0x4444444444444444444444444444444444444444";
  const anchor = "0x5555555555555555555555555555555555555555";
  const writer = "0x6666666666666666666666666666666666666666";
  const writerRelease = `0x${"77".repeat(32)}`;
  const zeroAddress = `0x${"0".repeat(40)}`;
  const zeroBytes32 = `0x${"0".repeat(64)}`;
  const policy = royaltyReleasePolicyCommitment({
    chainId: 84532,
    distributorAddress: royalty,
    authorityNonce: 1,
    settlementVerifier: settlement,
    qvlVerifier: qvl,
    executionPolicyAnchor: anchor,
    anchorWriterReleaseCommitment: writerRelease,
  });
  const authority = {
    schema: "dnai.royalty-release-authority.v1",
    chain_id: 84532,
    distributor_address: royalty,
    owner,
    settlement_verifier: settlement,
    qvl_verifier: qvl,
    execution_policy_anchor: anchor,
    anchor_writer: writer,
    anchor_writer_release_commitment: writerRelease,
    authority_nonce: 1,
    authority_timelock_seconds: 172800,
    release_policy_commitment: policy,
  };
  const state = {
    schema: "dnai.royalty-release-state.v1",
    chain_id: 84532,
    contract_address: royalty,
    block_number: 123456,
    block_hash: `0x${"88".repeat(32)}`,
    block_timestamp: 1_800_000_000,
    owner,
    pending_owner: zeroAddress,
    paused: false,
    settlement_verifier: settlement,
    qvl_verifier: qvl,
    execution_policy_anchor: anchor,
    anchor_writer_release_commitment: writerRelease,
    release_policy_commitment: policy,
    authority_nonce: 1,
    pending_settlement_verifier: zeroAddress,
    pending_qvl_verifier: zeroAddress,
    pending_execution_policy_anchor: zeroAddress,
    pending_anchor_writer_release_commitment: zeroBytes32,
    pending_release_policy_commitment: zeroBytes32,
    pending_authority_nonce: 0,
    pending_authority_activates_at: 0,
    pending_authority_revocation: false,
    settlement_verifier_ever_configured: true,
    qvl_verifier_ever_configured: true,
    anchor_writer_ever_configured: true,
    computed_release_policy_commitment: policy,
  };
  return {
    env: {
      VITE_ROYALTY_RELEASE_AUTHORITY_JSON: JSON.stringify(authority),
      VITE_ROYALTY_RELEASE_ACTIVE_STATE_JSON: JSON.stringify(state),
      VITE_ROYALTY_RELEASE_HISTORY_SHA256: `sha256:${"99".repeat(32)}`,
      VITE_ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256: `sha256:${"aa".repeat(32)}`,
      VITE_ROYALTY_DISTRIBUTOR_ADDRESS: royalty,
      VITE_ROYALTY_DISTRIBUTOR_CODE_HASH: `0x${"bb".repeat(32)}`,
      VITE_EXECUTION_POLICY_ANCHOR_ADDRESS: anchor,
      VITE_EXECUTION_POLICY_ANCHOR_WRITER: writer,
      VITE_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT: writerRelease,
    },
  };
}

test("rejects a noncanonical H before public Royalty projection", () => {
  assert.throws(
    () => projectRoyaltyReleaseBrowserEnv({}),
    /receipt|schema|object|fields/i,
  );
});

test("Cloudflare-facing normalization fails closed on absent, paused, pending, or mismatched authority", () => {
  const value = fixture();
  const valid = normalizeRoyaltyReleaseBrowserEnv(value.env);
  assert.equal(valid.authority.owner, JSON.parse(
    value.env.VITE_ROYALTY_RELEASE_AUTHORITY_JSON,
  ).owner);
  assert.notEqual(valid.historySha256, valid.historyReceiptSha256);
  const mutations = [
    (env) => { delete env.VITE_ROYALTY_RELEASE_HISTORY_SHA256; },
    (env) => { env.VITE_ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256 = env.VITE_ROYALTY_RELEASE_HISTORY_SHA256; },
    (env) => {
      const state = JSON.parse(env.VITE_ROYALTY_RELEASE_ACTIVE_STATE_JSON);
      state.paused = true;
      env.VITE_ROYALTY_RELEASE_ACTIVE_STATE_JSON = JSON.stringify(state);
    },
    (env) => {
      const state = JSON.parse(env.VITE_ROYALTY_RELEASE_ACTIVE_STATE_JSON);
      state.pending_owner = `0x${"a".repeat(40)}`;
      env.VITE_ROYALTY_RELEASE_ACTIVE_STATE_JSON = JSON.stringify(state);
    },
    (env) => { env.VITE_ROYALTY_DISTRIBUTOR_ADDRESS = `0x${"b".repeat(40)}`; },
    (env) => { env.VITE_EXECUTION_POLICY_ANCHOR_ADDRESS = `0x${"c".repeat(40)}`; },
    (env) => { env.VITE_EXECUTION_POLICY_ANCHOR_WRITER = `0x${"d".repeat(40)}`; },
  ];
  for (const mutate of mutations) {
    const env = structuredClone(value.env);
    mutate(env);
    assert.throws(() => normalizeRoyaltyReleaseBrowserEnv(env));
  }
});
