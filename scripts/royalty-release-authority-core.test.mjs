import assert from "node:assert/strict";
import test from "node:test";

import {
  ROYALTY_AUTHORITY_TIMELOCK_SECONDS,
  ROYALTY_INITIAL_AUTHORITY_NONCE,
  ROYALTY_RELEASE_AUTHORITY_SCHEMA,
  ROYALTY_RELEASE_POLICY_TYPEHASH,
  normalizeRoyaltyReleaseAuthority,
  royaltyReleasePolicyCommitment,
} from "./royalty-release-authority-core.mjs";

const address = (byte) => `0x${byte.padStart(2, "0").repeat(20)}`;
const bytes32 = (byte) => `0x${byte.padStart(2, "0").repeat(32)}`;

function authorityFixture() {
  const authority = {
    schema: ROYALTY_RELEASE_AUTHORITY_SCHEMA,
    chain_id: 84_532,
    distributor_address:
      "0x5fbdb2315678afecb367f032d93f642f64180aa3",
    owner: address("1"),
    settlement_verifier: address("3"),
    qvl_verifier: address("4"),
    execution_policy_anchor: address("5"),
    anchor_writer: address("6"),
    anchor_writer_release_commitment: bytes32("7"),
    authority_nonce: ROYALTY_INITIAL_AUTHORITY_NONCE,
    authority_timelock_seconds: ROYALTY_AUTHORITY_TIMELOCK_SECONDS,
    release_policy_commitment: "",
  };
  authority.release_policy_commitment = royaltyReleasePolicyCommitment({
    chainId: authority.chain_id,
    distributorAddress: authority.distributor_address,
    authorityNonce: authority.authority_nonce,
    settlementVerifier: authority.settlement_verifier,
    qvlVerifier: authority.qvl_verifier,
    executionPolicyAnchor: authority.execution_policy_anchor,
    anchorWriterReleaseCommitment:
      authority.anchor_writer_release_commitment,
  });
  return authority;
}

test("Royalty release-policy commitment matches the fixed Solidity KAT", () => {
  const authority = authorityFixture();
  assert.equal(
    ROYALTY_RELEASE_POLICY_TYPEHASH,
    "0x52ea595bfb36fbea11956e81e6cc1e6c8a72e57f6a45045c1b75494cd35cae3d",
  );
  assert.equal(
    authority.release_policy_commitment,
    "0xbae0498d891d1311e094e6d56860debeb7db162c773c247f94f270c79fe38679",
  );
  assert.deepEqual(normalizeRoyaltyReleaseAuthority(authority), authority);
});

test("every pair of Royalty release roles must remain distinct", () => {
  const roleFields = [
    "distributor_address",
    "owner",
    "settlement_verifier",
    "qvl_verifier",
    "execution_policy_anchor",
    "anchor_writer",
  ];
  let pairCount = 0;
  for (let left = 0; left < roleFields.length; left += 1) {
    for (let right = left + 1; right < roleFields.length; right += 1) {
      pairCount += 1;
      const authority = authorityFixture();
      authority[roleFields[right]] = authority[roleFields[left]];
      assert.throws(
        () => normalizeRoyaltyReleaseAuthority(authority),
        /must be distinct/,
        `${roleFields[left]} must not alias ${roleFields[right]}`,
      );
    }
  }
  assert.equal(pairCount, 15);
});

test("Royalty release authority is exact, canonical, and commitment-bound", () => {
  const withExtraField = { ...authorityFixture(), attacker: true };
  assert.throws(
    () => normalizeRoyaltyReleaseAuthority(withExtraField),
    /exact schema/,
  );

  const uppercase = authorityFixture();
  uppercase.distributor_address = uppercase.distributor_address
    .toUpperCase()
    .replace("0X", "0x");
  assert.throws(
    () => normalizeRoyaltyReleaseAuthority(uppercase),
    /canonical nonzero address/,
  );

  const policyDrift = authorityFixture();
  policyDrift.release_policy_commitment = bytes32("f");
  assert.throws(
    () => normalizeRoyaltyReleaseAuthority(policyDrift),
    /does not match the Solidity typed commitment/,
  );

  const nonceDrift = authorityFixture();
  nonceDrift.authority_nonce = 2;
  assert.throws(
    () => normalizeRoyaltyReleaseAuthority(nonceDrift),
    /authority nonce/,
  );

  const timelockDrift = authorityFixture();
  timelockDrift.authority_timelock_seconds -= 1;
  assert.throws(
    () => normalizeRoyaltyReleaseAuthority(timelockDrift),
    /authority timelock/,
  );
});
