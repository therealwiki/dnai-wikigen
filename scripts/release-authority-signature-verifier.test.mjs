import assert from "node:assert/strict";
import test from "node:test";

import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";

import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  canonicalLowSEip191Signature,
  eip191AuthorizationSigningDigest,
  eip191AuthorizationSigningMessage,
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  normalizeExpectedReviewerAuthority,
  reviewerSetSha256,
  verifyPinnedTwoSignerAuthorization,
} from "./release-authority-signature-verifier.mjs";
import {
  normalizeExpectedReviewerAuthority as normalizeExpectedReviewerAuthorityCore,
} from "./release-authority-signature-verifier-core.mjs";

const ALPHA = privateKeyToAccount(`0x${"11".repeat(32)}`);
const BRAVO = privateKeyToAccount(`0x${"22".repeat(32)}`);
const FORGED = privateKeyToAccount(`0x${"33".repeat(32)}`);
const SECP256K1_N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

function reviewer(address, controllerId) {
  return { address: address.toLowerCase(), controller_id: controllerId };
}

function fixture() {
  const approvedReviewers = [
    reviewer(ALPHA.address, "reviewer-alpha"),
    reviewer(BRAVO.address, "reviewer-bravo"),
  ].sort((left, right) => left.address.localeCompare(right.address));
  const hashes = approvedReviewers.map((entry) => executionPolicyReviewerHash(entry.address)).sort();
  const root = executionPolicyReviewerRootHash(hashes);
  const setSha = reviewerSetSha256(approvedReviewers);
  const authorityValue = {
    approved_reviewers: approvedReviewers,
    approved_reviewer_hashes: hashes,
    reviewer_root_hash: root,
    reviewer_set_sha256: setSha,
  };
  const authority = normalizeExpectedReviewerAuthority(authorityValue, {
    expectedReviewerRootHash: root,
    expectedReviewerSetSha256: setSha,
  });
  const payload = {
    schema: "dnai.test-two-signer-authorization.v1",
    release_sha: "0123456789abcdef0123456789abcdef01234567",
    chain_id: 84_532,
    subject_sha256: `sha256:${"12".repeat(32)}`,
  };
  const digest = eip191AuthorizationSigningDigest({
    domain: "dnai-wikigen/test-two-signer-authorization/v1\0",
    payload,
  });
  const message = eip191AuthorizationSigningMessage({
    prefix: "dnai-wikigen test two-signer authorization v1:",
    digest,
  });
  return { approvedReviewers, authority, authorityValue, digest, message, payload, root, setSha };
}

async function signatures(message, accounts = [ALPHA, BRAVO], identities = null) {
  const values = identities ?? [
    reviewer(ALPHA.address, "reviewer-alpha"),
    reviewer(BRAVO.address, "reviewer-bravo"),
  ];
  const results = await Promise.all(accounts.map((account) => account.signMessage({ message })));
  return values.map((identity, index) => ({
    ...identity,
    signature: results[index].toLowerCase(),
  })).sort((left, right) => left.address.localeCompare(right.address));
}

function highS(signature) {
  const r = signature.slice(2, 66);
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  const malleated = (SECP256K1_N - s).toString(16).padStart(64, "0");
  const v = signature.slice(130) === "1b" ? "1c" : "1b";
  return `0x${r}${malleated}${v}`;
}

test("shared verifier accepts two sorted low-s signatures under transitive pins", async () => {
  const value = fixture();
  const signed = await signatures(value.message);
  const evidence = verifyPinnedTwoSignerAuthorization({
    signatures: signed,
    message: value.message,
    reviewerAuthority: value.authority,
  });
  assert.equal(evidence.signature_scheme, PINNED_EIP191_SIGNATURE_SCHEME);
  assert.deepEqual(evidence.signature_verifier, PINNED_CAST_SIGNATURE_VERIFIER);
  assert.equal(evidence.signer_count, 2);
  assert.equal(evidence.reviewer_root_hash, value.root);
  assert.equal(evidence.reviewer_set_sha256, value.setSha);
  assert.equal(evidence.signers.every((entry) => !Object.hasOwn(entry, "signature")), true);
  const unbranded = normalizeExpectedReviewerAuthorityCore(value.authorityValue, {
    expectedReviewerRootHash: value.root,
    expectedReviewerSetSha256: value.setSha,
  });
  assert.throws(() => verifyPinnedTwoSignerAuthorization({
    signatures: signed,
    message: value.message,
    reviewerAuthority: unbranded,
  }), /transitively pinned reviewer authority/);
});

test("artifact-local self-selected roots fail without matching transitive pins", () => {
  const value = fixture();
  const forgedReviewers = [
    reviewer(FORGED.address, "reviewer-forged"),
    reviewer(BRAVO.address, "reviewer-bravo"),
  ].sort((left, right) => left.address.localeCompare(right.address));
  const forgedHashes = forgedReviewers.map((entry) => executionPolicyReviewerHash(entry.address)).sort();
  const forgedValue = {
    approved_reviewers: forgedReviewers,
    approved_reviewer_hashes: forgedHashes,
    reviewer_root_hash: executionPolicyReviewerRootHash(forgedHashes),
    reviewer_set_sha256: reviewerSetSha256(forgedReviewers),
  };
  assert.throws(
    () => normalizeExpectedReviewerAuthority(forgedValue),
    /transitive.*pins/,
  );
  assert.throws(
    () => normalizeExpectedReviewerAuthority(forgedValue, {
      expectedReviewerRootHash: value.root,
      expectedReviewerSetSha256: value.setSha,
    }),
    /does not match the transitive/,
  );
});

test("wrong signer, controller, order, signature, and high-s aliases fail", async () => {
  const value = fixture();
  const good = await signatures(value.message);
  const forged = await signatures(value.message, [FORGED, BRAVO], [
    reviewer(ALPHA.address, "reviewer-alpha"),
    reviewer(BRAVO.address, "reviewer-bravo"),
  ]);
  assert.throws(() => verifyPinnedTwoSignerAuthorization({
    signatures: forged,
    message: value.message,
    reviewerAuthority: value.authority,
  }), /verification failed/);
  const wrongController = structuredClone(good);
  wrongController[0].controller_id = "reviewer-wrong";
  assert.throws(() => verifyPinnedTwoSignerAuthorization({
    signatures: wrongController,
    message: value.message,
    reviewerAuthority: value.authority,
  }), /not in the transitively pinned/);
  assert.throws(() => verifyPinnedTwoSignerAuthorization({
    signatures: [...good].reverse(),
    message: value.message,
    reviewerAuthority: value.authority,
  }), /distinct sorted/);
  const altered = structuredClone(good);
  altered[0].signature = `0x${"00".repeat(65)}`;
  assert.throws(() => verifyPinnedTwoSignerAuthorization({
    signatures: altered,
    message: value.message,
    reviewerAuthority: value.authority,
  }), /canonical low-s/);
  const malleable = structuredClone(good);
  malleable[0].signature = highS(malleable[0].signature);
  assert.throws(() => canonicalLowSEip191Signature(malleable[0].signature), /canonical low-s/);
});

test("domain and message constructors reject cross-domain or unpinned inputs", () => {
  const value = fixture();
  const other = eip191AuthorizationSigningDigest({
    domain: "dnai-wikigen/other-two-signer-authorization/v1\0",
    payload: value.payload,
  });
  assert.notEqual(other, value.digest);
  assert.throws(() => eip191AuthorizationSigningDigest({
    domain: "missing-nul-domain",
    payload: value.payload,
  }), /NUL-terminated/);
  assert.throws(() => eip191AuthorizationSigningMessage({
    prefix: "short",
    digest: value.digest,
  }), /prefix or digest/);
});
