import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { DEPLOYMENT_TOOLCHAIN_AUTHORITY } from "./operator-policy-packet-core.mjs";
import {
  PINNED_CAST_SIGNATURE_VERIFIER as FACADE_PIN,
  eip191AuthorizationSigningDigest as facadeSigningDigest,
} from "./release-authority-signature-verifier.mjs";
import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  RELEASE_AUTHORITY_SIGNATURE_DOMAIN,
  canonicalLowSEip191Signature,
  eip191AuthorizationSigningDigest,
  eip191AuthorizationSigningMessage,
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  normalizeExpectedReviewerAuthority,
  normalizeReviewerAuthorizationSignatures,
  releaseAuthoritySignatureSha256,
  reviewerSetSha256,
  verifyIndependentEip191PersonalSignature,
  verifyIndependentEip191RawDigestSignature,
} from "./release-authority-signature-verifier-core.mjs";

const reviewers = [
  { address: `0x${"11".repeat(20)}`, controller_id: "controller-alpha" },
  { address: `0x${"22".repeat(20)}`, controller_id: "controller-bravo" },
  { address: `0x${"33".repeat(20)}`, controller_id: "controller-charlie" },
];
const signature = (r, s, v = 27) => (
  `0x${r.toString(16).padStart(64, "0")}${s
    .toString(16).padStart(64, "0")}${v.toString(16).padStart(2, "0")}`
);

function reviewerAuthority() {
  const approvedReviewerHashes = reviewers
    .map(({ address }) => executionPolicyReviewerHash(address))
    .sort();
  return {
    approved_reviewers: structuredClone(reviewers),
    approved_reviewer_hashes: approvedReviewerHashes,
    reviewer_root_hash:
      executionPolicyReviewerRootHash(approvedReviewerHashes),
    reviewer_set_sha256: reviewerSetSha256(reviewers),
  };
}

test("pure toolchain metadata and signing bytes remain byte-identical", () => {
  assert.deepEqual(PINNED_CAST_SIGNATURE_VERIFIER, FACADE_PIN);
  assert.deepEqual(PINNED_CAST_SIGNATURE_VERIFIER, {
    build_profile: DEPLOYMENT_TOOLCHAIN_AUTHORITY.foundry.buildProfile,
    commit_sha: DEPLOYMENT_TOOLCHAIN_AUTHORITY.foundry.commitSha,
    executable_sha256:
      DEPLOYMENT_TOOLCHAIN_AUTHORITY.foundry.castExecutableSha256,
    executable_user_relative_path: ".foundry/bin/cast",
    tool: "cast wallet verify",
    version: DEPLOYMENT_TOOLCHAIN_AUTHORITY.foundry.castVersion,
  });
  const input = {
    domain: "dnai-wikigen/test-authorization/v1\0",
    payload: { beta: 2, alpha: 1 },
  };
  assert.equal(
    eip191AuthorizationSigningDigest(input),
    facadeSigningDigest(input),
  );
  assert.equal(
    eip191AuthorizationSigningMessage({
      prefix: "dnai-wikigen test authorization v1:",
      digest: eip191AuthorizationSigningDigest(input),
    }),
    `dnai-wikigen test authorization v1:${eip191AuthorizationSigningDigest(input)}`,
  );
});

test("reviewer authority and exactly two sorted signatures normalize without a brand", () => {
  const authorityValue = reviewerAuthority();
  const authority = normalizeExpectedReviewerAuthority(authorityValue, {
    expectedReviewerRootHash: authorityValue.reviewer_root_hash,
    expectedReviewerSetSha256: authorityValue.reviewer_set_sha256,
  });
  const normalized = normalizeReviewerAuthorizationSignatures({
    signatures: reviewers.slice(0, 2).map((reviewer, index) => ({
      ...reviewer,
      signature: signature(index + 1, index + 2),
    })),
    reviewerAuthority: authority,
    expectedReviewerRootHash: authority.reviewer_root_hash,
    expectedReviewerSetSha256: authority.reviewer_set_sha256,
    expectedSignerCount: 2,
    requireEveryReviewer: false,
  });
  assert.equal(normalized.signer_count, 2);
  assert.deepEqual(
    normalized.signatures.map(({ address }) => address),
    reviewers.slice(0, 2).map(({ address }) => address),
  );
  assert.ok(Object.isFrozen(normalized));
  assert.equal(
    normalized.signatures[0].signature_sha256,
    releaseAuthoritySignatureSha256(normalized.signatures[0].signature),
  );
});

test("signature-byte digest and low-s boundary are domain separated", () => {
  const value = signature(1, 2, 28);
  assert.equal(canonicalLowSEip191Signature(value), value);
  assert.equal(
    releaseAuthoritySignatureSha256(value),
    `sha256:${createHash("sha256")
      .update(RELEASE_AUTHORITY_SIGNATURE_DOMAIN, "utf8")
      .update(Buffer.from(value.slice(2), "hex"))
      .digest("hex")}`,
  );
  const n = BigInt(
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  );
  assert.throws(
    () => canonicalLowSEip191Signature(signature(1, n - 1n)),
    /canonical low-s/i,
  );
  assert.throws(
    () => canonicalLowSEip191Signature(signature(1, 2, 0)),
    /v 27 or 28/i,
  );
});

test("independent UTF-8 and raw-bytes32 verification use distinct modes", () => {
  const address = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
  const message = "dnai-wikigen signature-core known answer";
  const digest = `0x${"ab".repeat(32)}`;
  const textSignature =
    "0x5a9fe1781f73da7eba28933818c6a5e518f8343cd08d20cb37dde13b5a5893b77c2151e5b4ba9488cf79d9e8610e3f30e40d60a409e9fbc1951673ba132b09301c";
  const rawSignature =
    "0x954242d09d28015eb35388c48d3f14e106973c0a7767c11eddba17e8b9d23a2f4abe381cfd5027b2ab8aeadf2363c7fb08b570656a82e82c618a7ebd1fc747c01c";
  assert.equal(
    verifyIndependentEip191PersonalSignature({
      address,
      message,
      signature: textSignature,
    }).address,
    address,
  );
  assert.equal(
    verifyIndependentEip191RawDigestSignature({
      address,
      digest,
      signature: rawSignature,
    }).address,
    address,
  );
  assert.throws(
    () => verifyIndependentEip191PersonalSignature({
      address,
      message: digest,
      signature: rawSignature,
    }),
    /verification failed/i,
  );
});

test("self-selected, reordered, duplicate-controller, and accessor inputs fail closed", () => {
  const authority = reviewerAuthority();
  const wrongRoot = `${"ff".repeat(32)}`;
  assert.throws(
    () => normalizeExpectedReviewerAuthority(authority, {
      expectedReviewerRootHash: wrongRoot,
      expectedReviewerSetSha256: authority.reviewer_set_sha256,
    }),
    /transitive root\/set pins/i,
  );
  const reordered = reviewers.slice(0, 2).reverse().map((reviewer, index) => ({
    ...reviewer,
    signature: signature(index + 1, index + 2),
  }));
  assert.throws(
    () => normalizeReviewerAuthorizationSignatures({
      signatures: reordered,
      reviewerAuthority: authority,
      expectedReviewerRootHash: authority.reviewer_root_hash,
      expectedReviewerSetSha256: authority.reviewer_set_sha256,
      expectedSignerCount: 2,
      requireEveryReviewer: false,
    }),
    /sorted signer addresses/i,
  );
  const duplicateController = reviewers.slice(0, 2).map((reviewer, index) => ({
    ...reviewer,
    controller_id: reviewers[0].controller_id,
    signature: signature(index + 1, index + 2),
  }));
  assert.throws(
    () => normalizeReviewerAuthorizationSignatures({
      signatures: duplicateController,
      reviewerAuthority: authority,
      expectedReviewerRootHash: authority.reviewer_root_hash,
      expectedReviewerSetSha256: authority.reviewer_set_sha256,
      expectedSignerCount: 2,
      requireEveryReviewer: false,
    }),
    /signer identity|distinct declared controllers/i,
  );
  let getterCalls = 0;
  const accessor = Object.defineProperty({}, "signatures", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return [];
    },
  });
  assert.throws(
    () => normalizeReviewerAuthorizationSignatures(accessor),
    /accessors|own data|schema/i,
  );
  assert.equal(getterCalls, 0);
});

test("signature boundaries reject inherited data and divergent Proxies and require a literal boolean", () => {
  const authority = reviewerAuthority();
  const validInput = {
    signatures: reviewers.slice(0, 2).map((reviewer, index) => ({
      ...reviewer,
      signature: signature(index + 1, index + 2),
    })),
    reviewerAuthority: authority,
    expectedReviewerRootHash: authority.reviewer_root_hash,
    expectedReviewerSetSha256: authority.reviewer_set_sha256,
    expectedSignerCount: 2,
    requireEveryReviewer: false,
  };

  for (const invalidBoolean of [0, 1, "false", null]) {
    assert.throws(
      () => normalizeReviewerAuthorizationSignatures({
        ...validInput,
        requireEveryReviewer: invalidBoolean,
      }),
      /literal boolean/i,
    );
  }

  let inheritedGetterCalls = 0;
  const inheritedPrototype = Object.defineProperty({}, "requireEveryReviewer", {
    enumerable: true,
    get() {
      inheritedGetterCalls += 1;
      return false;
    },
  });
  const inheritedInput = Object.assign(Object.create(inheritedPrototype), {
    signatures: validInput.signatures,
    reviewerAuthority: validInput.reviewerAuthority,
    expectedReviewerRootHash: validInput.expectedReviewerRootHash,
    expectedReviewerSetSha256: validInput.expectedReviewerSetSha256,
    expectedSignerCount: validInput.expectedSignerCount,
  });
  assert.throws(
    () => normalizeReviewerAuthorizationSignatures(inheritedInput),
    /custom prototypes|exact schema/i,
  );
  assert.equal(inheritedGetterCalls, 0);

  let proxyGetCalls = 0;
  let proxyDescriptorCalls = 0;
  const proxy = new Proxy({
    prefix: "dnai-wikigen descriptor snapshot v1:",
    digest: `sha256:${"ab".repeat(32)}`,
  }, {
    get() {
      proxyGetCalls += 1;
      return "attacker-controlled get view";
    },
    getOwnPropertyDescriptor(target, property) {
      proxyDescriptorCalls += 1;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  });
  assert.throws(
    () => eip191AuthorizationSigningMessage(proxy),
    /Proxy objects are forbidden/i,
  );
  assert.equal(proxyGetCalls, 0);
  assert.equal(proxyDescriptorCalls, 0);
});

test("pure signature core has no effectful verifier or authority-brand edge", () => {
  const source = readFileSync(
    new URL("./release-authority-signature-verifier-core.mjs", import.meta.url),
    "utf8",
  );
  for (const forbidden of [
    "node:fs",
    "node:path",
    "node:os",
    "node:child_process",
    "spawnSync",
    "Date.now",
    "process.",
    "WeakMap",
    "WeakSet",
    "Symbol(",
    "import(",
  ]) assert.equal(source.includes(forbidden), false, forbidden);
});
