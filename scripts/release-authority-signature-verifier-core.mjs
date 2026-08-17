import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  INDEPENDENT_EIP191_REPLAY_VERIFIER,
  recoverIndependentEip191PersonalSigner,
  recoverIndependentEip191PersonalSignerFromRawDigest,
} from "../web/scripts/independent-eip191-replay-core.mjs";

export const PINNED_EIP191_SIGNATURE_SCHEME =
  "eip191_personal_sign_secp256k1_low_s_65_byte";
export const PINNED_CAST_SIGNATURE_VERIFIER = Object.freeze({
  build_profile: "maxperf",
  commit_sha: "b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2",
  executable_sha256:
    "f7373e6e34939415fe048560ecf275463ea891fec5a124a38958983f3955542d",
  executable_user_relative_path: ".foundry/bin/cast",
  tool: "cast wallet verify",
  version: "1.5.1-stable",
});
export const EXECUTION_POLICY_REVIEWER_DOMAIN =
  "dnai-wikigen/execution-policy-approver/v1\0";
export const EXECUTION_POLICY_REVIEWER_ROOT_DOMAIN =
  "dnai-wikigen/execution-policy-approver-root/v1\0";
export const RELEASE_REVIEWER_SET_DOMAIN =
  "dnai-wikigen/release-reviewer-set/v1\0";
export const RELEASE_AUTHORITY_SIGNATURE_DOMAIN =
  "dnai-wikigen/release-authority-signature/v1\0";
export { INDEPENDENT_EIP191_REPLAY_VERIFIER };

const ADDRESS = /^0x[0-9a-f]{40}$/;
const CONTROLLER = /^[a-z0-9][a-z0-9._-]{7,63}$/;
const BARE_SHA256 = /^[0-9a-f]{64}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const SECP256K1_N =
  BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const SECP256K1_HALF_N = SECP256K1_N / 2n;
const ARRAY_INDEX = /^(?:0|[1-9][0-9]*)$/;
const MAXIMUM_CANONICAL_DEPTH = 64;
const MAXIMUM_CANONICAL_NODES = 100_000;

export class ReleaseAuthoritySignatureError extends TypeError {}

function fail(message) {
  throw new ReleaseAuthoritySignatureError(message);
}

/**
 * Reject Proxies non-trapping in the shared canonical validator, then copy the
 * graph exclusively from own data descriptors before any semantic read. The
 * only trusted value after this boundary is the detached plain-data snapshot.
 */
function snapshotCanonicalOwnDataGraph(value, label) {
  assertCanonicalPlainDataGraph(value, { label });
  const active = [];
  let nodes = 0;

  function visit(entry, depth) {
    if (entry === null || typeof entry === "string"
      || typeof entry === "boolean") return entry;
    if (typeof entry === "number") {
      if (!Number.isFinite(entry) || Object.is(entry, -0)) {
        fail(`${label} numbers must be finite and must not be negative zero`);
      }
      return entry;
    }
    if (typeof entry !== "object") {
      fail(`${label} allows only JSON data types`);
    }
    if (depth > MAXIMUM_CANONICAL_DEPTH) {
      fail(`${label} maximum depth exceeded`);
    }
    if (active.includes(entry)) fail(`${label} cycles are forbidden`);
    nodes += 1;
    if (nodes > MAXIMUM_CANONICAL_NODES) {
      fail(`${label} maximum node count exceeded`);
    }
    if (ArrayBuffer.isView(entry) || entry instanceof ArrayBuffer
      || (typeof SharedArrayBuffer !== "undefined"
        && entry instanceof SharedArrayBuffer)) {
      fail(`${label} typed, binary, or shared mutable buffers are forbidden`);
    }

    const isArray = Array.isArray(entry);
    let prototype;
    let descriptors;
    try {
      prototype = Object.getPrototypeOf(entry);
      descriptors = Object.getOwnPropertyDescriptors(entry);
    } catch {
      fail(`${label} could not be snapshotted as own data`);
    }
    if (isArray ? prototype !== Array.prototype
      : prototype !== Object.prototype && prototype !== null) {
      fail(`${label} custom prototypes are forbidden`);
    }
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== "string")) {
      fail(`${label} symbol keys are forbidden`);
    }
    let output;
    if (isArray) {
      const lengthDescriptor = descriptors.length;
      const stringKeys = keys.filter((key) => key !== "length");
      const length = lengthDescriptor?.value;
      if (!lengthDescriptor || lengthDescriptor.enumerable
        || !Object.hasOwn(lengthDescriptor, "value")
        || !Number.isSafeInteger(length) || length < 0
        || stringKeys.length !== length
        || stringKeys.some((key) => !ARRAY_INDEX.test(key))
        || stringKeys.map(Number).sort((left, right) => left - right)
          .some((index, position) => index !== position)) {
        fail(`${label} arrays must be dense and cannot have extra properties`);
      }
      output = [];
    } else {
      output = {};
    }

    for (const key of keys) {
      if (isArray && key === "length") continue;
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable
        || !Object.hasOwn(descriptor, "value")
        || typeof descriptor.get === "function"
        || typeof descriptor.set === "function") {
        fail(`${label} accessors and non-enumerable data fields are forbidden`);
      }
    }

    active.push(entry);
    for (const key of keys) {
      if (isArray && key === "length") continue;
      const child = visit(descriptors[key].value, depth + 1);
      Object.defineProperty(output, key, {
        value: child,
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    active.pop();
    return output;
  }

  return deepFreezeCanonicalPlainDataGraph(visit(value, 0), {
    label: `${label} snapshot`,
  });
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exact(value, keys, label) {
  const snapshot = snapshotCanonicalOwnDataGraph(value, label);
  if (!isRecord(snapshot)
    || JSON.stringify(Object.keys(snapshot).sort())
      !== JSON.stringify([...keys].sort())) {
    fail(`${label} fields do not match the exact schema`);
  }
  return snapshot;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function nonzeroAddress(value, label) {
  if (typeof value !== "string" || !ADDRESS.test(value)
    || value === ZERO_ADDRESS) {
    fail(`${label} must be a nonzero lowercase address`);
  }
  return value;
}

function controllerId(value, label) {
  if (typeof value !== "string" || !CONTROLLER.test(value)) {
    fail(`${label} must be a canonical controller ID`);
  }
  return value;
}

export function executionPolicyReviewerHash(address) {
  const normalized = nonzeroAddress(address, "reviewer address");
  return createHash("sha256")
    .update(EXECUTION_POLICY_REVIEWER_DOMAIN, "utf8")
    .update(normalized, "ascii")
    .digest("hex");
}

export function executionPolicyReviewerRootHash(reviewerHashes) {
  const snapshot = snapshotCanonicalOwnDataGraph(
    reviewerHashes,
    "reviewer hashes",
  );
  if (!Array.isArray(snapshot) || snapshot.length < 2
    || snapshot.some((entry) => !BARE_SHA256.test(entry))) {
    fail("reviewer hashes must contain at least two bare SHA-256 values");
  }
  const normalized = [...snapshot].sort();
  if (new Set(normalized).size !== normalized.length) {
    fail("reviewer hashes must be unique");
  }
  return createHash("sha256")
    .update(EXECUTION_POLICY_REVIEWER_ROOT_DOMAIN, "utf8")
    .update(JSON.stringify(normalized), "ascii")
    .digest("hex");
}

function normalizeReviewerSet(reviewers) {
  const snapshot = snapshotCanonicalOwnDataGraph(reviewers, "reviewer set");
  if (!Array.isArray(snapshot) || snapshot.length < 2
    || snapshot.length > 32) {
    fail("reviewer set must contain from two through 32 reviewers");
  }
  const normalized = snapshot.map((entry, index) => {
    const reviewer = exact(
      entry,
      ["address", "controller_id"],
      `reviewer set entry ${index}`,
    );
    return {
      address: nonzeroAddress(
        reviewer.address,
        `reviewer set entry ${index} address`,
      ),
      controller_id: controllerId(
        reviewer.controller_id,
        `reviewer set entry ${index} controller`,
      ),
    };
  });
  for (let index = 1; index < normalized.length; index += 1) {
    if (normalized[index - 1].address >= normalized[index].address) {
      fail("reviewer set must be strictly sorted by distinct address");
    }
  }
  if (new Set(normalized.map((entry) => entry.controller_id)).size
      !== normalized.length) {
    fail("reviewer set controller IDs must be distinct");
  }
  return normalized;
}

export function reviewerSetSha256(reviewers) {
  return `sha256:${createHash("sha256")
    .update(RELEASE_REVIEWER_SET_DOMAIN, "utf8")
    .update(canonicalText(normalizeReviewerSet(reviewers)), "utf8")
    .digest("hex")}`;
}

/**
 * Bind an artifact-carried reviewer set/root to pins supplied by an enclosing
 * transitive authority. This pure result is canonical data, never a brand.
 */
export function normalizeExpectedReviewerAuthority(value, optionsValue = {}) {
  const options = snapshotCanonicalOwnDataGraph(
    optionsValue,
    "expected reviewer authority options",
  );
  if (!isRecord(options)) {
    fail("expected reviewer authority options must be an object");
  }
  const { expectedReviewerRootHash, expectedReviewerSetSha256 } = options;
  if (!BARE_SHA256.test(expectedReviewerRootHash || "")
    || !SHA256.test(expectedReviewerSetSha256 || "")) {
    fail("transitive reviewer-root and reviewer-set pins are required");
  }
  const parsed = exact(value, [
    "approved_reviewer_hashes",
    "approved_reviewers",
    "reviewer_root_hash",
    "reviewer_set_sha256",
  ], "expected reviewer authority");
  const reviewers = normalizeReviewerSet(parsed.approved_reviewers);
  const hashes = reviewers
    .map((entry) => executionPolicyReviewerHash(entry.address))
    .sort();
  if (!Array.isArray(parsed.approved_reviewer_hashes)
    || JSON.stringify(parsed.approved_reviewer_hashes)
      !== JSON.stringify(hashes)) {
    fail("artifact reviewer hashes do not match the exact reviewer identities");
  }
  const root = executionPolicyReviewerRootHash(hashes);
  const setSha256 = reviewerSetSha256(reviewers);
  if (parsed.reviewer_root_hash !== root
    || parsed.reviewer_set_sha256 !== setSha256
    || root !== expectedReviewerRootHash
    || setSha256 !== expectedReviewerSetSha256) {
    fail("artifact reviewer authority does not match the transitive root/set pins");
  }
  return deepFreezeCanonicalPlainDataGraph({
    approved_reviewers: reviewers,
    approved_reviewer_hashes: hashes,
    reviewer_root_hash: root,
    reviewer_set_sha256: setSha256,
  }, { label: "normalized expected reviewer authority" });
}

export function canonicalLowSEip191Signature(
  value,
  label = "EIP-191 signature",
) {
  if (typeof value !== "string" || !SIGNATURE.test(value)) {
    fail(`${label} must be lowercase 65-byte hex`);
  }
  const r = BigInt(`0x${value.slice(2, 66)}`);
  const s = BigInt(`0x${value.slice(66, 130)}`);
  const v = Number.parseInt(value.slice(130), 16);
  if (r <= 0n || r >= SECP256K1_N
    || s <= 0n || s > SECP256K1_HALF_N
    || (v !== 27 && v !== 28)) {
    fail(`${label} must use canonical low-s secp256k1 with v 27 or 28`);
  }
  return value;
}

export function releaseAuthoritySignatureSha256(signature) {
  const canonical = canonicalLowSEip191Signature(signature);
  return `sha256:${createHash("sha256")
    .update(RELEASE_AUTHORITY_SIGNATURE_DOMAIN, "utf8")
    .update(Buffer.from(canonical.slice(2), "hex"))
    .digest("hex")}`;
}

export function eip191AuthorizationSigningDigest(input = {}) {
  const { domain, payload } = exact(
    input,
    ["domain", "payload"],
    "authorization signing digest input",
  );
  if (typeof domain !== "string" || domain.length < 8
    || !domain.endsWith("\0")) {
    fail("authorization signing domain must be a nonempty NUL-terminated string");
  }
  if (!isRecord(payload)) fail("authorization signing payload must be an object");
  const text = canonicalText(payload);
  if (Buffer.byteLength(text, "utf8") > 256 * 1024) {
    fail("authorization signing payload is too large");
  }
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(text, "utf8")
    .digest("hex")}`;
}

export function eip191AuthorizationSigningMessage(input = {}) {
  const { prefix, digest } = exact(
    input,
    ["digest", "prefix"],
    "authorization signing message input",
  );
  if (typeof prefix !== "string" || prefix.length < 8 || prefix.length > 160
    || /[^\x20-\x7e]/.test(prefix) || !SHA256.test(digest)) {
    fail("authorization signing message prefix or digest is invalid");
  }
  return `${prefix}${digest}`;
}

/**
 * Normalize the reviewer signatures carried by an authorization. Membership
 * is checked against the supplied canonical reviewer authority, but the
 * enclosing validator remains responsible for deriving that authority from a
 * separately authenticated transitive root and set.
 */
export function normalizeReviewerAuthorizationSignatures(input = {}) {
  const parsed = exact(input, [
    "signatures",
    "reviewerAuthority",
    "expectedReviewerRootHash",
    "expectedReviewerSetSha256",
    "expectedSignerCount",
    "requireEveryReviewer",
  ], "reviewer authorization signature input");
  const {
    signatures,
    reviewerAuthority,
    expectedReviewerRootHash,
    expectedReviewerSetSha256,
    expectedSignerCount,
    requireEveryReviewer,
  } = parsed;
  if (typeof requireEveryReviewer !== "boolean") {
    fail("requireEveryReviewer must be a literal boolean");
  }
  if (!Number.isSafeInteger(expectedSignerCount) || expectedSignerCount < 2
    || !Array.isArray(signatures)
    || signatures.length !== expectedSignerCount) {
    fail(`authorization requires exactly ${expectedSignerCount} reviewer signatures`);
  }
  const authority = normalizeExpectedReviewerAuthority(reviewerAuthority, {
    expectedReviewerRootHash,
    expectedReviewerSetSha256,
  });
  if (requireEveryReviewer
    && signatures.length !== authority.approved_reviewers.length) {
    fail("authorization requires an acceptance from every listed reviewer");
  }
  const expectedByAddress = new Map(
    authority.approved_reviewers.map((entry) => [
      entry.address,
      entry.controller_id,
    ]),
  );
  const normalized = signatures.map((entry, index) => {
    const parsed = exact(entry, [
      "address",
      "controller_id",
      "signature",
    ], `authorization signature ${index}`);
    const signer = nonzeroAddress(
      parsed.address,
      `authorization signature ${index} address`,
    );
    const controller = controllerId(
      parsed.controller_id,
      `authorization signature ${index} controller`,
    );
    if (expectedByAddress.get(signer) !== controller
      || !authority.approved_reviewer_hashes.includes(
        executionPolicyReviewerHash(signer),
      )) {
      fail(
        "authorization signer identity is not in the transitively pinned reviewer set",
      );
    }
    const signature = canonicalLowSEip191Signature(
      parsed.signature,
      `authorization signature ${index}`,
    );
    return {
      address: signer,
      controller_id: controller,
      signature,
      signature_sha256: releaseAuthoritySignatureSha256(signature),
    };
  });
  for (let index = 1; index < normalized.length; index += 1) {
    if (normalized[index - 1].address >= normalized[index].address) {
      fail("authorization signatures must use distinct sorted signer addresses");
    }
  }
  if (new Set(normalized.map((entry) => entry.controller_id)).size
      !== normalized.length) {
    fail("authorization signatures must use distinct declared controllers");
  }
  if (requireEveryReviewer
    && normalized.some((entry, index) => (
      entry.address !== authority.approved_reviewers[index].address
      || entry.controller_id !== authority.approved_reviewers[index].controller_id
    ))) {
    fail("authorization signatures do not cover the exact listed reviewer set");
  }
  return deepFreezeCanonicalPlainDataGraph({
    reviewer_root_hash: authority.reviewer_root_hash,
    reviewer_set_sha256: authority.reviewer_set_sha256,
    signer_count: normalized.length,
    signatures: normalized,
  }, { label: "normalized reviewer authorization signatures" });
}

function normalizeIndependentVerificationInput(input, fields, label) {
  const parsed = exact(input, fields, label);
  return {
    address: nonzeroAddress(parsed.address, `${label} address`),
    signature: canonicalLowSEip191Signature(
      parsed.signature,
      `${label} signature`,
    ),
    ...Object.fromEntries(fields
      .filter((field) => !["address", "signature"].includes(field))
      .map((field) => [field, parsed[field]])),
  };
}

/** Independently verify an EIP-191 signature over a UTF-8 message string. */
export function verifyIndependentEip191PersonalSignature(input = {}) {
  const parsed = normalizeIndependentVerificationInput(
    input,
    ["address", "message", "signature"],
    "independent EIP-191 UTF-8 verification",
  );
  if (typeof parsed.message !== "string") {
    fail("independent EIP-191 UTF-8 verification message must be a string");
  }
  const recovered = recoverIndependentEip191PersonalSigner({
    message: parsed.message,
    signature: parsed.signature,
  });
  if (recovered !== parsed.address) {
    fail("independent EIP-191 UTF-8 signature verification failed");
  }
  return Object.freeze({
    address: parsed.address,
    signature_sha256: releaseAuthoritySignatureSha256(parsed.signature),
  });
}

/** Independently verify personal-sign where the message is exactly bytes32. */
export function verifyIndependentEip191RawDigestSignature(input = {}) {
  const parsed = normalizeIndependentVerificationInput(
    input,
    ["address", "digest", "signature"],
    "independent EIP-191 raw-bytes32 verification",
  );
  const recovered = recoverIndependentEip191PersonalSignerFromRawDigest({
    digest: parsed.digest,
    signature: parsed.signature,
  });
  if (recovered !== parsed.address) {
    fail("independent EIP-191 raw-bytes32 signature verification failed");
  }
  return Object.freeze({
    address: parsed.address,
    signature_sha256: releaseAuthoritySignatureSha256(parsed.signature),
  });
}

/**
 * Verify a canonical reviewer authorization without filesystem or subprocess
 * capabilities. The caller remains responsible for deriving the supplied
 * reviewer authority from an independently authenticated root and set.
 */
export function verifyIndependentReviewerAuthorization(input = {}) {
  const parsed = exact(input, [
    "expectedSignerCount",
    "message",
    "requireEveryReviewer",
    "reviewerAuthority",
    "signatures",
  ], "independent reviewer authorization input");
  if (typeof parsed.message !== "string") {
    fail("independent reviewer authorization message must be a string");
  }
  const normalized = normalizeReviewerAuthorizationSignatures({
    signatures: parsed.signatures,
    reviewerAuthority: parsed.reviewerAuthority,
    expectedReviewerRootHash: parsed.reviewerAuthority?.reviewer_root_hash,
    expectedReviewerSetSha256: parsed.reviewerAuthority?.reviewer_set_sha256,
    expectedSignerCount: parsed.expectedSignerCount,
    requireEveryReviewer: parsed.requireEveryReviewer,
  });
  const signers = normalized.signatures.map((entry) => Object.freeze({
    controller_id: entry.controller_id,
    ...verifyIndependentEip191PersonalSignature({
      address: entry.address,
      message: parsed.message,
      signature: entry.signature,
    }),
  }));
  return deepFreezeCanonicalPlainDataGraph({
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
    reviewer_root_hash: normalized.reviewer_root_hash,
    reviewer_set_sha256: normalized.reviewer_set_sha256,
    signer_count: normalized.signer_count,
    signers,
  }, { label: "independent reviewer authorization evidence" });
}

export function verifyIndependentTwoSignerAuthorization(input = {}) {
  const parsed = exact(input, [
    "message", "reviewerAuthority", "signatures",
  ], "independent two-signer authorization input");
  return verifyIndependentReviewerAuthorization({
    message: parsed.message,
    reviewerAuthority: parsed.reviewerAuthority,
    signatures: parsed.signatures,
    expectedSignerCount: 2,
    requireEveryReviewer: false,
  });
}

export function verifyIndependentAllReviewerAuthorization(input = {}) {
  const parsed = exact(input, [
    "message", "reviewerAuthority", "signatures",
  ], "independent all-reviewer authorization input");
  const reviewerCount = parsed.reviewerAuthority.approved_reviewers?.length;
  if (!Number.isSafeInteger(reviewerCount) || reviewerCount < 2) {
    fail("independent all-reviewer authorization requires a canonical reviewer set");
  }
  return verifyIndependentReviewerAuthorization({
    message: parsed.message,
    reviewerAuthority: parsed.reviewerAuthority,
    signatures: parsed.signatures,
    expectedSignerCount: reviewerCount,
    requireEveryReviewer: true,
  });
}
