import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  ReleaseAuthoritySignatureError,
  canonicalLowSEip191Signature,
  normalizeExpectedReviewerAuthority as normalizeExpectedReviewerAuthorityCore,
  normalizeReviewerAuthorizationSignatures,
  releaseAuthoritySignatureSha256,
} from "./release-authority-signature-verifier-core.mjs";

export {
  EXECUTION_POLICY_REVIEWER_DOMAIN,
  EXECUTION_POLICY_REVIEWER_ROOT_DOMAIN,
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  RELEASE_REVIEWER_SET_DOMAIN,
  ReleaseAuthoritySignatureError,
  canonicalLowSEip191Signature,
  eip191AuthorizationSigningDigest,
  eip191AuthorizationSigningMessage,
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  reviewerSetSha256,
} from "./release-authority-signature-verifier-core.mjs";

const ADDRESS = /^0x[0-9a-f]{40}$/;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const NORMALIZED_AUTHORITIES = new WeakSet();

function fail(message) {
  throw new ReleaseAuthoritySignatureError(message);
}

function nonzeroAddress(value, label) {
  if (typeof value !== "string" || !ADDRESS.test(value)
    || value === ZERO_ADDRESS) {
    fail(`${label} must be a nonzero lowercase address`);
  }
  return value;
}

/**
 * Bind an artifact-carried reviewer set/root to pins supplied by an upstream
 * transitive authority and brand only the facade-produced immutable result.
 */
export function normalizeExpectedReviewerAuthority(value, options = {}) {
  const normalized = normalizeExpectedReviewerAuthorityCore(value, options);
  NORMALIZED_AUTHORITIES.add(normalized);
  return normalized;
}

function stableCastExecutableSnapshot() {
  const executablePath = path.join(
    os.homedir(),
    PINNED_CAST_SIGNATURE_VERIFIER.executable_user_relative_path,
  );
  if (path.resolve(executablePath) !== executablePath
    || fs.realpathSync.native(executablePath) !== executablePath) {
    fail("pinned cast executable path must be canonical and symlink-free");
  }
  const before = fs.lstatSync(executablePath);
  const expectedUid = typeof process.geteuid === "function" ? process.geteuid() : before.uid;
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
    || before.uid !== expectedUid || (before.mode & 0o022) !== 0) {
    fail("pinned cast executable must be an operator-owned single-link non-writable regular file");
  }
  const fd = fs.openSync(executablePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd);
    const after = fs.lstatSync(executablePath);
    if (opened.dev !== before.dev || opened.ino !== before.ino
      || after.dev !== opened.dev || after.ino !== opened.ino
      || opened.size !== before.size || opened.nlink !== 1) {
      fail("pinned cast executable identity changed while opening");
    }
    const digest = createHash("sha256");
    const buffer = Buffer.alloc(128 * 1024);
    let offset = 0;
    while (offset < opened.size) {
      const count = fs.readSync(fd, buffer, 0, Math.min(buffer.length, opened.size - offset), offset);
      if (count < 1) fail("pinned cast executable ended during its bounded read");
      digest.update(buffer.subarray(0, count));
      offset += count;
    }
    const finalFd = fs.fstatSync(fd);
    if (finalFd.dev !== opened.dev || finalFd.ino !== opened.ino
      || finalFd.size !== opened.size || finalFd.mtimeMs !== opened.mtimeMs
      || finalFd.ctimeMs !== opened.ctimeMs) {
      fail("pinned cast executable changed during hashing");
    }
    const sha = digest.digest("hex");
    if (sha !== PINNED_CAST_SIGNATURE_VERIFIER.executable_sha256) {
      fail("pinned cast executable bytes do not match the reviewed SHA-256");
    }
    return {
      executablePath,
      dev: opened.dev,
      ino: opened.ino,
      size: opened.size,
      mtimeMs: opened.mtimeMs,
      ctimeMs: opened.ctimeMs,
      sha256: sha,
    };
  } finally {
    fs.closeSync(fd);
  }
}

function sameExecutable(left, right) {
  return left.executablePath === right.executablePath
    && left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs
    && left.sha256 === right.sha256;
}

function runPinnedCast(args) {
  const before = stableCastExecutableSnapshot();
  const result = spawnSync(before.executablePath, args, {
    encoding: "utf8",
    timeout: 15_000,
    maxBuffer: 64 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      HOME: os.homedir(),
      LANG: "C",
      LC_ALL: "C",
      NO_COLOR: "1",
      PATH: "/usr/bin:/bin",
    },
  });
  const after = stableCastExecutableSnapshot();
  if (!sameExecutable(before, after)) {
    fail("pinned cast executable identity changed across invocation");
  }
  return result;
}

export function assertPinnedCastSignatureVerifier() {
  const result = runPinnedCast(["--version"]);
  const output = `${result.stdout || ""}\n${result.stderr || ""}`;
  if (result.error || result.status !== 0
    || !output.includes(`cast Version: ${PINNED_CAST_SIGNATURE_VERIFIER.version}`)
    || !output.includes(`Commit SHA: ${PINNED_CAST_SIGNATURE_VERIFIER.commit_sha}`)
    || !output.includes(`Build Profile: ${PINNED_CAST_SIGNATURE_VERIFIER.build_profile}`)) {
    fail("installed cast does not match the pinned EIP-191 signature verifier");
  }
  return { ...PINNED_CAST_SIGNATURE_VERIFIER };
}

export function verifyPinnedEip191PersonalSignature({ address, message, signature }) {
  const signer = nonzeroAddress(address, "signature verifier address");
  if (typeof message !== "string" || message.length < 8 || message.length > 1_024) {
    fail("signature verifier message is invalid");
  }
  const canonicalSignature = canonicalLowSEip191Signature(signature);
  assertPinnedCastSignatureVerifier();
  const result = runPinnedCast([
    "wallet", "verify", "--quiet", "--address", signer, message, canonicalSignature,
  ]);
  if (result.error || result.status !== 0) fail("EIP-191 personal signature verification failed");
  return {
    address: signer,
    signature_sha256: releaseAuthoritySignatureSha256(canonicalSignature),
  };
}

function verifyPinnedReviewerAuthorization({
  signatures,
  message,
  reviewerAuthority,
  expectedSignerCount,
  requireEveryReviewer,
}) {
  if (!reviewerAuthority || !NORMALIZED_AUTHORITIES.has(reviewerAuthority)) {
    fail("two-signer verification requires a transitively pinned reviewer authority");
  }
  const normalized = normalizeReviewerAuthorizationSignatures({
    signatures,
    reviewerAuthority,
    expectedReviewerRootHash: reviewerAuthority.reviewer_root_hash,
    expectedReviewerSetSha256: reviewerAuthority.reviewer_set_sha256,
    expectedSignerCount,
    requireEveryReviewer,
  });
  const evidence = normalized.signatures.map((entry) => ({
    controller_id: entry.controller_id,
    ...verifyPinnedEip191PersonalSignature({
      address: entry.address,
      message,
      signature: entry.signature,
    }),
  }));
  return Object.freeze({
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
    reviewer_root_hash: reviewerAuthority.reviewer_root_hash,
    reviewer_set_sha256: reviewerAuthority.reviewer_set_sha256,
    signer_count: normalized.signer_count,
    signers: evidence,
  });
}

export function verifyPinnedTwoSignerAuthorization({ signatures, message, reviewerAuthority }) {
  return verifyPinnedReviewerAuthorization({
    signatures,
    message,
    reviewerAuthority,
    expectedSignerCount: 2,
    requireEveryReviewer: false,
  });
}

export function verifyPinnedAllReviewerAuthorization({ signatures, message, reviewerAuthority }) {
  if (!reviewerAuthority || !NORMALIZED_AUTHORITIES.has(reviewerAuthority)) {
    fail("all-reviewer verification requires a transitively pinned reviewer authority");
  }
  return verifyPinnedReviewerAuthorization({
    signatures,
    message,
    reviewerAuthority,
    expectedSignerCount: reviewerAuthority.approved_reviewers.length,
    requireEveryReviewer: true,
  });
}
