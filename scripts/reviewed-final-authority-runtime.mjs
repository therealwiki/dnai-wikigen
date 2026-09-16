import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  assertReviewedCeremonyAuthorityProjection,
  projectReviewedCanonicalCeremonyAuthorityText,
} from "./ceremony-authority-projector.mjs";
import {
  assertProjectedChallengeRegistryRuntimeEnvironment,
  projectCanonicalChallengeRegistryRuntimeEnvironmentText,
} from "./challenge-registry-authority-projector.mjs";
import {
  canonicalArtifactSha256,
  describeAuthorityReviewSubjectText,
  parseAuthorityReviewEnvelopeText,
  parseDeploymentIntentCoreText,
} from "./operator-policy-packet-core.mjs";

export const REVIEWED_FINAL_AUTHORITY_RUNTIME_PROJECTION_SCHEMA =
  "dnai.reviewed-final-authority-runtime-projection.v1";
export const REVIEWED_FINAL_AUTHORITY_RUNTIME_PROJECTION_TRUTH =
  "stable_canonical_files_and_review_declarations_bound_not_reviewer_signatures_deployment_or_tdx";
export const REVIEWED_FINAL_AUTHORITY_RUNTIME_PROJECTION_DOMAIN =
  "dnai-wikigen/reviewed-final-authority-runtime-projection/v1\0";

const MAX_AUTHORITY_ARTIFACT_BYTES = 4 * 1024 * 1024;
const MAX_REVIEW_EVIDENCE_BYTES = 2 * 1024 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const RELEASE_SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const PROJECTIONS = new WeakMap();
const INPUT_FIELDS = Object.freeze([
  "cvmLaunchIntentPath",
  "deploymentIntentPath",
  "expectedFinalAuthoritySha256",
  "expectedReleaseSha",
  "finalAuthorityPath",
  "reviewEnvelopePath",
  "reviewEvidencePath",
]);

function fail(message) {
  throw new TypeError(message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    fail(`${label} fields are not exact`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function sha256Bytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function sameStat(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.uid === right.uid
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function canonicalAbsolutePath(filePath, label) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)
    || path.resolve(filePath) !== filePath || path.normalize(filePath) !== filePath) {
    fail(`${label} path must be canonical and absolute`);
  }
  let real;
  try {
    real = fs.realpathSync.native(filePath);
  } catch {
    fail(`${label} path cannot be resolved`);
  }
  if (real !== filePath) fail(`${label} path must not traverse a symlink or alias`);
  return filePath;
}

function assertStableFileStat(stat, label, maximum, minimum) {
  const currentUid = typeof process.getuid === "function"
    ? BigInt(process.getuid())
    : stat.uid;
  if (!stat.isFile() || stat.isSymbolicLink?.() || stat.nlink !== 1n
    || stat.uid !== currentUid || (stat.mode & 0o022n) !== 0n
    || (stat.mode & 0o400n) === 0n
    || stat.size < BigInt(minimum) || stat.size > BigInt(maximum)) {
    fail(`${label} must be an owned, single-link, non-writable bounded regular file`);
  }
  return stat;
}

function readStableOwnedFile(filePath, label, {
  maximum = MAX_AUTHORITY_ARTIFACT_BYTES,
  minimum = 2,
  utf8 = true,
} = {}) {
  const canonicalPath = canonicalAbsolutePath(filePath, label);
  const before = assertStableFileStat(
    fs.lstatSync(canonicalPath, { bigint: true }),
    label,
    maximum,
    minimum,
  );
  const fd = fs.openSync(canonicalPath, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    const opened = assertStableFileStat(
      fs.fstatSync(fd, { bigint: true }), label, maximum, minimum,
    );
    if (!sameStat(before, opened)) fail(`${label} changed while it was opened`);
    const bytes = fs.readFileSync(fd);
    const after = assertStableFileStat(
      fs.fstatSync(fd, { bigint: true }), label, maximum, minimum,
    );
    const current = assertStableFileStat(
      fs.lstatSync(canonicalPath, { bigint: true }), label, maximum, minimum,
    );
    if (!sameStat(opened, after) || !sameStat(after, current)
      || BigInt(bytes.length) !== opened.size
      || fs.realpathSync.native(canonicalPath) !== canonicalPath) {
      fail(`${label} changed during its bounded read`);
    }
    let text = null;
    if (utf8) {
      text = bytes.toString("utf8");
      if (!Buffer.from(text, "utf8").equals(bytes) || text.includes("\0")) {
        fail(`${label} is not canonical UTF-8 text`);
      }
    }
    return Object.freeze({
      path: canonicalPath,
      stat: opened,
      bytes,
      text,
      sha256: sha256Bytes(bytes),
    });
  } finally {
    fs.closeSync(fd);
  }
}

function assertFileStillStable(observation, label, maximum, minimum) {
  canonicalAbsolutePath(observation.path, label);
  const current = assertStableFileStat(
    fs.lstatSync(observation.path, { bigint: true }),
    label,
    maximum,
    minimum,
  );
  if (!sameStat(observation.stat, current)) {
    fail(`${label} changed before the complete authority graph was projected`);
  }
}

function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function projectionDigest(value) {
  return `sha256:${createHash("sha256")
    .update(REVIEWED_FINAL_AUTHORITY_RUNTIME_PROJECTION_DOMAIN, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

/**
 * Read and bind the exact reviewed final-authority file set. The wall clock is
 * deliberately internal: a production caller can select immutable paths and
 * expected pins, but cannot backdate review freshness.
 */
export function readReviewedFinalAuthorityRuntimeProjection(input = {}) {
  const parsed = exactRecord(
    input,
    INPUT_FIELDS,
    "reviewed final-authority runtime input",
  );
  if (!RELEASE_SHA.test(parsed.expectedReleaseSha)
    || !SHA256.test(parsed.expectedFinalAuthoritySha256)
    || parsed.expectedFinalAuthoritySha256 === `sha256:${"0".repeat(64)}`) {
    fail("reviewed final-authority expected pins are malformed");
  }

  const deployment = readStableOwnedFile(
    parsed.deploymentIntentPath,
    "deployment intent",
  );
  const launch = readStableOwnedFile(
    parsed.cvmLaunchIntentPath,
    "CVM launch intent",
  );
  const finalAuthority = readStableOwnedFile(
    parsed.finalAuthorityPath,
    "final authority",
  );
  const reviewEnvelope = readStableOwnedFile(
    parsed.reviewEnvelopePath,
    "final-authority review envelope",
  );
  const reviewEvidence = readStableOwnedFile(
    parsed.reviewEvidencePath,
    "final-authority review evidence",
    { maximum: MAX_REVIEW_EVIDENCE_BYTES, minimum: 1, utf8: false },
  );
  const checkedAtMs = Date.now();

  const reviewedCeremonyAuthorityProjection =
    projectReviewedCanonicalCeremonyAuthorityText({
      deploymentIntentText: deployment.text,
      cvmLaunchIntentText: launch.text,
      finalAuthorityText: finalAuthority.text,
      reviewEnvelopeText: reviewEnvelope.text,
      reviewEvidenceBytes: reviewEvidence.bytes,
      checkedAtMs,
    });
  assertReviewedCeremonyAuthorityProjection(reviewedCeremonyAuthorityProjection);
  const challengeRegistryRuntimeEnvironmentProjection =
    projectCanonicalChallengeRegistryRuntimeEnvironmentText(
      finalAuthority.text,
      { reviewedCeremonyAuthorityProjection },
    );
  assertProjectedChallengeRegistryRuntimeEnvironment(
    challengeRegistryRuntimeEnvironmentProjection,
  );

  if (reviewedCeremonyAuthorityProjection.releaseSha !== parsed.expectedReleaseSha
    || reviewedCeremonyAuthorityProjection.finalAuthoritySha256
      !== parsed.expectedFinalAuthoritySha256) {
    fail("reviewed final-authority files differ from the immutable expected pins");
  }

  const deploymentDescriptor = parseDeploymentIntentCoreText(deployment.text);
  const launchDescriptor = describeAuthorityReviewSubjectText(launch.text);
  const finalDescriptor = describeAuthorityReviewSubjectText(finalAuthority.text);
  if (!deploymentDescriptor.ok || !launchDescriptor.ok || !finalDescriptor.ok) {
    fail("reviewed final-authority dependency descriptors are invalid");
  }
  const review = parseAuthorityReviewEnvelopeText(reviewEnvelope.text, {
    checkedAtMs,
    subjectDescriptor: finalDescriptor,
    authorityDependencies: {
      deploymentIntent: deploymentDescriptor.intent,
      cvmLaunchIntent: launchDescriptor.subject,
    },
  });
  if (!review.ok || review.receipt.reviewEvidenceSha256 !== reviewEvidence.sha256) {
    fail("reviewed final-authority envelope or evidence binding is invalid");
  }

  for (const [observation, label, maximum, minimum] of [
    [deployment, "deployment intent", MAX_AUTHORITY_ARTIFACT_BYTES, 2],
    [launch, "CVM launch intent", MAX_AUTHORITY_ARTIFACT_BYTES, 2],
    [finalAuthority, "final authority", MAX_AUTHORITY_ARTIFACT_BYTES, 2],
    [reviewEnvelope, "final-authority review envelope", MAX_AUTHORITY_ARTIFACT_BYTES, 2],
    [reviewEvidence, "final-authority review evidence", MAX_REVIEW_EVIDENCE_BYTES, 1],
  ]) {
    assertFileStillStable(observation, label, maximum, minimum);
  }

  const projection = deepFreeze({
    schema: REVIEWED_FINAL_AUTHORITY_RUNTIME_PROJECTION_SCHEMA,
    truth_status: REVIEWED_FINAL_AUTHORITY_RUNTIME_PROJECTION_TRUTH,
    release_sha: reviewedCeremonyAuthorityProjection.releaseSha,
    chain_id: reviewedCeremonyAuthorityProjection.chainId,
    deployment_intent_sha256:
      reviewedCeremonyAuthorityProjection.deploymentIntentSha256,
    cvm_launch_intent_sha256:
      reviewedCeremonyAuthorityProjection.cvmLaunchIntentSha256,
    final_authority_sha256:
      reviewedCeremonyAuthorityProjection.finalAuthoritySha256,
    review_envelope_sha256: review.receipt.reviewEnvelopeSha256,
    review_evidence_sha256: reviewEvidence.sha256,
    review_approved_at: review.envelope.approved_at,
    review_expires_at: review.envelope.expires_at,
    artifact_file_sha256: {
      deployment_intent: deployment.sha256,
      cvm_launch_intent: launch.sha256,
      final_authority: finalAuthority.sha256,
      review_envelope: reviewEnvelope.sha256,
      review_evidence: reviewEvidence.sha256,
    },
  });
  const dependencies = deepFreeze({
    ceremony_authority_projection: reviewedCeremonyAuthorityProjection,
    challenge_registry_runtime_environment_projection:
      challengeRegistryRuntimeEnvironmentProjection,
    deployment_intent: deploymentDescriptor.intent,
    cvm_launch_intent: launchDescriptor.subject,
    final_authority: finalDescriptor.subject,
    review_envelope: review.envelope,
  });
  PROJECTIONS.set(projection, Object.freeze({
    digest: projectionDigest(projection),
    dependencies,
  }));
  return projection;
}

export function assertReviewedFinalAuthorityRuntimeProjection(value) {
  const provenance = value && PROJECTIONS.get(value);
  if (!provenance
    || value.schema !== REVIEWED_FINAL_AUTHORITY_RUNTIME_PROJECTION_SCHEMA
    || value.truth_status !== REVIEWED_FINAL_AUTHORITY_RUNTIME_PROJECTION_TRUTH
    || provenance.digest !== projectionDigest(value)
    || !RELEASE_SHA.test(value.release_sha)
    || value.chain_id !== 84_532
    || !SHA256.test(value.deployment_intent_sha256)
    || !SHA256.test(value.cvm_launch_intent_sha256)
    || !SHA256.test(value.final_authority_sha256)
    || !SHA256.test(value.review_envelope_sha256)
    || !SHA256.test(value.review_evidence_sha256)) {
    fail("an exact live reviewed final-authority runtime projection is required");
  }
  return value;
}

export function readReviewedFinalAuthorityRuntimeDependencies(value) {
  const projection = assertReviewedFinalAuthorityRuntimeProjection(value);
  const dependencies = PROJECTIONS.get(projection).dependencies;
  assertReviewedCeremonyAuthorityProjection(
    dependencies.ceremony_authority_projection,
  );
  assertProjectedChallengeRegistryRuntimeEnvironment(
    dependencies.challenge_registry_runtime_environment_projection,
  );
  if (dependencies.ceremony_authority_projection.finalAuthoritySha256
      !== projection.final_authority_sha256
    || dependencies.challenge_registry_runtime_environment_projection
      .finalAuthoritySha256 !== projection.final_authority_sha256
    || dependencies.final_authority.release_sha !== projection.release_sha
    || dependencies.final_authority.deployment_intent_sha256
      !== projection.deployment_intent_sha256
    || dependencies.final_authority.cvm_launch_intent_sha256
      !== projection.cvm_launch_intent_sha256) {
    fail("reviewed final-authority private dependencies drifted");
  }
  return dependencies;
}

export function reviewedFinalAuthorityRuntimeProjectionSha256(value) {
  return projectionDigest(assertReviewedFinalAuthorityRuntimeProjection(value));
}
