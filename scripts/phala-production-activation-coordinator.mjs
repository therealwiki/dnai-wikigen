import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";
import fs from "node:fs";
import path from "node:path";

import {
  canonicalFreshContractDeploymentReceiptText,
  freshContractDeploymentReceiptDigest,
  normalizeFreshContractDeploymentReceipt,
} from "./cvm-launch-intent-core.mjs";
import {
  canonicalCvmReleaseDescriptorSetReceiptText,
  normalizeCvmReleaseDescriptorSetReceipt,
} from "./cvm-release-descriptor-set.mjs";
import {
  assertCompletedPhalaProductionExecutorRuntimeResult,
  readPhalaProductionExecutorRuntimeDependencies,
} from "./phala-production-executor-runtime.mjs";
import {
  createPhalaSevenCvmReleaseVerificationAuthority,
  createPhalaSevenCvmVerifiedEvidenceSet,
  assertBrandedPhalaSevenCvmReleaseVerificationAuthority,
  assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority,
  assertProductionPhalaSevenCvmEvidenceSet,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
  phalaSevenCvmVerifiedEvidenceSetSha256,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  createPhalaSevenCvmLaunchCompletionReceipt,
  createPersistedPhalaSevenCvmLaunchCompletionReceipt,
  assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt,
  phalaSevenCvmLaunchCompletionReceiptSha256,
} from "./phala-seven-cvm-launch-completion.mjs";
import {
  loadPhalaSevenCvmHistoricalTranscriptPersistenceReceipt,
} from "./phala-seven-cvm-historical-transcript-persistence.mjs";
import {
  canonicalPhalaQvlMeasurementPolicySetText,
  normalizePhalaQvlMeasurementPolicySet,
  phalaQvlMeasurementPolicySetSha256,
} from "./phala-seven-cvm-measurement-policy.mjs";
import {
  canonicalReleaseManifestSigstoreVerificationReceiptText,
  assertProductionReleaseManifestSigstoreVerificationReceipt,
  releaseManifestSigstoreVerificationReceiptSha256,
} from "./release-manifest-sigstore-verifier.mjs";
import {
  canonicalReleaseReviewerAuthorityGenesisArtifactText,
  normalizeReleaseReviewerAuthorityGenesis,
  releaseReviewerAuthorityGenesisSha256,
} from "./release-reviewer-authority-genesis.mjs";
import {
  canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText,
  normalizeReleaseReviewerAuthorityGenesisAcceptance,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  normalizeStageAPinnedReviewerAuthority,
  normalizeStageBSuccessorReviewerAuthority,
} from "./release-authority-current-reviewer-facade.mjs";
import {
  canonicalReleaseCeremonyLedgerInitializationReceiptText,
  normalizeReleaseCeremonyLedgerInitializationReceipt,
  releaseCeremonyLedgerInitializationReceiptSha256,
} from "./release-ceremony-ledger.mjs";
import {
  RELEASE_CEREMONY_LOCK_PROTOCOL,
} from "./release-ceremony-lock.mjs";
import {
  readReviewedFinalAuthorityRuntimeProjection,
  assertReviewedFinalAuthorityRuntimeProjection,
  readReviewedFinalAuthorityRuntimeDependencies,
  reviewedFinalAuthorityRuntimeProjectionSha256,
} from "./reviewed-final-authority-runtime.mjs";
import {
  projectPhalaDeferredPublicEnvironmentAuthority,
  deferredPublicEnvironmentAuthorityDigest,
} from "./phala-production-environment-authority.mjs";
import {
  createPhalaPostMeasurementActivationPlan,
  assertFreshBrandedPhalaPostMeasurementActivationPlan,
  phalaPostMeasurementActivationPlanSha256,
} from "./phala-post-measurement-activation.mjs";
import {
  createPreCeremonyRuntimeAuthority,
  assertFreshBrandedPreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
} from "./pre-ceremony-runtime-authority.mjs";
import {
  CEREMONY_AUTHORIZATION_CORE_SCHEMA,
  CEREMONY_AUTHORIZATION_CORE_STATUS,
  MAX_RELEASE_AUTHORITY_REVIEW_LIFETIME_MS,
  MIN_RELEASE_AUTHORITY_REVIEW_HEADROOM_MS,
  assertFreshProductionCeremonyAuthorizationCore,
  canonicalCeremonyAuthorizationCoreArtifactText,
  ceremonyAuthorizationCoreSha256,
  ceremonyAuthorizationReviewSigningPayloadForProduction,
  releaseAuthorityReviewSigningMessage,
  releaseAuthorityReviewSigningPayloadSha256,
} from "./release-authority-stages.mjs";
import {
  phalaNonLiveBootstrapAuthorizationReceiptSha256,
} from "./phala-nonlive-bootstrap-authorization.mjs";
import {
  assertPinnedPhalaPrivateDirectoryPathIdentity,
  closePhalaPinnedPrivateDirectory,
  createExclusivePhalaPinnedPrivateFile,
  listPhalaPinnedPrivateEntries,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  phalaPinnedPrivatePathForDisplay,
  pinPhalaPrivateDirectory,
  readPhalaPinnedPrivateFile,
} from "./phala-pinned-private-directory.mjs";
import {
  beginProductionPhalaPostMeasurementActivation,
  completeProductionPhalaPostMeasurementActivation,
  quarantineProductionPhalaPostMeasurementActivationSession,
} from "./phala-post-measurement-activation-runtime.mjs";
import {
  consumePhalaProductionPostlaunchActivationCapability,
  disposePhalaProductionPostlaunchActivationCapability,
} from "./phala-production-postlaunch-activation-capability.mjs";

export const PHALA_PRODUCTION_ACTIVATION_EVIDENCE_SESSION_SCHEMA =
  "dnai.phala-production-activation-coordinator-evidence-session.v1";
export const PHALA_PRODUCTION_ACTIVATION_EVIDENCE_SESSION_STATUS =
  "release_authority_ready_pending_exact_seven_cvm_production_evidence";
export const PHALA_PRODUCTION_ACTIVATION_SIGNING_SESSION_SCHEMA =
  "dnai.phala-production-activation-coordinator-signing-session.v1";
export const PHALA_PRODUCTION_ACTIVATION_SIGNING_SESSION_STATUS =
  "l_plan_and_r_ready_pending_exact_canonical_signed_b";
export const PHALA_PRODUCTION_ACTIVATION_RUNTIME_SESSION_SCHEMA =
  "dnai.phala-production-activation-coordinator-runtime-session.v1";
export const PHALA_PRODUCTION_ACTIVATION_RUNTIME_SESSION_STATUS =
  "signed_b_consumed_combined_profile_patch_restart_authenticated_phala_attestation_observed_and_arena_presence_verified_pending_compute_recipient_activation";
export const PHALA_PRODUCTION_ACTIVATION_COORDINATOR_TRUTH =
  "same_process_branded_authority_chain_not_serializable_authority_or_live_traffic";
export const PHALA_PRODUCTION_ACTIVATION_DEFERRED_REVIEW_SCHEMA =
  "dnai.phala-production-activation-deferred-review.v1";
export const PHALA_PRODUCTION_ACTIVATION_DISPOSAL_RECEIPT_SCHEMA =
  "dnai.phala-production-activation-coordinator-disposal-receipt.v1";

const EVIDENCE_SESSION_DOMAIN =
  "dnai-wikigen/phala-production-activation-coordinator-evidence-session/v1\0";
const SIGNING_SESSION_DOMAIN =
  "dnai-wikigen/phala-production-activation-coordinator-signing-session/v1\0";
const RUNTIME_SESSION_DOMAIN =
  "dnai-wikigen/phala-production-activation-coordinator-runtime-session/v1\0";
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;
const MAX_SECRET_FILE_BYTES = 1024 * 1024;
const MAX_SIGNING_FILE_BYTES = 4 * 1024 * 1024;
const STAGE_B_LEASE_MS = 10 * 60 * 1_000;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const RELEASE_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const UTF8 = new TextDecoder("utf-8", { fatal: true });

const EVIDENCE_SESSIONS = new WeakMap();
const SIGNING_SESSIONS = new WeakMap();
const RUNTIME_SESSIONS = new WeakMap();

const QVL_EVIDENCE_DOMAINS = Object.freeze([
  "diligence_qvl_cvm",
  "arena_qvl_cvm",
  "anchor_writer_qvl_cvm",
  "compute_workload_qvl_cvm",
  "compute_metering_qvl_cvm",
]);
const WORKLOAD_EVIDENCE_DOMAINS = Object.freeze([
  "main_runtime_cvm",
  "independent_metering_cvm",
]);

const PREPARE_FIELDS = Object.freeze([
  "descriptorSetReceipt",
  "freshContractDeploymentReceipt",
  "launchRecoveryDirectory",
  "launchRuntimeResult",
  "measurementPolicySet",
  "releaseManifestSigstoreVerificationReceipt",
  "reviewerGenesis",
  "reviewerGenesisAcceptance",
]);
const EVIDENCE_RESUME_FIELDS = Object.freeze([
  "bootstrapPhaseInput",
  "finalPhaseInput",
  "postlaunchActivationCapability",
  "qvlIdentityEvidence",
  "session",
  "signingExchangeDirectory",
  "workloadVerdictEvidence",
]);
const EVIDENCE_PERSIST_FIELDS = Object.freeze([
  "qvlIdentityEvidence",
  "session",
  "workloadVerdictEvidence",
]);
const REVIEWED_FINAL_FILE_FIELDS = Object.freeze([
  "cvmLaunchIntent",
  "deploymentIntent",
  "finalAuthority",
  "reviewEnvelope",
  "reviewEvidence",
]);
const FILE_BINDING_FIELDS = Object.freeze(["path", "sha256"]);

function fail(message) {
  throw new Error(`production activation coordinator: ${message}`);
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactOwnRecord(value, fields, label) {
  if (!isRecord(value) || Object.getPrototypeOf(value) !== Object.prototype
    || Object.getOwnPropertySymbols(value).length !== 0) {
    fail(`${label} must be one exact plain object`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some((descriptor) => (
    !descriptor.enumerable || !Object.hasOwn(descriptor, "value")
  )) || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function ownPostlaunchCapabilityForDisposal(value) {
  if (!isRecord(value)) return null;
  const descriptor = Object.getOwnPropertyDescriptor(
    value,
    "postlaunchActivationCapability",
  );
  return descriptor && Object.hasOwn(descriptor, "value")
    ? descriptor.value
    : null;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonical(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(canonical(value), null, 2)}\n`;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const entry of Object.values(value)) deepFreeze(entry);
  return Object.freeze(value);
}

function domainSha256(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

function rawSha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    fail(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function exactCanonicalPath(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value) {
    fail(`${label} must be a canonical absolute path`);
  }
  return value;
}

function normalizeFileBinding(value, label) {
  const binding = exactOwnRecord(value, FILE_BINDING_FIELDS, `${label} binding`);
  return Object.freeze({
    path: exactCanonicalPath(binding.path, `${label} path`),
    sha256: exactSha256(binding.sha256, `${label} raw file digest`),
  });
}

function stableRead(bindingValue, label, {
  maximum = MAX_ARTIFACT_BYTES,
  minimum = 1,
  exactMode,
} = {}) {
  const binding = normalizeFileBinding(bindingValue, label);
  let fd;
  try {
    const lstat = fs.lstatSync(binding.path, { bigint: true });
    if (lstat.isSymbolicLink() || !lstat.isFile() || lstat.nlink !== 1n
      || (typeof process.getuid === "function"
        && lstat.uid !== BigInt(process.getuid()))
      || (lstat.mode & 0o022n) !== 0n
      || (exactMode !== undefined
        && (lstat.mode & 0o777n) !== BigInt(exactMode))
      || lstat.size < BigInt(minimum) || lstat.size > BigInt(maximum)
      || fs.realpathSync.native(binding.path) !== binding.path) {
      fail(`${label} file posture is not stable, private, and current-owner`);
    }
    fd = fs.openSync(binding.path, fs.constants.O_RDONLY | NOFOLLOW);
    const before = fs.fstatSync(fd, { bigint: true });
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd, { bigint: true });
    const current = fs.lstatSync(binding.path, { bigint: true });
    for (const observed of [before, after, current]) {
      if (!observed.isFile() || observed.nlink !== 1n
        || (typeof process.getuid === "function"
          && observed.uid !== BigInt(process.getuid()))
        || (observed.mode & 0o022n) !== 0n
        || (exactMode !== undefined
          && (observed.mode & 0o777n) !== BigInt(exactMode))) {
        fail(`${label} file posture changed during its bounded read`);
      }
    }
    const identity = (value) => [
      value.dev, value.ino, value.size, value.mtimeNs, value.ctimeNs,
    ].map(String).join(":");
    if (identity(before) !== identity(after)
      || identity(after) !== identity(current)
      || BigInt(bytes.length) !== before.size
      || rawSha256(bytes) !== binding.sha256) {
      fail(`${label} bytes or authenticated file identity changed`);
    }
    return Object.freeze({ binding, bytes, stat: before });
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function parseJson(read, label) {
  let text;
  let value;
  try {
    text = UTF8.decode(read.bytes);
    value = JSON.parse(text);
  } catch {
    fail(`${label} must contain bounded valid UTF-8 JSON`);
  }
  return { ...read, text, value };
}

function readCanonicalJson(binding, label, canonicalize, options) {
  const read = parseJson(stableRead(binding, label, options), label);
  const normalizedText = canonicalize(read.value);
  if (read.text !== normalizedText) {
    fail(`${label} bytes are not the exact canonical artifact`);
  }
  return Object.freeze({ ...read, normalizedText });
}

function readStrictCanonicalJson(binding, label, options) {
  return readCanonicalJson(binding, label, canonicalText, options);
}

function canonicalSecond(value, label) {
  if (typeof value !== "string" || !ISO_SECOND.test(value)
    || new Date(Date.parse(value)).toISOString().replace(".000Z", "Z") !== value) {
    fail(`${label} must be a canonical UTC second`);
  }
  return value;
}

function canonicalMillisecond(timeMs) {
  return new Date(timeMs).toISOString();
}

function publicFileIdentity(identity, basename) {
  return Object.freeze({
    basename,
    sha256: identity.sha256,
    size: identity.size,
    mode: identity.mode,
  });
}

function closeEvidenceState(state) {
  if (state?.recoveryHandle) {
    closePhalaPinnedPrivateDirectory(state.recoveryHandle);
    state.recoveryHandle = null;
  }
}

function closeSigningState(state) {
  if (state?.signingHandle) {
    closePhalaPinnedPrivateDirectory(state.signingHandle);
    state.signingHandle = null;
  }
  closeEvidenceState(state);
}

function sessionDigest(domain, value) {
  return domainSha256(domain, value);
}

/**
 * Enter the production evidence phase from the exact completed launch object.
 * The public return value is deliberately insufficient to reconstruct the
 * release-verification brand after serialization; the original launch result,
 * its private dependency view, and the release authority remain in this
 * process behind EVIDENCE_SESSIONS.
 */
export function preparePhalaProductionActivationEvidence(input = {}) {
  const parsed = exactOwnRecord(
    input,
    PREPARE_FIELDS,
    "production activation evidence preparation input",
  );
  const launch = assertCompletedPhalaProductionExecutorRuntimeResult(
    parsed.launchRuntimeResult,
  );
  const dependencies = readPhalaProductionExecutorRuntimeDependencies(launch);
  const recoveryDirectory = exactCanonicalPath(
    parsed.launchRecoveryDirectory,
    "launch recovery directory",
  );
  let recoveryHandle;
  try {
    recoveryHandle = pinPhalaPrivateDirectory(recoveryDirectory, {
      expectedIdentityAnchorSha256:
        launch.phala_recovery_directory_identity_anchor_sha256,
    });

    const measurementRead = parseJson(stableRead(
      parsed.measurementPolicySet,
      "QVL measurement policy set",
    ), "QVL measurement policy set");
    const measurementPolicySet = normalizePhalaQvlMeasurementPolicySet(
      measurementRead.value,
    );
    if (measurementRead.text
        !== canonicalPhalaQvlMeasurementPolicySetText(measurementPolicySet)) {
      fail("QVL measurement policy set bytes are not canonical");
    }

    const reviewerGenesisRead = parseJson(stableRead(
      parsed.reviewerGenesis,
      "reviewer genesis",
    ), "reviewer genesis");
    const reviewerGenesis = normalizeReleaseReviewerAuthorityGenesis(
      reviewerGenesisRead.value,
    );
    if (reviewerGenesisRead.text
        !== canonicalReleaseReviewerAuthorityGenesisArtifactText(
          reviewerGenesis,
        )) {
      fail("reviewer genesis bytes are not canonical");
    }
    const reviewerAcceptanceRead = parseJson(stableRead(
      parsed.reviewerGenesisAcceptance,
      "reviewer genesis acceptance",
    ), "reviewer genesis acceptance");
    const reviewerRootStatusHistory = Object.freeze([]);
    const reviewerGenesisAcceptance =
      normalizeReleaseReviewerAuthorityGenesisAcceptance(
        reviewerAcceptanceRead.value,
        { reviewerGenesis, statusHistory: reviewerRootStatusHistory },
      );
    if (reviewerAcceptanceRead.text
        !== canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
          reviewerGenesisAcceptance,
          { reviewerGenesis, statusHistory: reviewerRootStatusHistory },
        )) {
      fail("reviewer genesis-acceptance bytes are not canonical");
    }
    const reviewerAcceptanceSha256 =
      releaseReviewerAuthorityGenesisAcceptanceSha256(
        reviewerGenesisAcceptance,
        { reviewerGenesis, statusHistory: reviewerRootStatusHistory },
      );

    const freshReceiptRead = parseJson(stableRead(
      parsed.freshContractDeploymentReceipt,
      "fresh contract deployment receipt",
    ), "fresh contract deployment receipt");
    const freshReceiptPins = {
      expectedDeploymentIntentSha256:
        dependencies.signed_a_receipt.deployment_intent_sha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        reviewerAcceptanceSha256,
    };
    const freshContractDeploymentReceipt =
      normalizeFreshContractDeploymentReceipt(
        freshReceiptRead.value,
        freshReceiptPins,
      );
    if (freshReceiptRead.text
        !== canonicalFreshContractDeploymentReceiptText(
          freshContractDeploymentReceipt,
          freshReceiptPins,
        )) {
      fail("fresh contract deployment receipt bytes are not canonical");
    }
    const freshReceiptSha256 = `sha256:${freshContractDeploymentReceiptDigest(
      freshContractDeploymentReceipt,
      freshReceiptPins,
    )}`;

    const sigstoreRead = readCanonicalJson(
      parsed.releaseManifestSigstoreVerificationReceipt,
      "release-manifest Sigstore verification receipt",
      canonicalReleaseManifestSigstoreVerificationReceiptText,
    );
    const releaseManifestSigstoreVerificationReceipt =
      assertProductionReleaseManifestSigstoreVerificationReceipt(
        sigstoreRead.value,
      );
    const descriptorRead = readCanonicalJson(
      parsed.descriptorSetReceipt,
      "CVM descriptor-set receipt",
      canonicalCvmReleaseDescriptorSetReceiptText,
    );
    const descriptorSetReceipt = normalizeCvmReleaseDescriptorSetReceipt(
      descriptorRead.value,
    );

    const signedA = dependencies.signed_a_receipt;
    if (phalaQvlMeasurementPolicySetSha256(measurementPolicySet)
        !== signedA.qvl_measurement_policy_set_sha256
      || freshReceiptSha256
        !== signedA.fresh_contract_deployment_receipt_sha256
      || releaseManifestSigstoreVerificationReceiptSha256(
        releaseManifestSigstoreVerificationReceipt,
      ) !== signedA.image_release_sigstore_verification_receipt_sha256
      || descriptorSetReceipt.release_sha !== launch.release_sha
      || descriptorSetReceipt.image_manifest_sha256
        !== releaseManifestSigstoreVerificationReceipt.release_manifest_sha256
      || JSON.stringify(descriptorSetReceipt.descriptor_sha256_by_domain)
        !== JSON.stringify(signedA.descriptor_sha256_by_domain)) {
      fail("stable release artifacts do not form the completed signed-A lineage");
    }

    const releaseVerificationAuthority =
      createPhalaSevenCvmReleaseVerificationAuthority({
        signedAReceipt: signedA,
        bootstrapAuthority:
          dependencies.bootstrap_public_environment_authority,
        descriptorRuntimeAuthority:
          dependencies.cvm_descriptor_runtime_authority,
        measurementPolicySet,
        productionPostureReceipts:
          dependencies.production_posture_receipts,
        freshContractDeploymentReceipt,
        reviewerAuthorityGenesisAcceptanceSha256:
          reviewerAcceptanceSha256,
      });
    assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority(
      releaseVerificationAuthority,
    );
    const releaseAuthoritySha256 =
      phalaSevenCvmReleaseVerificationAuthoritySha256(
        releaseVerificationAuthority,
      );
    const publicSession = deepFreeze({
      schema: PHALA_PRODUCTION_ACTIVATION_EVIDENCE_SESSION_SCHEMA,
      status: PHALA_PRODUCTION_ACTIVATION_EVIDENCE_SESSION_STATUS,
      truth_status: PHALA_PRODUCTION_ACTIVATION_COORDINATOR_TRUTH,
      release_sha: launch.release_sha,
      batch_id: launch.batch_id,
      release_verification_authority_sha256: releaseAuthoritySha256,
      qvl_identity_evidence_domains: [...QVL_EVIDENCE_DOMAINS],
      workload_verdict_evidence_domains: [...WORKLOAD_EVIDENCE_DOMAINS],
      required_qvl_identity_evidence_count: QVL_EVIDENCE_DOMAINS.length,
      required_workload_verdict_evidence_count:
        WORKLOAD_EVIDENCE_DOMAINS.length,
      phala_recovery_directory_identity_anchor_sha256:
        phalaPinnedPrivateDirectoryIdentityAnchorSha256(recoveryHandle),
      next_required_input:
        "five_branded_production_qvl_identity_proofs_and_two_branded_production_workload_verdict_proofs",
      automatic_retry_authorized: false,
      activation_mutation_authorized: false,
      live_traffic_authorized: false,
    });
    const privateState = {
      consumed: false,
      publicDigest: sessionDigest(EVIDENCE_SESSION_DOMAIN, publicSession),
      launch,
      dependencies,
      recoveryDirectory,
      recoveryHandle,
      measurementPolicySet,
      freshContractDeploymentReceipt,
      freshReceiptSha256,
      reviewerGenesis,
      reviewerGenesisAcceptance,
      reviewerGenesisSha256:
        releaseReviewerAuthorityGenesisSha256(reviewerGenesis),
      reviewerGenesisAcceptanceSha256: reviewerAcceptanceSha256,
      releaseManifestSigstoreVerificationReceipt,
      descriptorSetReceipt,
      releaseVerificationAuthority,
      evidenceCheckpoint: null,
      launchCompletionCheckpoint: null,
      historicalTranscriptState: "not_attempted",
    };
    EVIDENCE_SESSIONS.set(publicSession, privateState);
    recoveryHandle = null;
    return publicSession;
  } finally {
    if (recoveryHandle) closePhalaPinnedPrivateDirectory(recoveryHandle);
  }
}

export function assertPhalaProductionActivationEvidenceSession(value) {
  const state = value && EVIDENCE_SESSIONS.get(value);
  if (!state || state.consumed
    || value.schema !== PHALA_PRODUCTION_ACTIVATION_EVIDENCE_SESSION_SCHEMA
    || value.status !== PHALA_PRODUCTION_ACTIVATION_EVIDENCE_SESSION_STATUS
    || value.truth_status !== PHALA_PRODUCTION_ACTIVATION_COORDINATOR_TRUTH
    || sessionDigest(EVIDENCE_SESSION_DOMAIN, value) !== state.publicDigest
    || value.activation_mutation_authorized !== false
    || value.live_traffic_authorized !== false) {
    fail("an exact live same-process evidence session is required");
  }
  assertCompletedPhalaProductionExecutorRuntimeResult(state.launch);
  readPhalaProductionExecutorRuntimeDependencies(state.launch);
  assertBrandedPhalaSevenCvmReleaseVerificationAuthority(
    state.releaseVerificationAuthority,
  );
  assertPinnedPhalaPrivateDirectoryPathIdentity(state.recoveryHandle);
  return value;
}

export function readPhalaProductionActivationEvidenceDependencies(value) {
  const session = assertPhalaProductionActivationEvidenceSession(value);
  const state = EVIDENCE_SESSIONS.get(session);
  return Object.freeze({
    releaseVerificationAuthority: state.releaseVerificationAuthority,
  });
}

function normalizeDeferredReview(value, expected) {
  const parsed = exactOwnRecord(value, [
    "cvm_launch_intent_sha256",
    "deployment_intent_sha256",
    "final_authority_sha256",
    "release_sha",
    "reviewed_at",
    "reviewed_unresolved_values_by_domain",
    "schema",
    "valid_until",
  ], "deferred-authority review artifact");
  if (parsed.schema !== PHALA_PRODUCTION_ACTIVATION_DEFERRED_REVIEW_SCHEMA
    || parsed.release_sha !== expected.releaseSha
    || parsed.deployment_intent_sha256 !== expected.deploymentIntentSha256
    || parsed.cvm_launch_intent_sha256 !== expected.cvmLaunchIntentSha256
    || !RELEASE_SHA.test(parsed.release_sha)
    || parsed.final_authority_sha256 !== exactSha256(
      parsed.final_authority_sha256,
      "deferred-review final authority",
    )) {
    fail("deferred-authority review does not bind the exact release lineage");
  }
  const reviewedAt = canonicalSecond(parsed.reviewed_at, "deferred reviewed_at");
  const validUntil = canonicalSecond(parsed.valid_until, "deferred valid_until");
  if (Date.parse(validUntil) <= Date.parse(reviewedAt)) {
    fail("deferred-authority review validity window is invalid");
  }
  if (!Array.isArray(parsed.reviewed_unresolved_values_by_domain)) {
    fail("deferred-authority unresolved values must be one exact array");
  }
  return Object.freeze({
    ...parsed,
    reviewed_at: reviewedAt,
    valid_until: validUntil,
  });
}

function readReviewedFinalAuthoritySet(filesValue, deferredReviewBinding, state) {
  const deferredRead = readStrictCanonicalJson(
    deferredReviewBinding,
    "deferred-authority review",
  );
  const deferredReview = normalizeDeferredReview(deferredRead.value, {
    releaseSha: state.launch.release_sha,
    deploymentIntentSha256:
      state.dependencies.signed_a_receipt.deployment_intent_sha256,
    cvmLaunchIntentSha256:
      state.dependencies.signed_a_receipt.cvm_launch_intent_sha256,
  });
  const files = exactOwnRecord(
    filesValue,
    REVIEWED_FINAL_FILE_FIELDS,
    "reviewed final-authority file set",
  );
  const bindings = Object.freeze({
    deploymentIntent: normalizeFileBinding(
      files.deploymentIntent,
      "reviewed deployment intent",
    ),
    cvmLaunchIntent: normalizeFileBinding(
      files.cvmLaunchIntent,
      "reviewed CVM launch intent",
    ),
    finalAuthority: normalizeFileBinding(
      files.finalAuthority,
      "reviewed final authority",
    ),
    reviewEnvelope: normalizeFileBinding(
      files.reviewEnvelope,
      "reviewed final-authority envelope",
    ),
    reviewEvidence: normalizeFileBinding(
      files.reviewEvidence,
      "reviewed final-authority evidence",
    ),
  });
  for (const [key, binding] of Object.entries(bindings)) {
    stableRead(binding, `reviewed final-authority ${key}`);
  }
  const projection = readReviewedFinalAuthorityRuntimeProjection({
    deploymentIntentPath: bindings.deploymentIntent.path,
    cvmLaunchIntentPath: bindings.cvmLaunchIntent.path,
    finalAuthorityPath: bindings.finalAuthority.path,
    reviewEnvelopePath: bindings.reviewEnvelope.path,
    reviewEvidencePath: bindings.reviewEvidence.path,
    expectedReleaseSha: state.launch.release_sha,
    expectedFinalAuthoritySha256: deferredReview.final_authority_sha256,
  });
  assertReviewedFinalAuthorityRuntimeProjection(projection);
  const projectedFilePins = projection.artifact_file_sha256;
  if (!isRecord(projectedFilePins)
    || projectedFilePins.deployment_intent !== bindings.deploymentIntent.sha256
    || projectedFilePins.cvm_launch_intent !== bindings.cvmLaunchIntent.sha256
    || projectedFilePins.final_authority !== bindings.finalAuthority.sha256
    || projectedFilePins.review_envelope !== bindings.reviewEnvelope.sha256
    || projectedFilePins.review_evidence !== bindings.reviewEvidence.sha256) {
    fail("reviewed final-authority projection differs from the five authenticated file pins");
  }
  for (const [key, binding] of Object.entries(bindings)) {
    stableRead(binding, `reviewed final-authority ${key}`);
  }
  if (projection.final_authority_sha256
      !== deferredReview.final_authority_sha256
    || projection.deployment_intent_sha256
      !== deferredReview.deployment_intent_sha256
    || projection.cvm_launch_intent_sha256
      !== deferredReview.cvm_launch_intent_sha256
    || Date.parse(deferredReview.reviewed_at) < Date.parse(
      projection.review_approved_at,
    )
    || Date.parse(deferredReview.valid_until) > Date.parse(
      projection.review_expires_at,
    )
    || Date.now() < Date.parse(deferredReview.reviewed_at)
    || Date.now() >= Date.parse(deferredReview.valid_until)) {
    fail("deferred review is stale, future-dated, or outside the reviewed final-authority window");
  }
  return Object.freeze({ bindings, projection, deferredReview });
}

function stageBBodyAndPayload({
  state,
  reviewedSet,
  deploymentIntent,
  reviewerStage,
  runtimeAuthority,
  evidenceSet,
  initializationReceiptBinding,
  immutableManifestBinding,
  initialLedgerBinding,
  transactionPlanBinding,
}) {
  const initializationRead = readCanonicalJson(
    initializationReceiptBinding,
    "ceremony ledger initialization receipt",
    canonicalReleaseCeremonyLedgerInitializationReceiptText,
    { exactMode: 0o444 },
  );
  const initialization = normalizeReleaseCeremonyLedgerInitializationReceipt(
    initializationRead.value,
  );
  const immutableManifest = stableRead(
    immutableManifestBinding,
    "immutable deployment manifest",
    { exactMode: 0o444, minimum: 2 },
  );
  const initialLedger = stableRead(
    initialLedgerBinding,
    "initial ceremony ledger",
    { exactMode: 0o600, minimum: 2 },
  );
  const transactionPlanRead = readStrictCanonicalJson(
    transactionPlanBinding,
    "ceremony transaction plan",
  );
  const initializationSha256 =
    releaseCeremonyLedgerInitializationReceiptSha256(initialization);
  if (initialization.release_sha !== state.launch.release_sha
    || initialization.deployment_intent_sha256
      !== reviewedSet.projection.deployment_intent_sha256
    || initialization.fresh_contract_deployment_receipt_sha256
      !== state.freshReceiptSha256
    || initialization.evidence.initialization_receipt_path
      !== initializationReceiptBinding.path
    || initialization.deployment_manifest.path
      !== immutableManifestBinding.path
    || initialization.deployment_manifest.sha256
      !== immutableManifestBinding.sha256
    || initialization.deployment_manifest.bytes !== immutableManifest.bytes.length
    || initialization.ledger.path !== initialLedgerBinding.path
    || initialization.ledger.sha256 !== initialLedgerBinding.sha256
    || initialization.ledger.bytes !== initialLedger.bytes.length
    || immutableManifestBinding.sha256 !== initialLedgerBinding.sha256
    || !immutableManifest.bytes.equals(initialLedger.bytes)) {
    fail("ceremony initialization files do not bind the exact immutable deployment manifest copy");
  }

  const signedA = state.dependencies.signed_a_receipt;
  const body = {
    schema: CEREMONY_AUTHORIZATION_CORE_SCHEMA,
    status: CEREMONY_AUTHORIZATION_CORE_STATUS,
    truth_status:
      "pre_ceremony_authorization_not_finalized_ceremony_or_live_activation",
    release_sha: state.launch.release_sha,
    network: { chain_id: 84_532, name: "base-sepolia" },
    deployment_authority: {
      deployment_intent_sha256: reviewedSet.projection.deployment_intent_sha256,
      reviewer_authority_genesis_sha256:
        state.reviewerGenesisSha256,
      reviewer_authority_genesis_acceptance_sha256:
        state.reviewerGenesisAcceptanceSha256,
      fresh_contract_deployment_receipt_sha256:
        state.freshReceiptSha256,
      immutable_deployment_manifest: {
        path: immutableManifestBinding.path,
        sha256: immutableManifestBinding.sha256,
        bytes: immutableManifest.bytes.length,
        mode: 0o444,
        schema_version: 2,
      },
      toolchain: deploymentIntent.release.toolchain,
    },
    cvm_launch_intent_sha256: reviewedSet.projection.cvm_launch_intent_sha256,
    cvm_bootstrap_authorization_receipt_sha256:
      phalaNonLiveBootstrapAuthorizationReceiptSha256(signedA),
    pre_ceremony_runtime_authority_sha256:
      preCeremonyRuntimeAuthoritySha256(runtimeAuthority),
    ceremony_ledger_initialization: {
      initialization_receipt_path: initializationReceiptBinding.path,
      initialization_receipt_sha256: initializationSha256,
      ledger_path: initialLedgerBinding.path,
      ledger_initial_sha256: initialLedgerBinding.sha256,
      ledger_initial_bytes: initialLedger.bytes.length,
      ledger_mode: 0o600,
      source_manifest_sha256: immutableManifestBinding.sha256,
      lock_protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
    },
    ceremony_transaction_plan: transactionPlanRead.value,
    lock_protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
  };

  const now = Date.now();
  const maximumExpiry = Math.min(
    now + Math.min(STAGE_B_LEASE_MS, MAX_RELEASE_AUTHORITY_REVIEW_LIFETIME_MS),
    evidenceSet.minimum_activation_evidence_lease_expires_at * 1_000 - 1_000,
    Date.parse(reviewedSet.projection.review_expires_at) - 1_000,
    Date.parse(reviewedSet.deferredReview.valid_until) - 1_000,
    Date.parse(reviewerStage.currentStatusExpiresAt),
  );
  if (maximumExpiry - now < MIN_RELEASE_AUTHORITY_REVIEW_HEADROOM_MS) {
    fail("insufficient fresh evidence/review headroom remains to issue the Stage-B signing lease");
  }
  const reviewMetadata = {
    reviewer_authority_genesis_sha256:
      state.reviewerGenesisSha256,
    reviewer_authority_genesis_acceptance_sha256:
      state.reviewerGenesisAcceptanceSha256,
    reviewer_authority_current_status_epoch:
      reviewerStage.currentStatus.epoch,
    reviewer_authority_current_status_sha256:
      reviewerStage.currentStatusSha256,
    approved_reviewer_hashes:
      reviewerStage.authority.approved_reviewer_hashes,
    reviewer_root_hash: reviewerStage.authority.reviewer_root_hash,
    reviewer_set_sha256: reviewerStage.authority.reviewer_set_sha256,
    signed_at: canonicalMillisecond(now),
    expires_at: canonicalMillisecond(maximumExpiry),
  };
  const payload = ceremonyAuthorizationReviewSigningPayloadForProduction(
    body,
    reviewMetadata,
    { preCeremonyRuntimeAuthority: runtimeAuthority },
  );
  return Object.freeze({
    body: deepFreeze(body),
    payload: deepFreeze(payload),
    reviewMetadata: deepFreeze(reviewMetadata),
    reviewerStage,
    deploymentIntent,
    initialization,
  });
}

function launchCompletionDependencies(state, evidenceSet) {
  return {
    signedAReceipt: state.dependencies.signed_a_receipt,
    freshContractDeploymentReceipt: state.freshContractDeploymentReceipt,
    reviewerAuthorityGenesisAcceptanceSha256:
      state.reviewerGenesisAcceptanceSha256,
    releaseManifestSigstoreVerificationReceipt:
      state.releaseManifestSigstoreVerificationReceipt,
    descriptorSetReceipt: state.descriptorSetReceipt,
    executorFinalState: state.dependencies.executor_final_state,
    productionPostureReceipts:
      state.dependencies.production_posture_receipts,
    releaseVerificationAuthority: state.releaseVerificationAuthority,
    verifiedEvidenceSet: evidenceSet,
  };
}

function requireOriginalProofReferences(value, retained, label) {
  if (!Array.isArray(value) || value.length !== retained.length
    || value.some((candidate, index) => candidate !== retained[index])) {
    fail(`${label} must contain the exact original same-process proof objects`);
  }
}

function evidenceSetForResume(state, parsed) {
  const checkpoint = state.evidenceCheckpoint;
  if (checkpoint !== null) {
    requireOriginalProofReferences(
      parsed.qvlIdentityEvidence,
      checkpoint.qvlIdentityEvidence,
      "QVL identity evidence retry",
    );
    requireOriginalProofReferences(
      parsed.workloadVerdictEvidence,
      checkpoint.workloadVerdictEvidence,
      "workload verdict evidence retry",
    );
    assertProductionPhalaSevenCvmEvidenceSet(checkpoint.evidenceSet);
    return checkpoint.evidenceSet;
  }
  const evidenceSet = createPhalaSevenCvmVerifiedEvidenceSet({
    releaseAuthority: state.releaseVerificationAuthority,
    qvlIdentityEvidence: parsed.qvlIdentityEvidence,
    workloadVerdictEvidence: parsed.workloadVerdictEvidence,
  });
  assertProductionPhalaSevenCvmEvidenceSet(evidenceSet);
  return evidenceSet;
}

function checkpointEvidenceForPersistence(state, parsed, evidenceSet) {
  if (state.evidenceCheckpoint !== null) {
    if (state.evidenceCheckpoint.evidenceSet !== evidenceSet) {
      fail("persisted evidence checkpoint changed during explicit recovery");
    }
    return state.evidenceCheckpoint;
  }
  const checkpoint = Object.freeze({
    evidenceSet,
    qvlIdentityEvidence: Object.freeze([...parsed.qvlIdentityEvidence]),
    workloadVerdictEvidence: Object.freeze([
      ...parsed.workloadVerdictEvidence,
    ]),
  });
  state.evidenceCheckpoint = checkpoint;
  return checkpoint;
}

function loadExactHistoricalTranscript(state, evidenceSet) {
  return loadPhalaSevenCvmHistoricalTranscriptPersistenceReceipt({
    directory: state.recoveryDirectory,
    directoryIdentityAnchorSha256:
      state.dependencies.executor_final_state
        .phala_recovery_directory_identity_anchor_sha256,
    expectedSevenCvmVerifiedEvidenceSetSha256:
      phalaSevenCvmVerifiedEvidenceSetSha256(evidenceSet),
    expectedHistoricalTranscriptFileSetSha256:
      evidenceSet.historical_transcript_file_set_sha256,
  });
}

function completionFromHistoricalTranscript(
  state,
  evidenceSet,
  historicalTranscriptPersistenceReceipt,
) {
  return createPhalaSevenCvmLaunchCompletionReceipt({
    ...launchCompletionDependencies(state, evidenceSet),
    historicalTranscriptPersistenceReceipt,
  });
}

async function persistOrRecoverLaunchCompletion({
  state,
  evidenceSet,
  qvlIdentityEvidence,
  workloadVerdictEvidence,
}) {
  state.historicalTranscriptState =
    "existing_transcript_state_unreconciled_operator_recovery_required";
  const existing = loadExactHistoricalTranscript(state, evidenceSet);
  if (existing !== null) {
    state.historicalTranscriptState = "exact_committed_reloaded";
    return completionFromHistoricalTranscript(state, evidenceSet, existing);
  }
  state.historicalTranscriptState = "persistence_attempted_unknown_or_partial";
  try {
    const completion =
      await createPersistedPhalaSevenCvmLaunchCompletionReceipt({
        recoveryDirectory: state.recoveryDirectory,
        qvlIdentityEvidence,
        workloadVerdictEvidence,
        ...launchCompletionDependencies(state, evidenceSet),
      });
    state.historicalTranscriptState = "exact_committed_created";
    return completion;
  } catch (persistenceError) {
    // Reconcile the only ambiguous safe case: the write-once manifest reached
    // its durable commit boundary but the facade failed before returning L.
    // This is a replay from exact persisted authority, not a proof retry.
    let recovered;
    try {
      recovered = loadExactHistoricalTranscript(state, evidenceSet);
    } catch (recoveryError) {
      throw new AggregateError(
        [persistenceError, recoveryError],
        "historical transcript persistence failed and durable state could not be reconciled",
      );
    }
    if (recovered === null) throw persistenceError;
    state.historicalTranscriptState = "exact_committed_recovered";
    return completionFromHistoricalTranscript(state, evidenceSet, recovered);
  }
}

/**
 * Persist the exact seven-CVM historical transcript and mint L before any
 * reviewed final-authority dependency is accepted. The returned values retain
 * their production brands only inside this process; the evidence session stays
 * live so the resident driver can wait for a separately supplied postlaunch
 * authority manifest and then enter the existing Stage-B path.
 */
export async function persistPhalaProductionActivationLaunchCompletion(
  input = {},
) {
  const parsed = exactOwnRecord(
    input,
    EVIDENCE_PERSIST_FIELDS,
    "production activation launch-completion persistence input",
  );
  const publicEvidenceSession = assertPhalaProductionActivationEvidenceSession(
    parsed.session,
  );
  const state = EVIDENCE_SESSIONS.get(publicEvidenceSession);
  state.consumed = true;
  try {
    if (state.launchCompletionCheckpoint !== null) {
      fail("one launch-completion checkpoint was already persisted for this session");
    }
    if (!Array.isArray(parsed.qvlIdentityEvidence)
      || !Array.isArray(parsed.workloadVerdictEvidence)) {
      fail("seven-CVM proof inputs must be exact arrays of branded proofs");
    }
    const evidenceSet = evidenceSetForResume(state, parsed);
    const evidenceCheckpoint = checkpointEvidenceForPersistence(
      state,
      parsed,
      evidenceSet,
    );
    const launchCompletion = await persistOrRecoverLaunchCompletion({
      state,
      evidenceSet,
      qvlIdentityEvidence: evidenceCheckpoint.qvlIdentityEvidence,
      workloadVerdictEvidence: evidenceCheckpoint.workloadVerdictEvidence,
    });
    assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt(launchCompletion);
    state.launchCompletionCheckpoint = launchCompletion;
    state.consumed = false;
    return Object.freeze({
      release_sha: state.launch.release_sha,
      batch_id: state.launch.batch_id,
      releaseVerificationAuthority: state.releaseVerificationAuthority,
      verifiedEvidenceSet: evidenceCheckpoint.evidenceSet,
      launchCompletionReceipt: launchCompletion,
      activation_mutation_authorized: false,
      live_traffic_authorized: false,
    });
  } catch (error) {
    // persistOrRecoverLaunchCompletion() performs its one permitted durable
    // reconciliation inside this call. Any error that escapes is terminal:
    // automatic retry would contradict the public session posture and could
    // compete with unknown partially persisted authority.
    EVIDENCE_SESSIONS.delete(publicEvidenceSession);
    closeEvidenceState(state);
    throw error;
  }
}

/**
 * Consume exact branded production proofs, persist their historical transcript,
 * mint L -> deferred authority -> plan -> R, and publish the canonical Stage-B
 * unsigned body and signing payload into a newly pinned private exchange.
 */
export async function resumePhalaProductionActivationWithEvidence(input = {}) {
  const capability = ownPostlaunchCapabilityForDisposal(input);
  try {
    return await resumePhalaProductionActivationWithEvidenceInternal(input);
  } finally {
    disposePhalaProductionPostlaunchActivationCapability(capability);
  }
}

/**
 * Resident-only entry point. The caller must have exclusively created and
 * retained the exact empty Stage-B exchange before any CVM mutation. The live
 * pinned handle is transferred into the coordinator on success; a serialized
 * path, clone, or pre-existing directory cannot substitute for it.
 */
export async function resumePhalaProductionActivationWithPinnedSigningExchange(
  input = {},
) {
  const capability = ownPostlaunchCapabilityForDisposal(input);
  try {
    const parsed = exactOwnRecord(
      input,
      [...EVIDENCE_RESUME_FIELDS, "signingExchangeAuthority"],
      "resident production activation evidence resume input",
    );
    const legacyInput = Object.fromEntries(
      EVIDENCE_RESUME_FIELDS.map((field) => [field, parsed[field]]),
    );
    return await resumePhalaProductionActivationWithEvidenceInternal(
      legacyInput,
      { pinnedSigningHandle: parsed.signingExchangeAuthority },
    );
  } finally {
    disposePhalaProductionPostlaunchActivationCapability(capability);
  }
}

async function resumePhalaProductionActivationWithEvidenceInternal(
  input = {},
  { pinnedSigningHandle = null } = {},
) {
  const parsed = exactOwnRecord(
    input,
    EVIDENCE_RESUME_FIELDS,
    "production activation evidence resume input",
  );
  const publicEvidenceSession = assertPhalaProductionActivationEvidenceSession(
    parsed.session,
  );
  const state = EVIDENCE_SESSIONS.get(publicEvidenceSession);
  state.consumed = true;
  let signingHandle;
  try {
    if (state.evidenceCheckpoint === null
      || state.launchCompletionCheckpoint === null) {
      disposePhalaProductionPostlaunchActivationCapability(
        parsed.postlaunchActivationCapability,
      );
      fail("exact persisted L checkpoint is required before postlaunch resume");
    }
    // Burn the manifest capability against the exact stored L/evidence
    // checkpoint before interpreting any caller-supplied proof array. A wrong
    // array is a terminal post-claim failure, never an opportunity to retry the
    // same independently reviewed final-authority manifest.
    const postlaunchAuthority =
      consumePhalaProductionPostlaunchActivationCapability(
        parsed.postlaunchActivationCapability,
        {
          evidenceSession: publicEvidenceSession,
          releaseSha: state.launch.release_sha,
          batchId: state.launch.batch_id,
          releaseVerificationAuthority: state.releaseVerificationAuthority,
          verifiedEvidenceSet: state.evidenceCheckpoint.evidenceSet,
          launchCompletionReceipt: state.launchCompletionCheckpoint,
        },
      );
    const postlaunchDependencies = postlaunchAuthority.dependencies;
    if (!Array.isArray(parsed.qvlIdentityEvidence)
      || !Array.isArray(parsed.workloadVerdictEvidence)) {
      fail("seven-CVM proof inputs must be exact arrays of branded proofs");
    }
    const evidenceSet = evidenceSetForResume(state, parsed);
    if (state.evidenceCheckpoint.evidenceSet !== evidenceSet) {
      fail("exact persisted L checkpoint is required before postlaunch resume");
    }
    const stageBReviewerStatusHistoryBinding = normalizeFileBinding(
      postlaunchAuthority.stageBReviewerStatusHistoryBinding,
      "late-bound Stage-B reviewer status history",
    );
    const stageBReviewerStatusHistoryRead = readStrictCanonicalJson(
      stageBReviewerStatusHistoryBinding,
      "late-bound Stage-B reviewer status history",
      { exactMode: 0o600 },
    );
    if (!Array.isArray(stageBReviewerStatusHistoryRead.value)
      || canonicalText(stageBReviewerStatusHistoryRead.value)
        !== canonicalText(postlaunchAuthority.stageBReviewerStatusHistory)) {
      fail("late-bound Stage-B reviewer status history changed after capability consumption");
    }
    const stageBReviewerStatusHistory = deepFreeze(
      stageBReviewerStatusHistoryRead.value,
    );
    const bootstrapPhaseInput = normalizeFileBinding(
      parsed.bootstrapPhaseInput,
      "main-runtime bootstrap phase secret input",
    );
    const finalPhaseInput = normalizeFileBinding(
      parsed.finalPhaseInput,
      "main-runtime final phase secret input",
    );
    stableRead(
      bootstrapPhaseInput,
      "main-runtime bootstrap phase secret input",
      { exactMode: 0o600, maximum: MAX_SECRET_FILE_BYTES, minimum: 2 },
    );
    stableRead(
      finalPhaseInput,
      "main-runtime final phase secret input",
      { exactMode: 0o600, maximum: MAX_SECRET_FILE_BYTES, minimum: 2 },
    );
    const initializationReceiptBinding = normalizeFileBinding(
      postlaunchDependencies.ceremonyLedgerInitializationReceipt,
      "ceremony ledger initialization receipt",
    );
    const immutableManifestBinding = normalizeFileBinding(
      postlaunchDependencies.immutableDeploymentManifest,
      "immutable deployment manifest",
    );
    const initialLedgerBinding = normalizeFileBinding(
      postlaunchDependencies.ceremonyLedgerInitial,
      "initial ceremony ledger",
    );
    const transactionPlanBinding = normalizeFileBinding(
      postlaunchDependencies.ceremonyTransactionPlan,
      "ceremony transaction plan",
    );
    stableRead(
      initializationReceiptBinding,
      "ceremony ledger initialization receipt",
      { exactMode: 0o444, minimum: 2 },
    );
    stableRead(
      immutableManifestBinding,
      "immutable deployment manifest",
      { exactMode: 0o444, minimum: 2 },
    );
    stableRead(
      initialLedgerBinding,
      "initial ceremony ledger",
      { exactMode: 0o600, minimum: 2 },
    );
    readStrictCanonicalJson(
      transactionPlanBinding,
      "ceremony transaction plan",
    );
    const signingExchangeDirectory = exactCanonicalPath(
      parsed.signingExchangeDirectory,
      "Stage-B signing exchange directory",
    );
    if (signingExchangeDirectory === state.recoveryDirectory
      || signingExchangeDirectory.startsWith(`${state.recoveryDirectory}${path.sep}`)) {
      fail("Stage-B signing exchange must be a new separate private directory");
    }
    if (pinnedSigningHandle === null) {
      if (fs.existsSync(signingExchangeDirectory)) {
        fail("Stage-B signing exchange must be a new separate private directory");
      }
    } else {
      assertPinnedPhalaPrivateDirectoryPathIdentity(pinnedSigningHandle);
      if (pinnedSigningHandle.path !== signingExchangeDirectory
        || listPhalaPinnedPrivateEntries(pinnedSigningHandle).length !== 0) {
        fail("resident Stage-B signing exchange must be the exact retained empty pinned authority");
      }
      signingHandle = pinnedSigningHandle;
    }
    // L was persisted by the dedicated checkpoint call before the manifest
    // could exist. Resume consumes that exact object; it never remints or
    // reloads L after accepting postlaunch authority.
    const evidenceCheckpoint = state.evidenceCheckpoint;
    const launchCompletion = state.launchCompletionCheckpoint;
    assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt(launchCompletion);

    // L and its private historical transcript are durable before the first
    // final-authority read. A first launch therefore never needs a reviewed
    // artifact containing CVM identities that did not exist before commit.
    const reviewedSet = readReviewedFinalAuthoritySet(
      postlaunchDependencies.reviewedFinalAuthorityFiles,
      postlaunchDependencies.deferredAuthorityReview,
      state,
    );
    const reviewedDependencies = readReviewedFinalAuthorityRuntimeDependencies(
      reviewedSet.projection,
    );
    const deploymentIntent = reviewedDependencies.deployment_intent;
    const stageAReviewerAuthority = normalizeStageAPinnedReviewerAuthority({
      reviewerGenesis: state.reviewerGenesis,
      reviewerGenesisAcceptance: state.reviewerGenesisAcceptance,
      reviewerStatusHistory: [],
      deploymentIntent,
      checkedAtMs: Date.now(),
      enforceFreshness: false,
    });
    if (stageAReviewerAuthority.genesisSha256 !== state.reviewerGenesisSha256
      || stageAReviewerAuthority.acceptanceSha256
        !== state.reviewerGenesisAcceptanceSha256
      || canonicalText(stageAReviewerAuthority.genesis)
        !== canonicalText(state.reviewerGenesis)
      || canonicalText(stageAReviewerAuthority.acceptance)
        !== canonicalText(state.reviewerGenesisAcceptance)) {
      fail("reviewed deployment intent does not reproduce the retained epoch-one Stage-A authority");
    }
    const reviewerStage = normalizeStageBSuccessorReviewerAuthority({
      reviewerGenesis: state.reviewerGenesis,
      reviewerGenesisAcceptance: state.reviewerGenesisAcceptance,
      reviewerStatusHistory: stageBReviewerStatusHistory,
      deploymentIntent,
      checkedAtMs: Date.now(),
      enforceFreshness: true,
    });

    const deferredAuthority =
      await projectPhalaDeferredPublicEnvironmentAuthority({
        releaseAuthority: state.releaseVerificationAuthority,
        verifiedEvidenceSet: evidenceSet,
        launchCompletionReceipt: launchCompletion,
        reviewedFinalAuthorityRuntimeProjection: reviewedSet.projection,
        reviewedUnresolvedValuesByDomain:
          reviewedSet.deferredReview.reviewed_unresolved_values_by_domain,
        reviewedAt: reviewedSet.deferredReview.reviewed_at,
        validUntil: reviewedSet.deferredReview.valid_until,
      });
    const plan = await createPhalaPostMeasurementActivationPlan({
      releaseAuthority: state.releaseVerificationAuthority,
      verifiedEvidenceSet: evidenceSet,
      launchCompletionReceipt: launchCompletion,
      bootstrapPublicEnvironmentAuthority:
        state.dependencies.bootstrap_public_environment_authority,
      postcommitProvisioningAuthority:
        state.dependencies.postcommit_provisioning_environment_authority,
      deferredPublicEnvironmentAuthority: deferredAuthority,
    });
    assertFreshBrandedPhalaPostMeasurementActivationPlan(plan);
    const runtimeAuthority = createPreCeremonyRuntimeAuthority({
      postMeasurementActivationPlan: plan,
    });
    assertFreshBrandedPreCeremonyRuntimeAuthority(runtimeAuthority);

    const stageB = stageBBodyAndPayload({
      state,
      reviewedSet,
      deploymentIntent,
      reviewerStage,
      runtimeAuthority,
      evidenceSet,
      initializationReceiptBinding,
      immutableManifestBinding,
      initialLedgerBinding,
      transactionPlanBinding,
    });

    if (signingHandle === undefined) {
      signingHandle = pinPhalaPrivateDirectory(signingExchangeDirectory);
    } else {
      assertPinnedPhalaPrivateDirectoryPathIdentity(signingHandle);
      if (listPhalaPinnedPrivateEntries(signingHandle).length !== 0) {
        fail("resident Stage-B signing exchange changed before code-owned publication");
      }
    }
    const runtimeSha256 = preCeremonyRuntimeAuthoritySha256(runtimeAuthority);
    const prefix = `stage-b-${state.launch.release_sha}-${runtimeSha256.slice(7, 31)}`;
    const unsignedBodyBasename = `${prefix}.unsigned-body.json`;
    const signingPayloadBasename = `${prefix}.signing-payload.json`;
    const signedBBasename = `${prefix}.signed.json`;
    const bodyBytes = Buffer.from(canonicalText(stageB.body), "utf8");
    const payloadBytes = Buffer.from(canonicalText(stageB.payload), "utf8");
    const unsignedBodyIdentity = createExclusivePhalaPinnedPrivateFile(
      signingHandle,
      unsignedBodyBasename,
      bodyBytes,
      { mode: 0o600, maximum: MAX_SIGNING_FILE_BYTES },
    );
    const signingPayloadIdentity = createExclusivePhalaPinnedPrivateFile(
      signingHandle,
      signingPayloadBasename,
      payloadBytes,
      { mode: 0o600, maximum: MAX_SIGNING_FILE_BYTES },
    );
    const publicSigningSession = deepFreeze({
      schema: PHALA_PRODUCTION_ACTIVATION_SIGNING_SESSION_SCHEMA,
      status: PHALA_PRODUCTION_ACTIVATION_SIGNING_SESSION_STATUS,
      truth_status: PHALA_PRODUCTION_ACTIVATION_COORDINATOR_TRUTH,
      release_sha: state.launch.release_sha,
      batch_id: state.launch.batch_id,
      release_verification_authority_sha256:
        phalaSevenCvmReleaseVerificationAuthoritySha256(
          state.releaseVerificationAuthority,
        ),
      seven_cvm_verified_evidence_set_sha256:
        phalaSevenCvmVerifiedEvidenceSetSha256(evidenceSet),
      seven_cvm_launch_completion_receipt_sha256:
        phalaSevenCvmLaunchCompletionReceiptSha256(launchCompletion),
      reviewed_final_authority_runtime_projection_sha256:
        reviewedFinalAuthorityRuntimeProjectionSha256(reviewedSet.projection),
      deferred_public_environment_authority_sha256:
        deferredPublicEnvironmentAuthorityDigest(deferredAuthority),
      post_measurement_activation_plan_sha256:
        phalaPostMeasurementActivationPlanSha256(plan),
      pre_ceremony_runtime_authority_sha256: runtimeSha256,
      signing_payload_sha256:
        releaseAuthorityReviewSigningPayloadSha256(stageB.payload),
      signing_message: releaseAuthorityReviewSigningMessage(stageB.payload),
      stage_b_reviewer_status_history_raw_file_sha256:
        stageBReviewerStatusHistoryBinding.sha256,
      stage_b_review_reviewer_authority_current_status_epoch:
        reviewerStage.currentStatus.epoch,
      stage_b_review_reviewer_authority_current_status_sha256:
        reviewerStage.currentStatusSha256,
      signing_exchange_directory_identity_anchor_sha256:
        phalaPinnedPrivateDirectoryIdentityAnchorSha256(signingHandle),
      unsigned_body_file:
        publicFileIdentity(unsignedBodyIdentity, unsignedBodyBasename),
      signing_payload_file:
        publicFileIdentity(signingPayloadIdentity, signingPayloadBasename),
      signed_b_output: Object.freeze({
        basename: signedBBasename,
        mode: "0600",
        canonical_json_required: true,
      }),
      next_required_input:
        "canonical_signed_b_at_the_code_owned_pinned_exchange_basename",
      automatic_retry_authorized: false,
      activation_mutation_authorized: false,
      live_traffic_authorized: false,
    });
    const signingState = {
      ...state,
      consumed: false,
      publicDigest: sessionDigest(SIGNING_SESSION_DOMAIN, publicSigningSession),
      signingHandle,
      signingExchangeDirectory,
      unsignedBodyIdentity,
      signingPayloadIdentity,
      unsignedBodyBasename,
      signingPayloadBasename,
      signedBBasename,
      bodyBytes,
      payloadBytes,
      evidenceSet: evidenceCheckpoint.evidenceSet,
      qvlIdentityEvidence: evidenceCheckpoint.qvlIdentityEvidence,
      workloadVerdictEvidence: evidenceCheckpoint.workloadVerdictEvidence,
      launchCompletion,
      reviewedFinalAuthorityProjection: reviewedSet.projection,
      deferredAuthority,
      plan,
      runtimeAuthority,
      stageB,
      stageBReviewerStatusHistory,
      stageBReviewerStatusHistoryBinding,
      bootstrapPhaseInput,
      finalPhaseInput,
      ceremonyAuthorizationDependencies: Object.freeze({
        deploymentIntent: stageB.deploymentIntent,
        freshContractDeploymentReceipt:
          state.freshContractDeploymentReceipt,
        reviewerGenesis: stageB.reviewerStage.genesis,
        reviewerGenesisAcceptance: stageB.reviewerStage.acceptance,
        stageBReviewerStatusHistory,
      }),
    };
    SIGNING_SESSIONS.set(publicSigningSession, signingState);
    signingHandle = null;
    state.recoveryHandle = null;
    EVIDENCE_SESSIONS.delete(publicEvidenceSession);
    return publicSigningSession;
  } catch (error) {
    try {
      disposePhalaProductionPostlaunchActivationCapability(
        parsed.postlaunchActivationCapability,
      );
      if (signingHandle) closePhalaPinnedPrivateDirectory(signingHandle);
    } finally {
      // A capability claim is one-shot. Any failure before the signing-session
      // handoff irreversibly disposes this evidence session; completed-L crash
      // recovery uses the separately reviewed continuation protocol.
      EVIDENCE_SESSIONS.delete(publicEvidenceSession);
      closeEvidenceState(state);
    }
    throw error;
  }
}

export function assertPhalaProductionActivationSigningSession(value) {
  const state = value && SIGNING_SESSIONS.get(value);
  if (!state || state.consumed
    || value.schema !== PHALA_PRODUCTION_ACTIVATION_SIGNING_SESSION_SCHEMA
    || value.status !== PHALA_PRODUCTION_ACTIVATION_SIGNING_SESSION_STATUS
    || value.truth_status !== PHALA_PRODUCTION_ACTIVATION_COORDINATOR_TRUTH
    || sessionDigest(SIGNING_SESSION_DOMAIN, value) !== state.publicDigest
    || value.activation_mutation_authorized !== false
    || value.live_traffic_authorized !== false) {
    fail("an exact live same-process Stage-B signing session is required");
  }
  assertPinnedPhalaPrivateDirectoryPathIdentity(state.signingHandle);
  assertPinnedPhalaPrivateDirectoryPathIdentity(state.recoveryHandle);
  assertFreshBrandedPhalaPostMeasurementActivationPlan(state.plan);
  assertFreshBrandedPreCeremonyRuntimeAuthority(state.runtimeAuthority);
  assertReviewedFinalAuthorityRuntimeProjection(
    state.reviewedFinalAuthorityProjection,
  );
  const body = readPhalaPinnedPrivateFile(
    state.signingHandle,
    state.unsignedBodyBasename,
    {
      mode: 0o600,
      maximum: MAX_SIGNING_FILE_BYTES,
      minimum: 2,
      expectedIdentity: state.unsignedBodyIdentity,
    },
  );
  const payload = readPhalaPinnedPrivateFile(
    state.signingHandle,
    state.signingPayloadBasename,
    {
      mode: 0o600,
      maximum: MAX_SIGNING_FILE_BYTES,
      minimum: 2,
      expectedIdentity: state.signingPayloadIdentity,
    },
  );
  if (!body.equals(state.bodyBytes) || !payload.equals(state.payloadBytes)) {
    fail("pinned Stage-B unsigned body or signing payload changed");
  }
  return value;
}

export function phalaProductionActivationSigningExchangePaths(value) {
  const session = assertPhalaProductionActivationSigningSession(value);
  const state = SIGNING_SESSIONS.get(session);
  return Object.freeze({
    unsignedBodyPath: phalaPinnedPrivatePathForDisplay(
      state.signingHandle,
      state.unsignedBodyBasename,
    ),
    signingPayloadPath: phalaPinnedPrivatePathForDisplay(
      state.signingHandle,
      state.signingPayloadBasename,
    ),
    signedBOutputPath: phalaPinnedPrivatePathForDisplay(
      state.signingHandle,
      state.signedBBasename,
    ),
  });
}

function parsePinnedCanonicalSignedB(state) {
  const bytes = readPhalaPinnedPrivateFile(
    state.signingHandle,
    state.signedBBasename,
    {
      mode: 0o600,
      maximum: MAX_SIGNING_FILE_BYTES,
      minimum: 2,
      allowMissing: false,
    },
  );
  let text;
  let parsed;
  try {
    text = UTF8.decode(bytes);
    parsed = JSON.parse(text);
  } catch {
    fail("pinned signed-B output is not bounded UTF-8 JSON");
  }
  const {
    stageBReviewerStatusHistory,
    ...baseCeremonyAuthorizationDependencies
  } = state.ceremonyAuthorizationDependencies;
  const options = {
    ...baseCeremonyAuthorizationDependencies,
    reviewerStatusHistory: stageBReviewerStatusHistory,
    preCeremonyRuntimeAuthority: state.runtimeAuthority,
    checkedAtMs: Date.now(),
  };
  const signedB = assertFreshProductionCeremonyAuthorizationCore(
    parsed,
    options,
  );
  const canonicalSignedB = canonicalCeremonyAuthorizationCoreArtifactText(
    signedB,
    options,
  );
  if (text !== canonicalSignedB) {
    fail("pinned signed-B output bytes are not the exact canonical artifact");
  }
  const normalizedUnsignedBody = { ...signedB };
  delete normalizedUnsignedBody.review;
  const recomputedPayload =
    ceremonyAuthorizationReviewSigningPayloadForProduction(
      normalizedUnsignedBody,
      state.stageB.reviewMetadata,
      { preCeremonyRuntimeAuthority: state.runtimeAuthority },
    );
  if (canonicalText(recomputedPayload) !== canonicalText(state.stageB.payload)
    || signedB.review.signing_payload_sha256
      !== releaseAuthorityReviewSigningPayloadSha256(state.stageB.payload)) {
    fail("pinned signed B does not contain the exact coordinator-issued body and signing payload");
  }
  return Object.freeze({
    signedB,
    signedBSha256: ceremonyAuthorizationCoreSha256(signedB, options),
    bytes,
  });
}

/**
 * Read the code-owned signed-B output basename from the still-open 0700
 * exchange, validate the exact canonical body/signatures against R, and enter
 * the mutation runtime. The signing session is consumed before any mutation so
 * an ambiguous failure can never be retried automatically.
 */
export async function beginPhalaProductionActivationFromSignedB(input = {}) {
  const parsed = exactOwnRecord(
    input,
    ["session"],
    "production activation signed-B resume input",
  );
  const publicSigningSession = assertPhalaProductionActivationSigningSession(
    parsed.session,
  );
  const state = SIGNING_SESSIONS.get(publicSigningSession);
  let signed;
  try {
    stableRead(
      state.bootstrapPhaseInput,
      "main-runtime bootstrap phase secret input",
      { exactMode: 0o600, maximum: MAX_SECRET_FILE_BYTES, minimum: 2 },
    );
    stableRead(
      state.finalPhaseInput,
      "main-runtime final phase secret input",
      { exactMode: 0o600, maximum: MAX_SECRET_FILE_BYTES, minimum: 2 },
    );
    signed = parsePinnedCanonicalSignedB(state);
  } catch (error) {
    // No mutation was attempted and no one-shot runtime proof was consumed.
    // Keep the exact branded signing session live so an absent or malformed
    // signer output can be corrected inside the same pinned exchange.
    throw error;
  }
  state.consumed = true;
  try {
    const targetEvidence = state.dependencies.production_target_authority_evidence;
    const activationSession =
      await beginProductionPhalaPostMeasurementActivation({
        plan: state.plan,
        preCeremonyRuntimeAuthority: state.runtimeAuthority,
        ceremonyAuthorization: signed.signedB,
        ceremonyAuthorizationDependencies:
          state.ceremonyAuthorizationDependencies,
        reviewedFinalAuthorityRuntimeProjection:
          state.reviewedFinalAuthorityProjection,
        launchRuntimeResult: state.launch,
        targetAuthority: targetEvidence.productionTargetAuthority,
        compatibilityReceipt: targetEvidence.compatibilityReceipt,
        sdkWireTransformStagingReceipt:
          targetEvidence.sdkWireTransformStagingReceipt,
        bootstrapPhaseInput: state.bootstrapPhaseInput,
        finalPhaseInput: state.finalPhaseInput,
        recoveryDirectory: state.recoveryDirectory,
      });
    const publicRuntimeSession = deepFreeze({
      schema: PHALA_PRODUCTION_ACTIVATION_RUNTIME_SESSION_SCHEMA,
      status: PHALA_PRODUCTION_ACTIVATION_RUNTIME_SESSION_STATUS,
      truth_status: PHALA_PRODUCTION_ACTIVATION_COORDINATOR_TRUTH,
      release_sha: state.launch.release_sha,
      batch_id: state.launch.batch_id,
      release_verification_authority_sha256:
        publicSigningSession.release_verification_authority_sha256,
      seven_cvm_verified_evidence_set_sha256:
        publicSigningSession.seven_cvm_verified_evidence_set_sha256,
      seven_cvm_launch_completion_receipt_sha256:
        publicSigningSession.seven_cvm_launch_completion_receipt_sha256,
      post_measurement_activation_plan_sha256:
        publicSigningSession.post_measurement_activation_plan_sha256,
      pre_ceremony_runtime_authority_sha256:
        publicSigningSession.pre_ceremony_runtime_authority_sha256,
      ceremony_authorization_sha256: signed.signedBSha256,
      durable_state_status: activationSession.durable_state_status,
      next_required_proof: activationSession.next_required_proof,
      automatic_retry_authorized: false,
      live_traffic_authorized: false,
    });
    RUNTIME_SESSIONS.set(publicRuntimeSession, {
      consumed: false,
      publicDigest: sessionDigest(RUNTIME_SESSION_DOMAIN, publicRuntimeSession),
      activationSession,
      signedB: signed.signedB,
      signedBSha256: signed.signedBSha256,
      plan: state.plan,
      runtimeAuthority: state.runtimeAuthority,
      ceremonyAuthorizationDependencies:
        state.ceremonyAuthorizationDependencies,
      evidenceSet: state.evidenceSet,
      qvlIdentityEvidence: state.qvlIdentityEvidence,
      workloadVerdictEvidence: state.workloadVerdictEvidence,
    });
    SIGNING_SESSIONS.delete(publicSigningSession);
    closeSigningState(state);
    return publicRuntimeSession;
  } catch (error) {
    SIGNING_SESSIONS.delete(publicSigningSession);
    closeSigningState(state);
    throw error;
  }
}

export function assertPhalaProductionActivationRuntimeSession(value) {
  const state = value && RUNTIME_SESSIONS.get(value);
  if (!state || state.consumed
    || value.schema !== PHALA_PRODUCTION_ACTIVATION_RUNTIME_SESSION_SCHEMA
    || value.status !== PHALA_PRODUCTION_ACTIVATION_RUNTIME_SESSION_STATUS
    || value.truth_status !== PHALA_PRODUCTION_ACTIVATION_COORDINATOR_TRUTH
    || sessionDigest(RUNTIME_SESSION_DOMAIN, value) !== state.publicDigest
    || value.live_traffic_authorized !== false) {
    fail("an exact live same-process activation runtime session is required");
  }
  assertFreshBrandedPhalaPostMeasurementActivationPlan(state.plan);
  assertFreshBrandedPreCeremonyRuntimeAuthority(state.runtimeAuthority);
  return value;
}

export function readPhalaProductionActivationRuntimeDeadlines(value) {
  const publicSession = assertPhalaProductionActivationRuntimeSession(value);
  const state = RUNTIME_SESSIONS.get(publicSession);
  const initialActivationEvidenceLeaseExpiresAt =
    state.plan.activation_evidence_lease_expires_at;
  const signedBReviewExpiresAt = Math.floor(
    Date.parse(state.signedB.review.expires_at) / 1_000,
  );
  const reviewedProjectionExpiresAt = Math.floor(
    Date.parse(state.reviewedFinalAuthorityProjection.review_expires_at)
      / 1_000,
  );
  const deferredAuthorityExpiresAt = Math.floor(
    Date.parse(state.deferredAuthority.valid_until) / 1_000,
  );
  const activationAuthorityExpiresAt = Math.min(
    initialActivationEvidenceLeaseExpiresAt,
    signedBReviewExpiresAt,
    reviewedProjectionExpiresAt,
    deferredAuthorityExpiresAt,
  );
  if (![initialActivationEvidenceLeaseExpiresAt, signedBReviewExpiresAt,
    reviewedProjectionExpiresAt, deferredAuthorityExpiresAt,
    activationAuthorityExpiresAt].every(Number.isSafeInteger)) {
    fail("production activation runtime authority deadlines are invalid");
  }
  return deepFreeze({
    initial_activation_evidence_lease_expires_at:
      initialActivationEvidenceLeaseExpiresAt,
    signed_b_review_expires_at: signedBReviewExpiresAt,
    reviewed_projection_expires_at: reviewedProjectionExpiresAt,
    deferred_authority_expires_at: deferredAuthorityExpiresAt,
    activation_authority_expires_at: activationAuthorityExpiresAt,
  });
}

/**
 * Finish the already-mutated runtime with the fresh recipient capability. The
 * exact compute-QVL and main-runtime verifier proofs are recovered from this
 * coordinator's original evidence session; they are never accepted again as
 * caller-authored or parsed values at the completion boundary.
 */
export async function completePhalaProductionActivation(input = {}) {
  const parsed = exactOwnRecord(
    input,
    ["recipientActivation", "session"],
    "production activation completion input",
  );
  const publicRuntimeSession = assertPhalaProductionActivationRuntimeSession(
    parsed.session,
  );
  const state = RUNTIME_SESSIONS.get(publicRuntimeSession);
  state.consumed = true;
  const qvlIdentityEvidence = state.qvlIdentityEvidence.find(
    (entry) => entry.domain === "compute_workload_qvl_cvm",
  );
  const mainRuntimeEvidence = state.workloadVerdictEvidence.find(
    (entry) => entry.domain === "main_runtime_cvm",
  );
  if (!qvlIdentityEvidence || !mainRuntimeEvidence) {
    RUNTIME_SESSIONS.delete(publicRuntimeSession);
    fail("same-process compute-QVL or main-runtime proof dependency disappeared");
  }
  try {
    const result = await completeProductionPhalaPostMeasurementActivation({
      session: state.activationSession,
      recipientActivation: parsed.recipientActivation,
      qvlIdentityEvidence,
      mainRuntimeEvidence,
    });
    if (result.live_traffic_authorized !== false) {
      fail("activation completion cannot authorize live traffic");
    }
    return result;
  } catch (error) {
    try {
      quarantineProductionPhalaPostMeasurementActivationSession(
        state.activationSession,
      );
    } catch {
      // The underlying runtime consumes its session after any accepted
      // one-shot recipient proof. Its durable journal remains the recovery
      // authority when quarantine can no longer reacquire that live object.
    }
    throw error;
  } finally {
    RUNTIME_SESSIONS.delete(publicRuntimeSession);
  }
}

function exactDisposableState(value, map, schema, domain, label) {
  const state = value && map.get(value);
  if (!state || state.consumed || value.schema !== schema
    || value.truth_status !== PHALA_PRODUCTION_ACTIVATION_COORDINATOR_TRUTH
    || sessionDigest(domain, value) !== state.publicDigest) {
    fail(`an exact unconsumed same-process ${label} session is required`);
  }
  return state;
}

function disposalReceipt(session, state, disposition) {
  return deepFreeze({
    schema: PHALA_PRODUCTION_ACTIVATION_DISPOSAL_RECEIPT_SCHEMA,
    status: "coordinator_session_disposed_fail_closed",
    truth_status:
      "local_session_authority_released_not_activation_completion_or_live_traffic",
    disposed_session_schema: session.schema,
    disposed_session_sha256: state.publicDigest,
    disposition,
    automatic_retry_authorized: false,
    activation_completion_claimed: false,
    live_traffic_authorized: false,
  });
}

function evidenceDisposalDisposition(state) {
  if (state.historicalTranscriptState === "not_attempted") {
    return "evidence_collection_cancelled_before_historical_transcript_persistence";
  }
  if (state.historicalTranscriptState
      === "persistence_attempted_unknown_or_partial") {
    return "evidence_collection_cancelled_after_transcript_persistence_attempt_operator_recovery_may_be_required_no_activation_mutation";
  }
  if (state.historicalTranscriptState
      === "existing_transcript_state_unreconciled_operator_recovery_required") {
    return "evidence_collection_cancelled_existing_transcript_state_unreconciled_operator_recovery_required_no_activation_mutation";
  }
  return "evidence_collection_cancelled_exact_seven_cvm_transcript_retained_no_activation_mutation";
}

/**
 * Explicitly release an abandoned or expired coordinator session. Freshness is
 * intentionally not a prerequisite for cleanup: WeakMap identity and the
 * immutable public-session digest prove which live local capability is being
 * consumed. Runtime disposal additionally records the underlying fail-closed
 * Compute-recipient-unavailable journal transition and releases its lock.
 */
export function disposePhalaProductionActivationSession(input = {}) {
  const parsed = exactOwnRecord(
    input,
    ["session"],
    "production activation session disposal input",
  );
  const session = parsed.session;
  if (EVIDENCE_SESSIONS.has(session)) {
    const state = exactDisposableState(
      session,
      EVIDENCE_SESSIONS,
      PHALA_PRODUCTION_ACTIVATION_EVIDENCE_SESSION_SCHEMA,
      EVIDENCE_SESSION_DOMAIN,
      "evidence",
    );
    state.consumed = true;
    EVIDENCE_SESSIONS.delete(session);
    closeEvidenceState(state);
    return disposalReceipt(
      session,
      state,
      evidenceDisposalDisposition(state),
    );
  }
  if (SIGNING_SESSIONS.has(session)) {
    const state = exactDisposableState(
      session,
      SIGNING_SESSIONS,
      PHALA_PRODUCTION_ACTIVATION_SIGNING_SESSION_SCHEMA,
      SIGNING_SESSION_DOMAIN,
      "Stage-B signing",
    );
    state.consumed = true;
    SIGNING_SESSIONS.delete(session);
    closeSigningState(state);
    return disposalReceipt(
      session,
      state,
      "signing_cancelled_persisted_seven_cvm_transcript_retained_no_activation_mutation",
    );
  }
  if (RUNTIME_SESSIONS.has(session)) {
    const state = exactDisposableState(
      session,
      RUNTIME_SESSIONS,
      PHALA_PRODUCTION_ACTIVATION_RUNTIME_SESSION_SCHEMA,
      RUNTIME_SESSION_DOMAIN,
      "activation runtime",
    );
    state.consumed = true;
    try {
      quarantineProductionPhalaPostMeasurementActivationSession(
        state.activationSession,
      );
    } finally {
      RUNTIME_SESSIONS.delete(session);
    }
    return disposalReceipt(
      session,
      state,
      "mutated_runtime_quarantined_compute_recipient_activation_unavailable",
    );
  }
  fail("an exact unconsumed same-process coordinator session is required for disposal");
}
