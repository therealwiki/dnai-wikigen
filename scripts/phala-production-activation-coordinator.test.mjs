import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import {
  PHALA_PRODUCTION_ACTIVATION_COORDINATOR_TRUTH,
  PHALA_PRODUCTION_ACTIVATION_DEFERRED_REVIEW_SCHEMA,
  PHALA_PRODUCTION_ACTIVATION_DISPOSAL_RECEIPT_SCHEMA,
  PHALA_PRODUCTION_ACTIVATION_EVIDENCE_SESSION_SCHEMA,
  PHALA_PRODUCTION_ACTIVATION_EVIDENCE_SESSION_STATUS,
  PHALA_PRODUCTION_ACTIVATION_RUNTIME_SESSION_SCHEMA,
  PHALA_PRODUCTION_ACTIVATION_RUNTIME_SESSION_STATUS,
  PHALA_PRODUCTION_ACTIVATION_SIGNING_SESSION_SCHEMA,
  PHALA_PRODUCTION_ACTIVATION_SIGNING_SESSION_STATUS,
  assertPhalaProductionActivationEvidenceSession,
  assertPhalaProductionActivationRuntimeSession,
  assertPhalaProductionActivationSigningSession,
  beginPhalaProductionActivationFromSignedB,
  completePhalaProductionActivation,
  disposePhalaProductionActivationSession,
  persistPhalaProductionActivationLaunchCompletion,
  phalaProductionActivationSigningExchangePaths,
  preparePhalaProductionActivationEvidence,
  readPhalaProductionActivationEvidenceDependencies,
  resumePhalaProductionActivationWithEvidence,
  resumePhalaProductionActivationWithPinnedSigningExchange,
} from "./phala-production-activation-coordinator.mjs";

const SOURCE_PATH = fileURLToPath(new URL(
  "./phala-production-activation-coordinator.mjs",
  import.meta.url,
));
const REPOSITORY_ROOT = fileURLToPath(new URL("../", import.meta.url));
const execFileAsync = promisify(execFile);

const RECOVERY_HARNESS_SOURCE = String.raw`
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { mock } from "node:test";
import { pathToFileURL } from "node:url";

const scenario = process.env.COORDINATOR_RECOVERY_SCENARIO;
assert.ok([
  "different-second-retry",
  "partial-lock",
  "wrong-proof-array",
].includes(scenario));
const moduleUrl = (basename) => pathToFileURL(
  path.join(process.cwd(), "scripts", basename),
).href;
const mockWithOriginalExports = async (basename, options) => {
  const target = moduleUrl(basename);
  const original = await import(target);
  return mock.module(target, {
    ...options,
    namedExports: {
      ...original,
      ...options.namedExports,
    },
  });
};
const canonical = (value) => {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonical(value[key])]),
  );
};
const canonicalText = (value) => JSON.stringify(canonical(value), null, 2) + "\n";
const rawSha256 = (bytes) => "sha256:" + createHash("sha256")
  .update(bytes).digest("hex");
const objectSha256 = (value) => rawSha256(Buffer.from(canonicalText(value), "utf8"));
const sha = (byte) => "sha256:" + byte.toString(16).padStart(2, "0").repeat(32);
const releaseSha = "ab".repeat(20);
const batchId = "coordinator-recovery-batch";
const deploymentIntentSha256 = sha(1);
const cvmLaunchIntentSha256 = sha(2);
const finalAuthoritySha256 = sha(3);
const measurementPolicySetSha256 = sha(4);
const freshReceiptBare = "05".repeat(32);
const freshReceiptSha256 = "sha256:" + freshReceiptBare;
const sigstoreReceiptSha256 = sha(6);
const imageManifestSha256 = sha(7);
const reviewerGenesisSha256 = sha(8);
const reviewerAcceptanceSha256 = sha(9);
const recoveryAnchorSha256 = sha(10);
const evidenceFileSetSha256 = sha(11);
const releaseAuthoritySha256 = sha(12);
const descriptorSha256ByDomain = Object.freeze({ main_runtime_cvm: sha(13) });
const startMs = Math.floor(Date.now() / 1_000) * 1_000;
const isoSecond = (milliseconds) => new Date(milliseconds)
  .toISOString().replace(".000Z", "Z");
const fileDigest = (filePath) => rawSha256(fs.readFileSync(filePath));

const launch = Object.freeze({
  release_sha: releaseSha,
  batch_id: batchId,
  phala_recovery_directory_identity_anchor_sha256: recoveryAnchorSha256,
});
const launchBrands = new WeakSet([launch]);
const signedA = Object.freeze({
  deployment_intent_sha256: deploymentIntentSha256,
  cvm_launch_intent_sha256: cvmLaunchIntentSha256,
  qvl_measurement_policy_set_sha256: measurementPolicySetSha256,
  fresh_contract_deployment_receipt_sha256: freshReceiptSha256,
  image_release_sigstore_verification_receipt_sha256: sigstoreReceiptSha256,
  descriptor_sha256_by_domain: descriptorSha256ByDomain,
});
const dependencies = Object.freeze({
  signed_a_receipt: signedA,
  bootstrap_public_environment_authority: Object.freeze({ kind: "bootstrap" }),
  cvm_descriptor_runtime_authority: Object.freeze({ kind: "descriptors" }),
  production_posture_receipts: Object.freeze([]),
  executor_final_state: Object.freeze({
    phala_recovery_directory_identity_anchor_sha256: recoveryAnchorSha256,
  }),
  postcommit_provisioning_environment_authority:
    Object.freeze({ kind: "postcommit" }),
  production_target_authority_evidence: Object.freeze({
    productionTargetAuthority: Object.freeze({}),
    compatibilityReceipt: Object.freeze({}),
    sdkWireTransformStagingReceipt: Object.freeze({}),
  }),
});
await mockWithOriginalExports("phala-production-executor-runtime.mjs", {
  namedExports: {
    assertCompletedPhalaProductionExecutorRuntimeResult(value) {
      if (!launchBrands.has(value)) throw new Error("missing launch brand");
      return value;
    },
    readPhalaProductionExecutorRuntimeDependencies(value) {
      if (!launchBrands.has(value)) throw new Error("missing launch dependency brand");
      return dependencies;
    },
  },
});

await mockWithOriginalExports("cvm-launch-intent-core.mjs", {
  namedExports: {
    normalizeFreshContractDeploymentReceipt(value) { return value; },
    canonicalFreshContractDeploymentReceiptText(value) {
      return canonicalText(value);
    },
    freshContractDeploymentReceiptDigest() { return freshReceiptBare; },
  },
});
await mockWithOriginalExports("cvm-release-descriptor-set.mjs", {
  namedExports: {
    normalizeCvmReleaseDescriptorSetReceipt(value) { return value; },
    canonicalCvmReleaseDescriptorSetReceiptText(value) {
      return canonicalText(value);
    },
  },
});
await mockWithOriginalExports("phala-seven-cvm-measurement-policy.mjs", {
  namedExports: {
    normalizePhalaQvlMeasurementPolicySet(value) { return value; },
    canonicalPhalaQvlMeasurementPolicySetText(value) {
      return canonicalText(value);
    },
    phalaQvlMeasurementPolicySetSha256() { return measurementPolicySetSha256; },
  },
});
await mockWithOriginalExports("release-manifest-sigstore-verifier.mjs", {
  namedExports: {
    assertProductionReleaseManifestSigstoreVerificationReceipt(value) {
      return value;
    },
    canonicalReleaseManifestSigstoreVerificationReceiptText(value) {
      return canonicalText(value);
    },
    releaseManifestSigstoreVerificationReceiptSha256() {
      return sigstoreReceiptSha256;
    },
  },
});
await mockWithOriginalExports("release-reviewer-authority-genesis.mjs", {
  namedExports: {
    normalizeReleaseReviewerAuthorityGenesis(value) { return value; },
    canonicalReleaseReviewerAuthorityGenesisArtifactText(value) {
      return canonicalText(value);
    },
    releaseReviewerAuthorityGenesisSha256() { return reviewerGenesisSha256; },
  },
});
await mockWithOriginalExports("release-reviewer-authority-genesis-acceptance.mjs", {
  namedExports: {
    normalizeReleaseReviewerAuthorityGenesisAcceptance(value) { return value; },
    canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(value) {
      return canonicalText(value);
    },
    releaseReviewerAuthorityGenesisAcceptanceSha256() {
      return reviewerAcceptanceSha256;
    },
  },
});
const reviewedDeploymentIntent = Object.freeze({
  release: Object.freeze({
    toolchain: Object.freeze({ forge: "mock-forge" }),
  }),
});
const lateBoundReviewerStatusHistory = Object.freeze([
  Object.freeze({ epoch: 1, marker: "deployment-root" }),
  Object.freeze({ epoch: 2, marker: "postlaunch-successor" }),
]);
const reviewerCurrentStatusSha256 = sha(14);
const authorityEvents = [];
let stageAFacadeCalls = 0;
let stageBFacadeCalls = 0;
await mockWithOriginalExports("release-authority-current-reviewer-facade.mjs", {
  namedExports: {
    normalizeStageAPinnedReviewerAuthority(options) {
      assert.equal(options.deploymentIntent, reviewedDeploymentIntent);
      assert.equal(
        options.reviewerGenesisAcceptance
          .reviewer_authority_current_status.epoch,
        1,
      );
      assert.deepEqual(options.reviewerStatusHistory, []);
      assert.equal(options.enforceFreshness, false);
      assert.ok(authorityEvents.includes("reviewed-deployment-intent"));
      assert.equal(downstreamProjectionCalls, 0);
      authorityEvents.push("stage-a");
      stageAFacadeCalls += 1;
      return Object.freeze({
        genesis: options.reviewerGenesis,
        genesisSha256: reviewerGenesisSha256,
        acceptance: options.reviewerGenesisAcceptance,
        acceptanceSha256: reviewerAcceptanceSha256,
      });
    },
    normalizeStageBSuccessorReviewerAuthority(options) {
      assert.equal(options.deploymentIntent, reviewedDeploymentIntent);
      assert.equal(
        options.reviewerGenesisAcceptance
          .reviewer_authority_current_status.epoch,
        1,
      );
      assert.deepEqual(
        options.reviewerStatusHistory,
        lateBoundReviewerStatusHistory,
      );
      assert.equal(options.enforceFreshness, true);
      assert.ok(authorityEvents.includes("reviewed-deployment-intent"));
      assert.equal(downstreamProjectionCalls, 0);
      authorityEvents.push("stage-b");
      stageBFacadeCalls += 1;
      return Object.freeze({
        genesis: options.reviewerGenesis,
        acceptance: options.reviewerGenesisAcceptance,
        currentStatus: Object.freeze({ epoch: 2 }),
        currentStatusExpiresAt: new Date(startMs + 3_000_000).toISOString(),
        currentStatusSha256: reviewerCurrentStatusSha256,
        authority: Object.freeze({
          approved_reviewer_hashes: Object.freeze([sha(15)]),
          reviewer_root_hash: sha(16),
          reviewer_set_sha256: sha(17),
        }),
      });
    },
  },
});

const releaseAuthority = Object.freeze({ kind: "release-authority" });
const releaseAuthorityBrands = new WeakSet([releaseAuthority]);
const evidenceBrands = new WeakSet();
let evidenceFactoryCalls = 0;
let evidenceFreshnessAssertions = 0;
let lastEvidenceIssuedAt = null;
const evidenceDigest = (value) => objectSha256({
  marker: value.marker,
  issued_at: value.issued_at,
});
const qvlIdentityEvidence = Object.freeze([
  Object.freeze({ domain: "diligence_qvl_cvm" }),
  Object.freeze({ domain: "arena_qvl_cvm" }),
  Object.freeze({ domain: "anchor_writer_qvl_cvm" }),
  Object.freeze({ domain: "compute_workload_qvl_cvm" }),
  Object.freeze({ domain: "compute_metering_qvl_cvm" }),
]);
const workloadVerdictEvidence = Object.freeze([
  Object.freeze({ domain: "main_runtime_cvm" }),
  Object.freeze({ domain: "independent_metering_cvm" }),
]);
await mockWithOriginalExports("phala-seven-cvm-verifier-evidence.mjs", {
  namedExports: {
    createPhalaSevenCvmReleaseVerificationAuthority() {
      return releaseAuthority;
    },
      assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority(value) {
        if (!releaseAuthorityBrands.has(value)) throw new Error("missing release brand");
        return value;
      },
      assertBrandedPhalaSevenCvmReleaseVerificationAuthority(value) {
        if (!releaseAuthorityBrands.has(value)) throw new Error("missing release brand");
        return value;
      },
    phalaSevenCvmReleaseVerificationAuthoritySha256() {
      return releaseAuthoritySha256;
    },
    createPhalaSevenCvmVerifiedEvidenceSet(options) {
      assert.equal(options.releaseAuthority, releaseAuthority);
      assert.deepEqual(options.qvlIdentityEvidence, qvlIdentityEvidence);
      assert.deepEqual(options.workloadVerdictEvidence, workloadVerdictEvidence);
      evidenceFactoryCalls += 1;
      const candidate = Object.freeze({
        marker: "evidence-set",
        issued_at: Math.floor(Date.now() / 1_000),
        minimum_activation_evidence_lease_expires_at:
          Math.floor(Date.now() / 1_000) + 3_600,
        historical_transcript_file_set_sha256: evidenceFileSetSha256,
      });
      lastEvidenceIssuedAt = candidate.issued_at;
      evidenceBrands.add(candidate);
      return candidate;
    },
    assertProductionPhalaSevenCvmEvidenceSet(value) {
      if (!evidenceBrands.has(value)) throw new Error("missing evidence brand");
      if (Math.floor(Date.now() / 1_000)
          >= value.minimum_activation_evidence_lease_expires_at) {
        throw new Error("evidence expired");
      }
      evidenceFreshnessAssertions += 1;
      return value;
    },
    phalaSevenCvmVerifiedEvidenceSetSha256(value) {
      if (!evidenceBrands.has(value)) throw new Error("missing evidence digest brand");
      return evidenceDigest(value);
    },
  },
});

let persistedTranscript = null;
let persistCalls = 0;
let loadCalls = 0;
let reconstructedCompletionCalls = 0;
const completionBrands = new WeakSet();
const completionFor = (digest) => {
  const completion = Object.freeze({ evidence_digest: digest });
  completionBrands.add(completion);
  return completion;
};
await mockWithOriginalExports("phala-seven-cvm-historical-transcript-persistence.mjs", {
  namedExports: {
    loadPhalaSevenCvmHistoricalTranscriptPersistenceReceipt(options) {
      loadCalls += 1;
      if (scenario === "partial-lock") {
        throw new Error("historical transcript persistence lock requires explicit recovery");
      }
      if (persistedTranscript === null) return null;
      assert.equal(
        options.expectedSevenCvmVerifiedEvidenceSetSha256,
        persistedTranscript.evidence_digest,
      );
      assert.equal(
        options.expectedHistoricalTranscriptFileSetSha256,
        evidenceFileSetSha256,
      );
      return persistedTranscript;
    },
  },
});
await mockWithOriginalExports("phala-seven-cvm-launch-completion.mjs", {
  namedExports: {
    async createPersistedPhalaSevenCvmLaunchCompletionReceipt(options) {
      persistCalls += 1;
      const digest = evidenceDigest(options.verifiedEvidenceSet);
      persistedTranscript = Object.freeze({ evidence_digest: digest });
      return completionFor(digest);
    },
    createPhalaSevenCvmLaunchCompletionReceipt(options) {
      reconstructedCompletionCalls += 1;
      const digest = evidenceDigest(options.verifiedEvidenceSet);
      assert.equal(
        options.historicalTranscriptPersistenceReceipt.evidence_digest,
        digest,
      );
      return completionFor(digest);
    },
    assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt(value) {
      if (!completionBrands.has(value)) throw new Error("missing L brand");
      return value;
    },
    phalaSevenCvmLaunchCompletionReceiptSha256(value) {
      if (!completionBrands.has(value)) throw new Error("missing L digest brand");
      return objectSha256(value);
    },
  },
});

await mockWithOriginalExports("reviewed-final-authority-runtime.mjs", {
  namedExports: {
    readReviewedFinalAuthorityRuntimeProjection(options) {
      return Object.freeze({
        artifact_file_sha256: Object.freeze({
          deployment_intent: fileDigest(options.deploymentIntentPath),
          cvm_launch_intent: fileDigest(options.cvmLaunchIntentPath),
          final_authority: fileDigest(options.finalAuthorityPath),
          review_envelope: fileDigest(options.reviewEnvelopePath),
          review_evidence: fileDigest(options.reviewEvidencePath),
        }),
        deployment_intent_sha256: deploymentIntentSha256,
        cvm_launch_intent_sha256: cvmLaunchIntentSha256,
        final_authority_sha256: finalAuthoritySha256,
        review_approved_at: new Date(startMs - 120_000).toISOString(),
        review_expires_at: new Date(startMs + 7_200_000).toISOString(),
      });
    },
    assertReviewedFinalAuthorityRuntimeProjection(value) { return value; },
    readReviewedFinalAuthorityRuntimeDependencies() {
      authorityEvents.push("reviewed-deployment-intent");
      return Object.freeze({ deployment_intent: reviewedDeploymentIntent });
    },
  },
});
let downstreamProjectionCalls = 0;
await mockWithOriginalExports("phala-production-environment-authority.mjs", {
  namedExports: {
    async projectPhalaDeferredPublicEnvironmentAuthority() {
      assert.deepEqual(authorityEvents, [
        "reviewed-deployment-intent",
        "stage-a",
        "stage-b",
      ]);
      authorityEvents.push("deferred-projection");
      downstreamProjectionCalls += 1;
      throw new Error("forced downstream Stage-B preparation failure");
    },
  },
});
mock.module(moduleUrl("phala-post-measurement-activation-runtime.mjs"), {
  namedExports: {
    async beginProductionPhalaPostMeasurementActivation() {
      throw new Error("runtime mutation must remain unreachable in recovery harness");
    },
    async completeProductionPhalaPostMeasurementActivation() {
      throw new Error("runtime completion must remain unreachable in recovery harness");
    },
    quarantineProductionPhalaPostMeasurementActivationSession() {
      throw new Error("runtime quarantine must remain unreachable in recovery harness");
    },
  },
});

let closedPinnedHandles = 0;
await mockWithOriginalExports("phala-pinned-private-directory.mjs", {
  namedExports: {
    pinPhalaPrivateDirectory(directory) {
      return { directory, open: true, anchor: recoveryAnchorSha256 };
    },
    assertPinnedPhalaPrivateDirectoryPathIdentity(handle) {
      if (!handle || handle.open !== true) throw new Error("closed pinned handle");
      return handle;
    },
    phalaPinnedPrivateDirectoryIdentityAnchorSha256(handle) {
      return handle.anchor;
    },
    closePhalaPinnedPrivateDirectory(handle) {
      if (!handle || handle.open !== true) throw new Error("double close");
      handle.open = false;
      closedPinnedHandles += 1;
    },
  },
});

const postlaunchCapability = Object.freeze({ kind: "postlaunch-capability" });
let postlaunchDependencies;
let stageBReviewerStatusHistoryBinding;
let capabilityConsumeCalls = 0;
let capabilityDisposeCalls = 0;
let capabilityLive = true;
await mockWithOriginalExports(
  "phala-production-postlaunch-activation-capability.mjs",
  {
    namedExports: {
      consumePhalaProductionPostlaunchActivationCapability(
        value,
        expected,
      ) {
        capabilityConsumeCalls += 1;
        assert.equal(value, postlaunchCapability);
        if (!capabilityLive) throw new Error("mock postlaunch capability is not live");
        capabilityLive = false;
        assert.equal(expected.releaseVerificationAuthority, releaseAuthority);
        assert.ok(evidenceBrands.has(expected.verifiedEvidenceSet));
        return Object.freeze({
          dependencies: postlaunchDependencies,
          stageBReviewerStatusHistory: lateBoundReviewerStatusHistory,
          stageBReviewerStatusHistoryBinding,
        });
      },
      disposePhalaProductionPostlaunchActivationCapability(value) {
        if (value !== postlaunchCapability || !capabilityLive) return false;
        capabilityLive = false;
        capabilityDisposeCalls += 1;
        return true;
      },
    },
  },
);

const coordinator = await import(
  moduleUrl("phala-production-activation-coordinator.mjs")
    + "?recovery-behavior=" + scenario,
);
const root = fs.realpathSync.native(
  fs.mkdtempSync(path.join(os.tmpdir(), "dnai-coordinator-recovery-")),
);
fs.chmodSync(root, 0o700);
const recoveryDirectory = path.join(root, "recovery");
fs.mkdirSync(recoveryDirectory, { mode: 0o700 });
const writeArtifact = (basename, value, mode = 0o600) => {
  const filePath = path.join(root, basename);
  const bytes = Buffer.from(canonicalText(value), "utf8");
  fs.writeFileSync(filePath, bytes, { mode });
  fs.chmodSync(filePath, mode);
  return Object.freeze({ path: filePath, sha256: rawSha256(bytes) });
};

try {
  const measurementPolicySet = writeArtifact("measurement-policy.json", {});
  const freshContractDeploymentReceipt = writeArtifact("fresh-receipt.json", {});
  const reviewerGenesis = writeArtifact("reviewer-genesis.json", {});
  const reviewerGenesisAcceptance = writeArtifact("reviewer-acceptance.json", {
    reviewer_authority_current_status: { epoch: 1 },
  });
  stageBReviewerStatusHistoryBinding = writeArtifact(
    "stage-b-reviewer-history.json",
    lateBoundReviewerStatusHistory,
    0o600,
  );
  const releaseManifestSigstoreVerificationReceipt = writeArtifact(
    "sigstore.json",
    { release_manifest_sha256: imageManifestSha256 },
  );
  const descriptorSetReceipt = writeArtifact("descriptors.json", {
    release_sha: releaseSha,
    image_manifest_sha256: imageManifestSha256,
    descriptor_sha256_by_domain: descriptorSha256ByDomain,
  });
  const session = coordinator.preparePhalaProductionActivationEvidence({
    descriptorSetReceipt,
    freshContractDeploymentReceipt,
    launchRecoveryDirectory: recoveryDirectory,
    launchRuntimeResult: launch,
    measurementPolicySet,
    releaseManifestSigstoreVerificationReceipt,
    reviewerGenesis,
    reviewerGenesisAcceptance,
  });

  const reviewedFinalAuthorityFiles = Object.freeze({
    deploymentIntent: writeArtifact("deployment-intent.json", { kind: "deployment" }),
    cvmLaunchIntent: writeArtifact("cvm-launch-intent.json", { kind: "launch" }),
    finalAuthority: writeArtifact("final-authority.json", { kind: "final" }),
    reviewEnvelope: writeArtifact("review-envelope.json", { kind: "envelope" }),
    reviewEvidence: writeArtifact("review-evidence.json", { kind: "evidence" }),
  });
  const deferredAuthorityReview = writeArtifact("deferred-review.json", {
    schema: coordinator.PHALA_PRODUCTION_ACTIVATION_DEFERRED_REVIEW_SCHEMA,
    release_sha: releaseSha,
    deployment_intent_sha256: deploymentIntentSha256,
    cvm_launch_intent_sha256: cvmLaunchIntentSha256,
    final_authority_sha256: finalAuthoritySha256,
    reviewed_at: isoSecond(startMs - 60_000),
    valid_until: isoSecond(startMs + 3_600_000),
    reviewed_unresolved_values_by_domain: [],
  });
  const bootstrapPhaseInput = writeArtifact("bootstrap-secrets.json", {});
  const finalPhaseInput = writeArtifact("final-secrets.json", {});
  const ceremonyLedgerInitializationReceipt = writeArtifact(
    "ledger-init.json",
    {},
    0o444,
  );
  const manifestValue = { immutable: true };
  const immutableDeploymentManifest = writeArtifact(
    "immutable-manifest.json",
    manifestValue,
    0o444,
  );
  const ceremonyLedgerInitial = writeArtifact(
    "ledger-initial.json",
    manifestValue,
    0o600,
  );
  const ceremonyTransactionPlan = writeArtifact("transaction-plan.json", {});
  postlaunchDependencies = Object.freeze({
    ceremonyLedgerInitializationReceipt,
    ceremonyLedgerInitial,
    ceremonyTransactionPlan,
    deferredAuthorityReview,
    immutableDeploymentManifest,
    reviewedFinalAuthorityFiles,
  });
  const resumeInput = {
    bootstrapPhaseInput,
    finalPhaseInput,
    postlaunchActivationCapability: postlaunchCapability,
    qvlIdentityEvidence,
    session,
    signingExchangeDirectory: path.join(root, "signing-exchange"),
    workloadVerdictEvidence,
  };
  let persistenceError;
  try {
    await coordinator.persistPhalaProductionActivationLaunchCompletion({
      qvlIdentityEvidence,
      session,
      workloadVerdictEvidence,
    });
  } catch (error) {
    persistenceError = error;
  }
  if (scenario === "partial-lock") {
    assert.match(persistenceError?.message || "", /lock requires explicit recovery/);
    await assert.rejects(
      coordinator.persistPhalaProductionActivationLaunchCompletion({
        qvlIdentityEvidence,
        session,
        workloadVerdictEvidence,
      }),
      /same-process/,
    );
    assert.throws(
      () => coordinator.disposePhalaProductionActivationSession({ session }),
      /same-process/,
    );
    console.log(JSON.stringify({
      scenario,
      evidenceFactoryCalls,
      persistCalls,
      loadCalls,
      capabilityConsumeCalls,
      closedPinnedHandles,
    }));
  } else if (scenario === "wrong-proof-array") {
    assert.equal(persistenceError, undefined);
    await assert.rejects(
      coordinator.resumePhalaProductionActivationWithEvidence({
        ...resumeInput,
        qvlIdentityEvidence: [...qvlIdentityEvidence].reverse(),
      }),
      /exact original|proof|checkpoint/,
    );
    await assert.rejects(
      coordinator.resumePhalaProductionActivationWithEvidence(resumeInput),
      /same-process/,
    );
    assert.throws(
      () => coordinator.disposePhalaProductionActivationSession({ session }),
      /same-process/,
    );
    console.log(JSON.stringify({
      scenario,
      capabilityConsumeCalls,
      capabilityDisposeCalls,
      capabilityLive,
      closedPinnedHandles,
    }));
  } else {
    assert.equal(persistenceError, undefined);
    let firstError;
    try {
      await coordinator.resumePhalaProductionActivationWithEvidence(resumeInput);
    } catch (error) {
      firstError = error;
    }
    assert.match(firstError?.message || "", /forced downstream Stage-B preparation failure/);
    await assert.rejects(
      coordinator.resumePhalaProductionActivationWithEvidence(resumeInput),
      /same-process/,
    );
    assert.throws(
      () => coordinator.disposePhalaProductionActivationSession({ session }),
      /same-process/,
    );
    console.log(JSON.stringify({
      scenario,
      evidenceFactoryCalls,
      evidenceFreshnessAssertions,
      persistCalls,
      loadCalls,
      reconstructedCompletionCalls,
      downstreamProjectionCalls,
      capabilityConsumeCalls,
      stageAFacadeCalls,
      stageBFacadeCalls,
      authorityEvents,
      closedPinnedHandles,
    }));
  }
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
`;

async function runRecoveryHarness(scenario) {
  const result = await execFileAsync(process.execPath, [
    "--experimental-test-module-mocks",
    "--input-type=module",
    "-e",
    RECOVERY_HARNESS_SOURCE,
  ], {
    cwd: REPOSITORY_ROOT,
    env: {
      ...process.env,
      COORDINATOR_RECOVERY_SCENARIO: scenario,
    },
    maxBuffer: 4 * 1024 * 1024,
    timeout: 30_000,
  });
  const lines = result.stdout.trim().split("\n");
  return JSON.parse(lines.at(-1));
}

test("coordinator publishes only explicit pending-session truth boundaries", () => {
  assert.equal(
    PHALA_PRODUCTION_ACTIVATION_EVIDENCE_SESSION_SCHEMA,
    "dnai.phala-production-activation-coordinator-evidence-session.v1",
  );
  assert.equal(
    PHALA_PRODUCTION_ACTIVATION_EVIDENCE_SESSION_STATUS,
    "release_authority_ready_pending_exact_seven_cvm_production_evidence",
  );
  assert.equal(
    PHALA_PRODUCTION_ACTIVATION_SIGNING_SESSION_SCHEMA,
    "dnai.phala-production-activation-coordinator-signing-session.v1",
  );
  assert.equal(
    PHALA_PRODUCTION_ACTIVATION_SIGNING_SESSION_STATUS,
    "l_plan_and_r_ready_pending_exact_canonical_signed_b",
  );
  assert.equal(
    PHALA_PRODUCTION_ACTIVATION_RUNTIME_SESSION_SCHEMA,
    "dnai.phala-production-activation-coordinator-runtime-session.v1",
  );
  assert.equal(
    PHALA_PRODUCTION_ACTIVATION_RUNTIME_SESSION_STATUS,
    "signed_b_consumed_combined_profile_patch_restart_authenticated_phala_attestation_observed_and_arena_presence_verified_pending_compute_recipient_activation",
  );
  assert.equal(
    PHALA_PRODUCTION_ACTIVATION_COORDINATOR_TRUTH,
    "same_process_branded_authority_chain_not_serializable_authority_or_live_traffic",
  );
  assert.equal(
    PHALA_PRODUCTION_ACTIVATION_DEFERRED_REVIEW_SCHEMA,
    "dnai.phala-production-activation-deferred-review.v1",
  );
  assert.equal(
    PHALA_PRODUCTION_ACTIVATION_DISPOSAL_RECEIPT_SCHEMA,
    "dnai.phala-production-activation-coordinator-disposal-receipt.v1",
  );
});

test("serialized or forged session-shaped values cannot recover coordinator authority", () => {
  const forgeries = [
    {
      assertion: assertPhalaProductionActivationEvidenceSession,
      schema: PHALA_PRODUCTION_ACTIVATION_EVIDENCE_SESSION_SCHEMA,
    },
    {
      assertion: assertPhalaProductionActivationSigningSession,
      schema: PHALA_PRODUCTION_ACTIVATION_SIGNING_SESSION_SCHEMA,
    },
    {
      assertion: assertPhalaProductionActivationRuntimeSession,
      schema: PHALA_PRODUCTION_ACTIVATION_RUNTIME_SESSION_SCHEMA,
    },
  ];
  for (const { assertion, schema } of forgeries) {
    assert.throws(
      () => assertion({
        schema,
        truth_status: PHALA_PRODUCTION_ACTIVATION_COORDINATOR_TRUTH,
        live_traffic_authorized: false,
      }),
      /same-process/,
    );
  }
  assert.throws(
    () => readPhalaProductionActivationEvidenceDependencies({}),
    /same-process/,
  );
  assert.throws(
    () => phalaProductionActivationSigningExchangePaths({}),
    /same-process/,
  );
  assert.throws(
    () => disposePhalaProductionActivationSession({ session: {} }),
    /same-process/,
  );
});

test("all coordinator entry points reject incomplete inputs before authority work", async () => {
  assert.throws(
    () => preparePhalaProductionActivationEvidence({}),
    /contain exactly the frozen fields/,
  );
  await assert.rejects(
    resumePhalaProductionActivationWithEvidence({}),
    /contain exactly the frozen fields/,
  );
  await assert.rejects(
    resumePhalaProductionActivationWithPinnedSigningExchange({}),
    /contain exactly the frozen fields/,
  );
  await assert.rejects(
    persistPhalaProductionActivationLaunchCompletion({}),
    /contain exactly the frozen fields/,
  );
  await assert.rejects(
    beginPhalaProductionActivationFromSignedB({}),
    /contain exactly the frozen fields/,
  );
  await assert.rejects(
    completePhalaProductionActivation({}),
    /contain exactly the frozen fields/,
  );
  assert.throws(
    () => disposePhalaProductionActivationSession({}),
    /contain exactly the frozen fields/,
  );
});

test("prepare rejects the legacy prelaunch reviewer-status-history carrier", () => {
  assert.throws(
    () => preparePhalaProductionActivationEvidence({
      descriptorSetReceipt: {},
      freshContractDeploymentReceipt: {},
      launchRecoveryDirectory: "/tmp/legacy-reviewer-history",
      launchRuntimeResult: {},
      measurementPolicySet: {},
      releaseManifestSigstoreVerificationReceipt: {},
      reviewerGenesis: {},
      reviewerGenesisAcceptance: {},
      reviewerStatusHistory: {},
    }),
    /contain exactly the frozen fields/,
  );
});

test("both evidence-resume entry points reject the legacy direct-dependency API", async () => {
  const legacy = {
    bootstrapPhaseInput: {},
    ceremonyLedgerInitial: {},
    ceremonyLedgerInitializationReceipt: {},
    ceremonyTransactionPlan: {},
    deferredAuthorityReview: {},
    finalPhaseInput: {},
    immutableDeploymentManifest: {},
    qvlIdentityEvidence: [],
    reviewedFinalAuthorityFiles: {},
    session: {},
    signingExchangeDirectory: "/tmp/legacy-stage-b",
    workloadVerdictEvidence: [],
  };
  await assert.rejects(
    resumePhalaProductionActivationWithEvidence(legacy),
    /contain exactly the frozen fields/,
  );
  await assert.rejects(
    resumePhalaProductionActivationWithPinnedSigningExchange({
      ...legacy,
      signingExchangeAuthority: {},
    }),
    /contain exactly the frozen fields/,
  );
});

test("coordinator requires the persisted L and burns manifest capability before final-authority read", () => {
  const source = fs.readFileSync(SOURCE_PATH, "utf8");
  const persistStart = source.indexOf(
    "export async function persistPhalaProductionActivationLaunchCompletion",
  );
  const resumeStart = source.indexOf(
    "async function resumePhalaProductionActivationWithEvidenceInternal",
  );
  const resumeEnd = source.indexOf(
    "export function assertPhalaProductionActivationSigningSession",
    resumeStart,
  );
  assert.ok(persistStart >= 0 && resumeStart > persistStart && resumeEnd > resumeStart);
  const persistBody = source.slice(persistStart, resumeStart);
  const body = source.slice(resumeStart, resumeEnd);
  assert.match(persistBody, /persistOrRecoverLaunchCompletion\(\{/);
  assert.match(
    persistBody,
    /state\.launchCompletionCheckpoint = launchCompletion/,
  );
  const capabilityIndex = body.indexOf(
    "consumePhalaProductionPostlaunchActivationCapability(",
  );
  const proofArrayInterpretationIndex = body.indexOf("evidenceSetForResume(");
  const finalAuthorityReadIndex = body.indexOf("readReviewedFinalAuthoritySet(");
  assert.ok(capabilityIndex >= 0);
  assert.ok(proofArrayInterpretationIndex > capabilityIndex);
  assert.ok(finalAuthorityReadIndex > capabilityIndex);
  assert.doesNotMatch(body, /persistOrRecoverLaunchCompletion\(\{/);
});

test("coordinator late-binds Stage-B reviewer authority after reviewed intent and remaps it for signed-B validation", () => {
  const source = fs.readFileSync(SOURCE_PATH, "utf8");
  const resumeStart = source.indexOf(
    "async function resumePhalaProductionActivationWithEvidenceInternal",
  );
  const resumeEnd = source.indexOf(
    "export function assertPhalaProductionActivationSigningSession",
    resumeStart,
  );
  const resumeBody = source.slice(resumeStart, resumeEnd);
  const finalAuthorityReadIndex = resumeBody.indexOf(
    "readReviewedFinalAuthoritySet(",
  );
  const reviewedIntentIndex = resumeBody.indexOf(
    "readReviewedFinalAuthorityRuntimeDependencies(",
  );
  const stageAIndex = resumeBody.indexOf(
    "normalizeStageAPinnedReviewerAuthority({",
  );
  const stageBIndex = resumeBody.indexOf(
    "normalizeStageBSuccessorReviewerAuthority({",
  );
  const deferredProjectionIndex = resumeBody.indexOf(
    "projectPhalaDeferredPublicEnvironmentAuthority({",
  );
  assert.ok(finalAuthorityReadIndex >= 0);
  assert.ok(reviewedIntentIndex > finalAuthorityReadIndex);
  assert.ok(stageAIndex > reviewedIntentIndex);
  assert.ok(stageBIndex > stageAIndex);
  assert.ok(deferredProjectionIndex > stageBIndex);
  assert.match(
    resumeBody.slice(stageAIndex, stageBIndex),
    /reviewerStatusHistory:\s*\[\][\s\S]*enforceFreshness:\s*false/,
  );
  assert.match(
    resumeBody.slice(stageBIndex, deferredProjectionIndex),
    /reviewerStatusHistory:\s*stageBReviewerStatusHistory[\s\S]*enforceFreshness:\s*true/,
  );

  const stageBBodyStart = source.indexOf("function stageBBodyAndPayload({");
  const launchCompletionStart = source.indexOf(
    "function launchCompletionDependencies(",
    stageBBodyStart,
  );
  const stageBBody = source.slice(stageBBodyStart, launchCompletionStart);
  const maximumExpiryIndex = stageBBody.indexOf("const maximumExpiry = Math.min(");
  const reviewMetadataIndex = stageBBody.indexOf("const reviewMetadata = {");
  assert.ok(maximumExpiryIndex >= 0 && reviewMetadataIndex > maximumExpiryIndex);
  assert.match(
    stageBBody.slice(maximumExpiryIndex, reviewMetadataIndex),
    /Date\.parse\(reviewerStage\.currentStatusExpiresAt\)/,
  );

  const signedBParserStart = source.indexOf("function parsePinnedCanonicalSignedB(");
  const signedBParserEnd = source.indexOf(
    "export async function beginPhalaProductionActivationFromSignedB",
    signedBParserStart,
  );
  const signedBParser = source.slice(signedBParserStart, signedBParserEnd);
  const carrierIndex = signedBParser.indexOf("stageBReviewerStatusHistory,");
  const remapIndex = signedBParser.indexOf(
    "reviewerStatusHistory: stageBReviewerStatusHistory",
  );
  const validationIndex = signedBParser.indexOf(
    "assertFreshProductionCeremonyAuthorizationCore(",
  );
  assert.ok(carrierIndex >= 0);
  assert.ok(remapIndex > carrierIndex);
  assert.ok(validationIndex > remapIndex);
});

test("a bubbled postlaunch resume failure burns capability and evidence session", async () => {
  const result = await runRecoveryHarness("different-second-retry");
  assert.equal(result.evidenceFactoryCalls, 1);
  assert.ok(result.evidenceFreshnessAssertions >= 2);
  assert.equal(result.persistCalls, 1);
  assert.equal(result.loadCalls, 1);
  assert.equal(result.reconstructedCompletionCalls, 0);
  assert.equal(result.downstreamProjectionCalls, 1);
  assert.equal(result.capabilityConsumeCalls, 1);
  assert.equal(result.stageAFacadeCalls, 1);
  assert.equal(result.stageBFacadeCalls, 1);
  assert.deepEqual(result.authorityEvents, [
    "reviewed-deployment-intent",
    "stage-a",
    "stage-b",
    "deferred-projection",
  ]);
  assert.equal(result.closedPinnedHandles, 1);
});

test("a wrong proof array is rejected only after the manifest capability is burned", async () => {
  const result = await runRecoveryHarness("wrong-proof-array");
  assert.equal(result.capabilityConsumeCalls, 1);
  assert.equal(result.capabilityDisposeCalls, 0);
  assert.equal(result.capabilityLive, false);
  assert.equal(result.closedPinnedHandles, 1);
});

test("a bubbled transcript persistence failure irreversibly disposes the session", async () => {
  const result = await runRecoveryHarness("partial-lock");
  assert.equal(result.evidenceFactoryCalls, 1);
  assert.equal(result.loadCalls, 1);
  assert.equal(result.persistCalls, 0);
  assert.equal(result.capabilityConsumeCalls, 0);
  assert.equal(result.closedPinnedHandles, 1);
});

test("source makes the full branded authority chain statically reachable without adapters", () => {
  const source = fs.readFileSync(SOURCE_PATH, "utf8");
  for (const required of [
    "readPhalaProductionExecutorRuntimeDependencies",
    "createPhalaSevenCvmReleaseVerificationAuthority",
    "createPhalaSevenCvmVerifiedEvidenceSet",
    "createPhalaSevenCvmLaunchCompletionReceipt",
    "createPersistedPhalaSevenCvmLaunchCompletionReceipt",
    "loadPhalaSevenCvmHistoricalTranscriptPersistenceReceipt",
    "readReviewedFinalAuthorityRuntimeProjection",
    "projectPhalaDeferredPublicEnvironmentAuthority",
    "createPhalaPostMeasurementActivationPlan",
    "createPreCeremonyRuntimeAuthority",
    "ceremonyAuthorizationReviewSigningPayloadForProduction",
    "beginProductionPhalaPostMeasurementActivation",
    "completeProductionPhalaPostMeasurementActivation",
    "quarantineProductionPhalaPostMeasurementActivationSession",
    "disposePhalaProductionActivationSession",
    "pinPhalaPrivateDirectory",
    "createExclusivePhalaPinnedPrivateFile",
    "readPhalaPinnedPrivateFile",
  ]) {
    assert.match(source, new RegExp(`\\b${required}\\b`));
  }
  assert.doesNotMatch(source, /testOnly(?:Now|Clock|Adapter|Client)/);
  assert.doesNotMatch(source, /\b(?:clock|client|callback|sdkAdapter)\s*:/);
  assert.doesNotMatch(source, /structuredClone/);
  assert.doesNotMatch(source, /bootstrapPhaseInputPath|finalPhaseInputPath/);
  assert.match(source, /bootstrapPhaseInput:\s*state\.bootstrapPhaseInput/);
  assert.match(source, /finalPhaseInput:\s*state\.finalPhaseInput/);
  assert.match(source, /state\.historicalTranscriptState = "exact_committed_recovered"/);
  assert.match(source, /checkpoint\.evidenceSet/);
  assert.match(source, /candidate !== retained\[index\]/);
  assert.match(
    source,
    /existing_transcript_state_unreconciled_operator_recovery_required/,
  );
  assert.match(
    source,
    /consumePhalaProductionPostlaunchActivationCapability/,
  );
  assert.match(source, /EVIDENCE_SESSIONS\.delete\(publicEvidenceSession\)/);
  assert.match(source, /closeEvidenceState\(state\)/);
  assert.match(source, /new WeakMap\(\)/);
  assert.match(source, /mode: 0o600/);
  assert.match(source, /Stage-B signing exchange must be a new separate private directory/);
  for (const key of [
    "deployment_intent",
    "cvm_launch_intent",
    "final_authority",
    "review_envelope",
    "review_evidence",
  ]) {
    assert.match(source, new RegExp(`projectedFilePins\\.${key}`));
  }
  assert.match(source, /state\.consumed = true;[\s\S]*beginProductionPhalaPostMeasurementActivation/);
});
