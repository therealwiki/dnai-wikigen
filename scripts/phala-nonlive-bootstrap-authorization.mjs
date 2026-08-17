import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { deepFreezeCanonicalPlainDataGraph } from "./canonical-authority-graph.mjs";
import {
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_STATUS,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_TRUTH,
  PHALA_NONLIVE_BOOTSTRAP_MAX_FUTURE_SKEW_MS,
  PHALA_NONLIVE_BOOTSTRAP_RECHECK_CHECKPOINTS,
  canonicalPhalaNonLiveBootstrapAuthorizationReceiptText,
  canonicalPhalaNonLiveBootstrapAuthorizationText,
  normalizePhalaNonLiveBootstrapAuthorization,
  normalizePhalaNonLiveBootstrapAuthorizationReceipt,
  phalaNonLiveBootstrapAuthorizationReceiptSha256,
  phalaNonLiveBootstrapSigningMessage,
  reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch as reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunchCore,
} from "./phala-nonlive-bootstrap-authorization-core.mjs";

export {
  PHALA_NONLIVE_BOOTSTRAP_ACTION_SCOPE,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_ID_DOMAIN,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_DOMAIN,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_STATUS,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_TRUTH,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_SCHEMA,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_STATUS,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_TRUTH,
  PHALA_NONLIVE_BOOTSTRAP_FORBIDDEN_SCOPE,
  PHALA_NONLIVE_BOOTSTRAP_MAX_FUTURE_SKEW_MS,
  PHALA_NONLIVE_BOOTSTRAP_MAX_LIFETIME_MS,
  PHALA_NONLIVE_BOOTSTRAP_RECHECK_CHECKPOINTS,
  PHALA_NONLIVE_BOOTSTRAP_SIGNING_DOMAIN,
  PHALA_NONLIVE_BOOTSTRAP_SIGNING_MESSAGE_PREFIX,
  PHALA_PERSISTED_NONLIVE_BOOTSTRAP_HISTORICAL_RECONSTRUCTION_SCHEMA,
  PHALA_PERSISTED_NONLIVE_BOOTSTRAP_HISTORICAL_RECONSTRUCTION_TRUTH,
  canonicalPhalaNonLiveBootstrapAuthorizationReceiptText,
  canonicalPhalaNonLiveBootstrapAuthorizationText,
  createPhalaNonLiveBootstrapSigningPayload,
  normalizePhalaNonLiveBootstrapAuthorization,
  normalizePhalaNonLiveBootstrapAuthorizationReceipt,
  phalaNonLiveBootstrapAuthorizationId,
  phalaNonLiveBootstrapAuthorizationReceiptSha256,
  phalaNonLiveBootstrapSigningDigest,
  phalaNonLiveBootstrapSigningMessage,
} from "./phala-nonlive-bootstrap-authorization-core.mjs";

import {
  canonicalBootstrapPublicEnvironmentAuthorityText,
  normalizeBootstrapPublicEnvironmentAuthority,
} from "./phala-bootstrap-public-environment-authority-core.mjs";
import {
  normalizeExpectedReviewerAuthority,
  verifyPinnedTwoSignerAuthorization,
} from "./release-authority-signature-verifier.mjs";
import {
  canonicalArtifactSha256,
  parseDeploymentIntentCoreText,
} from "./operator-policy-packet-core.mjs";
import {
  canonicalReleaseReviewerAuthorityGenesisArtifactText,
  normalizeReleaseReviewerAuthorityGenesis,
  releaseReviewerAuthorityGenesisSha256,
} from "./release-reviewer-authority-genesis.mjs";
import {
  assertReleaseReviewerAuthorityGenesisAcceptanceCurrentAtTime,
  canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  assertTrackedDescriptorMaterializationSources,
  cvmReleaseDescriptorSetReceiptSha256,
  validateCanonicalGeneratedCvmDescriptorSet,
  verifyExactTrackedSourceDescriptorReproduction,
} from "./cvm-release-descriptor-set-v3.mjs";
import {
  FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
  canonicalFreshContractDeploymentReceiptText,
  freshContractDeploymentReceiptDigest,
  normalizeFreshContractDeploymentReceipt,
} from "./cvm-launch-intent-core.mjs";
import {
  assertPhalaTargetFreshForCheckpoint,
  canonicalPhalaCompatibilityReceiptText,
  canonicalPhalaProductionTargetAuthorityText,
  canonicalPhalaSdkWireTransformStagingReceiptText,
  normalizePhalaCompatibilityReceipt,
  normalizePhalaProductionTargetAuthority,
  normalizePhalaSdkWireTransformStagingReceipt,
  phalaCompatibilityReceiptDigest,
  phalaProductionTargetAuthorityDigest,
  phalaSdkWireTransformStagingReceiptDigest,
} from "./phala-production-target-authority.mjs";
import {
  RELEASE_MANIFEST_SIGSTORE_AUTHORITY,
  RELEASE_MANIFEST_SIGSTORE_BLOCKER,
  assertProductionReleaseManifestSigstoreVerificationReceipt,
  canonicalReleaseManifestSigstoreVerificationReceiptText,
  releaseManifestSigstoreVerificationReceiptSha256,
  verifyReleaseManifestSigstoreAttestation,
} from "./release-manifest-sigstore-verifier.mjs";

const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const MAX_AUTHORIZATION_BYTES = 256 * 1_024;
const VERIFIED_RECEIPTS = new WeakSet();
const HISTORICALLY_VERIFIED_RECEIPTS = new WeakSet();
const VERIFIED_IMMEDIATE_RECHECKS = new WeakSet();
const STABLE_FILE_IMMEDIATE_RECHECKS = new WeakSet();
const DESCRIPTOR_VALIDATED_IMMEDIATE_RECHECKS = new WeakSet();
const TARGET_AUTHORITY_VALIDATED_IMMEDIATE_RECHECKS = new WeakSet();
const CONTRACT_ANCHOR_VALIDATED_IMMEDIATE_RECHECKS = new WeakSet();
const RELEASE_MANIFEST_SIGSTORE_VALIDATED_IMMEDIATE_RECHECKS = new WeakSet();
function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map((entry) => sortedObject(entry));
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sortedObject(value), null, 2)}\n`;
}

function sha256Bytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

export function assertPersistedPhalaNonLiveBootstrapAuthorizationReceipt({
  persistedReceipt,
  verifiedReceipt,
} = {}) {
  if (!verifiedReceipt
    || (!VERIFIED_RECEIPTS.has(verifiedReceipt)
      && !HISTORICALLY_VERIFIED_RECEIPTS.has(verifiedReceipt))) {
    throw new Error("persisted A receipt requires a cryptographically verified signed A result");
  }
  const persisted = normalizePhalaNonLiveBootstrapAuthorizationReceipt(
    persistedReceipt,
  );
  const verified = normalizePhalaNonLiveBootstrapAuthorizationReceipt(
    verifiedReceipt,
  );
  if (canonicalPhalaNonLiveBootstrapAuthorizationReceiptText(persisted)
      !== canonicalPhalaNonLiveBootstrapAuthorizationReceiptText(verified)) {
    throw new Error("persisted A receipt differs from the cryptographically verified signed A result");
  }
  return deepFreezeCanonicalPlainDataGraph(persisted, {
    label: "persisted non-live bootstrap authorization receipt",
  });
}

export function assertCryptographicallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt(
  receipt,
) {
  if (!receipt
    || (!VERIFIED_RECEIPTS.has(receipt)
      && !HISTORICALLY_VERIFIED_RECEIPTS.has(receipt))) {
    throw new Error("signed A receipt has not been cryptographically reconstructed");
  }
  return deepFreezeCanonicalPlainDataGraph(
    normalizePhalaNonLiveBootstrapAuthorizationReceipt(receipt),
    { label: "cryptographically verified signed A receipt" },
  );
}

// Launch completion is intentionally reconstructed after signed A has expired.
// Requiring the historical-only brand prevents a still-live bootstrap grant from
// being silently repurposed as completion evidence, while preserving the exact
// signature-verified bytes that authorized the completed mutation window.
export function assertHistoricallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt(
  receipt,
) {
  if (!receipt || !HISTORICALLY_VERIFIED_RECEIPTS.has(receipt)) {
    throw new Error("signed A receipt has not been historically cryptographically reconstructed");
  }
  return deepFreezeCanonicalPlainDataGraph(
    normalizePhalaNonLiveBootstrapAuthorizationReceipt(receipt),
    { label: "historically verified signed A receipt" },
  );
}

function brandReceipt(value) {
  const receipt = deepFreezeCanonicalPlainDataGraph(
    normalizePhalaNonLiveBootstrapAuthorizationReceipt(value),
    { label: "fresh signed A receipt brand" },
  );
  VERIFIED_RECEIPTS.add(receipt);
  return receipt;
}

function brandHistoricalReceipt(value) {
  const receipt = deepFreezeCanonicalPlainDataGraph(
    normalizePhalaNonLiveBootstrapAuthorizationReceipt(value),
    { label: "historical signed A receipt brand" },
  );
  HISTORICALLY_VERIFIED_RECEIPTS.add(receipt);
  return receipt;
}

function verifyPhalaNonLiveBootstrapAuthorizationInternal({
  authorization,
  bootstrapAuthority,
  reviewerAuthority,
  nowMs,
  authorizationArtifactFileSha256 = null,
  bootstrapAuthorityArtifactFileSha256 = null,
  historicalOnly = false,
} = {}) {
  const bootstrap = normalizeBootstrapPublicEnvironmentAuthority(bootstrapAuthority);
  const parsed = normalizePhalaNonLiveBootstrapAuthorization(
    authorization,
    { bootstrapAuthority: bootstrap },
  );
  const {
    signed_payload_sha256: signedPayloadSha256,
    signatures,
    ...payload
  } = parsed;
  const issuedAtMs = Date.parse(payload.issued_at);
  const expiresAtMs = Date.parse(payload.expires_at);
  const verificationNowMs = nowMs === undefined ? Date.now() : nowMs;
  if (!Number.isSafeInteger(verificationNowMs)
    || issuedAtMs
      > verificationNowMs + PHALA_NONLIVE_BOOTSTRAP_MAX_FUTURE_SKEW_MS
    || (historicalOnly
      ? expiresAtMs > verificationNowMs
      : expiresAtMs <= verificationNowMs)) {
    throw new Error(historicalOnly
      ? "historical non-live bootstrap authorization has not expired"
      : "non-live bootstrap authorization is not fresh");
  }
  const signatureEvidence = verifyPinnedTwoSignerAuthorization({
    signatures,
    message: phalaNonLiveBootstrapSigningMessage(payload, {
      bootstrapAuthority: bootstrap,
    }),
    reviewerAuthority,
  });
  if (signatureEvidence.reviewer_root_hash !== payload.reviewer_root_hash
    || signatureEvidence.reviewer_set_sha256 !== payload.reviewer_set_sha256) {
    throw new Error("verified bootstrap signers do not match the transitive reviewer authority");
  }
  const authorizationBytes = Buffer.from(
    canonicalPhalaNonLiveBootstrapAuthorizationText(parsed, {
      bootstrapAuthority: bootstrap,
    }),
    "utf8",
  );
  const bootstrapBytes = Buffer.from(
    canonicalBootstrapPublicEnvironmentAuthorityText(bootstrap),
    "utf8",
  );
  const authorizationFileSha = authorizationArtifactFileSha256 == null
    ? sha256Bytes(authorizationBytes)
    : exactSha256(
      authorizationArtifactFileSha256,
      "authorization artifact file SHA-256",
    );
  const bootstrapFileSha = bootstrapAuthorityArtifactFileSha256 == null
    ? sha256Bytes(bootstrapBytes)
    : exactSha256(
      bootstrapAuthorityArtifactFileSha256,
      "bootstrap authority artifact file SHA-256",
    );
  if (authorizationFileSha !== sha256Bytes(authorizationBytes)
    || bootstrapFileSha !== sha256Bytes(bootstrapBytes)) {
    throw new Error("stable artifact file hashes differ from canonical authorization bytes");
  }
  const receipt = {
    schema: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA,
    status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_STATUS,
    truth_status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_TRUTH,
    authorization_id: payload.authorization_id,
    batch_id: payload.batch_id,
    release_sha: payload.release_sha,
    bootstrap_public_environment_authority_sha256:
      payload.bootstrap_public_environment_authority_sha256,
    image_release_manifest_sha256: bootstrap.image_release_manifest_sha256,
    topology_sha256: bootstrap.topology_sha256,
    descriptor_sha256_by_domain: Object.fromEntries(
      bootstrap.domains.map((entry) => [entry.domain, entry.descriptor_sha256]),
    ),
    deployment_intent_sha256: payload.deployment_intent_sha256,
    fresh_contract_deployment_receipt_sha256:
      payload.fresh_contract_deployment_receipt_sha256,
    image_release_sigstore_verification_receipt_sha256:
      payload.image_release_sigstore_verification_receipt_sha256,
    cvm_launch_intent_sha256: payload.cvm_launch_intent_sha256,
    cvm_launch_review_receipt_sha256:
      payload.cvm_launch_review_receipt_sha256,
    production_target_authority_sha256:
      payload.production_target_authority_sha256,
    sdk_wire_transform_staging_receipt_sha256:
      payload.sdk_wire_transform_staging_receipt_sha256,
    qvl_measurement_policy_set_sha256:
      payload.qvl_measurement_policy_set_sha256,
    action_scope: payload.action_scope,
    forbidden_scope: payload.forbidden_scope,
    signed_payload_sha256: signedPayloadSha256,
    authorization_artifact_file_sha256: authorizationFileSha,
    bootstrap_authority_artifact_file_sha256: bootstrapFileSha,
    signature_scheme: signatureEvidence.signature_scheme,
    signature_verifier: signatureEvidence.signature_verifier,
    reviewer_root_hash: signatureEvidence.reviewer_root_hash,
    reviewer_set_sha256: signatureEvidence.reviewer_set_sha256,
    signer_count: 2,
    signers: signatureEvidence.signers,
    issued_at: payload.issued_at,
    expires_at: payload.expires_at,
    live_traffic_authorized: false,
    late_secret_activation_authorized: false,
    mutation_performed: false,
  };
  return historicalOnly ? brandHistoricalReceipt(receipt) : brandReceipt(receipt);
}

export function verifyPhalaNonLiveBootstrapAuthorization(options = {}) {
  return verifyPhalaNonLiveBootstrapAuthorizationInternal({
    ...options,
    historicalOnly: false,
  });
}

export function verifyHistoricalPhalaNonLiveBootstrapAuthorization(options = {}) {
  if (Object.hasOwn(options, "nowMs")) {
    throw new Error(
      "historical non-live bootstrap verification time must come from the current process clock",
    );
  }
  return verifyPhalaNonLiveBootstrapAuthorizationInternal({
    ...options,
    nowMs: Date.now(),
    historicalOnly: true,
  });
}

/**
 * Deterministically replays signed A for exact-37 historical validation.
 * Static Noble recovery verifies the exact canonical input-file identities,
 * while temporal validity is evaluated only at L's persisted completion
 * second. This never reruns the original Cast verifier, consults the current
 * clock, or mints a fresh/historical production brand.
 */
export function reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch(
  input = {},
) {
  return reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunchCore(
    input,
  );
}

function readStableCanonicalJson(filePath, label, {
  canonicalizer = canonicalText,
} = {}) {
  if (typeof canonicalizer !== "function") {
    throw new Error(`${label} canonicalizer must be a function`);
  }
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)
    || path.resolve(filePath) !== filePath
    || fs.realpathSync.native(filePath) !== filePath) {
    throw new Error(`${label} path must be absolute, canonical, and symlink-free`);
  }
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  let fd;
  try {
    fd = fs.openSync(filePath, flags);
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1 || (before.mode & 0o022) !== 0
      || (typeof process.getuid === "function" && before.uid !== process.getuid())
      || before.size < 2 || before.size > MAX_AUTHORIZATION_BYTES) {
      throw new Error(`${label} must be a current-owner bounded non-writable regular file`);
    }
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    const pathAfter = fs.lstatSync(filePath);
    if (before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeMs !== after.mtimeMs
      || before.ctimeMs !== after.ctimeMs || before.mode !== after.mode
      || before.uid !== after.uid || before.nlink !== after.nlink
      || pathAfter.dev !== after.dev || pathAfter.ino !== after.ino
      || pathAfter.mode !== after.mode || pathAfter.size !== after.size
      || fs.realpathSync.native(filePath) !== filePath
      || bytes.length !== before.size) {
      throw new Error(`${label} changed during its stable read`);
    }
    let value;
    try {
      value = JSON.parse(bytes.toString("utf8"));
    } catch {
      throw new Error(`${label} is not JSON`);
    }
    if (canonicalizer(value) !== bytes.toString("utf8")) {
      throw new Error(`${label} must use canonical sorted JSON bytes`);
    }
    return { bytes, value, sha256: sha256Bytes(bytes) };
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

async function readFreshReleaseManifestSigstoreEvidence({
  releaseDirectory,
  imageReleaseManifestPath,
  imageReleaseSigstoreBundlePath,
  imageReleaseSigstoreVerificationReceiptPath,
  bootstrapAuthorityEvidence,
} = {}) {
  if (typeof releaseDirectory !== "string" || !path.isAbsolute(releaseDirectory)
    || imageReleaseManifestPath !== path.join(
      releaseDirectory,
      RELEASE_MANIFEST_SIGSTORE_AUTHORITY.subject_filename,
    )
    || imageReleaseSigstoreBundlePath !== path.join(
      releaseDirectory,
      RELEASE_MANIFEST_SIGSTORE_AUTHORITY.bundle_filename,
    )) {
    throw new Error(
      "Sigstore manifest and bundle must be the exact canonical release-directory artifacts",
    );
  }
  const verified = assertProductionReleaseManifestSigstoreVerificationReceipt(
    await verifyReleaseManifestSigstoreAttestation({
      manifestPath: imageReleaseManifestPath,
      bundlePath: imageReleaseSigstoreBundlePath,
      expectedReleaseSha: bootstrapAuthorityEvidence.release_sha,
    }),
  );
  const receiptFile = readStableCanonicalJson(
    imageReleaseSigstoreVerificationReceiptPath,
    "image release Sigstore verification receipt",
    { canonicalizer: canonicalReleaseManifestSigstoreVerificationReceiptText },
  );
  const persisted = assertProductionReleaseManifestSigstoreVerificationReceipt(
    receiptFile.value,
  );
  if (canonicalReleaseManifestSigstoreVerificationReceiptText(persisted)
      !== canonicalReleaseManifestSigstoreVerificationReceiptText(verified)) {
    throw new Error(
      "persisted Sigstore verification receipt differs from the fresh pinned-gh verification",
    );
  }
  const receiptSha256 = releaseManifestSigstoreVerificationReceiptSha256(
    persisted,
  );
  if (receiptSha256
      !== bootstrapAuthorityEvidence
        .image_release_sigstore_verification_receipt_sha256
    || persisted.release_sha !== bootstrapAuthorityEvidence.release_sha
    || persisted.release_manifest_sha256
      !== bootstrapAuthorityEvidence.image_release_manifest_sha256
    || persisted.blocker_code !== RELEASE_MANIFEST_SIGSTORE_BLOCKER
    || persisted.blocker_status !== "cleared_by_this_receipt"
    || persisted.status !== "verified_by_pinned_gh_sigstore") {
    throw new Error(
      "production Sigstore verification does not equal the signed bootstrap image authority",
    );
  }
  return Object.freeze({
    releaseManifestSigstoreVerificationReceiptSha256: receiptSha256,
    releaseManifestSigstoreVerificationReceiptArtifactFileSha256:
      receiptFile.sha256,
    releaseManifestSha256: persisted.release_manifest_sha256,
    releaseManifestSigstoreBundleSha256:
      persisted.release_manifest_sigstore_bundle_sha256,
    ghExecutableSha256: persisted.gh_executable_sha256,
    verificationCommandSha256: persisted.verification_command_sha256,
    verificationOutputSha256: persisted.verification_output_sha256,
    verifiedIdentitySha256: persisted.verified_identity_sha256,
    blockerCode: RELEASE_MANIFEST_SIGSTORE_BLOCKER,
    blockerStatus: "cleared_by_this_receipt",
  });
}

function readTransitivelyPinnedReviewerAuthority({
  deploymentIntentPath,
  reviewerAuthorityGenesisPath,
  reviewerAuthorityGenesisAcceptancePath,
  bootstrapAuthority,
  nowMs,
} = {}) {
  const deploymentIntentFile = readStableCanonicalJson(
    deploymentIntentPath,
    "deployment intent",
  );
  const parsedIntent = parseDeploymentIntentCoreText(
    deploymentIntentFile.bytes.toString("utf8"),
  );
  if (!parsedIntent.ok) {
    throw new Error("deployment intent is not canonical deployment-intent v6 authority");
  }
  const deploymentIntentSha256 = canonicalArtifactSha256(parsedIntent.intent);
  if (deploymentIntentSha256 !== bootstrapAuthority.deployment_intent_sha256
    || parsedIntent.intent.release.releaseSha !== bootstrapAuthority.release_sha) {
    throw new Error("deployment intent does not match the bootstrap authority release");
  }
  const genesisFile = readStableCanonicalJson(
    reviewerAuthorityGenesisPath,
    "release reviewer authority genesis",
  );
  const deploymentRoleAddresses = [...new Set([
    parsedIntent.intent.deploymentControl.operatorAddress,
    parsedIntent.intent.staticContractInputs.computeCreditVault.developer,
  ])].sort();
  const deploymentRoleControllerIds = [
    parsedIntent.intent.deploymentControl.controllerId,
  ];
  const genesisOptions = {
    deploymentRoleAddresses,
    deploymentRoleControllerIds,
  };
  const genesis = normalizeReleaseReviewerAuthorityGenesis(
    genesisFile.value,
    genesisOptions,
  );
  if (genesisFile.bytes.toString("utf8")
      !== canonicalReleaseReviewerAuthorityGenesisArtifactText(
        genesis,
        genesisOptions,
      )) {
    throw new Error("release reviewer authority genesis normalized bytes drifted");
  }
  const genesisSha256 = releaseReviewerAuthorityGenesisSha256(
    genesis,
    genesisOptions,
  );
  if (genesis.release_sha !== bootstrapAuthority.release_sha
    || genesis.chain_id !== 84_532) {
    throw new Error("reviewer genesis release identity is invalid");
  }
  const acceptanceFile = readStableCanonicalJson(
    reviewerAuthorityGenesisAcceptancePath,
    "release reviewer authority genesis acceptance",
  );
  if (!Number.isSafeInteger(nowMs)) {
    throw new Error("reviewer current-status validation time must be an integer millisecond");
  }
  const statusNow = new Date(Math.floor(nowMs / 1_000) * 1_000)
    .toISOString()
    .replace(".000Z", "Z");
  const acceptanceOptions = {
    reviewerGenesis: genesis,
    ...genesisOptions,
  };
  const acceptance =
    assertReleaseReviewerAuthorityGenesisAcceptanceCurrentAtTime(
    acceptanceFile.value,
    {
      ...acceptanceOptions,
      now: statusNow,
      expectedCurrentStatusEpoch:
        parsedIntent.intent.release.reviewerAuthorityCurrentStatusEpoch,
      expectedCurrentStatusSha256:
        parsedIntent.intent.release.reviewerAuthorityCurrentStatusSha256,
    },
  );
  if (acceptanceFile.bytes.toString("utf8")
      !== canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
        acceptance,
        acceptanceOptions,
      )) {
    throw new Error("release reviewer genesis acceptance normalized bytes drifted");
  }
  const acceptanceSha256 = releaseReviewerAuthorityGenesisAcceptanceSha256(
    acceptance,
    acceptanceOptions,
  );
  if (acceptanceSha256
      !== parsedIntent.intent.release.reviewerAuthorityGenesisAcceptanceSha256
    || acceptance.reviewer_authority_genesis_sha256 !== genesisSha256
    || acceptance.release_sha !== bootstrapAuthority.release_sha
    || acceptance.chain_id !== 84_532
    || acceptance.reviewer_count
      !== acceptance.reviewer_authority_current_status.active_reviewers.length
    || acceptance.all_active_reviewers_required !== true
    || acceptance.reviewer_authority_current_status.epoch
      !== parsedIntent.intent.release.reviewerAuthorityCurrentStatusEpoch
    || acceptance.reviewer_authority_current_status_sha256
      !== parsedIntent.intent.release.reviewerAuthorityCurrentStatusSha256) {
    throw new Error(
      "current-status reviewer acceptance is not transitively precommitted by deployment intent",
    );
  }
  const currentStatus = acceptance.reviewer_authority_current_status;
  const reviewerAuthority = normalizeExpectedReviewerAuthority({
    approved_reviewers: currentStatus.active_reviewers,
    approved_reviewer_hashes: currentStatus.approved_reviewer_hashes,
    reviewer_root_hash: currentStatus.reviewer_root_hash,
    reviewer_set_sha256: currentStatus.reviewer_set_sha256,
  }, {
    expectedReviewerRootHash: currentStatus.reviewer_root_hash,
    expectedReviewerSetSha256: currentStatus.reviewer_set_sha256,
  });
  return {
    reviewerAuthority,
    deploymentIntentSha256,
    deploymentIntentArtifactFileSha256: deploymentIntentFile.sha256,
    reviewerAuthorityGenesisSha256: genesisSha256,
    reviewerAuthorityGenesisArtifactFileSha256: genesisFile.sha256,
    reviewerAuthorityGenesisAcceptanceSha256: acceptanceSha256,
    reviewerAuthorityGenesisAcceptanceArtifactFileSha256: acceptanceFile.sha256,
    reviewerAuthorityCurrentStatusEpoch: currentStatus.epoch,
    reviewerAuthorityCurrentStatusSha256:
      acceptance.reviewer_authority_current_status_sha256,
    reviewerGenesisAcceptanceCryptographicallyVerified: true,
    reviewerGenesisIndependentlyAnchored: false,
  };
}

function readFreshPhalaTargetAuthorityEvidence({
  compatibilityReceiptPath,
  sdkWireTransformStagingReceiptPath,
  productionTargetAuthorityPath,
  bootstrapAuthority,
  checkpoint,
  nowMs,
} = {}) {
  if (!Number.isSafeInteger(nowMs)) {
    throw new Error("target authority stable recheck time must be an integer millisecond");
  }
  const compatibilityFile = readStableCanonicalJson(
    compatibilityReceiptPath,
    "Phala compatibility receipt",
  );
  const compatibility = normalizePhalaCompatibilityReceipt(
    compatibilityFile.value,
  );
  if (compatibilityFile.bytes.toString("utf8")
      !== canonicalPhalaCompatibilityReceiptText(compatibility)) {
    throw new Error("Phala compatibility receipt normalized bytes drifted");
  }
  const compatibilitySha256 = phalaCompatibilityReceiptDigest(compatibility);

  const stagingFile = readStableCanonicalJson(
    sdkWireTransformStagingReceiptPath,
    "Phala SDK wire-transform staging receipt",
  );
  const staging = normalizePhalaSdkWireTransformStagingReceipt(
    stagingFile.value,
    { compatibilityReceipt: compatibility },
  );
  if (stagingFile.bytes.toString("utf8")
      !== canonicalPhalaSdkWireTransformStagingReceiptText(staging, {
        compatibilityReceipt: compatibility,
      })) {
    throw new Error("Phala SDK wire-transform staging receipt normalized bytes drifted");
  }
  const stagingSha256 = phalaSdkWireTransformStagingReceiptDigest(staging, {
    compatibilityReceipt: compatibility,
  });

  const targetFile = readStableCanonicalJson(
    productionTargetAuthorityPath,
    "Phala production target authority",
  );
  const target = normalizePhalaProductionTargetAuthority(targetFile.value, {
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
  });
  if (targetFile.bytes.toString("utf8")
      !== canonicalPhalaProductionTargetAuthorityText(target, {
        compatibilityReceipt: compatibility,
        sdkWireTransformStagingReceipt: staging,
      })) {
    throw new Error("Phala production target authority normalized bytes drifted");
  }
  const targetSha256 = phalaProductionTargetAuthorityDigest(target, {
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
  });
  if (stagingSha256
      !== bootstrapAuthority.sdk_wire_transform_staging_receipt_sha256
    || targetSha256 !== bootstrapAuthority.production_target_authority_sha256
    || target.release_sha !== bootstrapAuthority.release_sha
    || target.cvm_launch_intent_sha256
      !== bootstrapAuthority.cvm_launch_intent_sha256) {
    throw new Error(
      "stable Phala target capability evidence does not equal the signed bootstrap subject",
    );
  }
  const checkedAt = new Date(nowMs).toISOString().replace(/\.\d{3}Z$/, "Z");
  const freshness = assertPhalaTargetFreshForCheckpoint({
    targetAuthority: target,
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    checkpoint,
    now: checkedAt,
  });
  if (freshness.compatibility_receipt_sha256 !== compatibilitySha256
    || freshness.target_authority_sha256 !== targetSha256
    || freshness.fresh !== true
    || freshness.mutation_performed !== false) {
    throw new Error("Phala target freshness evidence is inconsistent");
  }
  return Object.freeze({
    compatibilityReceipt: deepFreezeCanonicalPlainDataGraph(
      structuredClone(compatibility),
      { label: "rechecked Phala compatibility receipt" },
    ),
    sdkWireTransformStagingReceipt: deepFreezeCanonicalPlainDataGraph(
      structuredClone(staging),
      { label: "rechecked SDK wire-transform staging receipt" },
    ),
    productionTargetAuthority: deepFreezeCanonicalPlainDataGraph(
      structuredClone(target),
      { label: "rechecked Phala production target authority" },
    ),
    compatibilityReceiptSha256: compatibilitySha256,
    compatibilityReceiptArtifactFileSha256: compatibilityFile.sha256,
    sdkWireTransformStagingReceiptSha256: stagingSha256,
    sdkWireTransformStagingReceiptArtifactFileSha256: stagingFile.sha256,
    productionTargetAuthoritySha256: targetSha256,
    productionTargetAuthorityArtifactFileSha256: targetFile.sha256,
    workspaceId: target.workspace.workspace_id,
    workspaceAccountSubjectSha256: target.workspace.account_subject_sha256,
    apiOrigin: target.api.origin,
    apiVersion: target.api.version,
    kmsId: target.kms.id,
    kmsSignerK256: target.kms.env_encrypt_signer_k256,
    osImageHash: target.os_image.os_image_hash,
    targetExpiresAt: target.expires_at,
    freshnessReceiptSha256: sha256Bytes(
      Buffer.from(canonicalText(freshness), "utf8"),
    ),
  });
}

export function readAndValidateFreshContractDeploymentAnchorEvidence({
  freshContractDeploymentReceiptPath,
  bootstrapAuthorityEvidence,
  reviewerAuthorityEvidence,
  expectedTinkerAccountBindingCeremonyReceiptSha256,
} = {}) {
  const authorityPins = {
    expectedDeploymentIntentSha256:
      reviewerAuthorityEvidence.deployment_intent_sha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      reviewerAuthorityEvidence.reviewer_authority_genesis_acceptance_sha256,
    expectedTinkerAccountBindingCeremonyReceiptSha256,
  };
  const receiptFile = readStableCanonicalJson(
    freshContractDeploymentReceiptPath,
    "fresh contract deployment receipt",
  );
  const receipt = normalizeFreshContractDeploymentReceipt(
    receiptFile.value,
    authorityPins,
  );
  if (receiptFile.bytes.toString("utf8")
      !== canonicalFreshContractDeploymentReceiptText(receipt, authorityPins)) {
    throw new Error("fresh contract deployment receipt normalized bytes drifted");
  }
  const receiptSha256 = `sha256:${freshContractDeploymentReceiptDigest(
    receipt,
    authorityPins,
  )}`;
  if (receiptSha256
      !== bootstrapAuthorityEvidence.fresh_contract_deployment_receipt_sha256
    || receipt.release_sha !== bootstrapAuthorityEvidence.release_sha
    || receipt.deployment_intent_sha256
      !== reviewerAuthorityEvidence.deployment_intent_sha256
    || receipt.reviewer_authority_genesis_acceptance_sha256
      !== reviewerAuthorityEvidence
        .reviewer_authority_genesis_acceptance_sha256) {
    throw new Error(
      "fresh contract deployment receipt does not equal the signed bootstrap subject",
    );
  }
  const anchor = receipt.contracts.find(
    (entry) => entry.name === "ExecutionPolicyAnchor",
  );
  const expectedDeploymentIntentBytes32 =
    `0x${receipt.deployment_intent_sha256.slice("sha256:".length)}`;
  const expectedGenesisAcceptanceBytes32 =
    `0x${receipt.reviewer_authority_genesis_acceptance_sha256
      .slice("sha256:".length)}`;
  if (!anchor
    || anchor.deployment_intent_sha256_bytes32
      !== expectedDeploymentIntentBytes32
    || anchor.reviewer_authority_genesis_acceptance_sha256_bytes32
      !== expectedGenesisAcceptanceBytes32
    || anchor.authority_commitment_read_proof
      !== FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF
    || anchor.authority_commitment_read_block !== anchor.deployment_block
    || anchor.authority_commitment_read_block_hash
      !== anchor.deployment_block_hash) {
    throw new Error(
      "ExecutionPolicyAnchor does not independently bind deployment intent and signed reviewer genesis acceptance",
    );
  }
  return Object.freeze({
    freshContractDeploymentReceiptSha256: receiptSha256,
    freshContractDeploymentReceiptArtifactFileSha256: receiptFile.sha256,
    executionPolicyAnchorAddress: anchor.address,
    executionPolicyAnchorDeploymentBlock: anchor.deployment_block,
    executionPolicyAnchorDeploymentBlockHash: anchor.deployment_block_hash,
    executionPolicyAnchorAuthorityCommitmentReadProof:
      FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
    deploymentIntentSha256Bytes32: expectedDeploymentIntentBytes32,
    reviewerAuthorityGenesisAcceptanceSha256Bytes32:
      expectedGenesisAcceptanceBytes32,
  });
}

export function readAndVerifyPhalaNonLiveBootstrapAuthorization({
  authorizationPath,
  bootstrapAuthorityPath,
  deploymentIntentPath,
  reviewerAuthorityGenesisPath,
  reviewerAuthorityGenesisAcceptancePath,
  nowMs = Date.now(),
} = {}) {
  const bootstrapFile = readStableCanonicalJson(
    bootstrapAuthorityPath,
    "bootstrap public environment authority",
  );
  const bootstrap = normalizeBootstrapPublicEnvironmentAuthority(
    bootstrapFile.value,
  );
  if (bootstrapFile.bytes.toString("utf8")
      !== canonicalBootstrapPublicEnvironmentAuthorityText(bootstrap)) {
    throw new Error("bootstrap public environment authority normalized bytes drifted");
  }
  const authorizationFile = readStableCanonicalJson(
    authorizationPath,
    "non-live bootstrap authorization",
  );
  const reviewerAuthorityEvidence = readTransitivelyPinnedReviewerAuthority({
    deploymentIntentPath,
    reviewerAuthorityGenesisPath,
    reviewerAuthorityGenesisAcceptancePath,
    bootstrapAuthority: bootstrap,
    nowMs,
  });
  const receipt = verifyPhalaNonLiveBootstrapAuthorization({
    authorization: authorizationFile.value,
    bootstrapAuthority: bootstrap,
    reviewerAuthority: reviewerAuthorityEvidence.reviewerAuthority,
    nowMs,
    authorizationArtifactFileSha256: authorizationFile.sha256,
    bootstrapAuthorityArtifactFileSha256: bootstrapFile.sha256,
  });
  if (authorizationFile.bytes.toString("utf8")
      !== canonicalPhalaNonLiveBootstrapAuthorizationText(
        authorizationFile.value,
        { bootstrapAuthority: bootstrap },
      )) {
    throw new Error("non-live bootstrap authorization normalized bytes drifted");
  }
  return Object.freeze({
    receipt,
    bootstrap_public_environment_authority: deepFreezeCanonicalPlainDataGraph(
      structuredClone(bootstrap),
      { label: "rechecked bootstrap public environment authority" },
    ),
    bootstrap_authority_evidence: Object.freeze({
      release_sha: bootstrap.release_sha,
      deployment_intent_sha256: bootstrap.deployment_intent_sha256,
      fresh_contract_deployment_receipt_sha256:
        bootstrap.fresh_contract_deployment_receipt_sha256,
      image_release_manifest_sha256: bootstrap.image_release_manifest_sha256,
      image_release_sigstore_verification_receipt_sha256:
        bootstrap.image_release_sigstore_verification_receipt_sha256,
      topology_sha256: bootstrap.topology_sha256,
      cvm_launch_intent_sha256: bootstrap.cvm_launch_intent_sha256,
      cvm_launch_review_receipt_sha256:
        bootstrap.cvm_launch_review_receipt_sha256,
      production_target_authority_sha256:
        bootstrap.production_target_authority_sha256,
      sdk_wire_transform_staging_receipt_sha256:
        bootstrap.sdk_wire_transform_staging_receipt_sha256,
      qvl_measurement_policy_set_sha256:
        bootstrap.qvl_measurement_policy_set_sha256,
      descriptor_sha256_by_domain: Object.freeze(Object.fromEntries(
        bootstrap.domains.map((entry) => [entry.domain, entry.descriptor_sha256]),
      )),
    }),
    reviewer_authority_evidence: Object.freeze({
      deployment_intent_sha256:
        reviewerAuthorityEvidence.deploymentIntentSha256,
      deployment_intent_artifact_file_sha256:
        reviewerAuthorityEvidence.deploymentIntentArtifactFileSha256,
      reviewer_authority_genesis_sha256:
        reviewerAuthorityEvidence.reviewerAuthorityGenesisSha256,
      reviewer_authority_genesis_artifact_file_sha256:
        reviewerAuthorityEvidence.reviewerAuthorityGenesisArtifactFileSha256,
      reviewer_authority_genesis_acceptance_sha256:
        reviewerAuthorityEvidence.reviewerAuthorityGenesisAcceptanceSha256,
      reviewer_authority_genesis_acceptance_artifact_file_sha256:
        reviewerAuthorityEvidence
          .reviewerAuthorityGenesisAcceptanceArtifactFileSha256,
      reviewer_authority_current_status_epoch:
        reviewerAuthorityEvidence.reviewerAuthorityCurrentStatusEpoch,
      reviewer_authority_current_status_sha256:
        reviewerAuthorityEvidence.reviewerAuthorityCurrentStatusSha256,
      reviewer_genesis_acceptance_cryptographically_verified:
        reviewerAuthorityEvidence
          .reviewerGenesisAcceptanceCryptographicallyVerified,
      reviewer_genesis_independently_anchored:
        reviewerAuthorityEvidence.reviewerGenesisIndependentlyAnchored,
    }),
  });
}

export function assertFreshPhalaNonLiveBootstrapAuthorizationReceipt({
  receipt,
  checkpoint,
  nowMs = Date.now(),
  expectedBatchId,
  expectedAuthorizationId,
  expectedTargetAuthoritySha256,
  expectedStagingReceiptSha256,
} = {}) {
  if (!receipt || !VERIFIED_RECEIPTS.has(receipt)
    || !PHALA_NONLIVE_BOOTSTRAP_RECHECK_CHECKPOINTS.includes(checkpoint)) {
    throw new Error("a branded non-live bootstrap receipt and exact checkpoint are required");
  }
  if (!Number.isSafeInteger(nowMs) || Date.parse(receipt.expires_at) <= nowMs
    || receipt.batch_id !== expectedBatchId
    || receipt.authorization_id !== expectedAuthorizationId
    || receipt.production_target_authority_sha256 !== expectedTargetAuthoritySha256
    || receipt.sdk_wire_transform_staging_receipt_sha256
      !== expectedStagingReceiptSha256) {
    throw new Error(`fresh exact non-live bootstrap authorization required ${checkpoint}`);
  }
  const recheck = Object.freeze({
    schema: "dnai.phala-nonlive-bootstrap-immediate-recheck.v1",
    status: "non_live_bootstrap_signatures_reverified",
    checkpoint,
    checked_at: new Date(nowMs).toISOString().replace(/\.\d{3}Z$/, "Z"),
    authorization_id: receipt.authorization_id,
    batch_id: receipt.batch_id,
    authorization_expires_at: receipt.expires_at,
    authorization_receipt_sha256:
      phalaNonLiveBootstrapAuthorizationReceiptSha256(receipt),
    stable_file_reread: false,
    fresh: true,
    live_traffic_authorized: false,
    mutation_performed: false,
  });
  VERIFIED_IMMEDIATE_RECHECKS.add(recheck);
  return recheck;
}

export function assertVerifiedPhalaNonLiveBootstrapImmediateRecheck({
  recheck,
  checkpoint,
  expectedBatchId,
  expectedAuthorizationId,
  requireStableFileReread = false,
  requireIndependentGenesisAnchor = false,
  requireDescriptorSetValidation = false,
  requireTargetAuthorityValidation = false,
  requireReleaseManifestSigstoreValidation = false,
} = {}) {
  if (!recheck || !VERIFIED_IMMEDIATE_RECHECKS.has(recheck)
    || recheck.status !== "non_live_bootstrap_signatures_reverified"
    || recheck.checkpoint !== checkpoint
    || recheck.batch_id !== expectedBatchId
    || recheck.authorization_id !== expectedAuthorizationId
    || (requireStableFileReread
      && (!STABLE_FILE_IMMEDIATE_RECHECKS.has(recheck)
        || recheck.stable_file_reread !== true
        || !SHA256.test(recheck.deployment_intent_artifact_file_sha256 ?? "")
        || !SHA256.test(recheck.reviewer_authority_genesis_sha256 ?? "")
        || !SHA256.test(
          recheck.reviewer_authority_genesis_artifact_file_sha256 ?? "",
        )
        || !SHA256.test(
          recheck.reviewer_authority_genesis_acceptance_sha256 ?? "",
        )
        || !SHA256.test(
          recheck.reviewer_authority_genesis_acceptance_artifact_file_sha256
            ?? "",
        )
        || recheck.reviewer_genesis_acceptance_cryptographically_verified
          !== true))
    || recheck.live_traffic_authorized !== false
    || recheck.mutation_performed !== false) {
    throw new Error("a branded exact immediate bootstrap recheck is required");
  }
  if (requireIndependentGenesisAnchor
    && (!CONTRACT_ANCHOR_VALIDATED_IMMEDIATE_RECHECKS.has(recheck)
      || recheck.reviewer_genesis_independently_anchored !== true
      || !SHA256.test(
        recheck.fresh_contract_deployment_receipt_sha256 ?? "",
      )
      || !SHA256.test(
        recheck.fresh_contract_deployment_receipt_artifact_file_sha256 ?? "",
      )
      || typeof recheck.execution_policy_anchor_address !== "string"
      || !/^0x(?!0{40}$)[0-9a-f]{40}$/.test(
        recheck.execution_policy_anchor_address,
      )
      || !Number.isSafeInteger(
        recheck.execution_policy_anchor_deployment_block,
      )
      || recheck.execution_policy_anchor_deployment_block < 1
      || !/^0x(?!0{64}$)[0-9a-f]{64}$/.test(
        recheck.execution_policy_anchor_deployment_block_hash ?? "",
      )
      || recheck.execution_policy_anchor_authority_commitment_read_proof
        !== FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF)) {
    throw new Error("reviewer genesis is not independently anchored");
  }
  if (requireDescriptorSetValidation
    && (!DESCRIPTOR_VALIDATED_IMMEDIATE_RECHECKS.has(recheck)
      || recheck.descriptor_set_validated !== true
      || !SHA256.test(recheck.descriptor_set_receipt_sha256 ?? "")
      || !SHA256.test(recheck.descriptor_source_receipt_sha256 ?? "")
      || !SHA256.test(recheck.descriptor_reproduction_receipt_sha256 ?? ""))) {
    throw new Error("canonical seven-CVM descriptor set is not freshly validated");
  }
  if (requireTargetAuthorityValidation
    && (!TARGET_AUTHORITY_VALIDATED_IMMEDIATE_RECHECKS.has(recheck)
      || recheck.target_authority_validated !== true
      || !SHA256.test(recheck.compatibility_receipt_sha256 ?? "")
      || !SHA256.test(
        recheck.compatibility_receipt_artifact_file_sha256 ?? "",
      )
      || !SHA256.test(
        recheck.sdk_wire_transform_staging_receipt_sha256 ?? "",
      )
      || !SHA256.test(
        recheck.sdk_wire_transform_staging_receipt_artifact_file_sha256 ?? "",
      )
      || !SHA256.test(recheck.production_target_authority_sha256 ?? "")
      || !SHA256.test(
        recheck.production_target_authority_artifact_file_sha256 ?? "",
      )
      || !SHA256.test(recheck.target_freshness_receipt_sha256 ?? ""))) {
    throw new Error("stable fresh Phala target capability evidence is not validated");
  }
  if (requireReleaseManifestSigstoreValidation
    && (!RELEASE_MANIFEST_SIGSTORE_VALIDATED_IMMEDIATE_RECHECKS.has(recheck)
      || recheck.release_manifest_sigstore_cryptographically_verified !== true
      || recheck.release_manifest_sigstore_blocker_code
        !== RELEASE_MANIFEST_SIGSTORE_BLOCKER
      || recheck.release_manifest_sigstore_blocker_status
        !== "cleared_by_this_receipt"
      || !SHA256.test(
        recheck.release_manifest_sigstore_verification_receipt_sha256 ?? "",
      )
      || !SHA256.test(
        recheck
          .release_manifest_sigstore_verification_receipt_artifact_file_sha256
          ?? "",
      )
      || !SHA256.test(recheck.release_manifest_sha256 ?? "")
      || !SHA256.test(
        recheck.release_manifest_sigstore_bundle_sha256 ?? "",
      )
      || !SHA256.test(recheck.sigstore_verified_identity_sha256 ?? ""))) {
    throw new Error(
      "production release manifest Sigstore receipt is not cryptographically validated",
    );
  }
  return recheck;
}

export function readReverifyAndCheckpointPhalaNonLiveBootstrapAuthorization({
  authorizationPath,
  bootstrapAuthorityPath,
  deploymentIntentPath,
  reviewerAuthorityGenesisPath,
  reviewerAuthorityGenesisAcceptancePath,
  compatibilityReceiptPath,
  sdkWireTransformStagingReceiptPath,
  productionTargetAuthorityPath,
  checkpoint,
  nowMs = Date.now(),
  expectedBatchId,
  expectedAuthorizationId,
  expectedTargetAuthoritySha256,
  expectedStagingReceiptSha256,
} = {}) {
  const verified = readAndVerifyPhalaNonLiveBootstrapAuthorization({
    authorizationPath,
    bootstrapAuthorityPath,
    deploymentIntentPath,
    reviewerAuthorityGenesisPath,
    reviewerAuthorityGenesisAcceptancePath,
    nowMs,
  });
  const {
    receipt,
    bootstrap_authority_evidence: bootstrapAuthorityEvidence,
    reviewer_authority_evidence: reviewerAuthorityEvidence,
  } = verified;
  const targetAuthorityEvidence = readFreshPhalaTargetAuthorityEvidence({
    compatibilityReceiptPath,
    sdkWireTransformStagingReceiptPath,
    productionTargetAuthorityPath,
    bootstrapAuthority: bootstrapAuthorityEvidence,
    checkpoint,
    nowMs,
  });
  const recheck = assertFreshPhalaNonLiveBootstrapAuthorizationReceipt({
    receipt,
    checkpoint,
    nowMs,
    expectedBatchId,
    expectedAuthorizationId,
    expectedTargetAuthoritySha256,
    expectedStagingReceiptSha256,
  });
  const stableRecheck = Object.freeze({
    ...recheck,
    stable_file_reread: true,
    deployment_intent_artifact_file_sha256:
      reviewerAuthorityEvidence.deployment_intent_artifact_file_sha256,
    reviewer_authority_genesis_sha256:
      reviewerAuthorityEvidence.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_artifact_file_sha256:
      reviewerAuthorityEvidence.reviewer_authority_genesis_artifact_file_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      reviewerAuthorityEvidence.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_genesis_acceptance_artifact_file_sha256:
      reviewerAuthorityEvidence
        .reviewer_authority_genesis_acceptance_artifact_file_sha256,
    reviewer_authority_current_status_epoch:
      reviewerAuthorityEvidence.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      reviewerAuthorityEvidence.reviewer_authority_current_status_sha256,
    reviewer_genesis_acceptance_cryptographically_verified:
      reviewerAuthorityEvidence
        .reviewer_genesis_acceptance_cryptographically_verified,
    reviewer_genesis_independently_anchored:
      reviewerAuthorityEvidence.reviewer_genesis_independently_anchored,
    target_authority_validated: true,
    compatibility_receipt_sha256:
      targetAuthorityEvidence.compatibilityReceiptSha256,
    compatibility_receipt_artifact_file_sha256:
      targetAuthorityEvidence.compatibilityReceiptArtifactFileSha256,
    sdk_wire_transform_staging_receipt_sha256:
      targetAuthorityEvidence.sdkWireTransformStagingReceiptSha256,
    sdk_wire_transform_staging_receipt_artifact_file_sha256:
      targetAuthorityEvidence
        .sdkWireTransformStagingReceiptArtifactFileSha256,
    production_target_authority_sha256:
      targetAuthorityEvidence.productionTargetAuthoritySha256,
    production_target_authority_artifact_file_sha256:
      targetAuthorityEvidence.productionTargetAuthorityArtifactFileSha256,
    target_freshness_receipt_sha256:
      targetAuthorityEvidence.freshnessReceiptSha256,
    target_authority_expires_at: targetAuthorityEvidence.targetExpiresAt,
    descriptor_set_validated: false,
  });
  VERIFIED_IMMEDIATE_RECHECKS.add(stableRecheck);
  STABLE_FILE_IMMEDIATE_RECHECKS.add(stableRecheck);
  TARGET_AUTHORITY_VALIDATED_IMMEDIATE_RECHECKS.add(stableRecheck);
  return Object.freeze({
    receipt,
    recheck: stableRecheck,
    // Preserve the exact, freshly reread public authority rather than forcing
    // later same-process release stages to reconstruct it from the deliberately
    // lossy evidence summary below.  The full value was already normalized and
    // byte-checked by readAndVerifyPhalaNonLiveBootstrapAuthorization().
    bootstrap_public_environment_authority:
      verified.bootstrap_public_environment_authority,
    bootstrap_authority_evidence: bootstrapAuthorityEvidence,
    reviewer_authority_evidence: reviewerAuthorityEvidence,
    target_authority_evidence: targetAuthorityEvidence,
  });
}

export async function readReverifyDescriptorSetAndCheckpointPhalaBootstrap({
  repositoryRoot,
  releaseDirectory,
  imageReleaseManifestPath,
  imageReleaseSigstoreBundlePath,
  imageReleaseSigstoreVerificationReceiptPath,
  authorizationPath,
  bootstrapAuthorityPath,
  deploymentIntentPath,
  reviewerAuthorityGenesisPath,
  reviewerAuthorityGenesisAcceptancePath,
  freshContractDeploymentReceiptPath,
  compatibilityReceiptPath,
  sdkWireTransformStagingReceiptPath,
  productionTargetAuthorityPath,
  checkpoint,
  nowMs = Date.now(),
  expectedBatchId,
  expectedAuthorizationId,
  expectedTargetAuthoritySha256,
  expectedStagingReceiptSha256,
} = {}) {
  const observedCheckpointStartMs = Date.now();
  if (nowMs !== undefined
    && (!Number.isSafeInteger(nowMs)
      || Math.abs(nowMs - observedCheckpointStartMs) > 1_000)) {
    throw new Error(
      "full launch checkpoint time must come from the current process clock",
    );
  }
  const checkpointNowMs = observedCheckpointStartMs;
  const verified = readReverifyAndCheckpointPhalaNonLiveBootstrapAuthorization({
    authorizationPath,
    bootstrapAuthorityPath,
    deploymentIntentPath,
    reviewerAuthorityGenesisPath,
    reviewerAuthorityGenesisAcceptancePath,
    compatibilityReceiptPath,
    sdkWireTransformStagingReceiptPath,
    productionTargetAuthorityPath,
    checkpoint,
    nowMs: checkpointNowMs,
    expectedBatchId,
    expectedAuthorizationId,
    expectedTargetAuthoritySha256,
    expectedStagingReceiptSha256,
  });
  const expectedReleaseSha = verified.bootstrap_authority_evidence.release_sha;
  const sourceReceipt = await assertTrackedDescriptorMaterializationSources({
    repositoryRoot,
    expectedReleaseSha,
  });
  const descriptorReceipt = await validateCanonicalGeneratedCvmDescriptorSet({
    releaseDirectory,
    expectedReleaseSha,
  });
  const reproductionReceipt = await verifyExactTrackedSourceDescriptorReproduction({
    repositoryRoot,
    releaseDirectory,
    expectedReleaseSha,
  });
  const sigstoreEvidence = await readFreshReleaseManifestSigstoreEvidence({
    releaseDirectory,
    imageReleaseManifestPath,
    imageReleaseSigstoreBundlePath,
    imageReleaseSigstoreVerificationReceiptPath,
    bootstrapAuthorityEvidence: verified.bootstrap_authority_evidence,
  });
  const contractAnchorEvidence = readAndValidateFreshContractDeploymentAnchorEvidence({
    freshContractDeploymentReceiptPath,
    bootstrapAuthorityEvidence: verified.bootstrap_authority_evidence,
    reviewerAuthorityEvidence: verified.reviewer_authority_evidence,
    expectedTinkerAccountBindingCeremonyReceiptSha256:
      descriptorReceipt.tinker_account_binding_ceremony_receipt_sha256,
  });
  const finalVerified = readReverifyAndCheckpointPhalaNonLiveBootstrapAuthorization({
    authorizationPath,
    bootstrapAuthorityPath,
    deploymentIntentPath,
    reviewerAuthorityGenesisPath,
    reviewerAuthorityGenesisAcceptancePath,
    compatibilityReceiptPath,
    sdkWireTransformStagingReceiptPath,
    productionTargetAuthorityPath,
    checkpoint,
    nowMs: Date.now(),
    expectedBatchId,
    expectedAuthorizationId,
    expectedTargetAuthoritySha256,
    expectedStagingReceiptSha256,
  });
  if (finalVerified.receipt.authorization_id !== verified.receipt.authorization_id
    || finalVerified.receipt.signed_payload_sha256
      !== verified.receipt.signed_payload_sha256
    || finalVerified.target_authority_evidence.productionTargetAuthoritySha256
      !== verified.target_authority_evidence.productionTargetAuthoritySha256
    || finalVerified.target_authority_evidence
      .sdkWireTransformStagingReceiptSha256
      !== verified.target_authority_evidence
        .sdkWireTransformStagingReceiptSha256) {
    throw new Error("launch authority changed during the full checkpoint");
  }
  const bootstrap = verified.bootstrap_authority_evidence;
  if (descriptorReceipt.image_manifest_sha256
      !== bootstrap.image_release_manifest_sha256
    || descriptorReceipt.image_manifest_sigstore_bundle_sha256
      !== sigstoreEvidence.releaseManifestSigstoreBundleSha256
    || descriptorReceipt.topology_sha256 !== bootstrap.topology_sha256
    || JSON.stringify(descriptorReceipt.descriptor_sha256_by_domain)
      !== JSON.stringify(bootstrap.descriptor_sha256_by_domain)
    || reproductionReceipt.generated_file_sha256["dnai-deployment-intent-core.json"]
      !== bootstrap.deployment_intent_sha256) {
    throw new Error(
      "freshly validated descriptor set does not equal the signed bootstrap subject",
    );
  }
  const recheck = Object.freeze({
    ...finalVerified.recheck,
    reviewer_genesis_independently_anchored: true,
    fresh_contract_deployment_receipt_sha256:
      contractAnchorEvidence.freshContractDeploymentReceiptSha256,
    fresh_contract_deployment_receipt_artifact_file_sha256:
      contractAnchorEvidence
        .freshContractDeploymentReceiptArtifactFileSha256,
    execution_policy_anchor_address:
      contractAnchorEvidence.executionPolicyAnchorAddress,
    execution_policy_anchor_deployment_block:
      contractAnchorEvidence.executionPolicyAnchorDeploymentBlock,
    execution_policy_anchor_deployment_block_hash:
      contractAnchorEvidence.executionPolicyAnchorDeploymentBlockHash,
    execution_policy_anchor_authority_commitment_read_proof:
      contractAnchorEvidence
        .executionPolicyAnchorAuthorityCommitmentReadProof,
    release_manifest_sigstore_cryptographically_verified: true,
    release_manifest_sigstore_blocker_code:
      sigstoreEvidence.blockerCode,
    release_manifest_sigstore_blocker_status:
      sigstoreEvidence.blockerStatus,
    release_manifest_sigstore_verification_receipt_sha256:
      sigstoreEvidence.releaseManifestSigstoreVerificationReceiptSha256,
    release_manifest_sigstore_verification_receipt_artifact_file_sha256:
      sigstoreEvidence
        .releaseManifestSigstoreVerificationReceiptArtifactFileSha256,
    release_manifest_sha256: sigstoreEvidence.releaseManifestSha256,
    release_manifest_sigstore_bundle_sha256:
      sigstoreEvidence.releaseManifestSigstoreBundleSha256,
    sigstore_verified_identity_sha256:
      sigstoreEvidence.verifiedIdentitySha256,
    descriptor_set_validated: true,
    descriptor_set_receipt_sha256:
      cvmReleaseDescriptorSetReceiptSha256(descriptorReceipt),
    descriptor_source_receipt_sha256: sha256Bytes(
      Buffer.from(canonicalText(sourceReceipt), "utf8"),
    ),
    descriptor_reproduction_receipt_sha256: sha256Bytes(
      Buffer.from(canonicalText(reproductionReceipt), "utf8"),
    ),
  });
  VERIFIED_IMMEDIATE_RECHECKS.add(recheck);
  STABLE_FILE_IMMEDIATE_RECHECKS.add(recheck);
  DESCRIPTOR_VALIDATED_IMMEDIATE_RECHECKS.add(recheck);
  TARGET_AUTHORITY_VALIDATED_IMMEDIATE_RECHECKS.add(recheck);
  CONTRACT_ANCHOR_VALIDATED_IMMEDIATE_RECHECKS.add(recheck);
  RELEASE_MANIFEST_SIGSTORE_VALIDATED_IMMEDIATE_RECHECKS.add(recheck);
  return Object.freeze({
    ...finalVerified,
    recheck,
    descriptor_set_receipt: descriptorReceipt,
    descriptor_source_receipt: sourceReceipt,
    descriptor_reproduction_receipt: reproductionReceipt,
    contract_anchor_evidence: contractAnchorEvidence,
    release_manifest_sigstore_evidence: sigstoreEvidence,
  });
}
