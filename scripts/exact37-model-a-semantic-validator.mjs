import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";

import {
  canonicalArtifactSha256,
  validateDeploymentIntentCore,
} from "./operator-policy-packet-core.mjs";
import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  verifyIndependentEip191PersonalSignature,
} from "./release-authority-signature-verifier-core.mjs";
import {
  reconstructPersistedReleaseReviewerAuthorityForHistoricalActivation,
} from "./release-reviewer-authority-core.mjs";
import {
  freshContractDeploymentReceiptDigest,
  normalizeFreshContractDeploymentReceipt,
} from "./cvm-launch-intent-core.mjs";
import {
  bootstrapPublicEnvironmentAuthorityDigest,
  normalizeBootstrapPublicEnvironmentAuthority,
} from "./phala-bootstrap-public-environment-authority-core.mjs";
import {
  phalaNonLiveBootstrapSigningDigest,
  reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch,
} from "./phala-nonlive-bootstrap-authorization-core.mjs";
import {
  normalizeCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-executor-state-core.mjs";
import {
  reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency,
} from "./phala-seven-cvm-launch-completion-core.mjs";
import {
  assertPersistedPreCeremonyRuntimeAuthority,
  normalizePreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
  projectPreCeremonyRuntimeAuthorityHistoricalLaunchBinding,
} from "./pre-ceremony-runtime-authority-core.mjs";
import {
  createPhalaSevenCvmHistoricalTranscriptFileSet,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";
import {
  normalizeReleaseManifestSigstoreVerificationReceipt,
  releaseManifestSigstoreVerificationReceiptSha256,
  cvmReleaseDescriptorSetReceiptSha256,
  normalizeCvmReleaseDescriptorSetReceipt,
} from "./release-manifest-descriptor-historical-core.mjs";
import {
  assertHistoricallyVerifiedComputeWorkloadActivationObservation,
  computeWorkloadActivationObservationSha256,
  computeWorkloadBrowserBindingSha256,
  projectComputeWorkloadBrowserBindingFromHistoricalObservation,
} from "./compute-workload-activation-observation-core.mjs";
import {
  normalizePhalaPostMeasurementActivationExecutionReceipt,
  phalaPostMeasurementActivationExecutionReceiptSha256,
} from "./phala-post-measurement-activation-receipt-core.mjs";
import {
  historicalCeremonyAuthorizationCoreSha256,
  historicalLiveActivationAuthoritySha256,
  historicalLiveActivationReviewSubjectSha256,
  normalizeHistoricalCeremonyAuthorizationCore,
  normalizeHistoricalLiveActivationAuthority,
  projectHistoricalCeremonyExpectedContext,
  projectHistoricalLiveActivationExpectedContext,
  projectHistoricalLiveActivationFrontendBinding,
} from "./release-authority-historical-core.mjs";
import { normalizeFinalReleaseAuthorityCore } from "./execution-policy-release-core.mjs";
import {
  FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS,
  assertHistoricalLiveActivationFinalCvmsMatchCandidate,
  assertFrontendBuildCandidateLineage,
  createFrontendBuildPreDPrivateInputs,
  frontendBuildCandidateReceiptSha256,
  frontendBuildInputManifestSha256,
  frontendBuildProjectedEnvSha256,
  historicalFinalReleaseAuthorityCoreSha256,
  historicalLiveReleaseCandidatePrebuildProjectionSha256,
  normalizeFrontendBuildInputManifest,
  normalizeHistoricalFrontendReleaseCandidate,
  validateHistoricalFinalReleaseAuthorityCoreBinding,
} from "../web/scripts/frontend-release-historical-core.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_EVIDENCE_CONTEXT_SCHEMA,
  reconstructPhalaSevenCvmHistoricalEvidenceSet,
} from "./phala-seven-cvm-historical-evidence-core.mjs";
import {
  projectExternalFiveEvidenceFilesFromExact37ByKey,
  validateExternalFiveHistoricalEvidenceBoundary,
} from "../web/scripts/external-five-historical-evidence-core.mjs";
import {
  recoverIndependentEip191PersonalSignerFromRawDigest,
} from "../web/scripts/independent-eip191-replay-core.mjs";
import {
  createExactModelADependencyGraph,
  exactModelADependencyGraphSha256,
} from "./exact-model-a-dependency-graph.mjs";

export const EXACT37_MODEL_A_INPUT_FLAGS = Object.freeze([
  "--release", "--release-core", "--runtime-authority-dependency",
  "--deployment-intent", "--contract-receipt",
  "--reviewer-authority-genesis", "--reviewer-authority-genesis-acceptance",
  "--bootstrap-authority", "--bootstrap-authorization",
  "--bootstrap-authorization-receipt", "--seven-cvm-launch-completion-receipt",
  "--main-runtime-qvl-challenge", "--main-runtime-independent-tdx-verdict",
  "--diligence-qvl-identity-request", "--diligence-qvl-identity-response",
  "--arena-qvl-identity-request", "--arena-qvl-identity-response",
  "--anchor-writer-qvl-identity-request", "--anchor-writer-qvl-identity-response",
  "--compute-workload-qvl-identity-request", "--compute-workload-qvl-identity-response",
  "--compute-metering-qvl-identity-request", "--compute-metering-qvl-identity-response",
  "--independent-metering-qvl-challenge",
  "--independent-metering-independent-tdx-verdict",
  "--image-release-sigstore-verification-receipt",
  "--cvm-descriptor-set-receipt", "--phala-executor-final-state",
  "--ceremony-authorization", "--ledger", "--artifact-evidence",
  "--arena-evidence", "--anchor-writer-evidence", "--email-oracle-evidence",
  "--live-activation-authority", "--compute-workload-activation-observation",
  "--frontend-build-candidate-receipt",
]);

export const EXACT37_MODEL_A_HISTORICAL_STATUS =
  "historical_authority_validated_live_chain_and_external_evidence_pending";
export const EXACT37_MODEL_A_INCOMPLETE_REASON =
  "Model-A exact-37 remains sealed pending current Base Sepolia state proofs, authenticated KMS/restart continuity, and a positive real 37-file known-answer vector";

const RAW14_FLAGS = Object.freeze(EXACT37_MODEL_A_INPUT_FLAGS.slice(11, 25));
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const REQUIRED_REPRODUCTION_FIELDS = Object.freeze([
  "frontendBuildSha256", "inputManifest", "serializedEnv",
]);

function fail(message) {
  throw new TypeError(message);
}

function exact(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must contain exactly the frozen fields`);
  }
  const prototype = Object.getPrototypeOf(value);
  const keys = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if ((prototype !== Object.prototype && prototype !== null)
    || keys.some((key) => typeof key !== "string")
    || JSON.stringify(keys.sort()) !== JSON.stringify([...fields].sort())
    || Object.values(descriptors).some((descriptor) => (
      !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true
    ))) {
    fail(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function exactInputEntry(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must contain exactly the frozen fields`);
  }
  const prototype = Object.getPrototypeOf(value);
  const keys = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if ((prototype !== Object.prototype && prototype !== null)
    || keys.some((key) => typeof key !== "string")
    || JSON.stringify(keys.sort()) !== JSON.stringify([...fields].sort())) {
    fail(`${label} must contain exactly the frozen fields`);
  }
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true) {
      fail(`${label} must contain exactly the frozen fields`);
    }
    // The stable file loader intentionally exposes a defensive-copy `bytes`
    // accessor. Historical semantic validation never executes it: immutable
    // canonical UTF-8 text is the single source snapshot instead.
    if (field === "bytes") {
      const isData = Object.hasOwn(descriptor, "value");
      const isReadOnlyAccessor = typeof descriptor.get === "function"
        && descriptor.set === undefined;
      if (!isData && !isReadOnlyAccessor) {
        fail(`${label} bytes transport descriptor is invalid`);
      }
    } else if (!Object.hasOwn(descriptor, "value")) {
      fail(`${label} must not contain accessors outside the ignored bytes transport`);
    }
  }
  return value;
}

function assertDenseDataArray(value, expectedLength, label) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
    || value.length !== expectedLength) {
    fail(`${label} must be one exact dense array`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")
    || keys.length !== expectedLength + 1
    || !Object.hasOwn(descriptors, "length")) {
    fail(`${label} must be one exact dense array`);
  }
  for (let index = 0; index < expectedLength; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || descriptor.enumerable !== true
      || !Object.hasOwn(descriptor, "value")) {
      fail(`${label} must be one exact dense array`);
    }
  }
  return value;
}

function digest(value, label) {
  if (!SHA256.test(String(value || ""))) fail(`${label} is not a nonzero SHA-256`);
  return value;
}

function rawSha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function keyForFlag(flag) {
  return flag.slice(2).replace(/-([a-z])/g, (_match, letter) => letter.toUpperCase());
}

export function normalizeExact37ModelAInputSet(value) {
  const parsed = exact(
    value,
    ["artifactPaths", "byFlag", "byKey", "entries", "totalBytes"],
    "exact-37 Model-A stable input set",
  );
  const expectedKeys = EXACT37_MODEL_A_INPUT_FLAGS.map(keyForFlag);
  const sourceEntries = assertDenseDataArray(
    parsed.entries,
    EXACT37_MODEL_A_INPUT_FLAGS.length,
    "exact-37 Model-A input entries",
  );
  const byFlag = exact(
    parsed.byFlag,
    EXACT37_MODEL_A_INPUT_FLAGS,
    "exact-37 Model-A by-flag projection",
  );
  const byKey = exact(
    parsed.byKey,
    expectedKeys,
    "exact-37 Model-A by-key projection",
  );
  const artifactPaths = exact(
    parsed.artifactPaths,
    ["byFlag", "byKey", "entries"],
    "exact-37 Model-A artifact paths",
  );
  const artifactPathsByFlag = exact(
    artifactPaths.byFlag,
    EXACT37_MODEL_A_INPUT_FLAGS,
    "exact-37 Model-A artifact paths by flag",
  );
  const artifactPathsByKey = exact(
    artifactPaths.byKey,
    expectedKeys,
    "exact-37 Model-A artifact paths by key",
  );
  assertDenseDataArray(
    artifactPaths.entries,
    EXACT37_MODEL_A_INPUT_FLAGS.length,
    "exact-37 Model-A artifact path entries",
  );
  const entries = sourceEntries.map((raw, index) => {
    const entry = exactInputEntry(raw, [
      "byteLength", "bytes", "filePath", "flag", "key", "metadata",
      "rawSha256", "text", "value",
    ],
      `exact-37 Model-A entry ${index}`);
    const expectedFlag = EXACT37_MODEL_A_INPUT_FLAGS[index];
    const expectedKey = keyForFlag(expectedFlag);
    const text = entry.text;
    if (entry.flag !== expectedFlag || entry.key !== expectedKey
      || typeof entry.filePath !== "string" || !entry.filePath.startsWith("/")
      || typeof text !== "string") {
      fail(`exact-37 Model-A entry ${index} must be ${expectedFlag} canonical bytes`);
    }
    // Snapshot exactly once from immutable string data. Do not read
    // `entry.bytes`, which may be a loader accessor, and do not use
    // `entry.value` as the semantic source.
    const bytes = Buffer.from(text, "utf8");
    let parsedValue;
    try {
      parsedValue = JSON.parse(text);
    } catch {
      fail(`exact-37 Model-A entry ${expectedFlag} is not valid JSON`);
    }
    assertCanonicalPlainDataGraph(parsedValue, {
      label: `exact-37 Model-A parsed ${expectedFlag}`,
    });
    assertCanonicalPlainDataGraph(entry.value, {
      label: `exact-37 Model-A carried ${expectedFlag} value`,
    });
    const canonicalText = `${JSON.stringify(parsedValue, null, 2)}\n`;
    if (canonicalText !== text
      || JSON.stringify(entry.value) !== JSON.stringify(parsedValue)
      || entry.byteLength !== bytes.length
      || rawSha256(bytes) !== entry.rawSha256) {
      fail(`exact-37 Model-A entry ${expectedFlag} bytes or digest changed`);
    }
    if (byFlag[expectedFlag] !== raw
      || byKey[expectedKey] !== raw
      || artifactPathsByFlag[expectedFlag] !== entry.filePath
      || artifactPathsByKey[expectedKey] !== entry.filePath) {
      fail(`exact-37 Model-A loader projections drifted for ${expectedFlag}`);
    }
    return Object.freeze({
      flag: expectedFlag,
      key: expectedKey,
      filePath: entry.filePath,
      byteLength: entry.byteLength,
      value: deepFreezeCanonicalPlainDataGraph(parsedValue, {
        label: `exact-37 Model-A normalized ${expectedFlag}`,
      }),
      rawSha256: digest(entry.rawSha256, `${expectedFlag} raw digest`),
    });
  });
  if (new Set(entries.map(({ rawSha256: sha }) => sha)).size !== entries.length) {
    fail("exact-37 Model-A inputs must have pairwise-distinct raw bytes");
  }
  if (parsed.totalBytes !== entries.reduce((sum, entry) => sum + entry.byteLength, 0)) {
    fail("exact-37 Model-A loader total byte count drifted");
  }
  return Object.freeze({
    entries: Object.freeze(entries),
    byKey: Object.freeze(Object.fromEntries(entries.map((entry) => [entry.key, entry]))),
  });
}

function reviewerRoleSeparation(intent) {
  return Object.freeze({
    deploymentRoleAddresses: Object.freeze([...new Set([
      intent.deploymentControl.operatorAddress,
      intent.staticContractInputs.computeCreditVault.developer,
    ])].sort()),
    deploymentRoleControllerIds: Object.freeze([
      intent.deploymentControl.controllerId,
    ]),
  });
}

function verifyHistoricalReviewSignatures({ signatures, message } = {}) {
  if (!Array.isArray(signatures) || signatures.length !== 2
    || typeof message !== "string") {
    return false;
  }
  try {
    for (const entry of signatures) {
      verifyIndependentEip191PersonalSignature({
        address: entry.address,
        message,
        signature: entry.signature,
      });
    }
    return true;
  } catch {
    return false;
  }
}

function assertReviewerStatusActiveAt(status, instantMs, label) {
  const notBeforeMs = Date.parse(status?.not_before);
  const expiresAtMs = Date.parse(status?.expires_at);
  if (!Number.isSafeInteger(instantMs)
    || !Number.isFinite(notBeforeMs) || !Number.isFinite(expiresAtMs)
    || instantMs < notBeforeMs || instantMs >= expiresAtMs) {
    fail(`${label} is outside the authenticated epoch-one reviewer window`);
  }
}

function projectRaw14HistoricalFiles(exactInputs) {
  return Object.fromEntries(RAW14_FLAGS.map((flag) => {
    const entry = exactInputs.byKey[keyForFlag(flag)];
    return [flag, {
      value: entry.value,
      sha256: entry.rawSha256,
      size: entry.byteLength,
    }];
  }));
}

function projectRaw14HistoricalEvidenceContext({
  launchReceipt,
  historicalRuntimeBinding,
  releaseCore,
  releaseCoreSha256,
  historicalTranscriptFileSetSha256,
}) {
  return {
    schema: PHALA_SEVEN_CVM_HISTORICAL_EVIDENCE_CONTEXT_SCHEMA,
    historical_runtime_binding: historicalRuntimeBinding,
    release_core_sha256: releaseCoreSha256,
    independent_metering_policy_set_hash:
      releaseCore.contracts.compute_credit_vault.metering_policy_set_hash,
    historical_transcript_file_set_sha256:
      historicalTranscriptFileSetSha256,
    launch_completed_at: launchReceipt.completed_at,
    domains: launchReceipt.domains.map((entry) => ({
      domain: entry.domain,
      machine_evidence_kind: entry.machine_evidence_kind,
      machine_evidence_sha256: entry.machine_evidence_sha256,
      machine_evidence_verified_at: entry.machine_evidence_verified_at,
      tdx_attestation_evidence_sha256:
        entry.tdx_attestation_evidence_sha256,
      tdx_attestation_verification_receipt_sha256:
        entry.tdx_attestation_verification_receipt_sha256,
      tdx_measurement_authority_sha256:
        entry.tdx_measurement_authority_sha256,
      qvl_release_policy_sha256: entry.qvl_release_policy_sha256,
      qvl_verification_receipt_sha256:
        entry.qvl_verification_receipt_sha256,
      qvl_identity_sha256: entry.qvl_identity_sha256,
      tee_identity: entry.tee_identity,
      bound_contract_address: entry.bound_contract_address,
    })),
  };
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) fail(`${label} drifted`);
}

function domainEntry(receipt, domain) {
  const entry = receipt.domains.find((item) => item.domain === domain);
  if (!entry) fail(`historical L omits ${domain}`);
  return entry;
}

function assertSignedCFinalCvmsMatchHistoricalLaunch(
  finalCvms,
  launchReceipt,
  activationExecutionReceipt,
) {
  if (!Array.isArray(finalCvms)
    || finalCvms.length !== launchReceipt.domains.length) {
    fail("signed C must carry the exact seven historical-L CVM targets");
  }
  for (let index = 0; index < launchReceipt.domains.length; index += 1) {
    const launchDomain = launchReceipt.domains[index];
    const finalCvm = finalCvms[index];
    const expectedEvidenceSha256 = launchDomain.domain === "main_runtime_cvm"
      ? activationExecutionReceipt.post_restart_evidence
        .get_cvm_attestation_observation_sha256
      : launchDomain.machine_evidence_sha256;
    if (finalCvm.cvm_key !== launchDomain.domain
      || finalCvm.app_id !== launchDomain.app_id
      || finalCvm.cvm_id !== launchDomain.cvm_id
      || finalCvm.compose_hash_sha256
        !== `sha256:${launchDomain.committed_compose_hash}`
      || finalCvm.tee_identity !== launchDomain.tee_identity
      || finalCvm.attestation_evidence_sha256 !== expectedEvidenceSha256) {
      fail(`signed C final ${launchDomain.domain} drifted from authenticated L/receipt evidence`);
    }
  }
}

function assertFrontendLineage(manifest, expected) {
  for (const [field, value] of Object.entries(expected)) {
    assertEqual(manifest.semantic_lineage[field], value, `frontend D lineage ${field}`);
  }
}

/**
 * Model-A historical authority validation.
 *
 * No filesystem, network, Date.now, current DCAP, or current QVL operation is
 * performed here. Epoch-one reviewer validity is evaluated only against the
 * caller's explicit validationTimeMs; exact37 has no status-history input and
 * therefore rejects all later epochs. The five external files have their
 * historical schemas, signatures, and B/R/O/C/D lineage replayed, while their
 * current chain, KMS, and restart claims remain a downstream proof boundary.
 */
export async function validateExact37ModelAHistoricalAuthority({
  inputs,
  validationTimeMs,
  reviewerStatusHistory,
  frontendBuildReproduction,
} = {}) {
  // Keep the standalone draft sealed as well as the CLI. Historical replay is
  // not current Base Sepolia consensus, KMS-registration, restart-continuity,
  // or positive real-input known-answer evidence, and must never be mistaken
  // for deployment or live-traffic authority.
  fail(EXACT37_MODEL_A_INCOMPLETE_REASON);

  if (!Number.isSafeInteger(validationTimeMs) || validationTimeMs < 1
    || validationTimeMs > 4_102_444_800_000
    || validationTimeMs % 1_000 !== 0) {
    fail("Model-A validation requires an explicit bounded whole-second validationTimeMs");
  }
  if (!Array.isArray(reviewerStatusHistory)
    || reviewerStatusHistory.length !== 0) {
    fail("Model-A exact-37 requires the explicit empty epoch-1 reviewer history");
  }
  const reproduction = exact(
    frontendBuildReproduction,
    REQUIRED_REPRODUCTION_FIELDS,
    "frontend D reproduction",
  );
  const exactInputs = normalizeExact37ModelAInputSet(inputs);
  const input = Object.fromEntries(
    Object.entries(exactInputs.byKey).map(([key, entry]) => [key, entry.value]),
  );
  const releaseCore = normalizeFinalReleaseAuthorityCore(input.releaseCore);
  const coreSha256 = historicalFinalReleaseAuthorityCoreSha256(releaseCore);

  const intentValidation = validateDeploymentIntentCore(input.deploymentIntent);
  if (!intentValidation.ok) fail("deployment intent is not the exact valid v6 artifact");
  const intent = input.deploymentIntent;
  const intentSha256 = canonicalArtifactSha256(intent);
  const roleSeparation = reviewerRoleSeparation(intent);
  const carriedAcceptance = input.reviewerAuthorityGenesisAcceptance;
  const carriedStatus = carriedAcceptance.reviewer_authority_current_status;
  const reviewerReconstruction =
    reconstructPersistedReleaseReviewerAuthorityForHistoricalActivation({
      reviewerGenesis: input.reviewerAuthorityGenesis,
      reviewerGenesisAcceptance: carriedAcceptance,
      expectedReleaseSha: intent.release.releaseSha,
      expectedChainId: intent.network.chainId,
      expectedReviewerGenesisSha256:
        carriedAcceptance.reviewer_authority_genesis_sha256,
      expectedReviewerGenesisAcceptanceSha256:
        intent.release.reviewerAuthorityGenesisAcceptanceSha256,
      expectedCurrentStatusSha256:
        intent.release.reviewerAuthorityCurrentStatusSha256,
      expectedStatusGuardianRootHash:
        input.reviewerAuthorityGenesis.status_guardian_root_hash,
      expectedStatusGuardianSetSha256:
        input.reviewerAuthorityGenesis.status_guardian_set_sha256,
      expectedReviewerRootHash: carriedStatus.reviewer_root_hash,
      expectedReviewerSetSha256: carriedStatus.reviewer_set_sha256,
      ...roleSeparation,
      validationTime: new Date(validationTimeMs).toISOString().replace(".000Z", "Z"),
    });
  assertEqual(
    intent.release.reviewerAuthorityCurrentStatusEpoch,
    reviewerReconstruction.reviewer_status_epoch,
    "deployment intent reviewer current-status epoch",
  );
  const genesis = reviewerReconstruction.reviewer_authority_genesis;
  const acceptance = reviewerReconstruction
    .reviewer_authority_genesis_acceptance;
  const genesisSha256 = reviewerReconstruction
    .reviewer_authority_genesis_sha256;
  const acceptanceSha256 = reviewerReconstruction
    .reviewer_authority_genesis_acceptance_sha256;
  assertEqual(
    intent.release.reviewerAuthorityGenesisAcceptanceSha256,
    acceptanceSha256,
    "deployment intent reviewer acceptance",
  );
  const activeReviewerAuthority = reviewerReconstruction.reviewer_authority;
  const reviewerAuthority = {
    reviewer_authority_genesis_sha256: genesisSha256,
    reviewer_authority_genesis_acceptance_sha256: acceptanceSha256,
    reviewer_authority_current_status_not_before: carriedStatus.not_before,
    reviewer_authority_current_status_expires_at: carriedStatus.expires_at,
    ...activeReviewerAuthority,
  };
  const contract = normalizeFreshContractDeploymentReceipt(input.contractReceipt, {
    expectedDeploymentIntentSha256: intentSha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256: acceptanceSha256,
  });
  const contractSha256 = `sha256:${freshContractDeploymentReceiptDigest(contract, {
    expectedDeploymentIntentSha256: intentSha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256: acceptanceSha256,
  })}`;
  const bootstrapAuthority = normalizeBootstrapPublicEnvironmentAuthority(
    input.bootstrapAuthority,
  );
  const bootstrapAuthoritySha256 = bootstrapPublicEnvironmentAuthorityDigest(
    bootstrapAuthority,
  );
  const runtimeAuthority = normalizePreCeremonyRuntimeAuthority(
    input.runtimeAuthorityDependency,
  );
  const runtimeAuthoritySha256 = preCeremonyRuntimeAuthoritySha256(runtimeAuthority);
  const executor = normalizeCompletedPhalaExecutorState(input.phalaExecutorFinalState);
  const executorSha256 = phalaExecutorStateDigest(executor);
  const launchCompletedAt = input.sevenCvmLaunchCompletionReceipt?.completed_at;
  assertReviewerStatusActiveAt(
    reviewerReconstruction.reviewer_authority_current_status,
    Date.parse(input.bootstrapAuthorization?.issued_at),
    "signed A issuance time",
  );
  const signedA = reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch({
    authorization: input.bootstrapAuthorization,
    bootstrapAuthority,
    reviewerAuthority: activeReviewerAuthority,
    persistedReceipt: input.bootstrapAuthorizationReceipt,
    launchCompletedAt,
    authorizationFileIdentity: {
      sha256: exactInputs.byKey.bootstrapAuthorization.rawSha256,
      size: exactInputs.byKey.bootstrapAuthorization.byteLength,
    },
    bootstrapAuthorityFileIdentity: {
      sha256: exactInputs.byKey.bootstrapAuthority.rawSha256,
      size: exactInputs.byKey.bootstrapAuthority.byteLength,
    },
  });
  const signedAReceipt = signedA.receipt;
  const signedAReceiptSha256 = signedA.receipt_sha256;
  const historicalRuntimeBinding =
    projectPreCeremonyRuntimeAuthorityHistoricalLaunchBinding(runtimeAuthority);
  const launch = reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency({
    persistedReceipt: input.sevenCvmLaunchCompletionReceipt,
    persistedExecutorFinalState: executor,
    historicalPreCeremonyRuntimeBinding: historicalRuntimeBinding,
    historicalBootstrapAuthorizationBinding:
      signedA.historical_bootstrap_authorization_binding,
  });
  assertEqual(launch.executor_final_state_sha256, executorSha256, "historical L executor");
  const launchReceipt = launch.receipt;
  const launchSha256 = launch.receipt_sha256;

  const transcriptFileIdentityByFlag = Object.fromEntries(RAW14_FLAGS.map((flag) => {
    const entry = exactInputs.entries[EXACT37_MODEL_A_INPUT_FLAGS.indexOf(flag)];
    return [flag, Object.freeze({
      sha256: entry.rawSha256,
      size: entry.byteLength,
    })];
  }));
  const historicalTranscript = createPhalaSevenCvmHistoricalTranscriptFileSet(
    transcriptFileIdentityByFlag,
  );
  const transcriptSha256 = phalaSevenCvmHistoricalTranscriptFileSetSha256(
    historicalTranscript,
  );
  const stageOneSignedAtMs = Date.parse(input.ceremonyAuthorization?.review?.signed_at);
  const stageOneExpiresAtMs = Date.parse(input.ceremonyAuthorization?.review?.expires_at);
  assertReviewerStatusActiveAt(
    reviewerReconstruction.reviewer_authority_current_status,
    stageOneSignedAtMs,
    "signed B review time",
  );
  const persistedRuntimeAuthority = assertPersistedPreCeremonyRuntimeAuthority({
    persistedAuthority: runtimeAuthority,
    reconstructedLaunchCompletionReceiptSha256: launchSha256,
    reconstructedHistoricalTranscriptFileSet: historicalTranscript,
    signedAtMs: stageOneSignedAtMs,
    reviewExpiresAtMs: stageOneExpiresAtMs,
  });
  const stageOneExpectedContext = projectHistoricalCeremonyExpectedContext({
    runtimeAuthority: persistedRuntimeAuthority,
    runtimeAuthoritySha256,
    freshContractDeploymentReceiptSha256: contractSha256,
    signedABootstrapAuthorizationReceiptSha256: signedAReceiptSha256,
    toolchain: intent.release.toolchain,
  });
  const stageOneOptions = {
    expectedContext: stageOneExpectedContext,
    reviewerAuthority,
    expectedSignatureVerifier: PINNED_CAST_SIGNATURE_VERIFIER,
    verifyReviewSignatures: verifyHistoricalReviewSignatures,
  };
  const stageOne = normalizeHistoricalCeremonyAuthorizationCore(
    input.ceremonyAuthorization,
    stageOneOptions,
  );
  const stageOneSha256 = historicalCeremonyAuthorizationCoreSha256(
    stageOne,
    stageOneOptions,
  );

  const sigstore = normalizeReleaseManifestSigstoreVerificationReceipt(
    input.imageReleaseSigstoreVerificationReceipt,
  );
  const sigstoreSha256 = releaseManifestSigstoreVerificationReceiptSha256(sigstore);
  const descriptors = normalizeCvmReleaseDescriptorSetReceipt(
    input.cvmDescriptorSetReceipt,
  );
  const descriptorSetSha256 = cvmReleaseDescriptorSetReceiptSha256(descriptors);
  for (const artifact of [bootstrapAuthority, signedAReceipt, launchReceipt, sigstore, descriptors]) {
    assertEqual(artifact.release_sha, runtimeAuthority.release_sha, "historical release SHA");
  }
  assertEqual(bootstrapAuthority.deployment_intent_sha256, intentSha256,
    "bootstrap deployment intent");
  assertEqual(bootstrapAuthority.fresh_contract_deployment_receipt_sha256,
    contractSha256, "bootstrap contract receipt");
  assertEqual(bootstrapAuthority.image_release_sigstore_verification_receipt_sha256,
    sigstoreSha256, "bootstrap Sigstore receipt");
  assertEqual(signedAReceipt.bootstrap_public_environment_authority_sha256,
    bootstrapAuthoritySha256, "signed A bootstrap authority");
  assertEqual(signedAReceipt.fresh_contract_deployment_receipt_sha256,
    contractSha256, "signed A contract receipt");
  assertEqual(signedAReceipt.image_release_sigstore_verification_receipt_sha256,
    sigstoreSha256, "signed A Sigstore receipt");
  assertEqual(launchReceipt.reviewer_authority_genesis_acceptance_sha256,
    acceptanceSha256, "historical L reviewer acceptance");
  assertEqual(launchReceipt.fresh_contract_deployment_receipt_sha256,
    contractSha256, "historical L contract receipt");
  assertEqual(launchReceipt.nonlive_bootstrap_authorization_receipt_sha256,
    signedAReceiptSha256, "historical L signed A receipt");
  assertEqual(launchReceipt.image_release_sigstore_verification_receipt_sha256,
    sigstoreSha256, "historical L Sigstore receipt");
  assertEqual(launchReceipt.descriptor_set_receipt_sha256,
    descriptorSetSha256, "historical L descriptor-set receipt");
  assertEqual(launchReceipt.executor_final_state_sha256, executorSha256,
    "historical L executor state");
  assertEqual(runtimeAuthority.historical_transcript_file_set_sha256,
    transcriptSha256, "persisted R historical transcript");
  assertEqual(runtimeAuthority.seven_cvm_launch_completion_receipt_sha256,
    launchSha256, "persisted R historical L");
  assertEqual(sigstore.release_manifest_sha256, descriptors.image_manifest_sha256,
    "Sigstore/descriptor image manifest");
  assertEqual(sigstore.release_manifest_sigstore_bundle_sha256,
    descriptors.image_manifest_sigstore_bundle_sha256,
    "Sigstore/descriptor bundle");
  assertEqual(bootstrapAuthority.image_release_manifest_sha256,
    descriptors.image_manifest_sha256, "bootstrap/descriptor image manifest");
  assertEqual(bootstrapAuthority.topology_sha256, descriptors.topology_sha256,
    "bootstrap/descriptor topology");
  for (const binding of bootstrapAuthority.domains) {
    assertEqual(binding.descriptor_sha256,
      descriptors.descriptor_sha256_by_domain[binding.domain],
      `bootstrap/descriptor ${binding.domain}`);
  }

  const historicalMachineEvidence = reconstructPhalaSevenCvmHistoricalEvidenceSet({
    rawArtifacts: projectRaw14HistoricalFiles(exactInputs),
    historicalEvidenceContext: projectRaw14HistoricalEvidenceContext({
      launchReceipt,
      historicalRuntimeBinding,
      releaseCore,
      releaseCoreSha256: coreSha256,
      historicalTranscriptFileSetSha256: transcriptSha256,
    }),
    recoverPersonalSigner: recoverIndependentEip191PersonalSignerFromRawDigest,
  });
  assertEqual(
    historicalMachineEvidence.seven_cvm_verified_evidence_set_sha256,
    launchReceipt.machine_verifier_evidence_set_sha256,
    "raw14 historical machine evidence set",
  );

  const stageTwoSignedAtMs = Date.parse(input.liveActivationAuthority?.review?.signed_at);
  assertReviewerStatusActiveAt(
    reviewerReconstruction.reviewer_authority_current_status,
    stageTwoSignedAtMs,
    "signed C review time",
  );
  const main = domainEntry(launchReceipt, "main_runtime_cvm");
  const computeQvl = domainEntry(launchReceipt, "compute_workload_qvl_cvm");
  const reconstructedMain = historicalMachineEvidence.evidence_set.domains.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  if (!reconstructedMain) {
    fail("raw14 historical evidence omits the main-runtime projection");
  }
  assertEqual(
    reconstructedMain.evidence_sha256,
    main.machine_evidence_sha256,
    "raw14/main-runtime historical evidence",
  );
  assertEqual(
    runtimeAuthority.post_measurement_activation_plan.runtime_commitments
      .TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256,
    main.machine_evidence_sha256,
    "persisted R activation-plan main-runtime evidence",
  );
  const bootstrapMain = bootstrapAuthority.domains.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  const ceremonyNonce = bootstrapMain?.values
    ?.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE;
  if (typeof ceremonyNonce !== "string") {
    fail("bootstrap main-runtime authority omits the compute ceremony nonce");
  }
  assertEqual(
    ceremonyNonce,
    runtimeAuthority.post_measurement_activation_plan.runtime_commitments
      .TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE,
    "bootstrap/R activation-plan ceremony nonce",
  );
  const activationExecutionReceipt =
    normalizePhalaPostMeasurementActivationExecutionReceipt(
      input.liveActivationAuthority?.post_ceremony_evidence
        ?.post_measurement_activation_execution_receipt,
    );
  const activationExecutionReceiptSha256 =
    phalaPostMeasurementActivationExecutionReceiptSha256(
      activationExecutionReceipt,
    );
  const computeVault = contract.contracts.find(
    ({ name }) => name === "ComputeCreditVault",
  );
  if (!computeVault) fail("fresh contract receipt omits ComputeCreditVault");
  const derivedOExpectations = {
    releaseSha: runtimeAuthority.release_sha,
    deploymentIntentSha256: intentSha256,
    releaseVerificationAuthoritySha256:
      runtimeAuthority.release_verification_authority_sha256,
    ceremonyNonce,
    qvlMeasurementPolicySetSha256:
      signedAReceipt.qvl_measurement_policy_set_sha256,
    historicalTranscriptFileSetSha256: transcriptSha256,
    freshContractDeploymentReceiptSha256: contractSha256,
    nonliveBootstrapAuthorizationReceiptSha256: signedAReceiptSha256,
    sevenCvmLaunchCompletionReceiptSha256: launchSha256,
    preCeremonyRuntimeAuthoritySha256: runtimeAuthoritySha256,
    postMeasurementActivationPlanSha256:
      runtimeAuthority.post_measurement_activation_plan_sha256,
    postMeasurementActivationExecutionReceiptSha256:
      activationExecutionReceiptSha256,
    ceremonyAuthorizationSha256: stageOneSha256,
    mainRuntimeAppId: main.app_id,
    mainRuntimeCvmId: main.cvm_id,
    mainRuntimeComposeHash: main.committed_compose_hash,
    mainRuntimeOsImageHash: main.os_image_hash,
    mainRuntimeDescriptorSha256: main.descriptor_sha256,
    mainRuntimePostureReceiptSha256:
      main.production_posture_verification_receipt_sha256,
    mainRuntimeTeeIdentity: main.tee_identity,
    mainRuntimeEvidenceSha256: main.machine_evidence_sha256,
    computeWorkloadQvlAppId: computeQvl.app_id,
    computeWorkloadQvlCvmId: computeQvl.cvm_id,
    computeWorkloadQvlComposeHash: computeQvl.committed_compose_hash,
    computeWorkloadQvlOsImageHash: computeQvl.os_image_hash,
    computeWorkloadQvlVerifierAddress: computeQvl.tee_identity,
    computeWorkloadQvlReleasePolicySha256:
      computeQvl.qvl_release_policy_sha256,
    computeWorkloadQvlMeasurementPolicySha256:
      computeQvl.tdx_measurement_authority_sha256,
    computeWorkloadQvlIdentityEvidenceSha256: computeQvl.machine_evidence_sha256,
    computeVaultAddress: computeVault.address,
    computeVaultRuntimeCodeHash: computeVault.runtime_code_hash,
  };
  const historicalOReplay =
    assertHistoricallyVerifiedComputeWorkloadActivationObservation({
      persistedObservation: input.computeWorkloadActivationObservation,
      expected: derivedOExpectations,
      authorizedAtMs: stageTwoSignedAtMs,
    });
  const historicalO = historicalOReplay.observation;
  const observationSha256 = computeWorkloadActivationObservationSha256(historicalO);
  const browserBinding =
    projectComputeWorkloadBrowserBindingFromHistoricalObservation(historicalOReplay);
  const browserBindingSha256 = computeWorkloadBrowserBindingSha256(browserBinding);

  const normalizedManifest = normalizeFrontendBuildInputManifest(
    reproduction.inputManifest,
  );
  const expectedPreDInputs = createFrontendBuildPreDPrivateInputs({
    liveCandidatePrebuildProjectionSha256:
      historicalLiveReleaseCandidatePrebuildProjectionSha256(input.release),
    rawSha256ByFlag: Object.fromEntries(
      FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS.map((flag) => {
        const entry = exactInputs.entries[EXACT37_MODEL_A_INPUT_FLAGS.indexOf(flag)];
        return [flag, entry.rawSha256];
      }),
    ),
  });
  if (JSON.stringify(normalizedManifest.pre_D_private_inputs)
      !== JSON.stringify(expectedPreDInputs)) {
    fail("frontend D manifest does not commit the exact acyclic 35-input projection");
  }
  const bootstrapAuthorizationSha256 = phalaNonLiveBootstrapSigningDigest(
    input.bootstrapAuthorization,
    { bootstrapAuthority },
  );
  const expectedFrontendLineage = {
    release_core_sha256: coreSha256,
    deployment_intent_sha256: intentSha256,
    fresh_contract_deployment_receipt_sha256: contractSha256,
    reviewer_authority_genesis_sha256: genesisSha256,
    reviewer_authority_genesis_acceptance_sha256: acceptanceSha256,
    bootstrap_authority_sha256: bootstrapAuthoritySha256,
    bootstrap_authorization_sha256: bootstrapAuthorizationSha256,
    bootstrap_authorization_receipt_sha256: signedAReceiptSha256,
    seven_cvm_launch_completion_receipt_sha256: launchSha256,
    historical_transcript_file_set_sha256: transcriptSha256,
    qvl_measurement_policy_set_sha256:
      historicalO.lineage.qvl_measurement_policy_set_sha256,
    runtime_authority_dependency_sha256: runtimeAuthoritySha256,
    ceremony_authorization_sha256: stageOneSha256,
    compute_workload_activation_observation_sha256: observationSha256,
  };
  assertFrontendLineage(normalizedManifest, expectedFrontendLineage);
  const frontendBuildSha256 = digest(
    reproduction.frontendBuildSha256,
    "frontend reproduction dist-manifest digest",
  );
  const authorityBinding = {
    deploymentIntentSha256: intentSha256,
    reviewerAuthorityGenesisAcceptanceSha256: acceptanceSha256,
    ceremonyAuthorizationSha256: stageOneSha256,
    runtimeAuthorityDependencySha256: runtimeAuthoritySha256,
    computeWorkloadActivationObservationSha256: observationSha256,
    frontendBuildSha256,
  };
  const buildReceipt = assertFrontendBuildCandidateLineage({
    receipt: input.frontendBuildCandidateReceipt,
    serializedEnv: reproduction.serializedEnv,
    inputManifest: normalizedManifest,
    authorityBinding,
  });
  const buildReceiptSha256 = frontendBuildCandidateReceiptSha256(buildReceipt);
  const releaseEnvSha256 = frontendBuildProjectedEnvSha256(
    reproduction.serializedEnv,
  );

  const stageTwoExpectedContext = projectHistoricalLiveActivationExpectedContext({
    runtimeAuthority: persistedRuntimeAuthority,
    runtimeAuthoritySha256,
    launchCompletionReceipt: launchReceipt,
    launchCompletionReceiptSha256: launchSha256,
    releaseVerificationAuthority: launch.release_verification_authority,
    releaseVerificationAuthoritySha256:
      launch.release_verification_authority_sha256,
  });
  const stageTwoOptions = {
    ceremonyAuthorization: stageOne,
    ceremonyAuthorizationOptions: stageOneOptions,
    expectedContext: stageTwoExpectedContext,
    reviewerAuthority,
    expectedSignatureVerifier: PINNED_CAST_SIGNATURE_VERIFIER,
    verifyReviewSignatures: verifyHistoricalReviewSignatures,
  };
  const stageTwo = normalizeHistoricalLiveActivationAuthority(
    input.liveActivationAuthority,
    stageTwoOptions,
  );
  const stageTwoSha256 = historicalLiveActivationAuthoritySha256(
    stageTwo,
    stageTwoOptions,
  );
  const post = stageTwo.post_ceremony_evidence;
  assertSignedCFinalCvmsMatchHistoricalLaunch(
    post.final_cvms,
    launchReceipt,
    activationExecutionReceipt,
  );
  assertEqual(post.compute_workload_activation_observation_sha256,
    observationSha256, "signed C historical O");
  if (JSON.stringify(post.compute_workload_browser_binding)
      !== JSON.stringify(browserBinding)) {
    fail("signed C browser binding differs from historical O");
  }
  assertEqual(computeWorkloadBrowserBindingSha256(post.compute_workload_browser_binding),
    browserBindingSha256, "signed C browser binding digest");
  assertEqual(post.frontend_release_env_sha256, releaseEnvSha256,
    "signed C frontend environment");
  assertEqual(post.frontend_build_candidate_receipt_sha256, buildReceiptSha256,
    "signed C frontend D receipt");
  assertEqual(post.frontend_build_sha256, frontendBuildSha256,
    "signed C frontend dist manifest");
  assertEqual(buildReceipt.release_env_sha256, releaseEnvSha256,
    "frontend D environment");
  assertEqual(buildReceipt.frontend_build_sha256, frontendBuildSha256,
    "frontend D dist manifest");

  const candidate = normalizeHistoricalFrontendReleaseCandidate(input.release, {
    authorityStage: "live",
  });
  assertEqual(candidate.release_sha, runtimeAuthority.release_sha,
    "final candidate release");
  assertEqual(candidate.deployment_intent_sha256, intentSha256,
    "final candidate deployment intent");
  assertEqual(candidate.operator_policy.runtime_authority_dependency_sha256,
    runtimeAuthoritySha256, "final candidate R");
  assertEqual(candidate.operator_policy.ceremony_authorization_sha256,
    stageOneSha256, "final candidate signed B");
  assertEqual(candidate.operator_policy.live_activation_authority_sha256,
    stageTwoSha256, "final candidate signed C");
  const releaseCoreBinding = validateHistoricalFinalReleaseAuthorityCoreBinding({
    candidateValue: candidate,
    coreValue: releaseCore,
    runtimeAuthorityValue: persistedRuntimeAuthority,
    authenticatedRuntimeAuthoritySha256: runtimeAuthoritySha256,
  });
  assertEqual(releaseCoreBinding.coreSha256, coreSha256,
    "historical final release authority core");
  const frontendBinding = projectHistoricalLiveActivationFrontendBinding(
    stageTwo,
    stageTwoOptions,
  );
  assertHistoricalLiveActivationFinalCvmsMatchCandidate(frontendBinding, candidate);

  const inputManifestSha256 = frontendBuildInputManifestSha256(normalizedManifest);
  const externalFiveHistoricalEvidence =
    validateExternalFiveHistoricalEvidenceBoundary({
      files: projectExternalFiveEvidenceFilesFromExact37ByKey(exactInputs.byKey),
      releaseCandidate: candidate,
      ceremonyAuthorization: stageOne,
      computeWorkloadActivationObservation: historicalO,
      frontendBuildInputManifest: normalizedManifest,
      frontendBuildCandidateReceipt: buildReceipt,
      liveActivationAuthority: stageTwo,
      authorityDigests: {
        ceremonyAuthorizationSha256: stageOneSha256,
        ceremonyNonce,
        computeWorkloadActivationObservationSha256: observationSha256,
        frontendBuildCandidateReceiptSha256: buildReceiptSha256,
        frontendBuildInputManifestSha256: inputManifestSha256,
        liveActivationAuthoritySha256: stageTwoSha256,
        releaseVerificationAuthoritySha256:
          launch.release_verification_authority_sha256,
        runtimeAuthorityDependencySha256: runtimeAuthoritySha256,
      },
      recoverIndependentEip191PersonalSigner:
        recoverIndependentEip191PersonalSignerFromRawDigest,
    });

  const unsignedStageTwo = Object.fromEntries(
    Object.entries(stageTwo).filter(([key]) => key !== "review"),
  );
  const dependencyGraph = createExactModelADependencyGraph({
    release_sha: candidate.release_sha,
    pre_d_release_inputs_sha256: inputManifestSha256,
    frontend_build_candidate_receipt_sha256: buildReceiptSha256,
    live_activation_review_subject_sha256:
      historicalLiveActivationReviewSubjectSha256(unsignedStageTwo, {
        ceremonyAuthorization: stageOne,
        ceremonyAuthorizationOptions: stageOneOptions,
        expectedContext: stageTwoExpectedContext,
      }),
    live_activation_authority_sha256: stageTwoSha256,
    final_release_raw_sha256: exactInputs.byKey.release.rawSha256,
    nodes: {
      deployment_intent_sha256: intentSha256,
      bootstrap_authorization_receipt_sha256: signedAReceiptSha256,
      seven_cvm_verified_evidence_set_sha256:
        historicalMachineEvidence.seven_cvm_verified_evidence_set_sha256,
      seven_cvm_launch_completion_receipt_sha256: launchSha256,
      historical_transcript_file_set_sha256: transcriptSha256,
      descriptor_runtime_authority_sha256:
        launch.release_verification_authority
          .cvm_descriptor_runtime_authority_sha256,
      release_verification_authority_sha256:
        launch.release_verification_authority_sha256,
      runtime_authority_dependency_sha256: runtimeAuthoritySha256,
      ceremony_authorization_sha256: stageOneSha256,
      post_measurement_activation_execution_receipt_sha256:
        activationExecutionReceiptSha256,
      compute_workload_activation_observation_sha256: observationSha256,
      frontend_build_candidate_receipt_sha256: buildReceiptSha256,
      live_activation_authority_sha256: stageTwoSha256,
      final_release_raw_sha256: exactInputs.byKey.release.rawSha256,
    },
  });
  const dependencyGraphSha256 = exactModelADependencyGraphSha256(dependencyGraph);

  return Object.freeze({
    status: EXACT37_MODEL_A_HISTORICAL_STATUS,
    releaseSha: candidate.release_sha,
    candidate,
    authorityBinding: Object.freeze({
      ...authorityBinding,
      liveActivationAuthoritySha256: stageTwoSha256,
      computeWorkloadBrowserBindingSha256: browserBindingSha256,
      frontendBuildCandidateReceiptSha256: buildReceiptSha256,
      releaseInputsSha256: buildReceipt.release_inputs_sha256,
    }),
    normalizedArtifacts: Object.freeze({
      intent, genesis, acceptance, contract, bootstrapAuthority,
      signedAReceipt, executor, launchReceipt, runtimeAuthority,
      stageOne, activationExecutionReceipt, historicalO, buildReceipt, stageTwo,
      reviewerReconstruction, historicalOReplay, historicalMachineEvidence,
      externalFiveHistoricalEvidence, releaseCore,
    }),
    historicalTranscript,
    frontendBinding,
    dependencyGraph,
    dependencyGraphSha256,
    current_clock_consulted_for_historical_a_l_r_o: false,
    historical_freshness_renewed: false,
    production_brand_minted_for_historical_a_l_r: false,
    liveTrafficAuthorized: false,
    downstreamLiveEvidenceBoundary: Object.freeze({
      required: true,
      flags: Object.freeze([
        "--ledger", "--artifact-evidence", "--arena-evidence",
        "--anchor-writer-evidence", "--email-oracle-evidence",
      ]),
      truth_status:
        "historical_external_signatures_and_byte_lineage_validated_but_current_chain_kms_and_restart_proofs_not_authenticated_here",
      historicalEvidence: externalFiveHistoricalEvidence,
    }),
  });
}
