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
  historicalFreshContractDeploymentReceiptV3Digest,
  normalizeHistoricalFreshContractDeploymentReceiptV3,
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
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA as
    HISTORICAL_CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  cvmReleaseDescriptorSetReceiptSha256 as
    historicalCvmReleaseDescriptorSetReceiptSha256,
  normalizeCvmReleaseDescriptorSetReceipt as
    normalizeHistoricalCvmReleaseDescriptorSetReceipt,
} from "./release-manifest-descriptor-historical-core.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA as
    CURRENT_CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  cvmReleaseDescriptorSetReceiptSha256,
  normalizeCvmReleaseDescriptorSetReceipt,
} from "./cvm-release-descriptor-set-v3.mjs";
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
import {
  FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
  FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA,
  normalizeHistoricalFinalReleaseAuthorityCoreV2,
  normalizeFinalReleaseAuthorityCore,
} from "./execution-policy-release-core-v3-historical.mjs";
import {
  FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS,
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
  reconstructPersistedHistoricalPhalaSevenCvmReleaseVerificationAuthority,
} from "./phala-seven-cvm-historical-release-verification-authority.mjs";
import {
  phalaSevenCvmVerifiedEvidenceSetSha256,
  replayPersistedHistoricalPhalaSevenCvmEvidence,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  projectExternalFiveEvidenceFilesFromExact37ByKey,
  projectExternalFiveHistoricalQvlAuthority,
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
  "historical_authority_and_recorded_time_dcap_validated_live_chain_and_external_evidence_pending";
export const EXACT35_MODEL_A_PREBUILD_STATUS =
  "historical_l_r_signed_b_o_and_recorded_time_dcap_authority_validated_current_release_checks_pending";
export const EXACT37_MODEL_A_INCOMPLETE_REASON =
  "Model-A exact-37 historical replay cannot itself authorize live traffic; current Base Sepolia, external evidence, clean-source, and reproducible-build checks remain mandatory";

export const EXACT35_MODEL_A_INPUT_FLAGS = Object.freeze([
  ...FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS,
]);
if (JSON.stringify(EXACT35_MODEL_A_INPUT_FLAGS)
    !== JSON.stringify(EXACT37_MODEL_A_INPUT_FLAGS.filter(
      (flag) => ![
        "--live-activation-authority",
        "--frontend-build-candidate-receipt",
      ].includes(flag),
    ))) {
  throw new TypeError("exact-35 and exact-37 Model-A input recipes drifted");
}

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

function normalizeExactModelAInputSet(value, inputFlags, label) {
  const parsed = exact(
    value,
    ["artifactPaths", "byFlag", "byKey", "entries", "totalBytes"],
    `${label} stable input set`,
  );
  const expectedKeys = inputFlags.map(keyForFlag);
  const sourceEntries = assertDenseDataArray(
    parsed.entries,
    inputFlags.length,
    `${label} input entries`,
  );
  const byFlag = exact(
    parsed.byFlag,
    inputFlags,
    `${label} by-flag projection`,
  );
  const byKey = exact(
    parsed.byKey,
    expectedKeys,
    `${label} by-key projection`,
  );
  const artifactPaths = exact(
    parsed.artifactPaths,
    ["byFlag", "byKey", "entries"],
    `${label} artifact paths`,
  );
  const artifactPathsByFlag = exact(
    artifactPaths.byFlag,
    inputFlags,
    `${label} artifact paths by flag`,
  );
  const artifactPathsByKey = exact(
    artifactPaths.byKey,
    expectedKeys,
    `${label} artifact paths by key`,
  );
  assertDenseDataArray(
    artifactPaths.entries,
    inputFlags.length,
    `${label} artifact path entries`,
  );
  const entries = sourceEntries.map((raw, index) => {
    const entry = exactInputEntry(raw, [
      "byteLength", "bytes", "filePath", "flag", "key", "metadata",
      "rawSha256", "text", "value",
    ],
      `exact-37 Model-A entry ${index}`);
    const expectedFlag = inputFlags[index];
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

export function normalizeExact37ModelAInputSet(value) {
  return normalizeExactModelAInputSet(
    value,
    EXACT37_MODEL_A_INPUT_FLAGS,
    "exact-37 Model-A",
  );
}

export function normalizeExact35ModelAPrebuildInputSet(value) {
  return normalizeExactModelAInputSet(
    value,
    EXACT35_MODEL_A_INPUT_FLAGS,
    "exact-35 Model-A prebuild",
  );
}

/**
 * Preserve the authenticated historical v2 wire format without allowing it
 * through current activation-facing v3 normalization.
 */
export function normalizeExactModelAFinalReleaseAuthorityCore(
  value,
  { expectedCoreSchema = FINAL_RELEASE_AUTHORITY_CORE_SCHEMA } = {},
) {
  if (expectedCoreSchema === FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA) {
    return normalizeHistoricalFinalReleaseAuthorityCoreV2(value);
  }
  if (expectedCoreSchema === FINAL_RELEASE_AUTHORITY_CORE_SCHEMA) {
    return normalizeFinalReleaseAuthorityCore(value);
  }
  fail("Model-A expected final release authority core schema is unsupported");
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

function projectRaw14HistoricalTranscriptFiles(exactInputs) {
  return RAW14_FLAGS.map((flag) => {
    const entry = exactInputs.byKey[keyForFlag(flag)];
    return Object.freeze({
      flag,
      text: `${JSON.stringify(entry.value, null, 2)}\n`,
    });
  });
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

export function normalizeExact37FreshContractDescriptorAuthorityTuple({
  descriptorReceipt,
  freshContractDeploymentReceipt,
  expectedDeploymentIntentSha256,
  expectedReviewerAuthorityGenesisAcceptanceSha256,
} = {}) {
  const descriptorSchema = descriptorReceipt?.schema;
  const currentAuthorityTuple =
    descriptorSchema === CURRENT_CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA;
  if (!currentAuthorityTuple
    && descriptorSchema !== HISTORICAL_CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA) {
    fail("descriptor/fresh-contract receipt authority tuple schema is unsupported");
  }
  const descriptors = currentAuthorityTuple
    ? normalizeCvmReleaseDescriptorSetReceipt(descriptorReceipt)
    : normalizeHistoricalCvmReleaseDescriptorSetReceipt(descriptorReceipt);
  const baseFreshReceiptAuthorityPins = {
    expectedDeploymentIntentSha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256,
  };
  const freshReceiptAuthorityPins = currentAuthorityTuple
    ? {
      ...baseFreshReceiptAuthorityPins,
      expectedTinkerAccountBindingCeremonyReceiptSha256:
        descriptors.tinker_account_binding_ceremony_receipt_sha256,
    }
    : baseFreshReceiptAuthorityPins;
  const contract = currentAuthorityTuple
    ? normalizeFreshContractDeploymentReceipt(
      freshContractDeploymentReceipt,
      freshReceiptAuthorityPins,
    )
    : normalizeHistoricalFreshContractDeploymentReceiptV3(
      freshContractDeploymentReceipt,
      freshReceiptAuthorityPins,
    );
  const contractSha256 = `sha256:${currentAuthorityTuple
    ? freshContractDeploymentReceiptDigest(
      contract,
      freshReceiptAuthorityPins,
    )
    : historicalFreshContractDeploymentReceiptV3Digest(
      contract,
      freshReceiptAuthorityPins,
    )}`;
  const descriptorSetSha256 = currentAuthorityTuple
    ? cvmReleaseDescriptorSetReceiptSha256(descriptors)
    : historicalCvmReleaseDescriptorSetReceiptSha256(descriptors);
  return Object.freeze({
    authority_tuple: currentAuthorityTuple ? "current" : "historical",
    contract,
    contract_sha256: contractSha256,
    descriptor_set: descriptors,
    descriptor_set_sha256: descriptorSetSha256,
    fresh_receipt_authority_pins: Object.freeze({
      ...freshReceiptAuthorityPins,
    }),
  });
}

/**
 * Model-A historical authority validation.
 *
 * No network, Date.now, current-QVL, or freshness-renewal operation is
 * performed here. The exact private transcript reruns DCAP at each recorded
 * second against its persisted collateral and must reproduce signed R's v5
 * evidence-set commitment. Epoch-one reviewer validity is evaluated only
 * against the caller's explicit validationTimeMs; exact37 has no
 * status-history input and therefore rejects all later epochs. The five
 * external files have their historical schemas, signatures, and B/R/O/C/D
 * lineage replayed, while their current chain, KMS, and restart claims remain
 * a downstream proof boundary.
 */
async function validateExactModelAHistoricalAuthority({
  inputs,
  validationTimeMs,
  reviewerStatusHistory,
  frontendBuildReproduction,
  authorityStage,
  expectedCoreSchema,
} = {}) {
  if (authorityStage !== "live" && authorityStage !== "prebuild") {
    fail("Model-A authority stage must be live or prebuild");
  }
  const live = authorityStage === "live";
  if (!Number.isSafeInteger(validationTimeMs) || validationTimeMs < 1
    || validationTimeMs > 4_102_444_800_000
    || validationTimeMs % 1_000 !== 0) {
    fail("Model-A validation requires an explicit bounded whole-second validationTimeMs");
  }
  if (!Array.isArray(reviewerStatusHistory)
    || reviewerStatusHistory.length !== 0) {
    fail("Model-A exact-37 requires the explicit empty epoch-1 reviewer history");
  }
  const reproduction = live
    ? exact(
      frontendBuildReproduction,
      REQUIRED_REPRODUCTION_FIELDS,
      "frontend D reproduction",
    )
    : null;
  if (!live && frontendBuildReproduction !== undefined) {
    fail("Model-A prebuild validation must not accept a post-D reproduction");
  }
  const exactInputs = live
    ? normalizeExact37ModelAInputSet(inputs)
    : normalizeExact35ModelAPrebuildInputSet(inputs);
  const input = Object.fromEntries(
    Object.entries(exactInputs.byKey).map(([key, entry]) => [key, entry.value]),
  );
  const releaseCore = normalizeExactModelAFinalReleaseAuthorityCore(
    input.releaseCore,
    { expectedCoreSchema },
  );
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
  const freshContractDescriptorTuple =
    normalizeExact37FreshContractDescriptorAuthorityTuple({
      descriptorReceipt: input.cvmDescriptorSetReceipt,
      freshContractDeploymentReceipt: input.contractReceipt,
      expectedDeploymentIntentSha256: intentSha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256: acceptanceSha256,
    });
  const descriptors = freshContractDescriptorTuple.descriptor_set;
  const contract = freshContractDescriptorTuple.contract;
  const contractSha256 = freshContractDescriptorTuple.contract_sha256;
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
  const persistenceReceiptSha256 = digest(
    launchReceipt.historical_transcript_persistence_receipt_sha256,
    "historical L transcript persistence receipt",
  );
  if (launchReceipt.private_historical_transcript_persisted !== true
    || launchReceipt
      .private_historical_transcript_contains_raw_quote_and_collateral !== true
    || launchReceipt.raw_quote_publicly_disclosed !== false
    || launchReceipt.raw_collateral_publicly_disclosed !== false
    || launchReceipt.raw_secret_egress !== false) {
    fail(
      "historical L does not prove the private exact-14 quote/collateral persistence boundary",
    );
  }
  assertEqual(
    launchReceipt.historical_transcript_file_set_sha256,
    transcriptSha256,
    "historical L exact-14 transcript file set",
  );
  if (JSON.stringify(launchReceipt.transcript_file_set)
      !== JSON.stringify(historicalTranscript)) {
    fail("historical L exact-14 transcript file-set bytes drifted");
  }
  assertEqual(
    launchReceipt.phala_recovery_directory_identity_anchor_sha256,
    runtimeAuthority.phala_recovery_directory_identity_anchor_sha256,
    "historical L/R recovery-directory identity anchor",
  );
  assertEqual(
    launchReceipt.phala_recovery_directory_identity_anchor_sha256,
    executor.phala_recovery_directory_identity_anchor_sha256,
    "historical L/executor recovery-directory identity anchor",
  );
  assertEqual(
    launchReceipt.machine_verifier_evidence_set_sha256,
    runtimeAuthority.post_measurement_activation_plan
      .seven_cvm_verified_evidence_set_sha256,
    "historical L/R verified evidence set",
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
  assertEqual(
    stageOne.pre_ceremony_runtime_authority_sha256,
    runtimeAuthoritySha256,
    "historical signed B/R persistence-carrying authority",
  );

  const sigstore = normalizeReleaseManifestSigstoreVerificationReceipt(
    input.imageReleaseSigstoreVerificationReceipt,
  );
  const sigstoreSha256 = releaseManifestSigstoreVerificationReceiptSha256(sigstore);
  const descriptorSetSha256 =
    freshContractDescriptorTuple.descriptor_set_sha256;
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

  const historicalReleaseVerificationAuthority =
    await reconstructPersistedHistoricalPhalaSevenCvmReleaseVerificationAuthority({
      releaseVerificationAuthority: launch.release_verification_authority,
      signedAReconstructionInput: {
        authorization: input.bootstrapAuthorization,
        authorizationFileIdentity: {
          sha256: exactInputs.byKey.bootstrapAuthorization.rawSha256,
          size: exactInputs.byKey.bootstrapAuthorization.byteLength,
        },
        bootstrapAuthority,
        bootstrapAuthorityFileIdentity: {
          sha256: exactInputs.byKey.bootstrapAuthority.rawSha256,
          size: exactInputs.byKey.bootstrapAuthority.byteLength,
        },
        persistedReceipt: signedAReceipt,
        reviewerAuthority: activeReviewerAuthority,
      },
      launchCompletionReceipt: launchReceipt,
      persistedRuntimeAuthority: runtimeAuthority,
      persistedCeremonyAuthorization: stageOne,
      ceremonyAuthorizationDependencies: {
        deploymentIntent: intent,
        freshContractDeploymentReceipt: contract,
        reviewerGenesis: input.reviewerAuthorityGenesis,
        reviewerGenesisAcceptance: input.reviewerAuthorityGenesisAcceptance,
        stageBReviewerStatusHistory: reviewerStatusHistory,
      },
      executorFinalState: executor,
      descriptorSetReceipt: descriptors,
      historicalTranscriptFileSet: historicalTranscript,
    });
  const historicalMachineReplay =
    await replayPersistedHistoricalPhalaSevenCvmEvidence({
      releaseAuthority: historicalReleaseVerificationAuthority,
      rawTranscriptFiles:
        projectRaw14HistoricalTranscriptFiles(exactInputs),
      executorFinalState: executor,
    });
  const historicalMachineEvidence = Object.freeze({
    seven_cvm_verified_evidence_set_sha256:
      phalaSevenCvmVerifiedEvidenceSetSha256(
        historicalMachineReplay.evidenceSet,
      ),
    evidence_set: historicalMachineReplay.evidenceSet,
    qvl_identity_evidence: historicalMachineReplay.qvlIdentityEvidence,
    workload_verdict_evidence:
      historicalMachineReplay.workloadVerdictEvidence,
    historical_corroboration: historicalMachineReplay.corroboration,
    recorded_time_dcap_reverified: true,
    persisted_collateral_revalidated: true,
    historical_release_verification_authority:
      historicalReleaseVerificationAuthority,
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

  if (!live) {
    const candidate = normalizeHistoricalFrontendReleaseCandidate(input.release, {
      authorityStage: "prebuild",
    });
    assertEqual(candidate.release_sha, runtimeAuthority.release_sha,
      "prebuild candidate release");
    assertEqual(candidate.deployment_intent_sha256, intentSha256,
      "prebuild candidate deployment intent");
    assertEqual(candidate.operator_policy.runtime_authority_dependency_sha256,
      runtimeAuthoritySha256, "prebuild candidate R");
    assertEqual(candidate.operator_policy.ceremony_authorization_sha256,
      stageOneSha256, "prebuild candidate signed B");
    const releaseCoreBinding = validateHistoricalFinalReleaseAuthorityCoreBinding({
      candidateValue: candidate,
      coreValue: releaseCore,
      runtimeAuthorityValue: persistedRuntimeAuthority,
      authenticatedRuntimeAuthoritySha256: runtimeAuthoritySha256,
      authorityStage: "prebuild",
      expectedCoreSchema,
    });
    assertEqual(releaseCoreBinding.coreSha256, coreSha256,
      "historical prebuild final release authority core");
    const semanticLineage = Object.freeze({
      release_core_sha256: coreSha256,
      deployment_intent_sha256: intentSha256,
      fresh_contract_deployment_receipt_sha256: contractSha256,
      reviewer_authority_genesis_sha256: genesisSha256,
      reviewer_authority_genesis_acceptance_sha256: acceptanceSha256,
      bootstrap_authority_sha256: bootstrapAuthoritySha256,
      bootstrap_authorization_sha256: phalaNonLiveBootstrapSigningDigest(
        input.bootstrapAuthorization,
        { bootstrapAuthority },
      ),
      bootstrap_authorization_receipt_sha256: signedAReceiptSha256,
      seven_cvm_launch_completion_receipt_sha256: launchSha256,
      historical_transcript_file_set_sha256: transcriptSha256,
      qvl_measurement_policy_set_sha256:
        historicalO.lineage.qvl_measurement_policy_set_sha256,
      runtime_authority_dependency_sha256: runtimeAuthoritySha256,
      ceremony_authorization_sha256: stageOneSha256,
      compute_workload_activation_observation_sha256: observationSha256,
    });
    return Object.freeze({
      status: EXACT35_MODEL_A_PREBUILD_STATUS,
      releaseSha: candidate.release_sha,
      candidate,
      authorityBinding: Object.freeze({
        deploymentIntentSha256: intentSha256,
        reviewerAuthorityGenesisAcceptanceSha256: acceptanceSha256,
        ceremonyAuthorizationSha256: stageOneSha256,
        runtimeAuthorityDependencySha256: runtimeAuthoritySha256,
      }),
      semanticLineage,
      authorityRoots: Object.freeze({
        contract_release_set_sha256: contractSha256,
        cvm_release_set_sha256: launchSha256,
        qvl_measurement_policy_set_sha256:
          historicalO.lineage.qvl_measurement_policy_set_sha256,
      }),
      normalizedArtifacts: Object.freeze({
        intent, genesis, acceptance, contract, bootstrapAuthority,
        signedAReceipt, executor, launchReceipt, runtimeAuthority,
        stageOne, historicalO, reviewerReconstruction, historicalOReplay,
        historicalMachineEvidence, releaseCore,
      }),
      historicalTranscript,
      persistenceReceiptSha256,
      current_clock_consulted_for_historical_a_l_r_o: false,
      historical_freshness_renewed: false,
      production_brand_minted_for_historical_a_l_r: false,
      liveTrafficAuthorized: false,
      downstreamLiveEvidenceBoundary: Object.freeze({
        required: true,
        truth_status:
          "current_chain_external_evidence_reproducible_D_and_signed_C_must_still_validate",
      }),
    });
  }

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
    expectedCoreSchema,
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
      historicalQvlAuthority: projectExternalFiveHistoricalQvlAuthority({
        qvlIdentityEvidence: historicalMachineEvidence.qvl_identity_evidence,
        activationEvidenceLeaseSeconds:
          launch.release_verification_authority
            .activation_evidence_lease_seconds,
      }),
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
      historicalReleaseVerificationAuthority,
      externalFiveHistoricalEvidence, releaseCore,
    }),
    historicalTranscript,
    persistenceReceiptSha256,
    frontendBinding,
    dependencyGraph,
    dependencyGraphSha256,
    current_clock_consulted_for_historical_a_l_r_o: false,
    recorded_time_dcap_replayed_from_private_exact14: true,
    persisted_intel_collateral_revalidated: true,
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

export async function validateExact35ModelAPrebuildAuthority({
  inputs,
  validationTimeMs,
  reviewerStatusHistory,
} = {}) {
  return validateExactModelAHistoricalAuthority({
    inputs,
    validationTimeMs,
    reviewerStatusHistory,
    authorityStage: "prebuild",
    expectedCoreSchema: FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
  });
}

export async function validateExact37ModelAHistoricalAuthority({
  inputs,
  validationTimeMs,
  reviewerStatusHistory,
  frontendBuildReproduction,
} = {}) {
  return validateExactModelAHistoricalAuthority({
    inputs,
    validationTimeMs,
    reviewerStatusHistory,
    frontendBuildReproduction,
    authorityStage: "live",
    expectedCoreSchema: FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
  });
}

export async function validateExact35ModelAHistoricalV2PrebuildAuthority({
  inputs,
  validationTimeMs,
  reviewerStatusHistory,
} = {}) {
  return validateExactModelAHistoricalAuthority({
    inputs,
    validationTimeMs,
    reviewerStatusHistory,
    authorityStage: "prebuild",
    expectedCoreSchema: FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA,
  });
}

export async function validateExact37ModelAHistoricalV2Authority({
  inputs,
  validationTimeMs,
  reviewerStatusHistory,
  frontendBuildReproduction,
} = {}) {
  return validateExactModelAHistoricalAuthority({
    inputs,
    validationTimeMs,
    reviewerStatusHistory,
    frontendBuildReproduction,
    authorityStage: "live",
    expectedCoreSchema: FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA,
  });
}
