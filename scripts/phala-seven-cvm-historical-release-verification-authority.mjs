import {
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA as
    LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  canonicalPhalaSevenCvmReleaseVerificationAuthorityText as
    canonicalLegacyPhalaSevenCvmReleaseVerificationAuthorityText,
  normalizePhalaSevenCvmReleaseVerificationAuthority as
    normalizeLegacyPhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256 as
    legacyPhalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  canonicalPhalaSevenCvmReleaseVerificationAuthorityText as
    canonicalCurrentPhalaSevenCvmReleaseVerificationAuthorityText,
  normalizePhalaSevenCvmReleaseVerificationAuthority as
    normalizeCurrentPhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256 as
    currentPhalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";
import {
  phalaNonLiveBootstrapAuthorizationReceiptSha256,
  reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch,
} from "./phala-nonlive-bootstrap-authorization-core.mjs";
import {
  freshContractDeploymentReceiptDigest,
  historicalFreshContractDeploymentReceiptV3Digest,
  normalizeFreshContractDeploymentReceipt,
  normalizeHistoricalFreshContractDeploymentReceiptV3,
} from "./cvm-launch-intent-core.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA as
    HISTORICAL_CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  cvmReleaseDescriptorSetReceiptSha256 as
    historicalCvmReleaseDescriptorSetReceiptSha256,
  normalizeCvmReleaseDescriptorSetReceipt as
    normalizeHistoricalCvmReleaseDescriptorSetReceipt,
} from "./release-manifest-descriptor-historical-core.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  cvmReleaseDescriptorSetReceiptSha256,
  normalizeCvmReleaseDescriptorSetReceipt,
} from "./cvm-release-descriptor-set-v3.mjs";
import {
  normalizeCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-executor-state-core.mjs";
import {
  reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency,
} from "./phala-seven-cvm-launch-completion-core.mjs";
import {
  phalaQvlMeasurementPolicySha256,
} from "./phala-seven-cvm-measurement-policy.mjs";
import {
  normalizePreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
  projectPreCeremonyRuntimeAuthorityHistoricalLaunchBinding,
} from "./pre-ceremony-runtime-authority-core.mjs";
import {
  historicalCeremonyAuthorizationCoreSha256,
  normalizeHistoricalCeremonyAuthorizationCore,
  projectHistoricalCeremonyExpectedContext,
} from "./release-authority-historical-core.mjs";
import {
  normalizeStageBSuccessorReviewerAuthority,
} from "./release-authority-current-reviewer-facade.mjs";
import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  verifyIndependentEip191PersonalSignature,
} from "./release-authority-signature-verifier-core.mjs";
import {
  normalizePhalaSevenCvmHistoricalTranscriptFileSet,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";

export const PHALA_SEVEN_CVM_HISTORICAL_RELEASE_AUTHORITY_METADATA_SCHEMA =
  "dnai.phala-seven-cvm-historical-release-authority-metadata.v1";
export const PHALA_SEVEN_CVM_HISTORICAL_RELEASE_AUTHORITY_METADATA_TRUTH =
  "original_signed_a_l_r_b_executor_and_transcript_lineage_reconstructed_without_freshness_renewal";

const METADATA_FIELDS = Object.freeze([
  "ceremony_authorization_sha256",
  "cvm_descriptor_runtime_authority_sha256",
  "executor_final_state_sha256",
  "historical_transcript_file_set_sha256",
  "nonlive_bootstrap_authorization_receipt_sha256",
  "pre_ceremony_runtime_authority_sha256",
  "release_verification_authority_sha256",
  "schema",
  "seven_cvm_launch_completion_receipt_sha256",
  "seven_cvm_verified_evidence_set_sha256",
  "truth_status",
]);
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const HISTORICALLY_RECONSTRUCTED_AUTHORITIES = new WeakMap();

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new TypeError(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function digest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${label} must be one nonzero canonical SHA-256 digest`);
  }
  return value;
}

function equal(actual, expected, label) {
  if (actual !== expected) {
    throw new TypeError(`${label} drifted from the original signed lineage`);
  }
}

function ownSchema(value, label) {
  if (!isRecord(value)
    || (Object.getPrototypeOf(value) !== Object.prototype
      && Object.getPrototypeOf(value) !== null)
    || !Object.hasOwn(value, "schema")
    || typeof value.schema !== "string") {
    throw new TypeError(`${label} has no canonical own schema`);
  }
  return value.schema;
}

function normalizeRecordedReleaseAuthority(value) {
  const schema = ownSchema(
    value,
    "recorded-time release-verification authority",
  );
  if (schema === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return normalizeCurrentPhalaSevenCvmReleaseVerificationAuthority(value);
  }
  if (schema
      === LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return normalizeLegacyPhalaSevenCvmReleaseVerificationAuthority(value);
  }
  throw new TypeError(
    "recorded-time release-verification authority version is unsupported",
  );
}

function recordedReleaseAuthoritySha256(value) {
  const schema = ownSchema(
    value,
    "recorded-time release-verification authority",
  );
  if (schema === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return currentPhalaSevenCvmReleaseVerificationAuthoritySha256(value);
  }
  if (schema
      === LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return legacyPhalaSevenCvmReleaseVerificationAuthoritySha256(value);
  }
  throw new TypeError(
    "recorded-time release-verification authority version is unsupported",
  );
}

function canonicalRecordedReleaseAuthorityText(value) {
  const schema = ownSchema(
    value,
    "recorded-time release-verification authority",
  );
  if (schema === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return canonicalCurrentPhalaSevenCvmReleaseVerificationAuthorityText(value);
  }
  if (schema
      === LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return canonicalLegacyPhalaSevenCvmReleaseVerificationAuthorityText(value);
  }
  throw new TypeError(
    "recorded-time release-verification authority version is unsupported",
  );
}

function normalizeMetadata(value) {
  const parsed = exactRecord(
    value,
    METADATA_FIELDS,
    "historical release-verification authority metadata",
  );
  if (parsed.schema
      !== PHALA_SEVEN_CVM_HISTORICAL_RELEASE_AUTHORITY_METADATA_SCHEMA
    || parsed.truth_status
      !== PHALA_SEVEN_CVM_HISTORICAL_RELEASE_AUTHORITY_METADATA_TRUTH) {
    throw new TypeError("historical release-verification metadata boundary is invalid");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_SEVEN_CVM_HISTORICAL_RELEASE_AUTHORITY_METADATA_SCHEMA,
    truth_status: PHALA_SEVEN_CVM_HISTORICAL_RELEASE_AUTHORITY_METADATA_TRUTH,
    release_verification_authority_sha256: digest(
      parsed.release_verification_authority_sha256,
      "historical release-verification authority",
    ),
    nonlive_bootstrap_authorization_receipt_sha256: digest(
      parsed.nonlive_bootstrap_authorization_receipt_sha256,
      "historical signed-A receipt",
    ),
    executor_final_state_sha256: digest(
      parsed.executor_final_state_sha256,
      "historical executor final state",
    ),
    seven_cvm_launch_completion_receipt_sha256: digest(
      parsed.seven_cvm_launch_completion_receipt_sha256,
      "historical seven-CVM launch completion",
    ),
    seven_cvm_verified_evidence_set_sha256: digest(
      parsed.seven_cvm_verified_evidence_set_sha256,
      "historical seven-CVM verified evidence set",
    ),
    historical_transcript_file_set_sha256: digest(
      parsed.historical_transcript_file_set_sha256,
      "historical transcript file set",
    ),
    cvm_descriptor_runtime_authority_sha256: digest(
      parsed.cvm_descriptor_runtime_authority_sha256,
      "historical CVM descriptor runtime authority",
    ),
    pre_ceremony_runtime_authority_sha256: digest(
      parsed.pre_ceremony_runtime_authority_sha256,
      "historical pre-ceremony runtime authority",
    ),
    ceremony_authorization_sha256: digest(
      parsed.ceremony_authorization_sha256,
      "historical signed-B ceremony authorization",
    ),
  }, { label: "historical release-verification authority metadata" });
}

function brandHistoricalAuthority(authorityValue, metadataValue) {
  const authority = normalizeRecordedReleaseAuthority(authorityValue);
  const metadata = normalizeMetadata(metadataValue);
  const authoritySha256 = recordedReleaseAuthoritySha256(authority);
  equal(
    metadata.release_verification_authority_sha256,
    authoritySha256,
    "historical release-verification authority metadata digest",
  );
  HISTORICALLY_RECONSTRUCTED_AUTHORITIES.set(authority, metadata);
  return authority;
}

export function assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority(
  value,
) {
  const metadata = value && HISTORICALLY_RECONSTRUCTED_AUTHORITIES.get(value);
  if (!metadata) {
    throw new TypeError(
      "release verification authority was not historically reconstructed from signed A/L/R/B dependencies",
    );
  }
  const normalized = normalizeRecordedReleaseAuthority(value);
  const authoritySha256 = recordedReleaseAuthoritySha256(normalized);
  if (authoritySha256 !== metadata.release_verification_authority_sha256
    || canonicalRecordedReleaseAuthorityText(normalized)
      !== canonicalRecordedReleaseAuthorityText(value)) {
    throw new TypeError("historical release-verification authority digest guard failed");
  }
  return value;
}

export function historicallyReconstructedPhalaSevenCvmReleaseVerificationAuthorityMetadata(
  value,
) {
  const authority =
    assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority(value);
  return HISTORICALLY_RECONSTRUCTED_AUTHORITIES.get(authority);
}

function contract(receipt, name) {
  const found = receipt.contracts.find((entry) => entry.name === name);
  if (!found) throw new TypeError(`fresh contract receipt omits ${name}`);
  return found;
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

/**
 * Normalize the one coherent recorded-time CVM authority tuple.
 *
 * This is an effect-free version router. It does not brand an authority or
 * renew freshness; it only proves that the descriptor, contract receipt,
 * descriptor-runtime authority, and release-verification authority all belong
 * to the same frozen generation.
 */
export function normalizeRecordedCvmAuthorityTuple({
  releaseVerificationAuthority,
  descriptorSetReceipt,
  freshContractDeploymentReceipt,
  expectedDeploymentIntentSha256,
  expectedReviewerAuthorityGenesisAcceptanceSha256,
} = {}) {
  exactRecord(arguments[0], [
    "descriptorSetReceipt",
    "expectedDeploymentIntentSha256",
    "expectedReviewerAuthorityGenesisAcceptanceSha256",
    "freshContractDeploymentReceipt",
    "releaseVerificationAuthority",
  ], "recorded-time CVM authority tuple input");
  const authority = normalizeRecordedReleaseAuthority(
    releaseVerificationAuthority,
  );
  const currentTuple =
    authority.schema === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA;
  const descriptorSchema = ownSchema(
    descriptorSetReceipt,
    "recorded-time descriptor-set receipt",
  );
  if ((currentTuple
        && descriptorSchema !== CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA)
    || (!currentTuple
        && descriptorSchema
          !== HISTORICAL_CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA)) {
    throw new TypeError(
      "recorded-time release authority and descriptor receipt versions are crossed",
    );
  }
  const descriptors = currentTuple
    ? normalizeCvmReleaseDescriptorSetReceipt(descriptorSetReceipt)
    : normalizeHistoricalCvmReleaseDescriptorSetReceipt(descriptorSetReceipt);
  const descriptorSetSha256 = currentTuple
    ? cvmReleaseDescriptorSetReceiptSha256(descriptors)
    : historicalCvmReleaseDescriptorSetReceiptSha256(descriptors);
  const authorityPins = {
    expectedDeploymentIntentSha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256,
    ...(currentTuple
      ? {
          expectedTinkerAccountBindingCeremonyReceiptSha256:
            descriptors.tinker_account_binding_ceremony_receipt_sha256,
        }
      : {}),
  };
  const contractReceipt = currentTuple
    ? normalizeFreshContractDeploymentReceipt(
      freshContractDeploymentReceipt,
      authorityPins,
    )
    : normalizeHistoricalFreshContractDeploymentReceiptV3(
      freshContractDeploymentReceipt,
      authorityPins,
    );
  const contractReceiptSha256 = `sha256:${currentTuple
    ? freshContractDeploymentReceiptDigest(contractReceipt, authorityPins)
    : historicalFreshContractDeploymentReceiptV3Digest(
      contractReceipt,
      authorityPins,
    )}`;
  const descriptorRuntime = authority.cvm_descriptor_runtime_authority;

  equal(
    authority.deployment_intent_sha256,
    expectedDeploymentIntentSha256,
    "recorded-time authority deployment intent",
  );
  equal(
    authority.release_sha,
    descriptors.release_sha,
    "recorded-time authority/descriptor release",
  );
  equal(
    authority.release_sha,
    contractReceipt.release_sha,
    "recorded-time authority/contract release",
  );
  equal(
    descriptorRuntime.descriptor_set_receipt_sha256,
    descriptorSetSha256,
    "recorded-time descriptor-runtime/descriptor receipt",
  );
  equal(
    authority.contracts.fresh_contract_deployment_receipt_sha256,
    contractReceiptSha256,
    "recorded-time authority/contract receipt",
  );
  if (currentTuple) {
    equal(
      authority.tinker_account_binding_ceremony_receipt_sha256,
      descriptors.tinker_account_binding_ceremony_receipt_sha256,
      "current authority/descriptor account-binding ceremony receipt",
    );
    equal(
      descriptorRuntime.tinker_account_binding_ceremony_receipt_sha256,
      descriptors.tinker_account_binding_ceremony_receipt_sha256,
      "current descriptor-runtime/descriptor account-binding ceremony receipt",
    );
    equal(
      contractReceipt.tinker_account_binding_ceremony_receipt_sha256,
      descriptors.tinker_account_binding_ceremony_receipt_sha256,
      "current contract/descriptor account-binding ceremony receipt",
    );
  }
  return deepFreezeCanonicalPlainDataGraph({
    current_tuple: currentTuple,
    release_verification_authority: authority,
    descriptor_set_receipt: descriptors,
    descriptor_set_receipt_sha256: descriptorSetSha256,
    fresh_contract_deployment_receipt: contractReceipt,
    fresh_contract_deployment_receipt_sha256: contractReceiptSha256,
  }, { label: "recorded-time CVM authority tuple" });
}

/**
 * Reconstruct the authority carried by persisted R and authenticated by signed B.
 *
 * Every historical dependency is evaluated at its recorded time. This function
 * never consults Date.now, reruns DCAP, refreshes a QVL challenge, or mints the
 * fresh production authority brand used by live launch code.
 */
export async function reconstructPersistedHistoricalPhalaSevenCvmReleaseVerificationAuthority({
  releaseVerificationAuthority,
  signedAReconstructionInput,
  launchCompletionReceipt,
  persistedRuntimeAuthority,
  persistedCeremonyAuthorization,
  ceremonyAuthorizationDependencies,
  executorFinalState,
  descriptorSetReceipt,
  historicalTranscriptFileSet,
} = {}) {
  exactRecord(arguments[0], [
    "ceremonyAuthorizationDependencies",
    "descriptorSetReceipt",
    "executorFinalState",
    "historicalTranscriptFileSet",
    "launchCompletionReceipt",
    "persistedCeremonyAuthorization",
    "persistedRuntimeAuthority",
    "releaseVerificationAuthority",
    "signedAReconstructionInput",
  ], "historical release-verification reconstruction input");
  const dependencies = exactRecord(ceremonyAuthorizationDependencies, [
    "deploymentIntent",
    "freshContractDeploymentReceipt",
    "reviewerGenesis",
    "reviewerGenesisAcceptance",
    "stageBReviewerStatusHistory",
  ], "historical signed-B dependency set");
  if (!Array.isArray(dependencies.stageBReviewerStatusHistory)) {
    throw new TypeError("historical signed-B Stage-B reviewer status history must be an array");
  }

  const authority = normalizeRecordedReleaseAuthority(
    releaseVerificationAuthority,
  );
  const authoritySchema = ownSchema(
    authority,
    "recorded-time release-verification authority",
  );
  const currentTuple =
    authoritySchema === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA;
  const authoritySha256 = recordedReleaseAuthoritySha256(authority);
  const signedAInput = exactRecord(signedAReconstructionInput, [
    "authorization",
    "authorizationFileIdentity",
    "bootstrapAuthority",
    "bootstrapAuthorityFileIdentity",
    "persistedReceipt",
    "reviewerAuthority",
  ], "historical signed-A reconstruction input");
  const signedAReconstruction =
    reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch({
      authorization: signedAInput.authorization,
      bootstrapAuthority: signedAInput.bootstrapAuthority,
      reviewerAuthority: signedAInput.reviewerAuthority,
      persistedReceipt: signedAInput.persistedReceipt,
      launchCompletedAt: launchCompletionReceipt?.completed_at,
      authorizationFileIdentity: signedAInput.authorizationFileIdentity,
      bootstrapAuthorityFileIdentity:
        signedAInput.bootstrapAuthorityFileIdentity,
    });
  const signedA = signedAReconstruction.receipt;
  const signedASha256 =
    phalaNonLiveBootstrapAuthorizationReceiptSha256(signedA);
  const executor = normalizeCompletedPhalaExecutorState(
    executorFinalState,
  );
  const executorSha256 = phalaExecutorStateDigest(executor);
  const runtime = normalizePreCeremonyRuntimeAuthority(
    persistedRuntimeAuthority,
  );
  const runtimeSha256 = preCeremonyRuntimeAuthoritySha256(runtime);
  const transcript =
    normalizePhalaSevenCvmHistoricalTranscriptFileSet(
      historicalTranscriptFileSet,
    );
  const transcriptSha256 =
    phalaSevenCvmHistoricalTranscriptFileSetSha256(transcript);
  const historicalLaunch =
    reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency({
      persistedReceipt: launchCompletionReceipt,
      persistedExecutorFinalState: executor,
      historicalPreCeremonyRuntimeBinding:
        projectPreCeremonyRuntimeAuthorityHistoricalLaunchBinding(runtime),
      historicalBootstrapAuthorizationBinding:
        signedAReconstruction.historical_bootstrap_authorization_binding,
    });
  const launch = historicalLaunch.receipt;
  const launchSha256 = historicalLaunch.receipt_sha256;
  const descriptorSetSchema = ownSchema(
    descriptorSetReceipt,
    "recorded-time descriptor-set receipt",
  );
  if ((currentTuple
        && descriptorSetSchema !== CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA)
    || (!currentTuple
        && descriptorSetSchema
          !== HISTORICAL_CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA)) {
    throw new TypeError(
      "recorded-time release authority and descriptor receipt versions are crossed",
    );
  }
  const descriptorSet = currentTuple
    ? normalizeCvmReleaseDescriptorSetReceipt(descriptorSetReceipt)
    : normalizeHistoricalCvmReleaseDescriptorSetReceipt(
      descriptorSetReceipt,
    );
  const descriptorSetSha256 = currentTuple
    ? cvmReleaseDescriptorSetReceiptSha256(descriptorSet)
    : historicalCvmReleaseDescriptorSetReceiptSha256(descriptorSet);
  const stageOneSignedAtMs = Date.parse(
    persistedCeremonyAuthorization?.review?.signed_at,
  );
  if (!Number.isSafeInteger(stageOneSignedAtMs) || stageOneSignedAtMs < 1) {
    throw new TypeError("historical signed B has no canonical original signing time");
  }
  const reviewerStage = normalizeStageBSuccessorReviewerAuthority({
    reviewerGenesis: dependencies.reviewerGenesis,
    reviewerGenesisAcceptance: dependencies.reviewerGenesisAcceptance,
    reviewerStatusHistory: dependencies.stageBReviewerStatusHistory,
    deploymentIntent: dependencies.deploymentIntent,
    checkedAtMs: stageOneSignedAtMs,
    enforceFreshness: false,
  });
  const reviewerAuthority = {
    reviewer_authority_genesis_sha256: reviewerStage.genesisSha256,
    reviewer_authority_genesis_acceptance_sha256:
      reviewerStage.acceptanceSha256,
    reviewer_authority_current_status_epoch:
      reviewerStage.currentStatus.epoch,
    reviewer_authority_current_status_not_before:
      reviewerStage.currentStatusNotBefore,
    reviewer_authority_current_status_expires_at:
      reviewerStage.currentStatusExpiresAt,
    reviewer_authority_current_status_sha256:
      reviewerStage.currentStatusSha256,
    ...reviewerStage.authority,
  };
  const freshContractAuthorityPins = {
    expectedDeploymentIntentSha256:
      authority.deployment_intent_sha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      reviewerStage.acceptanceSha256,
    ...(currentTuple
      ? {
          expectedTinkerAccountBindingCeremonyReceiptSha256:
            descriptorSet
              .tinker_account_binding_ceremony_receipt_sha256,
        }
      : {}),
  };
  normalizeRecordedCvmAuthorityTuple({
    releaseVerificationAuthority: authority,
    descriptorSetReceipt,
    freshContractDeploymentReceipt:
      dependencies.freshContractDeploymentReceipt,
    expectedDeploymentIntentSha256:
      authority.deployment_intent_sha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      reviewerStage.acceptanceSha256,
  });
  const freshContractSha256AtCeremony = `sha256:${
    currentTuple
      ? freshContractDeploymentReceiptDigest(
        dependencies.freshContractDeploymentReceipt,
        freshContractAuthorityPins,
      )
      : historicalFreshContractDeploymentReceiptV3Digest(
        dependencies.freshContractDeploymentReceipt,
        freshContractAuthorityPins,
      )
  }`;
  const ceremonyExpectedContext = projectHistoricalCeremonyExpectedContext({
    runtimeAuthority: runtime,
    runtimeAuthoritySha256: runtimeSha256,
    freshContractDeploymentReceiptSha256:
      freshContractSha256AtCeremony,
    signedABootstrapAuthorizationReceiptSha256: signedASha256,
    toolchain: dependencies.deploymentIntent.release.toolchain,
  });
  const ceremonyOptions = {
    expectedContext: ceremonyExpectedContext,
    reviewerAuthority,
    expectedSignatureVerifier: PINNED_CAST_SIGNATURE_VERIFIER,
    verifyReviewSignatures: verifyHistoricalReviewSignatures,
  };
  const ceremony = normalizeHistoricalCeremonyAuthorizationCore(
    persistedCeremonyAuthorization,
    ceremonyOptions,
  );
  const ceremonySha256 = historicalCeremonyAuthorizationCoreSha256(
    ceremony,
    ceremonyOptions,
  );
  const reviewerAcceptanceSha256 =
    ceremony.deployment_authority.reviewer_authority_genesis_acceptance_sha256;
  const normalizedFreshContractAuthorityPins = {
    ...freshContractAuthorityPins,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      reviewerAcceptanceSha256,
  };
  const freshContract = currentTuple
    ? normalizeFreshContractDeploymentReceipt(
      dependencies.freshContractDeploymentReceipt,
      normalizedFreshContractAuthorityPins,
    )
    : normalizeHistoricalFreshContractDeploymentReceiptV3(
      dependencies.freshContractDeploymentReceipt,
      normalizedFreshContractAuthorityPins,
    );
  const freshContractSha256 = `sha256:${
    currentTuple
      ? freshContractDeploymentReceiptDigest(
        freshContract,
        normalizedFreshContractAuthorityPins,
      )
      : historicalFreshContractDeploymentReceiptV3Digest(
        freshContract,
        normalizedFreshContractAuthorityPins,
      )
  }`;
  const diligenceRoom = contract(freshContract, "DiligenceRoom");
  const computeVault = contract(freshContract, "ComputeCreditVault");
  const descriptorRuntime = authority.cvm_descriptor_runtime_authority;
  const plan = runtime.post_measurement_activation_plan;

  equal(authority.release_sha, signedA.release_sha, "authority/signed-A release");
  equal(authority.release_sha, launch.release_sha, "authority/L release");
  equal(authority.release_sha, runtime.release_sha, "authority/R release");
  equal(authority.release_sha, ceremony.release_sha, "authority/B release");
  equal(authority.release_sha, executor.release_sha, "authority/executor release");
  equal(
    authority.deployment_intent_sha256,
    signedA.deployment_intent_sha256,
    "authority/signed-A deployment intent",
  );
  equal(
    authority.deployment_intent_sha256,
    launch.deployment_intent_sha256,
    "authority/L deployment intent",
  );
  equal(
    authority.deployment_intent_sha256,
    runtime.deployment_intent_sha256,
    "authority/R deployment intent",
  );
  equal(
    authority.deployment_intent_sha256,
    ceremony.deployment_authority.deployment_intent_sha256,
    "authority/B deployment intent",
  );
  equal(
    authority.bootstrap_authorization_receipt_sha256,
    signedASha256,
    "authority signed-A receipt",
  );
  equal(
    authority.bootstrap_authorization_receipt_sha256,
    launch.nonlive_bootstrap_authorization_receipt_sha256,
    "authority/L signed-A receipt",
  );
  equal(
    authority.bootstrap_authorization_receipt_sha256,
    executor.bootstrap_authorization_receipt_sha256,
    "authority/executor signed-A receipt",
  );
  equal(
    authority.qvl_measurement_policy_set_sha256,
    signedA.qvl_measurement_policy_set_sha256,
    "authority signed-A QVL policy set",
  );
  equal(
    authority.qvl_measurement_policy_set_sha256,
    plan.runtime_commitments
      .TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256,
    "authority activation-plan QVL policy set",
  );
  equal(
    authority.ceremony_nonce,
    plan.runtime_commitments.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE,
    "authority authenticated R activation-plan ceremony nonce",
  );
  const computeWorkloadPolicy = authority.qvl_measurement_policies.find(
    ({ domain }) => domain === "compute_workload_qvl_cvm",
  );
  if (!computeWorkloadPolicy) {
    throw new TypeError("authority omits the compute-workload QVL measurement policy");
  }
  equal(
    phalaQvlMeasurementPolicySha256(
      computeWorkloadPolicy,
    ),
    plan.runtime_commitments
      .TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256,
    "authority activation-plan compute-workload QVL policy",
  );

  equal(
    authority.contracts.fresh_contract_deployment_receipt_sha256,
    freshContractSha256,
    "authority fresh contract receipt",
  );
  equal(
    authority.contracts.fresh_contract_deployment_receipt_sha256,
    launch.fresh_contract_deployment_receipt_sha256,
    "authority/L fresh contract receipt",
  );
  equal(
    authority.contracts.fresh_contract_deployment_receipt_sha256,
    ceremony.deployment_authority.fresh_contract_deployment_receipt_sha256,
    "authority/B fresh contract receipt",
  );
  equal(
    authority.contracts.diligence_room,
    diligenceRoom.address,
    "authority DiligenceRoom address",
  );
  equal(
    authority.contracts.compute_credit_vault,
    computeVault.address,
    "authority ComputeCreditVault address",
  );
  equal(
    authority.contracts.compute_credit_vault_runtime_code_hash,
    computeVault.runtime_code_hash,
    "authority ComputeCreditVault runtime code hash",
  );

  equal(
    descriptorRuntime.release_sha,
    authority.release_sha,
    "descriptor-runtime release",
  );
  equal(
    descriptorRuntime.descriptor_set_receipt_sha256,
    descriptorSetSha256,
    "descriptor-runtime descriptor-set receipt",
  );
  equal(
    descriptorRuntime.descriptor_set_receipt_sha256,
    launch.descriptor_set_receipt_sha256,
    "descriptor-runtime/L descriptor-set receipt",
  );
  if (currentTuple) {
    equal(
      authority.tinker_account_binding_ceremony_receipt_sha256,
      descriptorSet.tinker_account_binding_ceremony_receipt_sha256,
      "current authority/descriptor account-binding ceremony receipt",
    );
    equal(
      descriptorRuntime.tinker_account_binding_ceremony_receipt_sha256,
      descriptorSet.tinker_account_binding_ceremony_receipt_sha256,
      "current descriptor-runtime/descriptor account-binding ceremony receipt",
    );
    equal(
      freshContract.tinker_account_binding_ceremony_receipt_sha256,
      descriptorSet.tinker_account_binding_ceremony_receipt_sha256,
      "current contract/descriptor account-binding ceremony receipt",
    );
  }
  equal(
    descriptorRuntime.image_manifest_sha256,
    signedA.image_release_manifest_sha256,
    "descriptor-runtime signed-A image manifest",
  );
  equal(
    descriptorRuntime.image_manifest_sha256,
    launch.image_release_manifest_sha256,
    "descriptor-runtime/L image manifest",
  );
  equal(
    descriptorRuntime.topology_sha256,
    signedA.topology_sha256,
    "descriptor-runtime signed-A topology",
  );
  equal(
    descriptorRuntime.topology_sha256,
    launch.topology_sha256,
    "descriptor-runtime/L topology",
  );

  equal(
    plan.release_verification_authority_sha256,
    authoritySha256,
    "activation-plan release authority digest",
  );
  equal(
    runtime.release_verification_authority_sha256,
    authoritySha256,
    "R release authority digest",
  );
  if (canonicalRecordedReleaseAuthorityText(
    plan.release_verification_authority,
  ) !== canonicalRecordedReleaseAuthorityText(authority)) {
    throw new TypeError("R activation plan carries different release authority bytes");
  }
  equal(
    runtime.seven_cvm_launch_completion_receipt_sha256,
    launchSha256,
    "R/L receipt digest",
  );
  equal(
    runtime.historical_transcript_file_set_sha256,
    transcriptSha256,
    "R historical transcript file set",
  );
  equal(
    launch.historical_transcript_file_set_sha256,
    transcriptSha256,
    "L historical transcript file set",
  );
  digest(
    launch.historical_transcript_persistence_receipt_sha256,
    "L historical transcript persistence receipt",
  );
  if (launch.private_historical_transcript_persisted !== true
    || launch.private_historical_transcript_contains_raw_quote_and_collateral
      !== true
    || launch.raw_quote_publicly_disclosed !== false
    || launch.raw_collateral_publicly_disclosed !== false
    || launch.raw_secret_egress !== false) {
    throw new TypeError(
      "L does not carry the durable private exact-14 quote/collateral boundary",
    );
  }
  if (JSON.stringify(launch.transcript_file_set) !== JSON.stringify(transcript)) {
    throw new TypeError("L historical transcript file-set bytes drifted");
  }
  equal(
    launch.executor_final_state_sha256,
    executorSha256,
    "L executor final state",
  );
  equal(
    launch.machine_verifier_evidence_set_sha256,
    plan.seven_cvm_verified_evidence_set_sha256,
    "L/R seven-CVM verified evidence set",
  );
  equal(
    launch.phala_recovery_directory_identity_anchor_sha256,
    executor.phala_recovery_directory_identity_anchor_sha256,
    "L/executor recovery-directory identity anchor",
  );
  equal(
    launch.phala_recovery_directory_identity_anchor_sha256,
    runtime.phala_recovery_directory_identity_anchor_sha256,
    "L/R recovery-directory identity anchor",
  );
  equal(
    ceremony.pre_ceremony_runtime_authority_sha256,
    runtimeSha256,
    "signed B/R digest",
  );
  equal(
    ceremony.cvm_bootstrap_authorization_receipt_sha256,
    signedASha256,
    "signed B/signed-A receipt",
  );
  equal(
    ceremony.cvm_launch_intent_sha256,
    signedA.cvm_launch_intent_sha256,
    "signed B/signed-A launch intent",
  );

  const launchByDomain = new Map(
    launch.domains.map((entry) => [entry.domain, entry]),
  );
  const executorReservationByDomain = new Map(
    executor.reservations.map((entry) => [entry.domain, entry]),
  );
  const executorCommitByDomain = new Map(
    executor.committed_prefix.map((entry) => [entry.domain, entry]),
  );
  const executorPostureByDomain = new Map(
    executor.posture_receipts.map((entry) => [entry.domain, entry]),
  );
  for (const descriptor of authority.descriptors) {
    const domain = descriptor.domain;
    const completion = launchByDomain.get(domain);
    const reservation = executorReservationByDomain.get(domain);
    const commit = executorCommitByDomain.get(domain);
    const posture = executorPostureByDomain.get(domain);
    if (!completion || !reservation || !commit || !posture) {
      throw new TypeError(`${domain} historical authority dependency is missing`);
    }
    for (const [actual, expected, label] of [
      [descriptor.descriptor_sha256, signedA.descriptor_sha256_by_domain[domain],
        "signed-A descriptor"],
      [descriptor.descriptor_sha256, descriptorSet.descriptor_sha256_by_domain[domain],
        "descriptor-set descriptor"],
      [descriptor.descriptor_sha256, completion.descriptor_sha256, "L descriptor"],
      [descriptor.app_id, reservation.app_id, "executor app ID"],
      [descriptor.app_id, completion.app_id, "L app ID"],
      [descriptor.cvm_id, commit.cvm_id, "executor CVM ID"],
      [descriptor.cvm_id, completion.cvm_id, "L CVM ID"],
      [descriptor.compose_hash, completion.committed_compose_hash, "L compose hash"],
      [descriptor.os_image_hash, completion.os_image_hash, "L OS image hash"],
      [descriptor.posture_receipt_sha256, posture.receipt_sha256,
        "executor posture receipt"],
      [descriptor.posture_receipt_sha256,
        completion.production_posture_verification_receipt_sha256,
        "L posture receipt"],
      [descriptor.posture_observed_at, completion.production_posture_verified_at,
        "L posture observed_at"],
      [descriptor.kms_id, completion.kms_id, "L KMS ID"],
      [descriptor.instance_type, completion.instance_type, "L instance type"],
      [descriptor.disk_size, completion.disk_size, "L disk size"],
    ]) {
      equal(actual, expected, `${domain} ${label}`);
    }
  }
  const mainCompletion = launchByDomain.get("main_runtime_cvm");
  const independentMetering = launchByDomain.get("independent_metering_cvm");
  equal(
    mainCompletion.bound_contract_address,
    authority.contracts.diligence_room,
    "L main-runtime DiligenceRoom binding",
  );
  equal(
    independentMetering.bound_contract_address,
    authority.contracts.compute_credit_vault,
    "L independent-metering ComputeCreditVault binding",
  );

  return brandHistoricalAuthority(authority, {
    schema: PHALA_SEVEN_CVM_HISTORICAL_RELEASE_AUTHORITY_METADATA_SCHEMA,
    truth_status: PHALA_SEVEN_CVM_HISTORICAL_RELEASE_AUTHORITY_METADATA_TRUTH,
    release_verification_authority_sha256: authoritySha256,
    nonlive_bootstrap_authorization_receipt_sha256: signedASha256,
    executor_final_state_sha256: executorSha256,
    seven_cvm_launch_completion_receipt_sha256: launchSha256,
    seven_cvm_verified_evidence_set_sha256:
      launch.machine_verifier_evidence_set_sha256,
    historical_transcript_file_set_sha256: transcriptSha256,
    cvm_descriptor_runtime_authority_sha256:
      authority.cvm_descriptor_runtime_authority_sha256,
    pre_ceremony_runtime_authority_sha256: runtimeSha256,
    ceremony_authorization_sha256: ceremonySha256,
  });
}
