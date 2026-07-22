import fs from "node:fs";
import path from "node:path";

import {
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  canonicalPhalaSevenCvmReleaseVerificationAuthorityText,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";

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
  const authority = normalizePhalaSevenCvmReleaseVerificationAuthority(
    authorityValue,
  );
  const metadata = normalizeMetadata(metadataValue);
  const authoritySha256 =
    phalaSevenCvmReleaseVerificationAuthoritySha256(authority);
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
  const normalized = normalizePhalaSevenCvmReleaseVerificationAuthority(value);
  const authoritySha256 =
    phalaSevenCvmReleaseVerificationAuthoritySha256(normalized);
  if (authoritySha256 !== metadata.release_verification_authority_sha256
    || canonicalPhalaSevenCvmReleaseVerificationAuthorityText(normalized)
      !== canonicalPhalaSevenCvmReleaseVerificationAuthorityText(value)) {
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

/**
 * Reconstruct the authority carried by persisted R and authenticated by signed B.
 *
 * Every historical dependency is evaluated at its recorded time. This function
 * never consults Date.now, reruns DCAP, refreshes a QVL challenge, or mints the
 * fresh production authority brand used by live launch code.
 */
export async function reconstructPersistedHistoricalPhalaSevenCvmReleaseVerificationAuthority({
  releaseVerificationAuthority,
  signedAReceipt,
  launchCompletionReceipt,
  launchCompletionOptions,
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
    "launchCompletionOptions",
    "launchCompletionReceipt",
    "persistedCeremonyAuthorization",
    "persistedRuntimeAuthority",
    "releaseVerificationAuthority",
    "signedAReceipt",
  ], "historical release-verification reconstruction input");
  const dependencies = exactRecord(ceremonyAuthorizationDependencies, [
    "deploymentIntent",
    "freshContractDeploymentReceipt",
    "reviewerGenesis",
    "reviewerGenesisAcceptance",
    "reviewerStatusHistory",
  ], "historical signed-B dependency set");
  if (!Array.isArray(dependencies.reviewerStatusHistory)) {
    throw new TypeError("historical signed-B reviewer status history must be an array");
  }

  const [
    bootstrapModule,
    contractModule,
    descriptorSetModule,
    executorModule,
    launchModule,
    measurementPolicyModule,
    runtimeModule,
    ceremonyModule,
    transcriptModule,
  ] = await Promise.all([
    import("./phala-nonlive-bootstrap-authorization.mjs"),
    import("./cvm-launch-intent-core.mjs"),
    import("./cvm-release-descriptor-set.mjs"),
    import("./phala-production-executor-core.mjs"),
    import("./phala-seven-cvm-launch-completion.mjs"),
    import("./phala-seven-cvm-measurement-policy.mjs"),
    import("./pre-ceremony-runtime-authority.mjs"),
    import("./release-ceremony-authorization.mjs"),
    import("./phala-seven-cvm-historical-transcript.mjs"),
  ]);

  const authority = normalizePhalaSevenCvmReleaseVerificationAuthority(
    releaseVerificationAuthority,
  );
  const authoritySha256 =
    phalaSevenCvmReleaseVerificationAuthoritySha256(authority);
  const signedA =
    bootstrapModule.assertHistoricallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt(
      signedAReceipt,
    );
  const signedASha256 =
    bootstrapModule.phalaNonLiveBootstrapAuthorizationReceiptSha256(signedA);
  const executor = executorModule.normalizeCompletedPhalaExecutorState(
    executorFinalState,
  );
  const executorSha256 = executorModule.phalaExecutorStateDigest(executor);
  const runtime = runtimeModule.normalizePreCeremonyRuntimeAuthority(
    persistedRuntimeAuthority,
  );
  const runtimeSha256 = runtimeModule.preCeremonyRuntimeAuthoritySha256(runtime);
  const transcript =
    transcriptModule.normalizePhalaSevenCvmHistoricalTranscriptFileSet(
      historicalTranscriptFileSet,
    );
  const transcriptSha256 =
    transcriptModule.phalaSevenCvmHistoricalTranscriptFileSetSha256(transcript);
  const launchSha256 = launchModule.phalaSevenCvmLaunchCompletionReceiptSha256(
    launchCompletionReceipt,
    launchCompletionOptions,
  );
  const descriptorSet = descriptorSetModule.normalizeCvmReleaseDescriptorSetReceipt(
    descriptorSetReceipt,
  );
  const descriptorSetSha256 =
    descriptorSetModule.cvmReleaseDescriptorSetReceiptSha256(descriptorSet);
  const stageOneSignedAtMs = Date.parse(
    persistedCeremonyAuthorization?.review?.signed_at,
  );
  if (!Number.isSafeInteger(stageOneSignedAtMs) || stageOneSignedAtMs < 1) {
    throw new TypeError("historical signed B has no canonical original signing time");
  }
  const ceremonyOptions = {
    deploymentIntent: dependencies.deploymentIntent,
    freshContractDeploymentReceipt:
      dependencies.freshContractDeploymentReceipt,
    reviewerGenesis: dependencies.reviewerGenesis,
    reviewerGenesisAcceptance: dependencies.reviewerGenesisAcceptance,
    reviewerStatusHistory: dependencies.reviewerStatusHistory,
    preCeremonyRuntimeAuthority: runtime,
    checkedAtMs: stageOneSignedAtMs,
    enforceFreshness: false,
  };
  const ceremony = ceremonyModule.normalizeCeremonyAuthorizationCore(
    persistedCeremonyAuthorization,
    ceremonyOptions,
  );
  const ceremonySha256 = ceremonyModule.ceremonyAuthorizationCoreSha256(
    ceremony,
    ceremonyOptions,
  );
  const reviewerAcceptanceSha256 =
    ceremony.deployment_authority.reviewer_authority_genesis_acceptance_sha256;
  const freshContract = contractModule.normalizeFreshContractDeploymentReceipt(
    dependencies.freshContractDeploymentReceipt,
    {
      expectedDeploymentIntentSha256: authority.deployment_intent_sha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        reviewerAcceptanceSha256,
    },
  );
  const freshContractSha256 = `sha256:${contractModule
    .freshContractDeploymentReceiptDigest(freshContract, {
      expectedDeploymentIntentSha256: authority.deployment_intent_sha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        reviewerAcceptanceSha256,
    })}`;
  const diligenceRoom = contract(freshContract, "DiligenceRoom");
  const computeVault = contract(freshContract, "ComputeCreditVault");
  const descriptorRuntime = authority.cvm_descriptor_runtime_authority;
  const plan = runtime.post_measurement_activation_plan;
  const launch = launchCompletionReceipt;

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
    authority.ceremony_nonce,
    `0x${signedA.authorization_id.slice("sha256:".length)}`,
    "authority signed-A ceremony nonce",
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
    "authority activation-plan ceremony nonce",
  );
  const computeWorkloadPolicy = authority.qvl_measurement_policies.find(
    ({ domain }) => domain === "compute_workload_qvl_cvm",
  );
  if (!computeWorkloadPolicy) {
    throw new TypeError("authority omits the compute-workload QVL measurement policy");
  }
  equal(
    measurementPolicyModule.phalaQvlMeasurementPolicySha256(
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
  if (canonicalPhalaSevenCvmReleaseVerificationAuthorityText(
    plan.release_verification_authority,
  ) !== canonicalPhalaSevenCvmReleaseVerificationAuthorityText(authority)) {
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

function isExactNodeTestEntrypoint() {
  const entrypoint = process.argv[1];
  if (process.env.NODE_TEST_CONTEXT !== "child-v8"
    || typeof entrypoint !== "string" || !entrypoint.endsWith(".test.mjs")) {
    return false;
  }
  try {
    return path.resolve(entrypoint) === fs.realpathSync.native(entrypoint);
  } catch {
    return false;
  }
}

function createSyntheticHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority({
  authority,
  metadata,
} = {}) {
  if (!isExactNodeTestEntrypoint()) {
    throw new TypeError(
      "synthetic historical release authority is available only inside node --test",
    );
  }
  // Normalization always creates a distinct object. A fresh authority brand is
  // therefore never upgraded in-place to the historical restart brand.
  return brandHistoricalAuthority(authority, metadata);
}

export const __test = Object.freeze({
  createSyntheticHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority,
});
