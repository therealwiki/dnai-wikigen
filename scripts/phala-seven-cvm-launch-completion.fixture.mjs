import {
  BASE_SEPOLIA_CHAIN_ID,
  CVM_LAUNCH_DESCRIPTOR_FILES,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import { PHALA_EXECUTION_ORDER } from "./phala-production-posture-core.mjs";
import {
  PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  createPhalaSevenCvmHistoricalTranscriptFileSet,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";
import {
  PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_SCHEMA,
  PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_STATUS,
  PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_TRUTH,
  PHALA_SEVEN_CVM_COMPLETION_ORDER,
  PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA,
  PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_STATUS,
  PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_TRUTH,
} from "./phala-seven-cvm-launch-completion-core.mjs";

const sha = (index) => `sha256:${index.toString(16).padStart(64, "0")}`;
const bare = (index) => index.toString(16).padStart(64, "0");
const app = (index) => index.toString(16).padStart(40, "0");
const address = (index) => `0x${index.toString(16).padStart(40, "0")}`;
const at = (seconds) => new Date(Date.UTC(2026, 6, 21, 10, 0, seconds))
  .toISOString().replace(".000Z", "Z");
const epoch = (seconds) => Math.floor(Date.parse(at(seconds)) / 1_000);

export function syntheticPhalaSevenCvmLaunchCompletionFixture() {
  const diligenceRoomAddress = address(900);
  const computeCreditVaultAddress = address(901);
  const descriptors = Object.fromEntries(PHALA_SEVEN_CVM_COMPLETION_ORDER.map(
    (domain, index) => [domain, sha(40 + index)],
  ));
  const authorityByDomain = Object.fromEntries(PHALA_SEVEN_CVM_COMPLETION_ORDER.map(
    (domain, globalIndex) => {
      const mutationIndex = PHALA_EXECUTION_ORDER.indexOf(domain);
      const workload = domain === "main_runtime_cvm"
        || domain === "independent_metering_cvm";
      return [domain, {
        domain,
        descriptor_file: CVM_LAUNCH_DESCRIPTOR_FILES[domain],
        descriptor_sha256: descriptors[domain],
        app_id: app(100 + globalIndex),
        cvm_id: `cvm-node-${String(globalIndex + 1).padStart(2, "0")}`,
        committed_compose_hash: bare(200 + globalIndex),
        kms_id: `kms-role-${String(globalIndex + 1).padStart(4, "0")}`,
        instance_type: "tdx.medium",
        disk_size: 80 + globalIndex,
        os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
        provision_attempted_at: at(10 + mutationIndex * 4),
        provision_observed_at: at(11 + mutationIndex * 4),
        commit_attempted_at: at(60 + mutationIndex * 4),
        commit_observed_at: at(61 + mutationIndex * 4),
        production_posture_verified_at: at(120 + globalIndex),
        machine_evidence_verified_at: epoch(180 + globalIndex),
        activation_evidence_lease_expires_at: epoch(1_080 + globalIndex),
        provision_observation_sha256: sha(300 + globalIndex),
        commit_observation_sha256: sha(320 + globalIndex),
        production_posture_verification_receipt_sha256: sha(340 + globalIndex),
        machine_evidence_kind: workload
          ? "workload_independent_signed_qvl_verdict"
          : "qvl_identity_local_dcap_verification",
        machine_evidence_sha256: sha(360 + globalIndex),
        tdx_attestation_evidence_sha256: sha(380 + globalIndex),
        tdx_attestation_verification_receipt_sha256: sha(400 + globalIndex),
        tdx_measurements_sha256: workload ? null : sha(410 + globalIndex),
        tdx_measurement_authority_sha256: sha(420 + globalIndex),
        qvl_release_policy_sha256: sha(440 + globalIndex),
        qvl_verification_receipt_sha256: sha(460 + globalIndex),
        qvl_identity_sha256: sha(480 + globalIndex),
        tee_identity: address(500 + globalIndex),
        bound_contract_name: domain === "main_runtime_cvm"
          ? "DiligenceRoom"
          : domain === "independent_metering_cvm"
            ? "ComputeCreditVault"
            : null,
        bound_contract_address: domain === "main_runtime_cvm"
          ? diligenceRoomAddress
          : domain === "independent_metering_cvm"
            ? computeCreditVaultAddress
            : null,
        private_historical_transcript_contains_quote_bytes: !workload,
        raw_quote_external_egress: false,
        raw_secret_egress: false,
      }];
    },
  ));
  const transcriptFileSet = createPhalaSevenCvmHistoricalTranscriptFileSet(
    Object.fromEntries(PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map(
      (flag, index) => [flag, { sha256: sha(600 + index), size: 1_000 + index }],
    )),
  );
  const transcriptFileSetSha256 =
    phalaSevenCvmHistoricalTranscriptFileSetSha256(transcriptFileSet);
  const expectedAuthority = {
    release_sha: "1".repeat(40),
    deployment_intent_sha256: sha(1),
    reviewer_authority_genesis_acceptance_sha256: sha(2),
    fresh_contract_deployment_receipt_sha256: sha(3),
    diligence_room_address: diligenceRoomAddress,
    compute_credit_vault_address: computeCreditVaultAddress,
    cvm_launch_intent_sha256: sha(4),
    nonlive_bootstrap_authorization_receipt_sha256: sha(5),
    bootstrap_authorization_id: sha(6),
    batch_id: sha(7),
    bootstrap_authorization_issued_at: at(0),
    bootstrap_authorization_expires_at: at(600),
    production_target_authority_sha256: sha(8),
    image_release_manifest_sha256: sha(9),
    image_release_sigstore_verification_receipt_sha256: sha(10),
    image_release_sigstore_bundle_sha256: sha(11),
    topology_sha256: sha(12),
    descriptor_set_receipt_sha256: sha(13),
    executor_final_state_sha256: sha(14),
    phala_recovery_directory_identity_anchor_sha256: sha(16),
    machine_verifier_evidence_set_sha256: sha(15),
    machine_verifier_evidence_mode: PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
    machine_verifier_verified_at: Math.max(...Object.values(authorityByDomain)
      .map((entry) => entry.machine_evidence_verified_at)),
    activation_evidence_lease_expires_at:
      Math.min(...Object.values(authorityByDomain)
        .map((entry) => entry.activation_evidence_lease_expires_at)),
    machine_verifier_evidence_issued_at:
      Math.max(...Object.values(authorityByDomain)
        .map((entry) => entry.machine_evidence_verified_at)) + 1,
    historical_transcript_persistence_receipt_sha256: sha(599),
    historical_transcript_file_set_sha256: transcriptFileSetSha256,
    transcript_file_set: transcriptFileSet,
    descriptor_sha256_by_domain: descriptors,
    domain_completion_authority_by_domain: authorityByDomain,
  };
  const releaseDescriptors = PHALA_SEVEN_CVM_COMPLETION_ORDER.map((domain) => {
    const completion = authorityByDomain[domain];
    return {
      domain,
      descriptor_sha256: completion.descriptor_sha256,
      app_id: completion.app_id,
      cvm_id: completion.cvm_id,
      compose_hash: completion.committed_compose_hash,
      os_image_hash: completion.os_image_hash,
      posture_receipt_sha256:
        completion.production_posture_verification_receipt_sha256,
      posture_observed_at: completion.production_posture_verified_at,
      kms_id: completion.kms_id,
      instance_type: completion.instance_type,
      disk_size: completion.disk_size,
    };
  });
  const syntheticReleaseAuthority =
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture({
      releaseSha: expectedAuthority.release_sha,
      deploymentIntentSha256: expectedAuthority.deployment_intent_sha256,
      bootstrapAuthorizationReceiptSha256:
        expectedAuthority.nonlive_bootstrap_authorization_receipt_sha256,
      freshContractDeploymentReceiptSha256:
        expectedAuthority.fresh_contract_deployment_receipt_sha256,
      diligenceRoom: diligenceRoomAddress,
      computeCreditVault: computeCreditVaultAddress,
      releaseDescriptors,
    });
  const releaseVerificationAuthority =
    normalizePhalaSevenCvmReleaseVerificationAuthority({
      ...syntheticReleaseAuthority,
      evidence_mode: PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
    });
  expectedAuthority.release_verification_authority =
    releaseVerificationAuthority;
  expectedAuthority.release_verification_authority_sha256 =
    phalaSevenCvmReleaseVerificationAuthoritySha256(
      releaseVerificationAuthority,
    );
  expectedAuthority.descriptor_set_receipt_sha256 =
    releaseVerificationAuthority.cvm_descriptor_runtime_authority
      .descriptor_set_receipt_sha256;
  expectedAuthority.image_release_manifest_sha256 =
    releaseVerificationAuthority.cvm_descriptor_runtime_authority
      .image_manifest_sha256;
  expectedAuthority.topology_sha256 =
    releaseVerificationAuthority.cvm_descriptor_runtime_authority
      .topology_sha256;
  const domains = PHALA_SEVEN_CVM_COMPLETION_ORDER.map((domain) => ({
    schema: PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_SCHEMA,
    status: PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_STATUS,
    truth_status: PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_TRUTH,
    ...authorityByDomain[domain],
  }));
  const receipt = {
    schema: PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA,
    status: PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_STATUS,
    truth_status: PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_TRUTH,
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    release_sha: expectedAuthority.release_sha,
    deployment_intent_sha256: expectedAuthority.deployment_intent_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      expectedAuthority.reviewer_authority_genesis_acceptance_sha256,
    fresh_contract_deployment_receipt_sha256:
      expectedAuthority.fresh_contract_deployment_receipt_sha256,
    cvm_launch_intent_sha256: expectedAuthority.cvm_launch_intent_sha256,
    nonlive_bootstrap_authorization_receipt_sha256:
      expectedAuthority.nonlive_bootstrap_authorization_receipt_sha256,
    bootstrap_authorization_id: expectedAuthority.bootstrap_authorization_id,
    batch_id: expectedAuthority.batch_id,
    production_target_authority_sha256:
      expectedAuthority.production_target_authority_sha256,
    image_release_manifest_sha256: expectedAuthority.image_release_manifest_sha256,
    image_release_sigstore_verification_receipt_sha256:
      expectedAuthority.image_release_sigstore_verification_receipt_sha256,
    image_release_sigstore_bundle_sha256:
      expectedAuthority.image_release_sigstore_bundle_sha256,
    topology_sha256: expectedAuthority.topology_sha256,
    descriptor_set_receipt_sha256: expectedAuthority.descriptor_set_receipt_sha256,
    executor_final_state_sha256: expectedAuthority.executor_final_state_sha256,
    phala_recovery_directory_identity_anchor_sha256:
      expectedAuthority.phala_recovery_directory_identity_anchor_sha256,
    machine_verifier_evidence_set_sha256:
      expectedAuthority.machine_verifier_evidence_set_sha256,
    machine_verifier_evidence_mode: PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
    machine_verifier_evidence_issued_at:
      expectedAuthority.machine_verifier_evidence_issued_at,
    activation_evidence_lease_expires_at:
      expectedAuthority.activation_evidence_lease_expires_at,
    release_verification_authority_sha256:
      expectedAuthority.release_verification_authority_sha256,
    historical_transcript_persistence_receipt_sha256:
      expectedAuthority.historical_transcript_persistence_receipt_sha256,
    historical_transcript_file_set_sha256:
      expectedAuthority.historical_transcript_file_set_sha256,
    transcript_file_set: expectedAuthority.transcript_file_set,
    completion_order: [...PHALA_SEVEN_CVM_COMPLETION_ORDER],
    mutation_order: [...PHALA_EXECUTION_ORDER],
    domains,
    completed_at: expectedAuthority.machine_verifier_verified_at,
    commit_count: 7,
    all_seven_committed: true,
    all_seven_production_posture_validated: true,
    five_qvl_identities_machine_verified: true,
    two_workload_verdicts_machine_verified: true,
    all_seven_machine_verified: true,
    live_traffic_authorized: false,
    late_secret_activation_authorized: false,
    compute_workload_recipient_activation_authorized: false,
    private_historical_transcript_persisted: true,
    private_historical_transcript_contains_raw_quote_and_collateral: true,
    private_historical_identity_response_quote_bytes_persisted: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_quote_external_egress: false,
    raw_private_artifact_egress: false,
    raw_secret_egress: false,
  };
  return { expectedAuthority, receipt };
}
