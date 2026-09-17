// SYNTHETIC CURRENT-PREBUILD ORCHESTRATION FIXTURE ONLY.
// Real current schemas and O EIP-191 signatures; no Intel DCAP claim, provider
// receipt, reviewer authorization, or production brand is created here.
// Tests replace the authenticated A/L/R/B/DCAP prefix with these inert facts.
import { createHash } from "node:crypto";
import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";
import { syntheticPhalaSevenCvmVerifierEvidenceFixture } from "./phala-seven-cvm-verifier-evidence.fixture.mjs";
import { syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture } from "./current-cvm-authority-v5.fixture.mjs";
import { phalaSevenCvmReleaseVerificationAuthoritySha256 } from "./phala-seven-cvm-release-verification-authority-v5-core.mjs";
import {
  independentTdxVerdictSigningDigest,
  normalizePhalaComputeWorkloadRecipientActivationVerification,
  phalaComputeWorkloadRecipientSourceActivationSha256,
} from "./phala-seven-cvm-historical-evidence-core.mjs";
import {
  syntheticPostMeasurementActivationPlanFixture,
  syntheticPreCeremonyRuntimeAuthorityFromPlanFixture,
} from "./pre-ceremony-runtime-authority.fixture.mjs";
import {
  normalizePhalaPostMeasurementActivationPlan,
} from "./phala-post-measurement-activation-core.mjs";
import { preCeremonyRuntimeAuthoritySha256 } from "./pre-ceremony-runtime-authority-core.mjs";
import { createUnbrandedComputeWorkloadActivationObservationCandidate } from "./compute-workload-activation-observation-core.mjs";
import * as receiptCore from "./phala-post-measurement-activation-receipt-v4-core.mjs";

const {
  PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
  PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_STATUS,
  PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_TRUTH,
  PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE,
  PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
  normalizePhalaPostMeasurementActivationExecutionReceipt,
  phalaArenaWorkerPresenceActivationProofSha256,
  phalaCombinedArenaComputeActivationVerificationSha256,
} = receiptCore;
const pin = (pair) => `sha256:${pair.repeat(32)}`;
const word = (pair) => `0x${pair.repeat(32)}`;
const canonical = (value) => Array.isArray(value) ? value.map(canonical)
  : value && typeof value === "object"
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]))
    : value;
const digest = (domain, value, compact = false) => "sha256:" + createHash("sha256")
  .update(domain).update(compact ? JSON.stringify(canonical(value))
    : JSON.stringify(canonical(value), null, 2) + "\n").digest("hex");
const instant = (seconds) => new Date(seconds * 1_000).toISOString().replace(".000Z", "Z");

function activationExecutionReceiptForObservation(observation) {
  const verifiedAt = observation.verification.verified_at;
  const authenticatedAt = observation.verification.authenticated_at;
  const instant = (seconds) => new Date(seconds * 1_000)
    .toISOString().replace(".000Z", "Z");
  const profileActivation = {
    profile_names: ["arena-runtime", "compute-execution"],
    compose_profiles_value: "arena-runtime,compute-execution",
  };
  const arenaWorkerPresence = {
    schema: PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
    heartbeat_schema: PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
    evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
    endpoint_commitment_sha256: pin("e7"),
    challenge_id: "dnaseq-variant-qc-safe-ir",
    challenge_version: "1.0.0",
    response_sha256: pin("e8"),
    release_binding_sha256: pin("e9"),
    heartbeat_observed_at: authenticatedAt,
    verified_at: authenticatedAt,
  };
  const arenaWorkerPresenceSha256 =
    phalaArenaWorkerPresenceActivationProofSha256(arenaWorkerPresence);
  const computeRecipientActivationSha256 =
    observation.verification.activation_verification_sha256;
  return normalizePhalaPostMeasurementActivationExecutionReceipt({
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
    status: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_STATUS,
    truth_status: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_TRUTH,
    chain_id: 84_532,
    release_sha: observation.release_sha,
    batch_id: pin("d0"),
    deployment_intent_sha256: observation.lineage.deployment_intent_sha256,
    cvm_launch_intent_sha256: pin("d1"),
    release_verification_authority_sha256:
      observation.lineage.release_verification_authority_sha256,
    seven_cvm_launch_completion_receipt_sha256:
      observation.lineage.seven_cvm_launch_completion_receipt_sha256,
    seven_cvm_verified_evidence_set_sha256:
      observation.lineage.seven_cvm_verified_evidence_set_sha256,
    phala_recovery_directory_identity_anchor_sha256: pin("d2"),
    pre_ceremony_runtime_authority_sha256:
      observation.lineage.pre_ceremony_runtime_authority_sha256,
    post_measurement_activation_plan_sha256:
      observation.lineage.post_measurement_activation_plan_sha256,
    ceremony_authorization_sha256:
      observation.lineage.ceremony_authorization_sha256,
    target: {
      domain: "main_runtime_cvm",
      descriptor_sha256: observation.main_runtime.descriptor_sha256,
      app_id: observation.main_runtime.app_id,
      cvm_id: observation.main_runtime.cvm_id,
      compose_hash: observation.main_runtime.compose_hash,
      os_image_hash: observation.main_runtime.os_image_hash,
    },
    profile_activation: profileActivation,
    runtime_commitments_sha256: pin("d3"),
    runtime_commitment_key_names_sha256: pin("d4"),
    allowed_environment_key_names_sha256: pin("d5"),
    allowed_environment_key_count: 2,
    injected_environment_key_names_sha256: pin("d6"),
    injected_environment_key_count: 1,
    private_environment_assembly_receipt_sha256: pin("d7"),
    adapter_identity_sha256: pin("d8"),
    activation_journal_state_sha256: pin("d9"),
    activation_journal_sha256: pin("da"),
    mutation_sequence: [...PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE],
    patch: {
      sdk_action: "updateCvmEnvs",
      call_sequence: 6,
      request_semantics_sha256: pin("db"),
      observation_sha256: pin("dc"),
      response_sha256: pin("dd"),
      body_field_names: ["encrypted_env"],
      encrypted_environment_only: true,
      allowed_environment_keys_mutated: false,
      attempt_recorded_at: instant(authenticatedAt - 5),
      observed_at: instant(authenticatedAt - 4),
      finalized_readiness: {
        readiness_sha256: pin("de"),
        finalized_block_number: 30_000_000,
        finalized_block_hash: word("d0"),
      },
    },
    restart: {
      sdk_action: "restartCvm",
      call_sequence: 7,
      request_semantics_sha256: pin("df"),
      observation_sha256: pin("e0"),
      response_sha256: pin("e1"),
      force: false,
      attempt_recorded_at: instant(authenticatedAt - 3),
      observed_at: instant(authenticatedAt - 2),
      finalized_readiness: {
        readiness_sha256: pin("e2"),
        finalized_block_number: 30_000_001,
        finalized_block_hash: word("d1"),
      },
    },
    post_restart_evidence: {
      get_cvm_info_call_sequence: 8,
      get_cvm_info_observation_sha256: pin("e3"),
      get_cvm_info_response_sha256: pin("e4"),
      get_cvm_info_observed_at: instant(authenticatedAt - 1),
      get_cvm_attestation_call_sequence: 9,
      get_cvm_attestation_observation_sha256: pin("e5"),
      get_cvm_attestation_response_sha256: pin("e6"),
      get_cvm_attestation_observed_at: instant(authenticatedAt - 1),
      cvm_online: true,
      attestation_error_absent: true,
      tcb_info_present: true,
      app_certificate_quote_present: true,
      pre_injection_attestation_sufficient: false,
    },
    arena_worker_presence: arenaWorkerPresence,
    arena_worker_presence_sha256: arenaWorkerPresenceSha256,
    recipient_activation: {
      activation_verification_sha256:
        computeRecipientActivationSha256,
      source_activation_sha256:
        observation.verification.activation_artifact_sha256,
      raw_transcript_sha256: observation.verification.raw_transcript_sha256,
      qvl_verdict_verifier_signature_sha256:
        observation.verification.qvl_verdict_verifier_signature_sha256,
      tdx_quote_sha256: observation.verification.tdx_quote_sha256,
      challenge_id: observation.verification.challenge_id,
      report_data: observation.recipient.report_data,
      recipient_key_id: observation.recipient.recipient_key_id,
      recipient_release_commitment:
        observation.recipient.recipient_release_commitment,
      authenticated_at: authenticatedAt,
      verified_at: verifiedAt,
      verdict_activation_evidence_lease_expires_at:
        observation.verification
          .verdict_activation_evidence_lease_expires_at,
      recipient_evidence_lease_expires_at:
        observation.recipient_evidence_lease_expires_at,
      expires_at: observation.verification.activation_verification_expires_at,
      post_restart_source_activation: true,
    },
    compute_recipient_activation_sha256: computeRecipientActivationSha256,
    combined_activation_verification_sha256:
      phalaCombinedArenaComputeActivationVerificationSha256({
        profileActivation,
        arenaWorkerPresenceSha256,
        computeRecipientActivationSha256,
      }),
    initial_activation_evidence_lease_expires_at:
      observation.initial_activation_evidence_lease_expires_at,
    recipient_evidence_lease_expires_at:
      observation.recipient_evidence_lease_expires_at,
    terminal_evidence_lease_expires_at:
      observation.terminal_evidence_lease_expires_at,
    completed_at: instant(verifiedAt),
    automatic_retry_authorized: false,
    ambiguous_outcome_quarantine_required: true,
    pre_injection_attestation_sufficient: false,
    raw_quote_persisted: false,
    raw_secret_egress: false,
    ciphertext_persisted: false,
    live_traffic_authorized: false,
  });
}

/** Re-sign only synthetic test material for the explicit current v5 authority. */
async function currentActivationFixture({ invalidSignature = false } = {}) {
  const base = await syntheticPhalaSevenCvmVerifierEvidenceFixture();
  const legacy = base.releaseAuthority;
  const releaseAuthority = syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture({
    releaseSha: "a".repeat(40),
    deploymentIntentSha256: legacy.deployment_intent_sha256,
    bootstrapAuthorizationReceiptSha256: legacy.bootstrap_authorization_receipt_sha256,
    ceremonyNonce: legacy.ceremony_nonce,
    freshContractDeploymentReceiptSha256: legacy.contracts.fresh_contract_deployment_receipt_sha256,
    diligenceRoom: legacy.contracts.diligence_room,
    computeCreditVault: legacy.contracts.compute_credit_vault,
    computeCreditVaultRuntimeCodeHash: legacy.contracts.compute_credit_vault_runtime_code_hash,
    qvlMeasurementPolicies: legacy.qvl_measurement_policies,
    releaseDescriptors: legacy.descriptors,
  });
  const authoritySha256 = phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  const activation = structuredClone(base.computeWorkloadActivationEvidence);
  const source = activation.source_activation;
  const verdict = source.authenticated_verdict;
  source.release_authority_sha256 = authoritySha256;
  verdict.release_authority_sha256 = authoritySha256;
  const challenge = {
    schema: "dnai.attestation-qvl-challenge.v2",
    chain_id: 84_532,
    domain: verdict.domain,
    profile: verdict.profile,
    cvm_id: verdict.cvm_id,
    deployment_intent_sha256: verdict.deployment_intent_sha256,
    release_authority_sha256: verdict.release_authority_sha256,
    ceremony_nonce: verdict.ceremony_nonce,
    measurement_policy_sha256: verdict.measurement_policy_sha256,
    release_policy_hash: verdict.release_policy_hash,
    challenge_id: verdict.challenge_id,
    issued_at: verdict.challenge_issued_at,
    expires_at: verdict.challenge_expires_at,
    verifier_address: verdict.verifier_address,
  };
  verdict.challenge_digest = "0x" + digest(
    "dnai-wikigen/attestation-qvl/challenge/v2\0", challenge, true,
  ).slice(7);
  const signingDigest = independentTdxVerdictSigningDigest(verdict);
  // This is the documented, public synthetic Compute-QVL test key, not a wallet.
  const testSigner = privateKeyToAccount("0x" + "44".repeat(32));
  if (testSigner.address.toLowerCase() !== verdict.verifier_address) {
    throw new Error("synthetic Compute-QVL fixture signer changed");
  }
  const signer = invalidSignature ? privateKeyToAccount("0x" + "55".repeat(32)) : testSigner;
  verdict.verifier_signature = (await signer.signMessage({ message: { raw: signingDigest } })).toLowerCase();
  source.verdict_digest = signingDigest;
  const releasePayload = {
    schema: "dnai.compute.workload-recipient-release.v2",
    chain_id: 84_532,
    domain: source.domain,
    profile: source.profile,
    cvm_id: source.cvm_id,
    deployment_intent_sha256: source.deployment_intent_sha256,
    release_authority_sha256: source.release_authority_sha256,
    ceremony_nonce: source.ceremony_nonce,
    measurement_policy_set_sha256: source.measurement_policy_set_sha256,
    measurement_policy_sha256: source.measurement_policy_sha256,
    main_runtime_evidence_sha256: source.main_runtime_evidence_sha256,
    recipient_key_id: source.recipient_key_id,
    report_data: source.report_data,
    compose_hash: source.compose_hash,
    app_id: source.app_id,
    os_image_hash: source.os_image_hash,
    release_policy_hash: source.release_policy_hash,
    verifier_address: source.verifier_address,
    verification_method: verdict.verification_method,
    signer_address: verdict.signer_address,
    contract_address: verdict.contract_address,
    recipient_attestation: source.recipient_attestation,
  };
  source.recipient_release_commitment = digest(
    "dnai-wikigen/compute-workload-recipient-release/v2\0", releasePayload, true,
  );
  const sourceSha256 = phalaComputeWorkloadRecipientSourceActivationSha256(source);
  const verdictSha256 = digest("dnai-wikigen/independent-tdx-verdict-artifact/v4\0", verdict);
  Object.assign(activation, {
    release_authority_sha256: authoritySha256,
    challenge_digest: verdict.challenge_digest,
    qvl_verdict_signing_digest: signingDigest,
    qvl_verdict_artifact_sha256: verdictSha256,
    activation_artifact_sha256: sourceSha256,
    recipient_release_commitment: source.recipient_release_commitment,
    qvl_verdict_verifier_signature_sha256: "sha256:" + createHash("sha256")
      .update("dnai-wikigen/release-authority-signature/v1\0")
      .update(Buffer.from(verdict.verifier_signature.slice(2), "hex")).digest("hex"),
    raw_transcript_sha256: digest("dnai-wikigen/phala-raw-verifier-transcript/v1\0", {
      schema: "dnai.phala-raw-verifier-transcript.v1",
      chain_id: 84_532,
      domain: "main_runtime_cvm",
      kind: "compute_workload_recipient_activation",
      artifact_sha256: [sourceSha256, verdictSha256],
    }),
  });
  return {
    now: base.now,
    initialLease: base.evidenceSet.minimum_activation_evidence_lease_expires_at,
    releaseAuthority,
    activation: normalizePhalaComputeWorkloadRecipientActivationVerification(activation),
  };
}

export async function createCurrentPrebuildObservationFixture(options = {}) {
  const { now, initialLease, releaseAuthority, activation } = await currentActivationFixture(options);
  // Construct R first. Neither its hash nor the standalone receipt needs C/D/O.
  const planRaw = structuredClone(syntheticPostMeasurementActivationPlanFixture({
    releaseSha: releaseAuthority.release_sha,
    deploymentIntentSha256: releaseAuthority.deployment_intent_sha256,
    cvmLaunchIntentSha256: pin("e2"),
    // The shared fixture still builds a historical plan; replace its authority
    // explicitly and rehash below. No historical digest is reinterpreted.
    createdAt: instant(now - 20),
    activationEvidenceLeaseExpiresAt: initialLease,
  }));
  planRaw.release_verification_authority = releaseAuthority;
  planRaw.release_verification_authority_sha256 = phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  planRaw.seven_cvm_verified_evidence_set_sha256 = pin("92");
  const main = releaseAuthority.descriptors.find((entry) => entry.domain === "main_runtime_cvm");
  const qvl = releaseAuthority.descriptors.find((entry) => entry.domain === "compute_workload_qvl_cvm");
  planRaw.target = Object.fromEntries(["domain", "descriptor_sha256", "app_id", "cvm_id", "compose_hash", "os_image_hash"]
    .map((key) => [key, main[key]]));
  Object.assign(planRaw.runtime_commitments, {
    TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE: releaseAuthority.ceremony_nonce,
    TINKER_COMPUTE_WORKLOAD_CVM_ID: main.cvm_id,
    TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256: releaseAuthority.deployment_intent_sha256,
    TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256: activation.main_runtime_evidence_sha256,
    TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256: releaseAuthority.qvl_measurement_policy_set_sha256,
    TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256: activation.measurement_policy_sha256,
    TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256: planRaw.release_verification_authority_sha256,
  });
  planRaw.environment_update.request_path = `/api/v1/cvms/${main.cvm_id}/envs`;
  planRaw.restart.request_path = `/api/v1/cvms/${main.cvm_id}/restart`;
  const plan = normalizePhalaPostMeasurementActivationPlan(planRaw);
  const runtime = syntheticPreCeremonyRuntimeAuthorityFromPlanFixture({ postMeasurementActivationPlan: plan });
  const runtimeSha256 = preCeremonyRuntimeAuthoritySha256(runtime);
  const binding = {
    capability_endpoint: "https://compute.release.wikigen.me/compute/workload-encryption-contract",
    historical_transcript_file_set_sha256: runtime.historical_transcript_file_set_sha256,
    seven_cvm_launch_completion_receipt_sha256: runtime.seven_cvm_launch_completion_receipt_sha256,
    seven_cvm_verified_evidence_set_sha256: plan.seven_cvm_verified_evidence_set_sha256,
    pre_ceremony_runtime_authority_sha256: runtimeSha256,
    post_measurement_activation_plan_sha256: runtime.post_measurement_activation_plan_sha256,
    post_measurement_activation_execution_receipt_sha256: pin("e4"),
    ceremony_authorization_sha256: pin("bc"),
    initial_activation_evidence_lease_expires_at: initialLease,
    recipient_evidence_lease_expires_at: activation.recipient_evidence_lease_expires_at,
    terminal_evidence_lease_expires_at: Math.min(initialLease, activation.recipient_evidence_lease_expires_at),
    ingress_policy: { max_verdict_age_seconds: 120, revoked_quote_hashes: [] },
  };
  // Temporary O is a data-only projection of the independent signed source;
  // the receipt has no O digest. Its digest then becomes the final O parent.
  const provisional = createUnbrandedComputeWorkloadActivationObservationCandidate({
    activationVerification: activation, releaseVerificationAuthority: releaseAuthority, authorityBinding: binding,
  });
  const receiptRaw = structuredClone(activationExecutionReceiptForObservation(provisional));
  Object.assign(receiptRaw, {
    batch_id: plan.batch_id,
    cvm_launch_intent_sha256: runtime.cvm_launch_intent_sha256,
    phala_recovery_directory_identity_anchor_sha256: runtime.phala_recovery_directory_identity_anchor_sha256,
    runtime_commitments_sha256: receiptCore.phalaPostMeasurementRuntimeCommitmentsSha256(plan.runtime_commitments),
    runtime_commitment_key_names_sha256: plan.runtime_commitment_key_names_sha256,
    allowed_environment_key_names_sha256: plan.allowed_environment_key_names_sha256,
    allowed_environment_key_count: plan.allowed_environment_key_count,
    injected_environment_key_names_sha256: plan.injected_environment_key_names_sha256,
    injected_environment_key_count: plan.injected_environment_key_names.length,
  });
  const receipt = normalizePhalaPostMeasurementActivationExecutionReceipt(receiptRaw);
  binding.post_measurement_activation_execution_receipt_sha256 = receiptCore.phalaPostMeasurementActivationExecutionReceiptSha256(receipt);
  const observation = createUnbrandedComputeWorkloadActivationObservationCandidate({
    activationVerification: activation, releaseVerificationAuthority: releaseAuthority, authorityBinding: binding,
  });
  const mainLaunch = {
    ...main,
    committed_compose_hash: main.compose_hash,
    production_posture_verification_receipt_sha256: main.posture_receipt_sha256,
    tee_identity: activation.main_runtime_signer_address,
    machine_evidence_sha256: activation.main_runtime_evidence_sha256,
  };
  const qvlLaunch = {
    ...qvl,
    committed_compose_hash: qvl.compose_hash,
    tee_identity: activation.qvl_verdict_verifier_address,
    qvl_release_policy_sha256: activation.qvl_release_policy_sha256,
    tdx_measurement_authority_sha256: activation.measurement_policy_sha256,
    machine_evidence_sha256: activation.qvl_identity_evidence_sha256,
  };
  const marker = (kind) => ({ synthetic_authenticated_prefix_boundary: kind });
  const authority = {
    intent: marker("intent"), intentSha256: runtime.deployment_intent_sha256,
    genesis: marker("genesis"), acceptance: marker("acceptance"),
    genesisSha256: pin("a1"), acceptanceSha256: pin("a2"),
    freshContractDescriptorTuple: { authority_tuple: "current" },
    contract: { contracts: [{ name: "ComputeCreditVault", address: activation.compute_vault_address,
      runtime_code_hash: activation.compute_vault_runtime_code_hash }] },
    contractSha256: releaseAuthority.contracts.fresh_contract_deployment_receipt_sha256,
    bootstrapAuthority: { domains: [{ domain: "main_runtime_cvm", values: {
      TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE: releaseAuthority.ceremony_nonce,
    } }] },
    bootstrapAuthoritySha256: pin("a3"), bootstrapAuthorizationSha256: pin("a4"),
    signedAReceipt: { qvl_measurement_policy_set_sha256: releaseAuthority.qvl_measurement_policy_set_sha256 },
    signedAReceiptSha256: releaseAuthority.bootstrap_authorization_receipt_sha256,
    executor: marker("executor"),
    launchReceipt: { batch_id: plan.batch_id, domains: [mainLaunch, qvlLaunch] },
    launchSha256: runtime.seven_cvm_launch_completion_receipt_sha256,
    runtimeAuthority: runtime, persistedRuntimeAuthority: runtime,
    runtimeAuthoritySha256: runtimeSha256,
    stageOne: { review: { signed_at: instant(now - 10), expires_at: instant(now + 120) } },
    stageOneSha256: binding.ceremony_authorization_sha256,
    reviewerReconstruction: marker("reviewers"),
    historicalMachineEvidence: {
      seven_cvm_verified_evidence_set_sha256: plan.seven_cvm_verified_evidence_set_sha256,
      evidence_set: { domains: [{ domain: "main_runtime_cvm", evidence_sha256: activation.main_runtime_evidence_sha256 }] },
    },
    historicalReleaseVerificationAuthority: releaseAuthority,
    historicalTranscript: marker("raw14/DCAP"), transcriptSha256: runtime.historical_transcript_file_set_sha256,
    persistenceReceiptSha256: pin("a5"),
  };
  return { now, receipt, observation, authority, runtimeAuthority: runtime, activation };
}
