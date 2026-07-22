import {
  assemblePrivatePostMeasurementEnvironment,
  authorizePhalaDeferredPublicEnvironmentAuthority,
  privatePostMeasurementEnvironmentAssemblyReceipt,
  provisioningEnvironmentAuthorityDigest,
  readExactBoundPhaseSecretInputFile,
} from "./phala-production-environment-authority.mjs";
import {
  assertCompletedPhalaProductionExecutorRuntimeResult,
} from "./phala-production-executor-runtime.mjs";
import {
  assertFreshBrandedPhalaPostMeasurementActivationPlan,
  phalaPostMeasurementActivationPlanSha256,
  readPhalaPostMeasurementActivationPlanDependencies,
} from "./phala-post-measurement-activation.mjs";
import {
  assertFreshBrandedPreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
} from "./pre-ceremony-runtime-authority.mjs";
import {
  ceremonyAuthorizationCoreSha256,
  normalizeCeremonyAuthorizationCore,
} from "./release-authority-stages.mjs";
import {
  authenticatedPhalaSdkObservationSha256,
  createPinnedPhalaProductionSdkAdapter,
  phalaAuthenticatedSdkRequestSemanticsSha256,
  pinnedPhalaProductionSdkAdapterIdentitySha256,
  readAuthenticatedPhalaSdkObservationResponse,
  resolvePinnedPhalaPackageIdentity,
  verifyImmediatePinnedLegacyEnvironmentKeyRefetch,
} from "./phala-production-sdk-adapter.mjs";
import {
  collectProductionFinalizedReadiness,
} from "./phala-production-finalized-readiness.mjs";
import {
  phalaProductionTargetAuthorityDigest,
} from "./phala-production-target-authority.mjs";
import {
  acquirePhalaPostMeasurementActivationLock,
  classifyPhalaPostMeasurementActivationRecovery,
  createInitialPhalaPostMeasurementActivationState,
  loadPhalaPostMeasurementActivationJournal,
  persistPhalaPostMeasurementActivationJournal,
  projectPhalaPostMeasurementActivationJournal,
  releasePhalaPostMeasurementActivationLock,
  transitionPhalaPostMeasurementActivationState,
} from "./phala-post-measurement-activation-journal.mjs";
import {
  createPrivatePostMeasurementEncryptedUpdate,
  destroyPrivatePostMeasurementEncryptedUpdate,
  finalizeProductionPhalaPostMeasurementActivationExecutionReceipt,
  phalaPrivatePostMeasurementAssemblyReceiptSha256,
  prepareProductionPhalaPostMeasurementActivationExecutionReceipt,
  projectProductionPhalaPostMeasurementMutationReadiness,
  readPreparedProductionPhalaPostMeasurementActivationExecutionDependencies,
  readPrivatePostMeasurementEncryptedUpdateCiphertext,
  registerPrivatePostMeasurementEncryptedUpdateObservation,
  phalaArenaWorkerPresenceActivationProofSha256,
} from "./phala-post-measurement-activation-receipt.mjs";
import {
  PhalaDurableReleaseChallengeLedger,
  phalaComputeWorkloadRecipientActivationVerificationSha256,
  verifyPhalaComputeWorkloadRecipientActivation,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  finalizeProductionComputeWorkloadActivationObservation,
  prepareProductionComputeWorkloadActivationObservation,
} from "./compute-workload-activation-observation.mjs";
import {
  assertReviewedFinalAuthorityRuntimeProjection,
} from "./reviewed-final-authority-runtime.mjs";
import {
  assertVerifiedArenaWorkerActivationProof,
  verifyArenaWorkerActivationCapability,
} from "./arena-worker-activation-verification.mjs";

export const PHALA_POST_MEASUREMENT_ACTIVATION_SESSION_SCHEMA =
  "dnai.phala-post-measurement-activation-session.v2";
export const PHALA_POST_MEASUREMENT_ACTIVATION_SESSION_STATUS =
  "combined_profile_patch_restart_authenticated_phala_attestation_observed_and_arena_presence_verified_pending_compute_recipient_activation";
export const PHALA_POST_MEASUREMENT_ACTIVATION_SESSION_TRUTH =
  "private_live_operator_session_with_reviewed_arena_presence_not_serializable_authority_execution_receipt_or_live_traffic";
export const PHALA_POST_MEASUREMENT_ACTIVATION_COMPLETION_RESULT_SCHEMA =
  "dnai.phala-post-measurement-activation-completion-result.v2";
export const PHALA_POST_MEASUREMENT_ACTIVATION_COMPLETION_RESULT_STATUS =
  "main_runtime_arena_and_compute_activation_observed_not_live_traffic";
export const PHALA_POST_MEASUREMENT_ACTIVATION_COMPLETION_RESULT_TRUTH =
  "authenticated_phala_attestation_observation_fresh_post_restart_arena_presence_and_independent_compute_recipient_activation_verified_execution_receipt_and_observation_produced_no_live_traffic_authority";

const SESSIONS = new WeakMap();

const BEGIN_FIELDS = Object.freeze([
  "plan",
  "preCeremonyRuntimeAuthority",
  "ceremonyAuthorization",
  "ceremonyAuthorizationDependencies",
  "reviewedFinalAuthorityRuntimeProjection",
  "launchRuntimeResult",
  "targetAuthority",
  "compatibilityReceipt",
  "sdkWireTransformStagingReceipt",
  "bootstrapPhaseInput",
  "finalPhaseInput",
  "recoveryDirectory",
]);
const COMPLETE_FIELDS = Object.freeze([
  "session",
  "recipientActivation",
  "qvlIdentityEvidence",
  "mainRuntimeEvidence",
]);

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function internalSecond() {
  return new Date(Math.floor(Date.now() / 1_000) * 1_000)
    .toISOString().replace(".000Z", "Z");
}

function canonicalAuthorityExpiryMs(value, label) {
  const expiresAt = Date.parse(value);
  if (!Number.isSafeInteger(expiresAt)) {
    throw new Error(`${label} must be a canonical authority expiry`);
  }
  return expiresAt;
}

function assertActivationAuthorityDeadlineCurrent(authority, label) {
  const checkedAtMs = Date.now();
  const planExpiresAtMs = authority?.plan?.activation_evidence_lease_expires_at
    * 1_000;
  const signedBReviewExpiresAtMs = canonicalAuthorityExpiryMs(
    authority?.signedB?.review?.expires_at,
    "signed-B review expires_at",
  );
  const reviewedProjectionExpiresAtMs = canonicalAuthorityExpiryMs(
    authority?.reviewedFinalAuthorityRuntimeProjection?.review_expires_at,
    "reviewed final-authority projection review_expires_at",
  );
  const deferredAuthorityExpiresAtMs = canonicalAuthorityExpiryMs(
    authority?.deferredAuthority?.valid_until,
    "deferred public-environment authority valid_until",
  );
  const terminalAuthorityDeadlineMs = Math.min(
    planExpiresAtMs,
    signedBReviewExpiresAtMs,
    reviewedProjectionExpiresAtMs,
    deferredAuthorityExpiresAtMs,
  );
  if (!Number.isSafeInteger(planExpiresAtMs)
    || checkedAtMs >= terminalAuthorityDeadlineMs) {
    throw new Error(
      `${label} is outside the minimum signed-B, reviewed, deferred, or initial evidence authority deadline`,
    );
  }
  return Math.floor(checkedAtMs / 1_000);
}

function assertCompletionEvidenceLeasesCurrent(authority, activation, label) {
  const checkedAt = assertActivationAuthorityDeadlineCurrent(authority, label);
  const recipientExpiresAt = activation?.recipient_evidence_lease_expires_at;
  const terminalExpiresAt = activation?.terminal_evidence_lease_expires_at;
  if (!Number.isSafeInteger(recipientExpiresAt)
    || !Number.isSafeInteger(terminalExpiresAt)
    || activation.expires_at !== terminalExpiresAt
    || terminalExpiresAt > recipientExpiresAt
    || checkedAt >= recipientExpiresAt
    || checkedAt >= terminalExpiresAt) {
    throw new Error(
      `${label} is outside the recipient or terminal activation-evidence lease`,
    );
  }
  return checkedAt;
}

async function awaitUnderInitialActivationEvidenceLease(authority, label, operation) {
  assertActivationAuthorityDeadlineCurrent(authority, `before ${label}`);
  let result;
  let failure;
  let failed = false;
  try {
    result = await operation();
  } catch (error) {
    failed = true;
    failure = error;
  }
  assertActivationAuthorityDeadlineCurrent(authority, `after ${label}`);
  if (failed) throw failure;
  return result;
}

async function awaitUnderCompletionEvidenceLeases(
  authority,
  activation,
  label,
  operation,
) {
  assertCompletionEvidenceLeasesCurrent(authority, activation, `before ${label}`);
  let result;
  let failure;
  let failed = false;
  try {
    result = await operation();
  } catch (error) {
    failed = true;
    failure = error;
  }
  assertCompletionEvidenceLeasesCurrent(authority, activation, `after ${label}`);
  if (failed) throw failure;
  return result;
}

function persistActivationJournalUnderInitialEvidenceLease({
  authority,
  label,
  ...journalInput
}) {
  assertActivationAuthorityDeadlineCurrent(authority, `before ${label}`);
  const journal = persistPhalaPostMeasurementActivationJournal(journalInput);
  assertActivationAuthorityDeadlineCurrent(authority, `after ${label}`);
  return journal;
}

function persistActivationJournalUnderCompletionEvidenceLeases({
  authority,
  activation,
  label,
  onBeforePersist,
  ...journalInput
}) {
  assertCompletionEvidenceLeasesCurrent(authority, activation, `before ${label}`);
  if (onBeforePersist !== undefined && typeof onBeforePersist !== "function") {
    throw new Error("completion journal persistence hook must be an internal function");
  }
  onBeforePersist?.();
  const journal = persistPhalaPostMeasurementActivationJournal(journalInput);
  assertCompletionEvidenceLeasesCurrent(authority, activation, `after ${label}`);
  return journal;
}

function ceremonyLineage({
  plan,
  runtimeAuthority,
  ceremonyAuthorization,
  ceremonyAuthorizationDependencies,
}) {
  const dependencies = exactRecord(ceremonyAuthorizationDependencies, [
    "deploymentIntent",
    "freshContractDeploymentReceipt",
    "reviewerGenesis",
    "reviewerGenesisAcceptance",
    "stageBReviewerStatusHistory",
  ], "post-measurement signed-B dependency set");
  if (!Array.isArray(dependencies.stageBReviewerStatusHistory)) {
    throw new Error("post-measurement Stage-B reviewer status history must be an exact array");
  }
  const ceremonyOptions = {
    deploymentIntent: dependencies.deploymentIntent,
    freshContractDeploymentReceipt: dependencies.freshContractDeploymentReceipt,
    reviewerGenesis: dependencies.reviewerGenesis,
    reviewerGenesisAcceptance: dependencies.reviewerGenesisAcceptance,
    reviewerStatusHistory: dependencies.stageBReviewerStatusHistory,
    preCeremonyRuntimeAuthority: runtimeAuthority,
  };
  const signedB = normalizeCeremonyAuthorizationCore(
    ceremonyAuthorization,
    ceremonyOptions,
  );
  const planSha256 = phalaPostMeasurementActivationPlanSha256(plan);
  const runtimeAuthoritySha256 = preCeremonyRuntimeAuthoritySha256(runtimeAuthority);
  const signedBSha256 = ceremonyAuthorizationCoreSha256(signedB, ceremonyOptions);
  if (runtimeAuthority.post_measurement_activation_plan_sha256 !== planSha256
    || runtimeAuthority.seven_cvm_launch_completion_receipt_sha256
      !== plan.seven_cvm_launch_completion_receipt_sha256
    || signedB.pre_ceremony_runtime_authority_sha256 !== runtimeAuthoritySha256
    || signedB.cvm_launch_intent_sha256 !== plan.cvm_launch_intent_sha256
    || signedB.release_sha !== plan.release_sha) {
    throw new Error("post-measurement plan, R, and signed B lineage drifted");
  }
  return {
    signedB,
    ceremonyOptions,
    planSha256,
    runtimeAuthoritySha256,
    signedBSha256,
  };
}

function mainCommit(state) {
  const committed = state.committed_prefix.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  if (!committed) throw new Error("completed launch lacks the main runtime commit");
  return committed;
}

function observationStateEntry(observation, adapter, method, callSequence) {
  const domain = method === "getCurrentUser" ? null : "main_runtime_cvm";
  if (observation.call_sequence !== callSequence) {
    throw new Error("post-measurement SDK observation sequence drifted");
  }
  return {
    method,
    call_sequence: callSequence,
    observation_sha256: authenticatedPhalaSdkObservationSha256(observation, {
      adapter,
      method,
      domain,
    }),
    request_semantics_sha256: observation.request_semantics_sha256,
    observed_at: observation.observed_at,
  };
}

function observationResponse(observation, adapter, method) {
  return readAuthenticatedPhalaSdkObservationResponse(observation, {
    adapter,
    method,
    domain: method === "getCurrentUser" ? null : "main_runtime_cvm",
  });
}

function assertPatchAccepted(response) {
  if (!isRecord(response)
    || response.status !== "in_progress"
    || response.allowed_envs_changed !== false
    || typeof response.correlation_id !== "string"
    || response.correlation_id.length < 1
    || response.correlation_id.length > 512) {
    throw new Error("encrypted-only environment PATCH was not accepted without key mutation");
  }
}

function assertRestartAccepted(response, cvmId) {
  if (!isRecord(response) || String(response.id) !== cvmId) {
    throw new Error("restart response does not identify the exact main-runtime CVM");
  }
}

function hasQuotedCertificate(value) {
  return Array.isArray(value?.app_certificates)
    && value.app_certificates.some((certificate) => (
      typeof certificate?.quote === "string" && certificate.quote.length > 0
    ));
}

function assertFreshPostRestartPhalaAttestationObservation({
  infoObservation,
  attestationObservation,
  adapter,
  plan,
}) {
  const info = observationResponse(infoObservation, adapter, "getCvmInfo");
  const attestation = observationResponse(
    attestationObservation,
    adapter,
    "getCvmAttestation",
  );
  if (!isRecord(info)
    || String(info.id) !== plan.target.cvm_id
    || String(info.app_id).replace(/^0x/, "").toLowerCase()
      !== plan.target.app_id
    || info.compose_hash !== plan.target.compose_hash
    || info.os?.os_image_hash !== plan.target.os_image_hash
    || !isRecord(attestation)
    || attestation.is_online !== true
    || attestation.error !== null
    || !isRecord(attestation.tcb_info)
    || !hasQuotedCertificate(attestation)) {
    throw new Error(
      "authenticated post-restart Phala attestation observation differs from the exact main target",
    );
  }
}

function signedBDeferredAuthorizationDependencies(value) {
  return {
    deploymentIntent: value.deploymentIntent,
    freshContractDeploymentReceipt: value.freshContractDeploymentReceipt,
    reviewerGenesis: value.reviewerGenesis,
    reviewerGenesisAcceptance: value.reviewerGenesisAcceptance,
    stageBReviewerStatusHistory: value.stageBReviewerStatusHistory,
  };
}

function sessionPublic(plan, lineage, state) {
  return Object.freeze({
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_SESSION_SCHEMA,
    status: PHALA_POST_MEASUREMENT_ACTIVATION_SESSION_STATUS,
    truth_status: PHALA_POST_MEASUREMENT_ACTIVATION_SESSION_TRUTH,
    release_sha: plan.release_sha,
    batch_id: plan.batch_id,
    target: Object.freeze({
      domain: "main_runtime_cvm",
      app_id: plan.target.app_id,
      cvm_id: plan.target.cvm_id,
    }),
    post_measurement_activation_plan_sha256: lineage.planSha256,
    pre_ceremony_runtime_authority_sha256: lineage.runtimeAuthoritySha256,
    ceremony_authorization_sha256: lineage.signedBSha256,
    phala_recovery_directory_identity_anchor_sha256:
      plan.phala_recovery_directory_identity_anchor_sha256,
    durable_state_status: state.status,
    next_required_proof:
      "fresh_production_compute_workload_recipient_activation_verified_after_restart",
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
  });
}

export async function beginProductionPhalaPostMeasurementActivation(input = {}) {
  const parsed = exactRecord(input, BEGIN_FIELDS, "post-measurement activation begin input");
  const plan = assertFreshBrandedPhalaPostMeasurementActivationPlan(parsed.plan);
  const runtimeAuthority = assertFreshBrandedPreCeremonyRuntimeAuthority(
    parsed.preCeremonyRuntimeAuthority,
  );
  const lineage = ceremonyLineage({
    plan,
    runtimeAuthority,
    ceremonyAuthorization: parsed.ceremonyAuthorization,
    ceremonyAuthorizationDependencies: parsed.ceremonyAuthorizationDependencies,
  });
  const launch = assertCompletedPhalaProductionExecutorRuntimeResult(
    parsed.launchRuntimeResult,
  );
  const reviewedFinalAuthorityRuntimeProjection =
    assertReviewedFinalAuthorityRuntimeProjection(
      parsed.reviewedFinalAuthorityRuntimeProjection,
    );
  if (Date.parse(reviewedFinalAuthorityRuntimeProjection.review_expires_at)
      <= Date.now()) {
    throw new Error(
      "reviewed final-authority runtime projection expired before activation",
    );
  }
  const planDependencies = readPhalaPostMeasurementActivationPlanDependencies(plan);
  const activationAuthority = Object.freeze({
    plan,
    signedB: lineage.signedB,
    reviewedFinalAuthorityRuntimeProjection,
    deferredAuthority: planDependencies.deferred_authority,
  });
  assertActivationAuthorityDeadlineCurrent(
    activationAuthority,
    "post-measurement activation begin authority",
  );
  const launchCompletion = planDependencies.launch_completion;
  const committed = mainCommit(launch.state);
  const recoveryDirectoryIdentityAnchorSha256 =
    plan.phala_recovery_directory_identity_anchor_sha256;
  const targetAuthoritySha256 = phalaProductionTargetAuthorityDigest(
    parsed.targetAuthority,
    {
      compatibilityReceipt: parsed.compatibilityReceipt,
      sdkWireTransformStagingReceipt: parsed.sdkWireTransformStagingReceipt,
    },
  );
  if (launch.batch_id !== plan.batch_id
    || launch.release_sha !== plan.release_sha
    || launch.state.launch_intent_sha256 !== plan.cvm_launch_intent_sha256
    || launch.phala_recovery_directory_identity_anchor_sha256
      !== recoveryDirectoryIdentityAnchorSha256
    || launch.state.phala_recovery_directory_identity_anchor_sha256
      !== recoveryDirectoryIdentityAnchorSha256
    || launchCompletion.phala_recovery_directory_identity_anchor_sha256
      !== recoveryDirectoryIdentityAnchorSha256
    || runtimeAuthority.phala_recovery_directory_identity_anchor_sha256
      !== recoveryDirectoryIdentityAnchorSha256
    || launch.state.target_authority_sha256
      !== launchCompletion.production_target_authority_sha256
    || targetAuthoritySha256 !== launch.state.target_authority_sha256
    || reviewedFinalAuthorityRuntimeProjection.release_sha !== plan.release_sha
    || reviewedFinalAuthorityRuntimeProjection.deployment_intent_sha256
      !== plan.deployment_intent_sha256
    || reviewedFinalAuthorityRuntimeProjection.cvm_launch_intent_sha256
      !== plan.cvm_launch_intent_sha256
    || reviewedFinalAuthorityRuntimeProjection.final_authority_sha256
      !== planDependencies.deferred_authority.final_release_authority_sha256
    || committed.app_id !== plan.target.app_id
    || committed.cvm_id !== plan.target.cvm_id
    || committed.compose_hash !== plan.target.compose_hash
    || launch.postcommit_provisioning_environment_authority
      !== planDependencies.postcommit_authority
    || provisioningEnvironmentAuthorityDigest(
      launch.provisioning_environment_authority,
    ) !== launch.provisioning_environment_authority_sha256) {
    throw new Error("post-measurement activation launch result differs from L/R plan lineage");
  }

  assertActivationAuthorityDeadlineCurrent(
    activationAuthority,
    "before acquiring the post-measurement activation lock",
  );
  const lock = acquirePhalaPostMeasurementActivationLock({
    directory: parsed.recoveryDirectory,
    directoryIdentityAnchorSha256: recoveryDirectoryIdentityAnchorSha256,
    activationPlanSha256: lineage.planSha256,
    ceremonyAuthorizationSha256: lineage.signedBSha256,
    acquiredAt: internalSecond(),
  });
  let state;
  let journal;
  let keepLock = false;
  let mutationAttemptDurable = false;
  let restartObserved = false;
  let challengeLedger;
  try {
    const existing = loadPhalaPostMeasurementActivationJournal({
      directory: parsed.recoveryDirectory,
      directoryIdentityAnchorSha256: recoveryDirectoryIdentityAnchorSha256,
      activationPlanSha256: lineage.planSha256,
    });
    if (existing) {
      const recovery = classifyPhalaPostMeasurementActivationRecovery(existing);
      throw new Error(
        `existing post-measurement activation journal requires explicit operator workflow:${recovery.action}`,
      );
    }
    assertActivationAuthorityDeadlineCurrent(
      activationAuthority,
      "before opening the durable recipient-challenge ledger",
    );
    challengeLedger = new PhalaDurableReleaseChallengeLedger(
      parsed.recoveryDirectory,
    );
    const bootstrapInput = readExactBoundPhaseSecretInputFile(
      parsed.bootstrapPhaseInput,
      {
        expectedDomain: "main_runtime_cvm",
        expectedPhase: "bootstrap_provision",
        expectedBatchId: plan.batch_id,
        expectedCvmLaunchIntentSha256: plan.cvm_launch_intent_sha256,
      },
    );
    const finalInput = readExactBoundPhaseSecretInputFile(parsed.finalPhaseInput, {
      expectedDomain: "main_runtime_cvm",
      expectedPhase: "final_authority_runtime",
      expectedBatchId: plan.batch_id,
      expectedCvmLaunchIntentSha256: plan.cvm_launch_intent_sha256,
    });
    const authorizedDeferredAuthority =
      await awaitUnderInitialActivationEvidenceLease(
        activationAuthority,
        "deferred public-environment authorization",
        () => authorizePhalaDeferredPublicEnvironmentAuthority({
          deferredAuthority: planDependencies.deferred_authority,
          preCeremonyRuntimeAuthority: runtimeAuthority,
          ceremonyAuthorization: lineage.signedB,
          ceremonyAuthorizationDependencies:
            signedBDeferredAuthorizationDependencies(
              parsed.ceremonyAuthorizationDependencies,
            ),
        }),
      );
    if (authorizedDeferredAuthority !== activationAuthority.deferredAuthority) {
      throw new Error("signed-B authorization returned another deferred authority");
    }
    const assembly = assemblePrivatePostMeasurementEnvironment({
      domain: "main_runtime_cvm",
      now: internalSecond(),
      activationPlanSha256: lineage.planSha256,
      bootstrapAuthority: planDependencies.bootstrap_authority,
      provisioningAuthority: launch.provisioning_environment_authority,
      postcommitProvisioningAuthority: planDependencies.postcommit_authority,
      deferredAuthority: authorizedDeferredAuthority,
      bootstrapSecretInput: bootstrapInput,
      finalSecretInput: finalInput,
    });
    const assemblyReceipt = privatePostMeasurementEnvironmentAssemblyReceipt(assembly);
    if (assemblyReceipt.environment_key_names_sha256
        !== plan.injected_environment_key_names_sha256
      || assemblyReceipt.value_count !== plan.injected_environment_key_names.length) {
      throw new Error("private post-measurement assembly differs from the signed activation plan");
    }
    const adapter = await awaitUnderInitialActivationEvidenceLease(
      activationAuthority,
      "pinned Phala SDK adapter creation",
      () => createPinnedPhalaProductionSdkAdapter({
        targetAuthority: parsed.targetAuthority,
        compatibilityReceipt: parsed.compatibilityReceipt,
        sdkWireTransformStagingReceipt: parsed.sdkWireTransformStagingReceipt,
      }),
    );
    state = createInitialPhalaPostMeasurementActivationState({
      batchId: plan.batch_id,
      releaseSha: plan.release_sha,
      activationPlanSha256: lineage.planSha256,
      preCeremonyRuntimeAuthoritySha256: lineage.runtimeAuthoritySha256,
      ceremonyAuthorizationSha256: lineage.signedBSha256,
      target: {
        domain: "main_runtime_cvm",
        app_id: plan.target.app_id,
        cvm_id: plan.target.cvm_id,
      },
      allowedEnvironmentKeyNamesSha256:
        plan.allowed_environment_key_names_sha256,
      injectedEnvironmentKeyNamesSha256:
        plan.injected_environment_key_names_sha256,
      adapterIdentitySha256:
        pinnedPhalaProductionSdkAdapterIdentitySha256(adapter),
      assemblyReceiptSha256:
        phalaPrivatePostMeasurementAssemblyReceiptSha256(assemblyReceipt),
    });
    journal = persistActivationJournalUnderInitialEvidenceLease({
      authority: activationAuthority,
      label: "initial activation journal persistence",
      directory: parsed.recoveryDirectory,
      state,
      lock,
    });

    const account = await awaitUnderInitialActivationEvidenceLease(
      activationAuthority,
      "authenticated Phala account observation",
      () => adapter.getCurrentUser(),
    );
    const firstEnvironmentKey = await awaitUnderInitialActivationEvidenceLease(
      activationAuthority,
      "first environment-encryption key observation",
      () => adapter.getAppEnvEncryptPubKey({
        domain: "main_runtime_cvm",
        appId: plan.target.app_id,
      }),
    );
    const refetchedEnvironmentKey = await awaitUnderInitialActivationEvidenceLease(
      activationAuthority,
      "immediate environment-encryption key refetch",
      () => adapter.getAppEnvEncryptPubKey({
        domain: "main_runtime_cvm",
        appId: plan.target.app_id,
      }),
    );
    const firstResponse = observationResponse(
      firstEnvironmentKey,
      adapter,
      "getAppEnvEncryptPubKey",
    );
    const refetchedResponse = observationResponse(
      refetchedEnvironmentKey,
      adapter,
      "getAppEnvEncryptPubKey",
    );
    const signedKey = await awaitUnderInitialActivationEvidenceLease(
      activationAuthority,
      "environment-encryption key signature verification",
      () => verifyImmediatePinnedLegacyEnvironmentKeyRefetch({
        identity: resolvePinnedPhalaPackageIdentity(),
        appId: plan.target.app_id,
        firstResponse,
        secondResponse: refetchedResponse,
        pinnedSigner: parsed.targetAuthority.kms.env_encrypt_signer_k256,
      }),
    );
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "pre_patch_reads_observed",
      observations: [
        observationStateEntry(account, adapter, "getCurrentUser", 1),
        observationStateEntry(
          firstEnvironmentKey,
          adapter,
          "getAppEnvEncryptPubKey",
          2,
        ),
        observationStateEntry(
          refetchedEnvironmentKey,
          adapter,
          "getAppEnvEncryptPubKey",
          3,
        ),
      ],
    });
    journal = persistActivationJournalUnderInitialEvidenceLease({
      authority: activationAuthority,
      label: "pre-PATCH observation journal persistence",
      directory: parsed.recoveryDirectory,
      state,
      lock,
    });

    const privateEncryptedUpdate = await awaitUnderInitialActivationEvidenceLease(
      activationAuthority,
      "private encrypted environment update creation",
      () => createPrivatePostMeasurementEncryptedUpdate({
        assembly,
        pinnedDstackIdentity: resolvePinnedPhalaPackageIdentity(),
        publicKey: signedKey.public_key,
        activationPlanSha256: lineage.planSha256,
        targetCvmId: plan.target.cvm_id,
      }),
    );
    let encryptedEnvironment =
      readPrivatePostMeasurementEncryptedUpdateCiphertext(privateEncryptedUpdate);
    let patchInvocation = {
      domain: "main_runtime_cvm",
      cvmId: plan.target.cvm_id,
      request: { encrypted_env: encryptedEnvironment },
    };
    const patchRequestSemanticsSha256 =
      phalaAuthenticatedSdkRequestSemanticsSha256({
        httpMethod: "PATCH",
        pathAndQuery: `/api/v1/cvms/${plan.target.cvm_id}/envs`,
        body: { encrypted_env: encryptedEnvironment },
      });
    const patchReadiness =
      await awaitUnderInitialActivationEvidenceLease(
        activationAuthority,
        "pre-PATCH finalized-readiness collection",
        () => collectProductionFinalizedReadiness({
          primaryRpcUrl: bootstrapInput.values.BASE_SEPOLIA_RPC_URL,
          secondaryRpcUrl: bootstrapInput.values.BASE_SEPOLIA_RPC_URL_SECONDARY,
        }),
      );
    const patchReadinessProjection =
      projectProductionPhalaPostMeasurementMutationReadiness({
        readiness: patchReadiness,
        action: "updateCvmEnvs",
        activationPlanSha256: lineage.planSha256,
        preCeremonyRuntimeAuthoritySha256: lineage.runtimeAuthoritySha256,
        ceremonyAuthorizationSha256: lineage.signedBSha256,
      });
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "mutation_attempt_recorded",
      action: "updateCvmEnvs",
      requestSemanticsSha256: patchRequestSemanticsSha256,
      recordedAt: internalSecond(),
    });
    journal = persistActivationJournalUnderInitialEvidenceLease({
      authority: activationAuthority,
      label: "PATCH mutation-attempt journal persistence",
      directory: parsed.recoveryDirectory,
      state,
      lock,
    });
    mutationAttemptDurable = true;
    let patchObservation;
    try {
      patchObservation = await awaitUnderInitialActivationEvidenceLease(
        activationAuthority,
        "encrypted-only environment PATCH",
        () => adapter.updateCvmEnvs(patchInvocation),
      );
      registerPrivatePostMeasurementEncryptedUpdateObservation({
        encryptedUpdate: privateEncryptedUpdate,
        adapter,
        patchObservation,
      });
    } catch (error) {
      destroyPrivatePostMeasurementEncryptedUpdate(privateEncryptedUpdate);
      throw error;
    } finally {
      patchInvocation.request.encrypted_env = null;
      patchInvocation = null;
      encryptedEnvironment = null;
    }
    assertPatchAccepted(observationResponse(
      patchObservation,
      adapter,
      "updateCvmEnvs",
    ));
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "mutation_observed",
      action: "updateCvmEnvs",
      observation: observationStateEntry(
        patchObservation,
        adapter,
        "updateCvmEnvs",
        4,
      ),
    });
    journal = persistActivationJournalUnderInitialEvidenceLease({
      authority: activationAuthority,
      label: "PATCH observation journal persistence",
      directory: parsed.recoveryDirectory,
      state,
      lock,
    });
    mutationAttemptDurable = false;

    const restartReadiness = await awaitUnderInitialActivationEvidenceLease(
      activationAuthority,
      "pre-restart finalized-readiness collection",
      () => collectProductionFinalizedReadiness({
        primaryRpcUrl: bootstrapInput.values.BASE_SEPOLIA_RPC_URL,
        secondaryRpcUrl: bootstrapInput.values.BASE_SEPOLIA_RPC_URL_SECONDARY,
      }),
    );
    const restartReadinessProjection =
      projectProductionPhalaPostMeasurementMutationReadiness({
        readiness: restartReadiness,
        action: "restartCvm",
        activationPlanSha256: lineage.planSha256,
        preCeremonyRuntimeAuthoritySha256: lineage.runtimeAuthoritySha256,
        ceremonyAuthorizationSha256: lineage.signedBSha256,
      });
    const restartRequestSemanticsSha256 =
      phalaAuthenticatedSdkRequestSemanticsSha256({
        httpMethod: "POST",
        pathAndQuery: `/api/v1/cvms/${plan.target.cvm_id}/restart`,
        body: { force: false },
      });
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "mutation_attempt_recorded",
      action: "restartCvm",
      requestSemanticsSha256: restartRequestSemanticsSha256,
      recordedAt: internalSecond(),
    });
    journal = persistActivationJournalUnderInitialEvidenceLease({
      authority: activationAuthority,
      label: "restart mutation-attempt journal persistence",
      directory: parsed.recoveryDirectory,
      state,
      lock,
    });
    mutationAttemptDurable = true;
    const restartObservation = await awaitUnderInitialActivationEvidenceLease(
      activationAuthority,
      "main-runtime restart mutation",
      () => adapter.restartCvm({
        domain: "main_runtime_cvm",
        cvmId: plan.target.cvm_id,
        force: false,
      }),
    );
    assertRestartAccepted(observationResponse(
      restartObservation,
      adapter,
      "restartCvm",
    ), plan.target.cvm_id);
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "mutation_observed",
      action: "restartCvm",
      observation: observationStateEntry(
        restartObservation,
        adapter,
        "restartCvm",
        5,
      ),
    });
    journal = persistActivationJournalUnderInitialEvidenceLease({
      authority: activationAuthority,
      label: "restart observation journal persistence",
      directory: parsed.recoveryDirectory,
      state,
      lock,
    });
    mutationAttemptDurable = false;
    restartObserved = true;

    const postRestartInfo = await awaitUnderInitialActivationEvidenceLease(
      activationAuthority,
      "post-restart CVM info observation",
      () => adapter.getCvmInfo({
        domain: "main_runtime_cvm",
        cvmId: plan.target.cvm_id,
      }),
    );
    const postRestartAttestation = await awaitUnderInitialActivationEvidenceLease(
      activationAuthority,
      "post-restart CVM attestation observation",
      () => adapter.getCvmAttestation({
        domain: "main_runtime_cvm",
        cvmId: plan.target.cvm_id,
      }),
    );
    assertFreshPostRestartPhalaAttestationObservation({
      infoObservation: postRestartInfo,
      attestationObservation: postRestartAttestation,
      adapter,
      plan,
    });
    state = transitionPhalaPostMeasurementActivationState(state, {
      type:
        "post_restart_authenticated_phala_attestation_observation_verified",
      observations: [
        observationStateEntry(
          postRestartInfo,
          adapter,
          "getCvmInfo",
          6,
        ),
        observationStateEntry(
          postRestartAttestation,
          adapter,
          "getCvmAttestation",
          7,
        ),
      ],
    });
    journal = persistActivationJournalUnderInitialEvidenceLease({
      authority: activationAuthority,
      label: "post-restart attestation journal persistence",
      directory: parsed.recoveryDirectory,
      state,
      lock,
    });
    const arenaWorkerPresenceCandidate =
      await awaitUnderInitialActivationEvidenceLease(
        activationAuthority,
        "Arena worker activation verification",
        () => verifyArenaWorkerActivationCapability({
          reviewedFinalAuthorityRuntimeProjection,
          postMeasurementActivationPlan: plan,
          postRestartAttestationObservedAt:
            state.sdk_observations[6].observed_at,
        }),
      );
    const arenaWorkerPresence = assertVerifiedArenaWorkerActivationProof(
      arenaWorkerPresenceCandidate,
    );
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "arena_worker_activation_verified",
      arenaWorkerPresenceSha256:
        phalaArenaWorkerPresenceActivationProofSha256(arenaWorkerPresence),
      verifiedAt: new Date(arenaWorkerPresence.verified_at * 1_000)
        .toISOString().replace(".000Z", "Z"),
    });
    journal = persistActivationJournalUnderInitialEvidenceLease({
      authority: activationAuthority,
      label: "Arena activation journal persistence",
      directory: parsed.recoveryDirectory,
      state,
      lock,
    });
    const session = sessionPublic(plan, lineage, state);
    SESSIONS.set(session, {
      plan,
      activationAuthority,
      runtimeAuthority,
      reviewedFinalAuthorityRuntimeProjection,
      arenaWorkerPresence,
      ceremonyAuthorization: lineage.signedB,
      ceremonyAuthorizationDependencies: parsed.ceremonyAuthorizationDependencies,
      privateEnvironmentAssemblyReceipt: assemblyReceipt,
      privateEncryptedUpdate,
      adapter,
      observations: {
        getCurrentUser: account,
        firstEnvironmentKey,
        refetchedEnvironmentKey,
        patch: patchObservation,
        restart: restartObservation,
        postRestartInfo,
        postRestartAttestation,
      },
      patchFinalizedReadiness: patchReadinessProjection,
      restartFinalizedReadiness: restartReadinessProjection,
      journal,
      journalDirectory: parsed.recoveryDirectory,
      journalState: state,
      journalLock: lock,
      challengeLedger,
    });
    keepLock = true;
    return session;
  } catch (error) {
    // Recovery-only journals remain writable after authority expiry so a
    // completed/ambiguous external mutation cannot be mistaken for authority
    // to retry. These branches never authorize PATCH, restart, or completion.
    if (state && mutationAttemptDurable
      && ["patch_attempt_durable", "restart_attempt_durable"].includes(state.status)) {
      try {
        state = transitionPhalaPostMeasurementActivationState(state, {
          type: "mutation_outcome_ambiguous",
        });
        persistPhalaPostMeasurementActivationJournal({
          directory: parsed.recoveryDirectory,
          state,
          lock,
        });
      } catch {
        // The already-durable attempt is the fail-closed recovery authority.
      }
    } else if (state && restartObserved && state.status === "restart_observed") {
      try {
        state = transitionPhalaPostMeasurementActivationState(state, {
          type: "post_restart_evidence_unavailable",
        });
        persistPhalaPostMeasurementActivationJournal({
          directory: parsed.recoveryDirectory,
          state,
          lock,
        });
      } catch {
        // The restart observation remains durable and requires explicit review.
      }
    } else if (state?.status
        === "post_restart_authenticated_phala_attestation_observation_verified") {
      try {
        state = transitionPhalaPostMeasurementActivationState(state, {
          type: "arena_worker_activation_unavailable",
        });
        persistPhalaPostMeasurementActivationJournal({
          directory: parsed.recoveryDirectory,
          state,
          lock,
        });
      } catch {
        // The authenticated Phala attestation observation remains durable for
        // explicit Arena review. Quote presence is not independent DCAP/QVL
        // verification of the TDX attestation.
      }
    }
    throw error;
  } finally {
    if (!keepLock) {
      try {
        challengeLedger?.close();
      } finally {
        releasePhalaPostMeasurementActivationLock(lock);
      }
    }
  }
}

function readLocalPhalaPostMeasurementActivationSession(value) {
  const session = value && SESSIONS.get(value);
  if (!session || value.schema !== PHALA_POST_MEASUREMENT_ACTIVATION_SESSION_SCHEMA
    || value.status !== PHALA_POST_MEASUREMENT_ACTIVATION_SESSION_STATUS
    || value.truth_status !== PHALA_POST_MEASUREMENT_ACTIVATION_SESSION_TRUTH
    || value.durable_state_status !== "arena_worker_activation_verified"
    || value.phala_recovery_directory_identity_anchor_sha256
      !== session.plan.phala_recovery_directory_identity_anchor_sha256
    || value.automatic_retry_authorized !== false
    || value.live_traffic_authorized !== false) {
    throw new Error("a live local post-measurement activation session is required");
  }
  return session;
}

function assertSessionActivationAuthorityCurrent(value, session, label) {
  const plan = assertFreshBrandedPhalaPostMeasurementActivationPlan(session.plan);
  const planDependencies = readPhalaPostMeasurementActivationPlanDependencies(plan);
  const runtimeAuthority = assertFreshBrandedPreCeremonyRuntimeAuthority(
    session.runtimeAuthority,
  );
  const reviewedFinalAuthorityRuntimeProjection =
    assertReviewedFinalAuthorityRuntimeProjection(
      session.reviewedFinalAuthorityRuntimeProjection,
    );
  const lineage = ceremonyLineage({
    plan,
    runtimeAuthority,
    ceremonyAuthorization: session.ceremonyAuthorization,
    ceremonyAuthorizationDependencies:
      session.ceremonyAuthorizationDependencies,
  });
  if (session.activationAuthority?.plan !== plan
    || session.activationAuthority?.signedB !== session.ceremonyAuthorization
    || session.activationAuthority?.reviewedFinalAuthorityRuntimeProjection
      !== reviewedFinalAuthorityRuntimeProjection
    || session.activationAuthority?.deferredAuthority
      !== planDependencies.deferred_authority
    || runtimeAuthority.activation_evidence_lease_expires_at
      !== plan.activation_evidence_lease_expires_at
    || value.post_measurement_activation_plan_sha256 !== lineage.planSha256
    || value.pre_ceremony_runtime_authority_sha256
      !== lineage.runtimeAuthoritySha256
    || value.ceremony_authorization_sha256 !== lineage.signedBSha256) {
    throw new Error(`${label} plan, R, signed B, or activation lease drifted`);
  }
  assertActivationAuthorityDeadlineCurrent(session.activationAuthority, label);
  return plan;
}

export function assertProductionPhalaPostMeasurementActivationSession(value) {
  const session = readLocalPhalaPostMeasurementActivationSession(value);
  assertSessionActivationAuthorityCurrent(
    value,
    session,
    "post-measurement activation session assertion",
  );
  return value;
}

export async function completeProductionPhalaPostMeasurementActivation(input = {}) {
  const parsed = exactRecord(
    input,
    COMPLETE_FIELDS,
    "post-measurement activation completion input",
  );
  const sessionPublicValue = assertProductionPhalaPostMeasurementActivationSession(
    parsed.session,
  );
  const session = SESSIONS.get(sessionPublicValue);
  const activationAuthority = session.activationAuthority;
  const planDependencies = readPhalaPostMeasurementActivationPlanDependencies(
    session.plan,
  );
  let state = session.journalState;
  let journal = session.journal;
  let recipientVerificationConsumed = false;
  let completionPersistenceAttempted = false;
  let completed = false;
  try {
    const arenaWorkerPresence = assertVerifiedArenaWorkerActivationProof(
      session.arenaWorkerPresence,
    );
    assertSessionActivationAuthorityCurrent(
      sessionPublicValue,
      session,
      "before one-use Compute recipient challenge consumption",
    );
    assertActivationAuthorityDeadlineCurrent(
      activationAuthority,
      "immediately before one-use Compute recipient challenge consumption",
    );
    const activation = verifyPhalaComputeWorkloadRecipientActivation({
      activation: parsed.recipientActivation,
      releaseAuthority: planDependencies.release_authority,
      qvlIdentityEvidence: parsed.qvlIdentityEvidence,
      mainRuntimeEvidence: parsed.mainRuntimeEvidence,
      challengeLedger: session.challengeLedger,
      minimumAuthenticatedAt: arenaWorkerPresence.verified_at,
    });
    recipientVerificationConsumed = true;
    assertCompletionEvidenceLeasesCurrent(
      activationAuthority,
      activation,
      "after one-use Compute recipient challenge consumption",
    );
    if (activation.authenticated_at
        < Math.floor(Date.parse(state.sdk_observations[6].observed_at) / 1_000)
      || activation.authenticated_at < arenaWorkerPresence.verified_at
      || activation.verified_at < arenaWorkerPresence.verified_at) {
      throw new Error(
        "recipient activation predates the ordered post-restart Arena authority",
      );
    }
    const computeVerifiedState = transitionPhalaPostMeasurementActivationState(state, {
      type: "compute_recipient_activation_verified",
      computeRecipientActivationSha256:
        phalaComputeWorkloadRecipientActivationVerificationSha256(activation),
      verifiedAt: new Date(activation.verified_at * 1_000)
        .toISOString().replace(".000Z", "Z"),
    });
    const completionSecond = assertCompletionEvidenceLeasesCurrent(
      activationAuthority,
      activation,
      "activation completion timestamp",
    );
    if (completionSecond < activation.verified_at
      || completionSecond >= session.plan.activation_evidence_lease_expires_at
      || completionSecond >= activation.recipient_evidence_lease_expires_at
      || completionSecond >= activation.terminal_evidence_lease_expires_at) {
      throw new Error(
        "actual activation completion time is outside the initial, recipient, or terminal evidence lease",
      );
    }
    const completedAt = new Date(completionSecond * 1_000)
      .toISOString().replace(".000Z", "Z");
    const proposedCompletedState = transitionPhalaPostMeasurementActivationState(
      computeVerifiedState,
      {
        type: "completed",
        completedAt,
      },
    );
    const projectedJournal = projectPhalaPostMeasurementActivationJournal(
      proposedCompletedState,
    );
    const receiptPreflightToken =
      await awaitUnderCompletionEvidenceLeases(
        activationAuthority,
        activation,
        "post-measurement execution-receipt preflight",
        () => prepareProductionPhalaPostMeasurementActivationExecutionReceipt({
          plan: session.plan,
          preCeremonyRuntimeAuthority: session.runtimeAuthority,
          ceremonyAuthorization: session.ceremonyAuthorization,
          ceremonyAuthorizationDependencies:
            session.ceremonyAuthorizationDependencies,
          privateEnvironmentAssemblyReceipt:
            session.privateEnvironmentAssemblyReceipt,
          privateEncryptedUpdate: session.privateEncryptedUpdate,
          adapter: session.adapter,
          observations: session.observations,
          patchFinalizedReadiness: session.patchFinalizedReadiness,
          restartFinalizedReadiness: session.restartFinalizedReadiness,
          arenaWorkerPresence,
          recipientActivation: activation,
          proposedCompletedState,
          projectedJournal,
        }),
      );
    const preparedReceiptDependencies =
      readPreparedProductionPhalaPostMeasurementActivationExecutionDependencies(
        receiptPreflightToken,
      );
    if (preparedReceiptDependencies.compute_workload_observation_binding
        .post_measurement_activation_execution_receipt_sha256
      !== preparedReceiptDependencies
        .post_measurement_activation_execution_receipt_sha256) {
      throw new Error("prepared receipt and Compute O authority binding drifted");
    }
    assertCompletionEvidenceLeasesCurrent(
      activationAuthority,
      activation,
      "before Compute activation-observation preflight",
    );
    const computeObservationPreflightToken =
      prepareProductionComputeWorkloadActivationObservation({
        activationExecutionReceiptPreflightToken: receiptPreflightToken,
        activationVerification: activation,
        releaseVerificationAuthority: planDependencies.release_authority,
      });
    journal = persistActivationJournalUnderCompletionEvidenceLeases({
      authority: activationAuthority,
      activation,
      label: "Compute recipient-verification journal persistence",
      directory: session.journalDirectory,
      state: computeVerifiedState,
      lock: session.journalLock,
      onBeforePersist() {
        completionPersistenceAttempted = true;
        state = computeVerifiedState;
      },
    });
    journal = persistActivationJournalUnderCompletionEvidenceLeases({
      authority: activationAuthority,
      activation,
      label: "activation-completed journal persistence",
      directory: session.journalDirectory,
      state: proposedCompletedState,
      lock: session.journalLock,
      onBeforePersist() {
        state = proposedCompletedState;
      },
    });
    assertCompletionEvidenceLeasesCurrent(
      activationAuthority,
      activation,
      "before activation execution-receipt finalization",
    );
    const activationExecutionReceipt =
      finalizeProductionPhalaPostMeasurementActivationExecutionReceipt({
        preflightToken: receiptPreflightToken,
        journal,
        journalDirectory: session.journalDirectory,
        journalState: state,
        journalLock: session.journalLock,
      });
    assertCompletionEvidenceLeasesCurrent(
      activationAuthority,
      activation,
      "after activation execution-receipt finalization",
    );
    assertCompletionEvidenceLeasesCurrent(
      activationAuthority,
      activation,
      "before Compute activation-observation finalization",
    );
    const computeWorkloadActivationObservation =
      finalizeProductionComputeWorkloadActivationObservation({
        preflightToken: computeObservationPreflightToken,
        activationExecutionReceipt,
      });
    assertCompletionEvidenceLeasesCurrent(
      activationAuthority,
      activation,
      "after Compute activation-observation finalization",
    );
    completed = true;
    return Object.freeze({
      schema: PHALA_POST_MEASUREMENT_ACTIVATION_COMPLETION_RESULT_SCHEMA,
      status: PHALA_POST_MEASUREMENT_ACTIVATION_COMPLETION_RESULT_STATUS,
      truth_status: PHALA_POST_MEASUREMENT_ACTIVATION_COMPLETION_RESULT_TRUTH,
      activation_execution_receipt: activationExecutionReceipt,
      compute_workload_activation_observation:
        computeWorkloadActivationObservation,
      live_traffic_authorized: false,
    });
  } catch (error) {
    // This is a fail-closed recovery record for an already-consumed one-use
    // challenge. It must remain writable after lease expiry and cannot produce
    // a completion receipt or O.
    if (recipientVerificationConsumed
      && !completionPersistenceAttempted
      && state.status === "arena_worker_activation_verified") {
      try {
        state = transitionPhalaPostMeasurementActivationState(state, {
          type: "compute_recipient_activation_unavailable",
        });
        persistPhalaPostMeasurementActivationJournal({
          directory: session.journalDirectory,
          state,
          lock: session.journalLock,
        });
      } catch {
        // The consumed Compute proof remains fail-closed for operator review.
      }
    }
    throw error;
  } finally {
    if (completed || recipientVerificationConsumed) {
      try {
        session.challengeLedger.close();
      } finally {
        SESSIONS.delete(sessionPublicValue);
        releasePhalaPostMeasurementActivationLock(session.journalLock);
      }
    }
  }
}

export function quarantineProductionPhalaPostMeasurementActivationSession(
  sessionValue,
) {
  const publicSession = sessionValue;
  const session = readLocalPhalaPostMeasurementActivationSession(publicSession);
  try {
    // Quarantine is deliberately available after authority expiry; it only
    // revokes the pending session and never authorizes another mutation.
    const state = transitionPhalaPostMeasurementActivationState(
      session.journalState,
      { type: "compute_recipient_activation_unavailable" },
    );
    return persistPhalaPostMeasurementActivationJournal({
      directory: session.journalDirectory,
      state,
      lock: session.journalLock,
    });
  } finally {
    try {
      session.challengeLedger.close();
    } finally {
      SESSIONS.delete(publicSession);
      releasePhalaPostMeasurementActivationLock(session.journalLock);
    }
  }
}
