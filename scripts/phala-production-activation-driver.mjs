#!/usr/bin/env node

import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  executePhalaSevenCvmProductionLaunch,
} from "./phala-production-executor-runtime.mjs";
import {
  beginPhalaProductionActivationFromSignedB,
  completePhalaProductionActivation,
  disposePhalaProductionActivationSession,
  phalaProductionActivationSigningExchangePaths,
  preparePhalaProductionActivationEvidence,
  readPhalaProductionActivationRuntimeDeadlines,
  readPhalaProductionActivationEvidenceDependencies,
  resumePhalaProductionActivationWithPinnedSigningExchange,
} from "./phala-production-activation-coordinator.mjs";
import {
  PHALA_WORKLOAD_DOMAIN_QVL_LINK,
  PhalaDurableReleaseChallengeLedger,
  createPhalaQvlIdentityChallenge,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
  verifyPhalaQvlIdentityLaunchEvidence,
  verifyPhalaWorkloadIndependentTdxVerdict,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  assertVerifiedComputeWorkloadActivationObservation,
  canonicalComputeWorkloadActivationObservationText,
  computeWorkloadActivationObservationSha256,
  projectComputeWorkloadBrowserEnvFromObservation,
} from "./compute-workload-activation-observation.mjs";
import {
  assertProductionPhalaPostMeasurementActivationExecutionReceipt,
  canonicalPhalaPostMeasurementActivationExecutionReceiptText,
  phalaPostMeasurementActivationExecutionReceiptSha256,
} from "./phala-post-measurement-activation-receipt.mjs";
import {
  assertActivationExecutionReceiptMatchesComputeWorkloadObservation,
} from "./release-authority-stages.mjs";
import {
  closePhalaPinnedPrivateDirectory,
  createExclusivePhalaPinnedPrivateFile,
  assertPinnedPhalaPrivateDirectoryPathIdentity,
  listPhalaPinnedPrivateEntries,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  phalaPinnedPrivatePathForDisplay,
  pinPhalaPrivateDirectory,
  readPhalaPinnedPrivateFile,
} from "./phala-pinned-private-directory.mjs";
import {
  PHALA_PRODUCTION_STAGE_B_ATTACHMENT_MANIFEST_BASENAME,
  PHALA_PRODUCTION_STAGE_B_ATTACHMENT_MANIFEST_SCHEMA,
} from "./phala-production-stage-b-attach.mjs";
import {
  canonicalResidentAbsolutePath,
  canonicalResidentJsonText,
  exactResidentRecord,
  normalizeResidentFileBinding,
  preflightResidentBoundFile,
  readStableCanonicalResident0600Json,
  waitForPinnedCanonicalResident0600Json,
} from "./phala-production-resident-io.mjs";

export const PHALA_PRODUCTION_ACTIVATION_DRIVER_REQUEST_SCHEMA =
  "dnai.phala-production-activation-driver-request.v1";
export const PHALA_PRODUCTION_ACTIVATION_DRIVER_CHECKPOINT_SCHEMA =
  "dnai.phala-production-activation-driver-checkpoint.v1";
export const PHALA_PRODUCTION_ACTIVATION_DRIVER_RESULT_SCHEMA =
  "dnai.phala-production-activation-driver-result.v1";
export const PHALA_PRODUCTION_ACTIVATION_DRIVER_FAILED_CODE =
  "phala_production_activation_driver_failed_closed";
export const PHALA_PRODUCTION_ACTIVATION_PUBLICATION_RECEIPT_BASENAME =
  "production-activation-publication-receipt.json";
export const PHALA_PRODUCTION_RECIPIENT_COMPLETION_HEADROOM_SECONDS = 30;

export const PHALA_PRODUCTION_ACTIVATION_DRIVER_STATES = Object.freeze([
  "request_preflight_complete",
  "seven_cvm_launch_complete_non_live",
  "collecting_five_qvl_identity_proofs",
  "collecting_two_workload_verdict_proofs",
  "waiting_for_external_stage_b_signatures",
  "post_measurement_runtime_mutated_non_live",
  "waiting_for_compute_recipient_activation",
  "activation_finalized_non_live",
  "bounded_outputs_published_non_live",
]);

const QVL_IDENTITY_DOMAINS = Object.freeze([
  "diligence_qvl_cvm",
  "arena_qvl_cvm",
  "anchor_writer_qvl_cvm",
  "compute_workload_qvl_cvm",
  "compute_metering_qvl_cvm",
]);
const WORKLOAD_DOMAINS = Object.freeze([
  "main_runtime_cvm",
  "independent_metering_cvm",
]);
const LAUNCH_FIELDS = Object.freeze([
  "authorizationPath",
  "bootstrapAuthorityPath",
  "compatibilityReceiptPath",
  "deploymentIntentPath",
  "freshContractDeploymentReceiptPath",
  "imageReleaseManifestPath",
  "imageReleaseSigstoreBundlePath",
  "imageReleaseSigstoreVerificationReceiptPath",
  "phaseSecretInputPaths",
  "productionTargetAuthorityPath",
  "recoveryDirectory",
  "releaseDirectory",
  "repositoryRoot",
  "reviewerAuthorityGenesisAcceptancePath",
  "reviewerAuthorityGenesisPath",
  "sdkWireTransformStagingReceiptPath",
]);
const REVIEWED_FINAL_FIELDS = Object.freeze([
  "cvmLaunchIntent",
  "deploymentIntent",
  "finalAuthority",
  "reviewEnvelope",
  "reviewEvidence",
]);
const ACTIVATION_FIELDS = Object.freeze([
  "bootstrapPhaseInput",
  "ceremonyLedgerInitial",
  "ceremonyLedgerInitializationReceipt",
  "ceremonyTransactionPlan",
  "deferredAuthorityReview",
  "descriptorSetReceipt",
  "evidenceExchangeAuthority",
  "evidenceTimeoutSeconds",
  "finalPhaseInput",
  "freshContractDeploymentReceipt",
  "immutableDeploymentManifest",
  "independentMeteringPolicySetHash",
  "measurementPolicySet",
  "outputAuthority",
  "pollIntervalMilliseconds",
  "qvlIdentityTtlSeconds",
  "recipientTimeoutSeconds",
  "releaseManifestSigstoreVerificationReceipt",
  "reviewedFinalAuthorityFiles",
  "reviewerGenesis",
  "reviewerGenesisAcceptance",
  "reviewerStatusHistory",
  "signingExchangeAuthority",
  "signingTimeoutSeconds",
]);
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const MAXIMUM_SECRET_BYTES = 1024 * 1024;
const MAXIMUM_TRANSPORT_BYTES = 4 * 1024 * 1024;
const CHAIN_ID = 84_532;

function usage() {
  return [
    "Usage:",
    "  node scripts/phala-production-activation-driver.mjs \\",
    "    --execute-request /absolute/private-resident-request.json",
    "",
    "The request must be canonical recursively sorted JSON in one owned 0600",
    "single-link file. The process remains resident through launch, verifier",
    "proof collection, Stage-B, restart, recipient activation, and final output",
    "publication so opaque WeakMap authority is never serialized or recovered.",
  ].join("\n");
}

function integerInRange(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function normalizeLaunchRequest(value) {
  const parsed = exactResidentRecord(
    value,
    LAUNCH_FIELDS,
    "resident seven-CVM launch request",
  );
  const normalized = {};
  for (const field of LAUNCH_FIELDS) {
    if (field === "phaseSecretInputPaths") {
      normalized[field] = parsed[field];
      continue;
    }
    normalized[field] = canonicalResidentAbsolutePath(
      parsed[field],
      `resident launch ${field}`,
    );
  }
  if (!parsed.phaseSecretInputPaths || typeof parsed.phaseSecretInputPaths !== "object"
    || Array.isArray(parsed.phaseSecretInputPaths)) {
    throw new Error("resident launch phaseSecretInputPaths must be one object");
  }
  return Object.freeze(normalized);
}

function normalizeActivationRequest(value) {
  const parsed = exactResidentRecord(
    value,
    ACTIVATION_FIELDS,
    "resident activation request",
  );
  const reviewed = exactResidentRecord(
    parsed.reviewedFinalAuthorityFiles,
    REVIEWED_FINAL_FIELDS,
    "resident reviewed final-authority files",
  );
  const bindingFields = Object.freeze([
    "bootstrapPhaseInput",
    "ceremonyLedgerInitial",
    "ceremonyLedgerInitializationReceipt",
    "ceremonyTransactionPlan",
    "deferredAuthorityReview",
    "descriptorSetReceipt",
    "finalPhaseInput",
    "freshContractDeploymentReceipt",
    "immutableDeploymentManifest",
    "measurementPolicySet",
    "releaseManifestSigstoreVerificationReceipt",
    "reviewerGenesis",
    "reviewerGenesisAcceptance",
    "reviewerStatusHistory",
  ]);
  const normalized = {};
  for (const field of bindingFields) {
    normalized[field] = normalizeResidentFileBinding(
      parsed[field],
      `resident activation ${field}`,
    );
  }
  normalized.reviewedFinalAuthorityFiles = Object.freeze(Object.fromEntries(
    REVIEWED_FINAL_FIELDS.map((field) => [
      field,
      normalizeResidentFileBinding(
        reviewed[field],
        `resident reviewed ${field}`,
      ),
    ]),
  ));
  for (const field of [
    "evidenceExchangeAuthority",
    "signingExchangeAuthority",
    "outputAuthority",
  ]) {
    const authority = exactResidentRecord(
      parsed[field],
      ["identity_anchor_sha256", "path"],
      `resident ${field}`,
    );
    if (typeof authority.identity_anchor_sha256 !== "string"
      || !SHA256.test(authority.identity_anchor_sha256)) {
      throw new Error(`resident ${field} identity anchor is invalid`);
    }
    normalized[field] = Object.freeze({
      path: canonicalResidentAbsolutePath(
        authority.path,
        `resident ${field} path`,
      ),
      identity_anchor_sha256: authority.identity_anchor_sha256,
    });
  }
  normalized.evidenceTimeoutSeconds = integerInRange(
    parsed.evidenceTimeoutSeconds,
    "resident evidence timeout",
    20,
    240,
  );
  normalized.signingTimeoutSeconds = integerInRange(
    parsed.signingTimeoutSeconds,
    "resident Stage-B timeout",
    20,
    240,
  );
  normalized.recipientTimeoutSeconds = integerInRange(
    parsed.recipientTimeoutSeconds,
    "resident recipient timeout",
    10,
    90,
  );
  normalized.pollIntervalMilliseconds = integerInRange(
    parsed.pollIntervalMilliseconds,
    "resident poll interval",
    25,
    1_000,
  );
  normalized.qvlIdentityTtlSeconds = integerInRange(
    parsed.qvlIdentityTtlSeconds,
    "resident QVL identity TTL",
    30,
    120,
  );
  if (typeof parsed.independentMeteringPolicySetHash !== "string"
    || !BYTES32.test(parsed.independentMeteringPolicySetHash)) {
    throw new Error("resident independent-metering policy-set hash is invalid");
  }
  normalized.independentMeteringPolicySetHash =
    parsed.independentMeteringPolicySetHash;
  return Object.freeze(normalized);
}

function assertDisjointPrivatePaths(paths, recoveryDirectory) {
  const entries = [...paths, recoveryDirectory];
  if (new Set(entries).size !== entries.length) {
    throw new Error("resident exchange, output, and recovery directories must be distinct");
  }
  for (let left = 0; left < entries.length; left += 1) {
    for (let right = left + 1; right < entries.length; right += 1) {
      if (entries[left].startsWith(`${entries[right]}${path.sep}`)
        || entries[right].startsWith(`${entries[left]}${path.sep}`)) {
        throw new Error("resident private directories must not contain one another");
      }
    }
  }
}

function preflightActivationBindings(activation) {
  const ordinary = Object.freeze([
    "ceremonyTransactionPlan",
    "deferredAuthorityReview",
    "descriptorSetReceipt",
    "freshContractDeploymentReceipt",
    "measurementPolicySet",
    "releaseManifestSigstoreVerificationReceipt",
    "reviewerGenesis",
    "reviewerGenesisAcceptance",
    "reviewerStatusHistory",
  ]);
  for (const field of ordinary) {
    preflightResidentBoundFile(
      activation[field],
      `resident activation ${field}`,
    );
  }
  for (const field of REVIEWED_FINAL_FIELDS) {
    preflightResidentBoundFile(
      activation.reviewedFinalAuthorityFiles[field],
      `resident reviewed ${field}`,
    );
  }
  preflightResidentBoundFile(
    activation.bootstrapPhaseInput,
    "resident bootstrap phase input",
    { exactMode: 0o600, maximum: MAXIMUM_SECRET_BYTES },
  );
  preflightResidentBoundFile(
    activation.finalPhaseInput,
    "resident final phase input",
    { exactMode: 0o600, maximum: MAXIMUM_SECRET_BYTES },
  );
  preflightResidentBoundFile(
    activation.ceremonyLedgerInitializationReceipt,
    "resident ceremony ledger initialization receipt",
    { exactMode: 0o444 },
  );
  preflightResidentBoundFile(
    activation.immutableDeploymentManifest,
    "resident immutable deployment manifest",
    { exactMode: 0o444 },
  );
  preflightResidentBoundFile(
    activation.ceremonyLedgerInitial,
    "resident initial ceremony ledger",
    { exactMode: 0o600 },
  );
}

export function normalizePhalaProductionActivationDriverRequest(value) {
  const parsed = exactResidentRecord(
    value,
    ["activation", "launch", "schema"],
    "production activation resident request",
  );
  if (parsed.schema !== PHALA_PRODUCTION_ACTIVATION_DRIVER_REQUEST_SCHEMA) {
    throw new Error("production activation resident request schema is invalid");
  }
  const launch = normalizeLaunchRequest(parsed.launch);
  const activation = normalizeActivationRequest(parsed.activation);
  assertDisjointPrivatePaths([
    activation.evidenceExchangeAuthority.path,
    activation.signingExchangeAuthority.path,
    activation.outputAuthority.path,
  ], launch.recoveryDirectory);
  preflightActivationBindings(activation);
  return Object.freeze({ schema: parsed.schema, launch, activation });
}

function checkpoint(state, detail = {}) {
  const value = {
    ...detail,
    schema: PHALA_PRODUCTION_ACTIVATION_DRIVER_CHECKPOINT_SCHEMA,
    state,
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
  };
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

class ResidentActivationStateMachine {
  #position = -1;

  advance(next, detail = {}) {
    const current = this.#position < 0
      ? null
      : PHALA_PRODUCTION_ACTIVATION_DRIVER_STATES[this.#position];
    if (next !== current) {
      const expected = PHALA_PRODUCTION_ACTIVATION_DRIVER_STATES[
        this.#position + 1
      ];
      if (next !== expected) {
        throw new Error(
          `resident activation transition ${current ?? "initial"} -> ${next} is forbidden`,
        );
      }
      this.#position += 1;
    }
    checkpoint(next, detail);
  }
}

function transportBasename(index, domain, suffix) {
  return `${String(index).padStart(2, "0")}-${domain.replaceAll("_", "-")}.${suffix}.json`;
}

function createPinnedCanonicalJson(handle, fileName, value, maximum = MAXIMUM_TRANSPORT_BYTES) {
  const bytes = Buffer.from(canonicalResidentJsonText(value), "utf8");
  return createExclusivePhalaPinnedPrivateFile(handle, fileName, bytes, {
    mode: 0o600,
    maximum,
  });
}

function workloadChallengeRequest(releaseAuthority, linkedQvlEvidence, domain) {
  const link = PHALA_WORKLOAD_DOMAIN_QVL_LINK[domain];
  const descriptor = releaseAuthority.descriptors.find(
    (entry) => entry.domain === domain,
  );
  if (!link || !descriptor || linkedQvlEvidence.domain !== link.qvl_domain) {
    throw new Error(`${domain} live QVL transport authority is incomplete`);
  }
  return Object.freeze({
    schema: "dnai.attestation-qvl-challenge-request.v2",
    chain_id: CHAIN_ID,
    domain,
    profile: link.profile,
    cvm_id: descriptor.cvm_id,
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    release_authority_sha256:
      phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority),
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_sha256: linkedQvlEvidence.measurement_policy_sha256,
  });
}

function reportDataBinding(activation, domain) {
  if (domain === "main_runtime_cvm") {
    return Object.freeze({ kind: "diligence_result_signer_v1" });
  }
  return Object.freeze({
    kind: "compute_metering_signer_v1",
    policy_set_hash: activation.independentMeteringPolicySetHash,
    signer_custody: "dstack_derived_independent_cvm",
  });
}

function safeDispose(session) {
  if (!session) return;
  try {
    disposePhalaProductionActivationSession({ session });
  } catch {
    // A coordinator entry point may have already consumed and quarantined its
    // one-shot session. Its durable journal is then the sole recovery authority.
  }
}

function attachEmptyResidentPrivateAuthority(authority, label) {
  const handle = pinPhalaPrivateDirectory(authority.path, {
    expectedIdentityAnchorSha256: authority.identity_anchor_sha256,
  });
  try {
    assertPinnedPhalaPrivateDirectoryPathIdentity(handle);
    if (listPhalaPinnedPrivateEntries(handle).length !== 0) {
      throw new Error(`${label} must be an empty pre-existing pinned authority`);
    }
    return handle;
  } catch (error) {
    closePhalaPinnedPrivateDirectory(handle);
    throw error;
  }
}

function stageBExternalSignaturesBasename(signedBOutputBasename) {
  if (typeof signedBOutputBasename !== "string"
    || !signedBOutputBasename.endsWith(".signed.json")) {
    throw new Error("coordinator Stage-B signed output basename is invalid");
  }
  return `${signedBOutputBasename.slice(0, -".signed.json".length)}.external-signatures.json`;
}

function createStageBAttachmentManifest(signingHandle, signingSession) {
  const externalSignaturesBasename = stageBExternalSignaturesBasename(
    signingSession.signed_b_output.basename,
  );
  const manifest = Object.freeze({
    schema: PHALA_PRODUCTION_STAGE_B_ATTACHMENT_MANIFEST_SCHEMA,
    status: "waiting_for_external_two_reviewer_signatures",
    truth_status:
      "non_signing_candidate_attachment_only_same_process_coordinator_validation_still_required",
    release_sha: signingSession.release_sha,
    batch_id: signingSession.batch_id,
    signing_payload_sha256: signingSession.signing_payload_sha256,
    signing_message: signingSession.signing_message,
    signing_exchange_directory_identity_anchor_sha256:
      signingSession.signing_exchange_directory_identity_anchor_sha256,
    unsigned_body_file: signingSession.unsigned_body_file,
    signing_payload_file: signingSession.signing_payload_file,
    external_signatures_input: Object.freeze({
      basename: externalSignaturesBasename,
      mode: "0600",
      canonical_json_required: true,
    }),
    signed_b_output: signingSession.signed_b_output,
    automatic_retry_authorized: false,
    activation_mutation_authorized: false,
    live_traffic_authorized: false,
  });
  createPinnedCanonicalJson(
    signingHandle,
    PHALA_PRODUCTION_STAGE_B_ATTACHMENT_MANIFEST_BASENAME,
    manifest,
    64 * 1024,
  );
  return Object.freeze({ manifest, externalSignaturesBasename });
}

function createRecipientTransportRequest(evidenceHandle, runtimeSession) {
  const basename = "08-compute-workload-recipient-activation.json";
  const requestBasename = "08-compute-workload-recipient-activation.request.json";
  const request = Object.freeze({
    schema: "dnai.phala-production-compute-recipient-transport-request.v1",
    status: "post_restart_runtime_ready_pending_live_recipient_activation",
    truth_status:
      "transport_instruction_only_not_recipient_attestation_or_activation_authority",
    release_sha: runtimeSession.release_sha,
    batch_id: runtimeSession.batch_id,
    release_verification_authority_sha256:
      runtimeSession.release_verification_authority_sha256,
    ceremony_authorization_sha256:
      runtimeSession.ceremony_authorization_sha256,
    required_activation_input: Object.freeze({
      basename,
      mode: "0600",
      canonical_json_required: true,
    }),
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
  });
  createPinnedCanonicalJson(evidenceHandle, requestBasename, request, 64 * 1024);
  return Object.freeze({ basename, requestBasename });
}

export function publishFinalOutputs(
  outputHandle,
  result,
  browserEnv,
  { releaseSha, batchId } = {},
) {
  if (!result || result.live_traffic_authorized !== false
    || !result.activation_execution_receipt
    || !result.compute_workload_activation_observation
    || !browserEnv || typeof browserEnv !== "object" || Array.isArray(browserEnv)
    || typeof releaseSha !== "string" || typeof batchId !== "string") {
    throw new Error("activation completion did not return exact non-live receipt and O outputs");
  }
  const assertCurrentExactPublicationAuthority = () => {
    const receipt =
      assertProductionPhalaPostMeasurementActivationExecutionReceipt(
        result.activation_execution_receipt,
      );
    const observation = assertVerifiedComputeWorkloadActivationObservation(
      result.compute_workload_activation_observation,
    );
    assertActivationExecutionReceiptMatchesComputeWorkloadObservation({
      activationExecutionReceipt: receipt,
      activationExecutionReceiptSha256:
        phalaPostMeasurementActivationExecutionReceiptSha256(receipt),
      observation,
    });
    if (receipt.release_sha !== releaseSha || receipt.batch_id !== batchId
      || observation.release_sha !== releaseSha) {
      throw new Error(
        "bounded publication identity differs from the branded receipt and O",
      );
    }
    const expectedBrowserEnv = projectComputeWorkloadBrowserEnvFromObservation(
      observation,
    );
    if (canonicalResidentJsonText(browserEnv)
        !== canonicalResidentJsonText(expectedBrowserEnv)) {
      throw new Error(
        "bounded publication browser environment differs from exact O projection",
      );
    }
    return Object.freeze({ receipt, observation });
  };
  let { receipt, observation } = assertCurrentExactPublicationAuthority();
  assertPinnedPhalaPrivateDirectoryPathIdentity(outputHandle);
  if (listPhalaPinnedPrivateEntries(outputHandle).length !== 0) {
    throw new Error("bounded output authority changed before publication");
  }
  const published = [];
  const createAndReread = (basename, bytes, maximum) => {
    const identity = createExclusivePhalaPinnedPrivateFile(
      outputHandle,
      basename,
      bytes,
      { mode: 0o600, maximum },
    );
    const reread = readPhalaPinnedPrivateFile(outputHandle, basename, {
      mode: 0o600,
      minimum: 0,
      maximum,
      expectedIdentity: identity,
    });
    if (!reread.equals(bytes)) {
      throw new Error(`${basename} differs after exact output publication reread`);
    }
    published.push(Object.freeze({ basename, bytes, identity, maximum }));
    return identity;
  };
  {
    const receiptBytes = Buffer.from(
      canonicalPhalaPostMeasurementActivationExecutionReceiptText(receipt),
      "utf8",
    );
    const observationBytes = Buffer.from(
      canonicalComputeWorkloadActivationObservationText(observation),
      "utf8",
    );
    const browserEnvBytes = Buffer.from(
      canonicalResidentJsonText(browserEnv),
      "utf8",
    );
    ({ receipt, observation } = assertCurrentExactPublicationAuthority());
    const receiptIdentity = createAndReread(
      "activation-execution-receipt.json",
      receiptBytes,
      MAXIMUM_TRANSPORT_BYTES,
    );
    const observationIdentity = createAndReread(
      "compute-workload-activation-observation.json",
      observationBytes,
      MAXIMUM_TRANSPORT_BYTES,
    );
    const browserEnvIdentity = createAndReread(
      "compute-workload-browser-env.json",
      browserEnvBytes,
      256 * 1024,
    );
    const publicationReceipt = Object.freeze({
      schema: "dnai.phala-production-activation-publication-receipt.v1",
      status: "all_bounded_post_activation_outputs_create_new_and_complete",
      truth_status:
        "receipt_observation_and_browser_env_published_manifest_written_last_no_live_traffic_authority",
      release_sha: releaseSha,
      batch_id: batchId,
      activation_execution_receipt: Object.freeze({
        basename: "activation-execution-receipt.json",
        raw_file_sha256: receiptIdentity.sha256,
        size: receiptIdentity.size,
        mode: receiptIdentity.mode,
        authority_sha256:
          phalaPostMeasurementActivationExecutionReceiptSha256(receipt),
      }),
      compute_workload_activation_observation: Object.freeze({
        basename: "compute-workload-activation-observation.json",
        raw_file_sha256: observationIdentity.sha256,
        size: observationIdentity.size,
        mode: observationIdentity.mode,
        authority_sha256: computeWorkloadActivationObservationSha256(observation),
      }),
      compute_workload_browser_env: Object.freeze({
        basename: "compute-workload-browser-env.json",
        raw_file_sha256: browserEnvIdentity.sha256,
        size: browserEnvIdentity.size,
        mode: browserEnvIdentity.mode,
      }),
      publication_complete: true,
      create_new_outputs_only: true,
      automatic_retry_authorized: false,
      live_traffic_authorized: false,
    });
    assertPinnedPhalaPrivateDirectoryPathIdentity(outputHandle);
    if (JSON.stringify(listPhalaPinnedPrivateEntries(outputHandle))
      !== JSON.stringify(published.map(({ basename }) => basename).sort())) {
      throw new Error("bounded output authority contains unexpected entries before final receipt");
    }
    const publicationBytes = Buffer.from(
      canonicalResidentJsonText(publicationReceipt),
      "utf8",
    );
    ({ receipt, observation } = assertCurrentExactPublicationAuthority());
    const publicationIdentity = createAndReread(
      PHALA_PRODUCTION_ACTIVATION_PUBLICATION_RECEIPT_BASENAME,
      publicationBytes,
      256 * 1024,
    );
    for (const file of published) {
      const finalReread = readPhalaPinnedPrivateFile(
        outputHandle,
        file.basename,
        {
          mode: 0o600,
          minimum: 0,
          maximum: file.maximum,
          expectedIdentity: file.identity,
        },
      );
      if (!finalReread.equals(file.bytes)) {
        throw new Error(`${file.basename} changed before complete publication return`);
      }
    }
    assertPinnedPhalaPrivateDirectoryPathIdentity(outputHandle);
    if (JSON.stringify(listPhalaPinnedPrivateEntries(outputHandle))
      !== JSON.stringify(published.map(({ basename }) => basename).sort())) {
      throw new Error("bounded output authority changed after final receipt publication");
    }
    ({ receipt, observation } = assertCurrentExactPublicationAuthority());
    return Object.freeze({
      output_directory_identity_anchor_sha256:
        phalaPinnedPrivateDirectoryIdentityAnchorSha256(outputHandle),
      activation_execution_receipt: Object.freeze({
        basename: "activation-execution-receipt.json",
        raw_file_sha256: receiptIdentity.sha256,
        authority_sha256:
          phalaPostMeasurementActivationExecutionReceiptSha256(receipt),
      }),
      compute_workload_activation_observation: Object.freeze({
        basename: "compute-workload-activation-observation.json",
        raw_file_sha256: observationIdentity.sha256,
        authority_sha256: computeWorkloadActivationObservationSha256(observation),
      }),
      compute_workload_browser_env: Object.freeze({
        basename: "compute-workload-browser-env.json",
        raw_file_sha256: browserEnvIdentity.sha256,
      }),
      publication_receipt: Object.freeze({
        basename: PHALA_PRODUCTION_ACTIVATION_PUBLICATION_RECEIPT_BASENAME,
        raw_file_sha256: publicationIdentity.sha256,
      }),
    });
  }
}

function assertPreterminalRecipientCompletionHeadroom(value, runtimeSession) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || !Number.isSafeInteger(value.expires_at)
    || !Number.isSafeInteger(value.recipient_evidence_lease_expires_at)
    || value.expires_at !== value.recipient_evidence_lease_expires_at) {
    throw new Error("recipient activation lacks a bounded expiry before completion");
  }
  const runtimeDeadlines = readPhalaProductionActivationRuntimeDeadlines(
    runtimeSession,
  );
  const terminalExpiresAt = Math.min(
    runtimeDeadlines.activation_authority_expires_at,
    value.recipient_evidence_lease_expires_at,
  );
  const currentCeilingSecond = Math.ceil(Date.now() / 1_000);
  if (terminalExpiresAt - currentCeilingSecond
      < PHALA_PRODUCTION_RECIPIENT_COMPLETION_HEADROOM_SECONDS) {
    throw new Error(
      "recipient activation lacks the required preterminal receipt/O/browser-env projection headroom",
    );
  }
}

async function executeResidentRequest(request) {
  const { launch, activation } = request;
  const state = new ResidentActivationStateMachine();
  let evidenceHandle;
  let signingHandle;
  let outputHandle;
  let challengeLedger;
  let liveSession = null;
  let completed = false;
  try {
    evidenceHandle = attachEmptyResidentPrivateAuthority(
      activation.evidenceExchangeAuthority,
      "resident evidence exchange authority",
    );
    signingHandle = attachEmptyResidentPrivateAuthority(
      activation.signingExchangeAuthority,
      "resident Stage-B signing exchange authority",
    );
    outputHandle = attachEmptyResidentPrivateAuthority(
      activation.outputAuthority,
      "resident bounded output authority",
    );
    challengeLedger = new PhalaDurableReleaseChallengeLedger(
      activation.evidenceExchangeAuthority.path,
      {
        expectedDevice: evidenceHandle.device,
        expectedInode: evidenceHandle.inode,
        expectedUid: evidenceHandle.uid,
      },
    );
    state.advance("request_preflight_complete", {
      evidence_exchange_authority: activation.evidenceExchangeAuthority,
      signing_exchange_authority: activation.signingExchangeAuthority,
      output_authority: activation.outputAuthority,
    });

    const launchRuntimeResult =
      await executePhalaSevenCvmProductionLaunch(launch);
    state.advance("seven_cvm_launch_complete_non_live", {
      release_sha: launchRuntimeResult.release_sha,
      batch_id: launchRuntimeResult.batch_id,
    });

    liveSession = preparePhalaProductionActivationEvidence({
      descriptorSetReceipt: activation.descriptorSetReceipt,
      freshContractDeploymentReceipt:
        activation.freshContractDeploymentReceipt,
      launchRecoveryDirectory: launch.recoveryDirectory,
      launchRuntimeResult,
      measurementPolicySet: activation.measurementPolicySet,
      releaseManifestSigstoreVerificationReceipt:
        activation.releaseManifestSigstoreVerificationReceipt,
      reviewerGenesis: activation.reviewerGenesis,
      reviewerGenesisAcceptance: activation.reviewerGenesisAcceptance,
      reviewerStatusHistory: activation.reviewerStatusHistory,
    });
    const { releaseVerificationAuthority } =
      readPhalaProductionActivationEvidenceDependencies(liveSession);
    const qvlIdentityEvidence = [];
    const evidenceDeadlineMs = Date.now()
      + activation.evidenceTimeoutSeconds * 1_000;
    state.advance("collecting_five_qvl_identity_proofs", {
      proof_count_required: QVL_IDENTITY_DOMAINS.length,
      live_qvl_transport_required: true,
    });
    for (let index = 0; index < QVL_IDENTITY_DOMAINS.length; index += 1) {
      const domain = QVL_IDENTITY_DOMAINS[index];
      const remainingSeconds = Math.floor((evidenceDeadlineMs - Date.now()) / 1_000);
      if (remainingSeconds < 2) {
        throw new Error("seven-CVM evidence collection deadline expired");
      }
      const ttlSeconds = Math.min(
        activation.qvlIdentityTtlSeconds,
        remainingSeconds,
      );
      const identityRequest = createPhalaQvlIdentityChallenge({
        domain,
        releaseAuthority: releaseVerificationAuthority,
        ttlSeconds,
      });
      const requestBasename = transportBasename(
        index + 1,
        domain,
        "identity-request",
      );
      const responseBasename = transportBasename(
        index + 1,
        domain,
        "identity-response",
      );
      const requestText = canonicalResidentJsonText(identityRequest);
      const requestIdentity = createExclusivePhalaPinnedPrivateFile(
        evidenceHandle,
        requestBasename,
        Buffer.from(requestText, "utf8"),
        { mode: 0o600, maximum: MAXIMUM_TRANSPORT_BYTES },
      );
      state.advance("collecting_five_qvl_identity_proofs", {
        domain,
        identity_request_path:
          phalaPinnedPrivatePathForDisplay(evidenceHandle, requestBasename),
        identity_request_sha256: requestIdentity.sha256,
        required_response_path:
          phalaPinnedPrivatePathForDisplay(evidenceHandle, responseBasename),
        live_qvl_identity_https_transport_required: true,
      });
      const responseRead = await waitForPinnedCanonicalResident0600Json({
        handle: evidenceHandle,
        fileName: responseBasename,
        label: `${domain} live QVL identity response`,
        deadlineMs: evidenceDeadlineMs,
        pollIntervalMilliseconds: activation.pollIntervalMilliseconds,
      });
      qvlIdentityEvidence.push(await verifyPhalaQvlIdentityLaunchEvidence({
        domain,
        releaseAuthority: releaseVerificationAuthority,
        request: identityRequest,
        response: responseRead.value,
        rawRequestText: requestText,
        rawResponseText: responseRead.text,
        ledger: challengeLedger,
      }));
    }

    const workloadVerdictEvidence = [];
    state.advance("collecting_two_workload_verdict_proofs", {
      proof_count_required: WORKLOAD_DOMAINS.length,
      live_qvl_and_workload_quote_transport_required: true,
    });
    for (let index = 0; index < WORKLOAD_DOMAINS.length; index += 1) {
      const domain = WORKLOAD_DOMAINS[index];
      const link = PHALA_WORKLOAD_DOMAIN_QVL_LINK[domain];
      const linkedQvl = qvlIdentityEvidence.find(
        (entry) => entry.domain === link.qvl_domain,
      );
      if (!linkedQvl) {
        throw new Error(`${domain} linked QVL identity proof disappeared`);
      }
      const request = workloadChallengeRequest(
        releaseVerificationAuthority,
        linkedQvl,
        domain,
      );
      const sequence = QVL_IDENTITY_DOMAINS.length + index + 1;
      const requestBasename = transportBasename(
        sequence,
        domain,
        "challenge-request",
      );
      const challengeBasename = transportBasename(
        sequence,
        domain,
        "challenge",
      );
      const verdictBasename = transportBasename(
        sequence,
        domain,
        "verdict",
      );
      const requestIdentity = createPinnedCanonicalJson(
        evidenceHandle,
        requestBasename,
        request,
        64 * 1024,
      );
      state.advance("collecting_two_workload_verdict_proofs", {
        domain,
        challenge_request_path:
          phalaPinnedPrivatePathForDisplay(evidenceHandle, requestBasename),
        challenge_request_sha256: requestIdentity.sha256,
        required_challenge_path:
          phalaPinnedPrivatePathForDisplay(evidenceHandle, challengeBasename),
        required_verdict_path:
          phalaPinnedPrivatePathForDisplay(evidenceHandle, verdictBasename),
        live_qvl_and_workload_quote_transport_required: true,
      });
      const challengeRead = await waitForPinnedCanonicalResident0600Json({
        handle: evidenceHandle,
        fileName: challengeBasename,
        label: `${domain} live QVL challenge`,
        deadlineMs: evidenceDeadlineMs,
        pollIntervalMilliseconds: activation.pollIntervalMilliseconds,
      });
      const verdictRead = await waitForPinnedCanonicalResident0600Json({
        handle: evidenceHandle,
        fileName: verdictBasename,
        label: `${domain} live independent TDX verdict`,
        deadlineMs: evidenceDeadlineMs,
        pollIntervalMilliseconds: activation.pollIntervalMilliseconds,
      });
      workloadVerdictEvidence.push(verifyPhalaWorkloadIndependentTdxVerdict({
        domain,
        releaseAuthority: releaseVerificationAuthority,
        challenge: challengeRead.value,
        verdict: verdictRead.value,
        rawChallengeText: challengeRead.text,
        rawVerdictText: verdictRead.text,
        expected: Object.freeze({
          reportDataBinding: reportDataBinding(activation, domain),
        }),
        qvlIdentityEvidence: linkedQvl,
        challengeLedger,
      }));
    }
    challengeLedger.close();
    challengeLedger = null;

    assertPinnedPhalaPrivateDirectoryPathIdentity(evidenceHandle);
    assertPinnedPhalaPrivateDirectoryPathIdentity(signingHandle);
    assertPinnedPhalaPrivateDirectoryPathIdentity(outputHandle);
    const signingSession = await resumePhalaProductionActivationWithPinnedSigningExchange({
      bootstrapPhaseInput: activation.bootstrapPhaseInput,
      ceremonyLedgerInitializationReceipt:
        activation.ceremonyLedgerInitializationReceipt,
      ceremonyLedgerInitial: activation.ceremonyLedgerInitial,
      ceremonyTransactionPlan: activation.ceremonyTransactionPlan,
      deferredAuthorityReview: activation.deferredAuthorityReview,
      finalPhaseInput: activation.finalPhaseInput,
      immutableDeploymentManifest: activation.immutableDeploymentManifest,
      qvlIdentityEvidence,
      reviewedFinalAuthorityFiles: activation.reviewedFinalAuthorityFiles,
      session: liveSession,
      signingExchangeAuthority: signingHandle,
      signingExchangeDirectory: activation.signingExchangeAuthority.path,
      workloadVerdictEvidence,
    });
    liveSession = signingSession;
    const signingPaths = phalaProductionActivationSigningExchangePaths(
      signingSession,
    );
    let stageB;
    assertPinnedPhalaPrivateDirectoryPathIdentity(signingHandle);
    stageB = createStageBAttachmentManifest(signingHandle, signingSession);
    state.advance("waiting_for_external_stage_b_signatures", {
      signing_exchange_directory: activation.signingExchangeAuthority.path,
      signing_exchange_directory_identity_anchor_sha256:
        signingSession.signing_exchange_directory_identity_anchor_sha256,
      attachment_manifest_path: phalaPinnedPrivatePathForDisplay(
        signingHandle,
        PHALA_PRODUCTION_STAGE_B_ATTACHMENT_MANIFEST_BASENAME,
      ),
      external_signatures_path: phalaPinnedPrivatePathForDisplay(
        signingHandle,
        stageB.externalSignaturesBasename,
      ),
      signed_b_output_path: signingPaths.signedBOutputPath,
      non_signing_attachment_helper:
        "scripts/phala-production-stage-b-attach.mjs",
    });
    await waitForPinnedCanonicalResident0600Json({
      handle: signingHandle,
      fileName: signingSession.signed_b_output.basename,
      label: "code-owned signed-B candidate",
      deadlineMs: Date.now() + activation.signingTimeoutSeconds * 1_000,
      pollIntervalMilliseconds: activation.pollIntervalMilliseconds,
    });

    let runtimeSession;
    try {
      runtimeSession = await beginPhalaProductionActivationFromSignedB({
        session: liveSession,
      });
    } catch (error) {
      safeDispose(liveSession);
      liveSession = null;
      throw error;
    }
    liveSession = runtimeSession;
    state.advance("post_measurement_runtime_mutated_non_live", {
      release_sha: runtimeSession.release_sha,
      batch_id: runtimeSession.batch_id,
      durable_state_status: runtimeSession.durable_state_status,
    });

    const recipientTransport = createRecipientTransportRequest(
      evidenceHandle,
      runtimeSession,
    );
    state.advance("waiting_for_compute_recipient_activation", {
      recipient_transport_request_path: phalaPinnedPrivatePathForDisplay(
        evidenceHandle,
        recipientTransport.requestBasename,
      ),
      required_recipient_activation_path: phalaPinnedPrivatePathForDisplay(
        evidenceHandle,
        recipientTransport.basename,
      ),
      live_post_restart_recipient_transport_required: true,
    });
    const recipientRead = await waitForPinnedCanonicalResident0600Json({
      handle: evidenceHandle,
      fileName: recipientTransport.basename,
      label: "live post-restart compute recipient activation",
      deadlineMs: Date.now() + activation.recipientTimeoutSeconds * 1_000,
      pollIntervalMilliseconds: activation.pollIntervalMilliseconds,
    });
    // This check is deliberately preterminal and conservative. It cannot mint
    // authority from the untrusted source object; the coordinator still
    // authenticates the exact activation. It only refuses to enter durable
    // completion unless at least 30 seconds remain for the immediate fresh-O
    // browser-env projection and create-new publication that follow.
    assertPreterminalRecipientCompletionHeadroom(
      recipientRead.value,
      liveSession,
    );
    const completion = await completePhalaProductionActivation({
      session: liveSession,
      recipientActivation: recipientRead.value,
    });
    // Retain the exact runtime capability until completion returns. If input
    // rejection happens before a lower layer consumes it, the outer finally
    // can still dispose/quarantine the live lock. If a lower layer already
    // consumed it, safeDispose fails closed against the stale reference.
    liveSession = null;
    if (completion.live_traffic_authorized !== false) {
      throw new Error("activation completion unexpectedly authorized live traffic");
    }
    // Do not weaken O freshness by switching to a historical projector. This
    // synchronous call follows completion without an intervening await. If it
    // still fails (for example an unexpectedly slow terminal operation), no
    // publication receipt is written and live traffic remains unauthorized;
    // the durable completion journal requires explicit operator recovery.
    const browserEnv = projectComputeWorkloadBrowserEnvFromObservation(
      completion.compute_workload_activation_observation,
    );
    completed = true;
    state.advance("activation_finalized_non_live", {
      release_sha: runtimeSession.release_sha,
      batch_id: runtimeSession.batch_id,
    });

    const outputs = publishFinalOutputs(
      outputHandle,
      completion,
      browserEnv,
      {
        releaseSha: runtimeSession.release_sha,
        batchId: runtimeSession.batch_id,
      },
    );
    const final = Object.freeze({
      schema: PHALA_PRODUCTION_ACTIVATION_DRIVER_RESULT_SCHEMA,
      status: "resident_production_activation_finalized_outputs_published_non_live",
      truth_status:
        "same_process_branded_authority_chain_completed_bounded_outputs_only_no_live_traffic_authority",
      release_sha: runtimeSession.release_sha,
      batch_id: runtimeSession.batch_id,
      outputs,
      capability_serialized: false,
      signer_key_material_accepted: false,
      automatic_retry_authorized: false,
      live_traffic_authorized: false,
    });
    state.advance("bounded_outputs_published_non_live", {
      release_sha: final.release_sha,
      batch_id: final.batch_id,
      output_directory: activation.outputAuthority.path,
    });
    process.stdout.write(canonicalResidentJsonText(final));
    return 0;
  } finally {
    if (!completed) safeDispose(liveSession);
    if (challengeLedger) challengeLedger.close();
    if (evidenceHandle) closePhalaPinnedPrivateDirectory(evidenceHandle);
    if (signingHandle) closePhalaPinnedPrivateDirectory(signingHandle);
    if (outputHandle) closePhalaPinnedPrivateDirectory(outputHandle);
  }
}

export async function main(argv = process.argv.slice(2)) {
  if (Array.isArray(argv) && argv.length === 1
    && ["--help", "-h"].includes(argv[0])) {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }
  if (!Array.isArray(argv) || argv.length !== 2
    || argv[0] !== "--execute-request") {
    throw new Error("resident activation accepts one exact 0600 request path");
  }
  const requestPath = canonicalResidentAbsolutePath(
    argv[1],
    "resident activation request",
  );
  const read = readStableCanonicalResident0600Json(
    requestPath,
    "resident activation request",
    { maximum: 128 * 1024 },
  );
  const request = normalizePhalaProductionActivationDriverRequest(read.value);
  return executeResidentRequest(request);
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().then(
    (code) => { process.exitCode = code; },
    () => {
      process.stderr.write(`${PHALA_PRODUCTION_ACTIVATION_DRIVER_FAILED_CODE}\n`);
      process.exitCode = 1;
    },
  );
}
