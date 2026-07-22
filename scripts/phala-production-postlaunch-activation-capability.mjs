import { createHash } from "node:crypto";

import {
  assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt,
  canonicalPhalaSevenCvmLaunchCompletionReceiptText,
  phalaSevenCvmLaunchCompletionReceiptSha256,
} from "./phala-seven-cvm-launch-completion.mjs";
import {
  assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority,
  assertProductionPhalaSevenCvmEvidenceSet,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
  phalaSevenCvmVerifiedEvidenceSetSha256,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  assertPinnedPhalaPrivateDirectoryPathIdentity,
  createExclusivePhalaPinnedPrivateFile,
  listPhalaPinnedPrivateEntries,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  readPhalaPinnedPrivateFile,
} from "./phala-pinned-private-directory.mjs";
import {
  canonicalResidentJsonText,
  exactResidentRecord,
  normalizeResidentFileBinding,
  preflightResidentBoundFile,
  readStableCanonicalResident0600Json,
  residentRawSha256,
  waitForPinnedCanonicalResident0600JsonPendingReady,
} from "./phala-production-resident-io.mjs";

export const PHALA_PRODUCTION_POSTLAUNCH_PROJECTION_SCHEMA =
  "dnai.phala-production-postlaunch-final-authority-input.v1";
export const PHALA_PRODUCTION_POSTLAUNCH_REQUEST_SCHEMA =
  "dnai.phala-production-postlaunch-authority-request.v2";
export const PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA =
  "dnai.phala-production-postlaunch-activation-input-manifest.v2";
export const PHALA_PRODUCTION_POSTLAUNCH_CAPABILITY_SCHEMA =
  "dnai.phala-production-postlaunch-activation-capability.v1";
export const PHALA_PRODUCTION_POSTLAUNCH_COMPLETION_BASENAME =
  "seven-cvm-launch-completion-receipt.json";
export const PHALA_PRODUCTION_POSTLAUNCH_PROJECTION_BASENAME =
  "postlaunch-final-authority-input.json";
export const PHALA_PRODUCTION_POSTLAUNCH_REQUEST_BASENAME =
  "postlaunch-authority-request.json";
export const PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME =
  "postlaunch-activation-input-manifest.json";

export const PHALA_PRODUCTION_POSTLAUNCH_REVIEWED_FINAL_FIELDS = Object.freeze([
  "cvmLaunchIntent",
  "deploymentIntent",
  "finalAuthority",
  "reviewEnvelope",
  "reviewEvidence",
]);
export const PHALA_PRODUCTION_POSTLAUNCH_DEPENDENCY_FIELDS = Object.freeze([
  "ceremonyLedgerInitial",
  "ceremonyLedgerInitializationReceipt",
  "ceremonyTransactionPlan",
  "deferredAuthorityReview",
  "immutableDeploymentManifest",
  "reviewedFinalAuthorityFiles",
  "stageBReviewerStatusHistory",
]);
export const PHALA_PRODUCTION_POSTLAUNCH_LINEAGE_FIELDS = Object.freeze([
  "batch_id",
  "cvm_launch_intent_sha256",
  "deployment_intent_sha256",
  "manifest_acceptance_deadline",
  "postlaunch_projection_raw_file_sha256",
  "postlaunch_request_raw_file_sha256",
  "release_sha",
  "release_verification_authority_sha256",
  "seven_cvm_launch_completion_receipt_sha256",
  "seven_cvm_verified_evidence_set_sha256",
]);

const POSTLAUNCH_PUBLIC_DOMAIN_FIELDS = Object.freeze([
  "app_id",
  "bound_contract_address",
  "bound_contract_name",
  "committed_compose_hash",
  "cvm_id",
  "descriptor_sha256",
  "disk_size",
  "domain",
  "instance_type",
  "kms_id",
  "machine_evidence_kind",
  "machine_evidence_sha256",
  "os_image_hash",
  "production_posture_verification_receipt_sha256",
  "qvl_identity_sha256",
  "qvl_release_policy_sha256",
  "qvl_verification_receipt_sha256",
  "tdx_attestation_evidence_sha256",
  "tdx_attestation_verification_receipt_sha256",
  "tdx_measurement_authority_sha256",
  "tdx_measurements_sha256",
  "tee_identity",
]);
const CHECKPOINT_FIELDS = Object.freeze([
  "activation_mutation_authorized",
  "batch_id",
  "launchCompletionReceipt",
  "live_traffic_authorized",
  "releaseVerificationAuthority",
  "release_sha",
  "verifiedEvidenceSet",
]);
const MANIFEST_FIELDS = Object.freeze([
  "activation_mutation_authorized",
  "automatic_retry_authorized",
  "batch_id",
  "cvm_launch_intent_sha256",
  "dependencies",
  "deployment_intent_sha256",
  "live_traffic_authorized",
  "manifest_acceptance_deadline",
  "postlaunch_projection_raw_file_sha256",
  "postlaunch_request_raw_file_sha256",
  "release_sha",
  "release_verification_authority_sha256",
  "schema",
  "seven_cvm_launch_completion_receipt_sha256",
  "seven_cvm_verified_evidence_set_sha256",
  "status",
  "truth_status",
]);
const CAPABILITY_WAIT_FIELDS = Object.freeze([
  "evidenceSession",
  "handle",
  "handoff",
  "launchCompletionReceipt",
  "pollIntervalMilliseconds",
  "releaseVerificationAuthority",
  "verifiedEvidenceSet",
]);
const CAPABILITY_CONSUME_FIELDS = Object.freeze([
  "batchId",
  "evidenceSession",
  "launchCompletionReceipt",
  "releaseSha",
  "releaseVerificationAuthority",
  "verifiedEvidenceSet",
]);
const HANDOFF_PUBLISH_FIELDS = Object.freeze([
  "checkpointValue",
  "evidenceHandle",
  "evidenceSession",
  "postlaunchAuthorityTimeoutSeconds",
  "postlaunchAuthorityHandle",
]);
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const RELEASE_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const ISO_MILLISECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CHAIN_ID = 84_532;
const MAXIMUM_TRANSPORT_BYTES = 4 * 1024 * 1024;
const MAXIMUM_MANIFEST_BYTES = 256 * 1024;
const CAPABILITY_DOMAIN =
  "dnai-wikigen/phala-production-postlaunch-activation-capability/v1\0";

// One evidence-session object may publish exactly one postlaunch handoff and
// can mint at most one capability. Failed publication or validation remains a
// terminal session-local state; callers cannot redirect the same session to a
// competing authority directory.
const SESSION_HANDOFFS = new WeakMap();
const AUTHORITY_HANDOFFS_BY_ANCHOR = new Map();
const CAPABILITIES = new WeakMap();

function terminalizePostlaunchHandoffState(state, status) {
  if (!state) return;
  state.status = status;
  state.capability = null;
  state.checkpoint = null;
  state.evidenceHandle = null;
  state.postlaunchAuthorityHandle = null;
  state.authorityDirectoryIdentityAnchorSha256 = null;
  state.handoff = null;
}

function sha256Text(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalResidentJsonText(value), "utf8")
    .digest("hex")}`;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const entry of Object.values(value)) deepFreeze(entry);
  return Object.freeze(value);
}

function canonicalManifestAcceptanceDeadline(value) {
  if (typeof value !== "string" || !ISO_MILLISECOND.test(value)
    || new Date(Date.parse(value)).toISOString() !== value) {
    throw new Error(
      "manifest acceptance deadline must be one canonical UTC millisecond",
    );
  }
  return value;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function exactReleaseSha(value, label) {
  if (typeof value !== "string" || !RELEASE_SHA.test(value)) {
    throw new Error(`${label} must be a nonzero lowercase release SHA`);
  }
  return value;
}

function exactBatchId(value, label) {
  if (typeof value !== "string" || value.length < 8 || value.length > 160
    || /[\0\r\n]/.test(value)) {
    throw new Error(`${label} must be one bounded batch identifier`);
  }
  return value;
}

function projectPostlaunchPublicDomain(domain) {
  return Object.freeze(Object.fromEntries(
    POSTLAUNCH_PUBLIC_DOMAIN_FIELDS.map((field) => [field, domain[field]]),
  ));
}

function normalizeCheckpoint(value) {
  const checkpoint = exactResidentRecord(
    value,
    CHECKPOINT_FIELDS,
    "postlaunch coordinator checkpoint",
  );
  if (checkpoint.activation_mutation_authorized !== false
    || checkpoint.live_traffic_authorized !== false) {
    throw new Error("postlaunch coordinator checkpoint unexpectedly authorizes mutation");
  }
  exactReleaseSha(checkpoint.release_sha, "postlaunch checkpoint release");
  exactBatchId(checkpoint.batch_id, "postlaunch checkpoint batch");
  assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority(
    checkpoint.releaseVerificationAuthority,
  );
  assertProductionPhalaSevenCvmEvidenceSet(checkpoint.verifiedEvidenceSet);
  assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt(
    checkpoint.launchCompletionReceipt,
  );
  return checkpoint;
}

export function createPhalaProductionPostlaunchProjection(value) {
  const checkpoint = normalizeCheckpoint(value);
  const launchCompletion = checkpoint.launchCompletionReceipt;
  canonicalPhalaSevenCvmLaunchCompletionReceiptText(launchCompletion);
  const launchCompletionSha256 =
    phalaSevenCvmLaunchCompletionReceiptSha256(launchCompletion);
  const releaseAuthoritySha256 = phalaSevenCvmReleaseVerificationAuthoritySha256(
    checkpoint.releaseVerificationAuthority,
  );
  const evidenceSetSha256 = phalaSevenCvmVerifiedEvidenceSetSha256(
    checkpoint.verifiedEvidenceSet,
  );
  if (checkpoint.release_sha !== launchCompletion.release_sha
    || checkpoint.batch_id !== launchCompletion.batch_id
    || launchCompletion.release_verification_authority_sha256
      !== releaseAuthoritySha256
    || launchCompletion.machine_verifier_evidence_set_sha256
      !== evidenceSetSha256
    || !Array.isArray(launchCompletion.domains)
    || launchCompletion.domains.length !== 7) {
    throw new Error("postlaunch checkpoint lineage differs from persisted L");
  }
  return Object.freeze({
    schema: PHALA_PRODUCTION_POSTLAUNCH_PROJECTION_SCHEMA,
    status:
      "seven_cvm_launch_completion_persisted_pending_reviewed_final_authority",
    truth_status:
      "public_machine_evidence_projection_not_review_signature_mutation_or_live_authority",
    chain_id: CHAIN_ID,
    release_sha: launchCompletion.release_sha,
    batch_id: launchCompletion.batch_id,
    deployment_intent_sha256: launchCompletion.deployment_intent_sha256,
    cvm_launch_intent_sha256: launchCompletion.cvm_launch_intent_sha256,
    fresh_contract_deployment_receipt_sha256:
      launchCompletion.fresh_contract_deployment_receipt_sha256,
    release_verification_authority_sha256: releaseAuthoritySha256,
    seven_cvm_verified_evidence_set_sha256: evidenceSetSha256,
    seven_cvm_launch_completion_receipt_sha256: launchCompletionSha256,
    historical_transcript_file_set_sha256:
      launchCompletion.historical_transcript_file_set_sha256,
    qvl_measurement_policy_set_sha256:
      checkpoint.releaseVerificationAuthority.qvl_measurement_policy_set_sha256,
    completed_at: launchCompletion.completed_at,
    activation_evidence_lease_expires_at:
      launchCompletion.activation_evidence_lease_expires_at,
    domains: Object.freeze(launchCompletion.domains.map(
      projectPostlaunchPublicDomain,
    )),
    private_historical_transcript_contains_raw_quote_bytes: true,
    raw_quote_external_egress: false,
    raw_secret_egress: false,
    raw_private_artifact_egress: false,
    encrypted_environment_ciphertext_egress: false,
    activation_mutation_authorized: false,
    live_traffic_authorized: false,
  });
}

function createPinnedCanonicalJson(handle, fileName, value, maximum) {
  return createExclusivePhalaPinnedPrivateFile(
    handle,
    fileName,
    Buffer.from(canonicalResidentJsonText(value), "utf8"),
    { mode: 0o600, maximum },
  );
}

export function publishPhalaProductionPostlaunchHandoff(input = {}) {
  const parsed = exactResidentRecord(
    input,
    HANDOFF_PUBLISH_FIELDS,
    "postlaunch handoff publication input",
  );
  if (!parsed.evidenceSession || typeof parsed.evidenceSession !== "object") {
    throw new Error("postlaunch handoff requires the exact evidence-session object");
  }
  if (SESSION_HANDOFFS.has(parsed.evidenceSession)) {
    throw new Error(
      "the evidence session already attempted one postlaunch handoff; parallel or replay publication is forbidden",
    );
  }
  const state = { status: "publication_started" };
  SESSION_HANDOFFS.set(parsed.evidenceSession, state);
  try {
    const checkpoint = normalizeCheckpoint(parsed.checkpointValue);
    if (!Number.isSafeInteger(parsed.postlaunchAuthorityTimeoutSeconds)
      || parsed.postlaunchAuthorityTimeoutSeconds < 1
      || parsed.postlaunchAuthorityTimeoutSeconds > 240) {
      throw new Error("postlaunch authority timeout is invalid");
    }
    const deadlineComputedAtMs = Date.now();
    const evidenceLeaseDeadlineMs =
      checkpoint.launchCompletionReceipt.activation_evidence_lease_expires_at
      * 1_000;
    const manifestAcceptanceDeadlineMs = Math.min(
      deadlineComputedAtMs + parsed.postlaunchAuthorityTimeoutSeconds * 1_000,
      evidenceLeaseDeadlineMs,
    );
    assertDeadlineActive(manifestAcceptanceDeadlineMs);
    const manifestAcceptanceDeadline = new Date(
      manifestAcceptanceDeadlineMs,
    ).toISOString();
    if (parsed.evidenceSession.release_sha !== checkpoint.release_sha
      || parsed.evidenceSession.batch_id !== checkpoint.batch_id) {
      throw new Error("postlaunch handoff evidence-session lineage is invalid");
    }
    assertPinnedPhalaPrivateDirectoryPathIdentity(parsed.evidenceHandle);
    assertPinnedPhalaPrivateDirectoryPathIdentity(
      parsed.postlaunchAuthorityHandle,
    );
    const authorityDirectoryIdentityAnchorSha256 =
      phalaPinnedPrivateDirectoryIdentityAnchorSha256(
        parsed.postlaunchAuthorityHandle,
      );
    if (AUTHORITY_HANDOFFS_BY_ANCHOR.has(
      authorityDirectoryIdentityAnchorSha256,
    )) {
      throw new Error(
        "postlaunch authority exchange is already assigned to another one-shot handoff",
      );
    }
    AUTHORITY_HANDOFFS_BY_ANCHOR.set(
      authorityDirectoryIdentityAnchorSha256,
      true,
    );
    if (listPhalaPinnedPrivateEntries(
      parsed.postlaunchAuthorityHandle,
    ).length !== 0) {
      throw new Error("postlaunch authority exchange changed before L publication");
    }
    const projection = createPhalaProductionPostlaunchProjection(checkpoint);
    const launchCompletionIdentity = createExclusivePhalaPinnedPrivateFile(
      parsed.evidenceHandle,
      PHALA_PRODUCTION_POSTLAUNCH_COMPLETION_BASENAME,
      Buffer.from(canonicalPhalaSevenCvmLaunchCompletionReceiptText(
        checkpoint.launchCompletionReceipt,
      ), "utf8"),
      { mode: 0o600, maximum: MAXIMUM_TRANSPORT_BYTES },
    );
    const projectionIdentity = createPinnedCanonicalJson(
      parsed.evidenceHandle,
      PHALA_PRODUCTION_POSTLAUNCH_PROJECTION_BASENAME,
      projection,
      512 * 1024,
    );
    const request = Object.freeze({
      schema: PHALA_PRODUCTION_POSTLAUNCH_REQUEST_SCHEMA,
      status: "waiting_for_exact_postlaunch_activation_input_manifest",
      truth_status:
        "transport_request_only_not_review_signature_mutation_or_live_authority",
      release_sha: projection.release_sha,
      batch_id: projection.batch_id,
      deployment_intent_sha256: projection.deployment_intent_sha256,
      cvm_launch_intent_sha256: projection.cvm_launch_intent_sha256,
      release_verification_authority_sha256:
        projection.release_verification_authority_sha256,
      seven_cvm_verified_evidence_set_sha256:
        projection.seven_cvm_verified_evidence_set_sha256,
      seven_cvm_launch_completion_receipt_sha256:
        projection.seven_cvm_launch_completion_receipt_sha256,
      manifest_acceptance_deadline: manifestAcceptanceDeadline,
      launch_completion_raw_file_sha256: launchCompletionIdentity.sha256,
      postlaunch_projection_raw_file_sha256: projectionIdentity.sha256,
      postlaunch_authority_exchange_identity_anchor_sha256:
        phalaPinnedPrivateDirectoryIdentityAnchorSha256(
          parsed.postlaunchAuthorityHandle,
        ),
      required_input: Object.freeze({
        basename: PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
        mode: "0600",
        canonical_json_required: true,
        schema: PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA,
      }),
      automatic_retry_authorized: false,
      activation_mutation_authorized: false,
      live_traffic_authorized: false,
    });
    const requestIdentity = createPinnedCanonicalJson(
      parsed.evidenceHandle,
      PHALA_PRODUCTION_POSTLAUNCH_REQUEST_BASENAME,
      request,
      128 * 1024,
    );
    assertPinnedPhalaPrivateDirectoryPathIdentity(parsed.evidenceHandle);
    assertPinnedPhalaPrivateDirectoryPathIdentity(
      parsed.postlaunchAuthorityHandle,
    );
    if (listPhalaPinnedPrivateEntries(
      parsed.postlaunchAuthorityHandle,
    ).length !== 0) {
      throw new Error("postlaunch authority exchange changed during L publication");
    }
    const handoff = Object.freeze({
      projection,
      request,
      launch_completion_raw_file_sha256: launchCompletionIdentity.sha256,
      postlaunch_projection_raw_file_sha256: projectionIdentity.sha256,
      postlaunch_request_raw_file_sha256: requestIdentity.sha256,
    });
    Object.assign(state, {
      status: "published",
      checkpoint,
      evidenceHandle: parsed.evidenceHandle,
      postlaunchAuthorityHandle: parsed.postlaunchAuthorityHandle,
      authorityDirectoryIdentityAnchorSha256,
      manifestAcceptanceDeadlineMs,
      handoff,
    });
    return handoff;
  } catch (error) {
    terminalizePostlaunchHandoffState(
      state,
      "publication_failed_terminal",
    );
    throw error;
  }
}

function normalizePostlaunchDependencies(value) {
  const parsed = exactResidentRecord(
    value,
    PHALA_PRODUCTION_POSTLAUNCH_DEPENDENCY_FIELDS,
    "postlaunch activation dependencies",
  );
  const reviewed = exactResidentRecord(
    parsed.reviewedFinalAuthorityFiles,
    PHALA_PRODUCTION_POSTLAUNCH_REVIEWED_FINAL_FIELDS,
    "postlaunch reviewed final-authority files",
  );
  return Object.freeze({
    ceremonyLedgerInitial: normalizeResidentFileBinding(
      parsed.ceremonyLedgerInitial,
      "postlaunch initial ceremony ledger",
    ),
    ceremonyLedgerInitializationReceipt: normalizeResidentFileBinding(
      parsed.ceremonyLedgerInitializationReceipt,
      "postlaunch ceremony-ledger initialization receipt",
    ),
    ceremonyTransactionPlan: normalizeResidentFileBinding(
      parsed.ceremonyTransactionPlan,
      "postlaunch ceremony transaction plan",
    ),
    deferredAuthorityReview: normalizeResidentFileBinding(
      parsed.deferredAuthorityReview,
      "postlaunch deferred-authority review",
    ),
    immutableDeploymentManifest: normalizeResidentFileBinding(
      parsed.immutableDeploymentManifest,
      "postlaunch immutable deployment manifest",
    ),
    stageBReviewerStatusHistory: normalizeResidentFileBinding(
      parsed.stageBReviewerStatusHistory,
      "postlaunch Stage-B reviewer status history",
    ),
    reviewedFinalAuthorityFiles: Object.freeze(Object.fromEntries(
      PHALA_PRODUCTION_POSTLAUNCH_REVIEWED_FINAL_FIELDS.map((field) => [
        field,
        normalizeResidentFileBinding(
          reviewed[field],
          `postlaunch reviewed ${field}`,
        ),
      ]),
    )),
  });
}

function normalizeExpectedLineage(value) {
  const parsed = exactResidentRecord(
    value,
    PHALA_PRODUCTION_POSTLAUNCH_LINEAGE_FIELDS,
    "expected postlaunch activation lineage",
  );
  exactReleaseSha(parsed.release_sha, "expected postlaunch release");
  exactBatchId(parsed.batch_id, "expected postlaunch batch");
  canonicalManifestAcceptanceDeadline(parsed.manifest_acceptance_deadline);
  for (const field of PHALA_PRODUCTION_POSTLAUNCH_LINEAGE_FIELDS) {
    if (field.endsWith("_sha256")) exactSha256(parsed[field], field);
  }
  return Object.freeze({ ...parsed });
}

export function normalizePhalaProductionPostlaunchInputManifest(
  value,
  expected,
) {
  const parsed = exactResidentRecord(
    value,
    MANIFEST_FIELDS,
    "postlaunch activation input manifest",
  );
  const expectedValue = normalizeExpectedLineage(expected);
  if (parsed.schema !== PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA
    || parsed.status !== "postlaunch_activation_inputs_ready_for_validation"
    || parsed.truth_status
      !== "file_bindings_only_pending_same_process_validation_not_mutation_or_live_authority"
    || parsed.activation_mutation_authorized !== false
    || parsed.automatic_retry_authorized !== false
    || parsed.live_traffic_authorized !== false
    || PHALA_PRODUCTION_POSTLAUNCH_LINEAGE_FIELDS.some(
      (field) => parsed[field] !== expectedValue[field],
    )) {
    throw new Error("postlaunch activation input manifest lineage or posture is invalid");
  }
  return Object.freeze({
    ...Object.fromEntries(
      PHALA_PRODUCTION_POSTLAUNCH_LINEAGE_FIELDS.map((field) => [
        field,
        expectedValue[field],
      ]),
    ),
    dependencies: normalizePostlaunchDependencies(parsed.dependencies),
  });
}

export function preflightPhalaProductionPostlaunchDependencies(dependencies) {
  for (const field of ["ceremonyTransactionPlan", "deferredAuthorityReview"]) {
    preflightResidentBoundFile(
      dependencies[field],
      `resident postlaunch ${field}`,
    );
  }
  for (const field of PHALA_PRODUCTION_POSTLAUNCH_REVIEWED_FINAL_FIELDS) {
    preflightResidentBoundFile(
      dependencies.reviewedFinalAuthorityFiles[field],
      `resident postlaunch reviewed ${field}`,
    );
  }
  preflightResidentBoundFile(
    dependencies.ceremonyLedgerInitializationReceipt,
    "resident postlaunch ceremony ledger initialization receipt",
    { exactMode: 0o444 },
  );
  preflightResidentBoundFile(
    dependencies.immutableDeploymentManifest,
    "resident postlaunch immutable deployment manifest",
    { exactMode: 0o444 },
  );
  preflightResidentBoundFile(
    dependencies.ceremonyLedgerInitial,
    "resident postlaunch initial ceremony ledger",
    { exactMode: 0o600 },
  );
  const reviewerHistoryRead = readStableCanonicalResident0600Json(
    dependencies.stageBReviewerStatusHistory.path,
    "resident postlaunch Stage-B reviewer status history",
  );
  if (residentRawSha256(reviewerHistoryRead.bytes)
      !== dependencies.stageBReviewerStatusHistory.sha256) {
    throw new Error(
      "resident postlaunch Stage-B reviewer status history bytes differ from its binding",
    );
  }
  if (!Array.isArray(reviewerHistoryRead.value)) {
    throw new Error(
      "resident postlaunch Stage-B reviewer status history must be one canonical bare array",
    );
  }
  return Object.freeze({
    stageBReviewerStatusHistory: Object.freeze({
      binding: dependencies.stageBReviewerStatusHistory,
      bytes: Buffer.from(reviewerHistoryRead.bytes),
      value: deepFreeze([...reviewerHistoryRead.value]),
    }),
  });
}

function assertExactPostlaunchAuthorityExchangeEntries(handle) {
  if (JSON.stringify(listPhalaPinnedPrivateEntries(handle))
      !== JSON.stringify([PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME])) {
    throw new Error("postlaunch authority exchange contains unexpected entries");
  }
}

function expectedLineageFromHandoff(handoff) {
  if (!handoff || typeof handoff !== "object" || !handoff.projection
    || !handoff.request
    || handoff.request.schema !== PHALA_PRODUCTION_POSTLAUNCH_REQUEST_SCHEMA
    || handoff.request.required_input?.schema
      !== PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA) {
    throw new Error("postlaunch handoff is invalid");
  }
  return normalizeExpectedLineage({
    release_sha: handoff.projection.release_sha,
    batch_id: handoff.projection.batch_id,
    deployment_intent_sha256: handoff.projection.deployment_intent_sha256,
    cvm_launch_intent_sha256: handoff.projection.cvm_launch_intent_sha256,
    manifest_acceptance_deadline:
      handoff.request.manifest_acceptance_deadline,
    release_verification_authority_sha256:
      handoff.projection.release_verification_authority_sha256,
    seven_cvm_verified_evidence_set_sha256:
      handoff.projection.seven_cvm_verified_evidence_set_sha256,
    seven_cvm_launch_completion_receipt_sha256:
      handoff.projection.seven_cvm_launch_completion_receipt_sha256,
    postlaunch_projection_raw_file_sha256:
      handoff.postlaunch_projection_raw_file_sha256,
    postlaunch_request_raw_file_sha256:
      handoff.postlaunch_request_raw_file_sha256,
  });
}

function assertDeadlineActive(deadlineMs) {
  if (!Number.isSafeInteger(deadlineMs) || Date.now() >= deadlineMs) {
    throw new Error(
      "postlaunch activation input acceptance deadline expired; automatic retry is forbidden",
    );
  }
}

async function validatePostlaunchActivationInputs({
  handle,
  handoff,
  pollIntervalMilliseconds,
}) {
  const expected = expectedLineageFromHandoff(handoff);
  const deadlineMs = Date.parse(expected.manifest_acceptance_deadline);
  assertDeadlineActive(deadlineMs);
  const read = await waitForPinnedCanonicalResident0600JsonPendingReady({
    handle,
    fileName: PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
    label: "postlaunch activation input manifest",
    deadlineMs,
    pollIntervalMilliseconds,
    maximum: MAXIMUM_MANIFEST_BYTES,
  });
  assertDeadlineActive(deadlineMs);
  assertPinnedPhalaPrivateDirectoryPathIdentity(handle);
  assertExactPostlaunchAuthorityExchangeEntries(handle);
  const normalized = normalizePhalaProductionPostlaunchInputManifest(
    read.value,
    expected,
  );
  const dependencyAuthority =
    preflightPhalaProductionPostlaunchDependencies(normalized.dependencies);
  assertDeadlineActive(deadlineMs);
  const rereadBytes = readPhalaPinnedPrivateFile(
    handle,
    PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
    {
      mode: 0o600,
      maximum: MAXIMUM_MANIFEST_BYTES,
      minimum: 2,
      expectedIdentity: read.identity,
    },
  );
  if (!rereadBytes.equals(read.bytes)) {
    throw new Error(
      "postlaunch activation input manifest changed during dependency preflight",
    );
  }
  assertPinnedPhalaPrivateDirectoryPathIdentity(handle);
  assertExactPostlaunchAuthorityExchangeEntries(handle);
  assertDeadlineActive(deadlineMs);
  return Object.freeze({
    deadlineMs,
    dependencyAuthority,
    dependencies: normalized.dependencies,
    expected,
    manifestIdentity: read.identity,
    manifestRawSha256: residentRawSha256(read.bytes),
    manifestText: read.text,
  });
}

/**
 * Compatibility validator. It performs the complete stable manifest and
 * dependency validation but intentionally returns no coordinator authority.
 * The coordinator accepts only the opaque capability minted by the stronger
 * evidence-session-bound entrypoint below.
 */
export async function waitForPostlaunchActivationInputs(input = {}) {
  const result = await validatePostlaunchActivationInputs(input);
  return result.dependencies;
}

function assertCheckpointLineage({
  evidenceSession,
  releaseVerificationAuthority,
  verifiedEvidenceSet,
  launchCompletionReceipt,
  expected,
}) {
  assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority(
    releaseVerificationAuthority,
  );
  assertProductionPhalaSevenCvmEvidenceSet(verifiedEvidenceSet);
  assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt(
    launchCompletionReceipt,
  );
  if (!evidenceSession || typeof evidenceSession !== "object"
    || evidenceSession.release_sha !== expected.release_sha
    || evidenceSession.batch_id !== expected.batch_id
    || evidenceSession.release_verification_authority_sha256
      !== expected.release_verification_authority_sha256
    || phalaSevenCvmReleaseVerificationAuthoritySha256(
      releaseVerificationAuthority,
    ) !== expected.release_verification_authority_sha256
    || phalaSevenCvmVerifiedEvidenceSetSha256(verifiedEvidenceSet)
      !== expected.seven_cvm_verified_evidence_set_sha256
    || phalaSevenCvmLaunchCompletionReceiptSha256(launchCompletionReceipt)
      !== expected.seven_cvm_launch_completion_receipt_sha256) {
    throw new Error("postlaunch capability checkpoint lineage is invalid");
  }
}

export async function waitForPhalaProductionPostlaunchActivationCapability(
  input = {},
) {
  const parsed = exactResidentRecord(
    input,
    CAPABILITY_WAIT_FIELDS,
    "postlaunch capability wait input",
  );
  const handoffState = parsed.evidenceSession
    && SESSION_HANDOFFS.get(parsed.evidenceSession);
  if (!handoffState || handoffState.status !== "published"
    || handoffState.handoff !== parsed.handoff
    || handoffState.postlaunchAuthorityHandle !== parsed.handle) {
    throw new Error(
      "postlaunch capability requires the exact unique published session handoff",
    );
  }
  handoffState.status = "validation_started";
  try {
    const expected = expectedLineageFromHandoff(parsed.handoff);
    assertCheckpointLineage({
      evidenceSession: parsed.evidenceSession,
      releaseVerificationAuthority: parsed.releaseVerificationAuthority,
      verifiedEvidenceSet: parsed.verifiedEvidenceSet,
      launchCompletionReceipt: parsed.launchCompletionReceipt,
      expected,
    });
    if (handoffState.checkpoint.releaseVerificationAuthority
        !== parsed.releaseVerificationAuthority
      || handoffState.checkpoint.verifiedEvidenceSet
        !== parsed.verifiedEvidenceSet
      || handoffState.checkpoint.launchCompletionReceipt
        !== parsed.launchCompletionReceipt) {
      throw new Error("postlaunch capability checkpoint object identities changed");
    }
    const validated = await validatePostlaunchActivationInputs(parsed);
    const evidenceLeaseDeadlineMs =
      parsed.launchCompletionReceipt.activation_evidence_lease_expires_at * 1_000;
    const deadlineMs = validated.deadlineMs;
    if (deadlineMs !== handoffState.manifestAcceptanceDeadlineMs
      || deadlineMs > evidenceLeaseDeadlineMs) {
      throw new Error(
        "postlaunch manifest acceptance deadline differs from its original handoff bound",
      );
    }
    assertDeadlineActive(deadlineMs);
    const publicCapability = Object.freeze({
      schema: PHALA_PRODUCTION_POSTLAUNCH_CAPABILITY_SCHEMA,
      status: "exact_postlaunch_manifest_validated_pending_one_coordinator_resume",
      truth_status:
        "same_process_one_shot_manifest_capability_not_serializable_mutation_or_live_authority",
      release_sha: expected.release_sha,
      batch_id: expected.batch_id,
      release_verification_authority_sha256:
        expected.release_verification_authority_sha256,
      seven_cvm_verified_evidence_set_sha256:
        expected.seven_cvm_verified_evidence_set_sha256,
      seven_cvm_launch_completion_receipt_sha256:
        expected.seven_cvm_launch_completion_receipt_sha256,
      postlaunch_projection_raw_file_sha256:
        expected.postlaunch_projection_raw_file_sha256,
      postlaunch_request_raw_file_sha256:
        expected.postlaunch_request_raw_file_sha256,
      postlaunch_manifest_raw_file_sha256: validated.manifestRawSha256,
      manifest_acceptance_deadline: expected.manifest_acceptance_deadline,
      postlaunch_authority_exchange_identity_anchor_sha256:
        handoffState.authorityDirectoryIdentityAnchorSha256,
      acceptance_deadline_ms: deadlineMs,
      one_shot: true,
      capability_serialized: false,
      automatic_retry_authorized: false,
      activation_mutation_authorized: false,
      live_traffic_authorized: false,
    });
    CAPABILITIES.set(publicCapability, {
      consumed: false,
      publicDigest: sha256Text(CAPABILITY_DOMAIN, publicCapability),
      evidenceSession: parsed.evidenceSession,
      releaseSha: expected.release_sha,
      batchId: expected.batch_id,
      releaseVerificationAuthority: parsed.releaseVerificationAuthority,
      releaseVerificationAuthoritySha256:
        expected.release_verification_authority_sha256,
      verifiedEvidenceSet: parsed.verifiedEvidenceSet,
      verifiedEvidenceSetSha256:
        expected.seven_cvm_verified_evidence_set_sha256,
      launchCompletionReceipt: parsed.launchCompletionReceipt,
      launchCompletionReceiptSha256:
        expected.seven_cvm_launch_completion_receipt_sha256,
      postlaunchProjectionRawFileSha256:
        expected.postlaunch_projection_raw_file_sha256,
      postlaunchRequestRawFileSha256:
        expected.postlaunch_request_raw_file_sha256,
      authorityHandle: parsed.handle,
      authorityDirectoryIdentityAnchorSha256:
        handoffState.authorityDirectoryIdentityAnchorSha256,
      manifestIdentity: validated.manifestIdentity,
      manifestRawSha256: validated.manifestRawSha256,
      manifestText: validated.manifestText,
      expected,
      dependencies: validated.dependencies,
      stageBReviewerStatusHistory:
        validated.dependencyAuthority.stageBReviewerStatusHistory,
      deadlineMs,
    });
    handoffState.status = "capability_minted";
    handoffState.capability = publicCapability;
    return publicCapability;
  } catch (error) {
    terminalizePostlaunchHandoffState(
      handoffState,
      "validation_failed_terminal",
    );
    throw error;
  }
}

export function assertPhalaProductionPostlaunchActivationCapability(value) {
  const state = value && CAPABILITIES.get(value);
  if (!state || state.consumed
    || value.schema !== PHALA_PRODUCTION_POSTLAUNCH_CAPABILITY_SCHEMA
    || value.one_shot !== true
    || value.capability_serialized !== false
    || value.activation_mutation_authorized !== false
    || value.live_traffic_authorized !== false
    || sha256Text(CAPABILITY_DOMAIN, value) !== state.publicDigest) {
    throw new Error(
      "an exact live same-process postlaunch activation capability is required",
    );
  }
  return value;
}

function retirePostlaunchActivationCapability(capability, state, status) {
  state.consumed = true;
  state.status = status;
  const handoffState = state.evidenceSession
    ? SESSION_HANDOFFS.get(state.evidenceSession)
    : null;
  if (handoffState?.capability === capability) {
    terminalizePostlaunchHandoffState(handoffState, status);
  }
  // Drop every private authority/dependency reference even if the caller
  // retains the frozen public lookalike. The WeakMap entry itself is removed,
  // so replay and assertion are indistinguishable from a forged capability.
  state.dependencies = null;
  state.authorityHandle = null;
  state.manifestIdentity = null;
  state.manifestText = null;
  state.expected = null;
  state.evidenceSession = null;
  state.releaseVerificationAuthority = null;
  state.verifiedEvidenceSet = null;
  state.launchCompletionReceipt = null;
  state.stageBReviewerStatusHistory = null;
  CAPABILITIES.delete(capability);
}

/**
 * Idempotently burn a capability without revealing its private dependencies.
 * Drivers and coordinator wrappers call this on every failure/cleanup path so
 * a capability minted immediately before an unrelated exception cannot remain
 * live or retain the postlaunch authority directory.
 */
export function disposePhalaProductionPostlaunchActivationCapability(
  capability,
) {
  const state = capability && CAPABILITIES.get(capability);
  if (!state) return false;
  retirePostlaunchActivationCapability(
    capability,
    state,
    "capability_disposed_without_coordinator_authority",
  );
  return true;
}

/**
 * Claim and burn the capability before validating its private lineage. A
 * failed interpretation, wrong session, stale deadline, manifest replacement,
 * or dependency substitution is terminal and cannot be retried with it.
 */
export function consumePhalaProductionPostlaunchActivationCapability(
  capability,
  expectedValue = {},
) {
  const state = capability && CAPABILITIES.get(capability);
  if (!state || state.consumed) {
    throw new Error(
      "an exact live same-process postlaunch activation capability is required",
    );
  }
  state.consumed = true;
  let coordinatorAuthority;
  try {
    const expected = exactResidentRecord(
      expectedValue,
      CAPABILITY_CONSUME_FIELDS,
      "postlaunch capability coordinator expectation",
    );
    assertPhalaProductionPostlaunchActivationCapabilityAfterClaim(
      capability,
      state,
    );
    assertDeadlineActive(state.deadlineMs);
    if (state.evidenceSession !== expected.evidenceSession
      || state.releaseSha !== expected.releaseSha
      || state.batchId !== expected.batchId
      || state.releaseVerificationAuthority
        !== expected.releaseVerificationAuthority
      || state.verifiedEvidenceSet !== expected.verifiedEvidenceSet
      || state.launchCompletionReceipt !== expected.launchCompletionReceipt) {
      throw new Error("postlaunch activation capability belongs to another checkpoint");
    }
    assertCheckpointLineage({
      evidenceSession: expected.evidenceSession,
      releaseVerificationAuthority: expected.releaseVerificationAuthority,
      verifiedEvidenceSet: expected.verifiedEvidenceSet,
      launchCompletionReceipt: expected.launchCompletionReceipt,
      expected: state.expected,
    });
    assertPinnedPhalaPrivateDirectoryPathIdentity(state.authorityHandle);
    if (phalaPinnedPrivateDirectoryIdentityAnchorSha256(state.authorityHandle)
        !== state.authorityDirectoryIdentityAnchorSha256) {
      throw new Error("postlaunch authority-directory identity changed");
    }
    assertExactPostlaunchAuthorityExchangeEntries(state.authorityHandle);
    const manifestBytes = readPhalaPinnedPrivateFile(
      state.authorityHandle,
      PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
      {
        mode: 0o600,
        maximum: MAXIMUM_MANIFEST_BYTES,
        minimum: 2,
        expectedIdentity: state.manifestIdentity,
      },
    );
    if (manifestBytes.toString("utf8") !== state.manifestText
      || residentRawSha256(manifestBytes) !== state.manifestRawSha256) {
      throw new Error("postlaunch manifest identity or bytes changed before consumption");
    }
    const dependencyAuthority =
      preflightPhalaProductionPostlaunchDependencies(state.dependencies);
    const retainedHistory = state.stageBReviewerStatusHistory;
    const observedHistory = dependencyAuthority.stageBReviewerStatusHistory;
    if (observedHistory.binding.path !== retainedHistory.binding.path
      || observedHistory.binding.sha256 !== retainedHistory.binding.sha256
      || !observedHistory.bytes.equals(retainedHistory.bytes)) {
      throw new Error(
        "postlaunch Stage-B reviewer status history changed before capability consumption",
      );
    }
    assertPinnedPhalaPrivateDirectoryPathIdentity(state.authorityHandle);
    assertExactPostlaunchAuthorityExchangeEntries(state.authorityHandle);
    assertDeadlineActive(state.deadlineMs);
    coordinatorAuthority = Object.freeze({
      dependencies: state.dependencies,
      stageBReviewerStatusHistory: retainedHistory.value,
      stageBReviewerStatusHistoryBinding: retainedHistory.binding,
    });
    return coordinatorAuthority;
  } finally {
    retirePostlaunchActivationCapability(
      capability,
      state,
      coordinatorAuthority === undefined
        ? "capability_claim_failed_terminal"
        : "capability_consumed_by_coordinator",
    );
  }
}

function assertPhalaProductionPostlaunchActivationCapabilityAfterClaim(
  value,
  state,
) {
  if (!state.consumed
    || value.schema !== PHALA_PRODUCTION_POSTLAUNCH_CAPABILITY_SCHEMA
    || value.one_shot !== true
    || value.capability_serialized !== false
    || value.activation_mutation_authorized !== false
    || value.live_traffic_authorized !== false
    || sha256Text(CAPABILITY_DOMAIN, value) !== state.publicDigest) {
    throw new Error("postlaunch activation capability integrity is invalid");
  }
}
