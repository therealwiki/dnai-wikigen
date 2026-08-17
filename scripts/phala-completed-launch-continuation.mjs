import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  assertCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  PHALA_EXECUTION_ORDER,
  assertPairwiseDistinctSignedEnvironmentKeys,
} from "./phala-production-executor-core.mjs";
import {
  normalizeCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-executor-state-core.mjs";
import {
  assertSecretFreeExecutorStructure,
} from "./phala-production-posture-core.mjs";
import {
  reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch,
} from "./phala-nonlive-bootstrap-authorization-core.mjs";
import {
  normalizeBootstrapPublicEnvironmentAuthority,
} from "./phala-bootstrap-public-environment-authority-core.mjs";
import {
  loadPhalaRecoveryJournal,
} from "./phala-production-recovery-journal.mjs";
import {
  verifyProductionCvmPostureObservation,
  productionCvmPostureVerificationReceiptSha256,
} from "./phala-production-posture-receipt.mjs";
import {
  assertPinnedPhalaHistoricalContinuityReadOnlySdkObserver,
  authenticatedPhalaSdkObservationSha256,
  createPinnedPhalaHistoricalContinuityReadOnlySdkObserver,
  phalaAuthenticatedAccountSubjectSha256,
  pinnedPhalaProductionSdkAdapterIdentitySha256,
  readAuthenticatedPhalaSdkObservationResponse,
  resolvePinnedPhalaPackageIdentity,
  verifyPinnedLegacyEnvironmentKey,
} from "./phala-production-sdk-adapter.mjs";
import {
  normalizePhalaCompatibilityReceipt,
  normalizePhalaProductionTargetAuthority,
  normalizePhalaSdkWireTransformStagingReceipt,
  phalaProductionTargetAuthorityDigest,
} from "./phala-production-target-authority.mjs";
import {
  closePhalaPinnedPrivateDirectory,
  createExclusivePhalaPinnedPrivateFile,
  listPhalaPinnedPrivateEntries,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  pinPhalaPrivateDirectory,
  readPhalaPinnedPrivateFile,
} from "./phala-pinned-private-directory.mjs";
import {
  reconstructPersistedHistoricalPhalaSevenCvmReleaseVerificationAuthority,
} from "./phala-seven-cvm-historical-release-verification-authority.mjs";
import {
  phalaSevenCvmVerifiedEvidenceSetSha256,
  replayPersistedHistoricalPhalaSevenCvmEvidence,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  normalizePreCeremonyRuntimeAuthority,
  projectPreCeremonyRuntimeAuthorityHistoricalLaunchBinding,
} from "./pre-ceremony-runtime-authority-core.mjs";
import {
  reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency,
} from "./phala-seven-cvm-launch-completion-core.mjs";
import {
  loadPhalaSevenCvmHistoricalTranscriptPersistenceReceipt,
  phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256,
  readDurablyPersistedPhalaSevenCvmHistoricalTranscriptTextEntries,
} from "./phala-seven-cvm-historical-transcript-persistence.mjs";
import {
  createPhalaCompletedLaunchContinuityReceipt,
  canonicalPhalaCompletedLaunchContinuityReceiptText,
  normalizePhalaCompletedLaunchContinuityReceipt,
  phalaCompletedLaunchContinuityReceiptSha256,
} from "./phala-completed-launch-continuation-core.mjs";

export const PHALA_COMPLETED_LAUNCH_CONTINUATION_CAPABILITY_SCHEMA =
  "dnai.phala-completed-seven-cvm-launch-continuation-capability.v2";
export const PHALA_COMPLETED_LAUNCH_CONTINUATION_CAPABILITY_STATUS =
  "recorded_time_dcap_and_current_continuity_reconciled_pending_one_shot_evidence_session_adoption";
export const PHALA_COMPLETED_LAUNCH_CONTINUATION_CAPABILITY_TRUTH =
  "opaque_same_process_one_shot_capability_for_signed_a_l_r_b_exact14_recorded_time_dcap_historical_L_and_current_nonmutating_continuity_not_serializable_launch_or_live_authority";
export const PHALA_COMPLETED_LAUNCH_CONTINUITY_RECEIPT_SUFFIX =
  ".completed-launch-continuity-receipt.json";

const CAPABILITY_DOMAIN =
  "dnai-wikigen/phala-completed-seven-cvm-launch-continuation-capability/v2\0";
const MAX_L_BYTES = 4 * 1024 * 1024;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const CAPABILITIES = new WeakMap();
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

const RESUME_FIELDS = Object.freeze([
  "ceremonyAuthorizationDependencies",
  "compatibilityReceipt",
  "historicalSignedA",
  "launchCompletionReceiptPath",
  "persistedCeremonyAuthorization",
  "persistedRuntimeAuthority",
  "productionTargetAuthority",
  "recoveryDirectory",
  "sdkWireTransformStagingReceipt",
  "descriptorSetReceipt",
]);
const HISTORICAL_A_FIELDS = Object.freeze([
  "authorization",
  "authorizationFileIdentity",
  "bootstrapAuthority",
  "bootstrapAuthorityFileIdentity",
  "persistedReceipt",
  "reviewerAuthority",
]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.getOwnPropertySymbols(value).length !== 0
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new TypeError(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function canonicalSecond() {
  return new Date(Math.floor(Date.now() / 1_000) * 1_000)
    .toISOString().replace(".000Z", "Z");
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function domainSha256(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(JSON.stringify(sorted(value)), "utf8")
    .digest("hex")}`;
}

function exactAbsoluteDirectory(value) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || fs.realpathSync.native(value) !== value) {
    throw new TypeError("continuation recovery directory must be absolute, canonical, and real");
  }
  return value;
}

function readStablePersistedL(filePath, recoveryDirectory) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)
    || path.resolve(filePath) !== filePath
    || path.dirname(filePath) !== recoveryDirectory
    || fs.realpathSync.native(filePath) !== filePath) {
    throw new TypeError(
      "persisted L must be one canonical file directly inside the recovery directory",
    );
  }
  let fd;
  try {
    const beforePath = fs.lstatSync(filePath, { bigint: true });
    if (beforePath.isSymbolicLink() || !beforePath.isFile()
      || beforePath.nlink !== 1n
      || (beforePath.mode & 0o777n) !== 0o600n
      || (typeof process.getuid === "function"
        && beforePath.uid !== BigInt(process.getuid()))
      || beforePath.size < 2n || beforePath.size > BigInt(MAX_L_BYTES)) {
      throw new TypeError("persisted L file posture is not exact owned 0600 immutable input");
    }
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | NOFOLLOW);
    const before = fs.fstatSync(fd, { bigint: true });
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd, { bigint: true });
    const afterPath = fs.lstatSync(filePath, { bigint: true });
    const identity = (stat) => [
      stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs,
      stat.mode, stat.uid, stat.nlink,
    ].map(String).join(":");
    if (identity(beforePath) !== identity(before)
      || identity(before) !== identity(after)
      || identity(after) !== identity(afterPath)
      || BigInt(bytes.length) !== before.size
      || fs.realpathSync.native(filePath) !== filePath) {
      throw new TypeError("persisted L changed during its stable read");
    }
    let value;
    try { value = JSON.parse(bytes.toString("utf8")); } catch {
      throw new TypeError("persisted L is not bounded UTF-8 JSON");
    }
    assertCanonicalPlainDataGraph(value, { label: "persisted immutable L" });
    if (canonicalText(value) !== bytes.toString("utf8")) {
      throw new TypeError("persisted L bytes are not recursively sorted canonical JSON");
    }
    return Object.freeze({ value, bytes, sha256: sha256(bytes) });
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function buildPostureProjection(raw, cvmId) {
  return {
    id: String(raw.id ?? cvmId),
    app_id: raw.app_id,
    compose_hash: raw.compose_hash,
    kms_info: { id: raw.kms_info?.id },
    kms_type: raw.kms_type,
    os: {
      os_image_hash: raw.os?.os_image_hash,
      is_dev: raw.os?.is_dev,
    },
    resource: {
      instance_type: raw.resource?.instance_type,
      disk_in_gb: raw.resource?.disk_in_gb,
    },
    listed: raw.listed,
    public_logs: raw.public_logs,
    public_sysinfo: raw.public_sysinfo,
    public_tcbinfo: raw.public_tcbinfo,
  };
}

function assertTargetMatchesHistoricalLaunch(target, targetSha256, state, launch) {
  if (targetSha256 !== state.target_authority_sha256
    || targetSha256 !== launch.production_target_authority_sha256
    || target.release_sha !== state.release_sha
    || target.cvm_launch_intent_sha256 !== state.launch_intent_sha256) {
    throw new TypeError("historical production target authority differs from journal or L");
  }
  const byDomain = new Map(launch.domains.map((entry) => [entry.domain, entry]));
  for (const domain of PHALA_EXECUTION_ORDER) {
    const historical = byDomain.get(domain);
    const resource = target.resource_targets[domain];
    if (!historical || !resource
      || historical.kms_id !== target.kms.id
      || historical.os_image_hash !== target.os_image.os_image_hash
      || historical.instance_type !== resource.instance_type
      || historical.disk_size !== resource.disk_size) {
      throw new TypeError(`${domain} historical target KMS, OS, or resource differs from immutable L`);
    }
  }
}

function assertNoConsumedOrPostMeasurementState(handle, batchId, {
  allowContinuityReceipt = false,
} = {}) {
  const stem = batchId.slice("sha256:".length);
  const continuityName = `${stem}${PHALA_COMPLETED_LAUNCH_CONTINUITY_RECEIPT_SUFFIX}`;
  const entries = listPhalaPinnedPrivateEntries(handle);
  if (entries.includes(`${stem}.lock.json`)
    || entries.some((entry) => entry.includes(".activation."))
    || entries.some((entry) => entry.startsWith(`.${stem}.activation`))
    || (!allowContinuityReceipt && entries.includes(continuityName))) {
    throw new Error(
      "completed launch is locked, consumed, replayed, or postmeasurement-mutated",
    );
  }
  return continuityName;
}

function rereadExactJournal(directory, launch, expected) {
  const journal = loadPhalaRecoveryJournal({
    directory,
    batchId: launch.batch_id,
    directoryIdentityAnchorSha256:
      launch.phala_recovery_directory_identity_anchor_sha256,
  });
  if (journal === null || canonicalText(journal) !== canonicalText(expected)) {
    throw new Error("completed production recovery journal changed during continuation");
  }
  return journal;
}

function publicCapability(receipt, receiptSha256) {
  const value = Object.freeze({
    schema: PHALA_COMPLETED_LAUNCH_CONTINUATION_CAPABILITY_SCHEMA,
    status: PHALA_COMPLETED_LAUNCH_CONTINUATION_CAPABILITY_STATUS,
    truth_status: PHALA_COMPLETED_LAUNCH_CONTINUATION_CAPABILITY_TRUTH,
    release_sha: receipt.release_sha,
    batch_id: receipt.batch_id,
    launch_completion_receipt_sha256:
      receipt.launch_completion_receipt_sha256,
    continuity_receipt_sha256: receiptSha256,
    recorded_time_dcap_replayed: true,
    persisted_intel_collateral_revalidated: true,
    historical_freshness_renewed: false,
    historical_launch_refreshed: false,
    historical_evidence_refreshed: false,
    capability_serialized: false,
    one_shot: true,
    activation_mutation_authorized: false,
    live_traffic_authorized: false,
  });
  return value;
}

function capabilityDigest(value) {
  return domainSha256(CAPABILITY_DOMAIN, value);
}

function assertCapabilityIntegrity(value, { requireUnconsumed = false } = {}) {
  const state = value && CAPABILITIES.get(value);
  if (!state
    || (requireUnconsumed && state.consumed)
    || value.schema !== PHALA_COMPLETED_LAUNCH_CONTINUATION_CAPABILITY_SCHEMA
    || value.status !== PHALA_COMPLETED_LAUNCH_CONTINUATION_CAPABILITY_STATUS
    || value.truth_status !== PHALA_COMPLETED_LAUNCH_CONTINUATION_CAPABILITY_TRUTH
    || value.continuity_receipt_sha256
      !== phalaCompletedLaunchContinuityReceiptSha256(state.continuityReceipt)
    || value.launch_completion_receipt_sha256
      !== state.continuityReceipt.launch_completion_receipt_sha256
    || value.recorded_time_dcap_replayed !== true
    || value.persisted_intel_collateral_revalidated !== true
    || value.historical_freshness_renewed !== false
    || value.historical_launch_refreshed !== false
    || value.historical_evidence_refreshed !== false
    || value.capability_serialized !== false
    || value.one_shot !== true
    || value.activation_mutation_authorized !== false
    || value.live_traffic_authorized !== false
    || capabilityDigest(value) !== state.publicDigest) {
    throw new Error("an exact unmodified completed-launch continuation capability is required");
  }
  return { value, state };
}

export function assertCompletedPhalaSevenCvmLaunchContinuationCapability(value) {
  return assertCapabilityIntegrity(value, { requireUnconsumed: true }).value;
}

/**
 * Internal adoption view used by the executor-runtime registrar. It does not
 * consume the capability; only the coordinator-facing consume function can do
 * that. The WeakMap brand prevents a serialized or cloned object from opening
 * this view.
 */
export function readCompletedPhalaSevenCvmLaunchContinuationForRuntimeAdoption(
  value,
) {
  const { state } = assertCapabilityIntegrity(value, { requireUnconsumed: true });
  if (state.runtimeAdopted !== true) {
    throw new Error(
      "completed-launch continuation has not passed executor-state provenance registration",
    );
  }
  return state.dependencies;
}

/**
 * One-shot claim used only by the executor-core provenance registrar. Claiming
 * before validation is intentionally fail-closed: any later error leaves this
 * capability unusable rather than permitting a second interpretation of the
 * same current observation set.
 */
export function claimCompletedPhalaSevenCvmLaunchContinuationForProvenance(
  value,
) {
  const { state } = assertCapabilityIntegrity(value, { requireUnconsumed: true });
  if (state.runtimeAdopted) {
    throw new Error("completed-launch continuation runtime adoption was already attempted");
  }
  state.runtimeAdopted = true;
  return state.dependencies;
}

export function consumeCompletedPhalaSevenCvmLaunchContinuationCapability(
  value,
) {
  const { state } = assertCapabilityIntegrity(value, { requireUnconsumed: true });
  if (state.runtimeAdopted !== true) {
    throw new Error("completed-launch continuation must be runtime-adopted before consumption");
  }
  state.consumed = true;
  return state.dependencies;
}

export async function resumeCompletedPhalaSevenCvmProductionLaunch(input = {}) {
  const parsed = exactRecord(
    input,
    RESUME_FIELDS,
    "completed seven-CVM production-launch continuation input",
  );
  const historicalAInput = exactRecord(
    parsed.historicalSignedA,
    HISTORICAL_A_FIELDS,
    "historical signed-A continuation input",
  );
  const recoveryDirectory = exactAbsoluteDirectory(parsed.recoveryDirectory);
  const startedAt = canonicalSecond();
  const persistedLRead = readStablePersistedL(
    parsed.launchCompletionReceiptPath,
    recoveryDirectory,
  );
  const persistedL = persistedLRead.value;
  if (!isRecord(persistedL) || typeof persistedL.batch_id !== "string"
    || !SHA256.test(persistedL.batch_id)
    || typeof persistedL.phala_recovery_directory_identity_anchor_sha256
      !== "string"
    || !SHA256.test(
      persistedL.phala_recovery_directory_identity_anchor_sha256,
    )) {
    throw new TypeError("persisted L omits its exact batch or recovery-directory anchor");
  }
  const handle = pinPhalaPrivateDirectory(recoveryDirectory, {
    expectedIdentityAnchorSha256:
      persistedL.phala_recovery_directory_identity_anchor_sha256,
  });
  let continuityName;
  try {
    continuityName = assertNoConsumedOrPostMeasurementState(
      handle,
      persistedL.batch_id,
    );
  } finally {
    closePhalaPinnedPrivateDirectory(handle);
  }
  const journal = loadPhalaRecoveryJournal({
    directory: recoveryDirectory,
    batchId: persistedL.batch_id,
    directoryIdentityAnchorSha256:
      persistedL.phala_recovery_directory_identity_anchor_sha256,
  });
  if (journal === null) {
    throw new Error("completed production recovery journal is absent");
  }
  const state = normalizeCompletedPhalaExecutorState(journal.state);
  if (journal.state_sha256 !== phalaExecutorStateDigest(state)) {
    throw new Error("completed production recovery journal state digest drifted");
  }

  const historicalSignedA =
    reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch({
      authorization: historicalAInput.authorization,
      bootstrapAuthority: historicalAInput.bootstrapAuthority,
      reviewerAuthority: historicalAInput.reviewerAuthority,
      persistedReceipt: historicalAInput.persistedReceipt,
      launchCompletedAt: persistedL.completed_at,
      authorizationFileIdentity: historicalAInput.authorizationFileIdentity,
      bootstrapAuthorityFileIdentity:
        historicalAInput.bootstrapAuthorityFileIdentity,
    });
  const historicalBootstrapAuthority =
    normalizeBootstrapPublicEnvironmentAuthority(
      historicalAInput.bootstrapAuthority,
    );
  const persistedRuntimeAuthority = normalizePreCeremonyRuntimeAuthority(
    parsed.persistedRuntimeAuthority,
  );
  const runtimeBinding =
    projectPreCeremonyRuntimeAuthorityHistoricalLaunchBinding(
      persistedRuntimeAuthority,
    );
  const historicalLaunch =
    reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency({
      persistedReceipt: persistedL,
      persistedExecutorFinalState: state,
      historicalPreCeremonyRuntimeBinding: runtimeBinding,
      historicalBootstrapAuthorizationBinding:
        historicalSignedA.historical_bootstrap_authorization_binding,
    });
  if (canonicalText(historicalLaunch.receipt)
      !== persistedLRead.bytes.toString("utf8")) {
    throw new Error("persisted immutable L differs from its historical reconstruction");
  }
  const transcriptReceipt =
    loadPhalaSevenCvmHistoricalTranscriptPersistenceReceipt({
      directory: recoveryDirectory,
      directoryIdentityAnchorSha256:
        historicalLaunch.receipt
          .phala_recovery_directory_identity_anchor_sha256,
      expectedSevenCvmVerifiedEvidenceSetSha256:
        historicalLaunch.receipt.machine_verifier_evidence_set_sha256,
      expectedHistoricalTranscriptFileSetSha256:
        historicalLaunch.receipt.historical_transcript_file_set_sha256,
    });
  if (transcriptReceipt === null
    || phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(
      transcriptReceipt,
    ) !== historicalLaunch.receipt
      .historical_transcript_persistence_receipt_sha256) {
    throw new Error("persisted exact-14 transcript manifest differs from immutable L");
  }
  const transcriptEntries =
    readDurablyPersistedPhalaSevenCvmHistoricalTranscriptTextEntries(
      transcriptReceipt,
    );
  const historicalReleaseVerificationAuthority =
    await reconstructPersistedHistoricalPhalaSevenCvmReleaseVerificationAuthority({
      releaseVerificationAuthority:
        historicalLaunch.release_verification_authority,
      signedAReconstructionInput: historicalAInput,
      launchCompletionReceipt: historicalLaunch.receipt,
      persistedRuntimeAuthority,
      persistedCeremonyAuthorization: parsed.persistedCeremonyAuthorization,
      ceremonyAuthorizationDependencies:
        parsed.ceremonyAuthorizationDependencies,
      executorFinalState: state,
      descriptorSetReceipt: parsed.descriptorSetReceipt,
      historicalTranscriptFileSet: transcriptReceipt.transcript_file_set,
    });
  const historicalMachineReplay =
    await replayPersistedHistoricalPhalaSevenCvmEvidence({
      releaseAuthority: historicalReleaseVerificationAuthority,
      rawTranscriptFiles: transcriptEntries,
      executorFinalState: state,
    });
  const historicalEvidenceSetSha256 =
    phalaSevenCvmVerifiedEvidenceSetSha256(
      historicalMachineReplay.evidenceSet,
    );
  if (historicalEvidenceSetSha256
      !== historicalLaunch.receipt.machine_verifier_evidence_set_sha256) {
    throw new Error("historical raw14 proof reconstruction differs from immutable L");
  }
  const historicalEvidence = deepFreezeCanonicalPlainDataGraph({
    schema: "dnai.phala-seven-cvm-recorded-time-dcap-replay.v1",
    truth_status:
      "signed_a_l_r_b_authority_exact14_protocol_signatures_recorded_time_dcap_and_persisted_intel_collateral_replayed_without_freshness_renewal_or_live_authority",
    launch_completion_receipt_sha256: historicalLaunch.receipt_sha256,
    release_verification_authority_sha256:
      historicalLaunch.release_verification_authority_sha256,
    seven_cvm_verified_evidence_set_sha256:
      historicalEvidenceSetSha256,
    historical_transcript_file_set_sha256:
      historicalLaunch.receipt.historical_transcript_file_set_sha256,
    all_seven_recorded_time_dcap_replayed: true,
    persisted_intel_collateral_revalidated: true,
    workload_eip191_signatures_replayed: true,
    freshness_renewed: false,
    production_live_brand_minted: false,
    live_traffic_authorized: false,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  }, { label: "recorded-time seven-CVM historical replay summary" });

  const compatibility = normalizePhalaCompatibilityReceipt(
    parsed.compatibilityReceipt,
  );
  const staging = normalizePhalaSdkWireTransformStagingReceipt(
    parsed.sdkWireTransformStagingReceipt,
    { compatibilityReceipt: compatibility },
  );
  const target = normalizePhalaProductionTargetAuthority(
    parsed.productionTargetAuthority,
    {
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
    },
  );
  for (const [raw, normalized, label] of [
    [parsed.compatibilityReceipt, compatibility, "historical compatibility receipt"],
    [parsed.sdkWireTransformStagingReceipt, staging, "historical SDK staging receipt"],
    [parsed.productionTargetAuthority, target, "historical production target"],
  ]) {
    if (JSON.stringify(sorted(raw)) !== JSON.stringify(sorted(normalized))) {
      throw new Error(`${label} must already contain exact normalized authority bytes`);
    }
  }
  const targetSha256 = phalaProductionTargetAuthorityDigest(target, {
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
  });
  assertTargetMatchesHistoricalLaunch(
    target,
    targetSha256,
    state,
    historicalLaunch.receipt,
  );
  if (historicalSignedA.receipt.production_target_authority_sha256
      !== targetSha256) {
    throw new Error("historically signature-verified A differs from production target");
  }

  const observer =
    await createPinnedPhalaHistoricalContinuityReadOnlySdkObserver({
      targetAuthority: target,
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
    });
  assertPinnedPhalaHistoricalContinuityReadOnlySdkObserver(observer);
  const accountObservation = await observer.getCurrentUser();
  const accountResponse = readAuthenticatedPhalaSdkObservationResponse(
    accountObservation,
    { adapter: observer, method: "getCurrentUser", domain: null },
  );
  const currentAccount = {
    account_subject_sha256:
      phalaAuthenticatedAccountSubjectSha256(accountResponse),
    call_sequence: accountObservation.call_sequence,
    observation_sha256: authenticatedPhalaSdkObservationSha256(
      accountObservation,
      { adapter: observer, method: "getCurrentUser", domain: null },
    ),
    observed_at: accountObservation.observed_at,
  };
  const pinnedDstackIdentity = resolvePinnedPhalaPackageIdentity();
  const launchByDomain = new Map(
    historicalLaunch.receipt.domains.map((entry) => [entry.domain, entry]),
  );
  const currentDomains = [];
  const currentPostureReceipts = [];
  const cvmInfoObservations = [];
  const attestationObservations = [];
  const environmentKeyObservations = [];
  const environmentKeyBindings = [];
  for (const domain of PHALA_EXECUTION_ORDER) {
    const historical = launchByDomain.get(domain);
    const infoObservation = await observer.getCvmInfo({
      domain,
      cvmId: historical.cvm_id,
    });
    const infoResponse = readAuthenticatedPhalaSdkObservationResponse(
      infoObservation,
      { adapter: observer, method: "getCvmInfo", domain },
    );
    const posture = verifyProductionCvmPostureObservation({
      domain,
      cvmId: historical.cvm_id,
      cvmInfo: buildPostureProjection(infoResponse, historical.cvm_id),
      expected: {
        appId: historical.app_id,
        composeHash: historical.committed_compose_hash,
        kmsId: historical.kms_id,
        instanceType: historical.instance_type,
        diskSize: historical.disk_size,
      },
    });
    const attestationObservation = await observer.getCvmAttestation({
      domain,
      cvmId: historical.cvm_id,
    });
    const attestationResponse = readAuthenticatedPhalaSdkObservationResponse(
      attestationObservation,
      { adapter: observer, method: "getCvmAttestation", domain },
    );
    assertCanonicalPlainDataGraph(attestationResponse, {
      label: `${domain} current authenticated attestation response`,
    });
    assertSecretFreeExecutorStructure(
      attestationResponse,
      `${domain} current authenticated attestation response`,
    );
    if (!isRecord(attestationResponse)
      || (Object.hasOwn(attestationResponse, "id")
        && String(attestationResponse.id) !== historical.cvm_id)
      || (Object.hasOwn(attestationResponse, "cvm_id")
        && String(attestationResponse.cvm_id) !== historical.cvm_id)
      || (Object.hasOwn(attestationResponse, "app_id")
        && String(attestationResponse.app_id).replace(/^0x/, "").toLowerCase()
          !== historical.app_id)) {
      throw new Error(`${domain} current attestation response identifies a different CVM`);
    }
    const environmentKeyObservation =
      await observer.getAppEnvEncryptPubKey({
        domain,
        appId: historical.app_id,
      });
    const environmentKeyResponse = readAuthenticatedPhalaSdkObservationResponse(
      environmentKeyObservation,
      { adapter: observer, method: "getAppEnvEncryptPubKey", domain },
    );
    const environmentKeyBinding = await verifyPinnedLegacyEnvironmentKey({
      identity: pinnedDstackIdentity,
      appId: historical.app_id,
      response: environmentKeyResponse,
      pinnedSigner: target.kms.env_encrypt_signer_k256,
    });
    const bindingSha256 = domainSha256(
      "dnai-wikigen/phala-signed-environment-key-binding/v1\0",
      environmentKeyBinding,
    );
    cvmInfoObservations.push(infoObservation);
    attestationObservations.push(attestationObservation);
    environmentKeyObservations.push(environmentKeyObservation);
    environmentKeyBindings.push(environmentKeyBinding);
    currentPostureReceipts.push(posture);
    currentDomains.push({
      domain,
      app_id: posture.app_id,
      cvm_id: posture.cvm_id,
      compose_hash: posture.compose_hash,
      kms_id: posture.kms_id,
      instance_type: posture.instance_type,
      disk_size: posture.disk_size,
      os_image_hash: posture.os_image_hash,
      kms_type: posture.kms_type,
      listed: posture.listed,
      public_logs: posture.public_logs,
      public_sysinfo: posture.public_sysinfo,
      public_tcbinfo: posture.public_tcbinfo,
      cvm_info_call_sequence: infoObservation.call_sequence,
      cvm_info_observation_sha256: authenticatedPhalaSdkObservationSha256(
        infoObservation,
        { adapter: observer, method: "getCvmInfo", domain },
      ),
      cvm_info_observed_at: infoObservation.observed_at,
      production_posture_verification_receipt_sha256:
        productionCvmPostureVerificationReceiptSha256(posture),
      attestation_call_sequence: attestationObservation.call_sequence,
      attestation_observation_sha256:
        authenticatedPhalaSdkObservationSha256(
          attestationObservation,
          { adapter: observer, method: "getCvmAttestation", domain },
        ),
      attestation_response_sha256: attestationObservation.sdk_response_sha256,
      attestation_observed_at: attestationObservation.observed_at,
      environment_key_call_sequence: environmentKeyObservation.call_sequence,
      environment_key_observation_sha256:
        authenticatedPhalaSdkObservationSha256(
          environmentKeyObservation,
          { adapter: observer, method: "getAppEnvEncryptPubKey", domain },
        ),
      environment_key_binding_sha256: bindingSha256,
      environment_public_key_sha256: environmentKeyBinding.public_key_sha256,
      environment_key_observed_at: environmentKeyObservation.observed_at,
    });
  }
  assertPairwiseDistinctSignedEnvironmentKeys(environmentKeyBindings);
  const completedAt = canonicalSecond();
  rereadExactJournal(recoveryDirectory, historicalLaunch.receipt, journal);
  const secondLRead = readStablePersistedL(
    parsed.launchCompletionReceiptPath,
    recoveryDirectory,
  );
  if (!secondLRead.bytes.equals(persistedLRead.bytes)) {
    throw new Error("persisted immutable L changed during current reconciliation");
  }
  const secondTranscript =
    loadPhalaSevenCvmHistoricalTranscriptPersistenceReceipt({
      directory: recoveryDirectory,
      directoryIdentityAnchorSha256:
        historicalLaunch.receipt
          .phala_recovery_directory_identity_anchor_sha256,
      expectedSevenCvmVerifiedEvidenceSetSha256:
        historicalLaunch.receipt.machine_verifier_evidence_set_sha256,
      expectedHistoricalTranscriptFileSetSha256:
        historicalLaunch.receipt.historical_transcript_file_set_sha256,
    });
  if (secondTranscript === null
    || phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(
      secondTranscript,
    ) !== phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(
      transcriptReceipt,
    )) {
    throw new Error("persisted historical transcript changed during reconciliation");
  }
  const receipt = createPhalaCompletedLaunchContinuityReceipt({
    adapterIdentitySha256:
      pinnedPhalaProductionSdkAdapterIdentitySha256(observer),
    completedAt,
    completedJournal: journal,
    currentAccount,
    currentDomains,
    historicalEvidenceReconstruction: historicalEvidence,
    launchCompletionRawFileSha256: persistedLRead.sha256,
    launchCompletionReceipt: historicalLaunch.receipt,
    launchCompletionReceiptSha256: historicalLaunch.receipt_sha256,
    signedAReceipt: historicalSignedA.receipt,
    startedAt,
  });
  const receiptSha256 = phalaCompletedLaunchContinuityReceiptSha256(receipt);
  const receiptBytes = Buffer.from(
    canonicalPhalaCompletedLaunchContinuityReceiptText(receipt),
    "utf8",
  );
  const finalHandle = pinPhalaPrivateDirectory(recoveryDirectory, {
    expectedIdentityAnchorSha256:
      historicalLaunch.receipt
        .phala_recovery_directory_identity_anchor_sha256,
  });
  try {
    if (assertNoConsumedOrPostMeasurementState(
      finalHandle,
      historicalLaunch.receipt.batch_id,
    ) !== continuityName) {
      throw new Error("continuity receipt namespace changed during reconciliation");
    }
    const identity = createExclusivePhalaPinnedPrivateFile(
      finalHandle,
      continuityName,
      receiptBytes,
      { mode: 0o600, maximum: 512 * 1024 },
    );
    const reread = readPhalaPinnedPrivateFile(
      finalHandle,
      continuityName,
      {
        mode: 0o600,
        maximum: 512 * 1024,
        minimum: 2,
        expectedIdentity: identity,
      },
    );
    if (!reread.equals(receiptBytes)
      || assertNoConsumedOrPostMeasurementState(
        finalHandle,
        historicalLaunch.receipt.batch_id,
        { allowContinuityReceipt: true },
      ) !== continuityName
      || phalaPinnedPrivateDirectoryIdentityAnchorSha256(finalHandle)
        !== historicalLaunch.receipt
          .phala_recovery_directory_identity_anchor_sha256) {
      throw new Error("durable continuity receipt did not re-read exactly");
    }
  } finally {
    closePhalaPinnedPrivateDirectory(finalHandle);
  }

  const capability = publicCapability(receipt, receiptSha256);
  const privateState = {
    consumed: false,
    runtimeAdopted: false,
    publicDigest: capabilityDigest(capability),
    continuityReceipt: receipt,
    dependencies: Object.freeze({
      historical_signed_a_reconstruction: historicalSignedA,
      signed_a_receipt: historicalSignedA.receipt,
      bootstrap_public_environment_authority:
        historicalBootstrapAuthority,
      executor_final_state: state,
      completed_recovery_journal: journal,
      persisted_launch_completion_receipt: historicalLaunch.receipt,
      persisted_launch_completion_receipt_sha256:
        historicalLaunch.receipt_sha256,
      persisted_launch_completion_raw_file_sha256: persistedLRead.sha256,
      historical_runtime_binding: runtimeBinding,
      release_verification_authority:
        historicalLaunch.release_verification_authority,
      release_verification_authority_sha256:
        historicalLaunch.release_verification_authority_sha256,
      historical_transcript_persistence_receipt: transcriptReceipt,
      historical_transcript_text_entries: transcriptEntries,
      historical_evidence_reconstruction: historicalEvidence,
      historical_evidence_set: historicalMachineReplay.evidenceSet,
      historical_qvl_identity_evidence:
        historicalMachineReplay.qvlIdentityEvidence,
      historical_workload_verdict_evidence:
        historicalMachineReplay.workloadVerdictEvidence,
      historical_release_verification_authority:
        historicalReleaseVerificationAuthority,
      production_target_authority_evidence: Object.freeze({
        compatibilityReceipt: compatibility,
        sdkWireTransformStagingReceipt: staging,
        productionTargetAuthority: target,
        productionTargetAuthoritySha256: targetSha256,
      }),
      current_continuity_receipt: receipt,
      current_continuity_receipt_sha256: receiptSha256,
      current_production_posture_receipts:
        Object.freeze([...currentPostureReceipts]),
      authenticated_current_account_observation: accountObservation,
      authenticated_cvm_info_observations:
        Object.freeze([...cvmInfoObservations]),
      authenticated_cvm_attestation_observations:
        Object.freeze([...attestationObservations]),
      authenticated_environment_key_observations:
        Object.freeze([...environmentKeyObservations]),
      current_environment_key_bindings:
        Object.freeze([...environmentKeyBindings]),
      pinned_phala_sdk_adapter: observer,
      recovery_directory: recoveryDirectory,
      historical_launch_refreshed: false,
      historical_evidence_refreshed: false,
      live_traffic_authorized: false,
    }),
  };
  CAPABILITIES.set(capability, privateState);
  const { adoptCompletedPhalaSevenCvmLaunchContinuation } = await import(
    "./phala-production-executor-runtime.mjs"
  );
  const launchRuntimeResult =
    await adoptCompletedPhalaSevenCvmLaunchContinuation(capability);
  return Object.freeze({
    launchRuntimeResult,
    continuationCapability: capability,
    continuityReceipt: receipt,
    continuityReceiptSha256: receiptSha256,
  });
}
