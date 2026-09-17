import { createHash } from "node:crypto";
import path from "node:path";

import {
  CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES,
} from "./cvm-launch-intent-core.mjs";
import {
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  phalaCombinedArenaComputeActivationVerificationSha256,
} from "./phala-post-measurement-activation-receipt-core.mjs";
import { assertSecretFreeExecutorStructure } from "./phala-production-executor-core.mjs";
import { ensurePhalaRecoveryJournalDirectory } from "./phala-production-recovery-journal.mjs";
import {
  assertPinnedPhalaPrivateDirectory,
  closePhalaPinnedPrivateDirectory,
  createExclusivePhalaPinnedPrivateFile,
  listPhalaPinnedPrivateEntries,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  phalaPinnedPrivatePathForDisplay,
  pinPhalaPrivateDirectory,
  publishPhalaPinnedPrivateFile,
  readPhalaPinnedPrivateFile,
  unlinkPhalaPinnedPrivateFile,
} from "./phala-pinned-private-directory.mjs";

export const PHALA_POST_MEASUREMENT_ACTIVATION_STATE_SCHEMA =
  "dnai.phala-post-measurement-activation-state.v2";
export const PHALA_POST_MEASUREMENT_ACTIVATION_JOURNAL_SCHEMA =
  "dnai.phala-post-measurement-activation-journal.v2";
export const PHALA_POST_MEASUREMENT_ACTIVATION_LOCK_SCHEMA =
  "dnai.phala-post-measurement-activation-lock.v1";
export const PHALA_POST_MEASUREMENT_ACTIVATION_STATE_DOMAIN =
  "dnai-wikigen/phala-post-measurement-activation-state/v2\0";
export const PHALA_POST_MEASUREMENT_ACTIVATION_JOURNAL_DOMAIN =
  "dnai-wikigen/phala-post-measurement-activation-journal/v2\0";

export const PHALA_POST_MEASUREMENT_ACTIVATION_TERMINAL_STATUSES = Object.freeze([
  "complete",
  "ambiguous_reconcile_required",
  "post_restart_evidence_operator_review_required",
]);

const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const CVM_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const MAX_JOURNAL_BYTES = 256 * 1024;
const LIVE_LOCKS = new WeakSet();
const DURABLE_COMPLETIONS = new WeakMap();

const STATE_FIELDS = Object.freeze([
  "schema",
  "status",
  "sequence",
  "batch_id",
  "release_sha",
  "activation_plan_sha256",
  "pre_ceremony_runtime_authority_sha256",
  "ceremony_authorization_sha256",
  "target",
  "profile_activation",
  "allowed_environment_key_names_sha256",
  "injected_environment_key_names_sha256",
  "adapter_identity_sha256",
  "assembly_receipt_sha256",
  "sdk_observations",
  "mutation_attempts",
  "pending_mutation",
  "arena_worker_presence_sha256",
  "arena_worker_presence_verified_at",
  "compute_recipient_activation_sha256",
  "compute_recipient_activation_verified_at",
  "combined_activation_verification_sha256",
  "failure_reason_code",
  "completed_at",
  "automatic_retry_authorized",
  "automatic_cleanup_authorized",
  "live_traffic_authorized",
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

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sortedObject(value), null, 2)}\n`;
}

function digest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(JSON.stringify(sortedObject(value)), "utf8")
    .digest("hex")}`;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function exactSecond(value, label) {
  const parsedMs = typeof value === "string" && ISO_SECOND.test(value)
    ? Date.parse(value)
    : Number.NaN;
  if (!Number.isFinite(parsedMs)
    || new Date(parsedMs).toISOString().replace(".000Z", "Z") !== value) {
    throw new Error(`${label} must be a canonical UTC second`);
  }
  return value;
}

function normalizeTarget(value) {
  const parsed = exactRecord(
    value,
    ["domain", "app_id", "cvm_id"],
    "activation journal target",
  );
  if (parsed.domain !== "main_runtime_cvm"
    || typeof parsed.app_id !== "string" || !APP_ID.test(parsed.app_id)
    || typeof parsed.cvm_id !== "string" || !CVM_ID.test(parsed.cvm_id)) {
    throw new Error("activation journal target must be the canonical main runtime");
  }
  return {
    domain: "main_runtime_cvm",
    app_id: parsed.app_id,
    cvm_id: parsed.cvm_id,
  };
}

function normalizeProfileActivation(value) {
  const parsed = exactRecord(value, [
    "profile_names",
    "compose_profiles_value",
  ], "activation journal profile set");
  if (JSON.stringify(parsed.profile_names)
      !== JSON.stringify(CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES)
    || parsed.compose_profiles_value
      !== CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE) {
    throw new Error(
      "activation journal profile set is omitted, reordered, substituted, or widened",
    );
  }
  return {
    profile_names: [...CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES],
    compose_profiles_value: CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  };
}

function normalizeObservation(value, index) {
  const parsed = exactRecord(value, [
    "method",
    "call_sequence",
    "observation_sha256",
    "request_semantics_sha256",
    "observed_at",
  ], `sdk_observations[${index}]`);
  const allowedMethods = [
    "getCurrentUser",
    "getAppEnvEncryptPubKey",
    "updateCvmEnvs",
    "restartCvm",
    "getCvmInfo",
    "getCvmAttestation",
  ];
  if (!allowedMethods.includes(parsed.method)
    || !Number.isSafeInteger(parsed.call_sequence)
    || parsed.call_sequence !== index + 1) {
    throw new Error("activation SDK observations must be gap-free and use exact methods");
  }
  return {
    method: parsed.method,
    call_sequence: parsed.call_sequence,
    observation_sha256: exactSha256(
      parsed.observation_sha256,
      `sdk_observations[${index}].observation_sha256`,
    ),
    request_semantics_sha256: exactSha256(
      parsed.request_semantics_sha256,
      `sdk_observations[${index}].request_semantics_sha256`,
    ),
    observed_at: exactSecond(parsed.observed_at, `sdk_observations[${index}].observed_at`),
  };
}

function normalizeMutationAttempt(value, index) {
  const parsed = exactRecord(value, [
    "action",
    "request_semantics_sha256",
    "recorded_at",
  ], `mutation_attempts[${index}]`);
  const expected = index === 0 ? "updateCvmEnvs" : "restartCvm";
  if (parsed.action !== expected) {
    throw new Error("activation mutation attempts must be PATCH then restart exactly once");
  }
  return {
    action: expected,
    request_semantics_sha256: exactSha256(
      parsed.request_semantics_sha256,
      `mutation_attempts[${index}].request_semantics_sha256`,
    ),
    recorded_at: exactSecond(parsed.recorded_at, `mutation_attempts[${index}].recorded_at`),
  };
}

function expectedMethodPrefix(length) {
  return [
    "getCurrentUser",
    "getAppEnvEncryptPubKey",
    "getAppEnvEncryptPubKey",
    "updateCvmEnvs",
    "restartCvm",
    "getCvmInfo",
    "getCvmAttestation",
  ].slice(0, length);
}

function assertStatusShape(state) {
  const observationMethods = state.sdk_observations.map(({ method }) => method);
  if (JSON.stringify(observationMethods)
      !== JSON.stringify(expectedMethodPrefix(observationMethods.length))) {
    throw new Error("activation journal SDK observation prefix drifted");
  }
  const status = state.status;
  const exact = ({
    observations,
    attempts,
    pending,
    arena,
    compute,
    failure,
    complete,
  }) => (
    state.sdk_observations.length === observations
    && state.mutation_attempts.length === attempts
    && (pending === null
      ? state.pending_mutation === null
      : state.pending_mutation?.action === pending)
    && (arena
      ? state.arena_worker_presence_sha256 !== null
        && state.arena_worker_presence_verified_at !== null
      : state.arena_worker_presence_sha256 === null
        && state.arena_worker_presence_verified_at === null)
    && (compute
      ? state.compute_recipient_activation_sha256 !== null
        && state.compute_recipient_activation_verified_at !== null
        && state.combined_activation_verification_sha256 !== null
      : state.compute_recipient_activation_sha256 === null
        && state.compute_recipient_activation_verified_at === null
        && state.combined_activation_verification_sha256 === null)
    && state.failure_reason_code === failure
    && (complete ? state.completed_at !== null : state.completed_at === null)
  );
  const valid = (
    (status === "initialized" && exact({
      observations: 0, attempts: 0, pending: null, arena: false,
      compute: false, failure: null, complete: false,
    }))
    || (status === "pre_patch_reads_observed" && exact({
      observations: 3, attempts: 0, pending: null, arena: false,
      compute: false, failure: null, complete: false,
    }))
    || (status === "patch_attempt_durable" && exact({
      observations: 3, attempts: 1, pending: "updateCvmEnvs", arena: false,
      compute: false, failure: null, complete: false,
    }))
    || (status === "patch_observed" && exact({
      observations: 4, attempts: 1, pending: null, arena: false,
      compute: false, failure: null, complete: false,
    }))
    || (status === "restart_attempt_durable" && exact({
      observations: 4, attempts: 2, pending: "restartCvm", arena: false,
      compute: false, failure: null, complete: false,
    }))
    || (status === "restart_observed" && exact({
      observations: 5, attempts: 2, pending: null, arena: false,
      compute: false, failure: null, complete: false,
    }))
    || (status === "post_restart_authenticated_phala_attestation_observation_verified"
      && exact({
      observations: 7, attempts: 2, pending: null, arena: false,
      compute: false, failure: null, complete: false,
    }))
    || (status === "arena_worker_activation_verified" && exact({
      observations: 7, attempts: 2, pending: null, arena: true,
      compute: false, failure: null, complete: false,
    }))
    || (status === "compute_recipient_activation_verified" && exact({
      observations: 7, attempts: 2, pending: null, arena: true,
      compute: true, failure: null, complete: false,
    }))
    || (status === "complete" && exact({
      observations: 7, attempts: 2, pending: null, arena: true,
      compute: true, failure: null, complete: true,
    }))
    || (status === "ambiguous_reconcile_required"
      && state.sdk_observations.length >= 3
      && state.sdk_observations.length <= 4
      && state.mutation_attempts.length >= 1
      && state.mutation_attempts.length <= 2
      && state.pending_mutation?.action
        === state.mutation_attempts.at(-1)?.action
      && state.arena_worker_presence_sha256 === null
      && state.arena_worker_presence_verified_at === null
      && state.compute_recipient_activation_sha256 === null
      && state.compute_recipient_activation_verified_at === null
      && state.combined_activation_verification_sha256 === null
      && [
        "update_cvm_envs_outcome_ambiguous",
        "restart_cvm_outcome_ambiguous",
      ].includes(state.failure_reason_code)
      && state.completed_at === null)
    || (status === "post_restart_evidence_operator_review_required"
      && (exact({
        observations: 5, attempts: 2, pending: null, arena: false,
        compute: false, failure: "post_restart_evidence_unavailable", complete: false,
      }) || exact({
        observations: 7, attempts: 2, pending: null, arena: false,
        compute: false, failure: "arena_worker_activation_unavailable", complete: false,
      }) || exact({
        observations: 7, attempts: 2, pending: null, arena: true,
        compute: false, failure: "compute_recipient_activation_unavailable", complete: false,
      })))
  );
  if (!valid) throw new Error("activation journal status does not match its exact prefixes");
  if (state.pending_mutation !== null) {
    const pending = exactRecord(state.pending_mutation, [
      "action",
      "request_semantics_sha256",
      "recorded_at",
    ], "pending activation mutation");
    const attempt = state.mutation_attempts.at(-1);
    if (canonicalText(pending) !== canonicalText(attempt)) {
      throw new Error("pending activation mutation differs from its durable attempt");
    }
  }
}

export function normalizePhalaPostMeasurementActivationState(value) {
  const parsed = exactRecord(value, STATE_FIELDS, "post-measurement activation state");
  if (parsed.schema !== PHALA_POST_MEASUREMENT_ACTIVATION_STATE_SCHEMA
    || !Number.isSafeInteger(parsed.sequence) || parsed.sequence < 0
    || typeof parsed.release_sha !== "string" || !SHA40.test(parsed.release_sha)
    || parsed.automatic_retry_authorized !== false
    || parsed.automatic_cleanup_authorized !== false
    || parsed.live_traffic_authorized !== false
    || !Array.isArray(parsed.sdk_observations)
    || parsed.sdk_observations.length > 7
    || !Array.isArray(parsed.mutation_attempts)
    || parsed.mutation_attempts.length > 2) {
    throw new Error("post-measurement activation state boundary is invalid");
  }
  const state = {
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_STATE_SCHEMA,
    status: parsed.status,
    sequence: parsed.sequence,
    batch_id: exactSha256(parsed.batch_id, "activation batch_id"),
    release_sha: parsed.release_sha,
    activation_plan_sha256: exactSha256(
      parsed.activation_plan_sha256,
      "activation plan digest",
    ),
    pre_ceremony_runtime_authority_sha256: exactSha256(
      parsed.pre_ceremony_runtime_authority_sha256,
      "pre-ceremony runtime authority digest",
    ),
    ceremony_authorization_sha256: exactSha256(
      parsed.ceremony_authorization_sha256,
      "signed ceremony authorization digest",
    ),
    target: normalizeTarget(parsed.target),
    profile_activation: normalizeProfileActivation(parsed.profile_activation),
    allowed_environment_key_names_sha256: exactSha256(
      parsed.allowed_environment_key_names_sha256,
      "allowed environment key-name digest",
    ),
    injected_environment_key_names_sha256: exactSha256(
      parsed.injected_environment_key_names_sha256,
      "injected environment key-name digest",
    ),
    adapter_identity_sha256: exactSha256(
      parsed.adapter_identity_sha256,
      "adapter identity digest",
    ),
    assembly_receipt_sha256: exactSha256(
      parsed.assembly_receipt_sha256,
      "private assembly receipt digest",
    ),
    sdk_observations: parsed.sdk_observations.map(normalizeObservation),
    mutation_attempts: parsed.mutation_attempts.map(normalizeMutationAttempt),
    pending_mutation: parsed.pending_mutation === null
      ? null
      : normalizeMutationAttempt(parsed.pending_mutation, parsed.mutation_attempts.length - 1),
    arena_worker_presence_sha256: parsed.arena_worker_presence_sha256 === null
      ? null
      : exactSha256(
        parsed.arena_worker_presence_sha256,
        "Arena worker presence proof digest",
      ),
    arena_worker_presence_verified_at:
      parsed.arena_worker_presence_verified_at === null
        ? null
        : exactSecond(
          parsed.arena_worker_presence_verified_at,
          "Arena worker presence verification time",
        ),
    compute_recipient_activation_sha256:
      parsed.compute_recipient_activation_sha256 === null
        ? null
        : exactSha256(
          parsed.compute_recipient_activation_sha256,
          "Compute recipient activation proof digest",
        ),
    compute_recipient_activation_verified_at:
      parsed.compute_recipient_activation_verified_at === null
        ? null
        : exactSecond(
          parsed.compute_recipient_activation_verified_at,
          "Compute recipient activation verification time",
        ),
    combined_activation_verification_sha256:
      parsed.combined_activation_verification_sha256 === null
        ? null
        : exactSha256(
          parsed.combined_activation_verification_sha256,
          "combined Arena and Compute activation verification digest",
        ),
    failure_reason_code: parsed.failure_reason_code,
    completed_at: parsed.completed_at === null
      ? null
      : exactSecond(parsed.completed_at, "activation completed_at"),
    automatic_retry_authorized: false,
    automatic_cleanup_authorized: false,
    live_traffic_authorized: false,
  };
  if (state.sequence !== (() => {
    const base = {
      initialized: 0,
      pre_patch_reads_observed: 1,
      patch_attempt_durable: 2,
      patch_observed: 3,
      restart_attempt_durable: 4,
      restart_observed: 5,
      post_restart_authenticated_phala_attestation_observation_verified: 6,
      arena_worker_activation_verified: 7,
      compute_recipient_activation_verified: 8,
      complete: 9,
      post_restart_evidence_operator_review_required:
        state.compute_recipient_activation_sha256 !== null
          ? 9
          : state.arena_worker_presence_sha256 !== null
            ? 8
            : state.sdk_observations.length === 7 ? 7 : 6,
    }[state.status];
    if (base !== undefined) return base;
    if (state.status === "ambiguous_reconcile_required") {
      return state.mutation_attempts.length === 1 ? 3 : 5;
    }
    return -1;
  })()) {
    throw new Error("activation journal sequence does not match its status");
  }
  assertStatusShape(state);
  const observedTimes = state.sdk_observations.map(({ observed_at: value }) => Date.parse(value));
  if (observedTimes.some((value, index) => index > 0 && value < observedTimes[index - 1])) {
    throw new Error("activation SDK observations must be chronological");
  }
  for (let index = 0; index < state.mutation_attempts.length; index += 1) {
    const attemptMs = Date.parse(state.mutation_attempts[index].recorded_at);
    const previousObservationIndex = index === 0 ? 2 : 3;
    const mutationObservationIndex = index === 0 ? 3 : 4;
    if (attemptMs < observedTimes[previousObservationIndex]
      || (observedTimes[mutationObservationIndex] !== undefined
        && (attemptMs > observedTimes[mutationObservationIndex]
          || state.mutation_attempts[index].request_semantics_sha256
            !== state.sdk_observations[mutationObservationIndex]
              .request_semantics_sha256))) {
      throw new Error("activation mutation was not durably recorded before observation");
    }
  }
  const postRestartAttestationMs = observedTimes[6];
  const arenaVerifiedMs = state.arena_worker_presence_verified_at === null
    ? null
    : Date.parse(state.arena_worker_presence_verified_at);
  const computeVerifiedMs = state.compute_recipient_activation_verified_at === null
    ? null
    : Date.parse(state.compute_recipient_activation_verified_at);
  if ((arenaVerifiedMs !== null
      && (postRestartAttestationMs === undefined
        || arenaVerifiedMs <= postRestartAttestationMs))
    || (computeVerifiedMs !== null
      && (arenaVerifiedMs === null || computeVerifiedMs < arenaVerifiedMs))) {
    throw new Error(
      "Arena and Compute activation proofs must be verified after post-restart attestation in order",
    );
  }
  if (state.combined_activation_verification_sha256 !== null
    && state.combined_activation_verification_sha256
      !== phalaCombinedArenaComputeActivationVerificationSha256({
        profileActivation: state.profile_activation,
        arenaWorkerPresenceSha256: state.arena_worker_presence_sha256,
        computeRecipientActivationSha256:
          state.compute_recipient_activation_sha256,
      })) {
    throw new Error("combined Arena and Compute activation verification digest drifted");
  }
  if (state.completed_at !== null
    && (computeVerifiedMs === null
      || Date.parse(state.completed_at) < computeVerifiedMs)) {
    throw new Error("activation completion predates its ordered activation proofs");
  }
  assertSecretFreeExecutorStructure(state, "post-measurement activation state");
  return state;
}

export function phalaPostMeasurementActivationStateSha256(value) {
  return digest(
    PHALA_POST_MEASUREMENT_ACTIVATION_STATE_DOMAIN,
    normalizePhalaPostMeasurementActivationState(value),
  );
}

export function createInitialPhalaPostMeasurementActivationState({
  batchId,
  releaseSha,
  activationPlanSha256,
  preCeremonyRuntimeAuthoritySha256,
  ceremonyAuthorizationSha256,
  target,
  allowedEnvironmentKeyNamesSha256,
  injectedEnvironmentKeyNamesSha256,
  adapterIdentitySha256,
  assemblyReceiptSha256,
} = {}) {
  return Object.freeze(normalizePhalaPostMeasurementActivationState({
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_STATE_SCHEMA,
    status: "initialized",
    sequence: 0,
    batch_id: batchId,
    release_sha: releaseSha,
    activation_plan_sha256: activationPlanSha256,
    pre_ceremony_runtime_authority_sha256: preCeremonyRuntimeAuthoritySha256,
    ceremony_authorization_sha256: ceremonyAuthorizationSha256,
    target,
    profile_activation: {
      profile_names: [...CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES],
      compose_profiles_value:
        CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
    },
    allowed_environment_key_names_sha256: allowedEnvironmentKeyNamesSha256,
    injected_environment_key_names_sha256: injectedEnvironmentKeyNamesSha256,
    adapter_identity_sha256: adapterIdentitySha256,
    assembly_receipt_sha256: assemblyReceiptSha256,
    sdk_observations: [],
    mutation_attempts: [],
    pending_mutation: null,
    arena_worker_presence_sha256: null,
    arena_worker_presence_verified_at: null,
    compute_recipient_activation_sha256: null,
    compute_recipient_activation_verified_at: null,
    combined_activation_verification_sha256: null,
    failure_reason_code: null,
    completed_at: null,
    automatic_retry_authorized: false,
    automatic_cleanup_authorized: false,
    live_traffic_authorized: false,
  }));
}

function normalizedObservationBatch(value, expectedMethods, startIndex) {
  if (!Array.isArray(value) || value.length !== expectedMethods.length) {
    throw new Error("activation transition has the wrong SDK observation count");
  }
  return value.map((entry, index) => {
    const normalized = normalizeObservation(entry, startIndex + index);
    if (normalized.method !== expectedMethods[index]) {
      throw new Error("activation transition SDK method order drifted");
    }
    return normalized;
  });
}

export function transitionPhalaPostMeasurementActivationState(value, event = {}) {
  const state = normalizePhalaPostMeasurementActivationState(value);
  if (PHALA_POST_MEASUREMENT_ACTIVATION_TERMINAL_STATUSES.includes(state.status)) {
    throw new Error("terminal post-measurement activation state cannot transition automatically");
  }
  let next;
  if (event.type === "pre_patch_reads_observed" && state.status === "initialized") {
    const observations = normalizedObservationBatch(
      event.observations,
      ["getCurrentUser", "getAppEnvEncryptPubKey", "getAppEnvEncryptPubKey"],
      0,
    );
    next = {
      ...state,
      status: "pre_patch_reads_observed",
      sequence: 1,
      sdk_observations: observations,
    };
  } else if (event.type === "mutation_attempt_recorded"
    && ((state.status === "pre_patch_reads_observed" && event.action === "updateCvmEnvs")
      || (state.status === "patch_observed" && event.action === "restartCvm"))) {
    const attempt = normalizeMutationAttempt({
      action: event.action,
      request_semantics_sha256: event.requestSemanticsSha256,
      recorded_at: event.recordedAt,
    }, state.mutation_attempts.length);
    next = {
      ...state,
      status: event.action === "updateCvmEnvs"
        ? "patch_attempt_durable"
        : "restart_attempt_durable",
      sequence: state.sequence + 1,
      mutation_attempts: [...state.mutation_attempts, attempt],
      pending_mutation: attempt,
    };
  } else if (event.type === "mutation_observed"
    && ((state.status === "patch_attempt_durable" && event.action === "updateCvmEnvs")
      || (state.status === "restart_attempt_durable" && event.action === "restartCvm"))) {
    const observation = normalizedObservationBatch(
      [event.observation],
      [event.action],
      state.sdk_observations.length,
    )[0];
    const attempt = state.mutation_attempts.at(-1);
    if (observation.request_semantics_sha256 !== attempt.request_semantics_sha256) {
      throw new Error("observed activation mutation differs from the durable request intent");
    }
    next = {
      ...state,
      status: event.action === "updateCvmEnvs" ? "patch_observed" : "restart_observed",
      sequence: state.sequence + 1,
      sdk_observations: [...state.sdk_observations, observation],
      pending_mutation: null,
    };
  } else if (event.type === "mutation_outcome_ambiguous"
    && ["patch_attempt_durable", "restart_attempt_durable"].includes(state.status)) {
    next = {
      ...state,
      status: "ambiguous_reconcile_required",
      sequence: state.sequence + 1,
      failure_reason_code: state.pending_mutation.action === "updateCvmEnvs"
        ? "update_cvm_envs_outcome_ambiguous"
        : "restart_cvm_outcome_ambiguous",
    };
  } else if (event.type
      === "post_restart_authenticated_phala_attestation_observation_verified"
    && state.status === "restart_observed") {
    const observations = normalizedObservationBatch(
      event.observations,
      ["getCvmInfo", "getCvmAttestation"],
      state.sdk_observations.length,
    );
    next = {
      ...state,
      status:
        "post_restart_authenticated_phala_attestation_observation_verified",
      sequence: 6,
      sdk_observations: [...state.sdk_observations, ...observations],
    };
  } else if (event.type === "post_restart_evidence_unavailable"
    && state.status === "restart_observed") {
    next = {
      ...state,
      status: "post_restart_evidence_operator_review_required",
      sequence: state.sequence + 1,
      failure_reason_code: "post_restart_evidence_unavailable",
    };
  } else if (event.type === "arena_worker_activation_unavailable"
    && state.status
      === "post_restart_authenticated_phala_attestation_observation_verified") {
    next = {
      ...state,
      status: "post_restart_evidence_operator_review_required",
      sequence: 7,
      failure_reason_code: "arena_worker_activation_unavailable",
    };
  } else if (event.type === "arena_worker_activation_verified"
    && state.status
      === "post_restart_authenticated_phala_attestation_observation_verified") {
    next = {
      ...state,
      status: "arena_worker_activation_verified",
      sequence: 7,
      arena_worker_presence_sha256: exactSha256(
        event.arenaWorkerPresenceSha256,
        "Arena worker presence proof digest",
      ),
      arena_worker_presence_verified_at: exactSecond(
        event.verifiedAt,
        "Arena worker presence verification time",
      ),
    };
  } else if (event.type === "compute_recipient_activation_unavailable"
    && state.status === "arena_worker_activation_verified") {
    next = {
      ...state,
      status: "post_restart_evidence_operator_review_required",
      sequence: 8,
      failure_reason_code: "compute_recipient_activation_unavailable",
    };
  } else if (event.type === "compute_recipient_activation_verified"
    && state.status === "arena_worker_activation_verified") {
    const computeRecipientActivationSha256 = exactSha256(
      event.computeRecipientActivationSha256,
      "Compute recipient activation proof digest",
    );
    next = {
      ...state,
      status: "compute_recipient_activation_verified",
      sequence: 8,
      compute_recipient_activation_sha256: computeRecipientActivationSha256,
      compute_recipient_activation_verified_at: exactSecond(
        event.verifiedAt,
        "Compute recipient activation verification time",
      ),
      combined_activation_verification_sha256:
        phalaCombinedArenaComputeActivationVerificationSha256({
          profileActivation: state.profile_activation,
          arenaWorkerPresenceSha256: state.arena_worker_presence_sha256,
          computeRecipientActivationSha256,
        }),
    };
  } else if (event.type === "completed"
    && state.status === "compute_recipient_activation_verified") {
    next = {
      ...state,
      status: "complete",
      sequence: 9,
      completed_at: exactSecond(event.completedAt, "activation completion time"),
    };
  } else {
    throw new Error("post-measurement activation transition is not authorized");
  }
  return Object.freeze(normalizePhalaPostMeasurementActivationState(next));
}

function stem(planSha256) {
  return exactSha256(planSha256, "activation plan digest").slice("sha256:".length);
}

export function phalaPostMeasurementActivationJournalPaths(directory, planSha256) {
  ensurePhalaRecoveryJournalDirectory(directory);
  const base = stem(planSha256);
  return Object.freeze({
    journal: path.join(directory, `${base}.activation.journal.json`),
    lock: path.join(directory, `${base}.activation.lock.json`),
  });
}

function activationJournalNames(planSha256) {
  const base = stem(planSha256);
  return Object.freeze({
    journal: `${base}.activation.journal.json`,
    lock: `${base}.activation.lock.json`,
  });
}

export function acquirePhalaPostMeasurementActivationLock({
  directory,
  activationPlanSha256,
  ceremonyAuthorizationSha256,
  acquiredAt,
  directoryIdentityAnchorSha256 = null,
} = {}) {
  const names = activationJournalNames(activationPlanSha256);
  const normalizedActivationPlanSha256 = exactSha256(
    activationPlanSha256,
    "activation lock plan digest",
  );
  const normalizedCeremonyAuthorizationSha256 = exactSha256(
    ceremonyAuthorizationSha256,
    "activation lock signed-B digest",
  );
  const normalizedAcquiredAt = exactSecond(acquiredAt, "activation lock acquired_at");
  const pinnedDirectory = pinPhalaPrivateDirectory(directory, {
    expectedIdentityAnchorSha256: directoryIdentityAnchorSha256,
  });
  const document = {
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_LOCK_SCHEMA,
    activation_plan_sha256: normalizedActivationPlanSha256,
    ceremony_authorization_sha256: normalizedCeremonyAuthorizationSha256,
    phala_recovery_directory_identity_anchor_sha256:
      phalaPinnedPrivateDirectoryIdentityAnchorSha256(pinnedDirectory),
    acquired_at: normalizedAcquiredAt,
    pid: process.pid,
    stale_lock_removal_automatic: false,
  };
  const bytes = Buffer.from(canonicalText(document), "utf8");
  let handedOff = false;
  try {
    if (listPhalaPinnedPrivateEntries(pinnedDirectory).some(
      (entry) => entry.startsWith(`.${names.lock}.release-`),
    )) {
      throw new Error(
        "a quarantined activation lock release exists; manual reconciliation is required",
      );
    }
    const lockIdentity = createExclusivePhalaPinnedPrivateFile(
      pinnedDirectory,
      names.lock,
      bytes,
      { mode: 0o600, maximum: MAX_JOURNAL_BYTES },
    );
    const reread = readPhalaPinnedPrivateFile(pinnedDirectory, names.lock, {
      mode: 0o600,
      maximum: MAX_JOURNAL_BYTES,
      minimum: 2,
      expectedIdentity: lockIdentity,
    });
    if (!reread.equals(bytes)) {
      throw new Error("post-measurement activation lock bytes are incomplete");
    }
    const lock = Object.freeze({
      directory,
      path: phalaPinnedPrivatePathForDisplay(pinnedDirectory, names.lock),
      activationPlanSha256,
      ceremonyAuthorizationSha256,
      lockName: names.lock,
      lockIdentity,
      pinnedDirectory,
    });
    LIVE_LOCKS.add(lock);
    handedOff = true;
    return lock;
  } catch (error) {
    throw error?.code === "EEXIST"
      ? new Error("post-measurement activation lock already exists; manual review is required")
      : error;
  } finally {
    if (!handedOff) closePhalaPinnedPrivateDirectory(pinnedDirectory);
  }
}

function requireLock(lock, directory, state) {
  if (!lock || !LIVE_LOCKS.has(lock) || lock.directory !== directory
    || lock.activationPlanSha256 !== state.activation_plan_sha256
    || lock.ceremonyAuthorizationSha256 !== state.ceremony_authorization_sha256) {
    throw new Error("the exact live post-measurement activation lock is required");
  }
  assertPinnedPhalaPrivateDirectory(lock.pinnedDirectory, directory);
  readPhalaPinnedPrivateFile(lock.pinnedDirectory, lock.lockName, {
    mode: 0o600,
    maximum: MAX_JOURNAL_BYTES,
    minimum: 2,
    expectedIdentity: lock.lockIdentity,
  });
  return lock.pinnedDirectory;
}

export function releasePhalaPostMeasurementActivationLock(lock) {
  if (!lock || !LIVE_LOCKS.has(lock)) return;
  readPhalaPinnedPrivateFile(lock.pinnedDirectory, lock.lockName, {
    mode: 0o600,
    maximum: MAX_JOURNAL_BYTES,
    minimum: 2,
    expectedIdentity: lock.lockIdentity,
  });
  unlinkPhalaPinnedPrivateFile(lock.pinnedDirectory, lock.lockName, {
    expectedSha256: lock.lockIdentity.sha256,
    expectedIdentity: lock.lockIdentity,
    mode: 0o600,
    maximum: MAX_JOURNAL_BYTES,
  });
  closePhalaPinnedPrivateDirectory(lock.pinnedDirectory);
  LIVE_LOCKS.delete(lock);
}

export function projectPhalaPostMeasurementActivationJournal(state) {
  const normalized = normalizePhalaPostMeasurementActivationState(state);
  const document = {
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_JOURNAL_SCHEMA,
    truth_status:
      "private_durable_patch_restart_recovery_metadata_no_values_ciphertext_or_atomicity_claim",
    activation_plan_sha256: normalized.activation_plan_sha256,
    state_sha256: phalaPostMeasurementActivationStateSha256(normalized),
    state: normalized,
    patch_and_restart_are_atomic: false,
    automatic_retry_authorized: false,
    automatic_cleanup_authorized: false,
  };
  assertSecretFreeExecutorStructure(document, "post-measurement activation journal");
  return deepFreezeCanonicalPlainDataGraph(document, {
    label: "projected post-measurement activation journal",
  });
}

export function normalizePhalaPostMeasurementActivationJournal(value) {
  const document = exactRecord(value, [
    "schema",
    "truth_status",
    "activation_plan_sha256",
    "state_sha256",
    "state",
    "patch_and_restart_are_atomic",
    "automatic_retry_authorized",
    "automatic_cleanup_authorized",
  ], "post-measurement activation journal");
  const state = normalizePhalaPostMeasurementActivationState(document.state);
  if (document.schema !== PHALA_POST_MEASUREMENT_ACTIVATION_JOURNAL_SCHEMA
    || document.truth_status
      !== "private_durable_patch_restart_recovery_metadata_no_values_ciphertext_or_atomicity_claim"
    || document.activation_plan_sha256 !== state.activation_plan_sha256
    || document.state_sha256 !== phalaPostMeasurementActivationStateSha256(state)
    || document.patch_and_restart_are_atomic !== false
    || document.automatic_retry_authorized !== false
    || document.automatic_cleanup_authorized !== false) {
    throw new Error("post-measurement activation journal is noncanonical or drifted");
  }
  const normalized = {
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_JOURNAL_SCHEMA,
    truth_status:
      "private_durable_patch_restart_recovery_metadata_no_values_ciphertext_or_atomicity_claim",
    activation_plan_sha256: state.activation_plan_sha256,
    state_sha256: phalaPostMeasurementActivationStateSha256(state),
    state,
    patch_and_restart_are_atomic: false,
    automatic_retry_authorized: false,
    automatic_cleanup_authorized: false,
  };
  assertSecretFreeExecutorStructure(normalized, "post-measurement activation journal");
  return normalized;
}

export function phalaPostMeasurementActivationJournalSha256(value) {
  return digest(
    PHALA_POST_MEASUREMENT_ACTIVATION_JOURNAL_DOMAIN,
    normalizePhalaPostMeasurementActivationJournal(value),
  );
}

export function loadPhalaPostMeasurementActivationJournal({
  directory,
  activationPlanSha256,
  directoryIdentityAnchorSha256 = null,
} = {}) {
  stem(activationPlanSha256);
  const pinnedDirectory = pinPhalaPrivateDirectory(directory, {
    expectedIdentityAnchorSha256: directoryIdentityAnchorSha256,
  });
  try {
    return loadActivationJournalFromPinnedDirectory(
      pinnedDirectory,
      activationPlanSha256,
    );
  } finally {
    closePhalaPinnedPrivateDirectory(pinnedDirectory);
  }
}

function loadActivationJournalFromPinnedDirectory(pinnedDirectory, activationPlanSha256) {
  const names = activationJournalNames(activationPlanSha256);
  const bytes = readPhalaPinnedPrivateFile(pinnedDirectory, names.journal, {
    mode: 0o600,
    maximum: MAX_JOURNAL_BYTES,
    minimum: 2,
    allowMissing: true,
  });
  if (bytes === null) return null;
  let parsed;
  try { parsed = JSON.parse(bytes.toString("utf8")); } catch {
    throw new Error("post-measurement activation journal is not valid JSON");
  }
  const document = normalizePhalaPostMeasurementActivationJournal(parsed);
  if (document.activation_plan_sha256 !== activationPlanSha256
    || canonicalText(document) !== bytes.toString("utf8")) {
    throw new Error("post-measurement activation journal is noncanonical or drifted");
  }
  assertSecretFreeExecutorStructure(document, "post-measurement activation journal");
  return document;
}

function samePrefix(left, right) {
  return canonicalText(right.slice(0, left.length)) === canonicalText(left);
}

function assertMonotonic(previous, next) {
  if (!previous) {
    if (next.state.status !== "initialized" || next.state.sequence !== 0) {
      throw new Error("the first activation journal state must be initialized");
    }
    return;
  }
  if (PHALA_POST_MEASUREMENT_ACTIVATION_TERMINAL_STATUSES.includes(
    previous.state.status,
  )) {
    throw new Error("terminal activation journals cannot be replaced automatically");
  }
  for (const field of [
    "batch_id",
    "release_sha",
    "activation_plan_sha256",
    "pre_ceremony_runtime_authority_sha256",
    "ceremony_authorization_sha256",
    "target",
    "profile_activation",
    "allowed_environment_key_names_sha256",
    "injected_environment_key_names_sha256",
    "adapter_identity_sha256",
    "assembly_receipt_sha256",
  ]) {
    if (canonicalText(previous.state[field]) !== canonicalText(next.state[field])) {
      throw new Error(`activation journal immutable field changed: ${field}`);
    }
  }
  for (const field of [
    "arena_worker_presence_sha256",
    "arena_worker_presence_verified_at",
    "compute_recipient_activation_sha256",
    "compute_recipient_activation_verified_at",
    "combined_activation_verification_sha256",
  ]) {
    if (previous.state[field] !== null
      && previous.state[field] !== next.state[field]) {
      throw new Error(`activation journal proof field changed: ${field}`);
    }
  }
  if (next.state.sequence !== previous.state.sequence + 1
    || !samePrefix(previous.state.sdk_observations, next.state.sdk_observations)
    || !samePrefix(previous.state.mutation_attempts, next.state.mutation_attempts)) {
    throw new Error("activation journal sequence or durable prefix regressed");
  }
}

function publishDocument(pinnedDirectory, journalName, document, publishMode, faultStage) {
  const bytes = Buffer.from(canonicalText(document), "utf8");
  if (bytes.length > MAX_JOURNAL_BYTES) {
    throw new Error("post-measurement activation journal exceeds its size bound");
  }
  return publishPhalaPinnedPrivateFile(pinnedDirectory, journalName, bytes, {
    publishMode,
    mode: 0o600,
    maximum: MAX_JOURNAL_BYTES,
    faultStage,
  });
}

export function persistPhalaPostMeasurementActivationJournal({
  directory,
  state,
  lock,
  faultStage = null,
} = {}) {
  const normalized = normalizePhalaPostMeasurementActivationState(state);
  const pinnedDirectory = requireLock(lock, directory, normalized);
  const names = activationJournalNames(normalized.activation_plan_sha256);
  const previous = loadActivationJournalFromPinnedDirectory(
    pinnedDirectory,
    normalized.activation_plan_sha256,
  );
  const document = projectPhalaPostMeasurementActivationJournal(normalized);
  assertMonotonic(previous, document);
  publishDocument(
    pinnedDirectory,
    names.journal,
    document,
    previous ? "replace" : "create",
    faultStage,
  );
  const reread = loadActivationJournalFromPinnedDirectory(
    pinnedDirectory,
    normalized.activation_plan_sha256,
  );
  if (!reread || canonicalText(reread) !== canonicalText(document)) {
    throw new Error("durably published activation journal did not re-read exactly");
  }
  if (reread.state.status === "complete") {
    DURABLE_COMPLETIONS.set(reread, Object.freeze({
      directory,
      path: phalaPinnedPrivatePathForDisplay(pinnedDirectory, names.journal),
      state_sha256: reread.state_sha256,
      plan_sha256: reread.activation_plan_sha256,
    }));
  }
  return reread;
}

export function assertDurablyPersistedCompletedPhalaPostMeasurementActivationJournal({
  journal,
  directory,
  state,
  lock,
} = {}) {
  const provenance = journal && DURABLE_COMPLETIONS.get(journal);
  const normalized = normalizePhalaPostMeasurementActivationState(state);
  if (!provenance || provenance.directory !== directory
    || provenance.plan_sha256 !== normalized.activation_plan_sha256
    || provenance.state_sha256 !== phalaPostMeasurementActivationStateSha256(normalized)
    || normalized.status !== "complete") {
    throw new Error("a durably persisted completed activation journal is required");
  }
  requireLock(lock, directory, normalized);
  const reread = loadActivationJournalFromPinnedDirectory(
    lock.pinnedDirectory,
    normalized.activation_plan_sha256,
  );
  if (!reread || canonicalText(reread) !== canonicalText(journal)) {
    throw new Error("completed activation journal changed after durable publication");
  }
  return journal;
}

export function classifyPhalaPostMeasurementActivationRecovery(journal) {
  if (!journal) return Object.freeze({ action: "initialize_new_activation" });
  const state = normalizePhalaPostMeasurementActivationState(journal.state);
  if ([
    "patch_attempt_durable",
    "restart_attempt_durable",
    "ambiguous_reconcile_required",
  ].includes(state.status)) {
    return Object.freeze({
      action: "read_only_reconciliation_required",
      pending_mutation: structuredClone(state.pending_mutation),
      automatic_retry_authorized: false,
      automatic_cleanup_authorized: false,
    });
  }
  return Object.freeze({
    action: PHALA_POST_MEASUREMENT_ACTIVATION_TERMINAL_STATUSES.includes(state.status)
      ? "terminal_operator_review_required"
      : "same_authority_resume_review_required",
    status: state.status,
    automatic_retry_authorized: false,
    automatic_cleanup_authorized: false,
  });
}
