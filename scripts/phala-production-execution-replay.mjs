import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  CVM_LAUNCH_DOMAINS,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_EXACT_SDK_CALL_SEQUENCE,
  assertProductionFinalizedPhalaMutationGate,
  normalizeCompletedPhalaExecutorState,
  normalizeSignedEnvironmentKeyResponse,
  phalaExecutorStateDigest,
  productionFinalizedPhalaMutationGateSha256,
} from "./phala-production-executor-core.mjs";
import {
  assertDurablyPersistedCompletedPhalaRecoveryJournal,
  pinnedPhalaRecoveryDirectoryForLiveLock,
} from "./phala-production-recovery-journal.mjs";
import {
  closePhalaPinnedPrivateDirectory,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  phalaPinnedPrivatePathForDisplay,
  pinPhalaPrivateDirectory,
  publishPhalaPinnedPrivateFile,
  readPhalaPinnedPrivateFile,
} from "./phala-pinned-private-directory.mjs";
import {
  assertAuthenticatedPhalaSdkObservation,
  assertPinnedPhalaProductionSdkAdapter,
  authenticatedPhalaSdkObservationSha256,
  pinnedPhalaProductionSdkAdapterIdentitySha256,
  projectPinnedPhalaProductionSdkAdapterIdentity,
  readAuthenticatedPhalaSdkObservationResponse,
} from "./phala-production-sdk-adapter.mjs";

export const PHALA_PRODUCTION_EXECUTION_REPLAY_SCHEMA =
  "dnai.phala-production-execution-replay.v1";
export const PHALA_PRODUCTION_EXECUTION_REPLAY_DOMAIN =
  "dnai-wikigen/phala-production-execution-replay/v1\0";
export const PHALA_TERMINAL_RECOVERY_JOURNAL_REPLAY_DOMAIN =
  "dnai-wikigen/phala-terminal-recovery-journal-replay/v1\0";

const SDK_REQUEST_DOMAIN =
  "dnai-wikigen/phala-authenticated-sdk-request/v1\0";
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const RELEASE_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const MAX_REPLAY_BYTES = 512 * 1024;
const DURABLY_PERSISTED_REPLAYS = new WeakMap();
const PHALA_EXECUTION_ORDER = Object.freeze([
  ...CVM_LAUNCH_DOMAINS.filter((domain) => domain !== "main_runtime_cvm"),
  "main_runtime_cvm",
]);

const GLOBAL_OBSERVATION_KEYS = Object.freeze([
  "getCurrentUser",
  "getCvmCreateResources",
  "getOsImages",
  "getKmsList",
  "getKmsInfo",
  "nextAppIds",
]);

const OBSERVATION_INPUT_KEYS = Object.freeze([
  "globals",
  "provisions",
  "first_environment_keys",
  "immediate_environment_key_refetches",
  "commits",
  "cvm_infos",
  "cvm_attestations",
]);

const CONTEXT_KEYS = Object.freeze([
  "directory",
  "state",
  "journal",
  "lock",
  "adapter",
  "provisionGates",
  "commitGates",
  "observations",
]);

const RECEIPT_KEYS = Object.freeze([
  "schema",
  "truth_status",
  "batch_id",
  "bootstrap_authorization_id",
  "release_sha",
  "target_authority_sha256",
  "phala_recovery_directory_identity_anchor_sha256",
  "executor_state_sha256",
  "terminal_recovery_journal_sha256",
  "adapter_identity_sha256",
  "call_sequence_contract",
  "sdk_call_count",
  "sdk_calls",
  "mutation_gate_count",
  "mutation_gates",
  "persisted_at",
  "payload_persistence",
  "live_traffic_authorized",
]);

const SDK_CALL_KEYS = Object.freeze([
  "call_sequence",
  "phase",
  "method",
  "domain",
  "observed_at",
  "observation_sha256",
  "request_semantics_sha256",
  "sdk_response_sha256",
]);

const MUTATION_GATE_KEYS = Object.freeze([
  "mutation_sequence",
  "action",
  "domain",
  "gate_sha256",
  "readiness_sha256",
  "request_semantics_sha256",
  "observation_sha256",
  "checked_at",
  "expires_at",
]);

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, keys, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...keys].sort())) {
    throw new Error(`${label} must contain exactly the allowed fields`);
  }
  return value;
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map((entry) => sortedObject(entry));
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function canonicalCompact(value) {
  return JSON.stringify(sortedObject(value));
}

function canonicalText(value) {
  return `${JSON.stringify(sortedObject(value), null, 2)}\n`;
}

function domainDigest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(Buffer.from(domain, "utf8"))
    .update(Buffer.from(canonicalCompact(value), "utf8"))
    .digest("hex")}`;
}

function digest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function timestamp(value, label) {
  const parsedMs = typeof value === "string" && ISO_SECOND.test(value)
    ? Date.parse(value)
    : Number.NaN;
  if (!Number.isFinite(parsedMs)
    || new Date(parsedMs).toISOString().replace(".000Z", "Z") !== value) {
    throw new Error(`${label} must be a canonical UTC second`);
  }
  return value;
}

function exactIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new Error(`${label} must be a canonical bounded identifier`);
  }
  return value;
}

function canonicalInternalTimestamp() {
  const now = Date.now();
  if (!Number.isFinite(now)) throw new Error("production replay clock is unavailable");
  return new Date(Math.floor(now / 1_000) * 1_000)
    .toISOString().replace(".000Z", "Z");
}

function sdkRequestSemanticsSha256(httpMethod, pathAndQuery, body = null) {
  return domainDigest(SDK_REQUEST_DOMAIN, {
    http_method: httpMethod,
    path_and_query: pathAndQuery,
    body,
  });
}

function expectedSdkSchedule() {
  const calls = [
    ["authenticate_workspace", "getCurrentUser", null],
    ["review_resources", "getCvmCreateResources", null],
    ["review_os_images", "getOsImages", null],
    ["review_kms_catalog", "getKmsList", null],
    ["review_kms_identity", "getKmsInfo", null],
    ["reserve_app_ids", "nextAppIds", null],
  ];
  for (const domain of PHALA_EXECUTION_ORDER) {
    calls.push(["provision", "provisionCvm", domain]);
  }
  for (const domain of PHALA_EXECUTION_ORDER) {
    calls.push(["first_environment_key", "getAppEnvEncryptPubKey", domain]);
  }
  for (const domain of PHALA_EXECUTION_ORDER) {
    calls.push(
      ["immediate_environment_key_refetch", "getAppEnvEncryptPubKey", domain],
      ["commit", "commitCvmProvision", domain],
    );
  }
  for (const domain of PHALA_EXECUTION_ORDER) {
    calls.push(["posture", "getCvmInfo", domain]);
  }
  for (const domain of PHALA_EXECUTION_ORDER) {
    calls.push(["attestation", "getCvmAttestation", domain]);
  }
  return Object.freeze(calls.map((entry) => Object.freeze(entry)));
}

export const PHALA_EXACT_AUTHENTICATED_SDK_REPLAY_SCHEDULE =
  expectedSdkSchedule();

function normalizeSdkCall(value, index) {
  const call = exactRecord(value, SDK_CALL_KEYS, `SDK replay call[${index}]`);
  const [phase, method, domain] = PHALA_EXACT_AUTHENTICATED_SDK_REPLAY_SCHEDULE[index]
    ?? [];
  if (call.call_sequence !== index + 1
    || call.phase !== phase || call.method !== method || call.domain !== domain) {
    throw new Error("SDK replay calls do not follow the exact authenticated call order");
  }
  return {
    call_sequence: call.call_sequence,
    phase: call.phase,
    method: call.method,
    domain: call.domain,
    observed_at: timestamp(call.observed_at, `SDK replay call[${index}] observed_at`),
    observation_sha256: digest(
      call.observation_sha256,
      `SDK replay call[${index}] observation`,
    ),
    request_semantics_sha256: digest(
      call.request_semantics_sha256,
      `SDK replay call[${index}] request semantics`,
    ),
    sdk_response_sha256: digest(
      call.sdk_response_sha256,
      `SDK replay call[${index}] SDK response`,
    ),
  };
}

function normalizeMutationGate(value, index) {
  const gate = exactRecord(
    value,
    MUTATION_GATE_KEYS,
    `mutation replay gate[${index}]`,
  );
  const domainIndex = index % PHALA_EXECUTION_ORDER.length;
  const action = index < PHALA_EXECUTION_ORDER.length
    ? "provisionCvm"
    : "commitCvmProvision";
  if (gate.mutation_sequence !== index + 1
    || gate.action !== action
    || gate.domain !== PHALA_EXECUTION_ORDER[domainIndex]) {
    throw new Error("mutation replay gates do not follow supporting-six-then-main order");
  }
  const checkedAt = timestamp(gate.checked_at, `mutation gate[${index}] checked_at`);
  const expiresAt = timestamp(gate.expires_at, `mutation gate[${index}] expires_at`);
  if (Date.parse(expiresAt) <= Date.parse(checkedAt)) {
    throw new Error("mutation replay gate did not have a positive authorization window");
  }
  return {
    mutation_sequence: gate.mutation_sequence,
    action: gate.action,
    domain: gate.domain,
    gate_sha256: digest(gate.gate_sha256, `mutation gate[${index}] digest`),
    readiness_sha256: digest(
      gate.readiness_sha256,
      `mutation gate[${index}] readiness`,
    ),
    request_semantics_sha256: digest(
      gate.request_semantics_sha256,
      `mutation gate[${index}] request semantics`,
    ),
    observation_sha256: digest(
      gate.observation_sha256,
      `mutation gate[${index}] observation`,
    ),
    checked_at: checkedAt,
    expires_at: expiresAt,
  };
}

export function normalizeProductionExecutionReplayReceipt(value) {
  assertCanonicalPlainDataGraph(value, { label: "production execution replay receipt" });
  const receipt = exactRecord(value, RECEIPT_KEYS, "production execution replay receipt");
  if (receipt.schema !== PHALA_PRODUCTION_EXECUTION_REPLAY_SCHEMA
    || receipt.truth_status
      !== "durably_persisted_digest_only_replay_of_locally_authenticated_exact_order_phala_execution"
    || typeof receipt.release_sha !== "string" || !RELEASE_SHA.test(receipt.release_sha)
    || receipt.payload_persistence
      !== "digests_only_no_requests_responses_ciphertext_or_secrets"
    || receipt.live_traffic_authorized !== false
    || canonicalCompact(receipt.call_sequence_contract)
      !== canonicalCompact(PHALA_EXACT_SDK_CALL_SEQUENCE)
    || receipt.sdk_call_count
      !== PHALA_EXACT_AUTHENTICATED_SDK_REPLAY_SCHEDULE.length
    || !Array.isArray(receipt.sdk_calls)
    || receipt.sdk_calls.length !== receipt.sdk_call_count
    || receipt.mutation_gate_count !== PHALA_EXECUTION_ORDER.length * 2
    || !Array.isArray(receipt.mutation_gates)
    || receipt.mutation_gates.length !== receipt.mutation_gate_count) {
    throw new Error("production execution replay receipt has invalid fixed semantics");
  }
  const sdkCalls = receipt.sdk_calls.map(normalizeSdkCall);
  const mutationGates = receipt.mutation_gates.map(normalizeMutationGate);
  if (new Set(sdkCalls.map(({ observation_sha256: valueDigest }) => valueDigest)).size
      !== sdkCalls.length
    || new Set(mutationGates.map(({ gate_sha256: valueDigest }) => valueDigest)).size
      !== mutationGates.length) {
    throw new Error("SDK observation and mutation gate digests must be pairwise distinct");
  }
  for (let index = 1; index < sdkCalls.length; index += 1) {
    if (Date.parse(sdkCalls[index].observed_at)
        < Date.parse(sdkCalls[index - 1].observed_at)) {
      throw new Error("authenticated SDK observation timestamps regressed");
    }
  }
  const provisionCalls = sdkCalls.filter(({ phase }) => phase === "provision");
  const commitCalls = sdkCalls.filter(({ phase }) => phase === "commit");
  for (let index = 0; index < mutationGates.length; index += 1) {
    const call = index < PHALA_EXECUTION_ORDER.length
      ? provisionCalls[index]
      : commitCalls[index - PHALA_EXECUTION_ORDER.length];
    const gate = mutationGates[index];
    if (gate.domain !== call.domain
      || gate.request_semantics_sha256 !== call.request_semantics_sha256
      || gate.observation_sha256 !== call.observation_sha256
      || Date.parse(gate.checked_at) > Date.parse(call.observed_at)
      || Date.parse(gate.expires_at) < Date.parse(call.observed_at)) {
      throw new Error("mutation gate replay does not bind its exact SDK call");
    }
  }
  const persistedAt = timestamp(receipt.persisted_at, "production replay persisted_at");
  if (Date.parse(persistedAt) < Date.parse(sdkCalls.at(-1).observed_at)) {
    throw new Error("production replay was backdated before its last SDK observation");
  }
  const normalized = {
    schema: PHALA_PRODUCTION_EXECUTION_REPLAY_SCHEMA,
    truth_status:
      "durably_persisted_digest_only_replay_of_locally_authenticated_exact_order_phala_execution",
    batch_id: digest(receipt.batch_id, "replay batch id"),
    bootstrap_authorization_id: digest(
      receipt.bootstrap_authorization_id,
      "replay bootstrap authorization id",
    ),
    release_sha: receipt.release_sha,
    target_authority_sha256: digest(
      receipt.target_authority_sha256,
      "replay target authority",
    ),
    phala_recovery_directory_identity_anchor_sha256: digest(
      receipt.phala_recovery_directory_identity_anchor_sha256,
      "replay recovery-directory identity anchor",
    ),
    executor_state_sha256: digest(
      receipt.executor_state_sha256,
      "replay executor state",
    ),
    terminal_recovery_journal_sha256: digest(
      receipt.terminal_recovery_journal_sha256,
      "replay terminal recovery journal",
    ),
    adapter_identity_sha256: digest(
      receipt.adapter_identity_sha256,
      "replay adapter identity",
    ),
    call_sequence_contract: [...PHALA_EXACT_SDK_CALL_SEQUENCE],
    sdk_call_count: sdkCalls.length,
    sdk_calls: sdkCalls,
    mutation_gate_count: mutationGates.length,
    mutation_gates: mutationGates,
    persisted_at: persistedAt,
    payload_persistence: "digests_only_no_requests_responses_ciphertext_or_secrets",
    live_traffic_authorized: false,
  };
  if (Buffer.byteLength(canonicalText(normalized), "utf8") > MAX_REPLAY_BYTES) {
    throw new Error("production execution replay receipt exceeds its size bound");
  }
  return deepFreezeCanonicalPlainDataGraph(normalized, {
    label: "normalized production execution replay receipt",
  });
}

export function canonicalProductionExecutionReplayReceiptText(value) {
  return canonicalText(normalizeProductionExecutionReplayReceipt(value));
}

export function productionExecutionReplayReceiptSha256(value) {
  return domainDigest(
    PHALA_PRODUCTION_EXECUTION_REPLAY_DOMAIN,
    normalizeProductionExecutionReplayReceipt(value),
  );
}

function assertPrivateRecoveryDirectory(directory) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)
    || path.resolve(directory) !== directory || path.normalize(directory) !== directory
    || fs.realpathSync.native(directory) !== directory) {
    throw new Error("production replay directory must be one canonical absolute real path");
  }
  const stat = fs.lstatSync(directory);
  if (stat.isSymbolicLink() || !stat.isDirectory()
    || (stat.mode & 0o777) !== 0o700
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("production replay directory must be owned and mode 0700");
  }
  return directory;
}

export function productionExecutionReplayReceiptPath(directory, batchId) {
  assertPrivateRecoveryDirectory(directory);
  digest(batchId, "production replay batch id");
  return path.join(
    directory,
    `${batchId.slice("sha256:".length)}.execution-replay.json`,
  );
}

function productionExecutionReplayReceiptName(batchId) {
  digest(batchId, "production replay batch id");
  return `${batchId.slice("sha256:".length)}.execution-replay.json`;
}

export function loadProductionExecutionReplayReceipt({
  directory,
  batchId,
  directoryIdentityAnchorSha256 = null,
} = {}) {
  productionExecutionReplayReceiptName(batchId);
  const pinnedDirectory = pinPhalaPrivateDirectory(directory, {
    expectedIdentityAnchorSha256: directoryIdentityAnchorSha256,
  });
  try {
    return loadProductionExecutionReplayReceiptFromPinnedDirectory(
      pinnedDirectory,
      batchId,
    );
  } finally {
    closePhalaPinnedPrivateDirectory(pinnedDirectory);
  }
}

function loadProductionExecutionReplayReceiptFromPinnedDirectory(
  pinnedDirectory,
  batchId,
) {
  const bytes = readPhalaPinnedPrivateFile(
    pinnedDirectory,
    productionExecutionReplayReceiptName(batchId),
    { mode: 0o600, maximum: MAX_REPLAY_BYTES, minimum: 2 },
  );
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("production replay receipt is not valid JSON");
  }
  const normalized = normalizeProductionExecutionReplayReceipt(parsed);
  if (canonicalText(normalized) !== bytes.toString("utf8")) {
    throw new Error("production replay receipt is not canonical JSON");
  }
  return normalized;
}

function observationInput(value) {
  const observations = exactRecord(
    value,
    OBSERVATION_INPUT_KEYS,
    "production replay observations",
  );
  exactRecord(
    observations.globals,
    GLOBAL_OBSERVATION_KEYS,
    "production replay global observations",
  );
  for (const [field, entries] of Object.entries(observations)) {
    if (field === "globals") continue;
    if (!Array.isArray(entries) || entries.length !== PHALA_EXECUTION_ORDER.length) {
      throw new Error(`${field} must contain exactly seven authenticated observations`);
    }
  }
  return observations;
}

function replayContextProjection(value) {
  return Object.fromEntries(CONTEXT_KEYS.map((key) => [key, value[key]]));
}

function exactObservation({ adapter, observation, method, domain, callSequence, state }) {
  const authenticated = assertAuthenticatedPhalaSdkObservation(observation, {
    adapter,
    method,
    domain,
  });
  if (authenticated.call_sequence !== callSequence
    || authenticated.adapter_identity_sha256
      !== pinnedPhalaProductionSdkAdapterIdentitySha256(adapter)
    || authenticated.target_authority_sha256 !== state.target_authority_sha256
    || authenticated.transport_authentication
      !== "canonical_current_profile_x_api_key_over_tls"
    || authenticated.http_status < 200 || authenticated.http_status >= 300) {
    throw new Error("authenticated SDK observation differs from replay authority");
  }
  timestamp(authenticated.observed_at, `${method} observation time`);
  digest(authenticated.request_semantics_sha256, `${method} request semantics`);
  digest(authenticated.sdk_response_sha256, `${method} response semantics`);
  const expectedMethod = ["provisionCvm", "commitCvmProvision"].includes(method)
    ? "POST"
    : "GET";
  if (authenticated.http_method !== expectedMethod) {
    throw new Error(`${method} used an unexpected HTTP method`);
  }
  return authenticated;
}

function sdkCallProjection(observation, phase) {
  return {
    call_sequence: observation.call_sequence,
    phase,
    method: observation.method,
    domain: observation.target_domain,
    observed_at: observation.observed_at,
    observation_sha256: observation.__authenticated_digest,
    request_semantics_sha256: observation.request_semantics_sha256,
    sdk_response_sha256: observation.sdk_response_sha256,
  };
}

function withAuthenticatedDigest(observation, options) {
  const value = exactObservation({ ...options, observation });
  return Object.freeze({
    ...value,
    __authenticated_digest: authenticatedPhalaSdkObservationSha256(value, {
      adapter: options.adapter,
      method: options.method,
      domain: options.domain,
    }),
  });
}

function assertExpectedGetRequest(observation, pathAndQuery, label) {
  const expected = sdkRequestSemanticsSha256("GET", pathAndQuery, null);
  if (observation.request_semantics_sha256 !== expected) {
    throw new Error(`${label} did not target the exact pinned SDK resource`);
  }
}

function terminalJournalSha256(journal) {
  return domainDigest(PHALA_TERMINAL_RECOVERY_JOURNAL_REPLAY_DOMAIN, journal);
}

function validateProductionReplayContext(raw) {
  const context = exactRecord(raw, CONTEXT_KEYS, "production replay context");
  const normalizedState = normalizeCompletedPhalaExecutorState(context.state);
  if (canonicalCompact(normalizedState) !== canonicalCompact(context.state)) {
    throw new Error("production replay state must already be exact and normalized");
  }
  assertDurablyPersistedCompletedPhalaRecoveryJournal({
    journal: context.journal,
    directory: context.directory,
    state: context.state,
    lock: context.lock,
  });
  const pinnedDirectory = pinnedPhalaRecoveryDirectoryForLiveLock({
    lock: context.lock,
    directory: context.directory,
    batchId: normalizedState.batch_id,
    authorizationId: normalizedState.bootstrap_authorization_id,
  });
  const pinnedDirectoryIdentityAnchorSha256 =
    phalaPinnedPrivateDirectoryIdentityAnchorSha256(pinnedDirectory);
  if (normalizedState.phala_recovery_directory_identity_anchor_sha256
      !== pinnedDirectoryIdentityAnchorSha256) {
    throw new Error(
      "executor state does not bind the exact pinned recovery-directory identity anchor",
    );
  }
  assertPinnedPhalaProductionSdkAdapter(context.adapter);
  const identity = projectPinnedPhalaProductionSdkAdapterIdentity(context.adapter);
  const identitySha256 = pinnedPhalaProductionSdkAdapterIdentitySha256(context.adapter);
  if (identity.production_target_authority_sha256
      !== normalizedState.target_authority_sha256) {
    throw new Error("adapter identity is not bound to the executor target authority");
  }
  if (!Array.isArray(context.provisionGates)
    || context.provisionGates.length !== PHALA_EXECUTION_ORDER.length
    || !Array.isArray(context.commitGates)
    || context.commitGates.length !== PHALA_EXECUTION_ORDER.length) {
    throw new Error("production replay requires exactly fourteen production mutation gates");
  }
  const observations = observationInput(context.observations);
  let nextSequence = 1;
  const sdkCalls = [];
  const observe = (observation, method, domain, phase) => {
    const authenticated = withAuthenticatedDigest(observation, {
      adapter: context.adapter,
      method,
      domain,
      callSequence: nextSequence,
      state: normalizedState,
    });
    nextSequence += 1;
    sdkCalls.push(sdkCallProjection(authenticated, phase));
    return authenticated;
  };

  const globals = {};
  const globalPhases = [
    "authenticate_workspace",
    "review_resources",
    "review_os_images",
    "review_kms_catalog",
    "review_kms_identity",
    "reserve_app_ids",
  ];
  for (let index = 0; index < GLOBAL_OBSERVATION_KEYS.length; index += 1) {
    const method = GLOBAL_OBSERVATION_KEYS[index];
    globals[method] = observe(
      observations.globals[method],
      method,
      null,
      globalPhases[index],
    );
  }
  assertExpectedGetRequest(globals.getCurrentUser, "/api/v1/auth/me", "getCurrentUser");
  assertExpectedGetRequest(
    globals.getCvmCreateResources,
    "/api/v1/teepods/cvm-create-resources",
    "getCvmCreateResources",
  );
  assertExpectedGetRequest(
    globals.getOsImages,
    "/api/v1/os-images?page=1&page_size=100&is_dev=false",
    "getOsImages",
  );
  assertExpectedGetRequest(
    globals.getKmsList,
    "/api/v1/kms?page=1&page_size=100&is_onchain=false",
    "getKmsList",
  );
  assertExpectedGetRequest(
    globals.nextAppIds,
    `/api/v1/kms/phala/next_app_id?counts=${PHALA_EXECUTION_ORDER.length}`,
    "nextAppIds",
  );
  const reservationsResponse = readAuthenticatedPhalaSdkObservationResponse(
    observations.globals.nextAppIds,
    { adapter: context.adapter, method: "nextAppIds", domain: null },
  );
  const reservationEnvelope = exactRecord(
    reservationsResponse,
    ["app_ids"],
    "nextAppIds response",
  );
  if (!Array.isArray(reservationEnvelope.app_ids)
    || reservationEnvelope.app_ids.length !== PHALA_EXECUTION_ORDER.length) {
    throw new Error("nextAppIds did not return the exact seven reservations");
  }
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    const returned = exactRecord(
      reservationEnvelope.app_ids[index],
      ["app_id", "nonce"],
      `nextAppIds reservation[${index}]`,
    );
    const expected = normalizedState.reservations[index];
    if (returned.app_id.replace(/^0x/, "").toLowerCase() !== expected.app_id
      || returned.nonce !== expected.nonce) {
      throw new Error("nextAppIds response differs from executor reservations");
    }
  }

  const provisions = [];
  let kmsId = null;
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    const domain = PHALA_EXECUTION_ORDER[index];
    const observation = observe(
      observations.provisions[index],
      "provisionCvm",
      domain,
      "provision",
    );
    const stateEntry = normalizedState.preparations[index];
    if (stateEntry.request_sha256 !== observation.request_semantics_sha256
      || stateEntry.observation_sha256 !== observation.__authenticated_digest
      || stateEntry.observed_at !== observation.observed_at) {
      throw new Error(`${domain} provision state does not bind the authenticated SDK call`);
    }
    const response = readAuthenticatedPhalaSdkObservationResponse(
      observations.provisions[index],
      { adapter: context.adapter, method: "provisionCvm", domain },
    );
    const responseAppId = typeof response?.app_id === "string"
      ? response.app_id.replace(/^0x/, "").toLowerCase()
      : "";
    if (!APP_ID.test(responseAppId)
      || responseAppId !== normalizedState.reservations[index].app_id) {
      throw new Error(`${domain} provision response differs from reserved app id`);
    }
    if (response?.kms_id != null && response?.kms_info?.id != null
      && response.kms_id !== response.kms_info.id) {
      throw new Error(`${domain} provision response contains conflicting KMS identities`);
    }
    const returnedKmsId = exactIdentifier(
      response?.kms_id ?? response?.kms_info?.id,
      `${domain} provision KMS id`,
    );
    if (kmsId !== null && returnedKmsId !== kmsId) {
      throw new Error("seven provision responses do not use one exact private KMS");
    }
    kmsId = returnedKmsId;
    provisions.push(observation);
  }
  assertExpectedGetRequest(
    globals.getKmsInfo,
    `/api/v1/kms/${kmsId}`,
    "getKmsInfo",
  );

  const firstKeys = [];
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    const domain = PHALA_EXECUTION_ORDER[index];
    firstKeys.push(observe(
      observations.first_environment_keys[index],
      "getAppEnvEncryptPubKey",
      domain,
      "first_environment_key",
    ));
  }

  const refetchedKeys = [];
  const commits = [];
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    const domain = PHALA_EXECUTION_ORDER[index];
    const appId = normalizedState.reservations[index].app_id;
    const first = firstKeys[index];
    assertExpectedGetRequest(
      first,
      `/api/v1/kms/${kmsId}/pubkey/${appId}`,
      `${domain} first environment key`,
    );
    const refetch = observe(
      observations.immediate_environment_key_refetches[index],
      "getAppEnvEncryptPubKey",
      domain,
      "immediate_environment_key_refetch",
    );
    assertExpectedGetRequest(
      refetch,
      `/api/v1/kms/${kmsId}/pubkey/${appId}`,
      `${domain} immediate environment key refetch`,
    );
    if (first.sdk_response_sha256 !== refetch.sdk_response_sha256) {
      throw new Error(`${domain} signed environment key changed before commit`);
    }
    const firstResponse = normalizeSignedEnvironmentKeyResponse(
      readAuthenticatedPhalaSdkObservationResponse(
        observations.first_environment_keys[index],
        { adapter: context.adapter, method: "getAppEnvEncryptPubKey", domain },
      ),
    );
    const refetchResponse = normalizeSignedEnvironmentKeyResponse(
      readAuthenticatedPhalaSdkObservationResponse(
        observations.immediate_environment_key_refetches[index],
        { adapter: context.adapter, method: "getAppEnvEncryptPubKey", domain },
      ),
    );
    if (canonicalCompact(firstResponse) !== canonicalCompact(refetchResponse)) {
      throw new Error(`${domain} environment key response changed before commit`);
    }
    const publicKeySha256 = `sha256:${createHash("sha256")
      .update(Buffer.from(firstResponse.public_key, "hex"))
      .digest("hex")}`;
    if (normalizedState.signed_key_bindings[index].public_key_sha256
        !== publicKeySha256) {
      throw new Error(`${domain} executor signed-key binding differs from SDK response`);
    }
    refetchedKeys.push(refetch);
    const commit = observe(
      observations.commits[index],
      "commitCvmProvision",
      domain,
      "commit",
    );
    const stateEntry = normalizedState.committed_prefix[index];
    if (stateEntry.request_sha256 !== commit.request_semantics_sha256
      || stateEntry.observation_sha256 !== commit.__authenticated_digest
      || stateEntry.observed_at !== commit.observed_at) {
      throw new Error(`${domain} commit state does not bind the authenticated SDK call`);
    }
    const response = readAuthenticatedPhalaSdkObservationResponse(
      observations.commits[index],
      { adapter: context.adapter, method: "commitCvmProvision", domain },
    );
    if (String(response?.id) !== stateEntry.cvm_id) {
      throw new Error(`${domain} commit response differs from committed CVM id`);
    }
    commits.push(commit);
  }

  const cvmInfos = [];
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    const domain = PHALA_EXECUTION_ORDER[index];
    const cvmId = normalizedState.committed_prefix[index].cvm_id;
    const observation = observe(
      observations.cvm_infos[index],
      "getCvmInfo",
      domain,
      "posture",
    );
    assertExpectedGetRequest(
      observation,
      `/api/v1/cvms/${cvmId}`,
      `${domain} getCvmInfo`,
    );
    const response = readAuthenticatedPhalaSdkObservationResponse(
      observations.cvm_infos[index],
      { adapter: context.adapter, method: "getCvmInfo", domain },
    );
    if (String(response?.id) !== cvmId) {
      throw new Error(`${domain} getCvmInfo response differs from committed CVM id`);
    }
    cvmInfos.push(observation);
  }

  const attestations = [];
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    const domain = PHALA_EXECUTION_ORDER[index];
    const cvmId = normalizedState.committed_prefix[index].cvm_id;
    const observation = observe(
      observations.cvm_attestations[index],
      "getCvmAttestation",
      domain,
      "attestation",
    );
    assertExpectedGetRequest(
      observation,
      `/api/v1/cvms/${cvmId}/attestation`,
      `${domain} getCvmAttestation`,
    );
    attestations.push(observation);
  }
  if (nextSequence - 1 !== PHALA_EXACT_AUTHENTICATED_SDK_REPLAY_SCHEDULE.length) {
    throw new Error("production replay did not consume the exact SDK call schedule");
  }

  const mutationGates = [];
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length * 2; index += 1) {
    const provision = index < PHALA_EXECUTION_ORDER.length;
    const domainIndex = index % PHALA_EXECUTION_ORDER.length;
    const domain = PHALA_EXECUTION_ORDER[domainIndex];
    const action = provision ? "provisionCvm" : "commitCvmProvision";
    const rawGate = provision
      ? context.provisionGates[domainIndex]
      : context.commitGates[domainIndex];
    const gate = assertProductionFinalizedPhalaMutationGate(rawGate, {
      nowMs: Date.parse(rawGate?.checked_at),
      minimumRemainingMs: 1,
    });
    const stateEntry = provision
      ? normalizedState.preparations[domainIndex]
      : normalizedState.committed_prefix[domainIndex];
    const observation = provision
      ? provisions[domainIndex]
      : commits[domainIndex];
    if (gate.action !== action || gate.domain !== domain
      || gate.batch_id !== normalizedState.batch_id
      || gate.bootstrap_authorization_id
        !== normalizedState.bootstrap_authorization_id
      || gate.bootstrap_authorization_receipt_sha256
        !== normalizedState.bootstrap_authorization_receipt_sha256
      || gate.production_target_authority_sha256
        !== normalizedState.target_authority_sha256
      || gate.readiness_sha256 !== stateEntry.readiness_sha256
      || stateEntry.request_sha256 !== observation.request_semantics_sha256
      || stateEntry.observation_sha256 !== observation.__authenticated_digest
      || Date.parse(gate.checked_at) > Date.parse(stateEntry.attempted_at)
      || Date.parse(stateEntry.attempted_at) > Date.parse(observation.observed_at)
      || Date.parse(gate.expires_at) < Date.parse(observation.observed_at)) {
      throw new Error(`${domain} ${action} gate, state, and observation provenance differ`);
    }
    mutationGates.push({
      mutation_sequence: index + 1,
      action,
      domain,
      gate_sha256: productionFinalizedPhalaMutationGateSha256(rawGate, {
        nowMs: Date.parse(gate.checked_at),
        minimumRemainingMs: 1,
      }),
      readiness_sha256: gate.readiness_sha256,
      request_semantics_sha256: observation.request_semantics_sha256,
      observation_sha256: observation.__authenticated_digest,
      checked_at: gate.checked_at,
      expires_at: gate.expires_at,
    });
  }

  return {
    pinned_directory: pinnedDirectory,
    pinned_directory_identity_anchor_sha256: pinnedDirectoryIdentityAnchorSha256,
    state: normalizedState,
    state_sha256: phalaExecutorStateDigest(normalizedState),
    journal_sha256: terminalJournalSha256(context.journal),
    adapter_identity_sha256: identitySha256,
    sdk_calls: sdkCalls,
    mutation_gates: mutationGates,
  };
}

function receiptFromValidatedContext(validated, persistedAt) {
  return normalizeProductionExecutionReplayReceipt({
    schema: PHALA_PRODUCTION_EXECUTION_REPLAY_SCHEMA,
    truth_status:
      "durably_persisted_digest_only_replay_of_locally_authenticated_exact_order_phala_execution",
    batch_id: validated.state.batch_id,
    bootstrap_authorization_id: validated.state.bootstrap_authorization_id,
    release_sha: validated.state.release_sha,
    target_authority_sha256: validated.state.target_authority_sha256,
    phala_recovery_directory_identity_anchor_sha256:
      validated.pinned_directory_identity_anchor_sha256,
    executor_state_sha256: validated.state_sha256,
    terminal_recovery_journal_sha256: validated.journal_sha256,
    adapter_identity_sha256: validated.adapter_identity_sha256,
    call_sequence_contract: [...PHALA_EXACT_SDK_CALL_SEQUENCE],
    sdk_call_count: validated.sdk_calls.length,
    sdk_calls: validated.sdk_calls,
    mutation_gate_count: validated.mutation_gates.length,
    mutation_gates: validated.mutation_gates,
    persisted_at: persistedAt,
    payload_persistence: "digests_only_no_requests_responses_ciphertext_or_secrets",
    live_traffic_authorized: false,
  });
}

function publishPrivateReplayReceipt(pinnedDirectory, receipt) {
  const name = productionExecutionReplayReceiptName(receipt.batch_id);
  const outputPath = phalaPinnedPrivatePathForDisplay(pinnedDirectory, name);
  const bytes = Buffer.from(canonicalText(receipt), "utf8");
  publishPhalaPinnedPrivateFile(pinnedDirectory, name, bytes, {
    publishMode: "create",
    mode: 0o600,
    maximum: MAX_REPLAY_BYTES,
  });
  return outputPath;
}

export function persistProductionExecutionReplay(raw = {}) {
  const context = exactRecord(raw, CONTEXT_KEYS, "production replay persistence input");
  const validated = validateProductionReplayContext(context);
  const receipt = receiptFromValidatedContext(validated, canonicalInternalTimestamp());
  const receiptPath = publishPrivateReplayReceipt(validated.pinned_directory, receipt);
  const reread = loadProductionExecutionReplayReceiptFromPinnedDirectory(
    validated.pinned_directory,
    validated.state.batch_id,
  );
  if (canonicalText(reread) !== canonicalText(receipt)) {
    throw new Error("durably persisted production replay did not re-read exactly");
  }
  DURABLY_PERSISTED_REPLAYS.set(reread, Object.freeze({
    directory: context.directory,
    directory_device: validated.pinned_directory.device,
    directory_inode: validated.pinned_directory.inode,
    directory_identity_anchor_sha256:
      validated.pinned_directory_identity_anchor_sha256,
    receipt_path: receiptPath,
    receipt_sha256: productionExecutionReplayReceiptSha256(reread),
    executor_state_sha256: validated.state_sha256,
    terminal_recovery_journal_sha256: validated.journal_sha256,
    adapter_identity_sha256: validated.adapter_identity_sha256,
  }));
  return reread;
}

export function assertDurablyPersistedProductionExecutionReplay(raw = {}) {
  const input = exactRecord(
    raw,
    ["receipt", ...CONTEXT_KEYS],
    "production replay assertion input",
  );
  const provenance = input.receipt && DURABLY_PERSISTED_REPLAYS.get(input.receipt);
  if (!provenance || provenance.directory !== input.directory) {
    throw new Error("a locally verified durably persisted production replay is required");
  }
  const validated = validateProductionReplayContext(replayContextProjection(input));
  if (provenance.executor_state_sha256 !== validated.state_sha256
    || provenance.directory_device !== validated.pinned_directory.device
    || provenance.directory_inode !== validated.pinned_directory.inode
    || provenance.directory_identity_anchor_sha256
      !== validated.pinned_directory_identity_anchor_sha256
    || provenance.terminal_recovery_journal_sha256 !== validated.journal_sha256
    || provenance.adapter_identity_sha256 !== validated.adapter_identity_sha256
    || input.receipt.executor_state_sha256 !== validated.state_sha256
    || input.receipt.terminal_recovery_journal_sha256 !== validated.journal_sha256
    || input.receipt.phala_recovery_directory_identity_anchor_sha256
      !== validated.pinned_directory_identity_anchor_sha256
    || input.receipt.adapter_identity_sha256 !== validated.adapter_identity_sha256) {
    throw new Error("production replay provenance changed after durable publication");
  }
  const expected = receiptFromValidatedContext(validated, input.receipt.persisted_at);
  if (canonicalText(expected) !== canonicalText(input.receipt)) {
    throw new Error("production replay no longer reconstructs from exact live provenance");
  }
  const reread = loadProductionExecutionReplayReceiptFromPinnedDirectory(
    validated.pinned_directory,
    validated.state.batch_id,
  );
  if (canonicalText(reread) !== canonicalText(input.receipt)
    || productionExecutionReplayReceiptSha256(reread)
      !== provenance.receipt_sha256) {
    throw new Error("production replay receipt changed after durable publication");
  }
  return input.receipt;
}
