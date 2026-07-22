import {
  keccak256,
  sha256 as viemSha256,
  stringToHex,
  type Address,
  type Hex,
} from "viem";
import { BASE_SEPOLIA, deployment } from "../config";
import { publicClient } from "./contract";
import { publicErrorText } from "./errorText";

const encoder = new TextEncoder();
const MAX_PUBLIC_RESPONSE_BYTES = 512 * 1024;
const MAX_PUBLIC_PROJECTION_DEPTH = 64;
const MAX_PUBLIC_PROJECTION_NODES = 50_000;
const MODELED_STATUS = "modeled";
const MODELED_ASSURANCE = "projection_only_no_hardened_executor";
const PER_ROW_STATUS = "per_row";
const PER_ROW_ASSURANCE = "per_submission_execution_provenance";
const WORKER_REPORTED_ASSURANCE = "worker_reported_qvl_binding_not_independently_verified";
const ARENA_WORKER_EVIDENCE_CLASSIFICATION = "authenticated_worker_presence_not_tdx_attestation";
const ARENA_WORKER_HEARTBEAT_SCHEMA = "dnai.arena.safe-worker-heartbeat.v1";
const ARENA_WORKER_RELEASE_BINDING_SCHEMA = "dnai.arena.safe-worker-release-binding.v1";
const ARENA_WORKER_HEARTBEAT_BINDING_SCHEMA = "dnai.arena.safe-worker-presence-binding.v1";
const ARENA_WORKER_RELEASE_BINDING_DOMAIN = "dnai-wikigen/arena-worker-release-binding/v1\0";
const ARENA_WORKER_HEARTBEAT_BINDING_DOMAIN = "dnai-wikigen/arena-worker-presence-binding/v1\0";
const MAX_ARENA_WORKER_HEARTBEAT_TIME = 4_102_444_800;

export interface ArenaExecutionCapability {
  status: "modeled";
  isolation: "non_hardened";
  backend: string;
  warning: string;
  hostile_code_ready: false;
  live_execution: false;
  worker_connected: false;
}

export interface ArenaChallengeManifest {
  surface: "arena_challenge_manifest";
  schema_version: 1;
  challenge_id: string;
  version: string;
  slug: string;
  title: string;
  summary: string;
  environment: string;
  candidate: {
    kind: string;
    runtime: string;
    entrypoint: string;
    max_source_bytes: number;
  };
  evaluation: {
    metric: string;
    direction: "higher_is_better" | "lower_is_better";
    release_mechanism: string;
    exact_reward_egress: false;
    ladder_policy: {
      step_denominator: number;
      max_submissions: number;
      max_improvement_steps: number;
    };
  };
  data_policy: { synthetic_only: boolean; raw_data_egress: false };
  execution_capability: ArenaExecutionCapability;
  manifest_hash: string;
  product_status: "modeled";
  execution_assurance: "projection_only_no_hardened_executor";
  raw_secret_egress: false;
}

export interface ArenaCatalog {
  surface: "arena_challenge_catalog";
  schema_version: 1;
  challenge_count: number;
  challenges: ArenaChallengeManifest[];
  product_status: "modeled";
  execution_assurance: "projection_only_no_hardened_executor";
  raw_secret_egress: false;
}

export interface ArenaPublicSubmission {
  surface: "arena_submission";
  schema_version: 2;
  submission_id: string;
  challenge_id: string;
  challenge_version: string;
  state: string;
  candidate_commitment: `sha256:${string}`;
  identity: { wallet_address_hash: string; project_id_hash: string };
  manifest: {
    schema_version: 1;
    challenge_manifest_hash: string;
    candidate_kind: string;
    runtime: string;
    entrypoint: string;
    mode: "test" | "benchmark" | "leaderboard";
    private_size_egress: false;
  };
  queue_events: Array<{
    sequence: number;
    from_state: string | null;
    to_state: string;
    reason: string;
  }>;
  ladder_release: null | {
    submission_index: number;
    accepted: boolean;
    leaderboard_step_index: number;
    step_denominator: number;
    improvement_steps_so_far: number;
    has_leaderboard_entry: boolean;
  };
  execution_capability: ArenaExecutionCapability;
  execution_provenance: ArenaExecutionProvenance;
  product_status: "modeled" | "live";
  execution_assurance: "projection_only_no_hardened_executor" | "worker_reported_qvl_binding_not_independently_verified";
  exact_timing_egress: false;
  encrypted_reference_public: false;
  raw_candidate_accepted: false;
  raw_secret_egress: false;
}

interface ArenaExecutionProvenanceBoundary {
  evidence_classification: "none" | "worker_reported_qvl_binding_not_independently_verified";
  independently_verified_by_client: false;
  raw_tdx_quote_egress: false;
  exact_score_egress: false;
  exact_timing_egress: false;
}

export type ArenaExecutionProvenance = ArenaExecutionProvenanceBoundary & (
  | {
    status: "not_executed";
    outcome: null;
    runtime: string;
    runtime_policy_commitment: null;
    challenge_manifest_hash: null;
    compose_hash: null;
    app_id: null;
    os_image_hash: null;
    quote_sha256: null;
    verifier_address: null;
    verdict_digest: null;
    tee_signer_address: null;
    chain_id: null;
    challenge_registry_address: null;
    evidence_classification: "none";
  }
  | {
    status: "worker_reported";
    outcome: "completed" | "failed";
    runtime: "dnai-safe-ir-v1";
    runtime_policy_commitment: `sha256:${string}`;
    challenge_manifest_hash: string;
    compose_hash: string;
    app_id: string;
    os_image_hash: string;
    quote_sha256: `sha256:${string}`;
    verifier_address: Address;
    verdict_digest: Hex;
    tee_signer_address: Address;
    chain_id: 84532;
    challenge_registry_address: Address;
    evidence_classification: "worker_reported_qvl_binding_not_independently_verified";
  }
);

export interface ArenaQueue {
  surface: "arena_public_queue";
  schema_version: 2;
  challenge_id: string;
  challenge_version: string;
  submission_count: number;
  submissions: ArenaPublicSubmission[];
  product_status: "per_row";
  execution_assurance: "per_submission_execution_provenance";
  raw_candidate_egress: false;
  exact_timing_egress: false;
  execution_capability: ArenaExecutionCapability;
}

export interface ArenaLeaderboardRow {
  rank: number;
  submission_id: string;
  identity: { wallet_address_hash: string; project_id_hash: string };
  candidate_commitment: string;
  leaderboard_step_index: number;
  step_denominator: number;
  improvement_steps_so_far: number;
  ladder_submission_index: number;
  execution_provenance: ArenaExecutionProvenance;
  product_status: "modeled" | "live";
  execution_assurance: "projection_only_no_hardened_executor" | "worker_reported_qvl_binding_not_independently_verified";
}

export interface ArenaLeaderboard {
  surface: "arena_public_leaderboard";
  schema_version: 2;
  challenge_id: string;
  challenge_version: string;
  row_count: number;
  rows: ArenaLeaderboardRow[];
  product_status: "per_row";
  execution_assurance: "per_submission_execution_provenance";
  raw_candidate_egress: false;
  exact_reward_egress: false;
  exact_timing_egress: false;
  encrypted_reference_egress: false;
  execution_capability: ArenaExecutionCapability;
}

export interface ArenaOwnerSubmission {
  surface: "arena_owner_submission";
  schema_version: 2;
  submission_id: string;
  challenge_id: string;
  challenge_version: string;
  identity: { wallet_address_hash: string; project_id_hash: string };
  candidate_commitment: `sha256:${string}`;
  manifest: {
    schema_version: 1;
    challenge_manifest_hash: string;
    candidate_kind: string;
    runtime: string;
    entrypoint: string;
    mode: "test" | "benchmark" | "leaderboard";
    private_size_egress: false;
  };
  state: string;
  bounded_result: null | {
    accepted: boolean;
    leaderboard_step_index: number;
    step_denominator: number;
    improvement_steps_so_far: number;
  };
  execution_capability: ArenaExecutionCapability;
  execution_provenance: ArenaExecutionProvenance;
  product_status: "modeled" | "live";
  execution_assurance: "projection_only_no_hardened_executor" | "worker_reported_qvl_binding_not_independently_verified";
  raw_candidate_egress: false;
  encrypted_reference_egress: false;
  exact_score_egress: false;
  exact_reward_egress: false;
  exact_timing_egress: false;
  internal_error_egress: false;
}

export interface ArenaOwnerSubmissions {
  surface: "arena_owner_submissions";
  schema_version: 2;
  challenge_id: string;
  challenge_version: string;
  owner_identity: string;
  page_count: number;
  submissions: ArenaOwnerSubmission[];
  has_more: boolean;
  next_cursor: string | null;
  scope: "authenticated_wallet_challenge_version";
  product_status: "per_row";
  execution_assurance: "per_submission_execution_provenance";
  raw_candidate_egress: false;
  encrypted_reference_egress: false;
  exact_score_egress: false;
  exact_reward_egress: false;
  exact_timing_egress: false;
  internal_error_egress: false;
}

export interface ArenaWorkerReleaseBinding {
  release_sha: string;
  image_digest: `sha256:${string}`;
  release_manifest_sha256: `sha256:${string}`;
  approved_challenge_set_sha256: `sha256:${string}`;
  approved_challenge_key: string;
  release_policy_commitment: `0x${string}`;
  catalog_manifest_hash: string;
  runtime: "dnai-safe-ir-v1";
  runtime_policy_commitment: `sha256:${string}`;
  compose_hash: string;
  app_id: string;
  os_image_hash: string;
}

export interface ArenaWorkerCapability {
  surface: "arena_worker_capability";
  schema_version: 2;
  challenge_id: string;
  challenge_version: string;
  status: "modeled" | "live";
  backend: "source_ready_preview" | "release_bound_safe_ir_worker";
  isolation: "not_connected" | "independent_job_gate_required";
  live_execution: boolean;
  worker_connected: boolean;
  safe_ir_execution_ready: boolean;
  hostile_general_code_ready: false;
  python_preview_live: false;
  freshness: "unavailable" | "fresh";
  evidence_authenticity: "unverified" | "hmac_verified";
  evidence_classification: "authenticated_worker_presence_not_tdx_attestation";
  gate_reason: "ready" | "python_preview_only" | "live_release_not_enabled" | "release_descriptor_unavailable" | "evidence_unavailable" | "evidence_invalid" | "evidence_mismatch" | "evidence_stale" | "worker_unavailable";
  heartbeat_observed_at: number | null;
  heartbeat_binding_sha256: `sha256:${string}` | null;
  release_binding_sha256: `sha256:${string}` | null;
  release_binding: ArenaWorkerReleaseBinding | null;
  warning: string;
  product_status: "modeled" | "live";
  exact_timing_egress: false;
  internal_error_egress: false;
  raw_candidate_egress: false;
  tdx_attestation_egress: false;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  return value as Record<string, unknown>;
}

function assertModeledCapability(value: unknown): asserts value is ArenaExecutionCapability {
  const capability = record(value, "Arena execution capability");
  if (
    capability.status !== MODELED_STATUS
    || capability.isolation !== "non_hardened"
    || capability.live_execution !== false
    || capability.hostile_code_ready !== false
    || capability.worker_connected !== false
    || typeof capability.backend !== "string"
    || typeof capability.warning !== "string"
  ) {
    throw new Error("Arena service made an unsupported execution-assurance claim");
  }
}

function assertNoForbiddenArenaFields(value: unknown): void {
  const forbidden = new Set([
    "candidate_source",
    "encrypted_reference",
    "exact_score",
    "internal_score",
    "project_id",
    "raw_candidate",
    "source_code",
    "source_bytes",
    "ciphertext_bytes",
    "wallet_address",
    "created_at",
    "updated_at",
    "occurred_at",
    "ladder_released_at",
  ]);
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  const seen = new WeakSet<object>();
  let visited = 0;
  while (stack.length > 0) {
    const next = stack.pop();
    if (!next || !next.value || typeof next.value !== "object") continue;
    if (next.depth > MAX_PUBLIC_PROJECTION_DEPTH) {
      throw new Error("Arena public projection exceeded the nesting limit");
    }
    if (++visited > MAX_PUBLIC_PROJECTION_NODES) {
      throw new Error("Arena public projection exceeded the node limit");
    }
    const object = next.value as object;
    if (seen.has(object)) throw new Error("Arena public projection contains a reference cycle");
    seen.add(object);
    if (Array.isArray(next.value)) {
      for (let index = next.value.length - 1; index >= 0; index -= 1) {
        stack.push({ value: next.value[index], depth: next.depth + 1 });
      }
      continue;
    }
    for (const [key, nested] of Object.entries(next.value as Record<string, unknown>)) {
      if (forbidden.has(key)) throw new Error(`Arena public projection contains forbidden field ${key}`);
      stack.push({ value: nested, depth: next.depth + 1 });
    }
  }
}

function assertProjectionTruth(value: Record<string, unknown>, label: string): void {
  if (value.product_status !== MODELED_STATUS || value.execution_assurance !== MODELED_ASSURANCE) {
    throw new Error(`${label} omitted the required modeled execution truth`);
  }
  if ("execution_capability" in value) assertModeledCapability(value.execution_capability);
}

function assertPerRowProjectionTruth(value: Record<string, unknown>, label: string): void {
  if (value.product_status !== PER_ROW_STATUS || value.execution_assurance !== PER_ROW_ASSURANCE) {
    throw new Error(`${label} omitted the required per-submission execution truth`);
  }
  if ("execution_capability" in value) assertModeledCapability(value.execution_capability);
}

function assertHex64(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} is not a lowercase SHA-256 digest`);
  }
}

const EXECUTION_PROVENANCE_FIELDS = [
  "status", "outcome", "runtime", "runtime_policy_commitment", "challenge_manifest_hash",
  "compose_hash", "app_id", "os_image_hash", "quote_sha256", "verifier_address",
  "verdict_digest", "tee_signer_address", "chain_id", "challenge_registry_address",
  "evidence_classification", "independently_verified_by_client", "raw_tdx_quote_egress",
  "exact_score_egress", "exact_timing_egress",
] as const;

function parseExecutionProvenance(value: unknown, label: string): ArenaExecutionProvenance {
  const evidence = exactRecord(value, EXECUTION_PROVENANCE_FIELDS, label);
  if (
    evidence.independently_verified_by_client !== false
    || evidence.raw_tdx_quote_egress !== false
    || evidence.exact_score_egress !== false
    || evidence.exact_timing_egress !== false
    || typeof evidence.runtime !== "string"
    || evidence.runtime.length < 1
    || evidence.runtime.length > 64
  ) throw new Error(`${label} violated the bounded evidence boundary`);

  if (evidence.status === "not_executed") {
    const nullable = [
      "outcome", "runtime_policy_commitment", "challenge_manifest_hash", "compose_hash", "app_id",
      "os_image_hash", "quote_sha256", "verifier_address", "verdict_digest", "tee_signer_address",
      "chain_id", "challenge_registry_address",
    ] as const;
    if (
      evidence.evidence_classification !== "none"
      || nullable.some((field) => evidence[field] !== null)
    ) throw new Error(`${label} made an execution claim without worker evidence`);
    return evidence as unknown as ArenaExecutionProvenance;
  }

  if (
    evidence.status !== "worker_reported"
    || !["completed", "failed"].includes(String(evidence.outcome))
    || evidence.runtime !== "dnai-safe-ir-v1"
    || evidence.evidence_classification !== WORKER_REPORTED_ASSURANCE
    || evidence.chain_id !== BASE_SEPOLIA.id
  ) throw new Error(`${label} made an unsupported worker evidence claim`);
  if (
    typeof evidence.runtime_policy_commitment !== "string"
    || !SHA256_COMMITMENT.test(evidence.runtime_policy_commitment)
    || evidence.runtime_policy_commitment === `sha256:${"0".repeat(64)}`
    || typeof evidence.quote_sha256 !== "string"
    || !SHA256_COMMITMENT.test(evidence.quote_sha256)
    || evidence.quote_sha256 === `sha256:${"0".repeat(64)}`
  ) throw new Error(`${label} contains a malformed SHA-256 commitment`);
  for (const [field, fieldLabel] of [
    ["challenge_manifest_hash", "challenge manifest"],
    ["compose_hash", "compose"],
    ["os_image_hash", "OS image"],
  ] as const) {
    assertHex64(evidence[field], `${label} ${fieldLabel}`);
    if (evidence[field] === "0".repeat(64)) throw new Error(`${label} contains a zero ${fieldLabel} commitment`);
  }
  boundedAscii(evidence.app_id, `${label} app id`, 128);
  const verifier = strictAddress(evidence.verifier_address, `${label} verifier`);
  const signer = strictAddress(evidence.tee_signer_address, `${label} TEE signer`);
  if (verifier === signer) throw new Error(`${label} verifier is not independent`);
  strictBytes32(evidence.verdict_digest, `${label} verdict digest`);
  strictAddress(evidence.challenge_registry_address, `${label} challenge registry`);
  return evidence as unknown as ArenaExecutionProvenance;
}

function assertRowExecutionTruth(value: Record<string, unknown>, label: string): ArenaExecutionProvenance {
  const evidence = parseExecutionProvenance(value.execution_provenance, `${label} execution provenance`);
  if (evidence.status === "worker_reported") {
    if (value.product_status !== "live" || value.execution_assurance !== WORKER_REPORTED_ASSURANCE) {
      throw new Error(`${label} did not bind its live label to worker-reported row evidence`);
    }
  } else if (value.product_status !== MODELED_STATUS || value.execution_assurance !== MODELED_ASSURANCE) {
    throw new Error(`${label} upgraded a row without execution evidence`);
  }
  return evidence;
}

const PUBLIC_SUBMISSION_FIELDS = [
  "surface", "schema_version", "submission_id", "challenge_id", "challenge_version", "identity",
  "candidate_commitment", "manifest", "state", "queue_events", "ladder_release",
  "execution_capability", "execution_provenance", "product_status", "execution_assurance",
  "exact_timing_egress", "encrypted_reference_public", "raw_candidate_accepted", "raw_secret_egress",
] as const;

function parsePublicSubmission(
  value: unknown,
  label: string,
  expectedChallenge?: { id: unknown; version: unknown },
): ArenaPublicSubmission {
  const submission = exactRecord(value, PUBLIC_SUBMISSION_FIELDS, label);
  assertModeledCapability(submission.execution_capability);
  const evidence = assertRowExecutionTruth(submission, label);
  const identity = exactRecord(submission.identity, ["wallet_address_hash", "project_id_hash"], `${label} identity`);
  const manifest = exactRecord(
    submission.manifest,
    ["schema_version", "challenge_manifest_hash", "candidate_kind", "runtime", "entrypoint", "mode", "private_size_egress"],
    `${label} manifest`,
  );
  assertHex64(identity.wallet_address_hash, `${label} wallet identity hash`);
  assertHex64(identity.project_id_hash, `${label} project identity hash`);
  assertHex64(manifest.challenge_manifest_hash, `${label} manifest hash`);
  if (
    evidence.runtime !== manifest.runtime
    || (evidence.status === "worker_reported" && evidence.challenge_manifest_hash !== manifest.challenge_manifest_hash)
  ) throw new Error(`${label} execution evidence does not bind its manifest`);
  if (
    submission.surface !== "arena_submission"
    || submission.schema_version !== 2
    || typeof submission.submission_id !== "string"
    || !/^sub_[0-9a-f]{24}$/.test(submission.submission_id)
    || typeof submission.challenge_id !== "string"
    || typeof submission.challenge_version !== "string"
    || (expectedChallenge && (
      submission.challenge_id !== expectedChallenge.id
      || submission.challenge_version !== expectedChallenge.version
    ))
    || typeof submission.candidate_commitment !== "string"
    || !SHA256_COMMITMENT.test(submission.candidate_commitment)
    || typeof submission.state !== "string"
    || manifest.schema_version !== 1
    || typeof manifest.candidate_kind !== "string"
    || typeof manifest.runtime !== "string"
    || typeof manifest.entrypoint !== "string"
    || !["test", "benchmark", "leaderboard"].includes(String(manifest.mode))
    || manifest.private_size_egress !== false
    || !Array.isArray(submission.queue_events)
    || submission.queue_events.length < 1
    || submission.queue_events.length > 32
    || submission.encrypted_reference_public !== false
    || submission.exact_timing_egress !== false
    || submission.raw_candidate_accepted !== false
    || submission.raw_secret_egress !== false
  ) throw new Error(`${label} failed its bounded schema checks`);
  for (const [index, rawEvent] of submission.queue_events.entries()) {
    const event = exactRecord(rawEvent, ["sequence", "from_state", "to_state", "reason"], `${label} queue event`);
    if (
      event.sequence !== index + 1
      || (event.from_state !== null && typeof event.from_state !== "string")
      || typeof event.to_state !== "string"
      || typeof event.reason !== "string"
    ) throw new Error(`${label} queue history is malformed`);
  }
  if (submission.ladder_release !== null) {
    const release = exactRecord(
      submission.ladder_release,
      ["submission_index", "accepted", "leaderboard_step_index", "step_denominator", "improvement_steps_so_far", "has_leaderboard_entry"],
      `${label} Ladder release`,
    );
    if (
      !Number.isInteger(release.submission_index)
      || typeof release.accepted !== "boolean"
      || !Number.isInteger(release.leaderboard_step_index)
      || !Number.isInteger(release.step_denominator)
      || Number(release.step_denominator) < 1
      || !Number.isInteger(release.improvement_steps_so_far)
      || typeof release.has_leaderboard_entry !== "boolean"
    ) throw new Error(`${label} Ladder release is malformed`);
  }
  return submission as unknown as ArenaPublicSubmission;
}

export async function readBoundedArenaResponseText(
  response: Response,
  maximumBytes = MAX_PUBLIC_RESPONSE_BYTES,
): Promise<string> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > MAX_PUBLIC_RESPONSE_BYTES) {
    throw new Error("Arena response byte limit is invalid");
  }
  const declared = response.headers.get("content-length")?.trim();
  if (declared && /^\d+$/.test(declared) && Number(declared) > maximumBytes) {
    await response.body?.cancel("Arena response exceeded the public size limit").catch(() => undefined);
    throw new Error("Arena response exceeded the public size limit");
  }
  if (!response.body) throw new Error("Arena returned an empty response");
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let received = 0;
  let text = "";
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      if (!(chunk.value instanceof Uint8Array)) throw new Error("Arena returned an invalid response stream");
      received += chunk.value.byteLength;
      if (received > maximumBytes) {
        await reader.cancel("Arena response exceeded the public size limit").catch(() => undefined);
        throw new Error("Arena response exceeded the public size limit");
      }
      text += decoder.decode(chunk.value, { stream: true });
    }
    text += decoder.decode();
  } catch (cause) {
    if (cause instanceof Error && cause.message === "Arena response exceeded the public size limit") throw cause;
    await reader.cancel("Arena response stream failed validation").catch(() => undefined);
    throw new Error("Arena returned an invalid UTF-8 response");
  } finally {
    reader.releaseLock();
  }
  if (received === 0) throw new Error("Arena returned an empty response");
  return text;
}

async function boundedJson(path: string, init: RequestInit = {}, publicProjection = true): Promise<unknown> {
  if (!deployment.delegateUrl) throw new Error("Fresh delegate endpoint is not configured");
  const baseUrl = deployment.delegateUrl.replace(/\/$/, "");
  const headers = new Headers(init.headers);
  if (!headers.has("Accept")) headers.set("Accept", "application/json");
  const response = await fetch(`${baseUrl}${path}`, {
    credentials: "omit",
    ...init,
    headers,
    signal: init.signal ?? AbortSignal.timeout(10_000),
  });
  const text = await readBoundedArenaResponseText(response);
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error("Arena returned malformed JSON");
  }
  if (!response.ok) {
    const fallback = `Request failed with status ${response.status}`;
    const detail = value && typeof value === "object" && "detail" in value
      ? (value as { detail: unknown }).detail
      : fallback;
    throw new Error(publicErrorText(detail, fallback));
  }
  if (publicProjection) assertNoForbiddenArenaFields(value);
  return value;
}

export function parseArenaCatalog(value: unknown): ArenaCatalog {
  assertNoForbiddenArenaFields(value);
  const catalog = record(value, "Arena catalog");
  assertProjectionTruth(catalog, "Arena catalog");
  if (
    catalog.surface !== "arena_challenge_catalog"
    || catalog.schema_version !== 1
    || catalog.raw_secret_egress !== false
    || !Array.isArray(catalog.challenges)
    || catalog.challenge_count !== catalog.challenges.length
    || catalog.challenges.length > 32
  ) {
    throw new Error("Arena catalog failed its bounded schema checks");
  }
  for (const item of catalog.challenges) {
    const challenge = record(item, "Arena challenge");
    assertProjectionTruth(challenge, "Arena challenge");
    assertModeledCapability(challenge.execution_capability);
    assertHex64(challenge.manifest_hash, "Arena manifest hash");
    const candidate = record(challenge.candidate, "Arena candidate policy");
    const evaluation = record(challenge.evaluation, "Arena evaluation policy");
    const dataPolicy = record(challenge.data_policy, "Arena data policy");
    if (
      challenge.surface !== "arena_challenge_manifest"
      || challenge.schema_version !== 1
      || challenge.raw_secret_egress !== false
      || typeof challenge.challenge_id !== "string"
      || typeof challenge.version !== "string"
      || typeof challenge.title !== "string"
      || typeof challenge.summary !== "string"
      || typeof candidate.max_source_bytes !== "number"
      || candidate.max_source_bytes < 1
      || candidate.max_source_bytes > 65_536
      || evaluation.exact_reward_egress !== false
      || dataPolicy.raw_data_egress !== false
    ) {
      throw new Error("Arena challenge failed its bounded schema checks");
    }
  }
  return catalog as unknown as ArenaCatalog;
}

export function parseArenaQueue(value: unknown): ArenaQueue {
  assertNoForbiddenArenaFields(value);
  const queue = record(value, "Arena queue");
  assertPerRowProjectionTruth(queue, "Arena queue");
  if (
    queue.surface !== "arena_public_queue"
    || queue.schema_version !== 2
    || typeof queue.challenge_id !== "string"
    || typeof queue.challenge_version !== "string"
    || queue.raw_candidate_egress !== false
    || queue.exact_timing_egress !== false
    || !Array.isArray(queue.submissions)
    || queue.submission_count !== queue.submissions.length
    || queue.submissions.length > 100
  ) {
    throw new Error("Arena queue failed its bounded schema checks");
  }
  for (const submission of queue.submissions) {
    parsePublicSubmission(submission, "Arena queue submission", {
      id: queue.challenge_id,
      version: queue.challenge_version,
    });
  }
  return queue as unknown as ArenaQueue;
}

export function parseArenaLeaderboard(value: unknown): ArenaLeaderboard {
  assertNoForbiddenArenaFields(value);
  const board = record(value, "Arena leaderboard");
  assertPerRowProjectionTruth(board, "Arena leaderboard");
  if (
    board.surface !== "arena_public_leaderboard"
    || board.schema_version !== 2
    || typeof board.challenge_id !== "string"
    || typeof board.challenge_version !== "string"
    || typeof board.challenge_manifest_hash !== "string"
    || board.raw_candidate_egress !== false
    || board.exact_reward_egress !== false
    || board.exact_timing_egress !== false
    || board.encrypted_reference_egress !== false
    || !Array.isArray(board.rows)
    || board.row_count !== board.rows.length
    || board.rows.length > 100
  ) {
    throw new Error("Arena leaderboard failed its bounded schema checks");
  }
  assertHex64(board.challenge_manifest_hash, "Arena leaderboard manifest hash");
  for (const rawRow of board.rows) {
    const row = exactRecord(rawRow, [
      "rank", "submission_id", "identity", "candidate_commitment", "leaderboard_step_index",
      "step_denominator", "improvement_steps_so_far", "ladder_submission_index",
      "execution_provenance", "product_status", "execution_assurance",
    ], "Arena leaderboard row");
    const identity = exactRecord(row.identity, ["wallet_address_hash", "project_id_hash"], "Arena leaderboard identity");
    assertHex64(identity.wallet_address_hash, "Arena leaderboard wallet identity hash");
    assertHex64(identity.project_id_hash, "Arena leaderboard project identity hash");
    const evidence = assertRowExecutionTruth(row, "Arena leaderboard row");
    if (evidence.status === "worker_reported" && evidence.challenge_manifest_hash !== board.challenge_manifest_hash) {
      throw new Error("Arena leaderboard row execution evidence does not bind the challenge manifest");
    }
    if (
      !Number.isInteger(row.rank)
      || Number(row.rank) < 1
      || typeof row.submission_id !== "string"
      || !/^sub_[0-9a-f]{24}$/.test(row.submission_id)
      || typeof row.candidate_commitment !== "string"
      || !SHA256_COMMITMENT.test(row.candidate_commitment)
      || !Number.isInteger(row.leaderboard_step_index)
      || !Number.isInteger(row.step_denominator)
      || Number(row.step_denominator) < 1
      || !Number.isInteger(row.improvement_steps_so_far)
      || !Number.isInteger(row.ladder_submission_index)
    ) throw new Error("Arena leaderboard row failed its bounded schema checks");
  }
  return board as unknown as ArenaLeaderboard;
}

const OWNER_PAGE_FIELDS = [
  "surface", "schema_version", "challenge_id", "challenge_version", "owner_identity",
  "page_count", "submissions", "has_more", "next_cursor", "scope", "product_status",
  "execution_assurance", "raw_candidate_egress", "encrypted_reference_egress",
  "exact_score_egress", "exact_reward_egress", "exact_timing_egress", "internal_error_egress",
] as const;
const OWNER_SUBMISSION_FIELDS = [
  "surface", "schema_version", "submission_id", "challenge_id", "challenge_version",
  "identity", "candidate_commitment", "manifest", "state", "bounded_result",
  "execution_capability", "execution_provenance", "product_status", "execution_assurance", "raw_candidate_egress",
  "encrypted_reference_egress", "exact_score_egress", "exact_reward_egress",
  "exact_timing_egress", "internal_error_egress",
] as const;

export function parseArenaOwnerSubmissions(value: unknown): ArenaOwnerSubmissions {
  assertNoForbiddenArenaFields(value);
  const page = exactRecord(value, OWNER_PAGE_FIELDS, "Arena owner submissions");
  assertPerRowProjectionTruth(page, "Arena owner submissions");
  assertHex64(page.owner_identity, "Arena owner identity");
  if (
    page.surface !== "arena_owner_submissions"
    || page.schema_version !== 2
    || typeof page.challenge_id !== "string"
    || typeof page.challenge_version !== "string"
    || page.scope !== "authenticated_wallet_challenge_version"
    || !Array.isArray(page.submissions)
    || page.submissions.length > 100
    || page.page_count !== page.submissions.length
    || typeof page.has_more !== "boolean"
    || (page.next_cursor !== null && (typeof page.next_cursor !== "string" || !/^sub_[0-9a-f]{24}$/.test(page.next_cursor)))
    || (page.has_more && page.next_cursor === null)
    || (!page.has_more && page.next_cursor !== null)
    || page.raw_candidate_egress !== false
    || page.encrypted_reference_egress !== false
    || page.exact_score_egress !== false
    || page.exact_reward_egress !== false
    || page.exact_timing_egress !== false
    || page.internal_error_egress !== false
  ) throw new Error("Arena owner submissions failed its bounded schema checks");

  for (const value of page.submissions) {
    const item = exactRecord(value, OWNER_SUBMISSION_FIELDS, "Arena owner submission");
    const evidence = assertRowExecutionTruth(item, "Arena owner submission");
    const identity = exactRecord(item.identity, ["wallet_address_hash", "project_id_hash"], "Arena owner identity projection");
    const manifest = exactRecord(item.manifest, ["schema_version", "challenge_manifest_hash", "candidate_kind", "runtime", "entrypoint", "mode", "private_size_egress"], "Arena owner manifest");
    assertHex64(identity.wallet_address_hash, "Arena wallet identity hash");
    assertHex64(identity.project_id_hash, "Arena project identity hash");
    assertHex64(manifest.challenge_manifest_hash, "Arena owner manifest hash");
    if (
      evidence.runtime !== manifest.runtime
      || (evidence.status === "worker_reported" && evidence.challenge_manifest_hash !== manifest.challenge_manifest_hash)
    ) throw new Error("Arena owner submission execution evidence does not bind its manifest");
    assertModeledCapability(item.execution_capability);
    if (
      item.surface !== "arena_owner_submission"
      || item.schema_version !== 2
      || item.challenge_id !== page.challenge_id
      || item.challenge_version !== page.challenge_version
      || typeof item.submission_id !== "string"
      || !/^sub_[0-9a-f]{24}$/.test(item.submission_id)
      || typeof item.candidate_commitment !== "string"
      || !SHA256_COMMITMENT.test(item.candidate_commitment)
      || typeof item.state !== "string"
      || manifest.schema_version !== 1
      || manifest.private_size_egress !== false
      || !["test", "benchmark", "leaderboard"].includes(String(manifest.mode))
      || item.raw_candidate_egress !== false
      || item.encrypted_reference_egress !== false
      || item.exact_score_egress !== false
      || item.exact_reward_egress !== false
      || item.exact_timing_egress !== false
      || item.internal_error_egress !== false
    ) throw new Error("Arena owner submission failed its bounded schema checks");
    if (item.bounded_result !== null) {
      const result = exactRecord(item.bounded_result, ["accepted", "leaderboard_step_index", "step_denominator", "improvement_steps_so_far"], "Arena bounded owner result");
      if (
        typeof result.accepted !== "boolean"
        || !Number.isInteger(result.leaderboard_step_index)
        || !Number.isInteger(result.step_denominator)
        || !Number.isInteger(result.improvement_steps_so_far)
        || Number(result.step_denominator) < 1
      ) throw new Error("Arena bounded owner result is invalid");
    }
  }
  return page as unknown as ArenaOwnerSubmissions;
}

const WORKER_CAPABILITY_FIELDS = [
  "surface", "schema_version", "challenge_id", "challenge_version", "status", "backend",
  "isolation", "live_execution", "worker_connected", "safe_ir_execution_ready",
  "hostile_general_code_ready", "python_preview_live", "freshness", "evidence_authenticity",
  "evidence_classification", "gate_reason", "heartbeat_observed_at", "heartbeat_binding_sha256",
  "release_binding_sha256", "release_binding", "warning", "product_status",
  "exact_timing_egress", "internal_error_egress", "raw_candidate_egress", "tdx_attestation_egress",
] as const;
const WORKER_RELEASE_FIELDS = [
  "release_sha", "image_digest", "release_manifest_sha256", "release_policy_commitment",
  "approved_challenge_set_sha256", "approved_challenge_key",
  "catalog_manifest_hash", "runtime", "runtime_policy_commitment", "compose_hash", "app_id",
  "os_image_hash",
] as const;

function arenaWorkerDomainCommitment(
  domain: string,
  payload: unknown,
): `sha256:${string}` {
  const digest = viemSha256(stringToHex(`${domain}${canonicalArenaJson(payload)}`));
  return `sha256:${digest.slice(2)}`;
}

export function arenaWorkerReleaseBindingSha256(
  binding: ArenaWorkerReleaseBinding,
): `sha256:${string}` {
  return arenaWorkerDomainCommitment(
    ARENA_WORKER_RELEASE_BINDING_DOMAIN,
    {
      schema: ARENA_WORKER_RELEASE_BINDING_SCHEMA,
      release_binding: binding,
    },
  );
}

export function arenaWorkerHeartbeatBindingSha256(
  challengeId: string,
  challengeVersion: string,
  heartbeatObservedAt: number,
  releaseBindingSha256: `sha256:${string}`,
): `sha256:${string}` {
  if (
    challengeId !== "dnaseq-variant-qc-safe-ir"
    || challengeVersion !== "1.0.0"
    || !Number.isSafeInteger(heartbeatObservedAt)
    || heartbeatObservedAt < 0
    || heartbeatObservedAt > MAX_ARENA_WORKER_HEARTBEAT_TIME
    || !SHA256_COMMITMENT.test(releaseBindingSha256)
  ) throw new Error("Arena worker heartbeat binding is invalid");
  return arenaWorkerDomainCommitment(
    ARENA_WORKER_HEARTBEAT_BINDING_DOMAIN,
    {
      schema: ARENA_WORKER_HEARTBEAT_BINDING_SCHEMA,
      heartbeat_schema: ARENA_WORKER_HEARTBEAT_SCHEMA,
      challenge_id: challengeId,
      challenge_version: challengeVersion,
      heartbeat_observed_at: heartbeatObservedAt,
      release_binding_sha256: releaseBindingSha256,
      evidence_classification: ARENA_WORKER_EVIDENCE_CLASSIFICATION,
    },
  );
}

export function parseArenaWorkerCapability(value: unknown): ArenaWorkerCapability {
  assertNoForbiddenArenaFields(value);
  const capability = exactRecord(value, WORKER_CAPABILITY_FIELDS, "Arena worker capability");
  const reasons = new Set([
    "ready", "python_preview_only", "live_release_not_enabled", "release_descriptor_unavailable",
    "evidence_unavailable", "evidence_invalid", "evidence_mismatch", "evidence_stale", "worker_unavailable",
  ]);
  let binding: Record<string, unknown> | null = null;
  if (capability.release_binding !== null) {
    binding = exactRecord(capability.release_binding, WORKER_RELEASE_FIELDS, "Arena worker release binding");
    assertHex64(binding.catalog_manifest_hash, "Arena worker catalog manifest hash");
    if (
      typeof binding.release_sha !== "string" || !/^[0-9a-f]{40}$/.test(binding.release_sha)
      || typeof binding.image_digest !== "string" || !SHA256_COMMITMENT.test(binding.image_digest)
      || typeof binding.release_manifest_sha256 !== "string" || !SHA256_COMMITMENT.test(binding.release_manifest_sha256)
      || typeof binding.approved_challenge_set_sha256 !== "string" || !SHA256_COMMITMENT.test(binding.approved_challenge_set_sha256)
      || binding.approved_challenge_set_sha256 === `sha256:${"0".repeat(64)}`
      || binding.approved_challenge_key !== `${capability.challenge_id}@${capability.challenge_version}`
      || typeof binding.release_policy_commitment !== "string" || !/^0x[0-9a-f]{64}$/.test(binding.release_policy_commitment)
      || binding.runtime !== "dnai-safe-ir-v1"
      || typeof binding.runtime_policy_commitment !== "string" || !SHA256_COMMITMENT.test(binding.runtime_policy_commitment)
      || typeof binding.compose_hash !== "string" || !HEX_64.test(binding.compose_hash)
      || typeof binding.app_id !== "string" || !/^[\x21-\x7e]{1,128}$/.test(binding.app_id)
      || typeof binding.os_image_hash !== "string" || !HEX_64.test(binding.os_image_hash)
    ) throw new Error("Arena worker release binding is invalid");
  }
  const releaseBindingSha256 = capability.release_binding_sha256;
  if (
    (binding === null && releaseBindingSha256 !== null)
    || (binding !== null && (
      typeof releaseBindingSha256 !== "string"
      || !SHA256_COMMITMENT.test(releaseBindingSha256)
      || arenaWorkerReleaseBindingSha256(
        binding as unknown as ArenaWorkerReleaseBinding,
      ) !== releaseBindingSha256
    ))
  ) throw new Error("Arena worker release binding digest is invalid");

  const heartbeatObservedAt = capability.heartbeat_observed_at;
  const heartbeatBindingSha256 = capability.heartbeat_binding_sha256;
  const hasLiveHeartbeatBinding = (
    Number.isSafeInteger(heartbeatObservedAt)
    && Number(heartbeatObservedAt) >= 0
    && Number(heartbeatObservedAt) <= MAX_ARENA_WORKER_HEARTBEAT_TIME
    && typeof heartbeatBindingSha256 === "string"
    && SHA256_COMMITMENT.test(heartbeatBindingSha256)
    && typeof releaseBindingSha256 === "string"
    && SHA256_COMMITMENT.test(releaseBindingSha256)
    && arenaWorkerHeartbeatBindingSha256(
      String(capability.challenge_id),
      String(capability.challenge_version),
      Number(heartbeatObservedAt),
      releaseBindingSha256 as `sha256:${string}`,
    ) === heartbeatBindingSha256
  );
  const live = capability.status === "live";
  if (
    capability.surface !== "arena_worker_capability"
    || capability.schema_version !== 2
    || typeof capability.challenge_id !== "string"
    || typeof capability.challenge_version !== "string"
    || !["modeled", "live"].includes(String(capability.status))
    || !reasons.has(String(capability.gate_reason))
    || capability.hostile_general_code_ready !== false
    || capability.python_preview_live !== false
    || capability.evidence_classification !== ARENA_WORKER_EVIDENCE_CLASSIFICATION
    || capability.exact_timing_egress !== false
    || capability.internal_error_egress !== false
    || capability.raw_candidate_egress !== false
    || capability.tdx_attestation_egress !== false
    || typeof capability.warning !== "string"
    || (live && (
      capability.challenge_id !== "dnaseq-variant-qc-safe-ir"
      || capability.challenge_version !== "1.0.0"
      || capability.product_status !== "live"
      || capability.backend !== "release_bound_safe_ir_worker"
      || capability.isolation !== "independent_job_gate_required"
      || capability.live_execution !== true
      || capability.worker_connected !== true
      || capability.safe_ir_execution_ready !== true
      || capability.freshness !== "fresh"
      || capability.evidence_authenticity !== "hmac_verified"
      || capability.gate_reason !== "ready"
      || binding === null
      || !hasLiveHeartbeatBinding
    ))
    || (!live && (
      capability.product_status !== "modeled"
      || capability.backend !== "source_ready_preview"
      || capability.isolation !== "not_connected"
      || capability.live_execution !== false
      || capability.worker_connected !== false
      || capability.safe_ir_execution_ready !== false
      || capability.freshness !== "unavailable"
      || capability.evidence_authenticity !== "unverified"
      || capability.gate_reason === "ready"
      || heartbeatObservedAt !== null
      || heartbeatBindingSha256 !== null
    ))
  ) throw new Error("Arena worker capability made an unsupported execution claim");
  return capability as unknown as ArenaWorkerCapability;
}

export function arenaWorkerPresenceMatchesRegistryPreflight(
  capability: ArenaWorkerCapability | undefined,
  preflight: ArenaChallengeRegistryBrowserPreflight | undefined,
): boolean {
  const binding = capability?.release_binding;
  if (!capability || !preflight || !binding) return false;
  return capability.status === "live"
    && capability.schema_version === 2
    && capability.live_execution
    && capability.worker_connected
    && capability.safe_ir_execution_ready
    && capability.gate_reason === "ready"
    && capability.evidence_classification === ARENA_WORKER_EVIDENCE_CLASSIFICATION
    && capability.challenge_id === "dnaseq-variant-qc-safe-ir"
    && capability.challenge_version === "1.0.0"
    && capability.challenge_id === preflight.catalogChallengeId
    && capability.challenge_version === preflight.catalogChallengeVersion
    && Number.isSafeInteger(capability.heartbeat_observed_at)
    && capability.heartbeat_binding_sha256 !== null
    && capability.release_binding_sha256 !== null
    && arenaWorkerReleaseBindingSha256(binding) === capability.release_binding_sha256
    && arenaWorkerHeartbeatBindingSha256(
      capability.challenge_id,
      capability.challenge_version,
      Number(capability.heartbeat_observed_at),
      capability.release_binding_sha256,
    ) === capability.heartbeat_binding_sha256
    && binding.approved_challenge_key
      === `${preflight.catalogChallengeId}@${preflight.catalogChallengeVersion}`
    && binding.approved_challenge_set_sha256
      === preflight.approvedChallengeSetSha256
    && binding.catalog_manifest_hash === preflight.catalogManifestHash
    && binding.release_policy_commitment === preflight.releasePolicyCommitment;
}

export async function fetchArenaCatalog(): Promise<ArenaCatalog> {
  return parseArenaCatalog(await boundedJson("/arena/challenges"));
}

export async function fetchArenaQueue(challengeId: string, version: string): Promise<ArenaQueue> {
  return parseArenaQueue(await boundedJson(`/arena/challenges/${encodeURIComponent(challengeId)}/versions/${encodeURIComponent(version)}/queue?limit=100`));
}

export async function fetchArenaLeaderboard(challengeId: string, version: string): Promise<ArenaLeaderboard> {
  return parseArenaLeaderboard(await boundedJson(`/arena/challenges/${encodeURIComponent(challengeId)}/versions/${encodeURIComponent(version)}/leaderboard?limit=100`));
}

export async function fetchArenaOwnerSubmissions(
  challengeId: string,
  version: string,
  accessToken: string,
  options: { limit?: number; cursor?: string | null } = {},
): Promise<ArenaOwnerSubmissions> {
  const limit = options.limit ?? 25;
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("Arena owner page limit is invalid");
  if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(accessToken) || accessToken.length > 4096) {
    throw new Error("Arena wallet session is invalid");
  }
  const cursor = options.cursor;
  if (cursor != null && !/^sub_[0-9a-f]{24}$/.test(cursor)) throw new Error("Arena owner cursor is invalid");
  const query = new URLSearchParams({ limit: String(limit) });
  if (cursor) query.set("cursor", cursor);
  return parseArenaOwnerSubmissions(await boundedJson(
    `/arena/challenges/${encodeURIComponent(challengeId)}/versions/${encodeURIComponent(version)}/submissions/mine?${query.toString()}`,
    { headers: { Authorization: `Bearer ${accessToken}` }, cache: "no-store" },
  ));
}

export async function fetchArenaWorkerCapability(challengeId: string, version: string): Promise<ArenaWorkerCapability> {
  return parseArenaWorkerCapability(await boundedJson(
    `/arena/challenges/${encodeURIComponent(challengeId)}/versions/${encodeURIComponent(version)}/worker-capability`,
    { cache: "no-store" },
  ));
}

export async function candidateCommitment(bytes: Uint8Array): Promise<`sha256:${string}`> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.slice()));
  const hex = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  digest.fill(0);
  return `sha256:${hex}`;
}

const HEX_64 = /^[0-9a-f]{64}$/;
const SHA256_COMMITMENT = /^sha256:[0-9a-f]{64}$/;
const WALLET_ADDRESS = /^0x[0-9a-f]{40}$/;
const CHALLENGE_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const ZERO_ADDRESS = `0x${"0".repeat(40)}` as Address;
const UINT256_MAX = (1n << 256n) - 1n;
const ARENA_APPROVED_CHALLENGE_SET_SCHEMA =
  "dnai.arena.release-approved-challenge-set.v1";
const ARENA_APPROVED_CHALLENGE_SET_DOMAIN =
  "dnai-wikigen/arena-release-approved-challenge-set/v1\0";
const CHALLENGE_REGISTRY_BINDING_FIELDS = [
  "registry_challenge_id",
  "registry_version",
  "controller_address",
  "pending_controller_address",
  "lifecycle",
  "paused",
  "configuration_frozen",
  "catalog_manifest_hash",
  "metadata_uri",
  "metadata_hash",
  "sealed_artifact_commitment",
  "evaluator_commitment",
  "release_policy_commitment",
] as const;
const ENVELOPE_FIELDS = [
  "schema_version",
  "algorithm",
  "encoding",
  "key_id",
  "attestation_report_data",
  "aad",
  "ephemeral_public_key",
  "nonce",
  "ciphertext",
] as const;
const AAD_FIELDS = [
  "service",
  "context",
  "schema_version",
  "challenge_id",
  "challenge_version",
  "challenge_manifest_hash",
  "submission_manifest_hash",
  "candidate_commitment",
  "identity",
  "idempotency_key_hash",
  "key_id",
  "attestation_report_data_sha256",
  "registry_authorization_sha256",
] as const;
const HKDF_INFO = "dnai-wikigen/arena-candidate-ingress/v1";
const REGISTRY_AUTHORIZATION_COMMITMENT_DOMAIN =
  "dnai-wikigen/arena-registry-authorization-snapshot/v1\0";

export const challengeRegistryAbi = [
  {
    type: "function",
    name: "registryPaused",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "challengeExists",
    stateMutability: "view",
    inputs: [{ name: "challengeId", type: "uint256" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "getChallenge",
    stateMutability: "view",
    inputs: [{ name: "challengeId", type: "uint256" }],
    outputs: [{
      name: "",
      type: "tuple",
      components: [
        { name: "controller", type: "address" },
        { name: "pendingController", type: "address" },
        { name: "lifecycle", type: "uint8" },
        { name: "createdAt", type: "uint64" },
        { name: "updatedAt", type: "uint64" },
        { name: "latestVersion", type: "uint32" },
        { name: "paused", type: "bool" },
        { name: "configurationFrozen", type: "bool" },
      ],
    }],
  },
  {
    type: "function",
    name: "getVersion",
    stateMutability: "view",
    inputs: [
      { name: "challengeId", type: "uint256" },
      { name: "version", type: "uint32" },
    ],
    outputs: [{
      name: "",
      type: "tuple",
      components: [
        { name: "metadataURI", type: "string" },
        { name: "metadataHash", type: "bytes32" },
        { name: "sealedArtifactCommitment", type: "bytes32" },
        { name: "evaluatorCommitment", type: "bytes32" },
        { name: "releasePolicyCommitment", type: "bytes32" },
        { name: "createdAt", type: "uint64" },
      ],
    }],
  },
] as const;

export interface ArenaChallengeRegistryBinding {
  registry_challenge_id: string;
  registry_version: number;
  controller_address: Address;
  pending_controller_address: Address;
  lifecycle: "open";
  paused: false;
  configuration_frozen: true;
  catalog_manifest_hash: string;
  metadata_uri: string;
  metadata_hash: Hex;
  sealed_artifact_commitment: Hex;
  evaluator_commitment: Hex;
  release_policy_commitment: Hex;
}

export interface ArenaChallengeRegistryState {
  controller: Address;
  pendingController: Address;
  lifecycle: number;
  createdAt: bigint;
  updatedAt: bigint;
  latestVersion: number;
  paused: boolean;
  configurationFrozen: boolean;
}

export interface ArenaChallengeRegistryVersionState {
  metadataURI: string;
  metadataHash: Hex;
  sealedArtifactCommitment: Hex;
  evaluatorCommitment: Hex;
  releasePolicyCommitment: Hex;
  createdAt: bigint;
}

export interface ArenaChallengeRegistryReader {
  getChainId(): Promise<number>;
  getFinalizedBlock(): Promise<{ number: bigint; hash: Hex; timestamp: bigint }>;
  getBytecode(address: Address, blockNumber: bigint): Promise<Hex | undefined>;
  registryPaused(address: Address, blockNumber: bigint): Promise<boolean>;
  challengeExists(address: Address, challengeId: bigint, blockNumber: bigint): Promise<boolean>;
  getChallenge(address: Address, challengeId: bigint, blockNumber: bigint): Promise<ArenaChallengeRegistryState>;
  getVersion(address: Address, challengeId: bigint, version: number, blockNumber: bigint): Promise<ArenaChallengeRegistryVersionState>;
}

export interface ArenaChallengeRegistryBrowserPreflight {
  // This is a local, caller-controlled RPC observation. It protects this
  // browser from preparing against an unexpected registry row, but it is not
  // submitted as evidence and cannot authorize proxy persistence or a worker.
  status: "browser_preflight_passed";
  verificationScope: "browser_only";
  proxyIndependentlyVerified: false;
  workerAuthorized: false;
  chainId: 84532;
  verifiedBlockNumber: bigint;
  verifiedBlockHash: Hex;
  verifiedBlockTimestamp: bigint;
  registryAddress: Address;
  registryCodeHash: Hex;
  approvedChallengeSetSha256: `sha256:${string}`;
  registryChallengeId: string;
  registryVersion: number;
  controllerAddress: Address;
  pendingControllerAddress: Address;
  catalogChallengeId: string;
  catalogChallengeVersion: string;
  catalogManifestHash: string;
  metadataURI: string;
  metadataHash: Hex;
  sealedArtifactCommitment: Hex;
  evaluatorCommitment: Hex;
  releasePolicyCommitment: Hex;
  registryPaused: false;
  challengePaused: false;
  lifecycle: 1;
  configurationFrozen: true;
  latestVersion: number;
}

/**
 * A browser-proposed, byte-canonical registry snapshot. The proxy accepts this
 * only as an AEAD-bound request parameter, then independently re-reads the
 * same finalized Base Sepolia block before persisting anything.
 */
export interface ArenaChallengeRegistryAuthorizationSnapshot {
  schema_version: 1;
  verification_model: "single_rpc_reported_finalized_pinned_block";
  chain_id: 84532;
  block_number: string;
  block_hash: Hex;
  block_timestamp: string;
  registry_address: Address;
  registry_runtime_code_hash: Hex;
  approved_challenge_set_sha256: `sha256:${string}`;
  catalog_challenge_id: string;
  catalog_challenge_version: string;
  catalog_manifest_hash: string;
  registry_challenge_id: string;
  registry_version: number;
  controller_address: Address;
  pending_controller_address: Address;
  metadata_uri: string;
  metadata_hash: Hex;
  sealed_artifact_commitment: Hex;
  evaluator_commitment: Hex;
  release_policy_commitment: Hex;
  registry_paused: false;
  challenge_paused: false;
  lifecycle: 1;
  configuration_frozen: true;
  latest_version: number;
}

export interface ArenaChallengeRegistryVerificationOptions {
  reader?: ArenaChallengeRegistryReader;
  registryAddress?: Address;
  registryCodeHash?: Hex;
  bindingsJson?: string;
  approvedChallengeSetSha256?: `sha256:${string}`;
}

const defaultArenaChallengeRegistryReader: ArenaChallengeRegistryReader = {
  getChainId: () => publicClient.getChainId(),
  getFinalizedBlock: async () => {
    const block = await publicClient.getBlock({
      blockTag: "finalized",
      includeTransactions: false,
    });
    if (block.number === null || block.hash === null) {
      throw new Error("Base Sepolia RPC returned an incomplete finalized block");
    }
    return { number: block.number, hash: block.hash, timestamp: block.timestamp };
  },
  getBytecode: (address, blockNumber) => publicClient.getBytecode({ address, blockNumber }),
  registryPaused: (address, blockNumber) => publicClient.readContract({
    address,
    abi: challengeRegistryAbi,
    functionName: "registryPaused",
    blockNumber,
  }),
  challengeExists: (address, challengeId, blockNumber) => publicClient.readContract({
    address,
    abi: challengeRegistryAbi,
    functionName: "challengeExists",
    args: [challengeId],
    blockNumber,
  }),
  getChallenge: async (address, challengeId, blockNumber) => await publicClient.readContract({
    address,
    abi: challengeRegistryAbi,
    functionName: "getChallenge",
    args: [challengeId],
    blockNumber,
  }) as ArenaChallengeRegistryState,
  getVersion: async (address, challengeId, version, blockNumber) => await publicClient.readContract({
    address,
    abi: challengeRegistryAbi,
    functionName: "getVersion",
    args: [challengeId, version],
    blockNumber,
  }) as ArenaChallengeRegistryVersionState,
};

export interface ArenaSubmissionManifest {
  schema_version: 1;
  challenge_manifest_hash: string;
  candidate_kind: string;
  runtime: string;
  entrypoint: string;
  source_bytes: number;
  mode: "leaderboard";
}

export interface ArenaSubmissionPayload {
  candidate_commitment: `sha256:${string}`;
  manifest: ArenaSubmissionManifest;
  registry_authorization: ArenaChallengeRegistryAuthorizationSnapshot;
  envelope: {
    schema_version: 1;
    algorithm: "X25519-HKDF-SHA256-AES-256-GCM";
    encoding: "base64url-nopad";
    key_id: `sha256:${string}`;
    attestation_report_data: string;
    aad: string;
    ephemeral_public_key: string;
    nonce: string;
    ciphertext: string;
  };
}

export interface PreparedArenaSubmission {
  challengeId: string;
  challengeVersion: string;
  walletAddress: string;
  idempotencyKey: string;
  candidateCommitment: `sha256:${string}`;
  sourceBytes: number;
  ciphertextSha256: `sha256:${string}`;
  keyId: `sha256:${string}`;
  quoteDigest: `sha256:${string}`;
  registryBrowserPreflight: ArenaChallengeRegistryBrowserPreflight;
  payload: ArenaSubmissionPayload;
}

export interface ArenaSubmissionResult {
  surface: "arena_submission_result";
  created: boolean;
  idempotent_replay: boolean;
  registry_ingress_boundary: {
    surface: "arena_registry_ingress_boundary";
    schema_version: 1;
    status: "proxy_independently_verified_at_finalized_block";
    verification_model: "single_rpc_reported_finalized_pinned_block";
    browser_preflight_accepted_as_authority: false;
    proxy_registry_authorized: true;
    worker_registry_authorized: false;
    registry_authorization_sha256: `sha256:${string}`;
    chain_id: 84532;
    block_number: string;
    block_hash: Hex;
    registry_address: Address;
    registry_challenge_id: string;
    registry_version: number;
    independent_rpc_quorum_verified: false;
    consensus_proof_verified: false;
  };
  candidate_ingress: {
    surface: "arena_candidate_ingress_receipt";
    schema_version: 1;
    blob_sha256: `sha256:${string}`;
    ciphertext_sha256: `sha256:${string}`;
    key_id: `sha256:${string}`;
    created: boolean;
    idempotent_replay: boolean;
    sealed_reference_public: false;
    plaintext_candidate_accepted: false;
    product_status: "modeled";
    execution_assurance: "projection_only_no_hardened_executor";
    raw_secret_egress: false;
    private_size_egress: false;
  };
  submission: ArenaPublicSubmission;
  raw_candidate_accepted: false;
  encrypted_reference_egress: false;
  raw_secret_egress: false;
}

interface ArenaAttestation {
  mode: "tdx";
  quote: string;
  encryption_public_key: string;
  report_context: "arena";
  report_data: string;
  quote_report_data: string;
  app_id: string;
  compose_hash: string;
  os_image_hash: string;
  verified: false;
}

interface ArenaEncryptionContract {
  recipient: {
    encryption_public_key: string;
    key_id: `sha256:${string}`;
    report_context: "arena";
    report_data: string;
    attestation_report_data_sha256: `sha256:${string}`;
  };
  limits: {
    max_aad_bytes: number;
    max_ciphertext_bytes_including_gcm_tag: number;
    max_plaintext_bytes_from_cipher_limit: number;
    max_envelopes_per_store: number;
    idempotency_key_max_bytes: number;
  };
}

export interface ArenaProtocolIdentity {
  wallet_address_hash: string;
  project_id_hash: string;
}

export interface ArenaCandidateBinding {
  service: "dnai-wikigen";
  context: "arena_candidate_ingress";
  schema_version: 1;
  challenge_id: string;
  challenge_version: string;
  challenge_manifest_hash: string;
  submission_manifest_hash: `sha256:${string}`;
  candidate_commitment: `sha256:${string}`;
  identity: ArenaProtocolIdentity;
  idempotency_key_hash: `sha256:${string}`;
  key_id: `sha256:${string}`;
  attestation_report_data_sha256: `sha256:${string}`;
  registry_authorization_sha256: `sha256:${string}`;
}

function exactRecord(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  const parsed = record(value, label);
  const actual = Object.keys(parsed).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} fields do not match the versioned protocol`);
  }
  return parsed;
}

function exactStringArray(value: unknown, expected: readonly string[], label: string): void {
  if (!Array.isArray(value) || value.length !== expected.length || value.some((item, index) => item !== expected[index])) {
    throw new Error(`${label} does not match the versioned protocol`);
  }
}

function integer(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || typeof value !== "number" || value < minimum || value > maximum) {
    throw new Error(`${label} is outside its approved bound`);
  }
  return value;
}

function boundedAscii(value: unknown, label: string, maximumBytes: number): string {
  if (typeof value !== "string" || value.length < 1 || encoder.encode(value).byteLength > maximumBytes || /[^\x20-\x7e]/.test(value)) {
    throw new Error(`${label} must be bounded printable ASCII`);
  }
  return value;
}

function strictBytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !BYTES32.test(value) || value === ZERO_BYTES32) {
    throw new Error(`${label} must be a nonzero lowercase bytes32 value`);
  }
  return value as Hex;
}

function strictAddress(value: unknown, label: string): Address {
  if (typeof value !== "string" || !WALLET_ADDRESS.test(value) || value === ZERO_ADDRESS) {
    throw new Error(`${label} must be a nonzero lowercase Ethereum address`);
  }
  return value as Address;
}

export function parseArenaChallengeRegistryBindings(value: string): Record<string, ArenaChallengeRegistryBinding> {
  if (!value) throw new Error("Arena ChallengeRegistry bindings are not pinned in this build");
  let decoded: unknown;
  try {
    decoded = JSON.parse(value);
  } catch {
    throw new Error("Arena ChallengeRegistry bindings contain malformed JSON");
  }
  const root = record(decoded, "Arena ChallengeRegistry bindings");
  const entries = Object.entries(root);
  if (entries.length < 1 || entries.length > 32) {
    throw new Error("Arena ChallengeRegistry bindings are outside the approved count");
  }
  const parsed: Record<string, ArenaChallengeRegistryBinding> = {};
  const registryChallengeIds = new Set<string>();
  for (const [catalogKey, rawBinding] of entries) {
    const separator = catalogKey.lastIndexOf("@");
    const challengeId = catalogKey.slice(0, separator);
    const challengeVersion = catalogKey.slice(separator + 1);
    if (separator < 1 || !CHALLENGE_ID.test(challengeId) || !SEMVER.test(challengeVersion)) {
      throw new Error(`Arena ChallengeRegistry binding key ${catalogKey} is malformed`);
    }
    const binding = exactRecord(rawBinding, CHALLENGE_REGISTRY_BINDING_FIELDS, `Arena ChallengeRegistry binding ${catalogKey}`);
    if (typeof binding.registry_challenge_id !== "string" || !/^[1-9][0-9]{0,77}$/.test(binding.registry_challenge_id)) {
      throw new Error(`Arena ChallengeRegistry binding ${catalogKey} has an invalid challenge id`);
    }
    const numericChallengeId = BigInt(binding.registry_challenge_id);
    if (numericChallengeId > UINT256_MAX) {
      throw new Error(`Arena ChallengeRegistry binding ${catalogKey} exceeds uint256`);
    }
    if (registryChallengeIds.has(binding.registry_challenge_id)) {
      throw new Error(`Arena ChallengeRegistry challenge id ${binding.registry_challenge_id} is bound more than once`);
    }
    registryChallengeIds.add(binding.registry_challenge_id);
    const registryVersion = integer(binding.registry_version, `Arena ChallengeRegistry binding ${catalogKey} version`, 1, 0xffff_ffff);
    const catalogManifestHash = binding.catalog_manifest_hash;
    assertHex64(catalogManifestHash, `Arena ChallengeRegistry binding ${catalogKey} catalog manifest hash`);
    const metadataHash = strictBytes32(binding.metadata_hash, `Arena ChallengeRegistry binding ${catalogKey} metadata hash`);
    if (metadataHash !== `0x${catalogManifestHash}`) {
      throw new Error(`Arena ChallengeRegistry binding ${catalogKey} metadata hash does not commit to its catalog manifest`);
    }
    const sealedArtifactCommitment = strictBytes32(binding.sealed_artifact_commitment, `Arena ChallengeRegistry binding ${catalogKey} sealed artifact commitment`);
    const evaluatorCommitment = strictBytes32(binding.evaluator_commitment, `Arena ChallengeRegistry binding ${catalogKey} evaluator commitment`);
    const releasePolicyCommitment = strictBytes32(binding.release_policy_commitment, `Arena ChallengeRegistry binding ${catalogKey} release policy commitment`);
    if (new Set([metadataHash, sealedArtifactCommitment, evaluatorCommitment, releasePolicyCommitment]).size !== 4) {
      throw new Error(`Arena ChallengeRegistry binding ${catalogKey} commitments must be pairwise distinct`);
    }
    if (binding.pending_controller_address !== ZERO_ADDRESS) {
      throw new Error(`Arena ChallengeRegistry binding ${catalogKey} pending controller must be the zero address`);
    }
    if (binding.lifecycle !== "open" || binding.paused !== false || binding.configuration_frozen !== true) {
      throw new Error(`Arena ChallengeRegistry binding ${catalogKey} must authorize an Open, unpaused, frozen challenge`);
    }
    parsed[catalogKey] = {
      registry_challenge_id: binding.registry_challenge_id,
      registry_version: registryVersion,
      controller_address: strictAddress(binding.controller_address, `Arena ChallengeRegistry binding ${catalogKey} controller`),
      pending_controller_address: ZERO_ADDRESS,
      lifecycle: "open",
      paused: false,
      configuration_frozen: true,
      catalog_manifest_hash: catalogManifestHash,
      metadata_uri: boundedAscii(binding.metadata_uri, `Arena ChallengeRegistry binding ${catalogKey} metadata URI`, 256),
      metadata_hash: metadataHash,
      sealed_artifact_commitment: sealedArtifactCommitment,
      evaluator_commitment: evaluatorCommitment,
      release_policy_commitment: releasePolicyCommitment,
    };
  }
  const expectedChallengeIds = Array.from({ length: entries.length }, (_, index) => String(index + 1));
  const actualChallengeIds = [...registryChallengeIds].sort((left, right) => (
    BigInt(left) < BigInt(right) ? -1 : BigInt(left) > BigInt(right) ? 1 : 0
  ));
  if (actualChallengeIds.some((value, index) => value !== expectedChallengeIds[index])) {
    throw new Error("Arena ChallengeRegistry bindings must use exact contiguous genesis challenge ids 1..N");
  }
  return parsed;
}

function canonicalArenaApprovalJson(value: unknown): string {
  const normalize = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(normalize);
    if (item && typeof item === "object") {
      return Object.fromEntries(Object.keys(item as Record<string, unknown>)
        .sort()
        .map((key) => [key, normalize((item as Record<string, unknown>)[key])]));
    }
    return item;
  };
  return JSON.stringify(normalize(value));
}

export function arenaReleaseApprovedChallengeSetSha256(
  bindings: Record<string, ArenaChallengeRegistryBinding>,
): `sha256:${string}` {
  const committedBindings = Object.fromEntries(
    Object.entries(bindings)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, binding]) => [
        key,
        Object.fromEntries(Object.entries(binding).filter(
          ([field]) => field !== "release_policy_commitment",
        )),
      ]),
  );
  const payload = canonicalArenaApprovalJson({
    schema: ARENA_APPROVED_CHALLENGE_SET_SCHEMA,
    bindings: committedBindings,
  });
  const digest = viemSha256(stringToHex(
    `${ARENA_APPROVED_CHALLENGE_SET_DOMAIN}${payload}`,
  ));
  return `sha256:${digest.slice(2)}`;
}

function registryReadFailure(cause: unknown): Error {
  const detail = cause instanceof Error && cause.message ? `: ${cause.message.slice(0, 180)}` : "";
  return new Error(`Arena ChallengeRegistry browser preflight could not read Base Sepolia state${detail}`);
}

export async function runArenaChallengeRegistryBrowserPreflight(
  challenge: ArenaChallengeManifest,
  options: ArenaChallengeRegistryVerificationOptions = {},
): Promise<ArenaChallengeRegistryBrowserPreflight> {
  if (!CHALLENGE_ID.test(challenge.challenge_id) || !SEMVER.test(challenge.version) || !HEX_64.test(challenge.manifest_hash)) {
    throw new Error("Arena challenge identity is malformed");
  }
  const registryAddress = options.registryAddress ?? deployment.challengeRegistryAddress;
  const registryCodeHash = options.registryCodeHash ?? deployment.challengeRegistryCodeHash;
  if (!registryAddress || !/^0x[0-9a-fA-F]{40}$/.test(registryAddress)) {
    throw new Error("Arena ChallengeRegistry address is not pinned in this build");
  }
  if (!registryCodeHash || !BYTES32.test(registryCodeHash) || registryCodeHash === ZERO_BYTES32) {
    throw new Error("Arena ChallengeRegistry runtime code hash is not pinned in this build");
  }
  const bindings = parseArenaChallengeRegistryBindings(
    options.bindingsJson ?? deployment.arenaChallengeRegistryBindingsJson,
  );
  const approvedSetSha256 = options.approvedChallengeSetSha256
    ?? deployment.arenaApprovedChallengeSetSha256;
  if (
    !approvedSetSha256
    || !SHA256_COMMITMENT.test(approvedSetSha256)
    || approvedSetSha256 === `sha256:${"0".repeat(64)}`
  ) {
    throw new Error("Arena release-approved challenge-set digest is not pinned in this build");
  }
  const observedApprovedSetSha256 = arenaReleaseApprovedChallengeSetSha256(bindings);
  if (observedApprovedSetSha256 !== approvedSetSha256) {
    throw new Error("Arena release-approved challenge-set digest does not match its exact bindings");
  }
  const catalogKey = `${challenge.challenge_id}@${challenge.version}`;
  const binding = bindings[catalogKey];
  if (!binding) throw new Error(`Arena challenge ${catalogKey} has no exact ChallengeRegistry binding`);
  if (challenge.manifest_hash !== binding.catalog_manifest_hash) {
    throw new Error(`Arena challenge ${catalogKey} manifest does not match the pinned ChallengeRegistry binding`);
  }

  const reader = options.reader ?? defaultArenaChallengeRegistryReader;
  let chainId: number;
  let blockNumber: bigint;
  let blockHash: Hex;
  let blockTimestamp: bigint;
  let bytecode: Hex | undefined;
  try {
    chainId = await reader.getChainId();
    if (chainId !== BASE_SEPOLIA.id) {
      throw new Error(`Arena ChallengeRegistry RPC returned chain ${chainId}; expected Base Sepolia ${BASE_SEPOLIA.id}`);
    }
    const finalizedBlock = await reader.getFinalizedBlock();
    blockNumber = finalizedBlock.number;
    blockHash = finalizedBlock.hash;
    blockTimestamp = finalizedBlock.timestamp;
    if (
      blockNumber < 1n
      || blockTimestamp < 1n
      || !BYTES32.test(blockHash)
      || blockHash === ZERO_BYTES32
    ) throw new Error("Arena ChallengeRegistry RPC returned an invalid finalized block");
    bytecode = await reader.getBytecode(registryAddress, blockNumber);
  } catch (cause) {
    if (cause instanceof Error && cause.message.includes("expected Base Sepolia")) throw cause;
    throw registryReadFailure(cause);
  }
  if (!bytecode || bytecode === "0x") {
    throw new Error("Arena ChallengeRegistry address has no runtime bytecode on Base Sepolia");
  }
  const observedCodeHash = keccak256(bytecode);
  if (observedCodeHash !== registryCodeHash) {
    throw new Error("Arena ChallengeRegistry runtime bytecode does not match the approved code hash");
  }

  const registryChallengeId = BigInt(binding.registry_challenge_id);
  let paused: boolean;
  let exists: boolean;
  try {
    [paused, exists] = await Promise.all([
      reader.registryPaused(registryAddress, blockNumber),
      reader.challengeExists(registryAddress, registryChallengeId, blockNumber),
    ]);
  } catch (cause) {
    throw registryReadFailure(cause);
  }
  if (paused) throw new Error("Arena ChallengeRegistry is paused");
  if (!exists) throw new Error(`Arena ChallengeRegistry challenge ${binding.registry_challenge_id} does not exist`);

  let registryChallenge: ArenaChallengeRegistryState;
  try {
    registryChallenge = await reader.getChallenge(registryAddress, registryChallengeId, blockNumber);
  } catch (cause) {
    throw registryReadFailure(cause);
  }
  if (registryChallenge.lifecycle !== 1) {
    throw new Error(`Arena ChallengeRegistry challenge is not Open (lifecycle ${registryChallenge.lifecycle})`);
  }
  if (registryChallenge.controller.toLowerCase() !== binding.controller_address) {
    throw new Error("Arena ChallengeRegistry controller does not match the pinned binding");
  }
  if (registryChallenge.pendingController.toLowerCase() !== binding.pending_controller_address) {
    throw new Error("Arena ChallengeRegistry pending controller does not match the pinned binding");
  }
  if (registryChallenge.paused) throw new Error("Arena ChallengeRegistry challenge is paused");
  if (!registryChallenge.configurationFrozen) throw new Error("Arena ChallengeRegistry challenge configuration is not frozen");
  if (registryChallenge.latestVersion !== binding.registry_version) {
    throw new Error(`Arena ChallengeRegistry current version is ${registryChallenge.latestVersion}; expected ${binding.registry_version}`);
  }

  let registryVersion: ArenaChallengeRegistryVersionState;
  try {
    registryVersion = await reader.getVersion(
      registryAddress,
      registryChallengeId,
      binding.registry_version,
      blockNumber,
    );
  } catch (cause) {
    throw registryReadFailure(cause);
  }
  if (registryVersion.metadataURI !== binding.metadata_uri) {
    throw new Error("Arena ChallengeRegistry metadata URI does not match the pinned binding");
  }
  if (registryVersion.metadataHash !== binding.metadata_hash) {
    throw new Error("Arena ChallengeRegistry metadata commitment does not match the catalog manifest");
  }
  if (registryVersion.sealedArtifactCommitment !== binding.sealed_artifact_commitment) {
    throw new Error("Arena ChallengeRegistry sealed artifact commitment does not match the pinned binding");
  }
  if (registryVersion.evaluatorCommitment !== binding.evaluator_commitment) {
    throw new Error("Arena ChallengeRegistry evaluator commitment does not match the pinned binding");
  }
  if (registryVersion.releasePolicyCommitment !== binding.release_policy_commitment) {
    throw new Error("Arena ChallengeRegistry release policy commitment does not match the pinned binding");
  }

  return {
    status: "browser_preflight_passed",
    verificationScope: "browser_only",
    proxyIndependentlyVerified: false,
    workerAuthorized: false,
    chainId: BASE_SEPOLIA.id,
    verifiedBlockNumber: blockNumber,
    verifiedBlockHash: blockHash,
    verifiedBlockTimestamp: blockTimestamp,
    registryAddress,
    registryCodeHash,
    approvedChallengeSetSha256: approvedSetSha256,
    registryChallengeId: binding.registry_challenge_id,
    registryVersion: binding.registry_version,
    controllerAddress: binding.controller_address,
    pendingControllerAddress: binding.pending_controller_address,
    catalogChallengeId: challenge.challenge_id,
    catalogChallengeVersion: challenge.version,
    catalogManifestHash: challenge.manifest_hash,
    metadataURI: binding.metadata_uri,
    metadataHash: binding.metadata_hash,
    sealedArtifactCommitment: binding.sealed_artifact_commitment,
    evaluatorCommitment: binding.evaluator_commitment,
    releasePolicyCommitment: binding.release_policy_commitment,
    registryPaused: false,
    challengePaused: false,
    lifecycle: 1,
    configurationFrozen: true,
    latestVersion: registryChallenge.latestVersion,
  };
}

function bytesFromHex(value: string, expectedBytes?: number): Uint8Array {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  if (!/^[0-9a-f]+$/.test(raw) || raw.length % 2 !== 0) throw new Error("Arena attestation contains malformed hex");
  const bytes = new Uint8Array(raw.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(raw.slice(index * 2, index * 2 + 2), 16);
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) throw new Error(`Arena attestation field must be ${expectedBytes} bytes`);
  return bytes;
}

function hexFromBytes(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

function concatenate(...values: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((total, value) => total + value.length, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

function base64url(value: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < value.length; offset += 8_192) {
    binary += String.fromCharCode(...value.subarray(offset, offset + 8_192));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function canonicalString(value: string): string {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

/** Python json.dumps(sort_keys=True,separators=(",",":"),ensure_ascii=True). */
export function canonicalArenaJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return canonicalString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Arena canonical JSON rejects non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalArenaJson).join(",")}]`;
  if (value && typeof value === "object") {
    const source = value as Record<string, unknown>;
    return `{${Object.keys(source).sort().map((key) => {
      if (source[key] === undefined) throw new Error("Arena canonical JSON rejects undefined values");
      return `${canonicalString(key)}:${canonicalArenaJson(source[key])}`;
    }).join(",")}}`;
  }
  throw new Error("Arena canonical JSON rejects unsupported values");
}

export function arenaChallengeRegistryAuthorizationSnapshot(
  preflight: ArenaChallengeRegistryBrowserPreflight,
): ArenaChallengeRegistryAuthorizationSnapshot {
  if (
    preflight.status !== "browser_preflight_passed"
    || preflight.verificationScope !== "browser_only"
    || preflight.proxyIndependentlyVerified !== false
    || preflight.workerAuthorized !== false
    || preflight.chainId !== BASE_SEPOLIA.id
    || preflight.verifiedBlockNumber < 1n
    || preflight.verifiedBlockTimestamp < 1n
    || !BYTES32.test(preflight.verifiedBlockHash)
    || preflight.verifiedBlockHash === ZERO_BYTES32
  ) throw new Error("Arena registry browser preflight cannot form an authorization snapshot");
  return {
    schema_version: 1,
    verification_model: "single_rpc_reported_finalized_pinned_block",
    chain_id: BASE_SEPOLIA.id,
    block_number: preflight.verifiedBlockNumber.toString(10),
    block_hash: preflight.verifiedBlockHash,
    block_timestamp: preflight.verifiedBlockTimestamp.toString(10),
    registry_address: preflight.registryAddress,
    registry_runtime_code_hash: preflight.registryCodeHash,
    approved_challenge_set_sha256: preflight.approvedChallengeSetSha256,
    catalog_challenge_id: preflight.catalogChallengeId,
    catalog_challenge_version: preflight.catalogChallengeVersion,
    catalog_manifest_hash: preflight.catalogManifestHash,
    registry_challenge_id: preflight.registryChallengeId,
    registry_version: preflight.registryVersion,
    controller_address: preflight.controllerAddress,
    pending_controller_address: preflight.pendingControllerAddress,
    metadata_uri: preflight.metadataURI,
    metadata_hash: preflight.metadataHash,
    sealed_artifact_commitment: preflight.sealedArtifactCommitment,
    evaluator_commitment: preflight.evaluatorCommitment,
    release_policy_commitment: preflight.releasePolicyCommitment,
    registry_paused: false,
    challenge_paused: false,
    lifecycle: 1,
    configuration_frozen: true,
    latest_version: preflight.latestVersion,
  };
}

export async function arenaChallengeRegistryAuthorizationSha256(
  snapshot: ArenaChallengeRegistryAuthorizationSnapshot,
): Promise<`sha256:${string}`> {
  const bytes = encoder.encode(
    `${REGISTRY_AUTHORIZATION_COMMITMENT_DOMAIN}${canonicalArenaJson(snapshot)}`,
  );
  try {
    return sha256Commitment(bytes);
  } finally {
    bytes.fill(0);
  }
}

const SAFE_IR_SCHEMA = "dnai.dnaseq-variant-qc-safe-ir.v1";
const SAFE_IR_MAX_BYTES = 4_096;
const SAFE_IR_MAX_INSTRUCTIONS = 12;
export const ARENA_SAFE_IR_STARTER_FILENAME = "dnai-dnaseq-variant-qc-safe-ir-v1.json";
const ARENA_SAFE_IR_STARTER_SOURCE =
  '{"negative_pipeline":[{"op":"mad_filter","threshold_milli":3000},{"high":1,"low":1,"op":"trim"}],"positive_pipeline":[{"op":"sort"},{"high":1,"low":1,"op":"trim"}],"schema":"dnai.dnaseq-variant-qc-safe-ir.v1"}';
const SAFE_IR_FIELDS: Record<string, readonly string[]> = {
  sort: ["op"],
  trim: ["high", "low", "op"],
  mad_filter: ["op", "threshold_milli"],
  head: ["count", "op"],
  tail: ["count", "op"],
  stride: ["offset", "op", "step"],
};

/** A fresh copy of the canonical, capability-free starter candidate bytes. */
export function arenaSafeIrStarterCandidateBytes(): Uint8Array {
  return encoder.encode(ARENA_SAFE_IR_STARTER_SOURCE);
}

function safeIrInteger(value: unknown, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error("Safe-IR operands must be bounded integers");
  }
  return value;
}

/** Local UX preflight; the CVM worker repeats every check after decryption. */
export function validateArenaSafeIrCandidateBytes(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.byteLength < 1 || value.byteLength > SAFE_IR_MAX_BYTES) {
    throw new Error("Safe-IR candidate must be between 1 and 4,096 bytes");
  }
  let source = "";
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch {
    throw new Error("Safe-IR candidate must be valid UTF-8");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new Error("Safe-IR candidate must be canonical JSON");
  }
  const program = record(parsed, "Safe-IR candidate");
  if (Object.keys(program).sort().join(",") !== "negative_pipeline,positive_pipeline,schema" || program.schema !== SAFE_IR_SCHEMA) {
    throw new Error("Safe-IR candidate fields or schema are unsupported");
  }
  if (canonicalArenaJson(program) !== source) {
    throw new Error("Safe-IR candidate must use canonical JSON encoding");
  }
  for (const key of ["positive_pipeline", "negative_pipeline"] as const) {
    const pipeline = program[key];
    if (!Array.isArray(pipeline) || pipeline.length > SAFE_IR_MAX_INSTRUCTIONS) {
      throw new Error("Safe-IR pipeline exceeds its instruction limit");
    }
    for (const value of pipeline) {
      const instruction = record(value, "Safe-IR instruction");
      const opcode = instruction.op;
      const fields = typeof opcode === "string" ? SAFE_IR_FIELDS[opcode] : undefined;
      if (!fields || Object.keys(instruction).sort().join(",") !== [...fields].sort().join(",")) {
        throw new Error("Safe-IR opcode or instruction fields are unsupported");
      }
      if (opcode === "trim") {
        safeIrInteger(instruction.low, 0, 64);
        safeIrInteger(instruction.high, 0, 64);
      } else if (opcode === "mad_filter") {
        safeIrInteger(instruction.threshold_milli, 100, 10_000);
      } else if (opcode === "head" || opcode === "tail") {
        safeIrInteger(instruction.count, 2, 512);
      } else if (opcode === "stride") {
        const step = safeIrInteger(instruction.step, 1, 16);
        const offset = safeIrInteger(instruction.offset, 0, 15);
        if (offset >= step) throw new Error("Safe-IR stride offset must be below step");
      }
    }
  }
}

async function sha256Hex(value: Uint8Array): Promise<string> {
  return hexFromBytes(await crypto.subtle.digest("SHA-256", arrayBuffer(value)));
}

async function sha256Commitment(value: Uint8Array): Promise<`sha256:${string}`> {
  return `sha256:${await sha256Hex(value)}`;
}

function canonicalBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalArenaJson(value));
}

export async function arenaSubmissionManifestHash(manifest: ArenaSubmissionManifest): Promise<`sha256:${string}`> {
  return sha256Commitment(canonicalBytes({
    schema_version: manifest.schema_version,
    challenge_manifest_hash: manifest.challenge_manifest_hash,
    candidate_kind: manifest.candidate_kind,
    runtime: manifest.runtime,
    entrypoint: manifest.entrypoint,
    mode: manifest.mode,
    private_size_egress: false,
  }));
}

async function publicIdentityHash(prefix: "arena_public_wallet" | "arena_public_project", value: string): Promise<string> {
  const domain = encoder.encode(prefix);
  const separator = new Uint8Array([0]);
  const json = canonicalBytes(value);
  const input = concatenate(domain, separator, json);
  try {
    return await sha256Hex(input);
  } finally {
    domain.fill(0);
    json.fill(0);
    input.fill(0);
  }
}

export async function arenaProtocolIdentity(walletAddress: string, projectId: string): Promise<ArenaProtocolIdentity> {
  const normalized = walletAddress.toLowerCase();
  if (!WALLET_ADDRESS.test(normalized)) throw new Error("Arena identity requires a 20-byte wallet address");
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(projectId)) throw new Error("Arena personal project identifier is malformed");
  const [walletHash, projectHash] = await Promise.all([
    publicIdentityHash("arena_public_wallet", normalized),
    publicIdentityHash("arena_public_project", projectId),
  ]);
  return { wallet_address_hash: walletHash, project_id_hash: projectHash };
}

export async function arenaPersonalProjectId(walletAddress: string): Promise<string> {
  const normalized = walletAddress.toLowerCase();
  if (!WALLET_ADDRESS.test(normalized)) throw new Error("Arena identity requires a 20-byte wallet address");
  return `personal-${(await sha256Hex(encoder.encode(`arena-personal-project:${normalized}`))).slice(0, 32)}`;
}

export async function arenaIdempotencyKeyHash(
  challengeId: string,
  challengeVersion: string,
  identity: ArenaProtocolIdentity,
  idempotencyKey: string,
): Promise<`sha256:${string}`> {
  if (!IDEMPOTENCY_KEY.test(idempotencyKey) || encoder.encode(idempotencyKey).byteLength > 128) throw new Error("Arena Idempotency-Key is malformed");
  return sha256Commitment(canonicalBytes({
    challenge_id: challengeId,
    challenge_version: challengeVersion,
    identity,
    idempotency_key: idempotencyKey,
  }));
}

export function arenaCandidateAad(binding: ArenaCandidateBinding): Uint8Array {
  const bytes = canonicalBytes(binding);
  if (bytes.length > 4_096) throw new Error("Arena candidate AAD exceeds the protocol bound");
  return bytes;
}

export function newArenaIdempotencyKey(): string {
  return `arena-${crypto.randomUUID()}`;
}

function parseArenaAttestation(value: unknown): ArenaAttestation {
  const item = exactRecord(value, ["mode", "quote", "encryption_public_key", "report_context", "report_data", "quote_report_data", "app_id", "compose_hash", "os_image_hash", "verified"], "Arena attestation");
  if (
    item.mode !== "tdx"
    || item.report_context !== "arena"
    || item.verified !== false
    || typeof item.quote !== "string"
    || typeof item.encryption_public_key !== "string"
    || typeof item.report_data !== "string"
    || typeof item.quote_report_data !== "string"
    || typeof item.app_id !== "string"
    || typeof item.compose_hash !== "string"
    || typeof item.os_image_hash !== "string"
  ) throw new Error("Arena attestation is not a fail-closed TDX envelope");
  bytesFromHex(item.encryption_public_key, 32).fill(0);
  bytesFromHex(item.report_data, 32).fill(0);
  return item as unknown as ArenaAttestation;
}

export function parseArenaEncryptionContract(value: unknown): ArenaEncryptionContract {
  const contract = exactRecord(value, ["surface", "schema_version", "product_status", "execution_assurance", "protocol", "encoding_rules", "aad", "recipient", "limits", "submission_gate", "envelope_exact_fields", "raw_secret_egress"], "Arena encryption contract");
  if (
    contract.surface !== "arena_candidate_browser_encryption_contract"
    || contract.schema_version !== 1
    || contract.product_status !== MODELED_STATUS
    || contract.execution_assurance !== MODELED_ASSURANCE
    || contract.raw_secret_egress !== false
  ) throw new Error("Arena encryption contract made an unsupported assurance claim");

  const protocol = exactRecord(contract.protocol, ["algorithm", "encoding", "x25519_public_key_bytes", "hkdf", "aes_gcm"], "Arena encryption protocol");
  const hkdf = exactRecord(protocol.hkdf, ["hash", "length_bytes", "salt", "info_utf8"], "Arena HKDF contract");
  const aes = exactRecord(protocol.aes_gcm, ["key_bits", "nonce_bytes", "tag_bytes", "additional_authenticated_data"], "Arena AES-GCM contract");
  if (
    protocol.algorithm !== "X25519-HKDF-SHA256-AES-256-GCM"
    || protocol.encoding !== "base64url-nopad"
    || protocol.x25519_public_key_bytes !== 32
    || hkdf.hash !== "SHA-256"
    || hkdf.length_bytes !== 32
    || hkdf.salt !== "SHA-256(canonical_aad_bytes)"
    || hkdf.info_utf8 !== HKDF_INFO
    || aes.key_bits !== 256
    || aes.nonce_bytes !== 12
    || aes.tag_bytes !== 16
    || aes.additional_authenticated_data !== "canonical_aad_bytes"
  ) throw new Error("Arena encryption algorithm contract is unsupported");

  const encoding = exactRecord(contract.encoding_rules, ["binary_fields", "canonical_json"], "Arena encoding rules");
  if (
    encoding.binary_fields !== "RFC4648 base64url without equals padding"
    || encoding.canonical_json !== "UTF-8 JSON; lexicographically sorted keys; comma and colon separators; ensure_ascii=true; allow_nan=false; no whitespace"
  ) throw new Error("Arena encoding contract is unsupported");

  const aad = exactRecord(contract.aad, ["service", "context", "schema_version", "exact_fields", "hash_formulas", "identity_derivation"], "Arena AAD contract");
  if (aad.service !== "dnai-wikigen" || aad.context !== "arena_candidate_ingress" || aad.schema_version !== 1) throw new Error("Arena AAD context is unsupported");
  exactStringArray(aad.exact_fields, AAD_FIELDS, "Arena AAD fields");
  exactRecord(aad.hash_formulas, ["challenge_manifest_hash", "submission_manifest_hash", "candidate_commitment", "identity.wallet_address_hash", "identity.project_id_hash", "idempotency_key_hash", "key_id", "attestation_report_data_sha256"], "Arena AAD hash formulas");
  exactRecord(aad.identity_derivation, ["wallet_address", "project_id"], "Arena identity derivation");

  const recipient = exactRecord(contract.recipient, ["encryption_public_key", "key_id", "report_context", "report_data", "attestation_report_data_sha256", "report_data_contract"], "Arena recipient");
  const reportContract = exactRecord(recipient.report_data_contract, ["hash", "canonical_json"], "Arena report-data contract");
  const reportObject = exactRecord(reportContract.canonical_json, ["context", "encryption_public_key", "key_id", "protocol", "service"], "Arena report-data object");
  if (
    typeof recipient.encryption_public_key !== "string"
    || typeof recipient.key_id !== "string"
    || typeof recipient.report_data !== "string"
    || typeof recipient.attestation_report_data_sha256 !== "string"
    || recipient.report_context !== "arena"
    || reportContract.hash !== "SHA-256"
    || reportObject.context !== "arena"
    || reportObject.encryption_public_key !== recipient.encryption_public_key
    || reportObject.key_id !== recipient.key_id
    || reportObject.protocol !== "arena_candidate_ingress_v1"
    || reportObject.service !== "dnai-wikigen"
    || !SHA256_COMMITMENT.test(recipient.key_id)
    || !SHA256_COMMITMENT.test(recipient.attestation_report_data_sha256)
  ) throw new Error("Arena recipient report-data contract is malformed");
  bytesFromHex(recipient.encryption_public_key, 32).fill(0);
  bytesFromHex(recipient.report_data, 32).fill(0);

  const limits = exactRecord(contract.limits, ["max_aad_bytes", "max_ciphertext_bytes_including_gcm_tag", "max_plaintext_bytes_from_cipher_limit", "max_envelopes_per_store", "idempotency_key_max_bytes"], "Arena encryption limits");
  if (
    limits.max_aad_bytes !== 4_096
    || limits.max_ciphertext_bytes_including_gcm_tag !== 65_536
    || limits.max_plaintext_bytes_from_cipher_limit !== 65_520
    || limits.idempotency_key_max_bytes !== 128
  ) throw new Error("Arena encryption limits do not match the reviewed protocol");
  integer(limits.max_envelopes_per_store, "Arena envelope capacity", 1, 10_000);

  const gate = exactRecord(contract.submission_gate, ["fresh_cvm_attestation_required", "independent_quote_and_measurement_verification_required", "matching_current_recipient_key_required", "matching_report_data_binding_required", "api_verified_field_is_not_a_policy_verdict", "server_generated_sealed_reference", "plaintext_candidate_accepted", "hostile_code_execution_enabled"], "Arena submission gate");
  if (
    gate.fresh_cvm_attestation_required !== true
    || gate.independent_quote_and_measurement_verification_required !== true
    || gate.matching_current_recipient_key_required !== true
    || gate.matching_report_data_binding_required !== true
    || gate.api_verified_field_is_not_a_policy_verdict !== true
    || gate.server_generated_sealed_reference !== true
    || gate.plaintext_candidate_accepted !== false
    || gate.hostile_code_execution_enabled !== false
  ) throw new Error("Arena submission gate is not fail closed");
  exactStringArray(contract.envelope_exact_fields, ENVELOPE_FIELDS, "Arena envelope fields");
  return { recipient, limits } as unknown as ArenaEncryptionContract;
}

async function quoteDigest(quote: string): Promise<`sha256:${string}`> {
  const bytes = bytesFromHex(quote);
  if (bytes.length < 632 || bytes.length > 16 * 1024) {
    bytes.fill(0);
    throw new Error("Arena TDX quote length is outside the approved bound");
  }
  try {
    return sha256Commitment(bytes);
  } finally {
    bytes.fill(0);
  }
}

async function verifiedArenaRecipient(): Promise<{ contract: ArenaEncryptionContract; attestation: ArenaAttestation; quoteDigest: `sha256:${string}` }> {
  if (!deployment.arenaSubmissionEnabled) throw new Error("Arena submissions are disabled until the fresh CVM is independently verified");
  if (!SHA256_COMMITMENT.test(deployment.arenaVerifiedQuoteSha256)) throw new Error("No independently verified Arena quote is pinned in this build");
  if (!deployment.composeHash) throw new Error("No approved CVM compose hash is pinned in this build");
  const noCache: RequestInit = {
    cache: "no-store",
    credentials: "omit",
    headers: { "Cache-Control": "no-cache, no-store", Pragma: "no-cache" },
  };
  const [attestationValue, contractValue] = await Promise.all([
    boundedJson("/attestation?context=arena", noCache, false),
    boundedJson("/arena/candidate-encryption-contract", noCache, false),
  ]);
  const attestation = parseArenaAttestation(attestationValue);
  const contract = parseArenaEncryptionContract(contractValue);
  const digest = await quoteDigest(attestation.quote);
  if (digest !== deployment.arenaVerifiedQuoteSha256) throw new Error("Arena quote does not match the independently verified quote pin");
  if (attestation.compose_hash !== deployment.composeHash) throw new Error("Arena compose hash does not match the approved frontend manifest");
  if (deployment.appId && attestation.app_id !== deployment.appId) throw new Error("Arena app identity does not match the approved frontend manifest");
  if (deployment.osImageHash && attestation.os_image_hash !== deployment.osImageHash) throw new Error("Arena OS image does not match the approved frontend manifest");
  if (
    contract.recipient.encryption_public_key !== attestation.encryption_public_key
    || contract.recipient.report_context !== attestation.report_context
    || contract.recipient.report_data !== attestation.report_data
  ) throw new Error("Arena attestation and current encryption recipient do not match");

  const publicKey = bytesFromHex(attestation.encryption_public_key, 32);
  const reportData = bytesFromHex(attestation.report_data, 32);
  const expectedKeyId = await sha256Commitment(publicKey);
  const expectedReportObject = {
    context: "arena",
    encryption_public_key: attestation.encryption_public_key,
    key_id: expectedKeyId,
    protocol: "arena_candidate_ingress_v1",
    service: "dnai-wikigen",
  };
  const expectedReportData = await sha256Hex(canonicalBytes(expectedReportObject));
  const expectedReportHash = await sha256Commitment(reportData);
  try {
    if (
      contract.recipient.key_id !== expectedKeyId
      || contract.recipient.report_data !== expectedReportData
      || contract.recipient.attestation_report_data_sha256 !== expectedReportHash
    ) throw new Error("Arena recipient is not bound to its versioned report-data contract");
    const quoteReportData = bytesFromHex(attestation.quote_report_data);
    try {
      if (
        (quoteReportData.length !== 32 && quoteReportData.length !== 64)
        || hexFromBytes(quoteReportData.slice(0, 32)) !== attestation.report_data
        || (quoteReportData.length === 64 && quoteReportData.slice(32).some((byte) => byte !== 0))
      ) throw new Error("Arena quote report data does not match the recipient binding");
    } finally {
      quoteReportData.fill(0);
    }
  } finally {
    publicKey.fill(0);
    reportData.fill(0);
  }
  return { contract, attestation, quoteDigest: digest };
}

export interface ArenaEncryptionTestOptions {
  ephemeralPrivateKey?: CryptoKey;
  ephemeralPublicKey?: CryptoKey;
  nonce?: Uint8Array;
}

export async function encryptArenaCandidateBytes(
  source: Uint8Array,
  recipientPublicKeyHex: string,
  aad: Uint8Array,
  options: ArenaEncryptionTestOptions = {},
): Promise<{ ephemeralPublicKey: string; nonce: string; ciphertext: string; ciphertextBytes: number; ciphertextSha256: `sha256:${string}` }> {
  if (source.length < 1 || source.length > 65_520) throw new Error("Arena candidate is outside the ciphertext capacity");
  if (aad.length < 1 || aad.length > 4_096) throw new Error("Arena AAD is outside its approved bound");
  const recipientBytes = bytesFromHex(recipientPublicKeyHex, 32);
  const recipient = await crypto.subtle.importKey("raw", arrayBuffer(recipientBytes), { name: "X25519" }, false, []);
  const generated = options.ephemeralPrivateKey
    ? undefined
    : await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]) as CryptoKeyPair;
  const ephemeralPrivate = options.ephemeralPrivateKey ?? generated?.privateKey;
  const ephemeralPublicKey = options.ephemeralPublicKey ?? generated?.publicKey;
  if (!ephemeralPrivate) throw new Error("Arena ephemeral key generation failed");
  if (!ephemeralPublicKey) throw new Error("Arena deterministic encryption requires the matching ephemeral public key");
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: recipient }, ephemeralPrivate, 256));
  const salt = new Uint8Array(await crypto.subtle.digest("SHA-256", arrayBuffer(aad)));
  const hkdf = await crypto.subtle.importKey("raw", arrayBuffer(sharedSecret), "HKDF", false, ["deriveKey"]);
  const info = encoder.encode(HKDF_INFO);
  const aes = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: arrayBuffer(salt), info: arrayBuffer(info) },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const nonce = options.nonce?.slice() ?? crypto.getRandomValues(new Uint8Array(12));
  if (nonce.length !== 12) throw new Error("Arena AES-GCM nonce must be 12 bytes");
  try {
    const ciphertextBytes = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: arrayBuffer(nonce), additionalData: arrayBuffer(aad), tagLength: 128 },
      aes,
      arrayBuffer(source),
    ));
    if (ciphertextBytes.length !== source.length + 16 || ciphertextBytes.length > 65_536) throw new Error("Arena ciphertext length violates the protocol");
    const ephemeralPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeralPublicKey));
    try {
      return {
        ephemeralPublicKey: base64url(ephemeralPublic),
        nonce: base64url(nonce),
        ciphertext: base64url(ciphertextBytes),
        ciphertextBytes: ciphertextBytes.length,
        ciphertextSha256: await sha256Commitment(ciphertextBytes),
      };
    } finally {
      ephemeralPublic.fill(0);
      ciphertextBytes.fill(0);
    }
  } finally {
    recipientBytes.fill(0);
    sharedSecret.fill(0);
    salt.fill(0);
    info.fill(0);
    nonce.fill(0);
  }
}

export async function prepareArenaSubmission(input: {
  source: Uint8Array;
  challenge: ArenaChallengeManifest;
  walletAddress: string;
  idempotencyKey?: string;
}): Promise<PreparedArenaSubmission> {
  const { source, challenge } = input;
  if (!CHALLENGE_ID.test(challenge.challenge_id) || !SEMVER.test(challenge.version) || !HEX_64.test(challenge.manifest_hash)) throw new Error("Arena challenge identity is malformed");
  if (source.length < 1 || source.length > challenge.candidate.max_source_bytes || source.length > 65_520) throw new Error("Program exceeds the selected challenge source limit");
  const candidateKind = boundedAscii(challenge.candidate.kind, "Arena candidate kind", 64);
  const runtime = boundedAscii(challenge.candidate.runtime, "Arena runtime", 64);
  const entrypoint = boundedAscii(challenge.candidate.entrypoint, "Arena entrypoint", 64);
  const idempotencyKey = input.idempotencyKey ?? newArenaIdempotencyKey();
  if (!IDEMPOTENCY_KEY.test(idempotencyKey) || encoder.encode(idempotencyKey).byteLength > 128) throw new Error("Arena Idempotency-Key is malformed");

  const [verified, registryBrowserPreflight, commitment, projectId] = await Promise.all([
    verifiedArenaRecipient(),
    runArenaChallengeRegistryBrowserPreflight(challenge),
    candidateCommitment(source),
    arenaPersonalProjectId(input.walletAddress),
  ]);
  const identity = await arenaProtocolIdentity(input.walletAddress, projectId);
  const registryAuthorization = arenaChallengeRegistryAuthorizationSnapshot(
    registryBrowserPreflight,
  );
  const registryAuthorizationSha256 = (
    await arenaChallengeRegistryAuthorizationSha256(registryAuthorization)
  );
  const manifest: ArenaSubmissionManifest = {
    schema_version: 1,
    challenge_manifest_hash: challenge.manifest_hash,
    candidate_kind: candidateKind,
    runtime,
    entrypoint,
    source_bytes: source.length,
    mode: "leaderboard",
  };
  const binding: ArenaCandidateBinding = {
    service: "dnai-wikigen",
    context: "arena_candidate_ingress",
    schema_version: 1,
    challenge_id: challenge.challenge_id,
    challenge_version: challenge.version,
    challenge_manifest_hash: challenge.manifest_hash,
    submission_manifest_hash: await arenaSubmissionManifestHash(manifest),
    candidate_commitment: commitment,
    identity,
    idempotency_key_hash: await arenaIdempotencyKeyHash(challenge.challenge_id, challenge.version, identity, idempotencyKey),
    key_id: verified.contract.recipient.key_id,
    attestation_report_data_sha256: verified.contract.recipient.attestation_report_data_sha256,
    registry_authorization_sha256: registryAuthorizationSha256,
  };
  const aad = arenaCandidateAad(binding);
  try {
    if (aad.length > verified.contract.limits.max_aad_bytes) throw new Error("Arena AAD exceeds the live contract limit");
    const encrypted = await encryptArenaCandidateBytes(source, verified.contract.recipient.encryption_public_key, aad);
    if (encrypted.ciphertextBytes > verified.contract.limits.max_ciphertext_bytes_including_gcm_tag) throw new Error("Arena ciphertext exceeds the live contract limit");
    return {
      challengeId: challenge.challenge_id,
      challengeVersion: challenge.version,
      walletAddress: input.walletAddress.toLowerCase(),
      idempotencyKey,
      candidateCommitment: commitment,
      sourceBytes: source.length,
      ciphertextSha256: encrypted.ciphertextSha256,
      keyId: verified.contract.recipient.key_id,
      quoteDigest: verified.quoteDigest,
      registryBrowserPreflight,
      payload: {
        candidate_commitment: commitment,
        manifest,
        registry_authorization: registryAuthorization,
        envelope: {
          schema_version: 1,
          algorithm: "X25519-HKDF-SHA256-AES-256-GCM",
          encoding: "base64url-nopad",
          key_id: verified.contract.recipient.key_id,
          attestation_report_data: verified.attestation.report_data,
          aad: base64url(aad),
          ephemeral_public_key: encrypted.ephemeralPublicKey,
          nonce: encrypted.nonce,
          ciphertext: encrypted.ciphertext,
        },
      },
    };
  } finally {
    aad.fill(0);
  }
}

function sameArenaChallengeRegistryBrowserPreflight(
  prepared: ArenaChallengeRegistryBrowserPreflight,
  current: ArenaChallengeRegistryBrowserPreflight,
): boolean {
  return prepared.status === current.status
    && prepared.verificationScope === current.verificationScope
    && prepared.proxyIndependentlyVerified === current.proxyIndependentlyVerified
    && prepared.workerAuthorized === current.workerAuthorized
    && prepared.chainId === current.chainId
    && current.verifiedBlockNumber >= prepared.verifiedBlockNumber
    && prepared.registryAddress === current.registryAddress
    && prepared.registryCodeHash === current.registryCodeHash
    && prepared.approvedChallengeSetSha256 === current.approvedChallengeSetSha256
    && prepared.registryChallengeId === current.registryChallengeId
    && prepared.registryVersion === current.registryVersion
    && prepared.controllerAddress === current.controllerAddress
    && prepared.pendingControllerAddress === current.pendingControllerAddress
    && prepared.catalogChallengeId === current.catalogChallengeId
    && prepared.catalogChallengeVersion === current.catalogChallengeVersion
    && prepared.catalogManifestHash === current.catalogManifestHash
    && prepared.metadataURI === current.metadataURI
    && prepared.metadataHash === current.metadataHash
    && prepared.sealedArtifactCommitment === current.sealedArtifactCommitment
    && prepared.evaluatorCommitment === current.evaluatorCommitment
    && prepared.releasePolicyCommitment === current.releasePolicyCommitment
    && prepared.registryPaused === current.registryPaused
    && prepared.challengePaused === current.challengePaused
    && prepared.lifecycle === current.lifecycle
    && prepared.configurationFrozen === current.configurationFrozen
    && prepared.latestVersion === current.latestVersion;
}

export function parseArenaSubmissionResult(value: unknown): ArenaSubmissionResult {
  assertNoForbiddenArenaFields(value);
  const result = exactRecord(value, ["surface", "created", "idempotent_replay", "registry_ingress_boundary", "candidate_ingress", "submission", "raw_candidate_accepted", "encrypted_reference_egress", "raw_secret_egress"], "Arena submission result");
  if (
    result.surface !== "arena_submission_result"
    || typeof result.created !== "boolean"
    || result.idempotent_replay !== !result.created
    || result.raw_candidate_accepted !== false
    || result.encrypted_reference_egress !== false
    || result.raw_secret_egress !== false
  ) throw new Error("Arena submission response violated the bounded boundary");
  const registryBoundary = exactRecord(result.registry_ingress_boundary, [
    "surface", "schema_version", "status", "verification_model",
    "browser_preflight_accepted_as_authority", "proxy_registry_authorized",
    "worker_registry_authorized", "registry_authorization_sha256", "chain_id",
    "block_number", "block_hash", "registry_address", "registry_challenge_id",
    "registry_version", "independent_rpc_quorum_verified", "consensus_proof_verified",
  ], "Arena registry ingress boundary");
  if (
    registryBoundary.surface !== "arena_registry_ingress_boundary"
    || registryBoundary.schema_version !== 1
    || registryBoundary.status !== "proxy_independently_verified_at_finalized_block"
    || registryBoundary.verification_model !== "single_rpc_reported_finalized_pinned_block"
    || registryBoundary.browser_preflight_accepted_as_authority !== false
    || registryBoundary.proxy_registry_authorized !== true
    || registryBoundary.worker_registry_authorized !== false
    || typeof registryBoundary.registry_authorization_sha256 !== "string"
    || !SHA256_COMMITMENT.test(registryBoundary.registry_authorization_sha256)
    || registryBoundary.chain_id !== BASE_SEPOLIA.id
    || typeof registryBoundary.block_number !== "string"
    || !/^[1-9][0-9]*$/.test(registryBoundary.block_number)
    || typeof registryBoundary.block_hash !== "string"
    || !BYTES32.test(registryBoundary.block_hash)
    || typeof registryBoundary.registry_address !== "string"
    || !WALLET_ADDRESS.test(registryBoundary.registry_address)
    || typeof registryBoundary.registry_challenge_id !== "string"
    || !/^(0|[1-9][0-9]*)$/.test(registryBoundary.registry_challenge_id)
    || !Number.isInteger(registryBoundary.registry_version)
    || Number(registryBoundary.registry_version) < 1
    || registryBoundary.independent_rpc_quorum_verified !== false
    || registryBoundary.consensus_proof_verified !== false
  ) throw new Error("Arena registry ingress boundary made an unsupported authorization claim");
  const ingress = exactRecord(result.candidate_ingress, ["surface", "schema_version", "blob_sha256", "ciphertext_sha256", "key_id", "created", "idempotent_replay", "sealed_reference_public", "plaintext_candidate_accepted", "product_status", "execution_assurance", "raw_secret_egress", "private_size_egress"], "Arena ingress receipt");
  if (
    ingress.surface !== "arena_candidate_ingress_receipt"
    || ingress.schema_version !== 1
    || !SHA256_COMMITMENT.test(String(ingress.blob_sha256))
    || !SHA256_COMMITMENT.test(String(ingress.ciphertext_sha256))
    || !SHA256_COMMITMENT.test(String(ingress.key_id))
    || typeof ingress.created !== "boolean"
    || ingress.idempotent_replay !== !ingress.created
    || ingress.sealed_reference_public !== false
    || ingress.plaintext_candidate_accepted !== false
    || ingress.product_status !== MODELED_STATUS
    || ingress.execution_assurance !== MODELED_ASSURANCE
    || ingress.raw_secret_egress !== false
    || ingress.private_size_egress !== false
  ) throw new Error("Arena ingress receipt violated the ciphertext-only boundary");
  const submission = parsePublicSubmission(result.submission, "Arena public submission");
  if (
    submission.product_status !== MODELED_STATUS
    || submission.execution_assurance !== MODELED_ASSURANCE
    || submission.execution_provenance.status !== "not_executed"
  ) throw new Error("Arena public submission receipt is malformed");
  const publicManifest = exactRecord(submission.manifest, ["schema_version", "challenge_manifest_hash", "candidate_kind", "runtime", "entrypoint", "mode", "private_size_egress"], "Arena public submission manifest");
  if (
    publicManifest.schema_version !== 1
    || !HEX_64.test(String(publicManifest.challenge_manifest_hash))
    || typeof publicManifest.candidate_kind !== "string"
    || typeof publicManifest.runtime !== "string"
    || typeof publicManifest.entrypoint !== "string"
    || publicManifest.mode !== "leaderboard"
    || publicManifest.private_size_egress !== false
  ) throw new Error("Arena public submission manifest exposed unsupported metadata");
  return value as ArenaSubmissionResult;
}

export async function submitPreparedArenaSubmission(
  prepared: PreparedArenaSubmission,
  accessToken: string,
  challenge: ArenaChallengeManifest,
): Promise<ArenaSubmissionResult> {
  if (!deployment.arenaSubmissionEnabled) throw new Error("Arena submissions are disabled until the fresh CVM is independently verified");
  if (typeof accessToken !== "string" || accessToken.length < 80 || accessToken.length > 4_096) throw new Error("Arena wallet token is malformed");
  if (!CHALLENGE_ID.test(prepared.challengeId) || !SEMVER.test(prepared.challengeVersion) || !IDEMPOTENCY_KEY.test(prepared.idempotencyKey)) throw new Error("Prepared Arena submission identity is malformed");
  if (
    challenge.challenge_id !== prepared.challengeId
    || challenge.version !== prepared.challengeVersion
    || challenge.manifest_hash !== prepared.payload.manifest.challenge_manifest_hash
    || !prepared.registryBrowserPreflight
  ) throw new Error("Prepared Arena submission does not match the selected challenge manifest");
  const currentRegistryPreflight = await runArenaChallengeRegistryBrowserPreflight(challenge);
  if (!sameArenaChallengeRegistryBrowserPreflight(prepared.registryBrowserPreflight, currentRegistryPreflight)) {
    throw new Error("Arena ChallengeRegistry browser preflight changed after candidate encryption");
  }
  const response = await boundedJson(
    `/arena/challenges/${encodeURIComponent(prepared.challengeId)}/versions/${encodeURIComponent(prepared.challengeVersion)}/submissions`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "Idempotency-Key": prepared.idempotencyKey,
      },
      body: JSON.stringify(prepared.payload),
      signal: AbortSignal.timeout(45_000),
    },
    true,
  );
  const result = parseArenaSubmissionResult(response);
  if (
    result.submission.challenge_id !== prepared.challengeId
    || result.submission.challenge_version !== prepared.challengeVersion
    || result.submission.candidate_commitment !== prepared.candidateCommitment
    || result.candidate_ingress.key_id !== prepared.keyId
    || result.candidate_ingress.ciphertext_sha256 !== prepared.ciphertextSha256
    || result.registry_ingress_boundary.registry_authorization_sha256
      !== await arenaChallengeRegistryAuthorizationSha256(
        prepared.payload.registry_authorization,
      )
    || result.registry_ingress_boundary.block_number
      !== prepared.payload.registry_authorization.block_number
    || result.registry_ingress_boundary.block_hash
      !== prepared.payload.registry_authorization.block_hash
    || result.registry_ingress_boundary.registry_address
      !== prepared.payload.registry_authorization.registry_address
  ) throw new Error("Arena submission receipt does not match the encrypted request");
  return result;
}
