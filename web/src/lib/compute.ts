import { deployment } from "../config";
import { sha256 } from "viem";
import { computeVaultJobId, computeVaultProjectId } from "./computeVault";
import {
  canonicalComputeJson,
  computeDispatchIntentCommitment,
} from "./computeDispatchCommitment";
import { publicErrorText } from "./errorText";

export {
  computeDispatchIntentCommitment,
  type ComputeDispatchIntentCommitmentFields,
} from "./computeDispatchCommitment";

const MAX_RESPONSE_BYTES = 512 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const RESOURCE_ID = /^[a-z][a-z0-9_]{2,63}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const NONZERO_BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const COMPUTE_REFERENCE = /^(?:0x(?!0{64}$)[0-9a-fA-F]{64}|[A-Za-z0-9][A-Za-z0-9._:-]{0,127})$/;
const DECIMAL_UINT256 = /^(?:0|[1-9][0-9]{0,77})$/;
const MAX_UINT256 = (1n << 256n) - 1n;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const WORKLOAD_ID = /^wrk_[0-9a-f]{32}$/;
const DISPATCH_MUTATION_ROUTE = "/compute/projects/{project_id}/dispatch-intents";
const DISPATCH_STATUS_ROUTE = "/compute/projects/{project_id}/dispatch-intents/{job_reference}";
const COMPILED_RECIPE_POLICY_DOMAIN = "dnai-wikigen/compute-compiled-recipe/v1\0";
const EXECUTION_POLICY_CONTEXT_DOMAIN = "dnai-wikigen/compute-execution-policy-context/v1\0";
const SUPPORTED_SCOPES = new Set([
  "jobs:create",
  "jobs:read",
  "workloads:create",
  "workloads:delete",
  "challenge:submit",
  "submissions:read",
  "receipts:read",
]);

export type ProjectRole = "owner" | "admin" | "developer" | "viewer";
export type DeviceKind = "developer_device" | "ci_service" | "autonomous_agent";
export type ComputeScope = "jobs:create" | "jobs:read" | "workloads:create" | "workloads:delete" | "challenge:submit" | "submissions:read" | "receipts:read";
export const COMPUTE_PUBLIC_CREDENTIAL_SCOPES = ["jobs:create", "jobs:read", "workloads:create", "workloads:delete"] as const satisfies readonly ComputeScope[];
export type ComputeJobStatus = "queued" | "running" | "succeeded" | "failed" | "canceled";
export type ComputeDispatchStage =
  | "intent_created"
  | "start_prepared"
  | "start_broadcast"
  | "start_confirmed"
  | "provider_dispatching"
  | "usage_finalized"
  | "metering_pending"
  | "metering_decided"
  | "settlement_prepared"
  | "settlement_broadcast"
  | "settled"
  | "blocked";

export interface ComputeDispatchCapability {
  metadata_intent_creation: boolean;
  provider_dispatch: boolean;
  independent_metering: boolean;
  settlement: boolean;
  exact_asset_only: true;
  mutation_route: typeof DISPATCH_MUTATION_ROUTE | null;
  status_route_template: typeof DISPATCH_STATUS_ROUTE;
  reason: string;
}

export interface ComputeFundingCapabilities {
  surface: "compute_funding_capabilities";
  schema_version: 1;
  card: { enabled: false; mutation_route: null; reason: string; card_data_accepted: false; distinct_from_exact_asset_capacity: true };
  usdc: { enabled: false; mutation_route: null; reason: string; capacity_model: "same_asset_nontransferable_vault_claim" };
  eth: { enabled: false; mutation_route: null; reason: string; capacity_model: "same_asset_nontransferable_vault_claim" };
  exact_asset_vault: {
    contract: "ComputeCreditVault";
    release_bound: true;
    review_status: "reviewed_and_extensively_tested_not_formally_audited";
    provider_dispatch_authoritative: false;
  };
  dispatch_intents: ComputeDispatchCapability;
  operator_testnet_grants: { enabled: boolean; auth: "configured_runtime_bearer"; cash_value: false };
  credits: {
    kind: "closed_loop_service_credit";
    transferable: false;
    redeemable: false;
    onchain_token: false;
    nominal_usd_cents_per_credit: 1;
    legacy_modeled_ledger: true;
    distinct_from_exact_asset_vault: true;
  };
}

export interface ComputeProject {
  project_id: string;
  name: string;
  role: ProjectRole;
  policy: {
    per_job_max_credits: number;
    daily_project_max_credits: number;
    credential_max_ttl_seconds: number;
    allowed_operations: ["inference", "training"] | string[];
  };
  members: { address: string; role: ProjectRole }[];
  created_at: number;
  updated_at: number;
  credit_instrument: "closed_loop_nontransferable_service_credit";
  provider_dispatch_enabled: boolean;
}

export interface ComputeDispatchIntentStatus {
  surface: "compute_dispatch_intent";
  schema_version: 2;
  project_reference: string;
  job_reference: string;
  project_id: `0x${string}`;
  job_id: `0x${string}`;
  user: `0x${string}`;
  asset: `0x${string}`;
  authorization_nonce: bigint;
  max_asset_debit: bigint;
  authorization_expiry: number;
  rate_policy_commitment: `0x${string}`;
  compose_hash: `0x${string}`;
  operation: "inference" | "training";
  model: "qwen3_8b";
  recipe: "qwen3_8b_bounded" | "qwen3_8b_lora_r32";
  result_policy: "bounded_summary_receipt" | "score_band_hash";
  resource_limits: {
    max_prefill_tokens: number;
    max_sample_tokens: number;
    max_train_tokens: number;
  };
  workload_id: string;
  workload_schema: "dnai.compute.workload.inference.v1" | "dnai.compute.workload.sft-jsonl.v1";
  manifest_commitment: `0x${string}`;
  workload_commitment: `0x${string}`;
  intent_commitment: `0x${string}`;
  execution_policy_context_hash: string;
  stage: ComputeDispatchStage;
  provider_authoritative: false;
  legacy_credit_ledger_mutated: false;
  provider_dispatch_status: "not_started" | "may_have_started" | "usage_finalized";
  provider_dispatch_may_have_occurred: boolean;
  provider_usage_finalized: boolean;
  raw_prompt_accepted: false;
  raw_examples_accepted: false;
  arbitrary_program_accepted: false;
  exact_timing_egress: false;
}

export interface ComputeDispatchIntentInput {
  jobReference: string;
  workloadId: string;
  asset: string;
  authorizationNonce: bigint;
  maxAssetDebit: bigint;
  authorizationExpiry: number;
  ratePolicyCommitment: string;
  composeHash: string;
  operation: "inference" | "training";
  resultPolicy: "bounded_summary_receipt" | "score_band_hash";
  maxPrefillTokens: number;
  maxSampleTokens: number;
  maxTrainTokens: number;
}

export interface ComputeDispatchIntentResult {
  created: boolean;
  idempotentReplay: boolean;
  intent: ComputeDispatchIntentStatus;
}

export interface ComputeExecutionPolicyTarget {
  resourceId: `0x${string}`;
  executionContextHash: string;
  authorizedUser: `0x${string}`;
}

export interface ComputeDevice {
  device_id: string;
  project_id: string;
  label: string;
  kind: DeviceKind;
  public_key_hash: string;
  status: "active" | "revoked";
  registered_at: number;
  revoked_at: number | null;
  binding: "encrypted_delivery_only_not_hardware_attestation";
  public_key_returned: false;
}

export interface ComputeCredential {
  credential_id: string;
  project_id: string;
  device_id: string;
  name: string;
  prefix: string;
  scopes: ComputeScope[];
  daily_credit_cap: number;
  generation: number;
  status: "active" | "expired" | "revoked";
  issued_at: number;
  expires_at: number;
  last_used_at: number | null;
  rotated_at: number | null;
  revoked_at: number | null;
  plaintext_token_stored: false;
  upstream_tinker_key_exposed: false;
}

export interface ComputeBalance {
  surface: "compute_credit_balance";
  schema_version: 1;
  project_id: string;
  available_credits: number;
  reserved_credits: number;
  total_service_credits: number;
  unit: "service_credit";
  nominal_usd_cents_per_credit: 1;
  transferable: false;
  redeemable: false;
  onchain_token: false;
}

export interface ComputeLedgerTransaction {
  transaction_id: string;
  sequence: number;
  kind: "testnet_grant" | "operator_grant" | "job_reserve" | "job_settle" | "job_release" | "job_cancel";
  project_id: string;
  job_id: string | null;
  amount_credits: number;
  postings: { account: string; delta: number }[];
  authority: string;
  created_at: number;
  settlement_status: string;
  transaction_hash: string;
  previous_hash: string;
}

export interface ComputeLedger {
  surface: "compute_ledger";
  schema_version: 1;
  project_id: string;
  balance: ComputeBalance;
  transactions: ComputeLedgerTransaction[];
  append_only: true;
  double_entry: true;
  currency: "service_credit";
  transferable: false;
  redeemable: false;
}

export interface ComputeJob {
  job_id: string;
  project_id: string;
  name: string;
  operation: "inference" | "training";
  model: "qwen3_8b";
  recipe: "qwen3_8b_bounded" | "qwen3_8b_lora_r32";
  max_credits: number;
  actual_credits: number | null;
  released_credits: number | null;
  result_policy: "bounded_summary_receipt" | "score_band_hash";
  environment_version: string;
  status: ComputeJobStatus;
  dispatch_status: "not_dispatched";
  backend_capability: "existing_tinker_training_proxy" | "future_inference_proxy";
  credential_id: string | null;
  created_at: number;
  updated_at: number;
  started_at: number | null;
  completed_at: number | null;
  metering_source: string | null;
  usage_receipt_hash: string | null;
  settlement_authority: string | null;
  provider_authoritative_settlement: false;
  raw_input_persisted: false;
  raw_output_persisted: false;
}

export interface ComputeJobCancellationReceipt {
  surface: "compute_job_cancellation";
  schema_version: 1;
  project_id: string;
  job_id: string;
  status: "canceled";
  changed: boolean;
  idempotent_replay: boolean;
  released_credits: number;
  credit_reversal: "reserved_to_available";
  ledger: {
    transaction_id: string;
    sequence: number;
    kind: "job_cancel";
    transaction_hash: string;
    previous_hash: string;
    settlement_status: "user_canceled_before_dispatch";
  };
  provider_dispatch_performed: false;
  service_settlement_performed: false;
}

export interface DeviceKeyMaterial {
  publicKeyHex: string;
  privateKey: CryptoKey;
}

interface ComputeCapsule {
  delivery: "x25519_aes_256_gcm_envelope";
  encrypted_token: {
    ephemeral_public_key: string;
    nonce: string;
    ciphertext: string;
  };
  associated_data: string;
  associated_data_hash: string;
  recipient_public_key_hash: string;
  plaintext_token_returned: false;
}

export interface ComputeCredentialDelivery {
  credential: ComputeCredential;
  capsule: ComputeCapsule;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is not an object`);
  return value as Record<string, unknown>;
}

function integer(value: unknown, label: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`${label} is outside the supported range`);
  }
  return Number(value);
}

function text(value: unknown, label: string, maximum = 256): string {
  if (typeof value !== "string" || value.length < 1 || encoder.encode(value).byteLength > maximum) {
    throw new Error(`${label} is malformed`);
  }
  return value;
}

function exactKeys(value: Record<string, unknown>, label: string, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw new Error(`${label} contains unsupported fields`);
  }
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} is malformed`);
  return value;
}

export function parseDispatchUint256(value: unknown, label = "uint256"): bigint {
  const normalized = typeof value === "number"
    ? Number.isSafeInteger(value) && value >= 0 ? String(value) : ""
    : typeof value === "bigint"
      ? value >= 0n ? value.toString() : ""
      : typeof value === "string" ? value : "";
  if (!DECIMAL_UINT256.test(normalized)) throw new Error(`${label} is not a canonical uint256`);
  const parsed = BigInt(normalized);
  if (parsed > MAX_UINT256) throw new Error(`${label} exceeds uint256`);
  return parsed;
}

function computeCompiledRecipePolicyCommitment(
  operation: string,
  model: string,
  recipe: string,
): `0x${string}` {
  const policy = operation === "inference" && model === "qwen3_8b" && recipe === "qwen3_8b_bounded"
    ? {
        allowed_result_policies: ["bounded_summary_receipt", "score_band_hash"],
        arbitrary_program_api: false,
        max_prefill_tokens: 32_768,
        max_sample_tokens: 4_096,
        max_train_tokens: 0,
        model,
        operation,
        raw_examples_api: false,
        raw_prompt_api: false,
        recipe,
        schema: "dnai.compute.compiled-recipe-policy.v1",
      }
    : operation === "training" && model === "qwen3_8b" && recipe === "qwen3_8b_lora_r32"
      ? {
          allowed_result_policies: ["bounded_summary_receipt", "score_band_hash"],
          arbitrary_program_api: false,
          max_prefill_tokens: 0,
          max_sample_tokens: 0,
          max_train_tokens: 10_000_000,
          model,
          operation,
          raw_examples_api: false,
          raw_prompt_api: false,
          recipe,
          schema: "dnai.compute.compiled-recipe-policy.v1",
        }
      : undefined;
  if (!policy) throw new Error("Compute execution policy recipe is not release-pinned");
  return sha256(encoder.encode(
    `${COMPILED_RECIPE_POLICY_DOMAIN}${canonicalComputeJson(policy)}`,
  ));
}

export function computeExecutionPolicyContextHash(input: {
  jobId: `0x${string}`;
  intentCommitment: `0x${string}`;
  operation: string;
  model: string;
  recipe: string;
}): string {
  const payload = canonicalComputeJson({
    intent_commitment: input.intentCommitment,
    job_id: input.jobId,
    recipe_policy_commitment: computeCompiledRecipePolicyCommitment(
      input.operation,
      input.model,
      input.recipe,
    ),
    schema: "dnai.compute.execution-policy-context.v1",
  });
  return sha256(encoder.encode(`${EXECUTION_POLICY_CONTEXT_DOMAIN}${payload}`)).slice(2);
}

function parseJsonWithoutPrecisionLoss(raw: string): unknown {
  let index = 0;
  let transformed = "";
  while (index < raw.length) {
    if (raw[index] === '"') {
      const start = index;
      index += 1;
      let escaped = false;
      while (index < raw.length) {
        const character = raw[index];
        index += 1;
        if (escaped) {
          escaped = false;
        } else if (character === "\\") {
          escaped = true;
        } else if (character === '"') {
          break;
        }
      }
      transformed += raw.slice(start, index);
      continue;
    }
    const remainder = raw.slice(index);
    const numeric = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(remainder)?.[0];
    if (numeric) {
      if (!/[.eE]/.test(numeric)) {
        if (numeric.length > 80) {
          transformed += JSON.stringify(numeric);
          index += numeric.length;
          continue;
        }
        try {
          const candidate = BigInt(numeric);
          if (candidate > BigInt(Number.MAX_SAFE_INTEGER) || candidate < BigInt(Number.MIN_SAFE_INTEGER)) {
            transformed += JSON.stringify(numeric);
            index += numeric.length;
            continue;
          }
        } catch {
          throw new Error("Compute service returned malformed JSON");
        }
      }
      transformed += numeric;
      index += numeric.length;
      continue;
    }
    transformed += raw[index];
    index += 1;
  }
  return JSON.parse(transformed);
}

function assertNoSensitiveFields(value: unknown): void {
  const forbidden = new Set([
    "card_number", "cvc", "cvv", "prompt", "prompts", "training_examples",
    "raw_input", "raw_output", "upstream_api_key", "upstream_tinker_key", "private_key",
    "plaintext_token", "wallet_signing_key", "runtime_bearer",
  ]);
  const pending: unknown[] = [value];
  let containers = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current || typeof current !== "object") continue;
    containers += 1;
    if (containers > 16_384) throw new Error("Compute response contains too many nested containers");
    if (Array.isArray(current)) {
      pending.push(...current);
      continue;
    }
    for (const [key, nested] of Object.entries(current as Record<string, unknown>)) {
      if (forbidden.has(key)) throw new Error(`Compute response contains forbidden field ${key}`);
      pending.push(nested);
    }
  }
}

async function readBoundedResponseText(response: Response): Promise<string> {
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error("Compute service did not return application/json");
  }
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new Error("Compute response exceeded the public size limit");
  }
  if (!response.body) throw new Error("Compute service returned an empty response");

  const reader = response.body.getReader();
  const streamDecoder = new TextDecoder("utf-8", { fatal: true });
  let body = "";
  let received = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("Compute response exceeded the public size limit");
      }
      body += streamDecoder.decode(value, { stream: true });
    }
    body += streamDecoder.decode();
    return body;
  } finally {
    reader.releaseLock();
  }
}

function baseUrl(): string {
  if (!deployment.delegateUrl) throw new Error("Fresh delegate endpoint is not configured");
  return deployment.delegateUrl.replace(/\/$/, "");
}

async function request(
  path: string,
  options: { method?: "GET" | "POST" | "DELETE"; token?: string; body?: unknown; idempotencyKey?: string; timeout?: number } = {},
): Promise<unknown> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.token) headers.Authorization = `Bearer ${options.token}`;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (options.idempotencyKey) headers["Idempotency-Key"] = options.idempotencyKey;
  const response = await fetch(`${baseUrl()}${path}`, {
    method: options.method ?? "GET",
    credentials: "omit",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal: AbortSignal.timeout(options.timeout ?? 12_000),
  });
  const raw = await readBoundedResponseText(response);
  let value: unknown;
  try {
    value = parseJsonWithoutPrecisionLoss(raw);
  } catch {
    throw new Error("Compute service returned malformed JSON");
  }
  if (!response.ok) {
    const body = value && typeof value === "object" && "detail" in value ? (value as { detail: unknown }).detail : undefined;
    const fallback = `Request failed with status ${response.status}`;
    throw new Error(publicErrorText(typeof body === "string" ? body : fallback, fallback));
  }
  assertNoSensitiveFields(value);
  return value;
}

function assertProject(value: unknown): asserts value is ComputeProject {
  const project = record(value, "Compute project");
  const policy = record(project.policy, "Compute project policy");
  if (
    !RESOURCE_ID.test(text(project.project_id, "project_id", 64))
    || !["owner", "admin", "developer", "viewer"].includes(String(project.role))
    || project.credit_instrument !== "closed_loop_nontransferable_service_credit"
    || typeof project.provider_dispatch_enabled !== "boolean"
    || !Array.isArray(project.members)
    || project.members.length > 64
    || !Array.isArray(policy.allowed_operations)
    || policy.allowed_operations.join(",") !== "inference,training"
  ) throw new Error("Compute project failed its bounded schema checks");
  integer(policy.per_job_max_credits, "per-job credit cap", 1, 500);
  integer(policy.daily_project_max_credits, "daily project cap", 1, 2_500);
  integer(policy.credential_max_ttl_seconds, "credential lifetime", 60, 604_800);
  for (const memberValue of project.members) {
    const member = record(memberValue, "project member");
    if (!/^0x[0-9a-fA-F]{40}$/.test(String(member.address)) || !["owner", "admin", "developer", "viewer"].includes(String(member.role))) {
      throw new Error("Compute project member is malformed");
    }
  }
}

function assertDevice(value: unknown): asserts value is ComputeDevice {
  const device = record(value, "Compute device");
  if (
    !RESOURCE_ID.test(String(device.device_id))
    || !RESOURCE_ID.test(String(device.project_id))
    || !["developer_device", "ci_service", "autonomous_agent"].includes(String(device.kind))
    || !["active", "revoked"].includes(String(device.status))
    || device.binding !== "encrypted_delivery_only_not_hardware_attestation"
    || device.public_key_returned !== false
    || !HEX_64.test(String(device.public_key_hash))
  ) throw new Error("Compute device failed its bounded schema checks");
}

function assertCredential(value: unknown): asserts value is ComputeCredential {
  const credential = record(value, "Compute credential");
  if (
    !RESOURCE_ID.test(String(credential.credential_id))
    || !RESOURCE_ID.test(String(credential.project_id))
    || !RESOURCE_ID.test(String(credential.device_id))
    || !Array.isArray(credential.scopes)
    || credential.scopes.length < 1
    || credential.scopes.length > 5
    || credential.scopes.some((scope) => typeof scope !== "string" || !SUPPORTED_SCOPES.has(scope))
    || !["active", "expired", "revoked"].includes(String(credential.status))
    || credential.plaintext_token_stored !== false
    || credential.upstream_tinker_key_exposed !== false
  ) throw new Error("Compute credential failed its bounded schema checks");
}

function assertBalance(value: unknown, projectId?: string): asserts value is ComputeBalance {
  const balance = record(value, "Compute balance");
  if (
    balance.surface !== "compute_credit_balance"
    || balance.schema_version !== 1
    || (projectId !== undefined && balance.project_id !== projectId)
    || balance.unit !== "service_credit"
    || balance.nominal_usd_cents_per_credit !== 1
    || balance.transferable !== false
    || balance.redeemable !== false
    || balance.onchain_token !== false
  ) throw new Error("Compute balance failed its bounded schema checks");
  const available = integer(balance.available_credits, "available credits", 0, 1_000_000);
  const reserved = integer(balance.reserved_credits, "reserved credits", 0, 1_000_000);
  if (integer(balance.total_service_credits, "total credits", 0, 1_000_000) !== available + reserved) {
    throw new Error("Compute balance does not reconcile");
  }
}

function assertJob(value: unknown, projectId?: string): asserts value is ComputeJob {
  const job = record(value, "Compute job");
  if (
    !RESOURCE_ID.test(String(job.job_id))
    || !RESOURCE_ID.test(String(job.project_id))
    || (projectId !== undefined && job.project_id !== projectId)
    || !["inference", "training"].includes(String(job.operation))
    || job.model !== "qwen3_8b"
    || !["qwen3_8b_bounded", "qwen3_8b_lora_r32"].includes(String(job.recipe))
    || !["queued", "running", "succeeded", "failed", "canceled"].includes(String(job.status))
    || job.dispatch_status !== "not_dispatched"
    || !["existing_tinker_training_proxy", "future_inference_proxy"].includes(String(job.backend_capability))
    || job.provider_authoritative_settlement !== false
    || job.raw_input_persisted !== false
    || job.raw_output_persisted !== false
  ) throw new Error("Compute job failed its bounded schema checks");
  integer(job.max_credits, "job reservation", 1, 500);
  if (job.usage_receipt_hash !== null && !SHA256.test(String(job.usage_receipt_hash))) throw new Error("Compute receipt hash is malformed");
}

function assertDispatchCapability(value: unknown): asserts value is ComputeDispatchCapability {
  const capability = record(value, "Compute dispatch-intent capability");
  exactKeys(capability, "Compute dispatch-intent capability", [
    "metadata_intent_creation",
    "provider_dispatch",
    "independent_metering",
    "settlement",
    "exact_asset_only",
    "mutation_route",
    "status_route_template",
    "reason",
  ]);
  const metadata = boolean(capability.metadata_intent_creation, "metadata intent creation capability");
  const provider = boolean(capability.provider_dispatch, "provider dispatch capability");
  const metering = boolean(capability.independent_metering, "independent metering capability");
  const settlement = boolean(capability.settlement, "settlement capability");
  const reason = text(capability.reason, "dispatch capability reason", 96);
  if (
    capability.exact_asset_only !== true
    || capability.status_route_template !== DISPATCH_STATUS_ROUTE
    || !/^[a-z][a-z0-9_]{2,95}$/.test(reason)
    || (metadata ? capability.mutation_route !== DISPATCH_MUTATION_ROUTE : capability.mutation_route !== null)
    || (provider && !metadata)
    || (metering && !provider)
    || (settlement && !metering)
  ) throw new Error("Compute dispatch-intent capability is contradictory");
}

export function parseComputeFundingCapabilities(value: unknown): ComputeFundingCapabilities {
  assertNoSensitiveFields(value);
  const capability = record(value, "Compute funding capabilities");
  exactKeys(capability, "Compute funding capabilities", [
    "surface",
    "schema_version",
    "card",
    "usdc",
    "eth",
    "exact_asset_vault",
    "dispatch_intents",
    "operator_testnet_grants",
    "credits",
  ]);
  const card = record(capability.card, "card capability");
  const usdc = record(capability.usdc, "USDC capability");
  const eth = record(capability.eth, "ETH capability");
  const vault = record(capability.exact_asset_vault, "exact-asset vault capability");
  const credits = record(capability.credits, "credit capability");
  const grants = record(capability.operator_testnet_grants, "testnet grant capability");
  exactKeys(card, "card capability", ["enabled", "mutation_route", "reason", "card_data_accepted", "distinct_from_exact_asset_capacity"]);
  exactKeys(usdc, "USDC capability", ["enabled", "mutation_route", "reason", "capacity_model"]);
  exactKeys(eth, "ETH capability", ["enabled", "mutation_route", "reason", "capacity_model"]);
  exactKeys(vault, "exact-asset vault capability", ["contract", "release_bound", "review_status", "provider_dispatch_authoritative"]);
  exactKeys(grants, "testnet grant capability", ["enabled", "auth", "cash_value"]);
  exactKeys(credits, "credit capability", [
    "kind", "transferable", "redeemable", "onchain_token",
    "nominal_usd_cents_per_credit", "legacy_modeled_ledger", "distinct_from_exact_asset_vault",
  ]);
  assertDispatchCapability(capability.dispatch_intents);
  if (
    capability.surface !== "compute_funding_capabilities"
    || capability.schema_version !== 1
    || card.enabled !== false
    || card.mutation_route !== null
    || card.card_data_accepted !== false
    || card.distinct_from_exact_asset_capacity !== true
    || usdc.enabled !== false
    || usdc.mutation_route !== null
    || usdc.capacity_model !== "same_asset_nontransferable_vault_claim"
    || eth.enabled !== false
    || eth.mutation_route !== null
    || eth.capacity_model !== "same_asset_nontransferable_vault_claim"
    || vault.contract !== "ComputeCreditVault"
    || vault.release_bound !== true
    || vault.review_status !== "reviewed_and_extensively_tested_not_formally_audited"
    || vault.provider_dispatch_authoritative !== false
    || credits.kind !== "closed_loop_service_credit"
    || credits.transferable !== false
    || credits.redeemable !== false
    || credits.onchain_token !== false
    || credits.nominal_usd_cents_per_credit !== 1
    || credits.legacy_modeled_ledger !== true
    || credits.distinct_from_exact_asset_vault !== true
    || typeof grants.enabled !== "boolean"
    || grants.auth !== "configured_runtime_bearer"
    || grants.cash_value !== false
  ) throw new Error("Compute funding capability made an unsupported claim");
  text(card.reason, "card capability reason", 128);
  text(usdc.reason, "USDC capability reason", 128);
  text(eth.reason, "ETH capability reason", 128);
  return capability as unknown as ComputeFundingCapabilities;
}

export async function fetchFundingCapabilities(): Promise<ComputeFundingCapabilities> {
  return parseComputeFundingCapabilities(await request("/compute/funding-capabilities"));
}

export async function listProjects(token: string): Promise<ComputeProject[]> {
  const result = record(await request("/compute/projects", { token }), "Compute projects");
  if (result.surface !== "compute_projects" || result.schema_version !== 1 || !Array.isArray(result.projects) || result.projects.length > 16) {
    throw new Error("Compute projects failed their bounded schema checks");
  }
  result.projects.forEach(assertProject);
  return result.projects as ComputeProject[];
}

export async function createProject(token: string, name: string, idempotencyKey: string): Promise<ComputeProject> {
  const result = record(await request("/compute/projects", { method: "POST", token, idempotencyKey, body: { name } }), "Compute project result");
  if (result.surface !== "compute_project_result" || typeof result.created !== "boolean" || typeof result.idempotent_replay !== "boolean") {
    throw new Error("Compute project result is malformed");
  }
  assertProject(result.project);
  return result.project;
}

export async function getProject(token: string, projectId: string): Promise<ComputeProject> {
  const result = await request(`/compute/projects/${encodeURIComponent(projectId)}`, { token });
  assertProject(result);
  return result;
}

export async function addProjectMember(token: string, projectId: string, address: string, role: Exclude<ProjectRole, "owner">): Promise<ComputeProject> {
  const result = await request(`/compute/projects/${encodeURIComponent(projectId)}/members`, { method: "POST", token, body: { address, role } });
  assertProject(result);
  return result;
}

export async function removeProjectMember(token: string, projectId: string, address: string): Promise<ComputeProject> {
  const result = await request(`/compute/projects/${encodeURIComponent(projectId)}/members/${encodeURIComponent(address)}`, { method: "DELETE", token });
  assertProject(result);
  return result;
}

export async function listDevices(token: string, projectId: string): Promise<ComputeDevice[]> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/devices`, { token }), "Compute devices");
  if (result.surface !== "compute_devices" || !Array.isArray(result.devices) || result.devices.length > 128) throw new Error("Compute devices are malformed");
  result.devices.forEach(assertDevice);
  return result.devices as ComputeDevice[];
}

export async function registerDevice(token: string, projectId: string, label: string, kind: DeviceKind, publicKey: string): Promise<ComputeDevice> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/devices`, { method: "POST", token, body: { label, kind, public_key: publicKey } }), "Compute device result");
  if (result.surface !== "compute_device") throw new Error("Compute device result is malformed");
  assertDevice(result.device);
  return result.device;
}

export async function revokeDevice(token: string, projectId: string, deviceId: string): Promise<ComputeDevice> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/devices/${encodeURIComponent(deviceId)}/revoke`, { method: "POST", token }), "Compute device result");
  if (result.surface !== "compute_device") throw new Error("Compute device result is malformed");
  assertDevice(result.device);
  return result.device;
}

export async function listCredentials(token: string, projectId: string): Promise<ComputeCredential[]> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/credentials`, { token }), "Compute credentials");
  if (result.surface !== "compute_credentials" || !Array.isArray(result.credentials) || result.credentials.length > 512) throw new Error("Compute credentials are malformed");
  result.credentials.forEach(assertCredential);
  return result.credentials as ComputeCredential[];
}

function parseCredentialDelivery(value: unknown, expectedSurface: "compute_credential_issuance" | "compute_credential_rotation"): ComputeCredentialDelivery {
  const result = record(value, "Compute credential delivery");
  const capsule = record(result.capsule, "Compute credential capsule");
  const encrypted = record(capsule.encrypted_token, "Compute encrypted token");
  assertCredential(result.credential);
  if (
    result.surface !== expectedSurface
    || capsule.delivery !== "x25519_aes_256_gcm_envelope"
    || capsule.plaintext_token_returned !== false
    || result.plaintext_token_returned !== false
    || (expectedSurface === "compute_credential_issuance" && result.upstream_tinker_key_exposed !== false)
    || !HEX_64.test(String(encrypted.ephemeral_public_key))
    || !/^[0-9a-f]{24}$/.test(String(encrypted.nonce))
    || !/^[0-9a-f]{32,16384}$/.test(String(encrypted.ciphertext))
    || !/^[0-9a-f]{2,8192}$/.test(String(capsule.associated_data))
    || !HEX_64.test(String(capsule.associated_data_hash))
    || !HEX_64.test(String(capsule.recipient_public_key_hash))
  ) throw new Error("Compute credential capsule failed its bounded schema checks");
  return { credential: result.credential, capsule: capsule as unknown as ComputeCapsule };
}

export async function issueCredential(
  token: string,
  projectId: string,
  input: { deviceId: string; name: string; scopes: ComputeScope[]; expiresInSeconds: number; dailyCreditCap: number },
): Promise<ComputeCredentialDelivery> {
  return parseCredentialDelivery(await request(`/compute/projects/${encodeURIComponent(projectId)}/credentials`, {
    method: "POST",
    token,
    body: {
      device_id: input.deviceId,
      name: input.name,
      scopes: input.scopes,
      expires_in_seconds: input.expiresInSeconds,
      daily_credit_cap: input.dailyCreditCap,
    },
  }), "compute_credential_issuance");
}

export async function rotateCredential(token: string, projectId: string, credentialId: string, expiresInSeconds: number): Promise<ComputeCredentialDelivery> {
  return parseCredentialDelivery(await request(`/compute/projects/${encodeURIComponent(projectId)}/credentials/${encodeURIComponent(credentialId)}/rotate`, {
    method: "POST", token, body: { expires_in_seconds: expiresInSeconds },
  }), "compute_credential_rotation");
}

export async function revokeCredential(token: string, projectId: string, credentialId: string): Promise<ComputeCredential> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/credentials/${encodeURIComponent(credentialId)}/revoke`, { method: "POST", token }), "Compute credential result");
  if (result.surface !== "compute_credential") throw new Error("Compute credential result is malformed");
  assertCredential(result.credential);
  return result.credential;
}

export async function fetchBalance(token: string, projectId: string): Promise<ComputeBalance> {
  const result = await request(`/compute/projects/${encodeURIComponent(projectId)}/balance`, { token });
  assertBalance(result, projectId);
  return result;
}

export async function fetchLedger(token: string, projectId: string): Promise<ComputeLedger> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/ledger?limit=100`, { token }), "Compute ledger");
  if (
    result.surface !== "compute_ledger"
    || result.schema_version !== 1
    || result.project_id !== projectId
    || result.append_only !== true
    || result.double_entry !== true
    || result.currency !== "service_credit"
    || result.transferable !== false
    || result.redeemable !== false
    || !Array.isArray(result.transactions)
    || result.transactions.length > 100
  ) throw new Error("Compute ledger failed its bounded schema checks");
  assertBalance(result.balance, projectId);
  for (const item of result.transactions) {
    const transaction = record(item, "Compute ledger transaction");
    if (!RESOURCE_ID.test(String(transaction.transaction_id)) || !HEX_64.test(String(transaction.transaction_hash)) || !HEX_64.test(String(transaction.previous_hash))) {
      throw new Error("Compute ledger transaction is malformed");
    }
    const postings = transaction.postings;
    if (!Array.isArray(postings) || postings.length < 2 || postings.length > 3 || postings.reduce((sum, posting) => sum + integer(record(posting, "ledger posting").delta, "posting delta", -1_000_000, 1_000_000), 0) !== 0) {
      throw new Error("Compute ledger transaction does not balance");
    }
  }
  return result as unknown as ComputeLedger;
}

export async function listJobs(token: string, projectId: string): Promise<ComputeJob[]> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/jobs?limit=100`, { token }), "Compute jobs");
  if (result.surface !== "compute_jobs" || result.schema_version !== 1 || !Array.isArray(result.jobs) || result.jobs.length > 100) throw new Error("Compute jobs are malformed");
  result.jobs.forEach((job) => assertJob(job, projectId));
  return result.jobs as ComputeJob[];
}

const DISPATCH_STAGES = new Set<ComputeDispatchStage>([
  "intent_created",
  "start_prepared",
  "start_broadcast",
  "start_confirmed",
  "provider_dispatching",
  "usage_finalized",
  "metering_pending",
  "metering_decided",
  "settlement_prepared",
  "settlement_broadcast",
  "settled",
  "blocked",
]);
const PRE_PROVIDER_STAGES = new Set<ComputeDispatchStage>([
  "intent_created", "start_prepared", "start_broadcast", "start_confirmed",
]);
const USAGE_FINALIZED_STAGES = new Set<ComputeDispatchStage>([
  "usage_finalized", "metering_pending", "metering_decided",
  "settlement_prepared", "settlement_broadcast", "settled",
]);

function boundedReference(value: unknown, label: string): string {
  const normalized = text(value, label, 128).trim();
  if (!COMPUTE_REFERENCE.test(normalized)) throw new Error(`${label} is malformed`);
  return normalized.startsWith("0x") ? normalized.toLowerCase() : normalized;
}

function lowerAddress(value: unknown, label: string, allowZero: boolean): `0x${string}` {
  const normalized = typeof value === "string" ? value.toLowerCase() : "";
  if (!ADDRESS.test(normalized) || (!allowZero && normalized === `0x${"0".repeat(40)}`)) {
    throw new Error(`${label} is malformed`);
  }
  return normalized as `0x${string}`;
}

function nonzeroBytes32(value: unknown, label: string): `0x${string}` {
  const normalized = typeof value === "string" ? value.toLowerCase() : "";
  if (!NONZERO_BYTES32.test(normalized)) throw new Error(`${label} is malformed`);
  return normalized as `0x${string}`;
}

export function parseComputeDispatchIntent(
  value: unknown,
  expected?: { projectReference?: string; jobReference?: string },
): ComputeDispatchIntentStatus {
  assertNoSensitiveFields(value);
  const intent = record(value, "Compute dispatch intent");
  exactKeys(intent, "Compute dispatch intent", [
    "surface", "schema_version", "project_reference", "job_reference", "project_id", "job_id",
    "user", "asset", "authorization_nonce", "max_asset_debit", "authorization_expiry",
    "rate_policy_commitment", "compose_hash", "operation", "model", "recipe", "result_policy",
    "resource_limits", "workload_id", "workload_schema", "manifest_commitment", "workload_commitment",
    "intent_commitment", "execution_policy_context_hash", "stage", "provider_authoritative",
    "legacy_credit_ledger_mutated", "provider_dispatch_status",
    "provider_dispatch_may_have_occurred", "provider_usage_finalized", "raw_prompt_accepted",
    "raw_examples_accepted", "arbitrary_program_accepted", "exact_timing_egress",
  ]);
  const limits = record(intent.resource_limits, "Compute dispatch resource limits");
  exactKeys(limits, "Compute dispatch resource limits", [
    "max_prefill_tokens", "max_sample_tokens", "max_train_tokens",
  ]);
  const projectReference = boundedReference(intent.project_reference, "dispatch project reference");
  const jobReference = boundedReference(intent.job_reference, "dispatch job reference");
  const projectId = nonzeroBytes32(intent.project_id, "dispatch project ID");
  const jobId = nonzeroBytes32(intent.job_id, "dispatch job ID");
  const stage = String(intent.stage) as ComputeDispatchStage;
  const providerStatus = String(intent.provider_dispatch_status);
  const providerMayHaveStarted = boolean(intent.provider_dispatch_may_have_occurred, "provider dispatch ambiguity flag");
  const usageFinalized = boolean(intent.provider_usage_finalized, "provider usage finalization flag");
  const operation = String(intent.operation);
  const recipe = String(intent.recipe);
  const maxPrefill = integer(limits.max_prefill_tokens, "maximum prefill tokens", 0, 100_000_000);
  const maxSample = integer(limits.max_sample_tokens, "maximum sample tokens", 0, 100_000_000);
  const maxTrain = integer(limits.max_train_tokens, "maximum training tokens", 0, 100_000_000);
  const authorizationNonce = parseDispatchUint256(intent.authorization_nonce, "authorization nonce");
  const maxAssetDebit = parseDispatchUint256(intent.max_asset_debit, "maximum asset debit");
  const user = lowerAddress(intent.user, "dispatch user", false);
  const asset = lowerAddress(intent.asset, "dispatch asset", true);
  const authorizationExpiry = integer(intent.authorization_expiry, "authorization expiry", 1, 4_102_444_800);
  const ratePolicyCommitment = nonzeroBytes32(intent.rate_policy_commitment, "rate-policy commitment");
  const composeHash = nonzeroBytes32(intent.compose_hash, "compose hash");
  const workloadId = String(intent.workload_id);
  const workloadSchema = String(intent.workload_schema);
  const manifestCommitment = nonzeroBytes32(intent.manifest_commitment, "manifest commitment");
  const workloadCommitment = nonzeroBytes32(intent.workload_commitment, "workload commitment");
  const intentCommitment = nonzeroBytes32(intent.intent_commitment, "intent commitment");
  const executionPolicyContextHash = typeof intent.execution_policy_context_hash === "string"
    && HEX_64.test(intent.execution_policy_context_hash)
    ? intent.execution_policy_context_hash
    : "";
  const expectedProject = expected?.projectReference === undefined
    ? undefined
    : boundedReference(expected.projectReference, "expected project reference");
  const expectedJob = expected?.jobReference === undefined
    ? undefined
    : boundedReference(expected.jobReference, "expected job reference");

  if (
    intent.surface !== "compute_dispatch_intent"
    || intent.schema_version !== 2
    || projectId !== computeVaultProjectId(projectReference)
    || jobId !== computeVaultJobId(jobReference)
    || (expectedProject !== undefined && projectReference !== expectedProject)
    || (expectedJob !== undefined && jobReference !== expectedJob)
    || maxAssetDebit === 0n
    || !DISPATCH_STAGES.has(stage)
    || !["not_started", "may_have_started", "usage_finalized"].includes(providerStatus)
    || intent.provider_authoritative !== false
    || intent.legacy_credit_ledger_mutated !== false
    || intent.raw_prompt_accepted !== false
    || intent.raw_examples_accepted !== false
    || intent.arbitrary_program_accepted !== false
    || intent.exact_timing_egress !== false
    || (providerStatus === "not_started" && (providerMayHaveStarted || usageFinalized))
    || (providerStatus === "may_have_started" && (!providerMayHaveStarted || usageFinalized))
    || (providerStatus === "usage_finalized" && (!providerMayHaveStarted || !usageFinalized))
    || (stage !== "blocked" && PRE_PROVIDER_STAGES.has(stage) && providerStatus !== "not_started")
    || (stage === "provider_dispatching" && providerStatus !== "may_have_started")
    || (stage !== "blocked" && USAGE_FINALIZED_STAGES.has(stage) && providerStatus !== "usage_finalized")
    || !["inference", "training"].includes(operation)
    || !WORKLOAD_ID.test(workloadId)
    || workloadSchema !== (operation === "inference"
      ? "dnai.compute.workload.inference.v1"
      : "dnai.compute.workload.sft-jsonl.v1")
    || intent.model !== "qwen3_8b"
    || !["bounded_summary_receipt", "score_band_hash"].includes(String(intent.result_policy))
    || (operation === "inference" && (
      recipe !== "qwen3_8b_bounded" || maxPrefill < 1 || maxPrefill > 32_768
      || maxSample < 1 || maxSample > 4_096 || maxTrain !== 0
    ))
    || (operation === "training" && (
      recipe !== "qwen3_8b_lora_r32" || maxPrefill !== 0 || maxSample !== 0
      || maxTrain < 1 || maxTrain > 10_000_000
    ))
  ) throw new Error("Compute dispatch intent failed its bounded schema checks");

  const expectedCommitment = computeDispatchIntentCommitment({
    projectReference,
    jobReference,
    projectId,
    jobId,
    user,
    asset,
    authorizationNonce,
    maxAssetDebit,
    authorizationExpiry,
    ratePolicyCommitment,
    composeHash,
    operation,
    model: String(intent.model),
    recipe,
    resultPolicy: String(intent.result_policy),
    maxPrefillTokens: maxPrefill,
    maxSampleTokens: maxSample,
    maxTrainTokens: maxTrain,
    workloadId,
    workloadSchema,
    manifestCommitment,
    workloadCommitment,
  });
  if (intentCommitment !== expectedCommitment) {
    throw new Error("Compute dispatch intent commitment does not match its canonical metadata");
  }
  const expectedPolicyContextHash = computeExecutionPolicyContextHash({
    jobId,
    intentCommitment,
    operation,
    model: String(intent.model),
    recipe,
  });
  if (executionPolicyContextHash !== expectedPolicyContextHash) {
    throw new Error("Compute execution-policy context does not match intent and compiled recipe");
  }

  const parsed = {
    ...intent,
    project_reference: projectReference,
    job_reference: jobReference,
    project_id: projectId,
    job_id: jobId,
    user,
    asset,
    authorization_nonce: authorizationNonce,
    max_asset_debit: maxAssetDebit,
    authorization_expiry: authorizationExpiry,
    rate_policy_commitment: ratePolicyCommitment,
    compose_hash: composeHash,
    workload_id: workloadId,
    workload_schema: workloadSchema,
    manifest_commitment: manifestCommitment,
    workload_commitment: workloadCommitment,
    operation,
    recipe,
    resource_limits: {
      max_prefill_tokens: maxPrefill,
      max_sample_tokens: maxSample,
      max_train_tokens: maxTrain,
    },
    intent_commitment: intentCommitment,
    execution_policy_context_hash: executionPolicyContextHash,
    stage,
    provider_dispatch_status: providerStatus,
  };
  return parsed as ComputeDispatchIntentStatus;
}

export function canCreateComputeDispatchIntent(
  project: ComputeProject | undefined,
  capability: ComputeDispatchCapability | undefined,
): boolean {
  return Boolean(
    project
    && ["owner", "admin", "developer"].includes(project.role)
    && project.provider_dispatch_enabled === true
    && capability?.metadata_intent_creation === true
    && capability.provider_dispatch === true
    && capability.independent_metering === true
    && capability.settlement === true
    && capability.exact_asset_only === true
    && capability.mutation_route === DISPATCH_MUTATION_ROUTE
    && capability.status_route_template === DISPATCH_STATUS_ROUTE
  );
}

function normalizeDispatchInput(input: ComputeDispatchIntentInput): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1_000);
  const jobReference = boundedReference(input.jobReference, "dispatch job reference");
  const workloadId = String(input.workloadId).trim();
  const authorizationNonce = parseDispatchUint256(input.authorizationNonce, "authorization nonce");
  const maxAssetDebit = parseDispatchUint256(input.maxAssetDebit, "maximum asset debit");
  const operation = input.operation;
  const prefill = integer(input.maxPrefillTokens, "maximum prefill tokens", 0, 100_000_000);
  const sample = integer(input.maxSampleTokens, "maximum sample tokens", 0, 100_000_000);
  const train = integer(input.maxTrainTokens, "maximum training tokens", 0, 100_000_000);
  if (
    maxAssetDebit === 0n
    || !WORKLOAD_ID.test(workloadId)
    || !Number.isSafeInteger(input.authorizationExpiry)
    || input.authorizationExpiry <= now
    || input.authorizationExpiry > now + 30 * 24 * 60 * 60
    || (operation === "inference" && (prefill < 1 || prefill > 32_768 || sample < 1 || sample > 4_096 || train !== 0))
    || (operation === "training" && (prefill !== 0 || sample !== 0 || train < 1 || train > 10_000_000))
  ) throw new Error("Compute dispatch intent exceeds its compiled public recipe");
  return {
    job_reference: jobReference,
    workload_id: workloadId,
    asset: lowerAddress(input.asset, "dispatch asset", true),
    authorization_nonce: authorizationNonce.toString(),
    max_asset_debit: maxAssetDebit.toString(),
    authorization_expiry: input.authorizationExpiry,
    rate_policy_commitment: nonzeroBytes32(input.ratePolicyCommitment, "rate-policy commitment"),
    compose_hash: nonzeroBytes32(input.composeHash, "compose hash"),
    operation,
    model: "qwen3_8b",
    recipe: operation === "training" ? "qwen3_8b_lora_r32" : "qwen3_8b_bounded",
    result_policy: input.resultPolicy,
    max_prefill_tokens: prefill,
    max_sample_tokens: sample,
    max_train_tokens: train,
  };
}

export async function fetchComputeDispatchIntent(
  token: string,
  projectReference: string,
  jobReference: string,
): Promise<ComputeDispatchIntentStatus> {
  const project = boundedReference(projectReference, "dispatch project reference");
  if (!RESOURCE_ID.test(project)) throw new Error("Dispatch project reference is not a Compute Console project ID");
  const job = boundedReference(jobReference, "dispatch job reference");
  const result = await request(
    `/compute/projects/${encodeURIComponent(project)}/dispatch-intents/${encodeURIComponent(job)}`,
    { token },
  );
  return parseComputeDispatchIntent(result, { projectReference: project, jobReference: job });
}

/**
 * Resolve a public Compute policy target only through the authenticated exact-
 * asset status route. Legacy service-credit job IDs are intentionally not
 * accepted by this browser workflow.
 */
export async function fetchComputeExecutionPolicyTarget(
  token: string,
  projectReference: string,
  jobReference: string,
  expectedWalletAddress: string,
): Promise<ComputeExecutionPolicyTarget> {
  const intent = await fetchComputeDispatchIntent(
    token,
    projectReference,
    jobReference,
  );
  const recomputed = computeExecutionPolicyContextHash({
    jobId: intent.job_id,
    intentCommitment: intent.intent_commitment,
    operation: intent.operation,
    model: intent.model,
    recipe: intent.recipe,
  });
  if (recomputed !== intent.execution_policy_context_hash) {
    throw new Error(
      "Authenticated Compute intent drifted from its execution-policy context",
    );
  }
  const expectedUser = lowerAddress(
    expectedWalletAddress,
    "expected Compute policy wallet",
    false,
  );
  if (intent.user !== expectedUser) {
    throw new Error(
      "Authenticated Compute intent is owned by a different wallet",
    );
  }
  return {
    resourceId: intent.job_id,
    executionContextHash: recomputed,
    authorizedUser: intent.user,
  };
}

export async function createComputeDispatchIntent(
  token: string,
  project: ComputeProject,
  capability: ComputeDispatchCapability,
  input: ComputeDispatchIntentInput,
  idempotencyKey: string,
): Promise<ComputeDispatchIntentResult> {
  if (!canCreateComputeDispatchIntent(project, capability)) {
    throw new Error("Exact-asset dispatch-intent creation is not enabled by this release");
  }
  if (!IDEMPOTENCY_KEY.test(idempotencyKey)) throw new Error("Compute dispatch idempotency key is malformed");
  const body = normalizeDispatchInput(input);
  const result = record(await request(
    `/compute/projects/${encodeURIComponent(project.project_id)}/dispatch-intents`,
    { method: "POST", token, idempotencyKey, body },
  ), "Compute dispatch-intent result");
  exactKeys(result, "Compute dispatch-intent result", [
    "surface", "schema_version", "created", "idempotent_replay", "intent",
    "legacy_credit_ledger_mutated", "provider_dispatch_status",
    "provider_dispatch_may_have_occurred", "provider_authoritative",
  ]);
  const created = boolean(result.created, "dispatch-intent created flag");
  const replay = boolean(result.idempotent_replay, "dispatch-intent replay flag");
  const intent = parseComputeDispatchIntent(result.intent, {
    projectReference: project.project_id,
    jobReference: String(body.job_reference),
  });
  if (
    result.surface !== "compute_dispatch_intent_result"
    || result.schema_version !== 2
    || created === replay
    || result.legacy_credit_ledger_mutated !== false
    || result.provider_authoritative !== false
    || result.provider_dispatch_status !== intent.provider_dispatch_status
    || result.provider_dispatch_may_have_occurred !== intent.provider_dispatch_may_have_occurred
  ) throw new Error("Compute dispatch-intent result is contradictory");
  return { created, idempotentReplay: replay, intent };
}

export async function createJob(
  token: string,
  projectId: string,
  input: { name: string; operation: "inference" | "training"; maxCredits: number; resultPolicy: "bounded_summary_receipt" | "score_band_hash"; environmentVersion: string },
  idempotencyKey: string,
): Promise<ComputeJob> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/jobs`, {
    method: "POST",
    token,
    idempotencyKey,
    body: {
      name: input.name,
      operation: input.operation,
      model: "qwen3_8b",
      recipe: input.operation === "training" ? "qwen3_8b_lora_r32" : "qwen3_8b_bounded",
      max_credits: input.maxCredits,
      result_policy: input.resultPolicy,
      environment_version: input.environmentVersion,
    },
  }), "Compute job result");
  if (result.surface !== "compute_job_result" || result.provider_dispatch_performed !== false) throw new Error("Compute job result made an unsupported dispatch claim");
  assertJob(result.job, projectId);
  return result.job;
}

export function canCancelComputeJob(job: ComputeJob, role: ProjectRole | undefined): boolean {
  return (
    role !== undefined
    && ["owner", "admin", "developer"].includes(role)
    && job.status === "queued"
    && job.dispatch_status === "not_dispatched"
    && job.started_at === null
    && job.completed_at === null
    && job.actual_credits === null
    && job.released_credits === null
    && job.metering_source === null
    && job.usage_receipt_hash === null
    && job.settlement_authority === null
  );
}

export function parseComputeJobCancellation(
  value: unknown,
  expectedProjectId: string,
  expectedJobId: string,
): ComputeJobCancellationReceipt {
  assertNoSensitiveFields(value);
  const result = record(value, "Compute job cancellation");
  exactKeys(result, "Compute job cancellation", [
    "surface",
    "schema_version",
    "project_id",
    "job_id",
    "status",
    "changed",
    "idempotent_replay",
    "released_credits",
    "credit_reversal",
    "ledger",
    "provider_dispatch_performed",
    "service_settlement_performed",
  ]);
  const ledger = record(result.ledger, "Compute cancellation ledger receipt");
  exactKeys(ledger, "Compute cancellation ledger receipt", [
    "transaction_id",
    "sequence",
    "kind",
    "transaction_hash",
    "previous_hash",
    "settlement_status",
  ]);
  if (
    result.surface !== "compute_job_cancellation"
    || result.schema_version !== 1
    || result.project_id !== expectedProjectId
    || result.job_id !== expectedJobId
    || !RESOURCE_ID.test(expectedProjectId)
    || !RESOURCE_ID.test(expectedJobId)
    || result.status !== "canceled"
    || typeof result.changed !== "boolean"
    || typeof result.idempotent_replay !== "boolean"
    || result.changed === result.idempotent_replay
    || result.credit_reversal !== "reserved_to_available"
    || result.provider_dispatch_performed !== false
    || result.service_settlement_performed !== false
    || !RESOURCE_ID.test(String(ledger.transaction_id))
    || ledger.kind !== "job_cancel"
    || !HEX_64.test(String(ledger.transaction_hash))
    || !HEX_64.test(String(ledger.previous_hash))
    || ledger.settlement_status !== "user_canceled_before_dispatch"
  ) throw new Error("Compute job cancellation failed its bounded schema checks");
  integer(result.released_credits, "released credits", 1, 500);
  integer(ledger.sequence, "cancellation ledger sequence", 1, 40_000);
  return result as unknown as ComputeJobCancellationReceipt;
}

export async function cancelComputeJob(
  token: string,
  projectId: string,
  jobId: string,
  idempotencyKey: string,
): Promise<ComputeJobCancellationReceipt> {
  if (!RESOURCE_ID.test(projectId) || !RESOURCE_ID.test(jobId)) {
    throw new Error("Compute cancellation target is malformed");
  }
  if (!IDEMPOTENCY_KEY.test(idempotencyKey)) {
    throw new Error("Compute cancellation idempotency key is malformed");
  }
  const result = await request(
    `/compute/projects/${encodeURIComponent(projectId)}/jobs/${encodeURIComponent(jobId)}/cancel`,
    {
      method: "POST",
      token,
      idempotencyKey,
      body: { reason: "user_requested_before_dispatch" },
    },
  );
  return parseComputeJobCancellation(result, projectId, jobId);
}

function bytesFromHex(value: string, exactBytes?: number): Uint8Array {
  if (!/^[0-9a-f]+$/.test(value) || value.length % 2 !== 0) throw new Error("Credential capsule contains invalid hex");
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  if (exactBytes !== undefined && bytes.length !== exactBytes) throw new Error("Credential capsule field has an invalid length");
  return bytes;
}

function hexFromBytes(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function buffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

export async function generateDeviceKey(): Promise<DeviceKeyMaterial> {
  if (!crypto?.subtle) throw new Error("This browser cannot create a device encryption key");
  const pair = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]) as CryptoKeyPair;
  const publicKey = await crypto.subtle.exportKey("raw", pair.publicKey);
  return { publicKeyHex: hexFromBytes(publicKey), privateKey: pair.privateKey };
}

async function sha256Text(value: string): Promise<string> {
  return hexFromBytes(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

export async function decryptCredentialCapsule(delivery: ComputeCredentialDelivery, deviceKey: DeviceKeyMaterial): Promise<string> {
  const { capsule, credential } = delivery;
  const ephemeralBytes = bytesFromHex(capsule.encrypted_token.ephemeral_public_key, 32);
  const nonce = bytesFromHex(capsule.encrypted_token.nonce, 12);
  const ciphertext = bytesFromHex(capsule.encrypted_token.ciphertext);
  const associatedData = bytesFromHex(capsule.associated_data);
  let shared = new Uint8Array();
  let plaintext = new Uint8Array();
  try {
    if (await sha256Text(`compute_credential_aad:${capsule.associated_data}`) !== capsule.associated_data_hash) {
      throw new Error("Credential token associated-data commitment is invalid");
    }
    if (await sha256Text(`compute_device_key:${deviceKey.publicKeyHex}`) !== capsule.recipient_public_key_hash) {
      throw new Error("Credential token recipient commitment is invalid");
    }
    const binding = record(JSON.parse(decoder.decode(associatedData)), "Credential token binding");
    if (
      Object.keys(binding).sort().join(",") !== "credential_id,device_id,expires_at,generation,jwt_id_hash,project_id,surface"
      || binding.surface !== "compute_credential"
      || binding.credential_id !== credential.credential_id
      || binding.project_id !== credential.project_id
      || binding.device_id !== credential.device_id
      || binding.generation !== credential.generation
      || binding.expires_at !== credential.expires_at
      || !HEX_64.test(String(binding.jwt_id_hash))
    ) throw new Error("Credential token binding does not match the issuance receipt");
    const ephemeral = await crypto.subtle.importKey("raw", buffer(ephemeralBytes), { name: "X25519" }, false, []);
    shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: ephemeral }, deviceKey.privateKey, 256));
    const hkdf = await crypto.subtle.importKey("raw", buffer(shared), "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: encoder.encode("dnai-wikigen-compute-credential-v1") },
      hkdf,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(associatedData), tagLength: 128 },
      key,
      buffer(ciphertext),
    ));
    const token = decoder.decode(plaintext);
    await validateCredentialTokenShape(token, credential, String(binding.jwt_id_hash));
    return token;
  } catch (cause) {
    if (cause instanceof Error && (cause.message.startsWith("Credential token") || cause.message.startsWith("Credential capsule"))) throw cause;
    throw new Error("Credential capsule could not be authenticated for this device");
  } finally {
    ephemeralBytes.fill(0);
    nonce.fill(0);
    ciphertext.fill(0);
    associatedData.fill(0);
    shared.fill(0);
    plaintext.fill(0);
  }
}

function decodeBase64UrlJson(value: string): Record<string, unknown> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Credential token encoding is invalid");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  if (bytes.length > 8_192) throw new Error("Credential token segment exceeds its bound");
  return record(JSON.parse(decoder.decode(bytes)), "Credential token segment");
}

async function validateCredentialTokenShape(token: string, credential: ComputeCredential, expectedJwtIdHash: string): Promise<void> {
  if (token.length < 80 || token.length > 4096) throw new Error("Credential token length is invalid");
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) throw new Error("Credential token format is invalid");
  const header = decodeBase64UrlJson(parts[0]);
  const payload = decodeBase64UrlJson(parts[1]);
  const now = Math.floor(Date.now() / 1000);
  const jwtId = String(payload.jti ?? "");
  if (
    Object.keys(header).sort().join(",") !== "alg,kid,typ"
    || header.alg !== "HS256"
    || header.kid !== "dstack-compute-credential-v1"
    || header.typ !== "JWT"
    || payload.sub !== credential.credential_id
    || payload.project_id !== credential.project_id
    || payload.device_id !== credential.device_id
    || payload.generation !== credential.generation
    || payload.daily_credit_cap !== credential.daily_credit_cap
    || payload.iat !== credential.issued_at
    || payload.nbf !== payload.iat
    || payload.exp !== credential.expires_at
    || !Number.isInteger(payload.iat)
    || Number(payload.iat) > now + 30
    || !Number.isInteger(payload.exp)
    || Number(payload.exp) <= now
    || Number(payload.exp) <= Number(payload.iat)
    || Number(payload.exp) - Number(payload.iat) > 604_800
    || !/^[0-9a-f]{32}$/.test(jwtId)
    || String(payload.scope).split(" ").join(",") !== credential.scopes.join(",")
  ) throw new Error("Credential token claims do not match the issuance receipt");
  if (await sha256Text(`compute_credential_jti:${jwtId}`) !== expectedJwtIdHash) {
    throw new Error("Credential token id does not match the authenticated capsule binding");
  }
}

export function newIdempotencyKey(prefix: string): string {
  const normalized = prefix.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 24) || "request";
  return `${normalized}:${crypto.randomUUID()}`;
}

export class UnresolvedIdempotencyAttempt {
  private attempt?: { fingerprint: string; key: string };

  keyFor(prefix: string, fingerprint: string): string {
    const requestFingerprint = `${prefix}\u0000${fingerprint}`;
    if (this.attempt?.fingerprint === requestFingerprint) return this.attempt.key;
    const key = newIdempotencyKey(prefix);
    this.attempt = { fingerprint: requestFingerprint, key };
    return key;
  }

  resolve(key: string): void {
    if (this.attempt?.key === key) this.attempt = undefined;
  }
}
