import { recoverMessageAddress, type Address, type Hex } from "viem";
import {
  POLICY_CANONICALIZATION_VERSION,
  PUBLIC_REVIEW_ROLES,
  computeExecutionResourceHash,
  computePolicyCommitments,
  pythonCanonicalJson,
  type PolicyCommitments,
} from "./policyCommitments";
import {
  configuredExecutionPolicyAnchorRelease,
  parseRollbackAnchorStatus,
  verifyRollbackAnchorStatus,
  type ExecutionPolicyAnchorObserver,
  type ExecutionPolicyAnchorRelease,
  type RollbackAnchorStatus,
} from "./executionPolicyAnchor";

const MAX_RESPONSE_BYTES = 128 * 1024;
const MAX_BUNDLE_BYTES = 64 * 1024;
const MAX_KERNEL_PAYLOAD_BYTES = 32_768;
const MAX_STRING_BYTES = 256;
const MAX_LIST_ITEMS = 64;
const HASH = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const RESOURCE_ID = /^[A-Za-z0-9_.:/-]{1,160}$/;
const REASON = /^[a-z0-9_]{1,96}$/;
const SIGNATURE = /^0x[0-9a-fA-F]{130}$/;
const EVALUATION_IDEMPOTENCY_KEY = /^sha256:[0-9a-f]{64}$/;
const ZERO_DECISION_HASH = "0".repeat(64);
const EVALUATION_IDEMPOTENCY_DOMAIN = "dnai-wikigen/execution-policy-evaluate-idempotency/v1";
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const EXECUTION_POLICY_SURFACES = [
  "deal_evaluation",
  "arena_execution",
  "compute_dispatch",
] as const;

export type ExecutionPolicySurface = typeof EXECUTION_POLICY_SURFACES[number];
export type ExecutionPolicyDecision = "pass" | "hold" | "deny";

export interface PolicyBundle {
  request: Record<string, unknown>;
  policy: Record<string, unknown>;
}

export interface PolicyStageOutcome {
  stage: number;
  decision: ExecutionPolicyDecision;
  reason_code: string;
  routed_role: string;
  matched_category_count: number;
  matched_category_hashes: string[];
}

export interface ExecutionPolicyRecord {
  canonicalization_version: typeof POLICY_CANONICALIZATION_VERSION;
  sequence: number;
  surface: ExecutionPolicySurface;
  resource_id_hash: string;
  decision: ExecutionPolicyDecision;
  reason_code: string;
  request_hash: string;
  policy_hash: string;
  execution_context_hash: string;
  recorded_at: number;
  expires_at: number;
  approver_hash: string;
  approval_hash: string;
  approval_domain_hash: string;
  approver_root_hash: string;
  previous_decision_hash: string;
  decision_hash: string;
  raw_policy_egress: false;
  raw_resource_id_egress: false;
  rollback_anchor: RollbackAnchorStatus;
}

export interface PolicyEvaluation {
  surface: "policy_kernel";
  schema_version: 3;
  canonicalization_version: typeof POLICY_CANONICALIZATION_VERSION;
  approval_domain_hash: string;
  approver_root_hash: string;
  decision: ExecutionPolicyDecision;
  stage: number;
  reason_code: string;
  routed_role: string;
  request_hash: string;
  policy_hash: string;
  execution_context_hash: string;
  purpose_hash: string;
  pipeline_hash: string;
  output_schema_hash: string;
  corpus_ref_hash: string;
  outcomes: PolicyStageOutcome[];
  raw_secret_egress: false;
  raw_policy_egress: false;
  execution_binding: ExecutionPolicyRecord;
}

export interface ExecutionPolicyStatus {
  surface: "execution_policy_status";
  schema_version: 3;
  canonicalization_version: typeof POLICY_CANONICALIZATION_VERSION;
  approval_domain_hash: string;
  approver_root_hash: string;
  found: boolean;
  resource_id_hash: string;
  current_pass: boolean;
  raw_resource_id_egress: false;
  record: ExecutionPolicyRecord | null;
  rollback_anchor: RollbackAnchorStatus;
}

export interface PolicyApprovalSummary {
  canonicalization_version: typeof POLICY_CANONICALIZATION_VERSION;
  decision: ExecutionPolicyDecision;
  request_hash: string;
  policy_hash: string;
  execution_context_hash: string;
  resource_id_hash: string;
  previous_decision_hash: string;
  approval_message_hash: string;
  approval_domain_hash: string;
  approver_root_hash: string;
  expires_at: number;
  wallet_signature_required: boolean;
  rollback_anchor: RollbackAnchorStatus;
}

export interface ExecutionPolicyWorkflowResult {
  approval: PolicyApprovalSummary;
  evaluation: PolicyEvaluation;
  status: ExecutionPolicyStatus;
}

interface PolicyApprovalMessage extends PolicyApprovalSummary {
  surface: "execution_policy_approval_message";
  schema_version: 3;
  approval_message: string;
  raw_policy_egress: false;
  raw_resource_id_egress: false;
}

export interface ExecutionPolicyClientOptions {
  delegateUrl: string;
  runtimeBearer: string;
  approvalDomainHash: string;
  approverRootHash: string;
  approvedApproverHashes: readonly string[];
  anchorRelease: ExecutionPolicyAnchorRelease;
  anchorObserver?: ExecutionPolicyAnchorObserver;
  /** Required for Compute; sourced from a strictly parsed authoritative job. */
  executionContextHash?: string;
  fetchImpl?: typeof fetch;
  /**
   * Called immediately before and after every policy transport boundary. UI
   * callers use this to fail closed if wallet, chain, release, or session
   * authority changes while an exact signed intent is in flight.
   */
  assertAuthorityCurrent?: () => void;
}

export interface RunExecutionPolicyInput extends ExecutionPolicyClientOptions {
  surface: ExecutionPolicySurface;
  resourceId: string;
  expiresAt: number;
  bundle: PolicyBundle;
  approverAddress: Address | string;
  personalSign: (message: string) => Promise<Hex | string>;
  /**
   * Receives the complete immutable, memory-only intent after signing and
   * before `/policy/evaluate` is attempted. It must never be persisted or
   * rendered because it contains the private bundle and signature.
   */
  onPreparedIntent?: (intent: PreparedExecutionPolicyIntent) => void;
}

export interface PreparedPolicyApproval extends PolicyApprovalSummary {
  readonly surface: "execution_policy_approval_message";
  readonly schema_version: 3;
  readonly approval_message: string;
  readonly raw_policy_egress: false;
  readonly raw_resource_id_egress: false;
}

/**
 * Opaque, memory-only recovery authority for one exact policy decision.
 *
 * This value contains the raw private bundle, resource reference, approval
 * message, and wallet signature. Callers must keep it in component memory,
 * never serialize it, and clear it only after exact status reconciliation.
 */
export interface PreparedExecutionPolicyIntent {
  readonly schema: "dnai-wikigen/execution-policy-prepared-intent/v1";
  readonly delegateBase: string;
  readonly surface: ExecutionPolicySurface;
  readonly resourceId: string;
  readonly expiresAt: number;
  readonly bundle: PolicyBundle;
  readonly executionContextHash: string;
  readonly approverAddress: Address;
  readonly approvalSignature: string;
  readonly evaluationIdempotencyKey: string;
  readonly approval: PreparedPolicyApproval;
  readonly commitments: PolicyCommitments;
  readonly previousSequence: number;
  readonly trust: {
    readonly approvalDomainHash: string;
    readonly approverRootHash: string;
    readonly approvedApproverHashes: readonly string[];
    readonly anchorRelease: ExecutionPolicyAnchorRelease;
  };
}

export interface RecoverExecutionPolicyInput extends ExecutionPolicyClientOptions {
  readonly intent: PreparedExecutionPolicyIntent;
  readonly approverAddress: Address | string;
  /** Test-only clock override; production callers leave this unset. */
  readonly now?: number;
}

export class ExecutionPolicyRecoveryMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExecutionPolicyRecoveryMismatchError";
  }
}

export class ExecutionPolicyIntentExpiredError extends Error {
  constructor(message = "The exact execution-policy intent expired before it could be safely submitted") {
    super(message);
    this.name = "ExecutionPolicyIntentExpiredError";
  }
}

const REQUEST_FIELDS = new Set([
  "request_id",
  "requester_ref",
  "purpose",
  "pipeline",
  "data_classes",
  "output_schema",
  "operations",
  "risk_tags",
]);
const REQUEST_REQUIRED = ["request_id", "requester_ref", "purpose", "pipeline", "data_classes", "output_schema"];
const POLICY_FIELDS = new Set([
  "policy_id",
  "version",
  "corpus_ref",
  "allowed_purposes",
  "denied_purposes",
  "allowed_pipelines",
  "allowed_output_schemas",
  "allowed_operations",
  "known_data_classes",
  "restricted_categories",
  "hold_categories",
  "ambiguous_categories",
  "hold_routes",
]);
const POLICY_REQUIRED = [
  "policy_id",
  "corpus_ref",
  "allowed_purposes",
  "allowed_pipelines",
  "allowed_output_schemas",
  "allowed_operations",
  "known_data_classes",
];

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const keys = Object.keys(value);
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) {
    throw new Error(`${label} contains unsupported fields`);
  }
}

function allowedKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  required: readonly string[],
  label: string,
): void {
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.has(key)) || required.some((key) => !(key in value))) {
    throw new Error(`${label} contains unsupported or missing fields`);
  }
}

function text(value: unknown, label: string, maximum = MAX_STRING_BYTES, allowEmpty = false): string {
  if (
    typeof value !== "string"
    || (!allowEmpty && value.length === 0)
    || encoder.encode(value).byteLength > maximum
    || /[\u0000-\u001f\u007f]/.test(value)
    || hasUnpairedSurrogate(value)
  ) {
    throw new Error(`${label} is not a bounded string`);
  }
  return value;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function approvalMessageText(value: unknown): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || encoder.encode(value).byteLength > 4096
    || /[\u0000-\u0009\u000b-\u001f\u007f]/.test(value)
    || hasUnpairedSurrogate(value)
  ) {
    throw new Error("Policy approval message is not a bounded canonical string");
  }
  return value;
}

function hash(value: unknown, label: string, allowEmpty = false): string {
  if (allowEmpty && value === "") return "";
  if (typeof value !== "string" || !HASH.test(value)) throw new Error(`${label} is not lowercase SHA-256 hex`);
  return value;
}

function configuredApprovalDomainHash(value: string): string {
  return hash(value, "Release-pinned policy approval domain hash");
}

function configuredApproverHashes(value: readonly string[]): readonly string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_LIST_ITEMS) {
    throw new Error("Release-pinned policy approver hashes are unavailable");
  }
  const normalized = value.map((item) => hash(item, "Release-pinned policy approver hash"));
  if (
    new Set(normalized).size !== normalized.length
    || normalized.some((item, index) => index > 0 && normalized[index - 1] >= item)
  ) {
    throw new Error("Release-pinned policy approver hashes are not a canonical sorted set");
  }
  return normalized;
}

function integer(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`${label} is outside its bounded range`);
  }
  return Number(value);
}

function decision(value: unknown, label: string): ExecutionPolicyDecision {
  if (value !== "pass" && value !== "hold" && value !== "deny") throw new Error(`${label} is invalid`);
  return value;
}

function reasonCode(value: unknown, label: string): string {
  if (typeof value !== "string" || !REASON.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

function routedRole(value: unknown, label: string): string {
  if (
    typeof value !== "string"
    || (value !== "" && !PUBLIC_REVIEW_ROLES.includes(value as typeof PUBLIC_REVIEW_ROLES[number]))
  ) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function falseFlag(value: unknown, label: string): false {
  if (value !== false) throw new Error(`${label} must remain false`);
  return false;
}

function validateStringList(value: unknown, label: string, allowEmpty: boolean): void {
  if (!Array.isArray(value) || value.length > MAX_LIST_ITEMS || (!allowEmpty && value.length === 0)) {
    throw new Error(`${label} is not a bounded string list`);
  }
  value.forEach((item) => text(item, label));
  if (new Set(value).size !== value.length) throw new Error(`${label} contains duplicate entries`);
}

function validateKernelRecordSize(value: Record<string, unknown>, label: string): void {
  if (encoder.encode(pythonCanonicalJson(value)).byteLength > MAX_KERNEL_PAYLOAD_BYTES) {
    throw new Error(`${label} exceeds the policy-kernel payload limit`);
  }
}

function validateRequest(value: Record<string, unknown>): void {
  allowedKeys(value, REQUEST_FIELDS, REQUEST_REQUIRED, "Policy request");
  for (const key of ["request_id", "requester_ref", "purpose", "pipeline", "output_schema"]) {
    text(value[key], `Policy request ${key}`);
  }
  validateStringList(value.data_classes, "Policy request data classes", false);
  if ("operations" in value) validateStringList(value.operations, "Policy request operations", true);
  if ("risk_tags" in value) validateStringList(value.risk_tags, "Policy request risk tags", true);
  validateKernelRecordSize(value, "Policy request");
}

function validatePolicy(value: Record<string, unknown>): void {
  allowedKeys(value, POLICY_FIELDS, POLICY_REQUIRED, "Corpus policy");
  for (const key of ["policy_id", "corpus_ref"]) text(value[key], `Corpus policy ${key}`);
  if ("version" in value) text(value.version, "Corpus policy version");
  for (const key of [
    "allowed_purposes",
    "allowed_pipelines",
    "allowed_output_schemas",
    "allowed_operations",
    "known_data_classes",
  ]) validateStringList(value[key], `Corpus policy ${key}`, false);
  for (const key of ["denied_purposes", "restricted_categories", "hold_categories", "ambiguous_categories"]) {
    if (key in value) validateStringList(value[key], `Corpus policy ${key}`, true);
  }
  if ("hold_routes" in value) {
    const routes = record(value.hold_routes, "Corpus policy hold routes");
    if (Object.keys(routes).length > MAX_LIST_ITEMS) throw new Error("Corpus policy hold routes exceed the item limit");
    for (const [key, route] of Object.entries(routes)) {
      text(key, "Corpus policy hold route category");
      if (!PUBLIC_REVIEW_ROLES.includes(route as typeof PUBLIC_REVIEW_ROLES[number])) {
        throw new Error("Corpus policy hold route is not a public review role");
      }
    }
  }
  validateKernelRecordSize(value, "Corpus policy");
}

/** Parse a transient operator bundle without retaining or rendering its raw fields. */
export function parsePolicyBundleText(source: string): PolicyBundle {
  if (typeof source !== "string" || encoder.encode(source).byteLength > MAX_BUNDLE_BYTES) {
    throw new Error("Policy bundle exceeds 64 KiB");
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(source);
  } catch {
    throw new Error("Policy bundle is not valid JSON");
  }
  const root = record(decoded, "Policy bundle");
  exactKeys(root, ["request", "policy"], "Policy bundle");
  const request = record(root.request, "Policy request");
  const policy = record(root.policy, "Corpus policy");
  validateRequest(request);
  validatePolicy(policy);
  return { request, policy };
}

function surface(value: unknown, label: string): ExecutionPolicySurface {
  if (!EXECUTION_POLICY_SURFACES.includes(value as ExecutionPolicySurface)) throw new Error(`${label} is invalid`);
  return value as ExecutionPolicySurface;
}

function expectedExecutionContextHash(
  policySurface: ExecutionPolicySurface,
  value: unknown,
): string {
  if (policySurface === "compute_dispatch") {
    return hash(value, "Compute execution-policy context hash");
  }
  if (value !== undefined && value !== ZERO_DECISION_HASH) {
    throw new Error("Deal and Arena execution policy use the zero context sentinel");
  }
  return ZERO_DECISION_HASH;
}

function endpointBase(value: string): string {
  if (!value) throw new Error("Live delegate endpoint is not configured");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Live delegate endpoint is invalid");
  }
  const localHttp = parsed.protocol === "http:"
    && ["127.0.0.1", "localhost", "[::1]", "::1"].includes(parsed.hostname);
  if ((parsed.protocol !== "https:" && !localHttp) || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("Live delegate endpoint does not satisfy transport policy");
  }
  return parsed.href.replace(/\/$/, "");
}

function bearer(value: string): string {
  if (!value || value.length > 4096 || value.trim() !== value || /[\u0000-\u0020\u007f]/.test(value)) {
    throw new Error("Runtime bearer is missing or malformed");
  }
  return value;
}

function resourceId(value: string): string {
  if (!RESOURCE_ID.test(value)) throw new Error("Execution resource reference is malformed");
  return value;
}

function approverAddress(value: string): Address {
  if (!ADDRESS.test(value)) throw new Error("Connect an EIP-1193 wallet before evaluating policy");
  return value as Address;
}

function responseError(status: number): Error {
  if (status === 401 || status === 403) return new Error("Delegate refused the runtime transport credential");
  if (status === 400) return new Error("Delegate rejected or could not persist the bounded policy decision");
  if (status === 409) return new ExecutionPolicyRecoveryMismatchError("Delegate rejected a conflicting execution-policy idempotency replay");
  if (status === 503) return new Error("Execution-policy trust roots are unavailable");
  return new Error(`Delegate policy request failed with status ${status}`);
}

async function responseJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("application/json")) throw new Error("Delegate policy endpoint did not return application/json");
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) throw new Error("Delegate policy response exceeded 128 KiB");
  if (!response.body) throw new Error("Delegate policy endpoint returned an empty response");
  const reader = response.body.getReader();
  let body = "";
  let received = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("Delegate policy response exceeded 128 KiB");
      }
      body += decoder.decode(value, { stream: true });
    }
    body += decoder.decode();
  } finally {
    reader.releaseLock();
  }
  if (!response.ok) throw responseError(response.status);
  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new Error("Delegate policy endpoint returned malformed JSON");
  }
}

async function post(
  options: ExecutionPolicyClientOptions,
  path: "/policy/approval-message" | "/policy/evaluate" | "/policy/status",
  body: Record<string, unknown>,
): Promise<unknown> {
  const request = options.fetchImpl ?? fetch;
  options.assertAuthorityCurrent?.();
  const response = await request(`${endpointBase(options.delegateUrl)}${path}`, {
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${bearer(options.runtimeBearer)}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    redirect: "error",
    referrerPolicy: "no-referrer",
    signal: AbortSignal.timeout(12_000),
  });
  try {
    options.assertAuthorityCurrent?.();
    const parsed = await responseJson(response);
    options.assertAuthorityCurrent?.();
    return parsed;
  } catch (cause) {
    if (response.body && !response.body.locked) {
      try {
        await response.body.cancel();
      } catch {
        // Preserve the policy or authority error; response cleanup is best effort.
      }
    }
    throw cause;
  }
}

async function sha256Hex(value: string): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto is required to verify the approval message");
  const digest = await globalThis.crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256HexBytes(value: Uint8Array): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto is required to verify policy evidence");
  const digest = await globalThis.crypto.subtle.digest("SHA-256", value as BufferSource);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

function signatureBytes(signature: string): Uint8Array {
  if (!SIGNATURE.test(signature)) throw new Error("Wallet returned an invalid personal_sign signature");
  return Uint8Array.from(signature.slice(2).match(/.{2}/g) ?? [], (pair) => Number.parseInt(pair, 16));
}

export function executionPolicyApproverHash(address: string): Promise<string> {
  const normalized = approverAddress(address).toLowerCase();
  return sha256HexBytes(concatBytes(
    encoder.encode("dnai-wikigen/execution-policy-approver/v1"),
    new Uint8Array([0]),
    encoder.encode(normalized),
  ));
}

export function executionPolicyApproverRootHash(approverHashes: readonly string[]): Promise<string> {
  const normalized = configuredApproverHashes(approverHashes);
  return sha256HexBytes(concatBytes(
    encoder.encode("dnai-wikigen/execution-policy-approver-root/v1"),
    new Uint8Array([0]),
    encoder.encode(pythonCanonicalJson(normalized)),
  ));
}

async function configuredPolicyTrust(input: ExecutionPolicyClientOptions): Promise<{
  approvalDomainHash: string;
  approverRootHash: string;
  approvedApproverHashes: readonly string[];
  anchorRelease: ExecutionPolicyAnchorRelease;
}> {
  const approvalDomainHash = configuredApprovalDomainHash(input.approvalDomainHash);
  const approverRootHash = hash(input.approverRootHash, "Release-pinned policy approver root hash");
  const approvedApproverHashes = configuredApproverHashes(input.approvedApproverHashes);
  if (await executionPolicyApproverRootHash(approvedApproverHashes) !== approverRootHash) {
    throw new Error("Release-pinned policy approvers do not match their immutable root");
  }
  const anchorRelease = configuredExecutionPolicyAnchorRelease(input.anchorRelease);
  return { approvalDomainHash, approverRootHash, approvedApproverHashes, anchorRelease };
}

export function executionPolicySignatureHash(signature: string): Promise<string> {
  return sha256HexBytes(concatBytes(
    encoder.encode("dnai-wikigen/execution-policy-signature/v1"),
    new Uint8Array([0]),
    signatureBytes(signature),
  ));
}

function rawHashBytes(value: string, label: string): Uint8Array {
  const normalized = hash(value, label);
  return Uint8Array.from(
    normalized.match(/.{2}/g) ?? [],
    (pair) => Number.parseInt(pair, 16),
  );
}

export async function executionPolicyEvaluationIdempotencyKey(
  approvalMessageHash: string,
): Promise<string> {
  const digest = await sha256HexBytes(concatBytes(
    encoder.encode(EVALUATION_IDEMPOTENCY_DOMAIN),
    new Uint8Array([0]),
    rawHashBytes(approvalMessageHash, "Policy approval-message hash"),
  ));
  return `sha256:${digest}`;
}

function canonicalPolicyApprovalMessage(input: {
  approvalDomainHash: string;
  approverRootHash: string;
  surface: ExecutionPolicySurface;
  resourceHash: string;
  previousDecisionHash: string;
  decision: ExecutionPolicyDecision;
  requestHash: string;
  policyHash: string;
  executionContextHash: string;
  expiresAt: number;
}): string {
  const canonicalPayload: Record<string, string | number> = {
    schema: "dnai-wikigen/execution-policy-approval/v3",
    canonicalization_version: POLICY_CANONICALIZATION_VERSION,
    approval_domain_hash: input.approvalDomainHash,
    approver_root_hash: input.approverRootHash,
    surface: input.surface,
    resource_id_hash: input.resourceHash,
    previous_decision_hash: input.previousDecisionHash,
    decision: input.decision,
    request_hash: input.requestHash,
    policy_hash: input.policyHash,
    execution_context_hash: input.executionContextHash,
    expires_at: input.expiresAt,
  };
  return `DNAI Wikigen execution policy approval\n${pythonCanonicalJson(canonicalPayload)}`;
}

export async function executionPolicyDecisionHash(record: ExecutionPolicyRecord): Promise<string> {
  const core: Record<string, unknown> = {
    sequence: record.sequence,
    surface: record.surface,
    resource_id_hash: record.resource_id_hash,
    decision: record.decision,
    reason_code: record.reason_code,
    request_hash: record.request_hash,
    policy_hash: record.policy_hash,
    execution_context_hash: record.execution_context_hash,
    recorded_at: record.recorded_at,
    expires_at: record.expires_at,
    approver_hash: record.approver_hash,
    approval_hash: record.approval_hash,
    approval_domain_hash: record.approval_domain_hash,
    approver_root_hash: record.approver_root_hash,
    canonicalization_version: record.canonicalization_version,
    previous_decision_hash: record.previous_decision_hash,
  };
  return sha256HexBytes(concatBytes(
    encoder.encode("execution_policy_decision"),
    new Uint8Array([0]),
    encoder.encode(pythonCanonicalJson(core)),
  ));
}

async function verifyPolicyRecordDigest(record: ExecutionPolicyRecord): Promise<void> {
  if (await executionPolicyDecisionHash(record) !== record.decision_hash) {
    throw new Error("Execution-policy decision digest does not match its bounded record");
  }
}

async function parseApprovalMessage(
  value: unknown,
  expectedSurface: ExecutionPolicySurface,
  expectedExpiry: number,
  expectedCommitments: PolicyCommitments,
  expectedContextHash: string,
  expectedApprovalDomainHash: string,
  expectedApproverRootHash: string,
  expectedPreviousDecisionHash: string,
  expectedPreviousSequence: number,
  anchorRelease: ExecutionPolicyAnchorRelease,
  anchorObserver?: ExecutionPolicyAnchorObserver,
): Promise<PolicyApprovalMessage> {
  const item = record(value, "Policy approval-message response");
  const required = [
    "surface",
    "schema_version",
    "canonicalization_version",
    "decision",
    "request_hash",
    "policy_hash",
    "execution_context_hash",
    "resource_id_hash",
    "previous_decision_hash",
    "expires_at",
    "approval_message",
    "approval_message_hash",
    "approval_domain_hash",
    "approver_root_hash",
    "raw_policy_egress",
    "raw_resource_id_egress",
    "rollback_anchor",
  ];
  exactKeys(item, required, "Policy approval-message response");
  if (
    item.surface !== "execution_policy_approval_message"
    || item.schema_version !== 3
    || item.canonicalization_version !== POLICY_CANONICALIZATION_VERSION
  ) {
    throw new Error("Policy approval-message response identity is invalid");
  }
  const parsedDecision = decision(item.decision, "Policy approval decision");
  const requestHash = hash(item.request_hash, "Policy approval request hash");
  const policyHash = hash(item.policy_hash, "Policy approval policy hash");
  const executionContextHash = hash(
    item.execution_context_hash,
    "Policy approval execution-context hash",
  );
  const resourceHash = hash(item.resource_id_hash, "Policy approval resource hash");
  const previousDecisionHash = hash(item.previous_decision_hash, "Policy approval previous-decision hash");
  const expiresAt = integer(item.expires_at, "Policy approval expiry", 1, 4_102_444_800);
  if (expiresAt !== expectedExpiry) throw new Error("Policy approval expiry drifted from the operator request");
  const approvalDomainHash = hash(item.approval_domain_hash, "Policy approval domain hash");
  if (approvalDomainHash !== expectedApprovalDomainHash) {
    throw new Error("Delegate policy approval domain does not match the release-pinned deployment");
  }
  const approverRootHash = hash(item.approver_root_hash, "Policy approval approver-root hash");
  if (approverRootHash !== expectedApproverRootHash) {
    throw new Error("Delegate policy approver root does not match the release-pinned signer set");
  }
  if (previousDecisionHash !== expectedPreviousDecisionHash) {
    throw new Error("Policy approval preview is stale relative to the latest bounded decision");
  }
  if (
    parsedDecision !== expectedCommitments.local_evaluation.decision
    || requestHash !== expectedCommitments.request_hash
    || policyHash !== expectedCommitments.policy_hash
    || executionContextHash !== expectedContextHash
    || resourceHash !== expectedCommitments.resource_id_hash
  ) {
    throw new Error("Delegate policy approval commitments do not match the browser evaluation");
  }
  const expectedMessage = canonicalPolicyApprovalMessage({
    approvalDomainHash,
    approverRootHash,
    surface: expectedSurface,
    resourceHash,
    previousDecisionHash,
    decision: parsedDecision,
    requestHash,
    policyHash,
    executionContextHash,
    expiresAt,
  });
  const approvalMessage = approvalMessageText(item.approval_message);
  if (approvalMessage !== expectedMessage) throw new Error("Delegate returned a non-canonical policy approval message");
  const approvalMessageHash = hash(item.approval_message_hash, "Policy approval-message hash");
  if (await sha256Hex(approvalMessage) !== approvalMessageHash) {
    throw new Error("Policy approval-message hash does not match its bounded message");
  }
  const rollbackAnchor = parseRollbackAnchorStatus(item.rollback_anchor);
  await verifyRollbackAnchorStatus(
    rollbackAnchor,
    anchorRelease,
    resourceHash,
    expectedPreviousDecisionHash === ZERO_DECISION_HASH ? "" : expectedPreviousDecisionHash,
    expectedPreviousSequence,
    anchorObserver,
  );
  return {
    surface: "execution_policy_approval_message",
    schema_version: 3,
    canonicalization_version: POLICY_CANONICALIZATION_VERSION,
    decision: parsedDecision,
    request_hash: requestHash,
    policy_hash: policyHash,
    execution_context_hash: executionContextHash,
    resource_id_hash: resourceHash,
    previous_decision_hash: previousDecisionHash,
    expires_at: expiresAt,
    approval_message: approvalMessage,
    approval_message_hash: approvalMessageHash,
    approval_domain_hash: approvalDomainHash,
    approver_root_hash: approverRootHash,
    wallet_signature_required: parsedDecision === "pass",
    raw_policy_egress: falseFlag(item.raw_policy_egress, "Policy approval raw-policy egress"),
    raw_resource_id_egress: falseFlag(item.raw_resource_id_egress, "Policy approval resource-id egress"),
    rollback_anchor: rollbackAnchor,
  };
}

function parseOutcome(value: unknown): PolicyStageOutcome {
  const item = record(value, "Policy stage outcome");
  exactKeys(item, ["stage", "decision", "reason_code", "routed_role", "matched_category_count", "matched_category_hashes"], "Policy stage outcome");
  if (!Array.isArray(item.matched_category_hashes) || item.matched_category_hashes.length > MAX_LIST_ITEMS) {
    throw new Error("Policy stage outcome hashes are invalid");
  }
  const matchedHashes = item.matched_category_hashes.map((value) => hash(value, "Policy matched-category hash"));
  const matchedCount = integer(item.matched_category_count, "Policy matched-category count", 0, MAX_LIST_ITEMS);
  if (matchedCount !== matchedHashes.length) throw new Error("Policy matched-category count is inconsistent");
  return {
    stage: integer(item.stage, "Policy outcome stage", 0, 4),
    decision: decision(item.decision, "Policy outcome decision"),
    reason_code: reasonCode(item.reason_code, "Policy outcome reason"),
    routed_role: routedRole(item.routed_role, "Policy outcome route"),
    matched_category_count: matchedCount,
    matched_category_hashes: matchedHashes,
  };
}

function parsePolicyRecord(value: unknown): ExecutionPolicyRecord {
  const item = record(value, "Execution-policy binding");
  const required = [
    "canonicalization_version",
    "sequence",
    "surface",
    "resource_id_hash",
    "decision",
    "reason_code",
    "request_hash",
    "policy_hash",
    "execution_context_hash",
    "recorded_at",
    "expires_at",
    "approver_hash",
    "approval_hash",
    "approval_domain_hash",
    "approver_root_hash",
    "previous_decision_hash",
    "decision_hash",
    "raw_policy_egress",
    "raw_resource_id_egress",
    "rollback_anchor",
  ];
  exactKeys(item, required, "Execution-policy binding");
  if (item.canonicalization_version !== POLICY_CANONICALIZATION_VERSION) {
    throw new Error("Execution-policy binding canonicalization version is invalid");
  }
  const parsedDecision = decision(item.decision, "Execution-policy binding decision");
  const recordedAt = integer(item.recorded_at, "Execution-policy recorded time", 1, 4_102_444_800);
  const expiresAt = integer(item.expires_at, "Execution-policy expiry", 1, 4_102_444_800);
  if (expiresAt <= recordedAt) throw new Error("Execution-policy binding expiry is invalid");
  const approverHash = hash(item.approver_hash, "Execution-policy approver hash", parsedDecision !== "pass");
  const approvalHash = hash(item.approval_hash, "Execution-policy approval hash", parsedDecision !== "pass");
  const approvalDomainHash = hash(item.approval_domain_hash, "Execution-policy approval domain hash", parsedDecision !== "pass");
  const approverRootHash = hash(item.approver_root_hash, "Execution-policy approver-root hash", parsedDecision !== "pass");
  if (parsedDecision !== "pass" && (approverHash || approvalHash || approvalDomainHash || approverRootHash)) {
    throw new Error("A non-pass execution-policy binding carries approval evidence");
  }
  return {
    canonicalization_version: POLICY_CANONICALIZATION_VERSION,
    sequence: integer(item.sequence, "Execution-policy binding sequence", 1, 20_000),
    surface: surface(item.surface, "Execution-policy binding surface"),
    resource_id_hash: hash(item.resource_id_hash, "Execution-policy resource hash"),
    decision: parsedDecision,
    reason_code: reasonCode(item.reason_code, "Execution-policy reason"),
    request_hash: hash(item.request_hash, "Execution-policy request hash"),
    policy_hash: hash(item.policy_hash, "Execution-policy policy hash"),
    execution_context_hash: hash(
      item.execution_context_hash,
      "Execution-policy execution-context hash",
    ),
    recorded_at: recordedAt,
    expires_at: expiresAt,
    approver_hash: approverHash,
    approval_hash: approvalHash,
    approval_domain_hash: approvalDomainHash,
    approver_root_hash: approverRootHash,
    previous_decision_hash: hash(item.previous_decision_hash, "Execution-policy previous-decision hash"),
    decision_hash: hash(item.decision_hash, "Execution-policy decision hash"),
    raw_policy_egress: falseFlag(item.raw_policy_egress, "Execution-policy raw-policy egress"),
    raw_resource_id_egress: falseFlag(item.raw_resource_id_egress, "Execution-policy resource-id egress"),
    rollback_anchor: parseRollbackAnchorStatus(item.rollback_anchor),
  };
}

async function parseEvaluation(
  value: unknown,
  expectedSurface: ExecutionPolicySurface,
  expectedCommitments: PolicyCommitments,
  expectedContextHash: string,
  expectedApprovalDomainHash: string,
  expectedApproverRootHash: string,
  expectedApproverHashes: readonly string[],
  expectedExpiry: number,
  expectedPreviousDecisionHash: string,
  anchorRelease: ExecutionPolicyAnchorRelease,
  anchorObserver?: ExecutionPolicyAnchorObserver,
): Promise<PolicyEvaluation> {
  const item = record(value, "Policy evaluation response");
  exactKeys(item, [
    "surface",
    "schema_version",
    "canonicalization_version",
    "approval_domain_hash",
    "approver_root_hash",
    "decision",
    "stage",
    "reason_code",
    "routed_role",
    "request_hash",
    "policy_hash",
    "execution_context_hash",
    "purpose_hash",
    "pipeline_hash",
    "output_schema_hash",
    "outcomes",
    "raw_secret_egress",
    "corpus_ref_hash",
    "raw_policy_egress",
    "execution_binding",
  ], "Policy evaluation response");
  if (
    item.surface !== "policy_kernel"
    || item.schema_version !== 3
    || item.canonicalization_version !== POLICY_CANONICALIZATION_VERSION
    || !Array.isArray(item.outcomes)
    || item.outcomes.length < 1
    || item.outcomes.length > 5
  ) {
    throw new Error("Policy evaluation response identity is invalid");
  }
  const approvalDomainHash = hash(item.approval_domain_hash, "Policy evaluation approval domain hash");
  if (approvalDomainHash !== expectedApprovalDomainHash) {
    throw new Error("Policy evaluation approval domain drifted from the release-pinned deployment");
  }
  const approverRootHash = hash(item.approver_root_hash, "Policy evaluation approver-root hash");
  if (approverRootHash !== expectedApproverRootHash) {
    throw new Error("Policy evaluation approver root drifted from the release-pinned signer set");
  }
  const parsedDecision = decision(item.decision, "Policy evaluation decision");
  const parsedStage = integer(item.stage, "Policy evaluation stage", 0, 4);
  const parsedReason = reasonCode(item.reason_code, "Policy evaluation reason");
  const parsedRoute = routedRole(item.routed_role, "Policy evaluation route");
  const requestHash = hash(item.request_hash, "Policy evaluation request hash");
  const policyHash = hash(item.policy_hash, "Policy evaluation policy hash");
  const executionContextHash = hash(
    item.execution_context_hash,
    "Policy evaluation execution-context hash",
  );
  const purposeHash = hash(item.purpose_hash, "Policy purpose hash");
  const pipelineHash = hash(item.pipeline_hash, "Policy pipeline hash");
  const outputSchemaHash = hash(item.output_schema_hash, "Policy output-schema hash");
  const corpusRefHash = hash(item.corpus_ref_hash, "Policy corpus-reference hash");
  const outcomes = item.outcomes.map(parseOutcome);
  const binding = parsePolicyRecord(item.execution_binding);
  const local = expectedCommitments.local_evaluation;
  if (
    parsedDecision !== local.decision
    || parsedStage !== local.stage
    || parsedReason !== local.reason_code
    || parsedRoute !== local.routed_role
    || pythonCanonicalJson(outcomes) !== pythonCanonicalJson(local.outcomes)
    || requestHash !== expectedCommitments.request_hash
    || policyHash !== expectedCommitments.policy_hash
    || executionContextHash !== expectedContextHash
    || purposeHash !== expectedCommitments.purpose_hash
    || pipelineHash !== expectedCommitments.pipeline_hash
    || outputSchemaHash !== expectedCommitments.output_schema_hash
    || corpusRefHash !== expectedCommitments.corpus_ref_hash
  ) {
    throw new Error("Policy evaluation does not match the browser's deterministic evaluation");
  }
  if (
    binding.canonicalization_version !== POLICY_CANONICALIZATION_VERSION
    || binding.surface !== expectedSurface
    || binding.resource_id_hash !== expectedCommitments.resource_id_hash
    || binding.decision !== parsedDecision
    || binding.reason_code !== parsedReason
    || binding.request_hash !== requestHash
    || binding.policy_hash !== policyHash
    || binding.execution_context_hash !== executionContextHash
    || binding.expires_at !== expectedExpiry
    || binding.previous_decision_hash !== expectedPreviousDecisionHash
    || (parsedDecision === "pass"
      ? binding.approval_domain_hash !== expectedApprovalDomainHash
      : binding.approval_domain_hash !== "")
    || (parsedDecision === "pass"
      ? binding.approver_root_hash !== expectedApproverRootHash
      : binding.approver_root_hash !== "")
    || (parsedDecision === "pass" && !expectedApproverHashes.includes(binding.approver_hash))
  ) {
    throw new Error("Policy evaluation binding does not match its bounded decision");
  }
  await verifyRollbackAnchorStatus(
    binding.rollback_anchor,
    anchorRelease,
    binding.resource_id_hash,
    binding.decision_hash,
    binding.sequence,
    anchorObserver,
  );
  return {
    surface: "policy_kernel",
    schema_version: 3,
    canonicalization_version: POLICY_CANONICALIZATION_VERSION,
    approval_domain_hash: approvalDomainHash,
    approver_root_hash: approverRootHash,
    decision: parsedDecision,
    stage: parsedStage,
    reason_code: parsedReason,
    routed_role: parsedRoute,
    request_hash: requestHash,
    policy_hash: policyHash,
    execution_context_hash: executionContextHash,
    purpose_hash: purposeHash,
    pipeline_hash: pipelineHash,
    output_schema_hash: outputSchemaHash,
    corpus_ref_hash: corpusRefHash,
    outcomes,
    raw_secret_egress: falseFlag(item.raw_secret_egress, "Policy secret egress"),
    raw_policy_egress: falseFlag(item.raw_policy_egress, "Policy raw-policy egress"),
    execution_binding: binding,
  };
}

async function parseStatus(
  value: unknown,
  expectedSurface: ExecutionPolicySurface,
  expectedResourceHash: string,
  expectedContextHash: string,
  expectedApprovalDomainHash: string,
  expectedApproverRootHash: string,
  expectedApproverHashes: readonly string[],
  anchorRelease: ExecutionPolicyAnchorRelease,
  anchorObserver?: ExecutionPolicyAnchorObserver,
): Promise<ExecutionPolicyStatus> {
  const item = record(value, "Execution-policy status response");
  exactKeys(item, [
    "surface",
    "schema_version",
    "canonicalization_version",
    "approval_domain_hash",
    "approver_root_hash",
    "found",
    "resource_id_hash",
    "current_pass",
    "raw_resource_id_egress",
    "record",
    "rollback_anchor",
  ], "Execution-policy status response");
  if (
    item.surface !== "execution_policy_status"
    || item.schema_version !== 3
    || item.canonicalization_version !== POLICY_CANONICALIZATION_VERSION
    || typeof item.found !== "boolean"
    || typeof item.current_pass !== "boolean"
  ) {
    throw new Error("Execution-policy status response identity is invalid");
  }
  const approvalDomainHash = hash(item.approval_domain_hash, "Execution-policy status approval domain hash");
  if (approvalDomainHash !== expectedApprovalDomainHash) {
    throw new Error("Execution-policy status approval domain drifted from the release-pinned deployment");
  }
  const approverRootHash = hash(item.approver_root_hash, "Execution-policy status approver-root hash");
  if (approverRootHash !== expectedApproverRootHash) {
    throw new Error("Execution-policy status approver root drifted from the release-pinned signer set");
  }
  const resourceHash = hash(item.resource_id_hash, "Execution-policy status resource hash");
  const parsedRecord = item.record === null ? null : parsePolicyRecord(item.record);
  const rollbackAnchor = parseRollbackAnchorStatus(item.rollback_anchor);
  const now = Math.floor(Date.now() / 1000);
  if (
    resourceHash !== expectedResourceHash
    || item.found !== Boolean(parsedRecord)
    || (!item.found && item.current_pass)
    || (parsedRecord && (parsedRecord.surface !== expectedSurface || parsedRecord.resource_id_hash !== resourceHash))
    || (item.current_pass && parsedRecord?.decision !== "pass")
    || (item.current_pass && parsedRecord?.approval_domain_hash !== approvalDomainHash)
    || (item.current_pass && parsedRecord?.execution_context_hash !== expectedContextHash)
    || (item.current_pass && parsedRecord?.approver_root_hash !== approverRootHash)
    || (item.current_pass && !expectedApproverHashes.includes(parsedRecord?.approver_hash ?? ""))
    || (item.current_pass && (parsedRecord?.expires_at ?? 0) <= now)
    || ((parsedRecord?.recorded_at ?? 0) > now + 30)
  ) throw new Error("Execution-policy status response is inconsistent");
  if (
    parsedRecord
    && pythonCanonicalJson(parsedRecord.rollback_anchor) !== pythonCanonicalJson(rollbackAnchor)
  ) throw new Error("Execution-policy status carries conflicting rollback anchors");
  await verifyRollbackAnchorStatus(
    rollbackAnchor,
    anchorRelease,
    resourceHash,
    parsedRecord?.decision_hash ?? "",
    parsedRecord?.sequence ?? 0,
    anchorObserver,
  );
  return {
    surface: "execution_policy_status",
    schema_version: 3,
    canonicalization_version: POLICY_CANONICALIZATION_VERSION,
    approval_domain_hash: approvalDomainHash,
    approver_root_hash: approverRootHash,
    found: item.found,
    resource_id_hash: resourceHash,
    current_pass: item.current_pass,
    raw_resource_id_egress: falseFlag(item.raw_resource_id_egress, "Execution-policy status resource-id egress"),
    record: parsedRecord,
    rollback_anchor: rollbackAnchor,
  };
}

function coreRequest(input: {
  surface: ExecutionPolicySurface;
  resourceId: string;
  expiresAt: number;
  bundle: PolicyBundle;
}): Record<string, unknown> {
  surface(input.surface, "Execution-policy surface");
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = integer(input.expiresAt, "Execution-policy expiry", now + 30, now + 30 * 24 * 60 * 60);
  validateRequest(input.bundle.request);
  validatePolicy(input.bundle.policy);
  return {
    surface: input.surface,
    resource_id: resourceId(input.resourceId),
    expires_at: expiresAt,
    request: input.bundle.request,
    policy: input.bundle.policy,
  };
}

export async function readExecutionPolicyStatus(input: ExecutionPolicyClientOptions & {
  surface: ExecutionPolicySurface;
  resourceId: string;
}): Promise<ExecutionPolicyStatus> {
  const expectedSurface = surface(input.surface, "Execution-policy surface");
  const expectedResourceId = resourceId(input.resourceId);
  const expectedContextHash = expectedExecutionContextHash(
    expectedSurface,
    input.executionContextHash,
  );
  const trust = await configuredPolicyTrust(input);
  const expectedResourceHash = await computeExecutionResourceHash(expectedSurface, expectedResourceId);
  const body = { surface: expectedSurface, resource_id: expectedResourceId };
  const parsed = await parseStatus(
    await post(input, "/policy/status", body),
    expectedSurface,
    expectedResourceHash,
    expectedContextHash,
    trust.approvalDomainHash,
    trust.approverRootHash,
    trust.approvedApproverHashes,
    trust.anchorRelease,
    input.anchorObserver,
  );
  if (parsed.record) await verifyPolicyRecordDigest(parsed.record);
  return parsed;
}

function deepFreezeIntentValue<T>(value: T): T {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value as Record<string, unknown>)) {
    deepFreezeIntentValue(nested);
  }
  return Object.freeze(value);
}

function clonePrivatePolicyBundle(value: PolicyBundle): PolicyBundle {
  // The strict parser both validates and creates a detached copy, preventing
  // caller mutation from changing an intent after wallet approval.
  return parsePolicyBundleText(JSON.stringify(value));
}

function exactIntentCoreRequest(intent: PreparedExecutionPolicyIntent): Record<string, unknown> {
  if (intent.schema !== "dnai-wikigen/execution-policy-prepared-intent/v1") {
    throw new ExecutionPolicyRecoveryMismatchError("Execution-policy recovery intent identity is invalid");
  }
  const expectedSurface = surface(intent.surface, "Prepared execution-policy surface");
  const expectedResourceId = resourceId(intent.resourceId);
  const expiresAt = integer(
    intent.expiresAt,
    "Prepared execution-policy expiry",
    1,
    4_102_444_800,
  );
  validateRequest(intent.bundle.request);
  validatePolicy(intent.bundle.policy);
  return {
    surface: expectedSurface,
    resource_id: expectedResourceId,
    expires_at: expiresAt,
    request: intent.bundle.request,
    policy: intent.bundle.policy,
  };
}

function approvalSummary(approval: PreparedPolicyApproval): PolicyApprovalSummary {
  return {
    decision: approval.decision,
    canonicalization_version: approval.canonicalization_version,
    request_hash: approval.request_hash,
    policy_hash: approval.policy_hash,
    execution_context_hash: approval.execution_context_hash,
    resource_id_hash: approval.resource_id_hash,
    previous_decision_hash: approval.previous_decision_hash,
    approval_message_hash: approval.approval_message_hash,
    approval_domain_hash: approval.approval_domain_hash,
    approver_root_hash: approval.approver_root_hash,
    expires_at: approval.expires_at,
    wallet_signature_required: approval.wallet_signature_required,
    rollback_anchor: approval.rollback_anchor,
  };
}

async function assertPreparedIntentContext(
  input: RecoverExecutionPolicyInput,
): Promise<{
  trust: Awaited<ReturnType<typeof configuredPolicyTrust>>;
  expectedApproverHash: string;
  expectedApprovalHash: string;
}> {
  const intent = input.intent;
  const body = exactIntentCoreRequest(intent);
  if (endpointBase(input.delegateUrl) !== intent.delegateBase) {
    throw new ExecutionPolicyRecoveryMismatchError("Delegate release endpoint changed after policy approval");
  }
  const trust = await configuredPolicyTrust(input);
  if (
    trust.approvalDomainHash !== intent.trust.approvalDomainHash
    || trust.approverRootHash !== intent.trust.approverRootHash
    || pythonCanonicalJson(trust.approvedApproverHashes)
      !== pythonCanonicalJson(intent.trust.approvedApproverHashes)
    || pythonCanonicalJson(trust.anchorRelease)
      !== pythonCanonicalJson(intent.trust.anchorRelease)
  ) {
    throw new ExecutionPolicyRecoveryMismatchError("Execution-policy release authority changed after approval");
  }
  const expectedApprover = approverAddress(input.approverAddress);
  if (expectedApprover.toLowerCase() !== intent.approverAddress.toLowerCase()) {
    throw new ExecutionPolicyRecoveryMismatchError("Connected approver changed after policy approval");
  }
  const expectedApproverHash = await executionPolicyApproverHash(expectedApprover);
  if (!trust.approvedApproverHashes.includes(expectedApproverHash)) {
    throw new ExecutionPolicyRecoveryMismatchError("Prepared approver is no longer in the immutable signer set");
  }
  const expectedContextHash = expectedExecutionContextHash(
    intent.surface,
    input.executionContextHash,
  );
  if (expectedContextHash !== intent.executionContextHash) {
    throw new ExecutionPolicyRecoveryMismatchError("Execution context changed after policy approval");
  }
  const commitments = await computePolicyCommitments(
    intent.bundle,
    intent.surface,
    intent.resourceId,
  );
  if (pythonCanonicalJson(commitments) !== pythonCanonicalJson(intent.commitments)) {
    throw new ExecutionPolicyRecoveryMismatchError("Prepared private policy bundle changed after approval");
  }
  const approval = intent.approval;
  if (
    approval.surface !== "execution_policy_approval_message"
    || approval.schema_version !== 3
    || approval.expires_at !== intent.expiresAt
    || approval.decision !== commitments.local_evaluation.decision
    || approval.request_hash !== commitments.request_hash
    || approval.policy_hash !== commitments.policy_hash
    || approval.execution_context_hash !== intent.executionContextHash
    || approval.resource_id_hash !== commitments.resource_id_hash
    || approval.approval_domain_hash !== trust.approvalDomainHash
    || approval.approver_root_hash !== trust.approverRootHash
  ) {
    throw new ExecutionPolicyRecoveryMismatchError("Prepared approval commitments changed after wallet consent");
  }
  const expectedMessage = canonicalPolicyApprovalMessage({
    approvalDomainHash: approval.approval_domain_hash,
    approverRootHash: approval.approver_root_hash,
    surface: intent.surface,
    resourceHash: approval.resource_id_hash,
    previousDecisionHash: approval.previous_decision_hash,
    decision: approval.decision,
    requestHash: approval.request_hash,
    policyHash: approval.policy_hash,
    executionContextHash: approval.execution_context_hash,
    expiresAt: approval.expires_at,
  });
  if (
    expectedMessage !== approval.approval_message
    || await sha256Hex(expectedMessage) !== approval.approval_message_hash
  ) {
    throw new ExecutionPolicyRecoveryMismatchError("Prepared approval message is not canonical");
  }
  const expectedIdempotencyKey = await executionPolicyEvaluationIdempotencyKey(
    approval.approval_message_hash,
  );
  if (
    !EVALUATION_IDEMPOTENCY_KEY.test(intent.evaluationIdempotencyKey)
    || intent.evaluationIdempotencyKey !== expectedIdempotencyKey
  ) {
    throw new ExecutionPolicyRecoveryMismatchError("Prepared policy idempotency commitment changed");
  }
  let expectedApprovalHash = "";
  if (approval.decision === "pass") {
    if (!SIGNATURE.test(intent.approvalSignature)) {
      throw new ExecutionPolicyRecoveryMismatchError("Prepared wallet signature is invalid");
    }
    let recovered: Address;
    try {
      recovered = await recoverMessageAddress({
        message: approval.approval_message,
        signature: intent.approvalSignature as Hex,
      });
    } catch {
      throw new ExecutionPolicyRecoveryMismatchError("Prepared wallet signature cannot be recovered");
    }
    if (recovered.toLowerCase() !== expectedApprover.toLowerCase()) {
      throw new ExecutionPolicyRecoveryMismatchError("Prepared wallet signature belongs to another approver");
    }
    expectedApprovalHash = await executionPolicySignatureHash(intent.approvalSignature);
  } else if (intent.approvalSignature) {
    throw new ExecutionPolicyRecoveryMismatchError("A non-pass intent carries wallet approval evidence");
  }
  if (
    body.expires_at !== approval.expires_at
    || body.surface !== intent.surface
    || body.resource_id !== intent.resourceId
  ) {
    throw new ExecutionPolicyRecoveryMismatchError("Prepared request body changed after approval");
  }
  input.assertAuthorityCurrent?.();
  return { trust, expectedApproverHash, expectedApprovalHash };
}

async function statusMatchesPreparedIntent(
  status: ExecutionPolicyStatus,
  intent: PreparedExecutionPolicyIntent,
  expectedApproverHash: string,
  expectedApprovalHash: string,
): Promise<boolean> {
  const binding = status.record;
  const local = intent.commitments.local_evaluation;
  if (
    !status.found
    || !binding
    || status.resource_id_hash !== intent.approval.resource_id_hash
    || binding.surface !== intent.surface
    || binding.resource_id_hash !== intent.approval.resource_id_hash
    || binding.decision !== intent.approval.decision
    || binding.reason_code !== local.reason_code
    || binding.request_hash !== intent.approval.request_hash
    || binding.policy_hash !== intent.approval.policy_hash
    || binding.execution_context_hash !== intent.executionContextHash
    || binding.expires_at !== intent.expiresAt
    || binding.previous_decision_hash !== intent.approval.previous_decision_hash
    || (binding.decision === "pass"
      ? (
        binding.approver_hash !== expectedApproverHash
        || binding.approval_hash !== expectedApprovalHash
        || binding.approval_domain_hash !== intent.trust.approvalDomainHash
        || binding.approver_root_hash !== intent.trust.approverRootHash
      )
      : Boolean(
        binding.approver_hash
        || binding.approval_hash
        || binding.approval_domain_hash
        || binding.approver_root_hash,
      ))
  ) return false;
  await verifyPolicyRecordDigest(binding);
  return true;
}

function statusMatchesPreparedPrior(
  status: ExecutionPolicyStatus,
  intent: PreparedExecutionPolicyIntent,
): boolean {
  if (intent.approval.previous_decision_hash === ZERO_DECISION_HASH) {
    return !status.found
      && status.record === null
      && status.rollback_anchor.resource_sequence === 0;
  }
  return Boolean(
    status.found
    && status.record
    && status.record.decision_hash === intent.approval.previous_decision_hash
    && status.record.sequence === intent.previousSequence,
  );
}

function workflowFromReconciledStatus(
  intent: PreparedExecutionPolicyIntent,
  status: ExecutionPolicyStatus,
): ExecutionPolicyWorkflowResult {
  if (!status.record) {
    throw new ExecutionPolicyRecoveryMismatchError("Reconciled policy status has no decision record");
  }
  const local = intent.commitments.local_evaluation;
  return {
    approval: approvalSummary(intent.approval),
    evaluation: {
      surface: "policy_kernel",
      schema_version: 3,
      canonicalization_version: POLICY_CANONICALIZATION_VERSION,
      approval_domain_hash: intent.trust.approvalDomainHash,
      approver_root_hash: intent.trust.approverRootHash,
      decision: local.decision,
      stage: local.stage,
      reason_code: local.reason_code,
      routed_role: local.routed_role,
      request_hash: intent.commitments.request_hash,
      policy_hash: intent.commitments.policy_hash,
      execution_context_hash: intent.executionContextHash,
      purpose_hash: intent.commitments.purpose_hash,
      pipeline_hash: intent.commitments.pipeline_hash,
      output_schema_hash: intent.commitments.output_schema_hash,
      corpus_ref_hash: intent.commitments.corpus_ref_hash,
      outcomes: local.outcomes,
      raw_secret_egress: false,
      raw_policy_egress: false,
      execution_binding: status.record,
    },
    status,
  };
}

export async function prepareExecutionPolicyIntent(
  input: RunExecutionPolicyInput,
): Promise<PreparedExecutionPolicyIntent> {
  const expectedApprover = approverAddress(input.approverAddress);
  const trust = await configuredPolicyTrust(input);
  const expectedApproverHash = await executionPolicyApproverHash(expectedApprover);
  if (!trust.approvedApproverHashes.includes(expectedApproverHash)) {
    throw new Error("Connected policy approver is not part of this release's immutable signer set");
  }
  if (typeof input.personalSign !== "function") {
    throw new Error("Connected wallet personal_sign is required");
  }
  const privateBundle = clonePrivatePolicyBundle(input.bundle);
  const stableInput = { ...input, bundle: privateBundle };
  const body = coreRequest(stableInput);
  const expiresAt = body.expires_at as number;
  const commitments = await computePolicyCommitments(
    privateBundle,
    input.surface,
    input.resourceId,
  );
  const executionContextHash = expectedExecutionContextHash(
    input.surface,
    input.executionContextHash,
  );
  const priorStatus = await readExecutionPolicyStatus(stableInput);
  const previousDecisionHash = priorStatus.record?.decision_hash ?? ZERO_DECISION_HASH;
  const approval = await parseApprovalMessage(
    await post(stableInput, "/policy/approval-message", body),
    input.surface,
    expiresAt,
    commitments,
    executionContextHash,
    trust.approvalDomainHash,
    trust.approverRootHash,
    previousDecisionHash,
    priorStatus.record?.sequence ?? 0,
    trust.anchorRelease,
    input.anchorObserver,
  );

  let signature = "";
  if (approval.decision === "pass") {
    input.assertAuthorityCurrent?.();
    const signed = await input.personalSign(approval.approval_message);
    input.assertAuthorityCurrent?.();
    if (typeof signed !== "string" || !SIGNATURE.test(signed)) {
      throw new Error("Wallet returned an invalid personal_sign signature");
    }
    let recovered: Address;
    try {
      recovered = await recoverMessageAddress({
        message: approval.approval_message,
        signature: signed as Hex,
      });
    } catch {
      throw new Error("Wallet returned a personal_sign signature that cannot be recovered");
    }
    if (recovered.toLowerCase() !== expectedApprover.toLowerCase()) {
      throw new Error("Wallet personal_sign signature does not match the connected approver");
    }
    signature = signed;
  }
  const intent: PreparedExecutionPolicyIntent = {
    schema: "dnai-wikigen/execution-policy-prepared-intent/v1",
    delegateBase: endpointBase(input.delegateUrl),
    surface: input.surface,
    resourceId: input.resourceId,
    expiresAt,
    bundle: privateBundle,
    executionContextHash,
    approverAddress: expectedApprover,
    approvalSignature: signature,
    evaluationIdempotencyKey: await executionPolicyEvaluationIdempotencyKey(
      approval.approval_message_hash,
    ),
    approval,
    commitments,
    previousSequence: priorStatus.record?.sequence ?? 0,
    trust: {
      approvalDomainHash: trust.approvalDomainHash,
      approverRootHash: trust.approverRootHash,
      approvedApproverHashes: [...trust.approvedApproverHashes],
      anchorRelease: { ...trust.anchorRelease },
    },
  };
  return deepFreezeIntentValue(intent);
}

export async function submitPreparedExecutionPolicyIntent(
  input: RecoverExecutionPolicyInput,
): Promise<ExecutionPolicyWorkflowResult> {
  const { intent } = input;
  const {
    trust,
    expectedApproverHash,
    expectedApprovalHash,
  } = await assertPreparedIntentContext(input);
  const now = input.now ?? Math.floor(Date.now() / 1_000);
  if (intent.expiresAt <= now) throw new ExecutionPolicyIntentExpiredError();
  const body = exactIntentCoreRequest(intent);
  const evaluation = await parseEvaluation(
    await post(input, "/policy/evaluate", {
      ...body,
      approver_address: intent.approval.decision === "pass"
        ? intent.approverAddress
        : "",
      approval_signature: intent.approvalSignature,
      previous_decision_hash: intent.approval.previous_decision_hash,
      idempotency_key: intent.evaluationIdempotencyKey,
    }),
    intent.surface,
    intent.commitments,
    intent.executionContextHash,
    trust.approvalDomainHash,
    trust.approverRootHash,
    trust.approvedApproverHashes,
    intent.expiresAt,
    intent.approval.previous_decision_hash,
    trust.anchorRelease,
    input.anchorObserver,
  );
  await verifyPolicyRecordDigest(evaluation.execution_binding);
  if (
    evaluation.decision === "pass"
    && (
      evaluation.execution_binding.approver_hash !== expectedApproverHash
      || evaluation.execution_binding.approval_hash !== expectedApprovalHash
    )
  ) {
    throw new Error("Persisted execution-policy signer evidence does not match the wallet approval");
  }
  if (
    evaluation.decision !== intent.approval.decision
    || evaluation.request_hash !== intent.approval.request_hash
    || evaluation.policy_hash !== intent.approval.policy_hash
    || evaluation.execution_context_hash !== intent.approval.execution_context_hash
    || evaluation.execution_binding.resource_id_hash !== intent.approval.resource_id_hash
  ) throw new Error("Policy evaluation drifted from the wallet approval message");
  const status = await readExecutionPolicyStatus({
    ...input,
    surface: intent.surface,
    resourceId: intent.resourceId,
  });
  if (
    !await statusMatchesPreparedIntent(
      status,
      intent,
      expectedApproverHash,
      expectedApprovalHash,
    )
    || status.record?.decision_hash !== evaluation.execution_binding.decision_hash
  ) {
    throw new ExecutionPolicyRecoveryMismatchError(
      "Latest execution-policy status does not match the exact persisted intent",
    );
  }
  return { approval: approvalSummary(intent.approval), evaluation, status };
}

/**
 * Recover one ambiguous evaluation without generating a new approval, expiry,
 * signature, previous-head binding, or idempotency commitment.
 *
 * Recovery reads the exact resource first. An exact committed record is
 * reconstructed from the browser-verified deterministic commitments and the
 * independently verified status. Only an unchanged prior head permits replay
 * of the byte-identical mutation.
 */
export async function recoverExecutionPolicyWorkflow(
  input: RecoverExecutionPolicyInput,
): Promise<ExecutionPolicyWorkflowResult> {
  const {
    expectedApproverHash,
    expectedApprovalHash,
  } = await assertPreparedIntentContext(input);
  const status = await readExecutionPolicyStatus({
    ...input,
    surface: input.intent.surface,
    resourceId: input.intent.resourceId,
  });
  if (await statusMatchesPreparedIntent(
    status,
    input.intent,
    expectedApproverHash,
    expectedApprovalHash,
  )) {
    return workflowFromReconciledStatus(input.intent, status);
  }
  if (!statusMatchesPreparedPrior(status, input.intent)) {
    throw new ExecutionPolicyRecoveryMismatchError(
      "The current execution-policy head matches neither the retained intent nor its exact prior head",
    );
  }
  const now = input.now ?? Math.floor(Date.now() / 1_000);
  if (input.intent.expiresAt <= now) throw new ExecutionPolicyIntentExpiredError();
  return submitPreparedExecutionPolicyIntent(input);
}

/**
 * Evaluate and persist one decision. PASS cannot reach `/policy/evaluate`
 * until the connected EIP-1193 wallet has signed the delegate's exact hash-only
 * personal-sign message. The prepared private intent is delivered to the
 * caller before mutation so an ambiguous response can be reconciled exactly.
 * The returned object contains no bearer, resource ID, raw request, raw policy,
 * approval message, or signature.
 */
export async function runExecutionPolicyWorkflow(
  input: RunExecutionPolicyInput,
): Promise<ExecutionPolicyWorkflowResult> {
  const intent = await prepareExecutionPolicyIntent(input);
  input.assertAuthorityCurrent?.();
  input.onPreparedIntent?.(intent);
  input.assertAuthorityCurrent?.();
  return submitPreparedExecutionPolicyIntent({
    ...input,
    intent,
    approverAddress: input.approverAddress,
  });
}
