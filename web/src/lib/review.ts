import type { Address, Hex } from "viem";
import { computeWorkloadDeployment, deployment } from "../config";
import { publicErrorText } from "./errorText";
import {
  parseRollbackAnchorStatus,
  verifyRollbackAnchorStatus,
  type RollbackAnchorStatus,
} from "./executionPolicyAnchor";

const MAX_RESPONSE_BYTES = 512 * 1024;
const HASH = /^[0-9a-f]{64}$/;
const NONZERO_HASH = /^(?!0{64}$)[0-9a-f]{64}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const ROLE = /^[a-z][a-z0-9-]{1,63}$/;
const CVM_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;

export const REVIEW_QUEUE_DEFAULT_PAGE_SIZE = 25;
export const REVIEW_QUEUE_MAX_PAGE_SIZE = 50;

declare const REVIEW_QUEUE_CURSOR_BRAND: unique symbol;

/**
 * An unmodified continuation returned by the review service.
 *
 * The browser validates the bounded wire shape, but never derives meaning from
 * the token or manufactures one from a ticket identifier.
 */
export type ReviewQueueCursor = string & {
  readonly [REVIEW_QUEUE_CURSOR_BRAND]: "ReviewQueueCursor";
};

export type ReviewDecision = "release" | "deny";
export type ReviewTicketStatus = "pending" | "released" | "denied" | "expired";

export interface ReviewTicket {
  ticket_ref_hash: string;
  turn_ref_hash: string;
  corpus_ref_hash: string;
  routed_role: string;
  reason_hash: string;
  opened_at: number;
  expires_at: number;
  status: ReviewTicketStatus;
  reviewer_ref_hash: string;
  submitter_ref_hash: string;
  required_approvals: number;
  approvals_count: number;
  approval_reviewer_hashes: readonly string[];
  approval_authorization_hashes: readonly string[];
  reviewer_authorization_hash: string;
  authority_context_hash: string;
  decision_hash: string;
  updated_at: number;
  raw_secret_egress: false;
}

export interface ReviewRoleAuthority {
  role: string;
  threshold: number;
  reviewer_count: number;
  reviewer_set_hash: string;
}

export interface ReviewReleaseContext {
  schema: "dnai.review-release-context.v1";
  chain_id: 84532;
  wallet_domain: string;
  wallet_uri: string;
  main_runtime_cvm_id: string;
  deployment_intent_sha256: string;
  release_authority_sha256: string;
  ceremony_nonce: Hex;
}

export interface ReviewRollbackAnchor {
  schema: "dnai.review-queue-rollback-anchor.v1";
  state_hash: string;
  decision_hash: string;
  sequence: number;
  rollback_anchor: RollbackAnchorStatus;
  opaque_commitments_only: true;
  raw_ticket_egress: false;
  raw_reviewer_identity_egress: false;
}

export interface ReviewAuthorityStatus {
  enabled: true;
  chain_id: 84532;
  authority_context_hash: string;
  release_context: ReviewReleaseContext;
  release_provenance: {
    reviewer_authority_genesis_acceptance_sha256: string;
    reviewer_authority_current_status_epoch: number;
    reviewer_authority_current_status_sha256: string;
    reviewer_authority_active_reviewers_sha256: string;
  };
  active_reviewers: {
    active_reviewer_count: number;
    active_reviewers_sha256: string;
    raw_reviewer_identity_egress: false;
  };
  rollback_protection: "base_sepolia_execution_policy_anchor";
  rollback_anchor: ReviewRollbackAnchor;
  schema: "dnai.review-authority-policy.v1";
  policy_sha256: string;
  roles: readonly ReviewRoleAuthority[];
  raw_reviewer_identity_egress: false;
}

export interface ReviewQueueStatus {
  surface: "human_review_queue";
  schema_version: 2;
  kind?: "review_queue_pending";
  routed_role?: string;
  ticket_count: number;
  pending_count: number;
  status_counts: Readonly<Record<ReviewTicketStatus, number>>;
  tickets: readonly ReviewTicket[];
  audit_hash: string;
  audit_count: number;
  raw_secret_egress: false;
  page: {
    limit: number;
    returned_count: number;
    has_more: boolean;
    next_cursor: ReviewQueueCursor | null;
  };
  authority: ReviewAuthorityStatus;
}

export interface ReviewQueueWindow {
  /** One independently verified page carrying the release-wide metadata. */
  snapshot: ReviewQueueStatus;
  /** Every verified ticket accumulated from the current cursor chain. */
  tickets: readonly ReviewTicket[];
  loaded_count: number;
  page_size: number;
  has_more: boolean;
  next_cursor: ReviewQueueCursor | null;
  routed_role: string | null;
  consumed_cursors: readonly ReviewQueueCursor[];
}

export interface ReviewChallenge {
  schema: "dnai.review-authority-challenge.v1";
  ticket_ref_hash: string;
  ticket_state_hash: string;
  routed_role: string;
  decision: ReviewDecision;
  reviewer_ref_hash: string;
  authority_context_hash: string;
  policy_sha256: string;
  nonce: string;
  message: string;
  issued_at: number;
  expires_at: number;
  chain_id: 84532;
  raw_reviewer_identity_egress: false;
}

export type ReviewAnchorVerifier = (
  status: RollbackAnchorStatus,
  expectedResourceHash: string,
  expectedDecisionHash: string,
  expectedRecordSequence: number,
) => Promise<void>;

export interface ReviewClientOptions {
  fetcher?: typeof fetch;
  verifyAnchor?: ReviewAnchorVerifier;
  nowSeconds?: number;
  signal?: AbortSignal;
}

export interface ReviewQueueFetchOptions extends ReviewClientOptions {
  cursor?: ReviewQueueCursor;
  limit?: number;
  routedRole?: string;
}

export class ReviewQueueRestartRequiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReviewQueueRestartRequiredError";
  }
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} contains unsupported fields`);
  }
}

function integer(value: unknown, label: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`${label} is outside its bounded range`);
  }
  return Number(value);
}

function string(value: unknown, label: string, maximum: number): string {
  if (typeof value !== "string" || value.length > maximum) throw new Error(`${label} is invalid`);
  return value;
}

function patterned(value: unknown, expression: RegExp, label: string): string {
  const parsed = string(value, label, 256);
  if (!expression.test(parsed)) throw new Error(`${label} is invalid`);
  return parsed;
}

function reviewQueuePageSize(value: unknown): number {
  return integer(
    value,
    "Review queue page size",
    1,
    REVIEW_QUEUE_MAX_PAGE_SIZE,
  );
}

function reviewQueueRole(value: unknown): string {
  return patterned(value, ROLE, "Review queue role");
}

export function parseReviewQueueCursor(value: unknown): ReviewQueueCursor {
  return patterned(
    value,
    HASH,
    "Review queue cursor",
  ) as ReviewQueueCursor;
}

function falseFlag(value: unknown, label: string): false {
  if (value !== false) throw new Error(`${label} must remain false`);
  return false;
}

function trueFlag(value: unknown, label: string): true {
  if (value !== true) throw new Error(`${label} must remain true`);
  return true;
}

function hash(value: unknown, label: string, allowEmpty = false): string {
  if (allowEmpty && value === "") return "";
  return patterned(value, HASH, label);
}

function hashList(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value) || value.length > 64) throw new Error(`${label} is invalid`);
  const parsed = value.map((item, index) => hash(item, `${label}[${index}]`));
  if (new Set(parsed).size !== parsed.length) throw new Error(`${label} contains duplicates`);
  return Object.freeze(parsed);
}

function parseTicket(value: unknown): ReviewTicket {
  const item = record(value, "Review ticket");
  exactKeys(item, [
    "ticket_ref_hash", "turn_ref_hash", "corpus_ref_hash", "routed_role", "reason_hash",
    "opened_at", "expires_at", "status", "reviewer_ref_hash", "submitter_ref_hash",
    "required_approvals", "approvals_count", "approval_reviewer_hashes",
    "approval_authorization_hashes", "reviewer_authorization_hash", "authority_context_hash",
    "decision_hash", "updated_at", "raw_secret_egress",
  ], "Review ticket");
  const status = string(item.status, "Review ticket status", 16);
  if (!["pending", "released", "denied", "expired"].includes(status)) {
    throw new Error("Review ticket status is invalid");
  }
  const approvals = hashList(item.approval_reviewer_hashes, "Review approval reviewers");
  const authorizations = hashList(item.approval_authorization_hashes, "Review approval authorizations");
  const requiredApprovals = integer(item.required_approvals, "Review threshold", 1, 64);
  const approvalsCount = integer(item.approvals_count, "Review approval count", 0, 64);
  if (
    approvals.length !== authorizations.length
    || approvals.length !== approvalsCount
    || approvalsCount > requiredApprovals
    || (status === "released" && approvalsCount < requiredApprovals)
    || (status === "pending" && approvalsCount >= requiredApprovals)
  ) throw new Error("Review ticket approval state is inconsistent");
  const openedAt = integer(item.opened_at, "Review opened time", 1, 4_102_444_800);
  const expiresAt = integer(item.expires_at, "Review expiry time", openedAt + 1, 4_102_444_800);
  const updatedAt = integer(item.updated_at, "Review update time", openedAt, 4_102_444_800);
  return Object.freeze({
    ticket_ref_hash: hash(item.ticket_ref_hash, "Review ticket reference"),
    turn_ref_hash: hash(item.turn_ref_hash, "Review turn reference"),
    corpus_ref_hash: hash(item.corpus_ref_hash, "Review corpus reference"),
    routed_role: patterned(item.routed_role, ROLE, "Review routed role"),
    reason_hash: hash(item.reason_hash, "Review reason hash"),
    opened_at: openedAt,
    expires_at: expiresAt,
    status: status as ReviewTicketStatus,
    reviewer_ref_hash: hash(item.reviewer_ref_hash, "Review reviewer reference", true),
    submitter_ref_hash: hash(item.submitter_ref_hash, "Review submitter reference", true),
    required_approvals: requiredApprovals,
    approvals_count: approvalsCount,
    approval_reviewer_hashes: approvals,
    approval_authorization_hashes: authorizations,
    reviewer_authorization_hash: hash(item.reviewer_authorization_hash, "Review authorization", true),
    authority_context_hash: hash(item.authority_context_hash, "Review ticket authority", true),
    decision_hash: hash(item.decision_hash, "Review decision hash", true),
    updated_at: updatedAt,
    raw_secret_egress: falseFlag(item.raw_secret_egress, "Review ticket secret egress"),
  });
}

function parseRole(value: unknown): ReviewRoleAuthority {
  const item = record(value, "Review role authority");
  exactKeys(item, ["role", "threshold", "reviewer_count", "reviewer_set_hash"], "Review role authority");
  const threshold = integer(item.threshold, "Review role threshold", 1, 64);
  const reviewerCount = integer(item.reviewer_count, "Review role reviewer count", threshold, 64);
  return Object.freeze({
    role: patterned(item.role, ROLE, "Review authority role"),
    threshold,
    reviewer_count: reviewerCount,
    reviewer_set_hash: hash(item.reviewer_set_hash, "Review role set hash"),
  });
}

function parseReleaseContext(value: unknown): ReviewReleaseContext {
  const item = record(value, "Review release context");
  exactKeys(item, [
    "schema", "chain_id", "wallet_domain", "wallet_uri", "main_runtime_cvm_id",
    "deployment_intent_sha256", "release_authority_sha256", "ceremony_nonce",
  ], "Review release context");
  if (item.schema !== "dnai.review-release-context.v1" || item.chain_id !== 84532) {
    throw new Error("Review release context identity is invalid");
  }
  return Object.freeze({
    schema: "dnai.review-release-context.v1",
    chain_id: 84532,
    wallet_domain: string(item.wallet_domain, "Review wallet domain", 255),
    wallet_uri: string(item.wallet_uri, "Review wallet URI", 512),
    main_runtime_cvm_id: patterned(item.main_runtime_cvm_id, CVM_ID, "Review main runtime CVM"),
    deployment_intent_sha256: patterned(item.deployment_intent_sha256, SHA256, "Review deployment intent"),
    release_authority_sha256: patterned(item.release_authority_sha256, SHA256, "Review release authority"),
    ceremony_nonce: patterned(item.ceremony_nonce, BYTES32, "Review ceremony nonce") as Hex,
  });
}

function parseRollbackAnchor(value: unknown): ReviewRollbackAnchor {
  const item = record(value, "Review rollback anchor");
  exactKeys(item, [
    "schema", "state_hash", "decision_hash", "sequence", "rollback_anchor",
    "opaque_commitments_only", "raw_ticket_egress", "raw_reviewer_identity_egress",
  ], "Review rollback anchor");
  if (item.schema !== "dnai.review-queue-rollback-anchor.v1") {
    throw new Error("Review rollback anchor identity is invalid");
  }
  return Object.freeze({
    schema: "dnai.review-queue-rollback-anchor.v1",
    state_hash: patterned(item.state_hash, NONZERO_HASH, "Review queue state hash"),
    decision_hash: patterned(item.decision_hash, NONZERO_HASH, "Review queue decision hash"),
    sequence: integer(item.sequence, "Review queue anchor sequence", 1),
    rollback_anchor: parseRollbackAnchorStatus(item.rollback_anchor),
    opaque_commitments_only: trueFlag(item.opaque_commitments_only, "Review anchor commitment boundary"),
    raw_ticket_egress: falseFlag(item.raw_ticket_egress, "Review anchor ticket egress"),
    raw_reviewer_identity_egress: falseFlag(item.raw_reviewer_identity_egress, "Review anchor reviewer egress"),
  });
}

function parseAuthority(value: unknown): ReviewAuthorityStatus {
  const item = record(value, "Review authority");
  exactKeys(item, [
    "enabled", "chain_id", "authority_context_hash", "release_context",
    "release_provenance", "active_reviewers", "rollback_protection", "rollback_anchor",
    "schema", "policy_sha256", "roles", "raw_reviewer_identity_egress",
  ], "Review authority");
  if (
    item.enabled !== true
    || item.chain_id !== 84532
    || item.rollback_protection !== "base_sepolia_execution_policy_anchor"
    || item.schema !== "dnai.review-authority-policy.v1"
  ) throw new Error("Review authority is not a live Base Sepolia release authority");
  const provenance = record(item.release_provenance, "Review release provenance");
  exactKeys(provenance, [
    "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_authority_current_status_epoch",
    "reviewer_authority_current_status_sha256",
    "reviewer_authority_active_reviewers_sha256",
  ], "Review release provenance");
  const active = record(item.active_reviewers, "Review active reviewer projection");
  exactKeys(active, [
    "active_reviewer_count", "active_reviewers_sha256", "raw_reviewer_identity_egress",
  ], "Review active reviewer projection");
  if (!Array.isArray(item.roles) || item.roles.length < 1 || item.roles.length > 16) {
    throw new Error("Review roles are invalid");
  }
  const roles = item.roles.map(parseRole);
  if (new Set(roles.map((role) => role.role)).size !== roles.length) {
    throw new Error("Review roles contain duplicates");
  }
  const activeSha = patterned(
    provenance.reviewer_authority_active_reviewers_sha256,
    SHA256,
    "Review active reviewer release pin",
  );
  const projectionSha = patterned(active.active_reviewers_sha256, SHA256, "Review active reviewer projection");
  if (activeSha !== projectionSha) throw new Error("Review active reviewer projections disagree");
  return Object.freeze({
    enabled: true,
    chain_id: 84532,
    authority_context_hash: patterned(item.authority_context_hash, NONZERO_HASH, "Review authority context"),
    release_context: parseReleaseContext(item.release_context),
    release_provenance: Object.freeze({
      reviewer_authority_genesis_acceptance_sha256: patterned(
        provenance.reviewer_authority_genesis_acceptance_sha256,
        SHA256,
        "Review genesis acceptance",
      ),
      reviewer_authority_current_status_epoch: integer(
        provenance.reviewer_authority_current_status_epoch,
        "Review current authority epoch",
        1,
        4_294_967_295,
      ),
      reviewer_authority_current_status_sha256: patterned(
        provenance.reviewer_authority_current_status_sha256,
        SHA256,
        "Review current authority status",
      ),
      reviewer_authority_active_reviewers_sha256: activeSha,
    }),
    active_reviewers: Object.freeze({
      active_reviewer_count: integer(active.active_reviewer_count, "Review active reviewer count", 1, 64),
      active_reviewers_sha256: projectionSha,
      raw_reviewer_identity_egress: falseFlag(active.raw_reviewer_identity_egress, "Review active reviewer egress"),
    }),
    rollback_protection: "base_sepolia_execution_policy_anchor",
    rollback_anchor: parseRollbackAnchor(item.rollback_anchor),
    schema: "dnai.review-authority-policy.v1",
    policy_sha256: patterned(item.policy_sha256, NONZERO_HASH, "Review policy hash"),
    roles: Object.freeze(roles),
    raw_reviewer_identity_egress: falseFlag(item.raw_reviewer_identity_egress, "Review reviewer identity egress"),
  });
}

export function parseReviewQueue(value: unknown): ReviewQueueStatus {
  const item = record(value, "Review queue");
  const baseKeys = [
    "surface", "schema_version", "ticket_count", "pending_count", "status_counts",
    "tickets", "audit_hash", "audit_count", "raw_secret_egress", "page", "authority",
  ] as const;
  const hasFilterMarker = "kind" in item || "routed_role" in item;
  exactKeys(
    item,
    hasFilterMarker ? [...baseKeys, "kind", "routed_role"] : baseKeys,
    "Review queue",
  );
  if (item.surface !== "human_review_queue" || item.schema_version !== 2) {
    throw new Error("Review queue identity is invalid");
  }
  let routedRole: string | undefined;
  if (hasFilterMarker) {
    if (item.kind !== "review_queue_pending") {
      throw new Error("Review queue filter identity is invalid");
    }
    routedRole = reviewQueueRole(item.routed_role);
  }
  const counts = record(item.status_counts, "Review status counts");
  exactKeys(counts, ["pending", "released", "denied", "expired"], "Review status counts");
  const statusCounts = Object.freeze({
    pending: integer(counts.pending, "Pending review count"),
    released: integer(counts.released, "Released review count"),
    denied: integer(counts.denied, "Denied review count"),
    expired: integer(counts.expired, "Expired review count"),
  });
  if (!Array.isArray(item.tickets) || item.tickets.length > 100) throw new Error("Review ticket page is invalid");
  const tickets = Object.freeze(item.tickets.map(parseTicket));
  const page = record(item.page, "Review queue page");
  exactKeys(page, ["limit", "returned_count", "has_more", "next_cursor"], "Review queue page");
  const ticketCount = integer(item.ticket_count, "Review ticket count", 0, 100_000);
  const pendingCount = integer(item.pending_count, "Pending review count", 0, ticketCount);
  const returnedCount = integer(page.returned_count, "Returned review count", 0, 100);
  const pageLimit = integer(page.limit, "Review page limit", 1, 100);
  const totalStatuses = Object.values(statusCounts).reduce((sum, count) => sum + count, 0);
  const hasMore = page.has_more;
  if (typeof hasMore !== "boolean") {
    throw new Error("Review queue pagination is inconsistent");
  }
  const nextCursor = hasMore
    ? parseReviewQueueCursor(page.next_cursor)
    : null;
  if (
    pendingCount !== statusCounts.pending
    || totalStatuses !== ticketCount
    || returnedCount !== tickets.length
    || tickets.length > pageLimit
    || (hasMore && tickets.length === 0)
    || (!hasMore && page.next_cursor !== "")
    || new Set(tickets.map((ticket) => ticket.ticket_ref_hash)).size !== tickets.length
  ) throw new Error("Review queue counts or pagination are inconsistent");
  const authority = parseAuthority(item.authority);
  for (const ticket of tickets) {
    if (ticket.authority_context_hash && ticket.authority_context_hash !== authority.authority_context_hash) {
      throw new Error("Review ticket belongs to another release authority");
    }
    if (!authority.roles.some((role) => role.role === ticket.routed_role && role.threshold === ticket.required_approvals)) {
      throw new Error("Review ticket role is not bound by the current authority");
    }
  }
  return Object.freeze({
    surface: "human_review_queue",
    schema_version: 2,
    ...(routedRole
      ? {
        kind: "review_queue_pending" as const,
        routed_role: routedRole,
      }
      : {}),
    ticket_count: ticketCount,
    pending_count: pendingCount,
    status_counts: statusCounts,
    tickets,
    audit_hash: hash(item.audit_hash, "Review audit hash"),
    audit_count: integer(item.audit_count, "Review audit count", 0, 1_000_000),
    raw_secret_egress: falseFlag(item.raw_secret_egress, "Review secret egress"),
    page: Object.freeze({
      limit: pageLimit,
      returned_count: returnedCount,
      has_more: hasMore,
      next_cursor: nextCursor,
    }),
    authority,
  });
}

export function parseReviewChallenge(value: unknown): ReviewChallenge {
  const item = record(value, "Review challenge");
  exactKeys(item, [
    "schema", "ticket_ref_hash", "ticket_state_hash", "routed_role", "decision",
    "reviewer_ref_hash", "authority_context_hash", "policy_sha256", "nonce", "message",
    "issued_at", "expires_at", "chain_id", "raw_reviewer_identity_egress",
  ], "Review challenge");
  if (item.schema !== "dnai.review-authority-challenge.v1" || item.chain_id !== 84532) {
    throw new Error("Review challenge identity is invalid");
  }
  const decision = string(item.decision, "Review decision", 16);
  if (decision !== "release" && decision !== "deny") throw new Error("Review decision is invalid");
  const issuedAt = integer(item.issued_at, "Review challenge issue time", 1, 4_102_444_800);
  const expiresAt = integer(item.expires_at, "Review challenge expiry", issuedAt + 1, issuedAt + 300);
  const message = string(item.message, "Review challenge message", 8_192);
  if (
    message.length < 32
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/u.test(message)
  ) throw new Error("Review challenge message contains unsafe text controls");
  return Object.freeze({
    schema: "dnai.review-authority-challenge.v1",
    ticket_ref_hash: hash(item.ticket_ref_hash, "Review challenge ticket"),
    ticket_state_hash: patterned(item.ticket_state_hash, NONZERO_HASH, "Review challenge ticket state"),
    routed_role: patterned(item.routed_role, ROLE, "Review challenge role"),
    decision,
    reviewer_ref_hash: hash(item.reviewer_ref_hash, "Review challenge reviewer"),
    authority_context_hash: patterned(item.authority_context_hash, NONZERO_HASH, "Review challenge authority"),
    policy_sha256: patterned(item.policy_sha256, NONZERO_HASH, "Review challenge policy"),
    nonce: patterned(item.nonce, /^[0-9a-f]{32}$/, "Review challenge nonce"),
    message,
    issued_at: issuedAt,
    expires_at: expiresAt,
    chain_id: 84532,
    raw_reviewer_identity_egress: falseFlag(item.raw_reviewer_identity_egress, "Review challenge identity egress"),
  });
}

async function readBoundedResponseText(response: Response): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) {
    throw new Error("Review response exceeded the public size limit");
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let body = "";
  let received = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("Review response exceeded the public size limit");
      }
      body += decoder.decode(value, { stream: true });
    }
    body += decoder.decode();
    return body;
  } finally {
    reader.releaseLock();
  }
}

function baseUrl(): string {
  if (!deployment.delegateUrl) throw new Error("Fresh delegate endpoint is not configured");
  return deployment.delegateUrl.replace(/\/$/, "");
}

async function request(path: string, options: {
  method?: "GET" | "POST";
  body?: unknown;
  fetcher?: typeof fetch;
  signal?: AbortSignal;
} = {}): Promise<unknown> {
  const signal = options.signal
    ? AbortSignal.any([options.signal, AbortSignal.timeout(12_000)])
    : AbortSignal.timeout(12_000);
  const response = await (options.fetcher ?? fetch)(`${baseUrl()}${path}`, {
    method: options.method ?? "GET",
    credentials: "omit",
    headers: {
      Accept: "application/json",
      ...(options.body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal,
  });
  const raw = await readBoundedResponseText(response);
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("Review service returned malformed JSON");
  }
  if (!response.ok) {
    const detail = value && typeof value === "object" && "detail" in value
      ? (value as { detail: unknown }).detail
      : `Request failed with status ${response.status}`;
    throw new Error(publicErrorText(detail, "Review request failed"));
  }
  return value;
}

export function reviewReleaseConfigured(): boolean {
  const trust = computeWorkloadDeployment.trustPolicy;
  return Boolean(
    deployment.delegateUrl
    && deployment.releaseIdentityStatus === "release_bound"
    && deployment.cvmId
    && deployment.executionPolicyAnchorRelease
    && computeWorkloadDeployment.configured
    && trust
    && trust.cvmId === deployment.cvmId,
  );
}

export async function verifyReviewQueueRelease(
  queue: ReviewQueueStatus,
  verifyAnchor?: ReviewAnchorVerifier,
): Promise<void> {
  const trust = computeWorkloadDeployment.trustPolicy;
  const anchorRelease = deployment.executionPolicyAnchorRelease;
  if (!reviewReleaseConfigured() || !trust || !anchorRelease || !deployment.cvmId) {
    throw new Error("The browser review release is not completely configured");
  }
  const context = queue.authority.release_context;
  if (
    context.chain_id !== 84532
    || context.wallet_domain !== deployment.walletAuthDomain
    || context.wallet_uri !== deployment.walletAuthUri
    || context.main_runtime_cvm_id !== deployment.cvmId
    || context.main_runtime_cvm_id !== trust.cvmId
    || context.deployment_intent_sha256 !== trust.deploymentIntentSha256
    || context.release_authority_sha256 !== trust.releaseAuthoritySha256
    || context.ceremony_nonce !== trust.ceremonyNonce
  ) throw new Error("Review service release context differs from the browser release");

  const anchor = queue.authority.rollback_anchor;
  const verifier = verifyAnchor ?? (async (status, resourceHash, decisionHash, sequence) => {
    await verifyRollbackAnchorStatus(
      status,
      anchorRelease,
      resourceHash,
      decisionHash,
      sequence,
    );
  });
  await verifier(
    anchor.rollback_anchor,
    queue.authority.authority_context_hash,
    anchor.decision_hash,
    anchor.sequence,
  );
}

export function reviewReleaseScopeKey(): string {
  const trust = computeWorkloadDeployment.trustPolicy;
  const anchor = deployment.executionPolicyAnchorRelease;
  return JSON.stringify([
    deployment.delegateUrl,
    deployment.releaseIdentityStatus,
    deployment.cvmId,
    deployment.walletAuthDomain,
    deployment.walletAuthUri,
    trust?.cvmId ?? "",
    trust?.deploymentIntentSha256 ?? "",
    trust?.releaseAuthoritySha256 ?? "",
    trust?.ceremonyNonce ?? "",
    anchor?.address ?? "",
    anchor?.runtimeCodeHash ?? "",
    anchor?.writer ?? "",
    anchor?.writerReleaseCommitment ?? "",
  ]);
}

/**
 * Stable identity for one release/filter/anchored queue snapshot.
 *
 * Finalized observation height is deliberately excluded: two pages may be
 * verified at later finalized blocks while still committing to the exact same
 * queue state. Authority, counts, audit head, and rollback state may not drift.
 */
export function reviewQueueSnapshotKey(queue: ReviewQueueStatus): string {
  const authority = queue.authority;
  const anchor = authority.rollback_anchor;
  return JSON.stringify([
    queue.routed_role ?? "",
    queue.ticket_count,
    queue.pending_count,
    queue.status_counts.pending,
    queue.status_counts.released,
    queue.status_counts.denied,
    queue.status_counts.expired,
    queue.audit_hash,
    queue.audit_count,
    authority.authority_context_hash,
    authority.policy_sha256,
    authority.release_context.chain_id,
    authority.release_context.wallet_domain,
    authority.release_context.wallet_uri,
    authority.release_context.main_runtime_cvm_id,
    authority.release_context.deployment_intent_sha256,
    authority.release_context.release_authority_sha256,
    authority.release_context.ceremony_nonce,
    authority.release_provenance.reviewer_authority_genesis_acceptance_sha256,
    authority.release_provenance.reviewer_authority_current_status_epoch,
    authority.release_provenance.reviewer_authority_current_status_sha256,
    authority.release_provenance.reviewer_authority_active_reviewers_sha256,
    authority.active_reviewers.active_reviewer_count,
    authority.active_reviewers.active_reviewers_sha256,
    authority.roles.map((role) => [
      role.role,
      role.threshold,
      role.reviewer_count,
      role.reviewer_set_hash,
    ]),
    anchor.state_hash,
    anchor.decision_hash,
    anchor.sequence,
    anchor.rollback_anchor.resource_id_hash,
    anchor.rollback_anchor.resource_decision_head,
    anchor.rollback_anchor.resource_sequence,
  ]);
}

export function startReviewQueueWindow(page: ReviewQueueStatus): ReviewQueueWindow {
  if (
    page.page.has_more !== Boolean(page.page.next_cursor)
    || page.tickets.length > page.ticket_count
    || (!page.page.has_more && page.tickets.length !== page.ticket_count)
  ) {
    throw new ReviewQueueRestartRequiredError(
      "Review queue first page is not a complete cursor-chain start",
    );
  }
  return Object.freeze({
    snapshot: page,
    tickets: page.tickets,
    loaded_count: page.tickets.length,
    page_size: page.page.limit,
    has_more: page.page.has_more,
    next_cursor: page.page.next_cursor,
    routed_role: page.routed_role ?? null,
    consumed_cursors: Object.freeze([]) as readonly ReviewQueueCursor[],
  });
}

export function appendReviewQueuePage(
  current: ReviewQueueWindow,
  nextPage: ReviewQueueStatus,
  requestedCursor: ReviewQueueCursor,
): ReviewQueueWindow {
  if (
    !current.has_more
    || !current.next_cursor
    || current.next_cursor !== requestedCursor
  ) {
    throw new ReviewQueueRestartRequiredError(
      "Review queue continuation no longer matches the displayed cursor",
    );
  }
  if (current.consumed_cursors.includes(requestedCursor)) {
    throw new ReviewQueueRestartRequiredError(
      "Review queue continuation cursor was already consumed",
    );
  }
  if (
    reviewQueueSnapshotKey(current.snapshot)
      !== reviewQueueSnapshotKey(nextPage)
    || current.page_size !== nextPage.page.limit
    || current.routed_role !== (nextPage.routed_role ?? null)
  ) {
    throw new ReviewQueueRestartRequiredError(
      "Review queue changed release, filter, or anchored state between pages",
    );
  }
  if (nextPage.tickets.length === 0) {
    throw new ReviewQueueRestartRequiredError(
      "Review queue continuation returned no records",
    );
  }
  const knownIds = new Set(
    current.tickets.map((ticket) => ticket.ticket_ref_hash),
  );
  if (
    nextPage.tickets.some((ticket) => knownIds.has(ticket.ticket_ref_hash))
  ) {
    throw new ReviewQueueRestartRequiredError(
      "Review queue continuation repeated a displayed ticket",
    );
  }
  const consumed = Object.freeze([
    ...current.consumed_cursors,
    requestedCursor,
  ]);
  if (
    nextPage.page.next_cursor
    && (
      nextPage.page.next_cursor === requestedCursor
      || consumed.includes(nextPage.page.next_cursor)
    )
  ) {
    throw new ReviewQueueRestartRequiredError(
      "Review queue continuation did not advance to a fresh opaque cursor",
    );
  }
  const tickets = Object.freeze([
    ...current.tickets,
    ...nextPage.tickets,
  ]);
  if (
    tickets.length > nextPage.ticket_count
    || (!nextPage.page.has_more && tickets.length !== nextPage.ticket_count)
  ) {
    throw new ReviewQueueRestartRequiredError(
      "Review queue continuation does not reconcile with the verified total",
    );
  }
  return Object.freeze({
    snapshot: nextPage,
    tickets,
    loaded_count: tickets.length,
    page_size: current.page_size,
    has_more: nextPage.page.has_more,
    next_cursor: nextPage.page.next_cursor,
    routed_role: current.routed_role,
    consumed_cursors: consumed,
  });
}

export async function fetchReviewQueue(
  options: ReviewQueueFetchOptions = {},
): Promise<ReviewQueueStatus> {
  const limit = reviewQueuePageSize(
    options.limit ?? REVIEW_QUEUE_DEFAULT_PAGE_SIZE,
  );
  const routedRole = options.routedRole
    ? reviewQueueRole(options.routedRole)
    : "";
  const cursor = options.cursor
    ? parseReviewQueueCursor(options.cursor)
    : undefined;
  const query = new URLSearchParams();
  query.set("limit", String(limit));
  if (routedRole) query.set("routed_role", routedRole);
  if (cursor) query.set("cursor", cursor);
  const queue = parseReviewQueue(await request(
    `/review/queue?${query.toString()}`,
    {
      fetcher: options.fetcher,
      signal: options.signal,
    },
  ));
  if (
    queue.page.limit !== limit
    || (queue.routed_role ?? "") !== routedRole
  ) {
    throw new Error("Review service changed the requested page or role filter");
  }
  await verifyReviewQueueRelease(queue, options.verifyAnchor);
  return queue;
}

export async function issueReviewChallenge(
  queue: Pick<ReviewQueueStatus, "authority"> & {
    tickets: readonly ReviewTicket[];
  },
  ticket: ReviewTicket,
  address: Address | string,
  decision: ReviewDecision,
  options: ReviewClientOptions = {},
): Promise<ReviewChallenge> {
  if (!ADDRESS.test(address.toLowerCase())) throw new Error("Connected reviewer wallet is invalid");
  if (!queue.tickets.some((item) => item.ticket_ref_hash === ticket.ticket_ref_hash)) {
    throw new Error("Review ticket is not present in the verified queue page");
  }
  const challenge = parseReviewChallenge(await request("/auth/review/challenge", {
    method: "POST",
    body: {
      address: address.toLowerCase(),
      ticket_ref_hash: ticket.ticket_ref_hash,
      decision,
    },
    fetcher: options.fetcher,
    signal: options.signal,
  }));
  const now = options.nowSeconds ?? Math.floor(Date.now() / 1_000);
  if (challenge.issued_at > now + 30 || challenge.expires_at <= now) {
    throw new Error("Review challenge is stale or has an invalid clock binding");
  }
  if (
    challenge.ticket_ref_hash !== ticket.ticket_ref_hash
    || challenge.routed_role !== ticket.routed_role
    || challenge.decision !== decision
    || challenge.authority_context_hash !== queue.authority.authority_context_hash
    || challenge.policy_sha256 !== queue.authority.policy_sha256
  ) throw new Error("Review challenge is bound to another ticket or release authority");
  return challenge;
}

export async function submitReviewDecision(
  nonce: string,
  signature: Hex | string,
  options: ReviewClientOptions = {},
): Promise<ReviewQueueStatus> {
  const signatureHex = typeof signature === "string" && signature.startsWith("0x")
    ? signature.slice(2)
    : "";
  if (
    !/^[0-9a-f]{32}$/.test(nonce)
    || signatureHex.length < 2
    || signatureHex.length > 8_192
    || signatureHex.length % 2 !== 0
    || !/^[0-9a-fA-F]+$/.test(signatureHex)
  ) {
    throw new Error("Review decision authorization is malformed");
  }
  const queue = parseReviewQueue(await request("/review/decide", {
    method: "POST",
    body: { nonce, signature },
    fetcher: options.fetcher,
    signal: options.signal,
  }));
  await verifyReviewQueueRelease(queue, options.verifyAnchor);
  return queue;
}
