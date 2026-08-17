import { deployment } from "../config";
import { publicErrorText } from "./errorText";

const MAX_RESPONSE_BYTES = 256 * 1024;
const DEFAULT_CREDENTIAL_PAGE_SIZE = 16;
const MAX_CREDENTIAL_PAGE_SIZE = 64;
const MAX_CREDENTIAL_CURSOR_BYTES = 1_024;
const MAX_UINT256 = (1n << 256n) - 1n;
const RESOURCE_ID = /^(?:tca|tcc)_[0-9a-f]{24}$/;
const ACCOUNT_ID = /^tca_[0-9a-f]{24}$/;
const CREDENTIAL_ID = /^tcc_[0-9a-f]{24}$/;
const RESERVATION_ID = /^tcr_[0-9a-f]{24}$/;
const HEX_32 = /^0x[0-9a-f]{64}$/;
const NONZERO_HEX_32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const NONZERO_SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const OPAQUE_CURSOR = /^[\x21-\x7e]+$/;
const TRAINING_STAGE = /^(?:policy_checked|api_key_loaded|training_created|checkpoint_saved|cleanup_completed|step_[1-9][0-9]*_completed)$/;
const BOUNDED_RESULT_TEXT = /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/;
const TINKER_CUSTOMER_TRAINING_POLICY_UNIT =
  "one_policy_unit_per_requested_max_usd_micro";
const TINKER_TRAINING_VALUE_BANDS = [
  "unknown",
  "invalid",
  "zero",
  "<1e6",
  "1e6-1e9",
  "1e9-1e12",
  "1e12-1e15",
  "1e15-1e18",
  ">=1e18",
] as const;
const TINKER_ACCOUNT_BINDING_TRUTH =
  "independently_attested_opaque_binding_handle_not_cryptographic_proof_of_provider_internal_identity";
const TINKER_ACCOUNT_BINDING_TYPE =
  "DnaiTinkerAccountBindingV1(uint256 chainId,bytes32 providerNamespace,bytes32 bindingRoot)";
const TINKER_ACCOUNT_BINDING_TYPEHASH =
  "0x7f67603ed57564d41a9f6c2ed90a06ffa1477e9f75cbd68a2cb624c63cd6a1f0";
const TINKER_PROVIDER_NAMESPACE =
  "0xbebf29be35e78cf8b75112a67af061d2e2b608bc0a2b4df1273bfd992f0a06f6";
const TINKER_CREDENTIAL_HKDF_INFO =
  "dnai-wikigen-tinker-customer-credential-v1";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export type TinkerAccountMode = "create" | "link_existing";
export type TinkerAccountLifecycleStatus =
  | "requested"
  | "active"
  | "cancelled"
  | "revoked";
export type TinkerCredentialStatus = "active" | "expired" | "revoked";

export interface TinkerCustomerSession {
  accessToken: string;
  address: string;
  issuedAt: number;
  expiresAt: number;
  walletAuthorizationVersion: number;
}

export interface TinkerAccountPolicy {
  allowed_operations: readonly ["training"];
  max_operation_policy_units: string;
  max_outstanding_policy_units: string;
  max_lifetime_policy_units: string;
  credential_max_ttl_seconds: number;
  max_active_credentials: number;
  inference_enabled: false;
  hosted_card_funding: "roadmap";
  token_exchange: "roadmap";
  raw_secret_egress: false;
}

export interface TinkerAccountBindingAuthority {
  truth_status: typeof TINKER_ACCOUNT_BINDING_TRUTH;
  account_binding_schema: "dnai.tinker-account-binding.v1";
  account_binding_version: 1;
  account_binding_chain_id: 84532;
  account_binding_type: typeof TINKER_ACCOUNT_BINDING_TYPE;
  account_binding_typehash: string;
  provider_namespace_label: "thinking-machines/tinker";
  provider_namespace: string;
  account_commitment: string;
  account_binding_receipt_digest: string;
  sealed_binding_record_hash: string;
  account_binding_ceremony_receipt_digest: string;
  deployment_intent_digest: string;
  account_binding_receipt_independently_attested: true;
  account_binding_handle_attested: true;
  provider_identity_checked: true;
  current_provider_session_rechecked: true;
  account_commitment_exact_match: true;
  provider_internal_identity_cryptographically_proven: false;
  raw_provider_account_id_egress: false;
  raw_binding_root_egress: false;
  raw_reviewer_share_egress: false;
  binding_root_or_share_digest_published: false;
  raw_provider_auth_egress: false;
  raw_provider_session_egress: false;
  raw_secret_egress: false;
}

export interface TinkerAccountStatus {
  surface: "tinker_customer_account_status";
  schema_version: 1;
  account_id: string;
  status: TinkerAccountLifecycleStatus;
  mode: TinkerAccountMode;
  owner_address_hash: string;
  request_commitment: string;
  account_commitment: string;
  release_lineage_digest: string;
  account_binding_authority_digest: string | null;
  account_binding_authority: TinkerAccountBindingAuthority | Record<string, never>;
  account_policy: TinkerAccountPolicy;
  credential_counts: Readonly<Record<string, number>>;
  reservation_counts: Readonly<Record<string, number>>;
  settled_policy_units: string;
  outstanding_policy_units: string;
  upstream_account_exists: boolean;
  raw_account_identifier_returned: false;
  upstream_tinker_key_exposed: false;
  upstream_project_exposed: false;
  hosted_card_funding: "roadmap";
  token_exchange: "roadmap";
  raw_secret_egress: false;
}

export interface TinkerGateReceipt {
  chain_id: 84532;
  finalized_block_number: number;
  finalized_block_hash: string;
  release_observation_digest: string;
  release_policy_tuple_digest: string;
  runtime_evidence_digest: string;
  tdx_verified: true;
  qvl_pass: true;
  raw_quote_publicly_disclosed: false;
  raw_collateral_publicly_disclosed: false;
  raw_secret_egress: false;
}

export interface TinkerAccountRequestReceipt {
  surface: "tinker_customer_account_request";
  schema_version: 1;
  account_id: string;
  status: "requested";
  mode: TinkerAccountMode;
  request_commitment: string;
  owner_address_hash: string;
  release_lineage_digest: string;
  account_binding_ceremony_receipt_digest: string;
  deployment_intent_digest: string;
  account_policy: TinkerAccountPolicy;
  upstream_account_exists: false;
  provisioning_performed: false;
  browser_supplied_account_commitment_accepted: false;
  hosted_card_funding: "roadmap";
  token_exchange: "roadmap";
  gate: TinkerGateReceipt;
  idempotent_replay: boolean;
  raw_secret_egress: false;
}

export interface TinkerCredentialSummary {
  credential_id: string;
  operations: readonly ["training"];
  scopes: readonly ["tinker:train"];
  max_operation_policy_units: string;
  recipient_public_key_hash: string;
  jwt_id_hash: string;
  status: TinkerCredentialStatus;
  persisted_status: "active" | "revoked";
  issued_at: number;
  expires_at: number;
  revoked_at: number;
  token_returned_in_plaintext: false;
}

export interface TinkerCredentialList {
  surface: "tinker_customer_credentials";
  schema_version: 2;
  account_id: string;
  account_status: TinkerAccountLifecycleStatus;
  release_lineage_digest: string;
  account_binding_authority_digest: string | null;
  total_credentials: number;
  page_credential_count: number;
  page_limit: number;
  maximum_page_size: 64;
  has_more: boolean;
  next_cursor: string | null;
  snapshot_sequence: number;
  ordering: "issued_at_desc_then_credential_id_desc";
  credentials: readonly TinkerCredentialSummary[];
  upstream_tinker_key_exposed: false;
  upstream_project_exposed: false;
  credential_capsules_returned: false;
  plaintext_token_egress: false;
  raw_secret_egress: false;
}

export interface TinkerCredentialHistory {
  readonly account_id: string;
  readonly account_status: TinkerAccountLifecycleStatus;
  readonly release_lineage_digest: string;
  readonly account_binding_authority_digest: string | null;
  readonly total_credentials: number;
  readonly page_limit: number;
  readonly maximum_page_size: 64;
  readonly has_more: boolean;
  readonly next_cursor: string | null;
  readonly snapshot_sequence: number;
  readonly ordering: "issued_at_desc_then_credential_id_desc";
  readonly credentials: readonly TinkerCredentialSummary[];
}

export interface TinkerCredentialPageOptions {
  readonly limit?: number;
  readonly cursor?: string;
  readonly signal?: AbortSignal;
}

export interface TinkerCredentialCapsule {
  delivery: "x25519_aes_256_gcm_envelope";
  encrypted_token: {
    ephemeral_public_key: string;
    nonce: string;
    ciphertext: string;
  };
  associated_data: string;
  associated_data_hash: string;
  recipient_public_key_hash: string;
  token_returned_in_plaintext: false;
}

export interface TinkerCredentialIssueReceipt {
  surface: "tinker_customer_credential_issue";
  schema_version: 1;
  credential_id: string;
  account_id: string;
  status: "active";
  operations: readonly ["training"];
  scopes: readonly ["tinker:train"];
  max_operation_policy_units: string;
  account_policy_digest: string;
  release_lineage_digest: string;
  account_binding_authority_digest: string;
  account_binding_ceremony_receipt_digest: string;
  deployment_intent_digest: string;
  issued_at: number;
  expires_at: number;
  jwt_id_hash: string;
  capsule: TinkerCredentialCapsule;
  upstream_tinker_key_exposed: false;
  upstream_project_exposed: false;
  token_returned_in_plaintext: false;
  gate: TinkerGateReceipt;
  idempotent_replay: boolean;
  raw_secret_egress: false;
}

export interface TinkerCredentialRotationReceipt {
  surface: "tinker_customer_credential_rotation";
  schema_version: 1;
  account_id: string;
  prior_credential_id: string;
  credential_id: string;
  status: "active";
  operations: readonly ["training"];
  scopes: readonly ["tinker:train"];
  max_operation_policy_units: string;
  account_policy_digest: string;
  release_lineage_digest: string;
  account_binding_authority_digest: string;
  account_binding_ceremony_receipt_digest: string;
  deployment_intent_digest: string;
  issued_at: number;
  expires_at: number;
  jwt_id_hash: string;
  capsule: TinkerCredentialCapsule;
  prior_credential_revoked: true;
  rotation_order: "revoke_then_issue_no_authority_overlap";
  gate: TinkerGateReceipt;
  idempotent_replay: boolean;
  upstream_tinker_key_exposed: false;
  upstream_project_exposed: false;
  token_returned_in_plaintext: false;
  raw_secret_egress: false;
}

export interface TinkerCredentialRevokeReceipt {
  surface: "tinker_customer_credential_revoke";
  schema_version: 1;
  credential_id: string;
  account_id: string;
  status: "revoked";
  jwt_id_hash: string;
  release_lineage_digest: string;
  account_binding_authority_digest: string;
  account_binding_ceremony_receipt_digest: string;
  deployment_intent_digest: string;
  revoked_at: number;
  gate: TinkerGateReceipt;
  idempotent_replay: boolean;
  raw_secret_egress: false;
}

export interface TinkerAccountRevokeReceipt {
  surface: "tinker_customer_account_revoke";
  schema_version: 1;
  account_id: string;
  status: "cancelled" | "revoked";
  owner_address_hash: string;
  release_lineage_digest: string;
  account_binding_authority_digest: string | null;
  account_binding_ceremony_receipt_digest: string;
  deployment_intent_digest: string;
  provisioning_result_attested: boolean;
  revoked_credentials: number;
  outstanding_reservations: number;
  new_authority_permitted: false;
  outstanding_reservations_require_attested_finalization: boolean;
  gate: TinkerGateReceipt;
  idempotent_replay: boolean;
  raw_secret_egress: false;
}

export type TinkerTrainingValueBand =
  typeof TINKER_TRAINING_VALUE_BANDS[number];

export type TinkerTrainingOutcome =
  | "policy_check_failed"
  | "policy_denied"
  | "api_key_missing"
  | "training_completed"
  | "training_failed"
  | "provider_outcome_ambiguous";

export interface TinkerTrainingResult {
  surface: "tinker_customer_training_result";
  schema_version: 1;
  success: boolean;
  outcome: TinkerTrainingOutcome;
  furthest_stage: string;
  deal_id_hash: string;
  model_hash: string;
  rank: number;
  steps_requested: number;
  steps_completed: number;
  max_usd_band: TinkerTrainingValueBand;
  metered_cost_band: TinkerTrainingValueBand;
  checkpoint_saved: boolean;
  error_kind: string;
  bounded_message: string;
  issued_at: number;
  provider_dispatch_attempted: boolean;
  provider_dispatch_performed: boolean;
  provider_outcome_ambiguous: boolean;
  raw_secret_egress: false;
}

export interface TinkerTrainingExecutionReceipt {
  surface: "tinker_customer_training_execution";
  schema_version: 1;
  status: "settled" | "released";
  reservation_id: string;
  reservation_commitment: string;
  workload_commitment: string;
  reserved_policy_units: string;
  actual_policy_units: string;
  released_policy_units: string;
  policy_unit_definition: typeof TINKER_CUSTOMER_TRAINING_POLICY_UNIT;
  provider_authoritative_billing: false;
  authority_accounting_only: true;
  fixed_ceiling_accounting: true;
  at_most_once_claim_committed: true;
  automatic_provider_redispatch: false;
  reconciliation_required: false;
  training_result: TinkerTrainingResult;
  settlement: {
    status: "settled" | "released";
    usage_receipt_hash: string;
    dispatch_runtime_evidence_digest: string;
    provider_dispatch_performed: boolean;
  };
  idempotent_replay: boolean;
  raw_secret_egress: false;
}

export interface TinkerTrainingReconciliationReceipt {
  surface: "tinker_customer_training_reconciliation";
  schema_version: 1;
  status: "reconciliation_required";
  reservation_id: string;
  reservation_commitment: string;
  workload_commitment: string;
  at_most_once_claim_committed: true;
  automatic_provider_redispatch: false;
  provider_outcome_confirmed: false;
  provider_authoritative_billing: false;
  authority_accounting_only: true;
  raw_secret_egress: false;
}

export interface TinkerTrainingControls {
  maxUsdMicros: number;
  steps: number;
  ttlSeconds: number;
}

export interface TinkerDeviceKey {
  publicKeyHex: string;
  privateKey: CryptoKey;
}

export class TinkerRequestError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "TinkerRequestError";
    this.status = status;
  }

  get restartRequired(): boolean {
    return this.status === 409;
  }
}

export class TinkerTrainingReconciliationError extends TinkerRequestError {
  readonly receipt: TinkerTrainingReconciliationReceipt;

  constructor(receipt: TinkerTrainingReconciliationReceipt) {
    super(
      "Training dispatch is held for reconciliation; this browser will not redispatch it",
      409,
    );
    this.name = "TinkerTrainingReconciliationError";
    this.receipt = receipt;
  }
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((field, index) => field !== wanted[index])
  ) {
    throw new Error(`${label} contains unsupported fields`);
  }
}

function exactString(
  value: unknown,
  expected: string,
  label: string,
): string {
  if (value !== expected) throw new Error(`${label} is invalid`);
  return expected;
}

function patterned(
  value: unknown,
  pattern: RegExp,
  label: string,
  maximum = 256,
): string {
  if (
    typeof value !== "string"
    || encoder.encode(value).byteLength > maximum
    || !pattern.test(value)
  ) throw new Error(`${label} is invalid`);
  return value;
}

function integer(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number,
): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < minimum
    || value > maximum
  ) throw new Error(`${label} is outside its supported bound`);
  return value;
}

function exactBoolean(
  value: unknown,
  expected: boolean,
  label: string,
): boolean {
  if (value !== expected) throw new Error(`${label} is invalid`);
  return expected;
}

function uint256String(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} is not a canonical uint256`);
  }
  const parsed = BigInt(value);
  if (parsed > MAX_UINT256) throw new Error(`${label} exceeds uint256`);
  return value;
}

function positiveUint256String(value: unknown, label: string): string {
  const parsed = uint256String(value, label);
  if (BigInt(parsed) < 1n) throw new Error(`${label} must be positive`);
  return parsed;
}

function parseStatusCounts(
  value: unknown,
  allowed: readonly string[],
  label: string,
): Readonly<Record<string, number>> {
  const counts = record(value, label);
  if (
    Object.keys(counts).some((status) => !allowed.includes(status))
    || Object.entries(counts).some(([, count]) => (
      typeof count !== "number"
      || !Number.isSafeInteger(count)
      || count < 1
      || count > 1_000_000
    ))
  ) throw new Error(`${label} is invalid`);
  return Object.freeze({ ...counts } as Record<string, number>);
}

function parseAccountPolicy(value: unknown): TinkerAccountPolicy {
  const policy = record(value, "Tinker account policy");
  exactKeys(policy, [
    "allowed_operations",
    "max_operation_policy_units",
    "max_outstanding_policy_units",
    "max_lifetime_policy_units",
    "credential_max_ttl_seconds",
    "max_active_credentials",
    "inference_enabled",
    "hosted_card_funding",
    "token_exchange",
    "raw_secret_egress",
  ], "Tinker account policy");
  if (
    !Array.isArray(policy.allowed_operations)
    || policy.allowed_operations.length !== 1
    || policy.allowed_operations[0] !== "training"
  ) throw new Error("Tinker account operations exceed this release");
  const operation = uint256String(
    policy.max_operation_policy_units,
    "Tinker per-operation policy units",
  );
  const outstanding = uint256String(
    policy.max_outstanding_policy_units,
    "Tinker outstanding policy units",
  );
  const lifetime = uint256String(
    policy.max_lifetime_policy_units,
    "Tinker lifetime policy units",
  );
  if (
    BigInt(operation) < 1n
    || BigInt(operation) > BigInt(outstanding)
    || BigInt(outstanding) > BigInt(lifetime)
  ) throw new Error("Tinker account policy caps are inconsistent");
  return Object.freeze({
    allowed_operations: ["training"] as const,
    max_operation_policy_units: operation,
    max_outstanding_policy_units: outstanding,
    max_lifetime_policy_units: lifetime,
    credential_max_ttl_seconds: integer(
      policy.credential_max_ttl_seconds,
      "Tinker credential maximum lifetime",
      60,
      3_600,
    ),
    max_active_credentials: integer(
      policy.max_active_credentials,
      "Tinker active credential cap",
      1,
      16,
    ),
    inference_enabled: exactBoolean(
      policy.inference_enabled,
      false,
      "Tinker inference capability",
    ) as false,
    hosted_card_funding: exactString(
      policy.hosted_card_funding,
      "roadmap",
      "Tinker hosted-card capability",
    ) as "roadmap",
    token_exchange: exactString(
      policy.token_exchange,
      "roadmap",
      "Tinker token-exchange capability",
    ) as "roadmap",
    raw_secret_egress: exactBoolean(
      policy.raw_secret_egress,
      false,
      "Tinker policy secret egress",
    ) as false,
  });
}

function parseGate(value: unknown): TinkerGateReceipt {
  const gate = record(value, "Tinker live gate");
  exactKeys(gate, [
    "chain_id",
    "finalized_block_number",
    "finalized_block_hash",
    "release_observation_digest",
    "release_policy_tuple_digest",
    "runtime_evidence_digest",
    "tdx_verified",
    "qvl_pass",
    "raw_quote_publicly_disclosed",
    "raw_collateral_publicly_disclosed",
    "raw_secret_egress",
  ], "Tinker live gate");
  if (gate.chain_id !== 84532) throw new Error("Tinker gate is not Base Sepolia");
  return Object.freeze({
    chain_id: 84532,
    finalized_block_number: integer(
      gate.finalized_block_number,
      "Tinker finalized block",
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    finalized_block_hash: patterned(
      gate.finalized_block_hash,
      NONZERO_HEX_32,
      "Tinker finalized block hash",
    ),
    release_observation_digest: patterned(
      gate.release_observation_digest,
      NONZERO_SHA256,
      "Tinker release observation",
    ),
    release_policy_tuple_digest: patterned(
      gate.release_policy_tuple_digest,
      NONZERO_SHA256,
      "Tinker release policy tuple",
    ),
    runtime_evidence_digest: patterned(
      gate.runtime_evidence_digest,
      NONZERO_SHA256,
      "Tinker runtime evidence",
    ),
    tdx_verified: exactBoolean(
      gate.tdx_verified,
      true,
      "Tinker TDX gate",
    ) as true,
    qvl_pass: exactBoolean(gate.qvl_pass, true, "Tinker QVL gate") as true,
    raw_quote_publicly_disclosed: exactBoolean(
      gate.raw_quote_publicly_disclosed,
      false,
      "Tinker quote disclosure",
    ) as false,
    raw_collateral_publicly_disclosed: exactBoolean(
      gate.raw_collateral_publicly_disclosed,
      false,
      "Tinker collateral disclosure",
    ) as false,
    raw_secret_egress: exactBoolean(
      gate.raw_secret_egress,
      false,
      "Tinker gate secret egress",
    ) as false,
  });
}

function parseBindingAuthority(
  value: unknown,
  expectedCommitment: string,
): TinkerAccountBindingAuthority | Record<string, never> {
  const authority = record(value, "Tinker account-binding authority");
  if (Object.keys(authority).length === 0) return Object.freeze({});
  exactKeys(authority, [
    "truth_status",
    "account_binding_schema",
    "account_binding_version",
    "account_binding_chain_id",
    "account_binding_type",
    "account_binding_typehash",
    "provider_namespace_label",
    "provider_namespace",
    "account_commitment",
    "account_binding_receipt_digest",
    "sealed_binding_record_hash",
    "account_binding_ceremony_receipt_digest",
    "deployment_intent_digest",
    "account_binding_receipt_independently_attested",
    "account_binding_handle_attested",
    "provider_identity_checked",
    "current_provider_session_rechecked",
    "account_commitment_exact_match",
    "provider_internal_identity_cryptographically_proven",
    "raw_provider_account_id_egress",
    "raw_binding_root_egress",
    "raw_reviewer_share_egress",
    "binding_root_or_share_digest_published",
    "raw_provider_auth_egress",
    "raw_provider_session_egress",
    "raw_secret_egress",
  ], "Tinker account-binding authority");
  if (
    authority.truth_status !== TINKER_ACCOUNT_BINDING_TRUTH
    || authority.account_binding_schema !== "dnai.tinker-account-binding.v1"
    || authority.account_binding_version !== 1
    || authority.account_binding_chain_id !== 84532
    || authority.account_binding_type !== TINKER_ACCOUNT_BINDING_TYPE
    || authority.account_binding_typehash !== TINKER_ACCOUNT_BINDING_TYPEHASH
    || authority.provider_namespace_label !== "thinking-machines/tinker"
    || authority.provider_namespace !== TINKER_PROVIDER_NAMESPACE
    || authority.account_commitment !== expectedCommitment
  ) throw new Error("Tinker account-binding authority drifted");
  const digests = [
    patterned(
      authority.account_binding_receipt_digest,
      NONZERO_SHA256,
      "Tinker account-binding receipt",
    ),
    patterned(
      authority.sealed_binding_record_hash,
      NONZERO_SHA256,
      "Tinker sealed binding record",
    ),
    patterned(
      authority.account_binding_ceremony_receipt_digest,
      NONZERO_SHA256,
      "Tinker ceremony receipt",
    ),
    patterned(
      authority.deployment_intent_digest,
      NONZERO_SHA256,
      "Tinker deployment intent",
    ),
  ];
  if (new Set(digests).size !== digests.length) {
    throw new Error("Tinker account-binding commitments are not distinct");
  }
  for (const field of [
    "account_binding_receipt_independently_attested",
    "account_binding_handle_attested",
    "provider_identity_checked",
    "current_provider_session_rechecked",
    "account_commitment_exact_match",
  ]) exactBoolean(authority[field], true, `Tinker ${field}`);
  for (const field of [
    "provider_internal_identity_cryptographically_proven",
    "raw_provider_account_id_egress",
    "raw_binding_root_egress",
    "raw_reviewer_share_egress",
    "binding_root_or_share_digest_published",
    "raw_provider_auth_egress",
    "raw_provider_session_egress",
    "raw_secret_egress",
  ]) exactBoolean(authority[field], false, `Tinker ${field}`);
  return Object.freeze(authority) as unknown as TinkerAccountBindingAuthority;
}

export function parseTinkerAccountStatus(value: unknown): TinkerAccountStatus {
  const status = record(value, "Tinker account status");
  exactKeys(status, [
    "surface",
    "schema_version",
    "account_id",
    "status",
    "mode",
    "owner_address_hash",
    "request_commitment",
    "account_commitment",
    "release_lineage_digest",
    "account_binding_authority_digest",
    "account_binding_authority",
    "account_policy",
    "credential_counts",
    "reservation_counts",
    "settled_policy_units",
    "outstanding_policy_units",
    "upstream_account_exists",
    "raw_account_identifier_returned",
    "upstream_tinker_key_exposed",
    "upstream_project_exposed",
    "hosted_card_funding",
    "token_exchange",
    "raw_secret_egress",
  ], "Tinker account status");
  if (
    status.surface !== "tinker_customer_account_status"
    || status.schema_version !== 1
    || !["requested", "active", "cancelled", "revoked"].includes(String(status.status))
    || !["create", "link_existing"].includes(String(status.mode))
  ) throw new Error("Tinker account status identity is invalid");
  const accountId = patterned(
    status.account_id,
    ACCOUNT_ID,
    "Tinker account ID",
  );
  const accountCommitment = patterned(
    status.account_commitment,
    NONZERO_HEX_32,
    "Tinker account commitment",
  );
  const lifecycle = status.status as TinkerAccountLifecycleStatus;
  const authorityDigest = status.account_binding_authority_digest === null
    ? null
    : patterned(
      status.account_binding_authority_digest,
      NONZERO_SHA256,
      "Tinker account-binding authority digest",
    );
  const authority = parseBindingAuthority(
    status.account_binding_authority,
    accountCommitment,
  );
  const hasAuthority = Object.keys(authority).length > 0;
  const activated = lifecycle === "active" || lifecycle === "revoked";
  if (
    activated !== hasAuthority
    || activated !== (authorityDigest !== null)
    || status.upstream_account_exists !== activated
  ) throw new Error("Tinker account activation evidence is inconsistent");
  const accountPolicy = parseAccountPolicy(status.account_policy);
  const settledPolicyUnits = uint256String(
    status.settled_policy_units,
    "Tinker settled policy units",
  );
  const outstandingPolicyUnits = uint256String(
    status.outstanding_policy_units,
    "Tinker outstanding policy units",
  );
  if (
    BigInt(settledPolicyUnits)
      > BigInt(accountPolicy.max_lifetime_policy_units)
    || BigInt(outstandingPolicyUnits)
      > BigInt(accountPolicy.max_outstanding_policy_units)
  ) throw new Error("Tinker account usage exceeds its immutable policy");
  return Object.freeze({
    surface: "tinker_customer_account_status",
    schema_version: 1,
    account_id: accountId,
    status: lifecycle,
    mode: status.mode as TinkerAccountMode,
    owner_address_hash: patterned(
      status.owner_address_hash,
      NONZERO_SHA256,
      "Tinker owner hash",
    ),
    request_commitment: patterned(
      status.request_commitment,
      NONZERO_SHA256,
      "Tinker request commitment",
    ),
    account_commitment: accountCommitment,
    release_lineage_digest: patterned(
      status.release_lineage_digest,
      NONZERO_SHA256,
      "Tinker release lineage",
    ),
    account_binding_authority_digest: authorityDigest,
    account_binding_authority: authority,
    account_policy: accountPolicy,
    credential_counts: parseStatusCounts(
      status.credential_counts,
      ["active", "expired", "revoked"],
      "Tinker credential counts",
    ),
    reservation_counts: parseStatusCounts(
      status.reservation_counts,
      ["reserved", "settled", "released"],
      "Tinker reservation counts",
    ),
    settled_policy_units: settledPolicyUnits,
    outstanding_policy_units: outstandingPolicyUnits,
    upstream_account_exists: activated,
    raw_account_identifier_returned: exactBoolean(
      status.raw_account_identifier_returned,
      false,
      "Tinker raw account identifier egress",
    ) as false,
    upstream_tinker_key_exposed: exactBoolean(
      status.upstream_tinker_key_exposed,
      false,
      "Tinker upstream key egress",
    ) as false,
    upstream_project_exposed: exactBoolean(
      status.upstream_project_exposed,
      false,
      "Tinker upstream project egress",
    ) as false,
    hosted_card_funding: exactString(
      status.hosted_card_funding,
      "roadmap",
      "Tinker hosted-card status",
    ) as "roadmap",
    token_exchange: exactString(
      status.token_exchange,
      "roadmap",
      "Tinker token-exchange status",
    ) as "roadmap",
    raw_secret_egress: exactBoolean(
      status.raw_secret_egress,
      false,
      "Tinker status secret egress",
    ) as false,
  });
}

export function parseTinkerAccountRequestReceipt(
  value: unknown,
): TinkerAccountRequestReceipt {
  const receipt = record(value, "Tinker account-request receipt");
  exactKeys(receipt, [
    "surface",
    "schema_version",
    "account_id",
    "status",
    "mode",
    "request_commitment",
    "owner_address_hash",
    "release_lineage_digest",
    "account_binding_ceremony_receipt_digest",
    "deployment_intent_digest",
    "account_policy",
    "upstream_account_exists",
    "provisioning_performed",
    "browser_supplied_account_commitment_accepted",
    "hosted_card_funding",
    "token_exchange",
    "gate",
    "idempotent_replay",
    "raw_secret_egress",
  ], "Tinker account-request receipt");
  if (
    receipt.surface !== "tinker_customer_account_request"
    || receipt.schema_version !== 1
    || receipt.status !== "requested"
    || !["create", "link_existing"].includes(String(receipt.mode))
    || receipt.upstream_account_exists !== false
    || receipt.provisioning_performed !== false
    || receipt.browser_supplied_account_commitment_accepted !== false
    || receipt.hosted_card_funding !== "roadmap"
    || receipt.token_exchange !== "roadmap"
    || typeof receipt.idempotent_replay !== "boolean"
    || receipt.raw_secret_egress !== false
  ) throw new Error("Tinker account-request receipt is invalid");
  return Object.freeze({
    ...receipt,
    account_id: patterned(receipt.account_id, ACCOUNT_ID, "Tinker account ID"),
    mode: receipt.mode as TinkerAccountMode,
    request_commitment: patterned(
      receipt.request_commitment,
      NONZERO_SHA256,
      "Tinker request commitment",
    ),
    owner_address_hash: patterned(
      receipt.owner_address_hash,
      NONZERO_SHA256,
      "Tinker owner hash",
    ),
    release_lineage_digest: patterned(
      receipt.release_lineage_digest,
      NONZERO_SHA256,
      "Tinker release lineage",
    ),
    account_binding_ceremony_receipt_digest: patterned(
      receipt.account_binding_ceremony_receipt_digest,
      NONZERO_SHA256,
      "Tinker ceremony receipt",
    ),
    deployment_intent_digest: patterned(
      receipt.deployment_intent_digest,
      NONZERO_SHA256,
      "Tinker deployment intent",
    ),
    account_policy: parseAccountPolicy(receipt.account_policy),
    gate: parseGate(receipt.gate),
  }) as TinkerAccountRequestReceipt;
}

function parseCredentialSummary(
  value: unknown,
): TinkerCredentialSummary {
  const credential = record(value, "Tinker credential");
  exactKeys(credential, [
    "credential_id",
    "status",
    "persisted_status",
    "operations",
    "scopes",
    "max_operation_policy_units",
    "recipient_public_key_hash",
    "jwt_id_hash",
    "issued_at",
    "expires_at",
    "revoked_at",
    "token_returned_in_plaintext",
  ], "Tinker credential");
  if (
    !Array.isArray(credential.operations)
    || credential.operations.length !== 1
    || credential.operations[0] !== "training"
    || !Array.isArray(credential.scopes)
    || credential.scopes.length !== 1
    || credential.scopes[0] !== "tinker:train"
    || !["active", "expired", "revoked"].includes(String(credential.status))
    || !["active", "revoked"].includes(String(credential.persisted_status))
    || credential.token_returned_in_plaintext !== false
  ) throw new Error("Tinker credential authority is invalid");
  const issuedAt = integer(
    credential.issued_at,
    "Tinker credential issue time",
    1,
    4_102_444_800,
  );
  const expiresAt = integer(
    credential.expires_at,
    "Tinker credential expiry",
    issuedAt + 1,
    4_102_444_800,
  );
  if (expiresAt - issuedAt > 3_600) {
    throw new Error("Tinker credential lifetime exceeds the release cap");
  }
  const revokedAt = integer(
    credential.revoked_at,
    "Tinker credential revocation time",
    0,
    4_102_444_800,
  );
  if (
    (credential.persisted_status === "revoked") !== (revokedAt > 0)
    || (credential.status === "revoked")
      !== (credential.persisted_status === "revoked")
    || (revokedAt > 0 && revokedAt < issuedAt)
  ) throw new Error("Tinker credential temporal state is inconsistent");
  return Object.freeze({
    credential_id: patterned(
      credential.credential_id,
      CREDENTIAL_ID,
      "Tinker credential ID",
    ),
    operations: ["training"] as const,
    scopes: ["tinker:train"] as const,
    max_operation_policy_units: positiveUint256String(
      credential.max_operation_policy_units,
      "Tinker credential operation cap",
    ),
    recipient_public_key_hash: patterned(
      credential.recipient_public_key_hash,
      NONZERO_SHA256,
      "Tinker credential recipient hash",
    ),
    jwt_id_hash: patterned(
      credential.jwt_id_hash,
      NONZERO_SHA256,
      "Tinker credential JWT ID hash",
    ),
    status: credential.status as TinkerCredentialStatus,
    persisted_status: credential.persisted_status as "active" | "revoked",
    issued_at: issuedAt,
    expires_at: expiresAt,
    revoked_at: revokedAt,
    token_returned_in_plaintext: false,
  });
}

function parseCredentialCapsule(value: unknown): TinkerCredentialCapsule {
  const capsule = record(value, "Tinker credential capsule");
  exactKeys(capsule, [
    "delivery",
    "encrypted_token",
    "associated_data",
    "associated_data_hash",
    "recipient_public_key_hash",
    "token_returned_in_plaintext",
  ], "Tinker credential capsule");
  const encrypted = record(
    capsule.encrypted_token,
    "Tinker encrypted credential",
  );
  exactKeys(
    encrypted,
    ["ephemeral_public_key", "nonce", "ciphertext"],
    "Tinker encrypted credential",
  );
  if (
    capsule.delivery !== "x25519_aes_256_gcm_envelope"
    || capsule.token_returned_in_plaintext !== false
  ) throw new Error("Tinker credential capsule contract is invalid");
  return Object.freeze({
    delivery: "x25519_aes_256_gcm_envelope",
    encrypted_token: Object.freeze({
      ephemeral_public_key: patterned(
        encrypted.ephemeral_public_key,
        HEX_64,
        "Tinker ephemeral public key",
      ),
      nonce: patterned(
        encrypted.nonce,
        /^[0-9a-f]{24}$/,
        "Tinker credential nonce",
      ),
      ciphertext: patterned(
        encrypted.ciphertext,
        /^[0-9a-f]{32,16384}$/,
        "Tinker credential ciphertext",
        16_384,
      ),
    }),
    associated_data: patterned(
      capsule.associated_data,
      /^[0-9a-f]{2,16384}$/,
      "Tinker credential associated data",
      16_384,
    ),
    associated_data_hash: patterned(
      capsule.associated_data_hash,
      NONZERO_SHA256,
      "Tinker credential associated-data hash",
    ),
    recipient_public_key_hash: patterned(
      capsule.recipient_public_key_hash,
      NONZERO_SHA256,
      "Tinker credential recipient hash",
    ),
    token_returned_in_plaintext: false,
  });
}

export function parseTinkerCredentialIssueReceipt(
  value: unknown,
): TinkerCredentialIssueReceipt {
  const receipt = record(value, "Tinker credential-issue receipt");
  exactKeys(receipt, [
    "surface",
    "schema_version",
    "credential_id",
    "account_id",
    "status",
    "operations",
    "scopes",
    "max_operation_policy_units",
    "account_policy_digest",
    "release_lineage_digest",
    "account_binding_authority_digest",
    "account_binding_ceremony_receipt_digest",
    "deployment_intent_digest",
    "issued_at",
    "expires_at",
    "jwt_id_hash",
    "capsule",
    "upstream_tinker_key_exposed",
    "upstream_project_exposed",
    "token_returned_in_plaintext",
    "gate",
    "idempotent_replay",
    "raw_secret_egress",
  ], "Tinker credential-issue receipt");
  if (
    receipt.surface !== "tinker_customer_credential_issue"
    || receipt.schema_version !== 1
    || receipt.status !== "active"
    || receipt.upstream_tinker_key_exposed !== false
    || receipt.upstream_project_exposed !== false
    || receipt.token_returned_in_plaintext !== false
    || typeof receipt.idempotent_replay !== "boolean"
    || receipt.raw_secret_egress !== false
  ) throw new Error("Tinker credential-issue receipt is invalid");
  if (
    !Array.isArray(receipt.operations)
    || receipt.operations.length !== 1
    || receipt.operations[0] !== "training"
    || !Array.isArray(receipt.scopes)
    || receipt.scopes.length !== 1
    || receipt.scopes[0] !== "tinker:train"
  ) throw new Error("Tinker credential-issue authority is invalid");
  const issuedAt = integer(
    receipt.issued_at,
    "Tinker credential issue time",
    1,
    4_102_444_800,
  );
  const expiresAt = integer(
    receipt.expires_at,
    "Tinker credential expiry",
    issuedAt + 1,
    4_102_444_800,
  );
  if (expiresAt - issuedAt > 3_600) {
    throw new Error("Tinker credential lifetime exceeds the release cap");
  }
  return Object.freeze({
    surface: "tinker_customer_credential_issue",
    schema_version: 1,
    credential_id: patterned(
      receipt.credential_id,
      CREDENTIAL_ID,
      "Tinker credential ID",
    ),
    account_id: patterned(
      receipt.account_id,
      ACCOUNT_ID,
      "Tinker account ID",
    ),
    status: "active",
    operations: ["training"] as const,
    scopes: ["tinker:train"] as const,
    max_operation_policy_units: positiveUint256String(
      receipt.max_operation_policy_units,
      "Tinker credential operation cap",
    ),
    account_policy_digest: patterned(
      receipt.account_policy_digest,
      NONZERO_SHA256,
      "Tinker account policy digest",
    ),
    release_lineage_digest: patterned(
      receipt.release_lineage_digest,
      NONZERO_SHA256,
      "Tinker credential release lineage",
    ),
    account_binding_authority_digest: patterned(
      receipt.account_binding_authority_digest,
      NONZERO_SHA256,
      "Tinker credential binding authority",
    ),
    account_binding_ceremony_receipt_digest: patterned(
      receipt.account_binding_ceremony_receipt_digest,
      NONZERO_SHA256,
      "Tinker credential ceremony receipt",
    ),
    deployment_intent_digest: patterned(
      receipt.deployment_intent_digest,
      NONZERO_SHA256,
      "Tinker credential deployment intent",
    ),
    issued_at: issuedAt,
    expires_at: expiresAt,
    jwt_id_hash: patterned(
      receipt.jwt_id_hash,
      NONZERO_SHA256,
      "Tinker credential JWT ID hash",
    ),
    capsule: parseCredentialCapsule(receipt.capsule),
    upstream_tinker_key_exposed: false,
    upstream_project_exposed: false,
    token_returned_in_plaintext: false,
    gate: parseGate(receipt.gate),
    idempotent_replay: receipt.idempotent_replay as boolean,
    raw_secret_egress: false,
  });
}

export function parseTinkerCredentialRotationReceipt(
  value: unknown,
  expectedAccountId: string,
  expectedPriorCredentialId: string,
): TinkerCredentialRotationReceipt {
  const receipt = record(value, "Tinker credential-rotation receipt");
  exactKeys(receipt, [
    "surface",
    "schema_version",
    "account_id",
    "prior_credential_id",
    "credential_id",
    "status",
    "operations",
    "scopes",
    "max_operation_policy_units",
    "account_policy_digest",
    "release_lineage_digest",
    "account_binding_authority_digest",
    "account_binding_ceremony_receipt_digest",
    "deployment_intent_digest",
    "issued_at",
    "expires_at",
    "jwt_id_hash",
    "capsule",
    "prior_credential_revoked",
    "rotation_order",
    "gate",
    "idempotent_replay",
    "upstream_tinker_key_exposed",
    "upstream_project_exposed",
    "token_returned_in_plaintext",
    "raw_secret_egress",
  ], "Tinker credential-rotation receipt");
  if (
    receipt.surface !== "tinker_customer_credential_rotation"
    || receipt.schema_version !== 1
    || receipt.account_id !== expectedAccountId
    || receipt.prior_credential_id !== expectedPriorCredentialId
    || receipt.status !== "active"
    || !Array.isArray(receipt.operations)
    || receipt.operations.length !== 1
    || receipt.operations[0] !== "training"
    || !Array.isArray(receipt.scopes)
    || receipt.scopes.length !== 1
    || receipt.scopes[0] !== "tinker:train"
    || receipt.prior_credential_revoked !== true
    || receipt.rotation_order !== "revoke_then_issue_no_authority_overlap"
    || typeof receipt.idempotent_replay !== "boolean"
    || receipt.upstream_tinker_key_exposed !== false
    || receipt.upstream_project_exposed !== false
    || receipt.token_returned_in_plaintext !== false
    || receipt.raw_secret_egress !== false
  ) throw new Error("Tinker credential-rotation receipt is invalid");
  const credentialId = patterned(
    receipt.credential_id,
    CREDENTIAL_ID,
    "Tinker replacement credential ID",
  );
  if (credentialId === expectedPriorCredentialId) {
    throw new Error("Tinker credential rotation reused its prior identity");
  }
  const issuedAt = integer(
    receipt.issued_at,
    "Tinker replacement issue time",
    1,
    4_102_444_800,
  );
  const expiresAt = integer(
    receipt.expires_at,
    "Tinker replacement expiry",
    issuedAt + 1,
    4_102_444_800,
  );
  if (expiresAt - issuedAt > 3_600) {
    throw new Error("Tinker replacement lifetime exceeds the release cap");
  }
  return Object.freeze({
    surface: "tinker_customer_credential_rotation",
    schema_version: 1,
    account_id: patterned(
      receipt.account_id,
      ACCOUNT_ID,
      "Tinker account ID",
    ),
    prior_credential_id: patterned(
      receipt.prior_credential_id,
      CREDENTIAL_ID,
      "Tinker prior credential ID",
    ),
    credential_id: credentialId,
    status: "active",
    operations: ["training"] as const,
    scopes: ["tinker:train"] as const,
    max_operation_policy_units: positiveUint256String(
      receipt.max_operation_policy_units,
      "Tinker replacement operation cap",
    ),
    account_policy_digest: patterned(
      receipt.account_policy_digest,
      NONZERO_SHA256,
      "Tinker account policy digest",
    ),
    release_lineage_digest: patterned(
      receipt.release_lineage_digest,
      NONZERO_SHA256,
      "Tinker replacement release lineage",
    ),
    account_binding_authority_digest: patterned(
      receipt.account_binding_authority_digest,
      NONZERO_SHA256,
      "Tinker replacement binding authority",
    ),
    account_binding_ceremony_receipt_digest: patterned(
      receipt.account_binding_ceremony_receipt_digest,
      NONZERO_SHA256,
      "Tinker replacement ceremony receipt",
    ),
    deployment_intent_digest: patterned(
      receipt.deployment_intent_digest,
      NONZERO_SHA256,
      "Tinker replacement deployment intent",
    ),
    issued_at: issuedAt,
    expires_at: expiresAt,
    jwt_id_hash: patterned(
      receipt.jwt_id_hash,
      NONZERO_SHA256,
      "Tinker replacement JWT ID hash",
    ),
    capsule: parseCredentialCapsule(receipt.capsule),
    prior_credential_revoked: true,
    rotation_order: "revoke_then_issue_no_authority_overlap",
    gate: parseGate(receipt.gate),
    idempotent_replay: receipt.idempotent_replay as boolean,
    upstream_tinker_key_exposed: false,
    upstream_project_exposed: false,
    token_returned_in_plaintext: false,
    raw_secret_egress: false,
  });
}

export function parseTinkerCredentialList(
  value: unknown,
  expectedAccountId: string,
): TinkerCredentialList {
  const result = record(value, "Tinker credential list");
  exactKeys(result, [
    "surface",
    "schema_version",
    "account_id",
    "account_status",
    "release_lineage_digest",
    "account_binding_authority_digest",
    "total_credentials",
    "page_credential_count",
    "page_limit",
    "maximum_page_size",
    "has_more",
    "next_cursor",
    "snapshot_sequence",
    "ordering",
    "credentials",
    "upstream_tinker_key_exposed",
    "upstream_project_exposed",
    "credential_capsules_returned",
    "plaintext_token_egress",
    "raw_secret_egress",
  ], "Tinker credential list");
  if (
    result.surface !== "tinker_customer_credentials"
    || result.schema_version !== 2
    || result.account_id !== expectedAccountId
    || !["requested", "active", "cancelled", "revoked"].includes(String(result.account_status))
    || !Array.isArray(result.credentials)
    || result.credentials.length > MAX_CREDENTIAL_PAGE_SIZE
    || typeof result.has_more !== "boolean"
    || result.maximum_page_size !== MAX_CREDENTIAL_PAGE_SIZE
    || result.ordering !== "issued_at_desc_then_credential_id_desc"
    || result.upstream_tinker_key_exposed !== false
    || result.upstream_project_exposed !== false
    || result.credential_capsules_returned !== false
    || result.plaintext_token_egress !== false
    || result.raw_secret_egress !== false
  ) throw new Error("Tinker credential list is invalid");
  const accountStatus = result.account_status as TinkerAccountLifecycleStatus;
  const totalCredentials = integer(
    result.total_credentials,
    "Tinker total credential count",
    0,
    100_000,
  );
  const pageCredentialCount = integer(
    result.page_credential_count,
    "Tinker page credential count",
    0,
    MAX_CREDENTIAL_PAGE_SIZE,
  );
  const pageLimit = integer(
    result.page_limit,
    "Tinker credential page limit",
    1,
    MAX_CREDENTIAL_PAGE_SIZE,
  );
  const snapshotSequence = integer(
    result.snapshot_sequence,
    "Tinker credential snapshot sequence",
    0,
    Number.MAX_SAFE_INTEGER,
  );
  if (
    pageCredentialCount !== result.credentials.length
    || pageCredentialCount > pageLimit
    || pageCredentialCount > totalCredentials
    || (totalCredentials > 0 && pageCredentialCount === 0)
    || (result.has_more && pageCredentialCount !== pageLimit)
  ) throw new Error("Tinker credential-list bounds are inconsistent");
  const nextCursor = result.next_cursor === null
    ? null
    : patterned(
      result.next_cursor,
      OPAQUE_CURSOR,
      "Tinker credential cursor",
      MAX_CREDENTIAL_CURSOR_BYTES,
    );
  if (result.has_more !== (nextCursor !== null)) {
    throw new Error("Tinker credential cursor state is inconsistent");
  }
  const authorityDigest = result.account_binding_authority_digest === null
    ? null
    : patterned(
      result.account_binding_authority_digest,
      NONZERO_SHA256,
      "Tinker credential-list binding authority",
    );
  if (
    ["active", "revoked"].includes(accountStatus) !== (authorityDigest !== null)
  ) throw new Error("Tinker credential-list activation evidence is inconsistent");
  const credentials = result.credentials.map(parseCredentialSummary);
  if (new Set(credentials.map((credential) => credential.credential_id)).size !== credentials.length) {
    throw new Error("Tinker credential list contains duplicate identities");
  }
  for (let index = 1; index < credentials.length; index += 1) {
    if (!credentialPrecedes(credentials[index - 1], credentials[index])) {
      throw new Error("Tinker credential list ordering is invalid");
    }
  }
  return Object.freeze({
    surface: "tinker_customer_credentials",
    schema_version: 2,
    account_id: expectedAccountId,
    account_status: accountStatus,
    release_lineage_digest: patterned(
      result.release_lineage_digest,
      NONZERO_SHA256,
      "Tinker credential-list release lineage",
    ),
    account_binding_authority_digest: authorityDigest,
    total_credentials: totalCredentials,
    page_credential_count: pageCredentialCount,
    page_limit: pageLimit,
    maximum_page_size: MAX_CREDENTIAL_PAGE_SIZE,
    has_more: result.has_more as boolean,
    next_cursor: nextCursor,
    snapshot_sequence: snapshotSequence,
    ordering: "issued_at_desc_then_credential_id_desc",
    credentials: Object.freeze(credentials),
    upstream_tinker_key_exposed: false,
    upstream_project_exposed: false,
    credential_capsules_returned: false,
    plaintext_token_egress: false,
    raw_secret_egress: false,
  });
}

function credentialPrecedes(
  earlier: TinkerCredentialSummary,
  later: TinkerCredentialSummary,
): boolean {
  return earlier.issued_at > later.issued_at
    || (
      earlier.issued_at === later.issued_at
      && earlier.credential_id > later.credential_id
    );
}

export function beginTinkerCredentialHistory(
  page: TinkerCredentialList,
): TinkerCredentialHistory {
  if (!page.has_more && page.credentials.length !== page.total_credentials) {
    throw new Error("Tinker credential history is incomplete");
  }
  return Object.freeze({
    account_id: page.account_id,
    account_status: page.account_status,
    release_lineage_digest: page.release_lineage_digest,
    account_binding_authority_digest:
      page.account_binding_authority_digest,
    total_credentials: page.total_credentials,
    page_limit: page.page_limit,
    maximum_page_size: page.maximum_page_size,
    has_more: page.has_more,
    next_cursor: page.next_cursor,
    snapshot_sequence: page.snapshot_sequence,
    ordering: page.ordering,
    credentials: Object.freeze([...page.credentials]),
  });
}

export function appendTinkerCredentialPage(
  history: TinkerCredentialHistory,
  page: TinkerCredentialList,
): TinkerCredentialHistory {
  if (
    !history.has_more
    || history.next_cursor === null
    || page.account_id !== history.account_id
    || page.account_status !== history.account_status
    || page.release_lineage_digest !== history.release_lineage_digest
    || page.account_binding_authority_digest
      !== history.account_binding_authority_digest
    || page.total_credentials !== history.total_credentials
    || page.page_limit !== history.page_limit
    || page.maximum_page_size !== history.maximum_page_size
    || page.snapshot_sequence !== history.snapshot_sequence
    || page.ordering !== history.ordering
    || page.credentials.length === 0
  ) throw new Error("Tinker credential page does not continue this snapshot");
  const previous = history.credentials.at(-1);
  const next = page.credentials[0];
  if (previous && !credentialPrecedes(previous, next)) {
    throw new Error("Tinker credential page boundary is not strictly ordered");
  }
  const identities = new Set(
    history.credentials.map((credential) => credential.credential_id),
  );
  if (page.credentials.some(
    (credential) => identities.has(credential.credential_id),
  )) throw new Error("Tinker credential page repeats an existing identity");
  const credentials = Object.freeze([
    ...history.credentials,
    ...page.credentials,
  ]);
  if (
    credentials.length > history.total_credentials
    || (page.has_more && credentials.length >= history.total_credentials)
    || (!page.has_more && credentials.length !== history.total_credentials)
  ) throw new Error("Tinker credential page count is inconsistent");
  return Object.freeze({
    ...history,
    has_more: page.has_more,
    next_cursor: page.next_cursor,
    credentials,
  });
}

export function refreshTinkerCredentialHistory(
  history: TinkerCredentialHistory,
  firstPage: TinkerCredentialList,
): TinkerCredentialHistory {
  if (
    history.account_id !== firstPage.account_id
    || history.snapshot_sequence !== firstPage.snapshot_sequence
  ) return beginTinkerCredentialHistory(firstPage);
  if (
    history.account_status !== firstPage.account_status
    || history.release_lineage_digest !== firstPage.release_lineage_digest
    || history.account_binding_authority_digest
      !== firstPage.account_binding_authority_digest
    || history.total_credentials !== firstPage.total_credentials
    || history.page_limit !== firstPage.page_limit
    || firstPage.credentials.length > history.credentials.length
    || firstPage.credentials.some(
      (credential, index) => (
        credential.credential_id !== history.credentials[index]?.credential_id
      ),
    )
  ) throw new Error("Tinker credential refresh drifted within one snapshot");
  return Object.freeze({
    ...history,
    account_status: firstPage.account_status,
    credentials: Object.freeze([
      ...firstPage.credentials,
      ...history.credentials.slice(firstPage.credentials.length),
    ]),
  });
}

export function assertTinkerCredentialListMatchesAccount(
  listing: TinkerCredentialList | TinkerCredentialHistory,
  account: TinkerAccountStatus,
): void {
  if (
    listing.account_id !== account.account_id
    || listing.account_status !== account.status
    || listing.release_lineage_digest !== account.release_lineage_digest
    || listing.account_binding_authority_digest
      !== account.account_binding_authority_digest
  ) throw new Error("Tinker credential list does not match its account record");
  const accountCap = BigInt(account.account_policy.max_operation_policy_units);
  if (listing.credentials.some(
    (credential) => BigInt(credential.max_operation_policy_units) > accountCap,
  )) {
    throw new Error("Tinker credential list exceeds its account policy");
  }
}

export function parseTinkerCredentialRevokeReceipt(
  value: unknown,
  expectedAccountId: string,
  expectedCredentialId: string,
): TinkerCredentialRevokeReceipt {
  const receipt = record(value, "Tinker credential-revoke receipt");
  exactKeys(receipt, [
    "surface",
    "schema_version",
    "credential_id",
    "account_id",
    "status",
    "jwt_id_hash",
    "release_lineage_digest",
    "account_binding_authority_digest",
    "account_binding_ceremony_receipt_digest",
    "deployment_intent_digest",
    "revoked_at",
    "gate",
    "idempotent_replay",
    "raw_secret_egress",
  ], "Tinker credential-revoke receipt");
  if (
    receipt.surface !== "tinker_customer_credential_revoke"
    || receipt.schema_version !== 1
    || receipt.account_id !== expectedAccountId
    || receipt.credential_id !== expectedCredentialId
    || receipt.status !== "revoked"
    || typeof receipt.idempotent_replay !== "boolean"
    || receipt.raw_secret_egress !== false
  ) throw new Error("Tinker credential-revoke receipt is invalid");
  return Object.freeze({
    surface: "tinker_customer_credential_revoke",
    schema_version: 1,
    credential_id: patterned(
      receipt.credential_id,
      CREDENTIAL_ID,
      "Tinker credential ID",
    ),
    account_id: patterned(
      receipt.account_id,
      ACCOUNT_ID,
      "Tinker account ID",
    ),
    status: "revoked",
    jwt_id_hash: patterned(
      receipt.jwt_id_hash,
      NONZERO_SHA256,
      "Tinker credential JWT ID hash",
    ),
    release_lineage_digest: patterned(
      receipt.release_lineage_digest,
      NONZERO_SHA256,
      "Tinker credential release lineage",
    ),
    account_binding_authority_digest: patterned(
      receipt.account_binding_authority_digest,
      NONZERO_SHA256,
      "Tinker credential binding authority",
    ),
    account_binding_ceremony_receipt_digest: patterned(
      receipt.account_binding_ceremony_receipt_digest,
      NONZERO_SHA256,
      "Tinker credential ceremony receipt",
    ),
    deployment_intent_digest: patterned(
      receipt.deployment_intent_digest,
      NONZERO_SHA256,
      "Tinker credential deployment intent",
    ),
    revoked_at: integer(
      receipt.revoked_at,
      "Tinker credential revocation time",
      1,
      4_102_444_800,
    ),
    gate: parseGate(receipt.gate),
    idempotent_replay: receipt.idempotent_replay as boolean,
    raw_secret_egress: false,
  });
}

export function parseTinkerAccountRevokeReceipt(
  value: unknown,
  expectedAccountId: string,
): TinkerAccountRevokeReceipt {
  const receipt = record(value, "Tinker account-revoke receipt");
  exactKeys(receipt, [
    "surface",
    "schema_version",
    "account_id",
    "status",
    "owner_address_hash",
    "release_lineage_digest",
    "account_binding_authority_digest",
    "account_binding_ceremony_receipt_digest",
    "deployment_intent_digest",
    "provisioning_result_attested",
    "revoked_credentials",
    "outstanding_reservations",
    "new_authority_permitted",
    "outstanding_reservations_require_attested_finalization",
    "gate",
    "idempotent_replay",
    "raw_secret_egress",
  ], "Tinker account-revoke receipt");
  if (
    receipt.surface !== "tinker_customer_account_revoke"
    || receipt.schema_version !== 1
    || receipt.account_id !== expectedAccountId
    || !["cancelled", "revoked"].includes(String(receipt.status))
    || receipt.new_authority_permitted !== false
    || typeof receipt.provisioning_result_attested !== "boolean"
    || typeof receipt.outstanding_reservations_require_attested_finalization !== "boolean"
    || typeof receipt.idempotent_replay !== "boolean"
    || receipt.raw_secret_egress !== false
  ) throw new Error("Tinker account-revoke receipt is invalid");
  const activated = receipt.status === "revoked";
  if (
    receipt.provisioning_result_attested !== activated
    || (activated && !NONZERO_SHA256.test(String(receipt.account_binding_authority_digest)))
    || (!activated && receipt.account_binding_authority_digest !== null)
  ) throw new Error("Tinker account-revoke activation evidence is inconsistent");
  const outstanding = integer(
    receipt.outstanding_reservations,
    "Tinker outstanding reservation count",
    0,
    1_000_000,
  );
  if (
    receipt.outstanding_reservations_require_attested_finalization
    !== (outstanding > 0)
  ) throw new Error("Tinker account-revoke liabilities are inconsistent");
  return Object.freeze({
    surface: "tinker_customer_account_revoke",
    schema_version: 1,
    account_id: patterned(
      receipt.account_id,
      ACCOUNT_ID,
      "Tinker account ID",
    ),
    status: receipt.status as "cancelled" | "revoked",
    owner_address_hash: patterned(
      receipt.owner_address_hash,
      NONZERO_SHA256,
      "Tinker owner hash",
    ),
    release_lineage_digest: patterned(
      receipt.release_lineage_digest,
      NONZERO_SHA256,
      "Tinker release lineage",
    ),
    account_binding_authority_digest: activated
      ? patterned(
        receipt.account_binding_authority_digest,
        NONZERO_SHA256,
        "Tinker binding authority digest",
      )
      : null,
    account_binding_ceremony_receipt_digest: patterned(
      receipt.account_binding_ceremony_receipt_digest,
      NONZERO_SHA256,
      "Tinker ceremony receipt",
    ),
    deployment_intent_digest: patterned(
      receipt.deployment_intent_digest,
      NONZERO_SHA256,
      "Tinker deployment intent",
    ),
    provisioning_result_attested: activated,
    revoked_credentials: integer(
      receipt.revoked_credentials,
      "Tinker revoked credential count",
      0,
      100_000,
    ),
    outstanding_reservations: outstanding,
    new_authority_permitted: false,
    outstanding_reservations_require_attested_finalization: outstanding > 0,
    gate: parseGate(receipt.gate),
    idempotent_replay: receipt.idempotent_replay as boolean,
    raw_secret_egress: false,
  });
}

function trainingValueBand(
  value: unknown,
  label: string,
): TinkerTrainingValueBand {
  if (
    typeof value !== "string"
    || !TINKER_TRAINING_VALUE_BANDS.includes(
      value as TinkerTrainingValueBand,
    )
  ) throw new Error(`${label} is invalid`);
  return value as TinkerTrainingValueBand;
}

function parseTinkerTrainingResult(value: unknown): TinkerTrainingResult {
  const result = record(value, "Tinker training result");
  exactKeys(result, [
    "surface",
    "schema_version",
    "success",
    "outcome",
    "furthest_stage",
    "deal_id_hash",
    "model_hash",
    "rank",
    "steps_requested",
    "steps_completed",
    "max_usd_band",
    "metered_cost_band",
    "checkpoint_saved",
    "error_kind",
    "bounded_message",
    "issued_at",
    "provider_dispatch_attempted",
    "provider_dispatch_performed",
    "provider_outcome_ambiguous",
    "raw_secret_egress",
  ], "Tinker training result");
  const outcomes: readonly TinkerTrainingOutcome[] = [
    "policy_check_failed",
    "policy_denied",
    "api_key_missing",
    "training_completed",
    "training_failed",
    "provider_outcome_ambiguous",
  ];
  if (
    result.surface !== "tinker_customer_training_result"
    || result.schema_version !== 1
    || typeof result.success !== "boolean"
    || typeof result.outcome !== "string"
    || !outcomes.includes(result.outcome as TinkerTrainingOutcome)
    || typeof result.checkpoint_saved !== "boolean"
    || typeof result.provider_dispatch_attempted !== "boolean"
    || typeof result.provider_dispatch_performed !== "boolean"
    || typeof result.provider_outcome_ambiguous !== "boolean"
    || result.raw_secret_egress !== false
  ) throw new Error("Tinker training result is invalid");
  const stepsRequested = integer(
    result.steps_requested,
    "Tinker training requested steps",
    1,
    50,
  );
  const stepsCompleted = integer(
    result.steps_completed,
    "Tinker training completed steps",
    0,
    stepsRequested,
  );
  const errorKind = patterned(
    result.error_kind,
    /^[A-Za-z0-9_.:-]*$/,
    "Tinker training error kind",
    128,
  );
  const boundedMessage = patterned(
    result.bounded_message,
    BOUNDED_RESULT_TEXT,
    "Tinker training bounded message",
    128,
  );
  const succeeded = result.success;
  if (
    succeeded
      ? (
        result.outcome !== "training_completed"
        || result.provider_dispatch_attempted !== true
        || result.provider_dispatch_performed !== true
        || result.provider_outcome_ambiguous !== false
        || stepsCompleted !== stepsRequested
      )
      : (
        result.outcome === "training_completed"
        || result.provider_dispatch_attempted !== false
        || result.provider_dispatch_performed !== false
        || result.provider_outcome_ambiguous !== false
      )
  ) throw new Error("Tinker training provider evidence is inconsistent");
  return Object.freeze({
    surface: "tinker_customer_training_result",
    schema_version: 1,
    success: succeeded,
    outcome: result.outcome as TinkerTrainingOutcome,
    furthest_stage: patterned(
      result.furthest_stage,
      TRAINING_STAGE,
      "Tinker training stage",
    ),
    deal_id_hash: patterned(
      result.deal_id_hash,
      HEX_64,
      "Tinker training deal hash",
    ),
    model_hash: patterned(
      result.model_hash,
      HEX_64,
      "Tinker training model hash",
    ),
    rank: integer(result.rank, "Tinker training rank", 1, 256),
    steps_requested: stepsRequested,
    steps_completed: stepsCompleted,
    max_usd_band: trainingValueBand(
      result.max_usd_band,
      "Tinker training authority band",
    ),
    metered_cost_band: trainingValueBand(
      result.metered_cost_band,
      "Tinker training metered-cost band",
    ),
    checkpoint_saved: result.checkpoint_saved as boolean,
    error_kind: errorKind,
    bounded_message: boundedMessage,
    issued_at: integer(
      result.issued_at,
      "Tinker training issue time",
      1,
      4_102_444_800,
    ),
    provider_dispatch_attempted: result.provider_dispatch_attempted as boolean,
    provider_dispatch_performed: result.provider_dispatch_performed as boolean,
    provider_outcome_ambiguous: false,
    raw_secret_egress: false,
  });
}

export function parseTinkerTrainingExecutionReceipt(
  value: unknown,
  expected?: { maxUsdMicros?: number; steps?: number },
): TinkerTrainingExecutionReceipt {
  const receipt = record(value, "Tinker training execution receipt");
  exactKeys(receipt, [
    "surface",
    "schema_version",
    "status",
    "reservation_id",
    "reservation_commitment",
    "workload_commitment",
    "reserved_policy_units",
    "actual_policy_units",
    "released_policy_units",
    "policy_unit_definition",
    "provider_authoritative_billing",
    "authority_accounting_only",
    "fixed_ceiling_accounting",
    "at_most_once_claim_committed",
    "automatic_provider_redispatch",
    "reconciliation_required",
    "training_result",
    "settlement",
    "idempotent_replay",
    "raw_secret_egress",
  ], "Tinker training execution receipt");
  if (
    receipt.surface !== "tinker_customer_training_execution"
    || receipt.schema_version !== 1
    || !["settled", "released"].includes(String(receipt.status))
    || receipt.policy_unit_definition
      !== TINKER_CUSTOMER_TRAINING_POLICY_UNIT
    || receipt.provider_authoritative_billing !== false
    || receipt.authority_accounting_only !== true
    || receipt.fixed_ceiling_accounting !== true
    || receipt.at_most_once_claim_committed !== true
    || receipt.automatic_provider_redispatch !== false
    || receipt.reconciliation_required !== false
    || typeof receipt.idempotent_replay !== "boolean"
    || receipt.raw_secret_egress !== false
  ) throw new Error("Tinker training execution receipt is invalid");
  const trainingResult = parseTinkerTrainingResult(receipt.training_result);
  const reserved = positiveUint256String(
    receipt.reserved_policy_units,
    "Tinker training reserved policy units",
  );
  const actual = uint256String(
    receipt.actual_policy_units,
    "Tinker training actual policy units",
  );
  const released = uint256String(
    receipt.released_policy_units,
    "Tinker training released policy units",
  );
  if (
    BigInt(actual) + BigInt(released) !== BigInt(reserved)
    || (expected?.maxUsdMicros !== undefined
      && reserved !== String(integer(
        expected.maxUsdMicros,
        "Tinker requested training ceiling",
        1,
        5_000_000,
      )))
    || (expected?.steps !== undefined
      && trainingResult.steps_requested !== integer(
        expected.steps,
        "Tinker requested training steps",
        1,
        50,
      ))
  ) throw new Error("Tinker training accounting differs from the request");
  const settled = receipt.status === "settled";
  if (
    trainingResult.success !== settled
    || (settled
      ? actual !== reserved || released !== "0"
      : actual !== "0" || released !== reserved)
  ) throw new Error("Tinker training settlement accounting is inconsistent");
  const settlement = record(
    receipt.settlement,
    "Tinker training settlement",
  );
  exactKeys(settlement, [
    "status",
    "usage_receipt_hash",
    "dispatch_runtime_evidence_digest",
    "provider_dispatch_performed",
  ], "Tinker training settlement");
  if (
    settlement.status !== receipt.status
    || settlement.provider_dispatch_performed
      !== trainingResult.provider_dispatch_performed
  ) throw new Error("Tinker training settlement evidence is inconsistent");
  return Object.freeze({
    surface: "tinker_customer_training_execution",
    schema_version: 1,
    status: receipt.status as "settled" | "released",
    reservation_id: patterned(
      receipt.reservation_id,
      RESERVATION_ID,
      "Tinker training reservation ID",
    ),
    reservation_commitment: patterned(
      receipt.reservation_commitment,
      NONZERO_SHA256,
      "Tinker training reservation commitment",
    ),
    workload_commitment: patterned(
      receipt.workload_commitment,
      NONZERO_SHA256,
      "Tinker training workload commitment",
    ),
    reserved_policy_units: reserved,
    actual_policy_units: actual,
    released_policy_units: released,
    policy_unit_definition: TINKER_CUSTOMER_TRAINING_POLICY_UNIT,
    provider_authoritative_billing: false,
    authority_accounting_only: true,
    fixed_ceiling_accounting: true,
    at_most_once_claim_committed: true,
    automatic_provider_redispatch: false,
    reconciliation_required: false,
    training_result: trainingResult,
    settlement: Object.freeze({
      status: receipt.status as "settled" | "released",
      usage_receipt_hash: patterned(
        settlement.usage_receipt_hash,
        NONZERO_SHA256,
        "Tinker training usage receipt",
      ),
      dispatch_runtime_evidence_digest: patterned(
        settlement.dispatch_runtime_evidence_digest,
        NONZERO_SHA256,
        "Tinker training dispatch evidence",
      ),
      provider_dispatch_performed:
        settlement.provider_dispatch_performed as boolean,
    }),
    idempotent_replay: receipt.idempotent_replay as boolean,
    raw_secret_egress: false,
  });
}

export function parseTinkerTrainingReconciliationReceipt(
  value: unknown,
): TinkerTrainingReconciliationReceipt {
  const receipt = record(value, "Tinker training reconciliation receipt");
  exactKeys(receipt, [
    "surface",
    "schema_version",
    "status",
    "reservation_id",
    "reservation_commitment",
    "workload_commitment",
    "at_most_once_claim_committed",
    "automatic_provider_redispatch",
    "provider_outcome_confirmed",
    "provider_authoritative_billing",
    "authority_accounting_only",
    "raw_secret_egress",
  ], "Tinker training reconciliation receipt");
  if (
    receipt.surface !== "tinker_customer_training_reconciliation"
    || receipt.schema_version !== 1
    || receipt.status !== "reconciliation_required"
    || receipt.at_most_once_claim_committed !== true
    || receipt.automatic_provider_redispatch !== false
    || receipt.provider_outcome_confirmed !== false
    || receipt.provider_authoritative_billing !== false
    || receipt.authority_accounting_only !== true
    || receipt.raw_secret_egress !== false
  ) throw new Error("Tinker training reconciliation receipt is invalid");
  return Object.freeze({
    surface: "tinker_customer_training_reconciliation",
    schema_version: 1,
    status: "reconciliation_required",
    reservation_id: patterned(
      receipt.reservation_id,
      RESERVATION_ID,
      "Tinker training reservation ID",
    ),
    reservation_commitment: patterned(
      receipt.reservation_commitment,
      NONZERO_SHA256,
      "Tinker training reservation commitment",
    ),
    workload_commitment: patterned(
      receipt.workload_commitment,
      NONZERO_SHA256,
      "Tinker training workload commitment",
    ),
    at_most_once_claim_committed: true,
    automatic_provider_redispatch: false,
    provider_outcome_confirmed: false,
    provider_authoritative_billing: false,
    authority_accounting_only: true,
    raw_secret_egress: false,
  });
}

function assertNoSensitiveFields(value: unknown): void {
  const forbiddenFragments = [
    "api_key",
    "apikey",
    "project_id",
    "cookie",
    "card_number",
    "card_cvc",
    "card_expiry",
    "payment_method_id",
    "prompt",
    "examples",
    "dataset",
    "output_text",
    "checkpoint_path",
    "raw_run_id",
    "private_key",
    "plaintext_token",
  ];
  const forbiddenExact = new Set([
    "provideraccountid",
    "provideridentifier",
    "providersession",
    "providerauth",
    "bindingroot",
    "reviewershare",
    "reviewershares",
    "authorization",
    "sessioncookie",
    "tinkerapikey",
  ]);
  const pending: unknown[] = [value];
  let containers = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current || typeof current !== "object") continue;
    containers += 1;
    if (containers > 8_192) {
      throw new Error("Tinker response contains too many nested containers");
    }
    if (Array.isArray(current)) {
      pending.push(...current);
      continue;
    }
    for (const [key, nested] of Object.entries(
      current as Record<string, unknown>,
    )) {
      const normalized = key.toLowerCase().replaceAll("-", "_");
      const compact = key.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (normalized === "plaintext_token_egress") {
        if (nested !== false) {
          throw new Error("Tinker response contains a forbidden field");
        }
        continue;
      }
      if (
        forbiddenFragments.some((fragment) => normalized.includes(fragment))
        || forbiddenExact.has(compact)
      ) throw new Error("Tinker response contains a forbidden field");
      pending.push(nested);
    }
  }
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error("Tinker service did not return application/json");
  }
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new Error("Tinker response exceeded the public size limit");
  }
  if (!response.body) throw new Error("Tinker service returned an empty response");
  const reader = response.body.getReader();
  const streamDecoder = new TextDecoder("utf-8", { fatal: true });
  let text = "";
  let received = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("Tinker response exceeded the public size limit");
      }
      text += streamDecoder.decode(value, { stream: true });
    }
    text += streamDecoder.decode();
  } finally {
    reader.releaseLock();
  }
  try {
    const parsed: unknown = JSON.parse(text);
    assertNoSensitiveFields(parsed);
    return parsed;
  } catch (cause) {
    if (
      cause instanceof Error
      && (
        cause.message.startsWith("Tinker response")
        || cause.message.startsWith("Tinker service")
      )
    ) throw cause;
    throw new Error("Tinker service returned malformed JSON");
  }
}

function baseUrl(): string {
  if (!deployment.delegateUrl) {
    throw new Error("Fresh delegate endpoint is not configured");
  }
  return deployment.delegateUrl.replace(/\/$/, "");
}

async function request(
  path: string,
  options: {
    method?: "GET" | "POST";
    token: string;
    body?: Record<string, unknown>;
    serializedBody?: string;
    idempotencyKey?: string;
    signal?: AbortSignal;
  },
): Promise<{ response: Response; value: unknown }> {
  if (
    typeof options.token !== "string"
    || options.token.length < 80
    || options.token.length > 4_096
    || !JWT.test(options.token)
  ) throw new Error("Tinker bearer token is malformed");
  if (
    options.idempotencyKey
    && !IDEMPOTENCY_KEY.test(options.idempotencyKey)
  ) throw new Error("Tinker idempotency key is malformed");
  const headers: Record<string, string> = {
    Accept: "application/json",
    Authorization: `Bearer ${options.token}`,
  };
  if (options.body && options.serializedBody !== undefined) {
    throw new Error("Tinker request body is ambiguous");
  }
  if (options.body || options.serializedBody !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (options.idempotencyKey) {
    headers["Idempotency-Key"] = options.idempotencyKey;
  }
  const signal = options.signal
    ? AbortSignal.any([options.signal, AbortSignal.timeout(12_000)])
    : AbortSignal.timeout(12_000);
  const response = await fetch(`${baseUrl()}${path}`, {
    method: options.method ?? "GET",
    credentials: "omit",
    cache: "no-store",
    headers,
    body: options.serializedBody
      ?? (options.body ? JSON.stringify(options.body) : undefined),
    signal,
  });
  const value = await readBoundedJson(response);
  return { response, value };
}

function throwResponseError(response: Response, value: unknown): never {
  const object = value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
  const fallback = `Tinker request failed with status ${response.status}`;
  throw new TinkerRequestError(publicErrorText(
    typeof object.detail === "string" ? object.detail : fallback,
    fallback,
  ), response.status);
}

export async function fetchCurrentTinkerAccount(
  token: string,
  signal?: AbortSignal,
): Promise<TinkerAccountStatus | undefined> {
  const { response, value } = await request(
    "/tinker/customer/accounts/current",
    { token, signal },
  );
  if (response.status === 404) return undefined;
  if (!response.ok) throwResponseError(response, value);
  return parseTinkerAccountStatus(value);
}

export async function fetchTinkerAccount(
  token: string,
  accountId: string,
  signal?: AbortSignal,
): Promise<TinkerAccountStatus> {
  patterned(accountId, ACCOUNT_ID, "Tinker account ID");
  const { response, value } = await request(
    `/tinker/customer/accounts/${encodeURIComponent(accountId)}`,
    { token, signal },
  );
  if (!response.ok) throwResponseError(response, value);
  const status = parseTinkerAccountStatus(value);
  if (status.account_id !== accountId) {
    throw new Error("Tinker service returned a different account");
  }
  return status;
}

export async function requestTinkerAccount(
  token: string,
  mode: TinkerAccountMode,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<TinkerAccountRequestReceipt> {
  if (!["create", "link_existing"].includes(mode)) {
    throw new Error("Tinker account mode is invalid");
  }
  const { response, value } = await request(
    "/tinker/customer/accounts/requests",
    {
      method: "POST",
      token,
      body: { mode },
      idempotencyKey,
      signal,
    },
  );
  if (!response.ok) throwResponseError(response, value);
  const receipt = parseTinkerAccountRequestReceipt(value);
  if (receipt.mode !== mode) {
    throw new Error("Tinker account receipt is bound to another mode");
  }
  return receipt;
}

function tinkerCredentialPageOptions(
  value?: AbortSignal | TinkerCredentialPageOptions,
): TinkerCredentialPageOptions {
  if (!value) return {};
  if (typeof AbortSignal !== "undefined" && value instanceof AbortSignal) {
    return { signal: value };
  }
  return value as TinkerCredentialPageOptions;
}

export async function listTinkerCredentials(
  token: string,
  accountId: string,
  optionsOrSignal?: AbortSignal | TinkerCredentialPageOptions,
): Promise<TinkerCredentialList> {
  patterned(accountId, ACCOUNT_ID, "Tinker account ID");
  const options = tinkerCredentialPageOptions(optionsOrSignal);
  const limit = options.limit ?? DEFAULT_CREDENTIAL_PAGE_SIZE;
  integer(
    limit,
    "Tinker credential page limit",
    1,
    MAX_CREDENTIAL_PAGE_SIZE,
  );
  const parameters = new URLSearchParams({ limit: String(limit) });
  if (options.cursor !== undefined) {
    parameters.set(
      "cursor",
      patterned(
        options.cursor,
        OPAQUE_CURSOR,
        "Tinker credential cursor",
        MAX_CREDENTIAL_CURSOR_BYTES,
      ),
    );
  }
  const { response, value } = await request(
    (
      `/tinker/customer/accounts/${encodeURIComponent(accountId)}`
      + `/credentials?${parameters.toString()}`
    ),
    { token, signal: options.signal },
  );
  if (!response.ok) throwResponseError(response, value);
  return parseTinkerCredentialList(value, accountId);
}

export async function issueTinkerCredential(
  token: string,
  accountId: string,
  recipientPublicKey: string,
  ttlSeconds: number,
  maxOperationPolicyUnits: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<TinkerCredentialIssueReceipt> {
  patterned(accountId, ACCOUNT_ID, "Tinker account ID");
  patterned(
    recipientPublicKey,
    HEX_64,
    "Tinker credential recipient key",
  );
  integer(ttlSeconds, "Tinker credential lifetime", 60, 3_600);
  const credentialCap = positiveUint256String(
    maxOperationPolicyUnits,
    "Tinker credential operation cap",
  );
  const serializedBody = (
    `{"recipient_public_key":${JSON.stringify(recipientPublicKey)},`
    + `"operations":["training"],"ttl_seconds":${ttlSeconds},`
    + `"max_operation_policy_units":${credentialCap}}`
  );
  const { response, value } = await request(
    `/tinker/customer/accounts/${encodeURIComponent(accountId)}/credentials`,
    {
      method: "POST",
      token,
      serializedBody,
      idempotencyKey,
      signal,
    },
  );
  if (!response.ok) throwResponseError(response, value);
  const receipt = parseTinkerCredentialIssueReceipt(value);
  if (receipt.account_id !== accountId) {
    throw new Error("Tinker credential receipt belongs to another account");
  }
  if (receipt.expires_at - receipt.issued_at !== ttlSeconds) {
    throw new Error("Tinker credential receipt changed its requested lifetime");
  }
  if (receipt.max_operation_policy_units !== credentialCap) {
    throw new Error("Tinker credential receipt widened or changed its cap");
  }
  return receipt;
}

export async function rotateTinkerCredential(
  token: string,
  accountId: string,
  priorCredentialId: string,
  recipientPublicKey: string,
  ttlSeconds: number,
  maxOperationPolicyUnits: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<TinkerCredentialRotationReceipt> {
  patterned(accountId, ACCOUNT_ID, "Tinker account ID");
  patterned(
    priorCredentialId,
    CREDENTIAL_ID,
    "Tinker prior credential ID",
  );
  patterned(
    recipientPublicKey,
    HEX_64,
    "Tinker replacement recipient key",
  );
  integer(ttlSeconds, "Tinker replacement lifetime", 60, 3_600);
  const credentialCap = positiveUint256String(
    maxOperationPolicyUnits,
    "Tinker replacement operation cap",
  );
  const serializedBody = (
    `{"recipient_public_key":${JSON.stringify(recipientPublicKey)},`
    + `"operations":["training"],"ttl_seconds":${ttlSeconds},`
    + `"max_operation_policy_units":${credentialCap}}`
  );
  const { response, value } = await request(
    `/tinker/customer/accounts/${encodeURIComponent(accountId)}/credentials/${encodeURIComponent(priorCredentialId)}/rotate`,
    {
      method: "POST",
      token,
      serializedBody,
      idempotencyKey,
      signal,
    },
  );
  if (!response.ok) throwResponseError(response, value);
  const receipt = parseTinkerCredentialRotationReceipt(
    value,
    accountId,
    priorCredentialId,
  );
  if (receipt.max_operation_policy_units !== credentialCap) {
    throw new Error("Tinker replacement credential widened or changed its cap");
  }
  if (receipt.expires_at - receipt.issued_at !== ttlSeconds) {
    throw new Error("Tinker replacement credential changed its requested lifetime");
  }
  return receipt;
}

export async function revokeTinkerCredential(
  token: string,
  accountId: string,
  credentialId: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<TinkerCredentialRevokeReceipt> {
  patterned(accountId, ACCOUNT_ID, "Tinker account ID");
  patterned(credentialId, CREDENTIAL_ID, "Tinker credential ID");
  const { response, value } = await request(
    `/tinker/customer/accounts/${encodeURIComponent(accountId)}/credentials/${encodeURIComponent(credentialId)}/revoke`,
    { method: "POST", token, body: {}, idempotencyKey, signal },
  );
  if (!response.ok) throwResponseError(response, value);
  return parseTinkerCredentialRevokeReceipt(
    value,
    accountId,
    credentialId,
  );
}

export async function revokeTinkerAccount(
  token: string,
  accountId: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<TinkerAccountRevokeReceipt> {
  patterned(accountId, ACCOUNT_ID, "Tinker account ID");
  const { response, value } = await request(
    `/tinker/customer/accounts/${encodeURIComponent(accountId)}/revoke`,
    { method: "POST", token, body: {}, idempotencyKey, signal },
  );
  if (!response.ok) throwResponseError(response, value);
  return parseTinkerAccountRevokeReceipt(value, accountId);
}

export async function executeTinkerCustomerTraining(
  credentialToken: string,
  controls: TinkerTrainingControls,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<TinkerTrainingExecutionReceipt> {
  const maxUsdMicros = integer(
    controls.maxUsdMicros,
    "Tinker training authority ceiling",
    1,
    5_000_000,
  );
  const steps = integer(
    controls.steps,
    "Tinker training steps",
    1,
    50,
  );
  const ttlSeconds = integer(
    controls.ttlSeconds,
    "Tinker training lifetime",
    60,
    3_600,
  );
  const serializedBody = (
    `{"max_usd_micros":${maxUsdMicros},"steps":${steps},`
    + `"ttl_seconds":${ttlSeconds}}`
  );
  const { response, value } = await request(
    "/tinker/customer/train",
    {
      method: "POST",
      token: credentialToken,
      serializedBody,
      idempotencyKey,
      signal,
    },
  );
  if (response.status === 409) {
    const error = record(value, "Tinker training conflict");
    if (Object.keys(error).length === 1 && "detail" in error) {
      try {
        throw new TinkerTrainingReconciliationError(
          parseTinkerTrainingReconciliationReceipt(error.detail),
        );
      } catch (cause) {
        if (cause instanceof TinkerTrainingReconciliationError) throw cause;
      }
    }
  }
  if (!response.ok) throwResponseError(response, value);
  return parseTinkerTrainingExecutionReceipt(value, {
    maxUsdMicros,
    steps,
  });
}

function assertSameTrainingClaim(
  actual: {
    reservation_id: string;
    reservation_commitment: string;
    workload_commitment: string;
  },
  expected: TinkerTrainingReconciliationReceipt,
): void {
  if (
    actual.reservation_id !== expected.reservation_id
    || actual.reservation_commitment !== expected.reservation_commitment
    || actual.workload_commitment !== expected.workload_commitment
  ) throw new Error("Tinker training recovery differs from the retained claim");
}

export async function recoverTinkerCustomerTraining(
  credentialToken: string,
  controls: TinkerTrainingControls,
  idempotencyKey: string,
  retainedHold: TinkerTrainingReconciliationReceipt,
  signal?: AbortSignal,
): Promise<TinkerTrainingExecutionReceipt> {
  const hold = parseTinkerTrainingReconciliationReceipt(retainedHold);
  try {
    const receipt = await executeTinkerCustomerTraining(
      credentialToken,
      controls,
      idempotencyKey,
      signal,
    );
    assertSameTrainingClaim(receipt, hold);
    return receipt;
  } catch (cause) {
    if (cause instanceof TinkerTrainingReconciliationError) {
      assertSameTrainingClaim(cause.receipt, hold);
    }
    throw cause;
  }
}

function hexFromBytes(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  return Array.from(
    bytes,
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
}

function bytesFromHex(
  value: string,
  expectedBytes?: number,
): Uint8Array {
  if (
    value.length % 2 !== 0
    || !/^[0-9a-f]+$/.test(value)
    || (expectedBytes !== undefined && value.length !== expectedBytes * 2)
  ) throw new Error("Tinker credential capsule contains malformed hex");
  return Uint8Array.from(
    value.match(/../g) ?? [],
    (byte) => Number.parseInt(byte, 16),
  );
}

function buffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

async function sha256Text(domain: string, value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(`${domain}\u0000${value}`),
  );
  return `sha256:${hexFromBytes(digest)}`;
}

export async function generateTinkerDeviceKey(): Promise<TinkerDeviceKey> {
  if (!crypto?.subtle) {
    throw new Error("This browser cannot create a Tinker delivery key");
  }
  const pair = await crypto.subtle.generateKey(
    { name: "X25519" },
    false,
    ["deriveBits"],
  ) as CryptoKeyPair;
  const publicKey = await crypto.subtle.exportKey("raw", pair.publicKey);
  return {
    publicKeyHex: hexFromBytes(publicKey),
    privateKey: pair.privateKey,
  };
}

function decodeJwtPart(value: string): Record<string, unknown> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Tinker credential token encoding is invalid");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/")
    + "=".repeat((4 - (value.length % 4)) % 4);
  const bytes = Uint8Array.from(
    atob(padded),
    (character) => character.charCodeAt(0),
  );
  if (bytes.length > 8_192) {
    throw new Error("Tinker credential token segment exceeds its bound");
  }
  return record(
    JSON.parse(decoder.decode(bytes)),
    "Tinker credential token segment",
  );
}

async function validateCredentialToken(
  token: string,
  receipt: TinkerCredentialIssueReceipt | TinkerCredentialRotationReceipt,
  binding: Record<string, unknown>,
): Promise<void> {
  if (
    token.length < 80
    || token.length > 4_096
    || !JWT.test(token)
  ) throw new Error("Tinker credential token format is invalid");
  const [headerPart, payloadPart] = token.split(".");
  const header = decodeJwtPart(headerPart);
  const payload = decodeJwtPart(payloadPart);
  exactKeys(header, ["alg", "kid", "typ"], "Tinker credential token header");
  exactKeys(payload, [
    "iss",
    "aud",
    "sub",
    "account_id",
    "owner_address_hash",
    "scope",
    "operations",
    "max_operation_policy_units",
    "release_policy_tuple_digest",
    "release_lineage_digest",
    "account_binding_authority_digest",
    "account_binding_ceremony_receipt_digest",
    "deployment_intent_digest",
    "account_policy_digest",
    "iat",
    "nbf",
    "exp",
    "jti",
  ], "Tinker credential token claims");
  if (
    header.alg !== "HS256"
    || header.kid !== "dstack-tinker-customer-v1"
    || header.typ !== "JWT"
  ) throw new Error("Tinker credential token header is invalid");
  const now = Math.floor(Date.now() / 1_000);
  if (
    payload.iss !== "dnai-wikigen:tinker-customer"
    || payload.aud !== "dnai-wikigen:tinker-proxy"
    || payload.sub !== receipt.credential_id
    || payload.account_id !== receipt.account_id
    || payload.owner_address_hash !== binding.owner_address_hash
    || payload.scope !== "tinker:train"
    || payload.operations !== "training"
    || payload.max_operation_policy_units
      !== receipt.max_operation_policy_units
    || payload.release_policy_tuple_digest
      !== receipt.gate.release_policy_tuple_digest
    || payload.release_lineage_digest !== receipt.release_lineage_digest
    || payload.account_binding_authority_digest
      !== receipt.account_binding_authority_digest
    || payload.account_binding_ceremony_receipt_digest
      !== receipt.account_binding_ceremony_receipt_digest
    || payload.deployment_intent_digest !== receipt.deployment_intent_digest
    || payload.account_policy_digest !== receipt.account_policy_digest
    || payload.iat !== receipt.issued_at
    || payload.nbf !== receipt.issued_at
    || payload.exp !== receipt.expires_at
    || !Number.isInteger(payload.iat)
    || Number(payload.iat) > now + 30
    || !Number.isInteger(payload.exp)
    || Number(payload.exp) <= now
    || Number(payload.exp) - Number(payload.iat) > 3_600
    || !/^[0-9a-f]{32}$/.test(String(payload.jti))
  ) throw new Error("Tinker credential token claims do not match the receipt");
  const jwtIdHash = await sha256Text(
    "tinker_customer_jti",
    String(payload.jti),
  );
  if (jwtIdHash !== receipt.jwt_id_hash) {
    throw new Error("Tinker credential token ID does not match its receipt");
  }
}

export async function decryptTinkerCredentialCapsule(
  receipt: TinkerCredentialIssueReceipt | TinkerCredentialRotationReceipt,
  deviceKey: TinkerDeviceKey,
): Promise<string> {
  const { capsule } = receipt;
  const ephemeralBytes = bytesFromHex(
    capsule.encrypted_token.ephemeral_public_key,
    32,
  );
  const nonce = bytesFromHex(capsule.encrypted_token.nonce, 12);
  const ciphertext = bytesFromHex(capsule.encrypted_token.ciphertext);
  const associatedData = bytesFromHex(capsule.associated_data);
  let shared = new Uint8Array();
  let plaintext = new Uint8Array();
  try {
    if (
      await sha256Text(
        "tinker_customer_credential_aad",
        capsule.associated_data,
      ) !== capsule.associated_data_hash
    ) throw new Error("Tinker credential associated-data commitment is invalid");
    if (
      await sha256Text(
        "tinker_customer_recipient",
        deviceKey.publicKeyHex,
      ) !== capsule.recipient_public_key_hash
    ) throw new Error("Tinker credential recipient commitment is invalid");
    const binding = record(
      JSON.parse(decoder.decode(associatedData)),
      "Tinker credential binding",
    );
    exactKeys(binding, [
      "surface",
      "credential_id",
      "account_id",
      "owner_address_hash",
      "recipient_public_key_hash",
      "operations",
      "max_operation_policy_units",
      "jwt_id_hash",
      "release_policy_tuple_digest",
      "release_lineage_digest",
      "account_binding_authority_digest",
      "account_binding_ceremony_receipt_digest",
      "deployment_intent_digest",
      "account_policy_digest",
      "expires_at",
    ], "Tinker credential binding");
    if (
      binding.surface !== "tinker_customer_credential"
      || binding.credential_id !== receipt.credential_id
      || binding.account_id !== receipt.account_id
      || binding.recipient_public_key_hash
        !== capsule.recipient_public_key_hash
      || !Array.isArray(binding.operations)
      || binding.operations.length !== 1
      || binding.operations[0] !== "training"
      || binding.max_operation_policy_units
        !== receipt.max_operation_policy_units
      || binding.jwt_id_hash !== receipt.jwt_id_hash
      || binding.release_policy_tuple_digest
        !== receipt.gate.release_policy_tuple_digest
      || binding.release_lineage_digest !== receipt.release_lineage_digest
      || binding.account_binding_authority_digest
        !== receipt.account_binding_authority_digest
      || binding.account_binding_ceremony_receipt_digest
        !== receipt.account_binding_ceremony_receipt_digest
      || binding.deployment_intent_digest !== receipt.deployment_intent_digest
      || binding.account_policy_digest !== receipt.account_policy_digest
      || binding.expires_at !== receipt.expires_at
      || !NONZERO_SHA256.test(String(binding.owner_address_hash))
    ) throw new Error("Tinker credential binding does not match its receipt");
    const ephemeral = await crypto.subtle.importKey(
      "raw",
      buffer(ephemeralBytes),
      { name: "X25519" },
      false,
      [],
    );
    shared = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "X25519", public: ephemeral },
      deviceKey.privateKey,
      256,
    ));
    const hkdf = await crypto.subtle.importKey(
      "raw",
      buffer(shared),
      "HKDF",
      false,
      ["deriveKey"],
    );
    const key = await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(),
        info: encoder.encode(TINKER_CREDENTIAL_HKDF_INFO),
      },
      hkdf,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: buffer(nonce),
        additionalData: buffer(associatedData),
        tagLength: 128,
      },
      key,
      buffer(ciphertext),
    ));
    const token = decoder.decode(plaintext);
    await validateCredentialToken(token, receipt, binding);
    return token;
  } catch (cause) {
    if (
      cause instanceof Error
      && cause.message.startsWith("Tinker credential")
    ) throw cause;
    throw new Error(
      "Tinker credential capsule could not be authenticated for this device",
    );
  } finally {
    ephemeralBytes.fill(0);
    nonce.fill(0);
    ciphertext.fill(0);
    associatedData.fill(0);
    shared.fill(0);
    plaintext.fill(0);
  }
}

export function newTinkerIdempotencyKey(prefix: string): string {
  const normalized = prefix.toLowerCase().replace(/[^a-z0-9]/g, "")
    .slice(0, 24) || "tinker";
  const key = `${normalized}:${crypto.randomUUID()}`;
  if (!IDEMPOTENCY_KEY.test(key)) {
    throw new Error("Browser could not create a Tinker idempotency key");
  }
  return key;
}

export class TinkerIdempotencyAttempt {
  private attempt?: { fingerprint: string; key: string };

  keyFor(prefix: string, fingerprint: string): string {
    const boundedFingerprint = `${prefix}\u0000${fingerprint}`;
    if (this.attempt?.fingerprint === boundedFingerprint) {
      return this.attempt.key;
    }
    const key = newTinkerIdempotencyKey(prefix);
    this.attempt = { fingerprint: boundedFingerprint, key };
    return key;
  }

  resolve(key: string): void {
    if (this.attempt?.key === key) this.attempt = undefined;
  }
}

export function tinkerSessionIsCurrent(
  session: TinkerCustomerSession | undefined,
  expected: {
    account: string | undefined;
    authorizationVersion: number;
    nowSeconds?: number;
  },
): boolean {
  const now = expected.nowSeconds ?? Math.floor(Date.now() / 1_000);
  return Boolean(
    session
    && expected.account
    && session.address.toLowerCase() === expected.account.toLowerCase()
    && session.walletAuthorizationVersion === expected.authorizationVersion
    && session.issuedAt <= now
    && session.expiresAt > now,
  );
}

export function formatTinkerPolicyUnits(value: string): string {
  const parsed = BigInt(uint256String(value, "Tinker policy units"));
  return new Intl.NumberFormat("en-US").format(parsed);
}

export function isTinkerResourceId(value: string): boolean {
  return RESOURCE_ID.test(value);
}

export function isTinkerCommitment(value: string): boolean {
  return NONZERO_SHA256.test(value)
    || NONZERO_HEX_32.test(value)
    || SHA256.test(value)
    || HEX_32.test(value);
}
