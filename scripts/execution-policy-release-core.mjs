import { createHash } from "node:crypto";
import { URL as NodeURL } from "node:url";

import { ethereumKeccak256Hex } from "./ethereum-keccak.mjs";
import { canonicalPublicHttpsOrigin } from "./canonical-public-https-url-core.mjs";
import {
  normalizeRoyaltyReleaseAuthority,
  normalizeRoyaltyReleaseState,
  royaltyReleaseStateSha256,
} from "./royalty-release-authority-core.mjs";

export const FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA =
  "dnai.final-release-authority-core.v2";
export const FINAL_RELEASE_AUTHORITY_CORE_V2_DOMAIN =
  "dnai-wikigen/final-release-authority-core/v2\0";
export const FINAL_RELEASE_AUTHORITY_CORE_V3_SCHEMA =
  "dnai.final-release-authority-core.v3";
export const FINAL_RELEASE_AUTHORITY_CORE_V3_DOMAIN =
  "dnai-wikigen/final-release-authority-core/v3\0";
export const FINAL_RELEASE_AUTHORITY_CORE_V4_SCHEMA =
  "dnai.final-release-authority-core.v4";
export const FINAL_RELEASE_AUTHORITY_CORE_V4_DOMAIN =
  "dnai-wikigen/final-release-authority-core/v4\0";
export const FINAL_RELEASE_AUTHORITY_CORE_SCHEMA =
  FINAL_RELEASE_AUTHORITY_CORE_V4_SCHEMA;
export const FINAL_RELEASE_AUTHORITY_CORE_DOMAIN =
  FINAL_RELEASE_AUTHORITY_CORE_V4_DOMAIN;
export const MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES = 65_536;
export const DILIGENCE_EVALUATOR_POLICY_SET_TYPE =
  "DiligenceRoomEvaluatorPolicySet(bytes32[3] evaluatorPolicies)";

// Compatibility aliases for ceremony tooling while filenames and CLI flags
// migrate. These aliases identify the final authority core; they do not retain
// the legacy packet/review commitment semantics.
export const EXECUTION_POLICY_RELEASE_CORE_SCHEMA =
  FINAL_RELEASE_AUTHORITY_CORE_SCHEMA;
export const EXECUTION_POLICY_RELEASE_CORE_DOMAIN =
  FINAL_RELEASE_AUTHORITY_CORE_DOMAIN;
export const MAX_EXECUTION_POLICY_RELEASE_CORE_BYTES =
  MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES;

const BASE_SEPOLIA_CHAIN_ID = 84_532;
const BASE_SEPOLIA_PUBLIC_RPC = "https://sepolia.base.org";
const BASE_SEPOLIA_USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const APPROVER_ROOT_DOMAIN =
  "dnai-wikigen/execution-policy-approver-root/v1\0";
const CANONICALIZATION_VERSION = "policy-kernel-canonicalization/v2";
const APPROVAL_SCHEMA = "dnai-wikigen/execution-policy-approval/v3";
const API_SCHEMA_VERSION = 3;
const HISTORICAL_STORE_SCHEMA_VERSION = 5;
const STORE_SCHEMA_VERSION = 6;
const HISTORICAL_ROLLBACK_ANCHOR_SCHEMA =
  "dnai.execution-policy-rollback-anchor.v1";
const ROLLBACK_ANCHOR_SCHEMA = "dnai.execution-policy-rollback-anchor.v2";
const ANCHOR_VERIFICATION_MODEL =
  "single_rpc_reported_finalized_with_confirmation_depth";
const ANCHOR_WRITER_CUSTODY =
  "dstack_derived_execution_policy_anchor_writer";
const ANCHOR_WRITER_KEY_PATH = "tinker/execution_policy_anchor_writer";
const GITHUB_REPOSITORY = "therealwiki/dnai-wikigen";
const GITHUB_SIGNER_WORKFLOW =
  "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml";
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_WORD = "0".repeat(64);
const CHALLENGE_VERSION_REVIEW_DELAY_SECONDS = 172_800;
const MAX_GENESIS_CHALLENGES = 32;
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/u;
const HISTORICAL_DNS_OR_IPV4_HOSTNAME_V2 =
  /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;
const PHALA_APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const CVM_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;

export const FINAL_RELEASE_SHARED_LINEAGE_SCHEMA =
  "dnai.final-release-shared-lineage.v1";
export const ROYALTY_SETTLEMENT_RELEASE_BINDING_TEMPLATE_SCHEMA =
  "dnai.royalty-settlement-release-binding-template.v1";
export const COLLABORATION_EXECUTION_RELEASE_AUTHORITY_SCHEMA =
  "dnai.collaboration-execution-release-authority.v1";
export const COMPUTE_WORKLOAD_WALLET_ADOPTION_RELEASE_DECISION_SCHEMA =
  "dnai.compute-workload-wallet-adoption-release-decision.v1";
export const EXECUTION_POLICY_RELEASE_MARKER_GENESIS_SCHEMA =
  "dnai.execution-policy-release-marker-genesis.v1";
export const EXECUTION_POLICY_RELEASE_MARKER_RESOURCE_DOMAIN =
  "dnai-wikigen/execution-policy/final-release-authority/v1";
export const EXECUTION_POLICY_RELEASE_MARKER_RESOURCE_HASH =
  ethereumKeccak256Hex(Buffer.from(
    EXECUTION_POLICY_RELEASE_MARKER_RESOURCE_DOMAIN,
    "utf8",
  ));
export const EXECUTION_POLICY_STORE_V6_CONTRACT = Object.freeze({
  surface: "execution_policy_store",
  schema_version: 6,
  payload_fields: Object.freeze([
    "sequence",
    "records",
    "royalty_confirmations",
  ]),
  policy_record_kind: "execution_policy_decision_v2",
  royalty_record_kind: "royalty_settlement_anchor_v1",
  local_record_sequence_semantics: "one_based_contiguous_local_sequence",
  previous_record_digest_field: "previous_record_digest",
  royalty_chain_sequence_field: "chain_sequence",
  royalty_authorization_plan_schema:
    "dnai.royalty-settlement-authorization-plan.v2",
  royalty_wallet_plan_record_schema:
    "dnai.royalty-settlement-wallet-plan-record.v1",
  royalty_confirmation_schema:
    "dnai.royalty-settlement-anchor-confirmation.v1",
  royalty_sponsor_dto_schema:
    "dnai.collaboration.royalty-settlement-wallet-plan.v1",
});
export const EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY = Object.freeze({
  schema: EXECUTION_POLICY_RELEASE_MARKER_GENESIS_SCHEMA,
  required: true,
  resource_domain: EXECUTION_POLICY_RELEASE_MARKER_RESOURCE_DOMAIN,
  resource_hash: EXECUTION_POLICY_RELEASE_MARKER_RESOURCE_HASH,
  decision_environment_key: "TINKER_RELEASE_AUTHORITY_SHA256",
  decision_semantics: "exact_final_release_authority_core_sha256",
  anchor_binding_semantics:
    "rollback_anchor_target_contract_writer_and_writer_release_commitment",
  marker_chain_sequence: 1,
  local_store_first_sequence: 1,
  chain_sequence_offset: 1,
  first_local_record_chain_sequence: 2,
  royalty_anchor_sequence_semantics:
    "onchain_global_sequence_including_release_marker",
});
export const EXECUTION_POLICY_ANCHOR_WRITER_GAS_RESERVE_POLICY_SCHEMA =
  "dnai.execution-policy-anchor-writer-gas-reserve.v1";
export const EXECUTION_POLICY_ANCHOR_WRITER_GAS_RESERVE_POLICY = Object.freeze({
  schema: EXECUTION_POLICY_ANCHOR_WRITER_GAS_RESERVE_POLICY_SCHEMA,
  release_marker_transaction_count: 1,
  expected_subsequent_anchor_count: 32,
  maximum_gas_per_transaction: 500_000,
  reviewed_max_fee_per_gas_wei: "2000000000",
  minimum_reserve_wei: "33000000000000000",
});

const COLLABORATION_EXECUTION_SERVICE = "collaboration-execution-worker";
const COLLABORATION_EXECUTION_PROFILE = "collaboration-execution";
const AUTHENTICATED_WORKER_HEARTBEAT_CLAIM =
  "authenticated_worker_presence_not_tdx_attestation";
const ROYALTY_SETTLEMENT_SIGNER_KEY_PATH =
  "tinker/collaboration_royalty_settlement_signer";
const ROYALTY_SETTLEMENT_SIGNER_CUSTODY =
  "dstack_derived_main_runtime_royalty_settlement_signer";
const ROYALTY_QVL_SIGNER_KEY_PATH_PREFIX =
  "dnai-wikigen/attestation-qvl/royalty-settlement-signer/v1";
const ROYALTY_QVL_SIGNER_CUSTODY =
  "dstack_derived_diligence_qvl_royalty_settlement_signer";
const ROYALTY_MAX_AUTHORIZATION_LIFETIME_SECONDS = 600;

const HISTORICAL_TOP_LEVEL_KEYS_V2_V3 = Object.freeze([
  "schema",
  "release_sha",
  "network",
  "operator_address",
  "deployment_intent_sha256",
  "cvm_launch_intent_sha256",
  "contracts",
  "cvm",
  "arena_registry_bindings",
  "wallet_auth",
  "requested_features",
  "execution_policy",
]);

const TOP_LEVEL_KEYS_V4 = Object.freeze([
  "schema",
  "release_sha",
  "network",
  "operator_address",
  "deployment_intent_sha256",
  "cvm_launch_intent_sha256",
  "seven_cvm_release_verification_authority_sha256",
  "shared_release_lineage",
  "contracts",
  "cvm",
  "arena_registry_bindings",
  "wallet_auth",
  "requested_features",
  "execution_policy",
  "royalty_release_authority",
  "royalty_release_active_state",
  "royalty_release_active_state_sha256",
  "royalty_release_history_sha256",
  "royalty_release_history_receipt_sha256",
  "royalty_settlement_release_binding_template",
  "collaboration_execution",
  "compute_workload_wallet_adoption",
]);

const CONTRACT_KEYS = Object.freeze([
  "diligence_room",
  "challenge_registry",
  "royalty_distributor",
  "tinker_account_encumbrance",
  "compute_credit_vault",
  "email_oracle_auth",
  "usdc",
]);

const CVM_KEYS = Object.freeze([
  "app_id",
  "cvm_id",
  "compose_hash",
  "local_compose_hash",
  "rendered_compose_sha256",
  "os_image_hash",
  "os_is_dev",
  "public_logs",
  "public_sysinfo",
  "public_tcbinfo",
  "tee_identity",
  "delegate_url",
  "images",
  "allowed_browser_origins",
  "compute_workload_ingress",
  "runtime_controls",
]);

const IMAGE_KEYS = Object.freeze([
  "service",
  "image",
  "source_digest",
  "source_ref",
  "repo",
  "signer_workflow",
  "provenance_attestation",
  "sbom_attestation",
]);

const IMAGE_REPOSITORIES = Object.freeze({
  delegate: "ghcr.io/therealwiki/dnai-wikigen/tinker-delegate",
  neko: "ghcr.io/therealwiki/dnai-wikigen/neko-chrome",
  oracle: "ghcr.io/therealwiki/dnai-wikigen/tee-email-oracle",
});

const REQUIRED_BROWSER_ORIGINS = Object.freeze([
  "https://wikigen.me",
  "https://wikigenme.pages.dev",
  "https://www.wikigen.me",
]);

const RUNTIME_CONTROL_EXPECTATIONS = Object.freeze({
  wallet_auth_required: true,
  runtime_bearer_required: true,
  durable_compute_store: true,
  durable_arena_store: true,
  durable_arena_ingress_store: true,
  artifact_ciphertext_only: true,
  plaintext_artifact_endpoint_disabled: true,
  plaintext_card_endpoint_disabled: true,
  bootstrap_fail_open_disabled: true,
  browser_ports_internal_only: true,
  nondefault_browser_credentials_required: true,
  project_owned_browser_images: true,
  oracle_internal_only: true,
  oracle_runtime_auth_required: true,
  oracle_health_liveness_only: true,
  oracle_pin_response_minimized: true,
  oracle_private_metadata_egress_prohibited: true,
  oracle_replay_fail_closed: true,
  provider_dispatch_enabled: false,
  hostile_candidate_execution_enabled: false,
  deal_settlement_enabled: false,
  remote_artifact_evaluator_enabled: false,
  raw_secret_egress_prohibited: true,
});

const HISTORICAL_REQUESTED_FEATURE_KEYS_V2 = Object.freeze([
  "contract_writes",
  "artifact_upload",
  "compute_console",
  "compute_vault_funding",
  "compute_vault_authorization",
  "compute_workload_upload",
  "arena_submission",
]);

const REQUESTED_FEATURE_KEYS_V3 = Object.freeze([
  "contract_writes",
  "artifact_upload",
  "compute_console",
  "tinker_customer",
  "collaboration",
  "compute_vault_funding",
  "compute_vault_authorization",
  "compute_workload_upload",
  "arena_submission",
]);

const REQUESTED_FEATURE_KEYS_V4 = Object.freeze([
  ...REQUESTED_FEATURE_KEYS_V3,
  "collaboration_execution",
  "royalty_settlement",
  "compute_workload_wallet_adoption",
]);

const HISTORICAL_EXECUTION_POLICY_KEYS = Object.freeze([
  "canonicalization_version",
  "approval_schema",
  "api_schema_version",
  "store_schema_version",
  "approver_hashes",
  "approver_root_hash",
  "rollback_anchor_target",
]);

const EXECUTION_POLICY_KEYS_V4 = Object.freeze([
  ...HISTORICAL_EXECUTION_POLICY_KEYS,
  "store_contract",
  "release_marker_genesis",
]);

const EXECUTION_POLICY_STORE_V6_CONTRACT_KEYS = Object.freeze(
  Object.keys(EXECUTION_POLICY_STORE_V6_CONTRACT),
);

const EXECUTION_POLICY_RELEASE_MARKER_GENESIS_KEYS = Object.freeze(
  Object.keys(EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY),
);

const HISTORICAL_ROLLBACK_ANCHOR_TARGET_KEYS = Object.freeze([
  "schema",
  "chain_id",
  "contract_address",
  "runtime_code_hash",
  "writer_address",
  "writer_release_commitment",
  "writer_custody",
  "writer_key_path",
  "confirmations",
  "max_block_age_seconds",
  "max_future_block_skew_seconds",
  "verification_model",
  "independent_rpc_quorum_verified",
  "consensus_proof_verified",
]);

const ROLLBACK_ANCHOR_TARGET_KEYS = Object.freeze([
  ...HISTORICAL_ROLLBACK_ANCHOR_TARGET_KEYS,
  "writer_gas_reserve_policy",
]);

const ANCHOR_WRITER_GAS_RESERVE_POLICY_KEYS = Object.freeze(
  Object.keys(EXECUTION_POLICY_ANCHOR_WRITER_GAS_RESERVE_POLICY),
);

export class FinalReleaseAuthorityCoreValidationError extends TypeError {}
export const ExecutionPolicyReleaseCoreValidationError =
  FinalReleaseAuthorityCoreValidationError;

function fail(message) {
  throw new FinalReleaseAuthorityCoreValidationError(message);
}

function isPlainRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertJsonTree(value, label = "release core", depth = 0, ancestors = new Set()) {
  if (depth > 16) fail(`${label} exceeds the maximum nesting depth`);
  if (typeof value === "string") {
    if (value === "" && label === "release core.wallet_auth.walletconnect_project_id") {
      return;
    }
    assertString(value, label, 4_096);
    return;
  }
  if (typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      fail(`${label} must not contain floating-point, unsafe, or negative-zero numbers`);
    }
    return;
  }
  if (value === null) fail(`${label} must not contain null`);
  if (Array.isArray(value)) {
    if (ancestors.has(value)) fail(`${label} must not contain cycles`);
    if (value.length > 256) fail(`${label} array is too large`);
    if (Object.keys(value).length !== value.length) {
      fail(`${label} must be a dense JSON array without extra properties`);
    }
    ancestors.add(value);
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) fail(`${label} must not contain array holes`);
      assertJsonTree(value[index], `${label}[${index}]`, depth + 1, ancestors);
    }
    ancestors.delete(value);
    return;
  }
  if (!isPlainRecord(value)) fail(`${label} must contain only JSON objects`);
  if (ancestors.has(value)) fail(`${label} must not contain cycles`);
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length > 128
    || ownKeys.some((key) =>
      typeof key !== "string"
      || !Object.prototype.propertyIsEnumerable.call(value, key))
  ) {
    fail(`${label} must be a bounded enumerable string-keyed JSON object`);
  }
  ancestors.add(value);
  for (const key of ownKeys) {
    assertString(key, `${label} key`, 128);
    assertJsonTree(value[key], `${label}.${key}`, depth + 1, ancestors);
  }
  ancestors.delete(value);
}

function exactRecord(value, keys, label) {
  if (!isPlainRecord(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    const missing = expected.filter((key) => !actual.includes(key));
    const extra = actual.filter((key) => !expected.includes(key));
    fail(
      `${label} has invalid keys (missing: ${missing.join(",") || "none"}; `
      + `extra: ${extra.join(",") || "none"})`,
    );
  }
  return value;
}

function assertString(value, label, maximumBytes) {
  if (
    typeof value !== "string"
    || value.length === 0
    || Buffer.byteLength(value, "utf8") > maximumBytes
    || CONTROL_CHARACTERS.test(value)
  ) {
    fail(`${label} must be a bounded non-control-character string`);
  }
  for (const character of value) {
    const point = character.codePointAt(0);
    if (point >= 0xd800 && point <= 0xdfff) {
      fail(`${label} must not contain an unpaired Unicode surrogate`);
    }
  }
  return value;
}

function printableAscii(value, label, maximumBytes) {
  assertString(value, label, maximumBytes);
  if (/[^\x20-\x7e]/u.test(value)) {
    fail(`${label} must contain only printable ASCII`);
  }
  return value;
}

function exactString(value, expected, label) {
  assertString(value, label, Math.max(128, Buffer.byteLength(expected, "utf8")));
  if (value !== expected) fail(`${label} must equal ${expected}`);
  return value;
}

function integer(value, label, minimum, maximum) {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || Object.is(value, -0)
    || value < minimum
    || value > maximum
    || Math.abs(value) > MAX_SAFE_INTEGER
  ) {
    fail(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function uint256Decimal(value, label) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    fail(`${label} must be a canonical uint256 decimal string`);
  }
  let parsed;
  try {
    parsed = BigInt(value);
  } catch {
    fail(`${label} must be a canonical uint256 decimal string`);
  }
  if (parsed < 0n || parsed >= (1n << 256n)) {
    fail(`${label} must fit uint256`);
  }
  return value;
}

function boolean(value, label) {
  if (typeof value !== "boolean") fail(`${label} must be boolean`);
  return value;
}

function releaseSha(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value)) {
    fail(`${label} must be a lowercase 40-character Git SHA`);
  }
  return value;
}

function phalaAppId(value, label) {
  if (typeof value !== "string" || !PHALA_APP_ID.test(value)) {
    fail(`${label} must be a nonzero lowercase 40-character Phala app ID`);
  }
  return value;
}

function cvmId(value, label) {
  if (typeof value !== "string" || !CVM_ID.test(value)) {
    fail(`${label} must be a canonical CVM ID`);
  }
  return value;
}

function address(value, label) {
  if (
    typeof value !== "string"
    || !/^0x[0-9a-f]{40}$/.test(value)
    || value === ZERO_ADDRESS
  ) {
    fail(`${label} must be a nonzero lowercase Ethereum address`);
  }
  return value;
}

function bareBytes32(value, label) {
  if (
    typeof value !== "string"
    || !/^[0-9a-f]{64}$/.test(value)
    || value === ZERO_WORD
  ) {
    fail(`${label} must be nonzero lowercase 32-byte hex without 0x`);
  }
  return value;
}

function bytes32(value, label) {
  if (
    typeof value !== "string"
    || !/^0x[0-9a-f]{64}$/.test(value)
    || value === `0x${ZERO_WORD}`
  ) {
    fail(`${label} must be a nonzero lowercase 0x-prefixed bytes32`);
  }
  return value;
}

export function diligenceEvaluatorPolicySetRoot(commitments) {
  if (!Array.isArray(commitments) || commitments.length !== 3) {
    fail("DiligenceRoom evaluator policy commitments must contain exactly three entries");
  }
  const policies = commitments.map((value, index) => bytes32(
    value,
    `DiligenceRoom evaluator policy commitment[${index}]`,
  )).sort();
  if (new Set(policies).size !== policies.length) {
    fail("DiligenceRoom evaluator policy commitments must be pairwise distinct");
  }
  const typehash = ethereumKeccak256Hex(Buffer.from(
    DILIGENCE_EVALUATOR_POLICY_SET_TYPE,
    "utf8",
  ));
  const encoded = Buffer.concat([
    Buffer.from(typehash.slice(2), "hex"),
    ...policies.map((value) => Buffer.from(value.slice(2), "hex")),
  ]);
  return ethereumKeccak256Hex(encoded);
}

function sha256Pin(value, label) {
  if (
    typeof value !== "string"
    || !/^sha256:[0-9a-f]{64}$/.test(value)
    || value === `sha256:${ZERO_WORD}`
  ) {
    fail(`${label} must be a nonzero lowercase sha256 pin`);
  }
  return value;
}

function walletConnectProjectId(value, label) {
  if (typeof value !== "string" || !/^(?:|[0-9a-f]{32})$/.test(value)) {
    fail(`${label} must be empty or exactly 32 lowercase hexadecimal characters`);
  }
  return value;
}

function historicalHttpsOriginV2(value, label) {
  assertString(value, label, 512);
  let parsed;
  try {
    parsed = new NodeURL(value);
  } catch {
    fail(`${label} must be a canonical HTTPS origin`);
  }
  if (
    parsed.protocol !== "https:"
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
    || parsed.pathname !== "/"
    || parsed.hostname !== parsed.hostname.toLowerCase()
    || !HISTORICAL_DNS_OR_IPV4_HOSTNAME_V2.test(parsed.hostname)
    || parsed.origin !== value
  ) {
    fail(`${label} must be a canonical lowercase HTTPS origin without a path`);
  }
  return value;
}

function currentPublicHttpsOriginV3(value, label) {
  assertString(value, label, 512);
  try {
    return canonicalPublicHttpsOrigin(value, label);
  } catch {
    fail(`${label} must be a canonical HTTPS origin`);
  }
}

function asciiJsonString(value) {
  // Deliberately iterate UTF-16 code units (no `u` flag). Python's
  // ensure_ascii=true represents astral code points as two surrogate escapes.
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

function canonicalJson(value) {
  if (typeof value === "string") return asciiJsonString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  }
  const entries = Object.keys(value)
    .sort()
    .map((key) => `${asciiJsonString(key)}:${canonicalJson(value[key])}`);
  return `{${entries.join(",")}}`;
}

function canonicalBytesOfNormalized(value) {
  return Buffer.from(canonicalJson(value), "ascii");
}

function recursivelySortedJsonValue(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => recursivelySortedJsonValue(entry));
  }
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, recursivelySortedJsonValue(value[key])]),
  );
}

function approverRootHash(approverHashes) {
  return createHash("sha256")
    .update(APPROVER_ROOT_DOMAIN, "utf8")
    .update(canonicalJson(approverHashes), "ascii")
    .digest("hex");
}

function normalizeBaseContract(value, key, extraKeys = []) {
  const parsed = exactRecord(
    value,
    ["address", "runtime_code_hash", ...extraKeys],
    `contracts.${key}`,
  );
  return {
    address: address(parsed.address, `contracts.${key}.address`),
    runtime_code_hash: bytes32(
      parsed.runtime_code_hash,
      `contracts.${key}.runtime_code_hash`,
    ),
  };
}

function normalizeEmailOracleRelease(value) {
  const parsed = exactRecord(value, [
    "oracle_compose_hash",
    "consumer_compose_hash",
    "device_id",
    "kms_contract_address",
    "kms_runtime_code_hash",
    "kms_implementation_address",
    "kms_implementation_runtime_code_hash",
    "kms_registration_tx_hash",
    "kms_registration_block",
    "kms_registration_block_hash",
    "target_boot",
    "restart_key_derivation_proof_hash",
    "external_evidence_sha256",
  ], "contracts.email_oracle_auth.release");
  const boot = exactRecord(parsed.target_boot, [
    "instance_id",
    "mr_aggregated",
    "mr_system",
    "os_image_hash",
    "tcb_status",
    "advisory_ids",
    "info_hash",
  ], "contracts.email_oracle_auth.release.target_boot");
  if (!Array.isArray(boot.advisory_ids) || boot.advisory_ids.length !== 0) {
    fail("EmailOracleAuth target boot advisory_ids must be the exact empty array");
  }
  return {
    oracle_compose_hash: bytes32(
      parsed.oracle_compose_hash,
      "contracts.email_oracle_auth.release.oracle_compose_hash",
    ),
    consumer_compose_hash: bytes32(
      parsed.consumer_compose_hash,
      "contracts.email_oracle_auth.release.consumer_compose_hash",
    ),
    device_id: bytes32(parsed.device_id, "contracts.email_oracle_auth.release.device_id"),
    kms_contract_address: address(
      parsed.kms_contract_address,
      "contracts.email_oracle_auth.release.kms_contract_address",
    ),
    kms_runtime_code_hash: bytes32(
      parsed.kms_runtime_code_hash,
      "contracts.email_oracle_auth.release.kms_runtime_code_hash",
    ),
    kms_implementation_address: address(
      parsed.kms_implementation_address,
      "contracts.email_oracle_auth.release.kms_implementation_address",
    ),
    kms_implementation_runtime_code_hash: bytes32(
      parsed.kms_implementation_runtime_code_hash,
      "contracts.email_oracle_auth.release.kms_implementation_runtime_code_hash",
    ),
    kms_registration_tx_hash: bytes32(
      parsed.kms_registration_tx_hash,
      "contracts.email_oracle_auth.release.kms_registration_tx_hash",
    ),
    kms_registration_block: integer(
      parsed.kms_registration_block,
      "contracts.email_oracle_auth.release.kms_registration_block",
      1,
      MAX_SAFE_INTEGER,
    ),
    kms_registration_block_hash: bytes32(
      parsed.kms_registration_block_hash,
      "contracts.email_oracle_auth.release.kms_registration_block_hash",
    ),
    target_boot: {
      instance_id: address(
        boot.instance_id,
        "contracts.email_oracle_auth.release.target_boot.instance_id",
      ),
      mr_aggregated: bytes32(
        boot.mr_aggregated,
        "contracts.email_oracle_auth.release.target_boot.mr_aggregated",
      ),
      mr_system: bytes32(
        boot.mr_system,
        "contracts.email_oracle_auth.release.target_boot.mr_system",
      ),
      os_image_hash: bytes32(
        boot.os_image_hash,
        "contracts.email_oracle_auth.release.target_boot.os_image_hash",
      ),
      tcb_status: exactString(
        boot.tcb_status,
        "UpToDate",
        "contracts.email_oracle_auth.release.target_boot.tcb_status",
      ),
      advisory_ids: [],
      info_hash: bytes32(
        boot.info_hash,
        "contracts.email_oracle_auth.release.target_boot.info_hash",
      ),
    },
    restart_key_derivation_proof_hash: bytes32(
      parsed.restart_key_derivation_proof_hash,
      "contracts.email_oracle_auth.release.restart_key_derivation_proof_hash",
    ),
    external_evidence_sha256: bytes32(
      parsed.external_evidence_sha256,
      "contracts.email_oracle_auth.release.external_evidence_sha256",
    ),
  };
}

function normalizeContracts(value) {
  const parsed = exactRecord(value, CONTRACT_KEYS, "contracts");

  const diligenceBase = normalizeBaseContract(parsed.diligence_room, "diligence_room", [
    "developer",
    "result_verifier",
    "attestation_verifier",
    "attestation_release_policy_hash",
    "attestation_binding_frozen",
    "evaluator_policy_commitments",
    "evaluator_policy_set_root",
    "release_admission",
  ]);
  const diligenceAdmissionRaw = exactRecord(
    parsed.diligence_room.release_admission,
    [
      "tee_identity",
      "compose_hash",
      "approved_tee_identity_count",
      "approved_compose_count",
      "additions_frozen",
    ],
    "contracts.diligence_room.release_admission",
  );
  const diligenceAdmission = {
    tee_identity: address(
      diligenceAdmissionRaw.tee_identity,
      "contracts.diligence_room.release_admission.tee_identity",
    ),
    compose_hash: bareBytes32(
      diligenceAdmissionRaw.compose_hash,
      "contracts.diligence_room.release_admission.compose_hash",
    ),
    approved_tee_identity_count: integer(
      diligenceAdmissionRaw.approved_tee_identity_count,
      "contracts.diligence_room.release_admission.approved_tee_identity_count",
      1,
      1,
    ),
    approved_compose_count: integer(
      diligenceAdmissionRaw.approved_compose_count,
      "contracts.diligence_room.release_admission.approved_compose_count",
      1,
      1,
    ),
    additions_frozen: boolean(
      diligenceAdmissionRaw.additions_frozen,
      "contracts.diligence_room.release_admission.additions_frozen",
    ),
  };
  if (!diligenceAdmission.additions_frozen) {
    fail("DiligenceRoom release admission additions must be frozen");
  }
  if (!Array.isArray(parsed.diligence_room.evaluator_policy_commitments)
    || parsed.diligence_room.evaluator_policy_commitments.length !== 3) {
    fail("DiligenceRoom evaluator policy commitments must contain exactly three entries");
  }
  const evaluatorPolicyCommitments =
    parsed.diligence_room.evaluator_policy_commitments.map((value, index) => bytes32(
      value,
      `contracts.diligence_room.evaluator_policy_commitments[${index}]`,
    )).sort();
  if (new Set(evaluatorPolicyCommitments).size !== 3) {
    fail("DiligenceRoom evaluator policy commitments must be pairwise distinct");
  }
  const evaluatorPolicySetRoot = diligenceEvaluatorPolicySetRoot(
    evaluatorPolicyCommitments,
  );
  if (bytes32(
    parsed.diligence_room.evaluator_policy_set_root,
    "contracts.diligence_room.evaluator_policy_set_root",
  ) !== evaluatorPolicySetRoot) {
    fail("DiligenceRoom evaluator policy set root is not derived from the exact sorted policy set");
  }
  const diligence = {
    ...diligenceBase,
    developer: address(parsed.diligence_room.developer, "contracts.diligence_room.developer"),
    result_verifier: address(
      parsed.diligence_room.result_verifier,
      "contracts.diligence_room.result_verifier",
    ),
    attestation_verifier: address(
      parsed.diligence_room.attestation_verifier,
      "contracts.diligence_room.attestation_verifier",
    ),
    attestation_release_policy_hash: bytes32(
      parsed.diligence_room.attestation_release_policy_hash,
      "contracts.diligence_room.attestation_release_policy_hash",
    ),
    attestation_binding_frozen: boolean(
      parsed.diligence_room.attestation_binding_frozen,
      "contracts.diligence_room.attestation_binding_frozen",
    ),
    evaluator_policy_commitments: evaluatorPolicyCommitments,
    evaluator_policy_set_root: evaluatorPolicySetRoot,
    release_admission: diligenceAdmission,
  };
  if (!diligence.attestation_binding_frozen) {
    fail("DiligenceRoom attestation binding must be frozen");
  }

  const challengeBase = normalizeBaseContract(parsed.challenge_registry, "challenge_registry", [
    "owner",
    "pending_owner",
    "registry_paused",
    "minimum_version_review_delay_seconds",
    "expected_challenge_count",
  ]);
  const challenge = {
    ...challengeBase,
    owner: address(parsed.challenge_registry.owner, "contracts.challenge_registry.owner"),
    pending_owner: exactString(
      parsed.challenge_registry.pending_owner,
      ZERO_ADDRESS,
      "contracts.challenge_registry.pending_owner",
    ),
    registry_paused: boolean(
      parsed.challenge_registry.registry_paused,
      "contracts.challenge_registry.registry_paused",
    ),
    minimum_version_review_delay_seconds: integer(
      parsed.challenge_registry.minimum_version_review_delay_seconds,
      "contracts.challenge_registry.minimum_version_review_delay_seconds",
      CHALLENGE_VERSION_REVIEW_DELAY_SECONDS,
      CHALLENGE_VERSION_REVIEW_DELAY_SECONDS,
    ),
    expected_challenge_count: integer(
      parsed.challenge_registry.expected_challenge_count,
      "contracts.challenge_registry.expected_challenge_count",
      1,
      MAX_GENESIS_CHALLENGES,
    ),
  };
  if (challenge.registry_paused) {
    fail("ChallengeRegistry must be active for the reviewed genesis catalog");
  }

  const royalty = normalizeBaseContract(parsed.royalty_distributor, "royalty_distributor");

  const encumbranceKeys = [
    "owner",
    "account_commitment",
    "max_add_balance_wei",
    "max_spend_wei",
    "approved_compose_hashes",
    "approved_compose_root",
    "approved_compose_count",
    "managers",
    "manager_root",
    "manager_count",
    "release_policy_commitment",
    "release_max_add_balance_wei",
    "release_max_spend_wei",
    "release_compose_root",
    "release_compose_count",
    "release_manager_root",
    "release_manager_count",
    "release_policy_frozen",
    "emergency_halted",
    "per_operation_caps",
    "custodies_funds",
  ];
  const encumbranceBase = normalizeBaseContract(
    parsed.tinker_account_encumbrance,
    "tinker_account_encumbrance",
    encumbranceKeys,
  );
  if (
    !Array.isArray(parsed.tinker_account_encumbrance.approved_compose_hashes)
    || parsed.tinker_account_encumbrance.approved_compose_hashes.length !== 1
  ) {
    fail("contracts.tinker_account_encumbrance.approved_compose_hashes must contain exactly one release compose hash");
  }
  const approvedComposeHashes = parsed.tinker_account_encumbrance.approved_compose_hashes.map(
    (value, index) => bytes32(
      value,
      `contracts.tinker_account_encumbrance.approved_compose_hashes[${index}]`,
    ),
  );
  if (
    !Array.isArray(parsed.tinker_account_encumbrance.managers)
    || parsed.tinker_account_encumbrance.managers.length !== 1
  ) {
    fail("contracts.tinker_account_encumbrance.managers must contain exactly one release manager");
  }
  const managers = parsed.tinker_account_encumbrance.managers.map((value, index) =>
    address(value, `contracts.tinker_account_encumbrance.managers[${index}]`));
  const encumbrance = {
    ...encumbranceBase,
    owner: address(
      parsed.tinker_account_encumbrance.owner,
      "contracts.tinker_account_encumbrance.owner",
    ),
    account_commitment: bytes32(
      parsed.tinker_account_encumbrance.account_commitment,
      "contracts.tinker_account_encumbrance.account_commitment",
    ),
    max_add_balance_wei: uint256Decimal(
      parsed.tinker_account_encumbrance.max_add_balance_wei,
      "contracts.tinker_account_encumbrance.max_add_balance_wei",
    ),
    max_spend_wei: uint256Decimal(
      parsed.tinker_account_encumbrance.max_spend_wei,
      "contracts.tinker_account_encumbrance.max_spend_wei",
    ),
    approved_compose_hashes: approvedComposeHashes,
    approved_compose_root: bytes32(
      parsed.tinker_account_encumbrance.approved_compose_root,
      "contracts.tinker_account_encumbrance.approved_compose_root",
    ),
    approved_compose_count: integer(
      parsed.tinker_account_encumbrance.approved_compose_count,
      "contracts.tinker_account_encumbrance.approved_compose_count",
      1,
      16,
    ),
    managers,
    manager_root: bytes32(
      parsed.tinker_account_encumbrance.manager_root,
      "contracts.tinker_account_encumbrance.manager_root",
    ),
    manager_count: integer(
      parsed.tinker_account_encumbrance.manager_count,
      "contracts.tinker_account_encumbrance.manager_count",
      1,
      16,
    ),
    release_policy_commitment: bytes32(
      parsed.tinker_account_encumbrance.release_policy_commitment,
      "contracts.tinker_account_encumbrance.release_policy_commitment",
    ),
    release_max_add_balance_wei: uint256Decimal(
      parsed.tinker_account_encumbrance.release_max_add_balance_wei,
      "contracts.tinker_account_encumbrance.release_max_add_balance_wei",
    ),
    release_max_spend_wei: uint256Decimal(
      parsed.tinker_account_encumbrance.release_max_spend_wei,
      "contracts.tinker_account_encumbrance.release_max_spend_wei",
    ),
    release_compose_root: bytes32(
      parsed.tinker_account_encumbrance.release_compose_root,
      "contracts.tinker_account_encumbrance.release_compose_root",
    ),
    release_compose_count: integer(
      parsed.tinker_account_encumbrance.release_compose_count,
      "contracts.tinker_account_encumbrance.release_compose_count",
      1,
      16,
    ),
    release_manager_root: bytes32(
      parsed.tinker_account_encumbrance.release_manager_root,
      "contracts.tinker_account_encumbrance.release_manager_root",
    ),
    release_manager_count: integer(
      parsed.tinker_account_encumbrance.release_manager_count,
      "contracts.tinker_account_encumbrance.release_manager_count",
      1,
      16,
    ),
    release_policy_frozen: boolean(
      parsed.tinker_account_encumbrance.release_policy_frozen,
      "contracts.tinker_account_encumbrance.release_policy_frozen",
    ),
    emergency_halted: boolean(
      parsed.tinker_account_encumbrance.emergency_halted,
      "contracts.tinker_account_encumbrance.emergency_halted",
    ),
    per_operation_caps: boolean(
      parsed.tinker_account_encumbrance.per_operation_caps,
      "contracts.tinker_account_encumbrance.per_operation_caps",
    ),
    custodies_funds: boolean(
      parsed.tinker_account_encumbrance.custodies_funds,
      "contracts.tinker_account_encumbrance.custodies_funds",
    ),
  };
  if (
    encumbrance.approved_compose_count !== approvedComposeHashes.length
    || encumbrance.release_compose_count !== approvedComposeHashes.length
    || encumbrance.manager_count !== managers.length
    || encumbrance.release_manager_count !== managers.length
    || encumbrance.approved_compose_root !== encumbrance.release_compose_root
    || encumbrance.manager_root !== encumbrance.release_manager_root
    || encumbrance.max_add_balance_wei !== encumbrance.release_max_add_balance_wei
    || encumbrance.max_spend_wei !== encumbrance.release_max_spend_wei
    || encumbrance.release_policy_frozen !== true
    || encumbrance.emergency_halted !== false
    || encumbrance.per_operation_caps !== true
    || encumbrance.custodies_funds !== false
  ) {
    fail("TinkerAccountEncumbrance must bind one exact active, frozen, noncustodial release policy");
  }

  const vaultBase = normalizeBaseContract(parsed.compute_credit_vault, "compute_credit_vault", [
    "owner",
    "developer",
    "metering_verifier",
    "metering_qvl_verifier",
    "metering_policy_set_hash",
    "metering_binding_frozen",
    "developer_fee_bps",
    "tee_identity",
    "compose_hash",
    "rate_policies",
  ]);
  const ratePoliciesRaw = exactRecord(
    parsed.compute_credit_vault.rate_policies,
    ["native", "erc20"],
    "contracts.compute_credit_vault.rate_policies",
  );
  const normalizeRatePolicy = (value, name) => {
    const policy = exactRecord(
      value,
      ["commitment", "asset", "provider", "developer_fee_bps"],
      `contracts.compute_credit_vault.rate_policies.${name}`,
    );
    return {
      commitment: bytes32(
        policy.commitment,
        `contracts.compute_credit_vault.rate_policies.${name}.commitment`,
      ),
      asset: name === "native"
        ? exactString(
          policy.asset,
          ZERO_ADDRESS,
          `contracts.compute_credit_vault.rate_policies.${name}.asset`,
        )
        : address(
          policy.asset,
          `contracts.compute_credit_vault.rate_policies.${name}.asset`,
        ),
      provider: address(
        policy.provider,
        `contracts.compute_credit_vault.rate_policies.${name}.provider`,
      ),
      developer_fee_bps: integer(
        policy.developer_fee_bps,
        `contracts.compute_credit_vault.rate_policies.${name}.developer_fee_bps`,
        0,
        2_000,
      ),
    };
  };
  const ratePolicies = {
    native: normalizeRatePolicy(ratePoliciesRaw.native, "native"),
    erc20: normalizeRatePolicy(ratePoliciesRaw.erc20, "erc20"),
  };
  const vault = {
    ...vaultBase,
    owner: address(parsed.compute_credit_vault.owner, "contracts.compute_credit_vault.owner"),
    developer: address(
      parsed.compute_credit_vault.developer,
      "contracts.compute_credit_vault.developer",
    ),
    metering_verifier: address(
      parsed.compute_credit_vault.metering_verifier,
      "contracts.compute_credit_vault.metering_verifier",
    ),
    metering_qvl_verifier: address(
      parsed.compute_credit_vault.metering_qvl_verifier,
      "contracts.compute_credit_vault.metering_qvl_verifier",
    ),
    metering_policy_set_hash: bytes32(
      parsed.compute_credit_vault.metering_policy_set_hash,
      "contracts.compute_credit_vault.metering_policy_set_hash",
    ),
    metering_binding_frozen: boolean(
      parsed.compute_credit_vault.metering_binding_frozen,
      "contracts.compute_credit_vault.metering_binding_frozen",
    ),
    developer_fee_bps: integer(
      parsed.compute_credit_vault.developer_fee_bps,
      "contracts.compute_credit_vault.developer_fee_bps",
      0,
      2_000,
    ),
    tee_identity: address(
      parsed.compute_credit_vault.tee_identity,
      "contracts.compute_credit_vault.tee_identity",
    ),
    compose_hash: bareBytes32(
      parsed.compute_credit_vault.compose_hash,
      "contracts.compute_credit_vault.compose_hash",
    ),
    rate_policies: ratePolicies,
  };

  const emailBase = normalizeBaseContract(parsed.email_oracle_auth, "email_oracle_auth", [
    "owner",
    "consumer_address",
    "upgrade_delay_seconds",
    "release",
  ]);
  const email = {
    ...emailBase,
    owner: address(parsed.email_oracle_auth.owner, "contracts.email_oracle_auth.owner"),
    consumer_address: address(
      parsed.email_oracle_auth.consumer_address,
      "contracts.email_oracle_auth.consumer_address",
    ),
    upgrade_delay_seconds: integer(
      parsed.email_oracle_auth.upgrade_delay_seconds,
      "contracts.email_oracle_auth.upgrade_delay_seconds",
      172_800,
      31_536_000,
    ),
    release: normalizeEmailOracleRelease(parsed.email_oracle_auth.release),
  };

  const usdcBase = normalizeBaseContract(parsed.usdc, "usdc", ["symbol", "decimals"]);
  const usdc = {
    ...usdcBase,
    symbol: exactString(parsed.usdc.symbol, "USDC", "contracts.usdc.symbol"),
    decimals: integer(parsed.usdc.decimals, "contracts.usdc.decimals", 6, 6),
  };
  if (usdc.address !== BASE_SEPOLIA_USDC) {
    fail("contracts.usdc.address must be canonical Base Sepolia USDC");
  }
  if (vault.rate_policies.erc20.asset !== usdc.address) {
    fail("ComputeCreditVault ERC20 asset must equal contracts.usdc.address");
  }
  if (
    vault.rate_policies.native.commitment === vault.rate_policies.erc20.commitment
    || vault.rate_policies.native.developer_fee_bps !== vault.developer_fee_bps
    || vault.rate_policies.erc20.developer_fee_bps !== vault.developer_fee_bps
  ) {
    fail("ComputeCreditVault rate-policy tuples must bind distinct commitments and the frozen developer fee");
  }
  if (!vault.metering_binding_frozen) {
    fail("ComputeCreditVault metering binding must be frozen");
  }

  const normalized = {
    diligence_room: diligence,
    challenge_registry: challenge,
    royalty_distributor: royalty,
    tinker_account_encumbrance: encumbrance,
    compute_credit_vault: vault,
    email_oracle_auth: email,
    usdc,
  };
  const addresses = Object.values(normalized).map((entry) => entry.address);
  if (new Set(addresses).size !== addresses.length) {
    fail("contract addresses must be unique");
  }
  return normalized;
}

function normalizeArenaRegistryBindings(value, challengePolicy) {
  if (!isPlainRecord(value)) {
    fail("arena_registry_bindings must be an object");
  }
  const entries = Object.entries(value).sort(([left], [right]) => (
    left < right ? -1 : left > right ? 1 : 0
  ));
  if (entries.length < 1 || entries.length > MAX_GENESIS_CHALLENGES) {
    fail(`arena_registry_bindings must contain one to ${MAX_GENESIS_CHALLENGES} exact genesis challenges`);
  }
  if (entries.length !== challengePolicy.expected_challenge_count) {
    fail("ChallengeRegistry expected_challenge_count must equal the exact Arena genesis catalog size");
  }
  const normalized = {};
  const registryIds = new Set();
  const registryVersions = new Set();
  for (const [catalogKey, rawBinding] of entries) {
    if (!/^[a-z0-9][a-z0-9-]{0,63}@(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(catalogKey)) {
      fail(`Arena registry binding key ${catalogKey} must be a lowercase slug and canonical semantic version`);
    }
    const binding = exactRecord(rawBinding, [
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
    ], `arena_registry_bindings.${catalogKey}`);
    const registryChallengeId = uint256Decimal(
      binding.registry_challenge_id,
      `arena_registry_bindings.${catalogKey}.registry_challenge_id`,
    );
    if (registryChallengeId === "0") {
      fail(`arena_registry_bindings.${catalogKey}.registry_challenge_id must be positive`);
    }
    const registryVersion = integer(
      binding.registry_version,
      `arena_registry_bindings.${catalogKey}.registry_version`,
      1,
      0xffff_ffff,
    );
    if (registryIds.has(registryChallengeId)) {
      fail("Arena genesis catalog must bind each registry challenge id exactly once");
    }
    const registryVersionKey = `${registryChallengeId}@${registryVersion}`;
    if (registryVersions.has(registryVersionKey)) {
      fail("Arena genesis catalog must not repeat a registry challenge version");
    }
    registryIds.add(registryChallengeId);
    registryVersions.add(registryVersionKey);
    const catalogManifestHash = bareBytes32(
      binding.catalog_manifest_hash,
      `arena_registry_bindings.${catalogKey}.catalog_manifest_hash`,
    );
    const metadataHash = bytes32(
      binding.metadata_hash,
      `arena_registry_bindings.${catalogKey}.metadata_hash`,
    );
    const sealedArtifactCommitment = bytes32(
      binding.sealed_artifact_commitment,
      `arena_registry_bindings.${catalogKey}.sealed_artifact_commitment`,
    );
    const evaluatorCommitment = bytes32(
      binding.evaluator_commitment,
      `arena_registry_bindings.${catalogKey}.evaluator_commitment`,
    );
    const releasePolicyCommitment = bytes32(
      binding.release_policy_commitment,
      `arena_registry_bindings.${catalogKey}.release_policy_commitment`,
    );
    if (metadataHash !== `0x${catalogManifestHash}`) {
      fail(`arena_registry_bindings.${catalogKey}.metadata_hash must commit to catalog_manifest_hash`);
    }
    if (new Set([
      metadataHash,
      sealedArtifactCommitment,
      evaluatorCommitment,
      releasePolicyCommitment,
    ]).size !== 4) {
      fail(`arena_registry_bindings.${catalogKey} commitments must be pairwise distinct`);
    }
    const paused = boolean(
      binding.paused,
      `arena_registry_bindings.${catalogKey}.paused`,
    );
    const configurationFrozen = boolean(
      binding.configuration_frozen,
      `arena_registry_bindings.${catalogKey}.configuration_frozen`,
    );
    if (paused || !configurationFrozen) {
      fail(`arena_registry_bindings.${catalogKey} must authorize an unpaused frozen challenge`);
    }
    normalized[catalogKey] = {
      registry_challenge_id: registryChallengeId,
      registry_version: registryVersion,
      controller_address: address(
        binding.controller_address,
        `arena_registry_bindings.${catalogKey}.controller_address`,
      ),
      pending_controller_address: exactString(
        binding.pending_controller_address,
        ZERO_ADDRESS,
        `arena_registry_bindings.${catalogKey}.pending_controller_address`,
      ),
      lifecycle: exactString(
        binding.lifecycle,
        "open",
        `arena_registry_bindings.${catalogKey}.lifecycle`,
      ),
      paused: false,
      configuration_frozen: true,
      catalog_manifest_hash: catalogManifestHash,
      metadata_uri: printableAscii(
        binding.metadata_uri,
        `arena_registry_bindings.${catalogKey}.metadata_uri`,
        256,
      ),
      metadata_hash: metadataHash,
      sealed_artifact_commitment: sealedArtifactCommitment,
      evaluator_commitment: evaluatorCommitment,
      release_policy_commitment: releasePolicyCommitment,
    };
  }
  const expectedIds = Array.from(
    { length: entries.length },
    (_, index) => String(index + 1),
  );
  const actualIds = [...registryIds].sort((left, right) => (
    BigInt(left) < BigInt(right) ? -1 : BigInt(left) > BigInt(right) ? 1 : 0
  ));
  if (JSON.stringify(actualIds) !== JSON.stringify(expectedIds)) {
    fail("Arena genesis catalog registry challenge ids must be the exact contiguous range 1..N");
  }
  return normalized;
}

function normalizeImage(value, release, index) {
  const parsed = exactRecord(value, IMAGE_KEYS, `cvm.images[${index}]`);
  const service = assertString(parsed.service, `cvm.images[${index}].service`, 32);
  const repository = IMAGE_REPOSITORIES[service];
  if (!repository) fail(`cvm.images[${index}].service is not supported`);
  const image = assertString(parsed.image, `cvm.images[${index}].image`, 512);
  if (!new RegExp(`^${repository.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}@sha256:[0-9a-f]{64}$`).test(image)) {
    fail(`cvm.images[${index}].image must be the exact project-owned digest reference`);
  }
  const sourceDigest = releaseSha(
    parsed.source_digest,
    `cvm.images[${index}].source_digest`,
  );
  if (sourceDigest !== release) fail(`cvm.images[${index}].source_digest must equal release_sha`);
  const sourceRef = assertString(parsed.source_ref, `cvm.images[${index}].source_ref`, 256);
  if (
    sourceRef !== "refs/heads/main"
    && !/^refs\/tags\/v[0-9][0-9A-Za-z._-]*$/.test(sourceRef)
  ) {
    fail(`cvm.images[${index}].source_ref must be main or a version tag`);
  }
  return {
    service,
    image,
    source_digest: sourceDigest,
    source_ref: sourceRef,
    repo: exactString(parsed.repo, GITHUB_REPOSITORY, `cvm.images[${index}].repo`),
    signer_workflow: exactString(
      parsed.signer_workflow,
      GITHUB_SIGNER_WORKFLOW,
      `cvm.images[${index}].signer_workflow`,
    ),
    provenance_attestation: exactString(
      parsed.provenance_attestation,
      "verified",
      `cvm.images[${index}].provenance_attestation`,
    ),
    sbom_attestation: exactString(
      parsed.sbom_attestation,
      "verified",
      `cvm.images[${index}].sbom_attestation`,
    ),
  };
}

function normalizeRuntimeControls(value) {
  const keys = Object.keys(RUNTIME_CONTROL_EXPECTATIONS);
  const parsed = exactRecord(value, keys, "cvm.runtime_controls");
  const normalized = {};
  for (const key of keys) {
    const observed = boolean(parsed[key], `cvm.runtime_controls.${key}`);
    if (observed !== RUNTIME_CONTROL_EXPECTATIONS[key]) {
      fail(`cvm.runtime_controls.${key} does not match the reviewed release value`);
    }
    normalized[key] = observed;
  }
  return normalized;
}

function normalizeComputeWorkloadIngress(value) {
  const parsed = exactRecord(value, [
    "max_verdict_age_seconds",
    "revoked_quote_hashes",
  ], "cvm.compute_workload_ingress");
  const maximumAge = integer(
    parsed.max_verdict_age_seconds,
    "cvm.compute_workload_ingress.max_verdict_age_seconds",
    1,
    300,
  );
  if (!Array.isArray(parsed.revoked_quote_hashes)
    || parsed.revoked_quote_hashes.length > 256) {
    fail("cvm.compute_workload_ingress.revoked_quote_hashes must contain at most 256 entries");
  }
  const revoked = parsed.revoked_quote_hashes.map((value, index) => bytes32(
    value,
    `cvm.compute_workload_ingress.revoked_quote_hashes[${index}]`,
  ));
  const canonical = [...new Set(revoked)].sort();
  if (canonical.length !== revoked.length
    || canonical.some((value, index) => value !== revoked[index])) {
    fail("cvm.compute_workload_ingress.revoked_quote_hashes must be sorted and unique");
  }
  return {
    max_verdict_age_seconds: maximumAge,
    revoked_quote_hashes: canonical,
  };
}

function normalizeCvm(
  value,
  release,
  normalizeHttpsOrigin,
  { requireCanonicalMainRuntimeIdentity = false } = {},
) {
  const parsed = exactRecord(value, CVM_KEYS, "cvm");
  if (!Array.isArray(parsed.images) || parsed.images.length !== 3) {
    fail("cvm.images must contain exactly delegate, neko, and oracle");
  }
  const images = parsed.images
    .map((entry, index) => normalizeImage(entry, release, index))
    .sort((left, right) => left.service.localeCompare(right.service));
  if (
    images.some((entry, index) => entry.service !== Object.keys(IMAGE_REPOSITORIES)[index])
  ) {
    fail("cvm.images must contain exactly delegate, neko, and oracle once each");
  }

  if (!Array.isArray(parsed.allowed_browser_origins) || parsed.allowed_browser_origins.length !== 3) {
    fail("cvm.allowed_browser_origins must contain exactly three reviewed origins");
  }
  const origins = parsed.allowed_browser_origins
    .map((entry, index) => normalizeHttpsOrigin(
      entry,
      `cvm.allowed_browser_origins[${index}]`,
    ))
    .sort();
  if (origins.some((entry, index) => entry !== REQUIRED_BROWSER_ORIGINS[index])) {
    fail("cvm.allowed_browser_origins must equal the reviewed production origin set");
  }

  const normalized = {
    app_id: requireCanonicalMainRuntimeIdentity
      ? phalaAppId(parsed.app_id, "cvm.app_id")
      : assertString(parsed.app_id, "cvm.app_id", 128),
    cvm_id: requireCanonicalMainRuntimeIdentity
      ? cvmId(parsed.cvm_id, "cvm.cvm_id")
      : assertString(parsed.cvm_id, "cvm.cvm_id", 128),
    compose_hash: bareBytes32(parsed.compose_hash, "cvm.compose_hash"),
    local_compose_hash: bareBytes32(parsed.local_compose_hash, "cvm.local_compose_hash"),
    rendered_compose_sha256: bareBytes32(
      parsed.rendered_compose_sha256,
      "cvm.rendered_compose_sha256",
    ),
    os_image_hash: bareBytes32(parsed.os_image_hash, "cvm.os_image_hash"),
    os_is_dev: boolean(parsed.os_is_dev, "cvm.os_is_dev"),
    public_logs: boolean(parsed.public_logs, "cvm.public_logs"),
    public_sysinfo: boolean(parsed.public_sysinfo, "cvm.public_sysinfo"),
    public_tcbinfo: boolean(parsed.public_tcbinfo, "cvm.public_tcbinfo"),
    tee_identity: address(parsed.tee_identity, "cvm.tee_identity"),
    delegate_url: normalizeHttpsOrigin(parsed.delegate_url, "cvm.delegate_url"),
    images,
    allowed_browser_origins: origins,
    compute_workload_ingress: normalizeComputeWorkloadIngress(
      parsed.compute_workload_ingress,
    ),
    runtime_controls: normalizeRuntimeControls(parsed.runtime_controls),
  };
  if (
    normalized.os_is_dev
    || normalized.public_logs
    || normalized.public_sysinfo
    || normalized.public_tcbinfo
  ) {
    fail("cvm must use the reviewed non-dev private production posture");
  }
  return normalized;
}

function normalizeRequestedFeatures(value, keys) {
  const parsed = exactRecord(value, keys, "requested_features");
  const normalized = {};
  for (const key of keys) {
    normalized[key] = boolean(parsed[key], `requested_features.${key}`);
  }
  if (normalized.compute_vault_authorization && !normalized.compute_vault_funding) {
    fail("compute_vault_authorization requires compute_vault_funding");
  }
  if (Object.hasOwn(normalized, "collaboration_execution")
    && normalized.collaboration_execution
    && (!normalized.collaboration
      || !normalized.compute_workload_upload
      || !normalized.compute_vault_authorization)) {
    fail("collaboration_execution requires collaboration, compute_workload_upload, and compute_vault_authorization");
  }
  if (Object.hasOwn(normalized, "royalty_settlement")
    && normalized.royalty_settlement
    && (!normalized.collaboration_execution || !normalized.contract_writes)) {
    fail("royalty_settlement requires collaboration_execution and contract_writes");
  }
  if (Object.hasOwn(normalized, "compute_workload_wallet_adoption")
    && normalized.compute_workload_wallet_adoption
    && (!normalized.compute_workload_upload
      || !normalized.compute_vault_authorization)) {
    fail("compute_workload_wallet_adoption requires compute_workload_upload and compute_vault_authorization");
  }
  return normalized;
}

function normalizeExecutionPolicyStoreV6Contract(value) {
  const parsed = exactRecord(
    value,
    EXECUTION_POLICY_STORE_V6_CONTRACT_KEYS,
    "execution_policy.store_contract",
  );
  if (!Array.isArray(parsed.payload_fields)
    || parsed.payload_fields.length
      !== EXECUTION_POLICY_STORE_V6_CONTRACT.payload_fields.length) {
    fail("execution_policy.store_contract.payload_fields must be the exact v6 field order");
  }
  const payloadFields = parsed.payload_fields.map((field, index) => exactString(
    field,
    EXECUTION_POLICY_STORE_V6_CONTRACT.payload_fields[index],
    `execution_policy.store_contract.payload_fields[${index}]`,
  ));
  return {
    surface: exactString(
      parsed.surface,
      EXECUTION_POLICY_STORE_V6_CONTRACT.surface,
      "execution_policy.store_contract.surface",
    ),
    schema_version: integer(
      parsed.schema_version,
      "execution_policy.store_contract.schema_version",
      EXECUTION_POLICY_STORE_V6_CONTRACT.schema_version,
      EXECUTION_POLICY_STORE_V6_CONTRACT.schema_version,
    ),
    payload_fields: payloadFields,
    policy_record_kind: exactString(
      parsed.policy_record_kind,
      EXECUTION_POLICY_STORE_V6_CONTRACT.policy_record_kind,
      "execution_policy.store_contract.policy_record_kind",
    ),
    royalty_record_kind: exactString(
      parsed.royalty_record_kind,
      EXECUTION_POLICY_STORE_V6_CONTRACT.royalty_record_kind,
      "execution_policy.store_contract.royalty_record_kind",
    ),
    local_record_sequence_semantics: exactString(
      parsed.local_record_sequence_semantics,
      EXECUTION_POLICY_STORE_V6_CONTRACT.local_record_sequence_semantics,
      "execution_policy.store_contract.local_record_sequence_semantics",
    ),
    previous_record_digest_field: exactString(
      parsed.previous_record_digest_field,
      EXECUTION_POLICY_STORE_V6_CONTRACT.previous_record_digest_field,
      "execution_policy.store_contract.previous_record_digest_field",
    ),
    royalty_chain_sequence_field: exactString(
      parsed.royalty_chain_sequence_field,
      EXECUTION_POLICY_STORE_V6_CONTRACT.royalty_chain_sequence_field,
      "execution_policy.store_contract.royalty_chain_sequence_field",
    ),
    royalty_authorization_plan_schema: exactString(
      parsed.royalty_authorization_plan_schema,
      EXECUTION_POLICY_STORE_V6_CONTRACT.royalty_authorization_plan_schema,
      "execution_policy.store_contract.royalty_authorization_plan_schema",
    ),
    royalty_wallet_plan_record_schema: exactString(
      parsed.royalty_wallet_plan_record_schema,
      EXECUTION_POLICY_STORE_V6_CONTRACT.royalty_wallet_plan_record_schema,
      "execution_policy.store_contract.royalty_wallet_plan_record_schema",
    ),
    royalty_confirmation_schema: exactString(
      parsed.royalty_confirmation_schema,
      EXECUTION_POLICY_STORE_V6_CONTRACT.royalty_confirmation_schema,
      "execution_policy.store_contract.royalty_confirmation_schema",
    ),
    royalty_sponsor_dto_schema: exactString(
      parsed.royalty_sponsor_dto_schema,
      EXECUTION_POLICY_STORE_V6_CONTRACT.royalty_sponsor_dto_schema,
      "execution_policy.store_contract.royalty_sponsor_dto_schema",
    ),
  };
}

function normalizeExecutionPolicyReleaseMarkerGenesis(value) {
  const parsed = exactRecord(
    value,
    EXECUTION_POLICY_RELEASE_MARKER_GENESIS_KEYS,
    "execution_policy.release_marker_genesis",
  );
  const normalized = {
    schema: exactString(
      parsed.schema,
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.schema,
      "execution_policy.release_marker_genesis.schema",
    ),
    required: boolean(
      parsed.required,
      "execution_policy.release_marker_genesis.required",
    ),
    resource_domain: exactString(
      parsed.resource_domain,
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.resource_domain,
      "execution_policy.release_marker_genesis.resource_domain",
    ),
    resource_hash: exactString(
      parsed.resource_hash,
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.resource_hash,
      "execution_policy.release_marker_genesis.resource_hash",
    ),
    decision_environment_key: exactString(
      parsed.decision_environment_key,
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.decision_environment_key,
      "execution_policy.release_marker_genesis.decision_environment_key",
    ),
    decision_semantics: exactString(
      parsed.decision_semantics,
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.decision_semantics,
      "execution_policy.release_marker_genesis.decision_semantics",
    ),
    anchor_binding_semantics: exactString(
      parsed.anchor_binding_semantics,
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.anchor_binding_semantics,
      "execution_policy.release_marker_genesis.anchor_binding_semantics",
    ),
    marker_chain_sequence: integer(
      parsed.marker_chain_sequence,
      "execution_policy.release_marker_genesis.marker_chain_sequence",
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.marker_chain_sequence,
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.marker_chain_sequence,
    ),
    local_store_first_sequence: integer(
      parsed.local_store_first_sequence,
      "execution_policy.release_marker_genesis.local_store_first_sequence",
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.local_store_first_sequence,
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.local_store_first_sequence,
    ),
    chain_sequence_offset: integer(
      parsed.chain_sequence_offset,
      "execution_policy.release_marker_genesis.chain_sequence_offset",
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.chain_sequence_offset,
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.chain_sequence_offset,
    ),
    first_local_record_chain_sequence: integer(
      parsed.first_local_record_chain_sequence,
      "execution_policy.release_marker_genesis.first_local_record_chain_sequence",
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.first_local_record_chain_sequence,
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY.first_local_record_chain_sequence,
    ),
    royalty_anchor_sequence_semantics: exactString(
      parsed.royalty_anchor_sequence_semantics,
      EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY
        .royalty_anchor_sequence_semantics,
      "execution_policy.release_marker_genesis.royalty_anchor_sequence_semantics",
    ),
  };
  if (!normalized.required
    || normalized.marker_chain_sequence !== normalized.chain_sequence_offset
    || normalized.first_local_record_chain_sequence
      !== normalized.local_store_first_sequence + normalized.chain_sequence_offset) {
    fail("execution-policy release marker genesis sequence contract is invalid");
  }
  return normalized;
}

function normalizeAnchorWriterGasReservePolicy(value) {
  const label =
    "execution_policy.rollback_anchor_target.writer_gas_reserve_policy";
  const parsed = exactRecord(
    value,
    ANCHOR_WRITER_GAS_RESERVE_POLICY_KEYS,
    label,
  );
  const expected = EXECUTION_POLICY_ANCHOR_WRITER_GAS_RESERVE_POLICY;
  const normalized = {
    schema: exactString(parsed.schema, expected.schema, `${label}.schema`),
    release_marker_transaction_count: integer(
      parsed.release_marker_transaction_count,
      `${label}.release_marker_transaction_count`,
      expected.release_marker_transaction_count,
      expected.release_marker_transaction_count,
    ),
    expected_subsequent_anchor_count: integer(
      parsed.expected_subsequent_anchor_count,
      `${label}.expected_subsequent_anchor_count`,
      expected.expected_subsequent_anchor_count,
      expected.expected_subsequent_anchor_count,
    ),
    maximum_gas_per_transaction: integer(
      parsed.maximum_gas_per_transaction,
      `${label}.maximum_gas_per_transaction`,
      expected.maximum_gas_per_transaction,
      expected.maximum_gas_per_transaction,
    ),
    reviewed_max_fee_per_gas_wei: uint256Decimal(
      parsed.reviewed_max_fee_per_gas_wei,
      `${label}.reviewed_max_fee_per_gas_wei`,
    ),
    minimum_reserve_wei: uint256Decimal(
      parsed.minimum_reserve_wei,
      `${label}.minimum_reserve_wei`,
    ),
  };
  const computedMinimum = (
    BigInt(normalized.release_marker_transaction_count
      + normalized.expected_subsequent_anchor_count)
    * BigInt(normalized.maximum_gas_per_transaction)
    * BigInt(normalized.reviewed_max_fee_per_gas_wei)
  ).toString(10);
  if (normalized.reviewed_max_fee_per_gas_wei
      !== expected.reviewed_max_fee_per_gas_wei
    || normalized.minimum_reserve_wei !== expected.minimum_reserve_wei
    || normalized.minimum_reserve_wei !== computedMinimum) {
    fail(`${label} must equal the exact computed release gas-reserve policy`);
  }
  return normalized;
}

function normalizeExecutionPolicy(value, { includeReleaseMarkerGenesis }) {
  const parsed = exactRecord(
    value,
    includeReleaseMarkerGenesis
      ? EXECUTION_POLICY_KEYS_V4
      : HISTORICAL_EXECUTION_POLICY_KEYS,
    "execution_policy",
  );
  if (!Array.isArray(parsed.approver_hashes)) {
    fail("execution_policy.approver_hashes must be an array");
  }
  if (parsed.approver_hashes.length < 1 || parsed.approver_hashes.length > 64) {
    fail("execution_policy.approver_hashes must contain one to 64 entries");
  }
  const approverHashes = parsed.approver_hashes.map((entry, index) =>
    bareBytes32(entry, `execution_policy.approver_hashes[${index}]`));
  const canonicalApprovers = [...new Set(approverHashes)].sort();
  if (
    canonicalApprovers.length !== approverHashes.length
    || canonicalApprovers.some((entry, index) => entry !== approverHashes[index])
  ) {
    fail("execution_policy.approver_hashes must be lowercase, sorted, and unique");
  }
  const root = bareBytes32(
    parsed.approver_root_hash,
    "execution_policy.approver_root_hash",
  );
  if (root !== approverRootHash(approverHashes)) {
    fail("execution_policy.approver_root_hash does not match the exact approver set");
  }

  const anchor = exactRecord(
    parsed.rollback_anchor_target,
    includeReleaseMarkerGenesis
      ? ROLLBACK_ANCHOR_TARGET_KEYS
      : HISTORICAL_ROLLBACK_ANCHOR_TARGET_KEYS,
    "execution_policy.rollback_anchor_target",
  );
  const anchorSchema = includeReleaseMarkerGenesis
    ? ROLLBACK_ANCHOR_SCHEMA
    : HISTORICAL_ROLLBACK_ANCHOR_SCHEMA;
  const normalizedAnchor = {
    schema: exactString(
      anchor.schema,
      anchorSchema,
      "execution_policy.rollback_anchor_target.schema",
    ),
    chain_id: integer(
      anchor.chain_id,
      "execution_policy.rollback_anchor_target.chain_id",
      BASE_SEPOLIA_CHAIN_ID,
      BASE_SEPOLIA_CHAIN_ID,
    ),
    contract_address: address(
      anchor.contract_address,
      "execution_policy.rollback_anchor_target.contract_address",
    ),
    runtime_code_hash: bytes32(
      anchor.runtime_code_hash,
      "execution_policy.rollback_anchor_target.runtime_code_hash",
    ),
    writer_address: address(
      anchor.writer_address,
      "execution_policy.rollback_anchor_target.writer_address",
    ),
    writer_release_commitment: bytes32(
      anchor.writer_release_commitment,
      "execution_policy.rollback_anchor_target.writer_release_commitment",
    ),
    writer_custody: exactString(
      anchor.writer_custody,
      ANCHOR_WRITER_CUSTODY,
      "execution_policy.rollback_anchor_target.writer_custody",
    ),
    writer_key_path: exactString(
      anchor.writer_key_path,
      ANCHOR_WRITER_KEY_PATH,
      "execution_policy.rollback_anchor_target.writer_key_path",
    ),
    confirmations: integer(
      anchor.confirmations,
      "execution_policy.rollback_anchor_target.confirmations",
      2,
      256,
    ),
    max_block_age_seconds: integer(
      anchor.max_block_age_seconds,
      "execution_policy.rollback_anchor_target.max_block_age_seconds",
      30,
      3_600,
    ),
    max_future_block_skew_seconds: integer(
      anchor.max_future_block_skew_seconds,
      "execution_policy.rollback_anchor_target.max_future_block_skew_seconds",
      0,
      300,
    ),
    verification_model: exactString(
      anchor.verification_model,
      ANCHOR_VERIFICATION_MODEL,
      "execution_policy.rollback_anchor_target.verification_model",
    ),
    independent_rpc_quorum_verified: boolean(
      anchor.independent_rpc_quorum_verified,
      "execution_policy.rollback_anchor_target.independent_rpc_quorum_verified",
    ),
    consensus_proof_verified: boolean(
      anchor.consensus_proof_verified,
      "execution_policy.rollback_anchor_target.consensus_proof_verified",
    ),
    ...(includeReleaseMarkerGenesis
      ? { writer_gas_reserve_policy: normalizeAnchorWriterGasReservePolicy(
        anchor.writer_gas_reserve_policy,
      ) }
      : {}),
  };
  if (
    normalizedAnchor.independent_rpc_quorum_verified
    || normalizedAnchor.consensus_proof_verified
  ) {
    fail("rollback anchor target must preserve the exact single-RPC trust classification");
  }

  const storeSchemaVersion = includeReleaseMarkerGenesis
    ? STORE_SCHEMA_VERSION
    : HISTORICAL_STORE_SCHEMA_VERSION;
  const normalized = {
    canonicalization_version: exactString(
      parsed.canonicalization_version,
      CANONICALIZATION_VERSION,
      "execution_policy.canonicalization_version",
    ),
    approval_schema: exactString(
      parsed.approval_schema,
      APPROVAL_SCHEMA,
      "execution_policy.approval_schema",
    ),
    api_schema_version: integer(
      parsed.api_schema_version,
      "execution_policy.api_schema_version",
      API_SCHEMA_VERSION,
      API_SCHEMA_VERSION,
    ),
    store_schema_version: integer(
      parsed.store_schema_version,
      "execution_policy.store_schema_version",
      storeSchemaVersion,
      storeSchemaVersion,
    ),
    approver_hashes: approverHashes,
    approver_root_hash: root,
    rollback_anchor_target: normalizedAnchor,
  };
  if (includeReleaseMarkerGenesis) {
    normalized.store_contract = normalizeExecutionPolicyStoreV6Contract(
      parsed.store_contract,
    );
    if (normalized.store_contract.schema_version
      !== normalized.store_schema_version) {
      fail("execution-policy store version does not match its exact v6 contract");
    }
    normalized.release_marker_genesis =
      normalizeExecutionPolicyReleaseMarkerGenesis(
        parsed.release_marker_genesis,
      );
  }
  return normalized;
}

function normalizeSharedReleaseLineage(value) {
  const parsed = exactRecord(value, [
    "schema",
    "release_sha",
    "deployment_intent_sha256",
    "cvm_launch_intent_sha256",
    "seven_cvm_release_verification_authority_sha256",
    "main_runtime_cvm_id",
    "main_runtime_compose_hash",
    "main_runtime_app_id",
    "main_runtime_os_image_hash",
  ], "shared_release_lineage");
  return {
    schema: exactString(
      parsed.schema,
      FINAL_RELEASE_SHARED_LINEAGE_SCHEMA,
      "shared_release_lineage.schema",
    ),
    release_sha: releaseSha(
      parsed.release_sha,
      "shared_release_lineage.release_sha",
    ),
    deployment_intent_sha256: sha256Pin(
      parsed.deployment_intent_sha256,
      "shared_release_lineage.deployment_intent_sha256",
    ),
    cvm_launch_intent_sha256: sha256Pin(
      parsed.cvm_launch_intent_sha256,
      "shared_release_lineage.cvm_launch_intent_sha256",
    ),
    seven_cvm_release_verification_authority_sha256: sha256Pin(
      parsed.seven_cvm_release_verification_authority_sha256,
      "shared_release_lineage.seven_cvm_release_verification_authority_sha256",
    ),
    main_runtime_cvm_id: cvmId(
      parsed.main_runtime_cvm_id,
      "shared_release_lineage.main_runtime_cvm_id",
    ),
    main_runtime_compose_hash: bareBytes32(
      parsed.main_runtime_compose_hash,
      "shared_release_lineage.main_runtime_compose_hash",
    ),
    main_runtime_app_id: phalaAppId(
      parsed.main_runtime_app_id,
      "shared_release_lineage.main_runtime_app_id",
    ),
    main_runtime_os_image_hash: bareBytes32(
      parsed.main_runtime_os_image_hash,
      "shared_release_lineage.main_runtime_os_image_hash",
    ),
  };
}

function normalizeCanonicalRoyaltyAuthority(value) {
  try {
    return normalizeRoyaltyReleaseAuthority(value);
  } catch (error) {
    fail(`royalty_release_authority is invalid: ${error?.message ?? "unknown error"}`);
  }
}

function normalizeCanonicalRoyaltyActiveState(value, authority) {
  try {
    return normalizeRoyaltyReleaseState(value, {
      authority,
      phase: "phase_two_active",
    });
  } catch (error) {
    fail(`royalty_release_active_state is invalid: ${error?.message ?? "unknown error"}`);
  }
}

function canonicalRoyaltyActiveStateSha256(value, authority) {
  try {
    return royaltyReleaseStateSha256(value, {
      authority,
      phase: "phase_two_active",
    });
  } catch (error) {
    fail(`royalty_release_active_state_sha256 cannot be derived: ${error?.message ?? "unknown error"}`);
  }
}

export function normalizeRoyaltySettlementReleaseBindingTemplate(value) {
  const parsed = exactRecord(value, [
    "schema",
    "chain_id",
    "distributor_address",
    "distributor_runtime_code_hash",
    "authority_nonce",
    "settlement_verifier_address",
    "settlement_verifier_key_path",
    "settlement_verifier_custody",
    "royalty_qvl_verifier_address",
    "royalty_qvl_signer_key_id",
    "royalty_qvl_signer_key_path",
    "royalty_qvl_signer_custody",
    "royalty_qvl_policy_template_sha256",
    "qvl_release_policy_hash",
    "measurement_policy_sha256",
    "execution_policy_anchor_address",
    "anchor_writer_release_commitment",
    "release_policy_commitment",
    "main_runtime_cvm_id",
    "deployment_intent_sha256",
    "ceremony_nonce",
    "compose_hash",
    "app_id",
    "os_image_hash",
    "max_authorization_lifetime_seconds",
  ], "royalty_settlement_release_binding_template");
  const qvlSignerKeyId = bytes32(
    parsed.royalty_qvl_signer_key_id,
    "royalty_settlement_release_binding_template.royalty_qvl_signer_key_id",
  );
  return {
    schema: exactString(
      parsed.schema,
      ROYALTY_SETTLEMENT_RELEASE_BINDING_TEMPLATE_SCHEMA,
      "royalty_settlement_release_binding_template.schema",
    ),
    chain_id: integer(
      parsed.chain_id,
      "royalty_settlement_release_binding_template.chain_id",
      BASE_SEPOLIA_CHAIN_ID,
      BASE_SEPOLIA_CHAIN_ID,
    ),
    distributor_address: address(
      parsed.distributor_address,
      "royalty_settlement_release_binding_template.distributor_address",
    ),
    distributor_runtime_code_hash: bytes32(
      parsed.distributor_runtime_code_hash,
      "royalty_settlement_release_binding_template.distributor_runtime_code_hash",
    ),
    authority_nonce: integer(
      parsed.authority_nonce,
      "royalty_settlement_release_binding_template.authority_nonce",
      1,
      MAX_SAFE_INTEGER,
    ),
    settlement_verifier_address: address(
      parsed.settlement_verifier_address,
      "royalty_settlement_release_binding_template.settlement_verifier_address",
    ),
    settlement_verifier_key_path: exactString(
      parsed.settlement_verifier_key_path,
      ROYALTY_SETTLEMENT_SIGNER_KEY_PATH,
      "royalty_settlement_release_binding_template.settlement_verifier_key_path",
    ),
    settlement_verifier_custody: exactString(
      parsed.settlement_verifier_custody,
      ROYALTY_SETTLEMENT_SIGNER_CUSTODY,
      "royalty_settlement_release_binding_template.settlement_verifier_custody",
    ),
    royalty_qvl_verifier_address: address(
      parsed.royalty_qvl_verifier_address,
      "royalty_settlement_release_binding_template.royalty_qvl_verifier_address",
    ),
    royalty_qvl_signer_key_id: qvlSignerKeyId,
    royalty_qvl_signer_key_path: exactString(
      parsed.royalty_qvl_signer_key_path,
      `${ROYALTY_QVL_SIGNER_KEY_PATH_PREFIX}/${qvlSignerKeyId.slice(2)}`,
      "royalty_settlement_release_binding_template.royalty_qvl_signer_key_path",
    ),
    royalty_qvl_signer_custody: exactString(
      parsed.royalty_qvl_signer_custody,
      ROYALTY_QVL_SIGNER_CUSTODY,
      "royalty_settlement_release_binding_template.royalty_qvl_signer_custody",
    ),
    royalty_qvl_policy_template_sha256: sha256Pin(
      parsed.royalty_qvl_policy_template_sha256,
      "royalty_settlement_release_binding_template.royalty_qvl_policy_template_sha256",
    ),
    qvl_release_policy_hash: bytes32(
      parsed.qvl_release_policy_hash,
      "royalty_settlement_release_binding_template.qvl_release_policy_hash",
    ),
    measurement_policy_sha256: sha256Pin(
      parsed.measurement_policy_sha256,
      "royalty_settlement_release_binding_template.measurement_policy_sha256",
    ),
    execution_policy_anchor_address: address(
      parsed.execution_policy_anchor_address,
      "royalty_settlement_release_binding_template.execution_policy_anchor_address",
    ),
    anchor_writer_release_commitment: bytes32(
      parsed.anchor_writer_release_commitment,
      "royalty_settlement_release_binding_template.anchor_writer_release_commitment",
    ),
    release_policy_commitment: bytes32(
      parsed.release_policy_commitment,
      "royalty_settlement_release_binding_template.release_policy_commitment",
    ),
    main_runtime_cvm_id: cvmId(
      parsed.main_runtime_cvm_id,
      "royalty_settlement_release_binding_template.main_runtime_cvm_id",
    ),
    deployment_intent_sha256: sha256Pin(
      parsed.deployment_intent_sha256,
      "royalty_settlement_release_binding_template.deployment_intent_sha256",
    ),
    ceremony_nonce: bytes32(
      parsed.ceremony_nonce,
      "royalty_settlement_release_binding_template.ceremony_nonce",
    ),
    compose_hash: bytes32(
      parsed.compose_hash,
      "royalty_settlement_release_binding_template.compose_hash",
    ),
    app_id: phalaAppId(
      parsed.app_id,
      "royalty_settlement_release_binding_template.app_id",
    ),
    os_image_hash: bareBytes32(
      parsed.os_image_hash,
      "royalty_settlement_release_binding_template.os_image_hash",
    ),
    max_authorization_lifetime_seconds: integer(
      parsed.max_authorization_lifetime_seconds,
      "royalty_settlement_release_binding_template.max_authorization_lifetime_seconds",
      ROYALTY_MAX_AUTHORIZATION_LIFETIME_SECONDS,
      ROYALTY_MAX_AUTHORIZATION_LIFETIME_SECONDS,
    ),
  };
}

function normalizeCollaborationExecutionAuthority(value) {
  const parsed = exactRecord(value, [
    "schema",
    "service",
    "profile",
    "enabled",
    "release_sha",
    "release_verification_sha256",
    "authenticated_worker_required",
    "heartbeat_claim_required",
    "heartbeat_claim_semantics",
    "tdx_attestation_claimed",
  ], "collaboration_execution");
  const normalized = {
    schema: exactString(
      parsed.schema,
      COLLABORATION_EXECUTION_RELEASE_AUTHORITY_SCHEMA,
      "collaboration_execution.schema",
    ),
    service: exactString(
      parsed.service,
      COLLABORATION_EXECUTION_SERVICE,
      "collaboration_execution.service",
    ),
    profile: exactString(
      parsed.profile,
      COLLABORATION_EXECUTION_PROFILE,
      "collaboration_execution.profile",
    ),
    enabled: boolean(
      parsed.enabled,
      "collaboration_execution.enabled",
    ),
    release_sha: releaseSha(
      parsed.release_sha,
      "collaboration_execution.release_sha",
    ),
    release_verification_sha256: sha256Pin(
      parsed.release_verification_sha256,
      "collaboration_execution.release_verification_sha256",
    ),
    authenticated_worker_required: boolean(
      parsed.authenticated_worker_required,
      "collaboration_execution.authenticated_worker_required",
    ),
    heartbeat_claim_required: boolean(
      parsed.heartbeat_claim_required,
      "collaboration_execution.heartbeat_claim_required",
    ),
    heartbeat_claim_semantics: exactString(
      parsed.heartbeat_claim_semantics,
      AUTHENTICATED_WORKER_HEARTBEAT_CLAIM,
      "collaboration_execution.heartbeat_claim_semantics",
    ),
    tdx_attestation_claimed: boolean(
      parsed.tdx_attestation_claimed,
      "collaboration_execution.tdx_attestation_claimed",
    ),
  };
  if (!normalized.authenticated_worker_required
    || !normalized.heartbeat_claim_required
    || normalized.tdx_attestation_claimed) {
    fail("collaboration_execution must require an authenticated heartbeat without claiming TDX attestation");
  }
  return normalized;
}

function normalizeComputeWorkloadWalletAdoption(value) {
  const parsed = exactRecord(value, [
    "schema",
    "enabled",
    "device_spend_authority",
    "credential_uploader_attribution_preserved",
    "device_ciphertext_upload_authority_preserved",
    "wallet_funding_authority_required",
    "workload_dispatch_authority_required",
  ], "compute_workload_wallet_adoption");
  const normalized = {
    schema: exactString(
      parsed.schema,
      COMPUTE_WORKLOAD_WALLET_ADOPTION_RELEASE_DECISION_SCHEMA,
      "compute_workload_wallet_adoption.schema",
    ),
    enabled: boolean(
      parsed.enabled,
      "compute_workload_wallet_adoption.enabled",
    ),
    device_spend_authority: boolean(
      parsed.device_spend_authority,
      "compute_workload_wallet_adoption.device_spend_authority",
    ),
    credential_uploader_attribution_preserved: boolean(
      parsed.credential_uploader_attribution_preserved,
      "compute_workload_wallet_adoption.credential_uploader_attribution_preserved",
    ),
    device_ciphertext_upload_authority_preserved: boolean(
      parsed.device_ciphertext_upload_authority_preserved,
      "compute_workload_wallet_adoption.device_ciphertext_upload_authority_preserved",
    ),
    wallet_funding_authority_required: boolean(
      parsed.wallet_funding_authority_required,
      "compute_workload_wallet_adoption.wallet_funding_authority_required",
    ),
    workload_dispatch_authority_required: boolean(
      parsed.workload_dispatch_authority_required,
      "compute_workload_wallet_adoption.workload_dispatch_authority_required",
    ),
  };
  if (normalized.device_spend_authority
    || !normalized.credential_uploader_attribution_preserved
    || !normalized.device_ciphertext_upload_authority_preserved
    || !normalized.wallet_funding_authority_required
    || !normalized.workload_dispatch_authority_required) {
    fail("compute_workload_wallet_adoption must preserve uploader attribution and prohibit device spend authority");
  }
  return normalized;
}

function validateCrossBindings(core, { diligenceDeveloperPolicy }) {
  const { contracts, cvm, operator_address: operator, execution_policy: policy } = core;
  const operatorBindings = [
    ["ChallengeRegistry owner", contracts.challenge_registry.owner],
    ["TinkerAccountEncumbrance owner", contracts.tinker_account_encumbrance.owner],
    ["ComputeCreditVault owner", contracts.compute_credit_vault.owner],
    ["EmailOracleAuth owner", contracts.email_oracle_auth.owner],
  ];
  if (diligenceDeveloperPolicy === "historical-operator-v2") {
    operatorBindings.unshift([
      "DiligenceRoom developer",
      contracts.diligence_room.developer,
    ]);
  } else if (diligenceDeveloperPolicy === "permanent-distinct-v3"
    || diligenceDeveloperPolicy === "permanent-distinct-v4") {
    if (
      contracts.diligence_room.developer === operator
      || contracts.diligence_room.developer === contracts.diligence_room.address
    ) {
      fail("DiligenceRoom permanent developer must differ from the deployment operator and room contract");
    }
  } else {
    fail("final release authority core uses an unsupported developer policy");
  }
  for (const [label, observed] of operatorBindings) {
    if (observed !== operator) fail(`${label} must equal operator_address`);
  }
  if (cvm.tee_identity === operator) fail("cvm.tee_identity must differ from operator_address");
  if (
    contracts.tinker_account_encumbrance.approved_compose_hashes[0]
      !== `0x${cvm.compose_hash}`
    || contracts.tinker_account_encumbrance.managers[0] !== cvm.tee_identity
  ) {
    fail("TinkerAccountEncumbrance release authority must equal the one reviewed main CVM compose and TEE identity");
  }
  if (
    contracts.diligence_room.release_admission.tee_identity !== cvm.tee_identity
    || contracts.diligence_room.release_admission.compose_hash !== cvm.compose_hash
  ) {
    fail("DiligenceRoom release admission must equal the one reviewed main CVM compose and TEE identity");
  }
  if (
    contracts.compute_credit_vault.tee_identity !== cvm.tee_identity
    || contracts.compute_credit_vault.compose_hash !== cvm.compose_hash
  ) {
    fail("ComputeCreditVault execution roots must match the main CVM");
  }
  if (contracts.email_oracle_auth.consumer_address !== cvm.tee_identity) {
    fail("EmailOracleAuth consumer must equal the main CVM TEE identity");
  }
  if (
    contracts.email_oracle_auth.release.oracle_compose_hash !== `0x${cvm.compose_hash}`
    || contracts.email_oracle_auth.release.consumer_compose_hash !== `0x${cvm.compose_hash}`
  ) {
    fail("EmailOracleAuth oracle and consumer admission must equal the reviewed main CVM compose");
  }
  if (
    contracts.email_oracle_auth.release.target_boot.os_image_hash
      !== `0x${cvm.os_image_hash}`
  ) {
    fail("EmailOracleAuth target boot OS image must equal the main CVM OS image");
  }
  const emailInfrastructureRoles = [
    contracts.email_oracle_auth.address,
    contracts.email_oracle_auth.owner,
    contracts.email_oracle_auth.consumer_address,
    contracts.email_oracle_auth.release.kms_contract_address,
    contracts.email_oracle_auth.release.kms_implementation_address,
    contracts.email_oracle_auth.release.target_boot.instance_id,
  ];
  if (new Set(emailInfrastructureRoles).size !== emailInfrastructureRoles.length) {
    fail("EmailOracleAuth owner, consumer, KMS proxy, implementation, instance, and auth contract must be distinct");
  }
  const controlPlaneRoles = [
    operator,
    cvm.tee_identity,
    ...(diligenceDeveloperPolicy === "permanent-distinct-v3"
      || diligenceDeveloperPolicy === "permanent-distinct-v4"
      ? [contracts.diligence_room.developer]
      : []),
    contracts.diligence_room.result_verifier,
    contracts.diligence_room.attestation_verifier,
    contracts.compute_credit_vault.developer,
    contracts.compute_credit_vault.metering_verifier,
    contracts.compute_credit_vault.metering_qvl_verifier,
    policy.rollback_anchor_target.writer_address,
  ];
  if (new Set(controlPlaneRoles).size !== controlPlaneRoles.length) {
    fail("all governance, TEE, verifier, metering, and anchor-writer roles must be distinct");
  }

  const providerForbiddenRoles = new Set([
    ...controlPlaneRoles,
    ...Object.values(contracts).map((entry) => entry.address),
    policy.rollback_anchor_target.contract_address,
  ]);
  if (
    contracts.compute_credit_vault.rate_policies.native.provider
      === contracts.compute_credit_vault.rate_policies.erc20.provider
  ) {
    fail("ComputeCreditVault native and ERC20 providers must be distinct payout recipients");
  }
  for (const [label, provider] of [
    ["native", contracts.compute_credit_vault.rate_policies.native.provider],
    ["ERC20", contracts.compute_credit_vault.rate_policies.erc20.provider],
  ]) {
    if (providerForbiddenRoles.has(provider)) {
      fail(`ComputeCreditVault ${label} provider must be separate from governance, contracts, TEE, verifier, metering, and anchor roles`);
    }
  }

  const anchor = policy.rollback_anchor_target;
  if (
    anchor.writer_release_commitment
      !== `0x${core.cvm_launch_intent_sha256.slice("sha256:".length)}`
  ) {
    fail(
      "rollback anchor writer release commitment must equal the reviewed CVM launch-intent digest",
    );
  }
  const contractAddresses = new Set(Object.values(contracts).map((entry) => entry.address));
  for (const infrastructureAddress of [
    contracts.email_oracle_auth.release.kms_contract_address,
    contracts.email_oracle_auth.release.kms_implementation_address,
    contracts.email_oracle_auth.release.target_boot.instance_id,
  ]) {
    if (
      contractAddresses.has(infrastructureAddress)
      || controlPlaneRoles.includes(infrastructureAddress)
      || anchor.contract_address === infrastructureAddress
    ) {
      fail("Email KMS and target-instance addresses must be separate from application, control-plane, and anchor roles");
    }
  }
  if (contractAddresses.has(anchor.contract_address)) {
    fail("rollback anchor target must be separate from the application contracts");
  }
  if (controlPlaneRoles.some((role) => contractAddresses.has(role))) {
    fail("control-plane roles must not equal an application contract address");
  }
  if (controlPlaneRoles.includes(anchor.contract_address)) {
    fail("control-plane roles must not equal the rollback anchor contract");
  }
}

function validateV4CrossBindings(core) {
  const lineage = core.shared_release_lineage;
  const royalty = core.royalty_release_authority;
  const template = core.royalty_settlement_release_binding_template;
  const anchor = core.execution_policy.rollback_anchor_target;
  const sevenCvmSha = core.seven_cvm_release_verification_authority_sha256;

  if (lineage.release_sha !== core.release_sha
    || lineage.deployment_intent_sha256 !== core.deployment_intent_sha256
    || lineage.cvm_launch_intent_sha256 !== core.cvm_launch_intent_sha256
    || lineage.seven_cvm_release_verification_authority_sha256 !== sevenCvmSha
    || lineage.main_runtime_cvm_id !== core.cvm.cvm_id
    || lineage.main_runtime_compose_hash !== core.cvm.compose_hash
    || lineage.main_runtime_app_id !== core.cvm.app_id
    || lineage.main_runtime_os_image_hash !== core.cvm.os_image_hash) {
    fail("shared_release_lineage must exactly bind the release, deployment, seven-CVM authority, and main-runtime identity");
  }

  if (core.collaboration_execution.release_sha !== core.release_sha
    || core.collaboration_execution.release_verification_sha256 !== sevenCvmSha
    || core.collaboration_execution.enabled
      !== core.requested_features.collaboration_execution) {
    fail("collaboration_execution must bind the release, seven-CVM verification authority, and signed feature decision");
  }
  if (core.compute_workload_wallet_adoption.enabled
    !== core.requested_features.compute_workload_wallet_adoption) {
    fail("compute_workload_wallet_adoption.enabled must equal the signed requested feature");
  }

  if (royalty.chain_id !== core.network.chain_id
    || royalty.distributor_address !== core.contracts.royalty_distributor.address
    || royalty.owner !== core.operator_address
    || royalty.execution_policy_anchor !== anchor.contract_address
    || royalty.anchor_writer !== anchor.writer_address
    || royalty.anchor_writer_release_commitment
      !== anchor.writer_release_commitment) {
    fail("royalty_release_authority must exactly bind the reviewed contract, owner, and execution-policy anchor");
  }
  const activeStateSha = canonicalRoyaltyActiveStateSha256(
    core.royalty_release_active_state,
    royalty,
  );
  if (core.royalty_release_active_state_sha256 !== activeStateSha) {
    fail("royalty_release_active_state_sha256 must equal the canonical active-state digest");
  }
  if (new Set([
    core.royalty_release_active_state_sha256,
    core.royalty_release_history_sha256,
    core.royalty_release_history_receipt_sha256,
  ]).size !== 3) {
    fail("Royalty active-state, history, and H receipt digests must be distinct");
  }

  if (template.chain_id !== core.network.chain_id
    || template.distributor_address !== core.contracts.royalty_distributor.address
    || template.distributor_runtime_code_hash
      !== core.contracts.royalty_distributor.runtime_code_hash
    || template.authority_nonce !== royalty.authority_nonce
    || template.settlement_verifier_address !== royalty.settlement_verifier
    || template.royalty_qvl_verifier_address !== royalty.qvl_verifier
    || template.execution_policy_anchor_address
      !== royalty.execution_policy_anchor
    || template.anchor_writer_release_commitment
      !== royalty.anchor_writer_release_commitment
    || template.release_policy_commitment
      !== royalty.release_policy_commitment
    || template.main_runtime_cvm_id !== core.cvm.cvm_id
    || template.deployment_intent_sha256 !== core.deployment_intent_sha256
    || template.compose_hash !== `0x${core.cvm.compose_hash}`
    || template.app_id !== core.cvm.app_id
    || template.os_image_hash !== core.cvm.os_image_hash) {
    fail("royalty settlement release-binding template must exactly bind canonical Royalty and main-runtime authority");
  }
  if (new Set([
    template.royalty_qvl_policy_template_sha256,
    template.measurement_policy_sha256,
    core.deployment_intent_sha256,
    sevenCvmSha,
  ]).size !== 4) {
    fail("Royalty QVL template, measurement, deployment, and seven-CVM commitments must be domain-distinct");
  }

  const royaltySigners = [
    royalty.settlement_verifier,
    royalty.qvl_verifier,
  ];
  const forbiddenSignerRoles = new Set([
    core.operator_address,
    core.cvm.tee_identity,
    core.contracts.diligence_room.developer,
    core.contracts.diligence_room.result_verifier,
    core.contracts.diligence_room.attestation_verifier,
    core.contracts.compute_credit_vault.developer,
    core.contracts.compute_credit_vault.metering_verifier,
    core.contracts.compute_credit_vault.metering_qvl_verifier,
    anchor.writer_address,
    ...Object.values(core.contracts).map((entry) => entry.address),
  ]);
  if (royaltySigners.some((signer) => forbiddenSignerRoles.has(signer))) {
    fail("Royalty settlement and QVL signers must be independent from Diligence, metering, governance, TEE, anchor, and contract roles");
  }
}

/**
 * Validate and normalize the exact pre-anchor release-core artifact.
 *
 * The returned object is a fresh JSON value. Unordered image/origin sets are
 * sorted; semantically ordered approver hashes must already be sorted/unique.
 */
function normalizeFinalReleaseAuthorityCoreVersion(
  value,
  {
    schema,
    topLevelKeys,
    requestedFeatureKeys,
    normalizeHttpsOrigin,
    diligenceDeveloperPolicy,
    requireCanonicalMainRuntimeIdentity = false,
    includeV4Bindings = false,
  },
) {
  assertJsonTree(value);
  const parsed = exactRecord(
    value,
    topLevelKeys,
    "final release authority core",
  );
  const release = releaseSha(parsed.release_sha, "release_sha");
  const network = exactRecord(parsed.network, ["chain_id", "public_rpc_url"], "network");
  const contracts = normalizeContracts(parsed.contracts);
  const normalized = {
    schema: exactString(parsed.schema, schema, "schema"),
    release_sha: release,
    network: {
      chain_id: integer(
        network.chain_id,
        "network.chain_id",
        BASE_SEPOLIA_CHAIN_ID,
        BASE_SEPOLIA_CHAIN_ID,
      ),
      public_rpc_url: exactString(
        network.public_rpc_url,
        BASE_SEPOLIA_PUBLIC_RPC,
        "network.public_rpc_url",
      ),
    },
    operator_address: address(parsed.operator_address, "operator_address"),
    deployment_intent_sha256: sha256Pin(
      parsed.deployment_intent_sha256,
      "deployment_intent_sha256",
    ),
    cvm_launch_intent_sha256: sha256Pin(
      parsed.cvm_launch_intent_sha256,
      "cvm_launch_intent_sha256",
    ),
    contracts,
    cvm: normalizeCvm(parsed.cvm, release, normalizeHttpsOrigin, {
      requireCanonicalMainRuntimeIdentity,
    }),
    arena_registry_bindings: normalizeArenaRegistryBindings(
      parsed.arena_registry_bindings,
      contracts.challenge_registry,
    ),
    wallet_auth: (() => {
      const wallet = exactRecord(
        parsed.wallet_auth,
        ["domain", "uri", "walletconnect_project_id"],
        "wallet_auth",
      );
      return {
        domain: exactString(wallet.domain, "www.wikigen.me", "wallet_auth.domain"),
        uri: exactString(
          wallet.uri,
          "https://www.wikigen.me",
          "wallet_auth.uri",
        ),
        walletconnect_project_id: walletConnectProjectId(
          wallet.walletconnect_project_id,
          "wallet_auth.walletconnect_project_id",
        ),
      };
    })(),
    requested_features: normalizeRequestedFeatures(
      parsed.requested_features,
      requestedFeatureKeys,
    ),
    execution_policy: normalizeExecutionPolicy(parsed.execution_policy, {
      includeReleaseMarkerGenesis: includeV4Bindings,
    }),
  };
  if (includeV4Bindings) {
    const royaltyAuthority = normalizeCanonicalRoyaltyAuthority(
      parsed.royalty_release_authority,
    );
    const royaltyActiveState = normalizeCanonicalRoyaltyActiveState(
      parsed.royalty_release_active_state,
      royaltyAuthority,
    );
    Object.assign(normalized, {
      seven_cvm_release_verification_authority_sha256: sha256Pin(
        parsed.seven_cvm_release_verification_authority_sha256,
        "seven_cvm_release_verification_authority_sha256",
      ),
      shared_release_lineage: normalizeSharedReleaseLineage(
        parsed.shared_release_lineage,
      ),
      royalty_release_authority: royaltyAuthority,
      royalty_release_active_state: royaltyActiveState,
      royalty_release_active_state_sha256: sha256Pin(
        parsed.royalty_release_active_state_sha256,
        "royalty_release_active_state_sha256",
      ),
      royalty_release_history_sha256: sha256Pin(
        parsed.royalty_release_history_sha256,
        "royalty_release_history_sha256",
      ),
      royalty_release_history_receipt_sha256: sha256Pin(
        parsed.royalty_release_history_receipt_sha256,
        "royalty_release_history_receipt_sha256",
      ),
      royalty_settlement_release_binding_template:
        normalizeRoyaltySettlementReleaseBindingTemplate(
          parsed.royalty_settlement_release_binding_template,
        ),
      collaboration_execution: normalizeCollaborationExecutionAuthority(
        parsed.collaboration_execution,
      ),
      compute_workload_wallet_adoption:
        normalizeComputeWorkloadWalletAdoption(
          parsed.compute_workload_wallet_adoption,
        ),
    });
  }
  validateCrossBindings(normalized, { diligenceDeveloperPolicy });
  if (includeV4Bindings) validateV4CrossBindings(normalized);
  const encoded = canonicalBytesOfNormalized(normalized);
  if (encoded.length > MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES) {
    fail(
      `canonical final release authority core exceeds ${MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES} bytes`,
    );
  }
  return normalized;
}

/**
 * Validate the current v4 authority. Historical v2/v3 values are never
 * accepted through this activation-facing entry point.
 */
export function normalizeFinalReleaseAuthorityCore(value) {
  return normalizeFinalReleaseAuthorityCoreVersion(value, {
    schema: FINAL_RELEASE_AUTHORITY_CORE_V4_SCHEMA,
    topLevelKeys: TOP_LEVEL_KEYS_V4,
    requestedFeatureKeys: REQUESTED_FEATURE_KEYS_V4,
    normalizeHttpsOrigin: currentPublicHttpsOriginV3,
    diligenceDeveloperPolicy: "permanent-distinct-v4",
    requireCanonicalMainRuntimeIdentity: true,
    includeV4Bindings: true,
  });
}

/** Validate the frozen historical v2 wire format for offline replay only. */
export function normalizeHistoricalFinalReleaseAuthorityCoreV2(value) {
  return normalizeFinalReleaseAuthorityCoreVersion(value, {
    schema: FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA,
    topLevelKeys: HISTORICAL_TOP_LEVEL_KEYS_V2_V3,
    requestedFeatureKeys: HISTORICAL_REQUESTED_FEATURE_KEYS_V2,
    normalizeHttpsOrigin: historicalHttpsOriginV2,
    diligenceDeveloperPolicy: "historical-operator-v2",
  });
}

export const normalizeExecutionPolicyReleaseCore =
  normalizeFinalReleaseAuthorityCore;

/** Return compact recursively key-sorted ensure-ASCII JSON with no newline. */
export function canonicalFinalReleaseAuthorityCoreBytes(value) {
  return canonicalBytesOfNormalized(normalizeFinalReleaseAuthorityCore(value));
}

export function canonicalHistoricalFinalReleaseAuthorityCoreV2Bytes(value) {
  return canonicalBytesOfNormalized(
    normalizeHistoricalFinalReleaseAuthorityCoreV2(value),
  );
}

export const canonicalExecutionPolicyReleaseCoreBytes =
  canonicalFinalReleaseAuthorityCoreBytes;

/** Return recursively sorted two-space JSON with exactly one final newline. */
export function canonicalFinalReleaseAuthorityCoreArtifactText(value) {
  const normalized = normalizeFinalReleaseAuthorityCore(value);
  return `${JSON.stringify(recursivelySortedJsonValue(normalized), null, 2)}\n`;
}

export function canonicalHistoricalFinalReleaseAuthorityCoreV2ArtifactText(value) {
  const normalized = normalizeHistoricalFinalReleaseAuthorityCoreV2(value);
  return `${JSON.stringify(recursivelySortedJsonValue(normalized), null, 2)}\n`;
}

/** Return the bare lowercase SHA-256 final release authority commitment. */
export function finalReleaseAuthorityCoreDigest(value) {
  return createHash("sha256")
    .update(FINAL_RELEASE_AUTHORITY_CORE_DOMAIN, "utf8")
    .update(canonicalFinalReleaseAuthorityCoreBytes(value))
    .digest("hex");
}

/** Return the frozen historical v2 commitment for offline replay only. */
export function historicalFinalReleaseAuthorityCoreV2Digest(value) {
  return createHash("sha256")
    .update(FINAL_RELEASE_AUTHORITY_CORE_V2_DOMAIN, "utf8")
    .update(canonicalHistoricalFinalReleaseAuthorityCoreV2Bytes(value))
    .digest("hex");
}

export const executionPolicyReleaseCoreDigest =
  finalReleaseAuthorityCoreDigest;
